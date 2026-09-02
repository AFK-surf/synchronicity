import Synchronicity.MptGc
import Synchronicity.ScopedSync

/-!
Convergence of mptsync, in the three pieces it decomposes into (§5.2, §5.3).

1. **Head selection is a join.**  `offer_head` adopts a head into the pending
   slot when it supersedes the greatest head recorded so far, under the
   lexicographic `(seq, root)` order.  `select_eq_of_mem_iff` says the head a
   node ends up with depends only on *which* heads it has heard, not on their
   order or multiplicity: two nodes that have heard the same heads hold the
   same one.  `seq_only_diverges` is the design's own warning made concrete —
   the same rule on `seq` alone is order-dependent.

2. **The derived view is a function of root and scope.**  `HasValue` is
   `Trie::get`; `view_deterministic` says a key has one value under a root, and
   `ScopedView` — what `materialize_diff` derives under a read scope — is
   therefore the same on every node that promoted the same head under the same
   scope.  `admitted_key_readable` says a node whose trie is complete within
   its scope can read every admitted key, or the key lies under a boundary the
   walk stopped at.

3. **The fetch terminates, and a fetch that can take no step is complete.**
   `FetchStep` is one learned item — a node, a refusal, or a value — for a
   position the scoped walk is asking about, served by a peer holding the
   root.  `fetch_terminates` bounds every fetch by the size of the origin's
   trie; `stuck_complete` says a fetch with no step left has established
   `CompleteWithin`, which is the premise `try_promote` flips on
   (`stuck_fetch_promotes`).

What is assumed, and stated as hypotheses rather than proved: that heads reach
every node (`select_eq_of_mem_iff` takes the same membership as given); that a
peer holding the root's head stays reachable and answers (a `FetchStep` exists
whenever the responder would serve); that the origin's trie is whole
(`Whole`) and finite (`Bounded`); and, for out-of-line values, that a held
node is admitted where the walk meets it (`stuck_complete`'s `hadm` — a node
held from a position where it revealed less may sit at one where it reveals
more, and the responder will not serve its value there; Rust abandons that
head after `MAX_UNPRODUCTIVE_ROUNDS` and retries).
-/

namespace Synchronicity.Convergence

open Synchronicity (Path Scope)
open Synchronicity.ScopedSync

/-! ## Head selection is a join -/

/-- A signed head's ordering key. -/
structure Head where
  seq : Nat
  root : Hash
  deriving DecidableEq

namespace Head

/-- `SignedHead::supersedes`: strictly greater under `(seq, root)`. -/
def Lt (a b : Head) : Prop := a.seq < b.seq ∨ (a.seq = b.seq ∧ a.root < b.root)

instance (a b : Head) : Decidable (Lt a b) :=
  inferInstanceAs (Decidable (a.seq < b.seq ∨ (a.seq = b.seq ∧ a.root < b.root)))

variable {a b d : Head}

theorem lt_irrefl (a : Head) : ¬ Lt a a := by
  rintro (h | ⟨_, h⟩) <;> exact Nat.lt_irrefl _ h

theorem lt_trans (h₁ : Lt a b) (h₂ : Lt b d) : Lt a d := by
  rcases h₁ with h₁ | ⟨e₁, h₁⟩ <;> rcases h₂ with h₂ | ⟨e₂, h₂⟩
  · exact Or.inl (Nat.lt_trans h₁ h₂)
  · exact Or.inl (by omega)
  · exact Or.inl (by omega)
  · exact Or.inr ⟨by omega, Nat.lt_trans h₁ h₂⟩

theorem trichotomy (a b : Head) : Lt a b ∨ a = b ∨ Lt b a := by
  rcases Nat.lt_trichotomy a.seq b.seq with h | h | h
  · exact Or.inl (Or.inl h)
  · rcases Nat.lt_trichotomy a.root b.root with hr | hr | hr
    · exact Or.inl (Or.inr ⟨h, hr⟩)
    · exact Or.inr (Or.inl (by cases a; cases b; simp_all))
    · exact Or.inr (Or.inr (Or.inr ⟨h.symm, hr⟩))
  · exact Or.inr (Or.inr (Or.inl h))

/-- Two heads neither of which supersedes the other are one head. -/
theorem eq_of_not_lt (h₁ : ¬ Lt a b) (h₂ : ¬ Lt b a) : a = b := by
  rcases trichotomy a b with h | h | h
  · exact absurd h h₁
  · exact h
  · exact absurd h h₂

theorem not_lt_trans (h₁ : ¬ Lt a b) (h₂ : ¬ Lt b d) : ¬ Lt a d := by
  intro h
  rcases trichotomy b d with hbd | rfl | hdb
  · exact h₂ hbd
  · exact h₁ h
  · exact h₁ (lt_trans h hdb)

end Head

/- RUST-IMPL: mpt-head-adopt — `reconcile.rs::offer_head`, `supersedes(floor)`:
   a head takes the slot when it strictly beats the greatest head recorded,
   and is otherwise only retained. -/
def adopt (floor : Option Head) (h : Head) : Option Head :=
  match floor with
  | none => some h
  | some f => if Head.Lt f h then some h else some f

/-- The head a node holds after hearing `heads` in that order. -/
def select (heads : List Head) : Option Head := heads.foldl adopt none

theorem adopt_spec (floor : Option Head) (h : Head) :
    ∃ a, adopt floor h = some a ∧ (a = h ∨ floor = some a) ∧ ¬ Head.Lt a h ∧
      ∀ f, floor = some f → ¬ Head.Lt a f := by
  cases floor with
  | none => exact ⟨h, rfl, Or.inl rfl, Head.lt_irrefl h, fun _ hf => nomatch hf⟩
  | some f =>
    by_cases hlt : Head.Lt f h
    · refine ⟨h, by simp [adopt, hlt], Or.inl rfl, Head.lt_irrefl h, fun f' hf' => ?_⟩
      injection hf' with hf'
      subst hf'
      intro hhf
      exact Head.lt_irrefl _ (Head.lt_trans hlt hhf)
    · refine ⟨f, by simp [adopt, hlt], Or.inr rfl, hlt, fun f' hf' => ?_⟩
      injection hf' with hf'
      subst hf'
      exact Head.lt_irrefl _

theorem foldl_adopt_some (l : List Head) (acc : Option Head) (m : Head)
    (h : l.foldl adopt acc = some m) :
    (acc = some m ∨ m ∈ l) ∧ (∀ h' ∈ l, ¬ Head.Lt m h') ∧
      (∀ a, acc = some a → ¬ Head.Lt m a) := by
  induction l generalizing acc with
  | nil =>
    refine ⟨Or.inl h, ?_, ?_⟩
    · intro h' hh'
      exact absurd hh' (List.not_mem_nil)
    · intro a ha
      rw [List.foldl_nil] at h
      rw [h] at ha
      injection ha with ha
      subst ha
      exact Head.lt_irrefl _
  | cons x l ih =>
    obtain ⟨a, ha, hax, hnax, hnaf⟩ := adopt_spec acc x
    rw [List.foldl_cons, ha] at h
    obtain ⟨hmem, hl, hacc⟩ := ih (some a) h
    have hma : ¬ Head.Lt m a := hacc a rfl
    refine ⟨?_, fun h' hh' => ?_, fun f hf => Head.not_lt_trans hma (hnaf f hf)⟩
    · rcases hmem with hmem | hmem
      · injection hmem with hmem
        subst hmem
        rcases hax with rfl | hacc'
        · exact Or.inr List.mem_cons_self
        · exact Or.inl hacc'
      · exact Or.inr (List.mem_cons_of_mem x hmem)
    · rcases List.mem_cons.mp hh' with rfl | hh'
      · exact Head.not_lt_trans hma hnax
      · exact hl h' hh'

theorem foldl_adopt_isSome (l : List Head) (a : Head) :
    ∃ m, l.foldl adopt (some a) = some m := by
  induction l generalizing a with
  | nil => exact ⟨a, rfl⟩
  | cons x l ih =>
    obtain ⟨b, hb, _⟩ := adopt_spec (some a) x
    rw [List.foldl_cons, hb]
    exact ih b

/-- The head selected is a maximum of the heads heard. -/
theorem select_max (h : select l = some m) : m ∈ l ∧ ∀ h' ∈ l, ¬ Head.Lt m h' := by
  obtain ⟨hmem, hl, _⟩ := foldl_adopt_some l none m h
  exact ⟨hmem.resolve_left (fun h => nomatch h), hl⟩

theorem select_none : select l = none ↔ l = [] := by
  constructor
  · intro h
    cases l with
    | nil => rfl
    | cons x l =>
      obtain ⟨m, hm⟩ := foldl_adopt_isSome l x
      simp [select, List.foldl_cons, adopt, hm] at h
  · rintro rfl
    rfl

/-- A maximum, whenever there is one, is what selection finds. -/
theorem select_eq_of_max (hmem : m ∈ l) (hmax : ∀ h' ∈ l, ¬ Head.Lt m h') : select l = some m := by
  cases hsel : select l with
  | none =>
    rw [select_none] at hsel
    subst hsel
    exact absurd hmem (List.not_mem_nil)
  | some m' =>
    obtain ⟨hmem', hmax'⟩ := select_max hsel
    rw [Head.eq_of_not_lt (hmax' m hmem) (hmax m' hmem')]

/-- **Head selection converges.**  Two nodes that have heard the same heads —
in any order, any number of times — hold the same head. -/
theorem select_eq_of_mem_iff (h : ∀ x, x ∈ l ↔ x ∈ l') : select l = select l' := by
  cases hsel : select l with
  | none =>
    rw [select_none] at hsel
    subst hsel
    cases l' with
    | nil => rfl
    | cons x l' => exact absurd ((h x).mpr List.mem_cons_self) (List.not_mem_nil)
  | some m =>
    obtain ⟨hmem, hmax⟩ := select_max hsel
    exact (select_eq_of_max ((h m).mp hmem) fun h' hh' => hmax h' ((h h').mpr hh')).symm

theorem select_perm (h : l.Perm l') : select l = select l' :=
  select_eq_of_mem_iff fun _ => h.mem_iff

/-- The floor never moves down: hearing more heads never selects a lesser one. -/
theorem select_mono (h : select l = some m) (h' : select (l ++ l₂) = some m') : ¬ Head.Lt m' m := by
  obtain ⟨hmem, _⟩ := select_max h
  exact (select_max h').2 m (List.mem_append_left l₂ hmem)

/-- The design's warning (§5.2): the same fold on `seq` alone is
order-dependent, so two peers hearing equal-`seq` heads in different orders
would diverge permanently. -/
def adoptSeq (floor : Option Head) (h : Head) : Option Head :=
  match floor with
  | none => some h
  | some f => if f.seq < h.seq then some h else some f

theorem seq_only_diverges :
    [Head.mk 1 0, Head.mk 1 1].foldl adoptSeq none ≠ [Head.mk 1 1, Head.mk 1 0].foldl adoptSeq none := by
  decide

/-! ## The derived view is a function of root and scope -/

variable {c : Content} {s : Scope} {st : Store} {r x y : Hash} {p q key : Path}

/-- The node at `p` carries the value of `key`: a leaf whose remaining key
completes `p`, or a branch value sitting exactly at `p`. -/
def CarriesKey (c : Content) (x : Hash) (p key : Path) (v : ValueRef) : Prop :=
  (∃ rest, c x = some (.leaf rest v) ∧ key = p ++ rest) ∨
  (∃ children, c x = some (.branch children (some v)) ∧ key = p)

/- RUST-IMPL: mpt-trie-get — `trie.rs::Trie::get`: the value of a key under a
   root is what the descent finds at the key's position. -/
def HasValue (c : Content) (root : Hash) (key : Path) (v : ValueRef) : Prop :=
  ∃ p x, At c root p x ∧ CarriesKey c x p key v

theorem carries_prefix {v : ValueRef} (h : CarriesKey c x p key v) : p <+: key := by
  rcases h with ⟨rest, _, rfl⟩ | ⟨_, _, rfl⟩
  · exact List.prefix_append _ rest
  · exact List.prefix_refl _

/-- Two value-carrying nodes for one key, one at or below the other, agree. -/
theorem carries_unique_of_below {v₁ v₂ : ValueRef} {x₁ x₂ : Hash} (canon : Canonical c)
    (hat₁ : At c r p x₁) (h₁ : CarriesKey c x₁ p key v₁)
    (hat₂ : At c r (p ++ q) x₂) (h₂ : CarriesKey c x₂ (p ++ q) key v₂) : v₁ = v₂ := by
  have hq : At c x₁ q x₂ := At.split canon hat₁ hat₂
  rcases h₁ with ⟨rest, hc₁, _⟩ | ⟨children, hc₁, hkey₁⟩
  · obtain ⟨rfl, rfl⟩ := At.leaf_nil hq hc₁
    rcases h₂ with ⟨rest', hc₂, _⟩ | ⟨_, hc₂, _⟩
    · rw [hc₁] at hc₂
      simp only [Option.some.injEq, Node.leaf.injEq] at hc₂
      exact hc₂.2
    · rw [hc₁] at hc₂
      injection hc₂ with h
      cases h
  · subst hkey₁
    have hq0 : q = [] := by
      have hl := (carries_prefix h₂).length_le
      rw [List.length_append] at hl
      exact List.eq_nil_of_length_eq_zero (by omega)
    subst hq0
    have hx : x₂ = x₁ := At.unique canon hq At.here
    subst hx
    rcases h₂ with ⟨_, hc₂, _⟩ | ⟨_, hc₂, _⟩
    · rw [hc₁] at hc₂
      injection hc₂ with h
      cases h
    · rw [hc₁] at hc₂
      simp only [Option.some.injEq, Node.branch.injEq] at hc₂
      exact hc₂.2

/-- A key has one value under a root. -/
theorem view_deterministic {v₁ v₂ : ValueRef} (canon : Canonical c)
    (h₁ : HasValue c r key v₁) (h₂ : HasValue c r key v₂) : v₁ = v₂ := by
  obtain ⟨p₁, x₁, hat₁, hk₁⟩ := h₁
  obtain ⟨p₂, x₂, hat₂, hk₂⟩ := h₂
  rcases List.prefix_or_prefix_of_prefix (carries_prefix hk₁) (carries_prefix hk₂) with
    ⟨q, rfl⟩ | ⟨q, rfl⟩
  · exact carries_unique_of_below canon hat₁ hk₁ hat₂ hk₂
  · exact (carries_unique_of_below canon hat₂ hk₂ hat₁ hk₁).symm

/- RUST-IMPL: mpt-materialize-scoped — `reconcile.rs::try_promote`, the
   `materialize_diff` under the read scope.  What a node reading under `s`
   derives from a root: a function of the content, the root and the scope, and
   of nothing about the node — not which peers served it, nor in what order. -/
def ScopedView (c : Content) (s : Scope) (root : Hash) (key : Path) (v : ValueRef) : Prop :=
  s.AdmitsKey key ∧ HasValue c root key v

/-- **Views converge.**  Every node that promoted the same head under the same
scope derives the same value for every key. -/
theorem scoped_view_deterministic {v₁ v₂ : ValueRef} (canon : Canonical c)
    (h₁ : ScopedView c s r key v₁) (h₂ : ScopedView c s r key v₂) : v₁ = v₂ :=
  view_deterministic canon h₁.2 h₂.2

theorem reach_or_boundary_aux (hc : CompleteWithin c st s r) (h : At c y q x) :
    ∀ p, Reach c st s r p y → s.AdmitsPath (p ++ q) →
      Reach c st s r (p ++ q) x ∨
        ∃ p' x', p' <+: p ++ q ∧ Reach c st s r p' x' ∧ Boundary s st p' x' := by
  induction h with
  | here =>
    intro p hr _
    exact Or.inl (by simpa using hr)
  | @step y n stp k rest x hcn hchild _ ih =>
    intro p hr hadm
    rcases (hc _ _ hr).1 with hheld | hb
    · have hadm' : s.AdmitsPath (p ++ stp) := by
        rw [← List.append_assoc] at hadm
        exact Scope.admitsPath_of_append hadm
      have hr' : Reach c st s r (p ++ stp) k :=
        Reach.child hr hheld (held_not_boundary hheld) hcn hchild hadm'
      have := ih (p ++ stp) hr' (by rw [List.append_assoc]; exact hadm)
      rwa [List.append_assoc] at this
    · exact Or.inr ⟨p, y, List.prefix_append _ _, hr, hb⟩

/-- **A complete scoped node can read its view.**  Under a root complete within
the scope, every admitted key with a value has its value-carrying node held —
or the key lies under a boundary the walk stopped at, a position the serving
peer refused. -/
theorem admitted_key_readable {v : ValueRef} (hc : CompleteWithin c st s r)
    (hkey : s.AdmitsKey key) (hv : HasValue c r key v) :
    (∃ p x, At c r p x ∧ CarriesKey c x p key v ∧ st.held x) ∨
      ∃ p' x', p' <+: key ∧ Reach c st s r p' x' ∧ Boundary s st p' x' := by
  obtain ⟨p, x, hat, hk⟩ := hv
  have hp : p <+: key := carries_prefix hk
  have hadm : s.AdmitsPath p :=
    Scope.admitsPath_of_prefix (Scope.admitsPath_of_admitsKey hkey) hp
  have hroot : Reach c st s r [] r := Reach.root (Scope.admitsPath_of_prefix hadm List.nil_prefix)
  rcases reach_or_boundary_aux hc hat [] hroot (by simpa using hadm) with hr | ⟨p', x', hpre, hr', hb⟩
  · simp only [List.nil_append] at hr
    rcases (hc _ _ hr).1 with hheld | hb
    · exact Or.inl ⟨p, x, hat, hk, hheld⟩
    · exact Or.inr ⟨p, x, hp, hr, hb⟩
  · simp only [List.nil_append] at hpre
    exact Or.inr ⟨p', x', hpre.trans hp, hr', hb⟩

/-! ## The fetch terminates, and a stuck fetch is complete -/

variable {heads : Hash → Prop}

/- RUST-IMPL: mpt-fetch-progress — `reconcile.rs::fetch_pending`, `learned`:
   one round commits what the responder served for the positions the walk
   asked about.  Each step is one such item — a node, a refusal, or a value —
   and is a `ScopedSync.Learn` step, so everything `reachable_confined` says
   holds of a fetching delegate. -/
inductive FetchStep (c : Content) (s : Scope) (heads : Hash → Prop) (root : Hash) :
    Store → Store → Prop where
  | node {st : Store} {p : Path} {x : Hash} {n : Node} :
      Reach c st s root p x → ¬ st.held x → ServeNode c s heads ⟨root, p, x⟩ x n →
      FetchStep c s heads root st { st with held := fun y => y = x ∨ st.held y }
  | redact {st : Store} {p : Path} {x : Hash} :
      Reach c st s root p x → ¬ st.held x → ¬ st.redacted p x → Redacts c s heads ⟨root, p, x⟩ x →
      FetchStep c s heads root st
        { st with redacted := fun q y => (q = p ∧ y = x) ∨ st.redacted q y }
  | value {st : Store} {p : Path} {x : Hash} {n : Node} {v : Hash} :
      Reach c st s root p x → st.held x → c x = some n → n.valueHash = some v →
      ¬ st.heldValue v → ServeValue c s heads ⟨root, p, v⟩ v →
      FetchStep c s heads root st { st with heldValue := fun y => y = v ∨ st.heldValue y }

theorem FetchStep.learn {st st' : Store} (h : FetchStep c s heads r st st') : Learn c s heads st st' := by
  cases h with
  | node _ _ served => exact Learn.node served
  | redact _ _ _ refused => exact Learn.redacted refused
  | value _ _ _ _ _ served => exact Learn.value served

/-- The origin's trie is finite: a list names every node, every position, and
every out-of-line value reachable from the root. -/
structure Bounded (c : Content) (root : Hash) where
  nodes : List Hash
  positions : List (Path × Hash)
  values : List Hash
  node_mem : ∀ p x, At c root p x → x ∈ nodes
  position_mem : ∀ p x, At c root p x → (p, x) ∈ positions
  value_mem : ∀ p x n v, At c root p x → c x = some n → n.valueHash = some v → v ∈ values

section Measure

variable {α : Type} {P Q : α → Prop} [DecidablePred P] [DecidablePred Q]

theorem filter_length_le_of_imp {l : List α} (hpq : ∀ a, Q a → P a) :
    (l.filter fun a => decide (Q a)).length ≤ (l.filter fun a => decide (P a)).length := by
  induction l with
  | nil => exact Nat.le_refl _
  | cons b l ih =>
    by_cases hq : Q b
    · have hp := hpq b hq
      simp only [List.filter_cons, hq, hp, decide_true, List.length_cons, ↓reduceIte]
      omega
    · by_cases hp : P b
      · simp only [List.filter_cons, hq, hp, decide_true, decide_false, List.length_cons,
          ↓reduceIte, Bool.false_eq_true]
        omega
      · simp only [List.filter_cons, hq, hp, decide_false, ↓reduceIte, Bool.false_eq_true]
        exact ih

theorem filter_length_lt_of_imp {l : List α} (hpq : ∀ a, Q a → P a) (a : α) (ha : a ∈ l)
    (hp : P a) (hq : ¬ Q a) :
    (l.filter fun a => decide (Q a)).length < (l.filter fun a => decide (P a)).length := by
  induction l with
  | nil => exact absurd ha (List.not_mem_nil)
  | cons b l ih =>
    rcases List.mem_cons.mp ha with rfl | hmem
    · simp only [List.filter_cons, hq, hp, decide_true, decide_false, List.length_cons,
        ↓reduceIte, Bool.false_eq_true]
      exact Nat.lt_succ_of_le (filter_length_le_of_imp hpq)
    · have := ih hmem
      by_cases hqb : Q b
      · have hpb := hpq b hqb
        simp only [List.filter_cons, hqb, hpb, decide_true, List.length_cons, ↓reduceIte]
        omega
      · by_cases hpb : P b
        · simp only [List.filter_cons, hqb, hpb, decide_true, decide_false, List.length_cons,
            ↓reduceIte, Bool.false_eq_true]
          omega
        · simp only [List.filter_cons, hqb, hpb, decide_false, ↓reduceIte, Bool.false_eq_true]
          exact this

end Measure

open Classical in
/-- How many elements of `l` satisfy `P`. -/
noncomputable def count {α : Type} (l : List α) (P : α → Prop) : Nat :=
  (l.filter fun a => decide (P a)).length

theorem count_lt_of_imp {α : Type} {l : List α} {P Q : α → Prop} (hpq : ∀ a, Q a → P a) (a : α)
    (ha : a ∈ l) (hp : P a) (hq : ¬ Q a) : count l Q < count l P := by
  unfold count
  exact @filter_length_lt_of_imp _ _ _ (fun a => Classical.propDecidable (P a))
    (fun a => Classical.propDecidable (Q a)) l hpq a ha hp hq

/-- What a fetch has left to learn: the bounded nodes not yet held, not yet
refused, and the bounded values not yet held. -/
noncomputable def remaining (b : Bounded c r) (st : Store) : Nat :=
  count b.nodes (fun x => ¬ st.held x) + count b.positions (fun px => ¬ st.redacted px.1 px.2) +
    count b.values (fun v => ¬ st.heldValue v)

theorem remaining_lt {st st' : Store} (b : Bounded c r) (hstep : FetchStep c s heads r st st') :
    remaining b st' < remaining b st := by
  cases hstep with
  | @node p x n hr _ _ =>
    have hx : x ∈ b.nodes := b.node_mem p x hr.at
    have hlt : count b.nodes (fun y => ¬ (y = x ∨ st.held y)) < count b.nodes (fun y => ¬ st.held y) :=
      count_lt_of_imp (fun _ h hy => h (Or.inr hy)) x hx (by assumption) (fun h => h (Or.inl rfl))
    simp only [remaining]
    omega
  | @redact p x hr _ _ _ =>
    have hpx : (p, x) ∈ b.positions := b.position_mem p x hr.at
    have hlt : count b.positions (fun qy => ¬ ((qy.1 = p ∧ qy.2 = x) ∨ st.redacted qy.1 qy.2)) <
        count b.positions (fun qy => ¬ st.redacted qy.1 qy.2) :=
      count_lt_of_imp (fun _ h hy => h (Or.inr hy)) (p, x) hpx (by assumption)
        (fun h => h (Or.inl ⟨rfl, rfl⟩))
    simp only [remaining]
    omega
  | @value p x n v hr _ hcn hv _ _ =>
    have hv' : v ∈ b.values := b.value_mem p x n v hr.at hcn hv
    have hlt : count b.values (fun y => ¬ (y = v ∨ st.heldValue y)) <
        count b.values (fun y => ¬ st.heldValue y) :=
      count_lt_of_imp (fun _ h hy => h (Or.inr hy)) v hv' (by assumption) (fun h => h (Or.inl rfl))
    simp only [remaining]
    omega

/-- **The fetch terminates.**  No infinite sequence of fetch steps exists over a
finite trie: every step learns something the bound counts. -/
theorem fetch_terminates (b : Bounded c r) :
    ¬ ∃ f : Nat → Store, ∀ i, FetchStep c s heads r (f i) (f (i + 1)) := by
  rintro ⟨f, hf⟩
  have hdec : ∀ i, remaining b (f i) + i ≤ remaining b (f 0) := by
    intro i
    induction i with
    | zero => exact Nat.le_refl _
    | succ i ih =>
      have := remaining_lt b (hf i)
      omega
  have := hdec (remaining b (f 0) + 1)
  omega

/-- The origin's trie is whole: every position under the root names a node. -/
def Whole (c : Content) (root : Hash) : Prop := ∀ p x, At c root p x → ∃ n, c x = some n

/-- For a scoped peer the claimed hash is not consulted, so the want a walk
sends for a *value* — naming the value's hash at the node's position — is
admitted at the node. -/
theorem honest_value_want_admitted {prefixes : List Path} (hs : s.prefixes = some prefixes)
    (hhead : heads r) (hr : Reach c st s r p x) (claimed : Hash) :
    Admit c s heads ⟨r, p, claimed⟩ x := by
  unfold Admit
  rw [hs]
  exact ⟨hhead, hr.admits, hr.at⟩

/-- **A stuck fetch is complete.**  When a peer holding the root's head would
serve anything the walk still asks for, a store with no fetch step left is
complete within the scope.  `hadm` is the value-side assumption discussed in
the module comment. -/
theorem stuck_complete (hhead : heads r) (hwhole : Whole c r)
    (hadm : ∀ p x n, Reach c st s r p x → st.held x → c x = some n → AdmitsNode s p n)
    (hstuck : ∀ st', ¬ FetchStep c s heads r st st') : CompleteWithin c st s r := by
  intro p x hr
  have settle : ¬ st.held x → Boundary s st p x := by
    intro hheld
    obtain ⟨n, hcn⟩ := hwhole _ _ hr.at
    by_cases hn : AdmitsNode s p n
    · exact absurd (FetchStep.node hr hheld ⟨honest_want_admitted hhead hr, hcn, hn⟩) (hstuck _)
    · have hfull : ¬ s.IsFull := fun full => hn (admitsNode_of_full full p n)
      by_cases hred : st.redacted p x
      · exact ⟨hheld, fun inside => hn (no_redaction_inside_grant inside n), hred⟩
      · exact absurd
          (FetchStep.redact hr hheld hred ⟨hfull, honest_want_admitted hhead hr, n, hcn, hn⟩)
          (hstuck _)
  refine ⟨?_, fun hnb n v hcn hv => ?_⟩
  · by_cases hheld : st.held x
    · exact Or.inl hheld
    · exact Or.inr (settle hheld)
  · have hheld : st.held x := by
      by_cases hheld : st.held x
      · exact hheld
      · exact absurd (settle hheld) hnb
    by_cases hval : st.heldValue v
    · exact hval
    exfalso
    refine hstuck _ (FetchStep.value hr hheld hcn hv hval ⟨rfl, ?_⟩)
    cases hs : s.prefixes with
    | none => trivial
    | some _ => exact ⟨x, n, honest_value_want_admitted hs hhead hr v, hcn, hv,
        hadm _ _ _ hr hheld hcn⟩

/-- The promotion `try_promote` performs once the fetch has nothing left: with
`MptGc.State.complete` read as `CompleteWithin`, a stuck fetch enables
`MptGc.Promote`, whose other premises are the slot state `offer_head` wrote. -/
theorem stuck_fetch_promotes (m : MptGc.State) (hp : m.pending) (hret : m.retained)
    (hhead : heads r) (hwhole : Whole c r)
    (hadm : ∀ p x n, Reach c st s r p x → st.held x → c x = some n → AdmitsNode s p n)
    (hstuck : ∀ st', ¬ FetchStep c s heads r st st') :
    MptGc.Promote { m with complete := CompleteWithin c st s r }
      { m with
        complete := CompleteWithin c st s r
        pending := False
        active := True
        materialized := True } :=
  ⟨hp, hret, stuck_complete hhead hwhole hadm hstuck, rfl⟩

end Synchronicity.Convergence
