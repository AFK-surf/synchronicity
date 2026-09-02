import Mathlib.Data.Prod.Lex
import Mathlib.Data.List.MinMax
import Mathlib.Data.Set.Card
import Mathlib.Order.WellFounded
import Synchronicity.MptGc
import Synchronicity.ScopedSync

/-!
Convergence of mptsync, in the three pieces it decomposes into (§5.2, §5.3),
and the theorem that puts them back together (`converge`).

1. **Head selection is a join.**  `offer_head` adopts a head into the pending
   slot when it supersedes the greatest head recorded so far, under the
   lexicographic `(seq, root)` order — a `LinearOrder` on `Head`, so `adopt`
   is `max` and `select` is `List.maximum`.  `select_eq_of_mem_iff` says the
   head a node ends up with depends only on *which* heads it has heard, not on
   their order or multiplicity: two nodes that have heard the same heads hold
   the same one.  That the order is total is what §5.2's note about `seq`
   alone is about: ties in `seq` need `root` to break them.
   `adopt_supersedes`/`adopt_retains` are the two `MptGc` transitions the
   comparison chooses between.

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
   root.  `fetchStep_wf` bounds every fetch by the size of the origin's trie
   (`Bounded`: finitely many positions under the root); `stuck_complete` says
   a fetch with no step left has established `CompleteWithin`, which is the
   premise `try_promote` flips on (`stuck_fetch_promotes`).

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
  /-- The origin's publish sequence number. -/
  seq : ℕ
  /-- The trie root the head signs. -/
  root : Hash
  deriving DecidableEq

namespace Head

/-- The `(seq, root)` pair, lexicographically ordered. -/
def key (h : Head) : ℕ ×ₗ ℕ := toLex (h.seq, h.root)

theorem key_injective : Function.Injective key := by
  intro a b h
  cases a; cases b
  simpa [key] using h

/-- `SignedHead::supersedes` is the strict order of `(seq, root)`. -/
instance : LinearOrder Head := LinearOrder.lift' key key_injective

theorem lt_iff {a b : Head} : a < b ↔ a.seq < b.seq ∨ (a.seq = b.seq ∧ a.root < b.root) :=
  Prod.Lex.lt_iff

/-- The strict order, under the name the earlier statements used. -/
abbrev Lt (a b : Head) : Prop := a < b

end Head

/-- `reconcile.rs::offer_head`, `supersedes(floor)`: a head takes the slot
when it strictly beats the greatest head recorded, and is otherwise only
retained. -/
@[rust_impl "mpt-head-adopt"]
def adopt (floor : Option Head) (h : Head) : Option Head :=
  match floor with
  | none => some h
  | some f => if f < h then some h else some f

/-- The head a node holds after hearing `heads` in that order. -/
def select (heads : List Head) : Option Head := heads.foldl adopt none

/-- A head that supersedes the floor is adopted: this is the offer that takes
the pending slot, `MptGc.OfferPending` at the new head's root. -/
theorem adopt_supersedes {f h : Head} (hlt : f < h) (m : MptGc.State) :
    adopt (some f) h = some h ∧ MptGc.OfferPending m { m with retained := True, pending := True } :=
  ⟨by simp [adopt, hlt], rfl⟩

/-- A head that does not supersede the floor leaves it standing: the `NotNewer`
arm, `MptGc.Retain` at the offered head's root. -/
theorem adopt_retains {f h : Head} (hlt : ¬ f < h) (m : MptGc.State) :
    adopt (some f) h = some f ∧ MptGc.Retain m { m with retained := True } :=
  ⟨by simp [adopt, hlt], rfl⟩

/-- Adoption over a floor is `max`. -/
theorem adopt_some (f h : Head) : adopt (some f) h = some (max f h) := by
  by_cases hlt : f < h
  · simp [adopt, hlt, max_eq_right hlt.le]
  · simp [adopt, hlt, max_eq_left (not_lt.mp hlt)]

theorem foldl_adopt_some (l : List Head) (a : Head) :
    l.foldl adopt (some a) = max (a : WithBot Head) l.maximum := by
  induction l generalizing a with
  | nil => rw [List.maximum_nil]; exact (max_eq_left (bot_le : (⊥ : WithBot Head) ≤ a)).symm
  | cons b l ih =>
    rw [List.foldl_cons, adopt_some, ih, List.maximum_cons, WithBot.coe_max, max_assoc]

/-- Selection is the maximum of the heads heard. -/
theorem select_eq_maximum (l : List Head) : select l = l.maximum := by
  cases l with
  | nil => rfl
  | cons a l => rw [select, List.foldl_cons, List.maximum_cons]; exact foldl_adopt_some l a

variable {l l' l₂ : List Head} {m m' : Head}

/-- The head selected is a maximum of the heads heard. -/
theorem select_max (h : select l = some m) : m ∈ l ∧ ∀ h' ∈ l, h' ≤ m :=
  List.maximum_eq_coe_iff.mp ((select_eq_maximum l).symm.trans h)

theorem select_none : select l = none ↔ l = [] := by
  rw [select_eq_maximum]; exact List.maximum_eq_bot

/-- A maximum, whenever there is one, is what selection finds. -/
theorem select_eq_of_max (hmem : m ∈ l) (hmax : ∀ h' ∈ l, h' ≤ m) : select l = some m :=
  (select_eq_maximum l).trans (List.maximum_eq_coe_iff.mpr ⟨hmem, hmax⟩)

/-- **Head selection converges.**  Two nodes that have heard the same heads —
in any order, any number of times — hold the same head. -/
theorem select_eq_of_mem_iff (h : ∀ x, x ∈ l ↔ x ∈ l') : select l = select l' := by
  cases hsel : select l with
  | none =>
    rw [select_none] at hsel
    subst hsel
    cases l' with
    | nil => rfl
    | cons x l' => exact absurd ((h x).mpr List.mem_cons_self) List.not_mem_nil
  | some m =>
    obtain ⟨hmem, hmax⟩ := select_max hsel
    exact (select_eq_of_max ((h m).mp hmem) fun h' hh' => hmax h' ((h h').mpr hh')).symm

/-- The floor never moves down: hearing more heads never selects a lesser one. -/
theorem select_mono (h : select l = some m) (h' : select (l ++ l₂) = some m') : ¬ m' < m :=
  not_lt.mpr ((select_max h').2 m (List.mem_append_left l₂ (select_max h).1))

/-! ## The derived view is a function of root and scope -/

variable {c : Content} {s : Scope} {st : Store} {r x y : Hash} {p q key : Path}

/-- The node at `p` carries the value of `key`: a leaf whose remaining key
completes `p`, or a branch value sitting exactly at `p`. -/
def CarriesKey (c : Content) (x : Hash) (p key : Path) (v : ValueRef) : Prop :=
  (∃ rest, c x = some (.leaf rest v) ∧ key = p ++ rest) ∨
  (∃ children, c x = some (.branch children (some v)) ∧ key = p)

/-- `trie.rs::Trie::get`: the value of a key under a root is what the descent
finds at the key's position. -/
@[rust_impl "mpt-trie-get"]
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

/-- `reconcile.rs::try_promote`, the `materialize_diff` under the read scope.
What a node reading under `s` derives from a root: a function of the content,
the root and the scope, and of nothing about the node — not which peers served
it, nor in what order. -/
@[rust_impl "mpt-materialize-scoped"]
def ScopedView (c : Content) (s : Scope) (root : Hash) (key : Path) (v : ValueRef) : Prop :=
  s.AdmitsKey key ∧ HasValue c root key v

/-- **Views converge.**  Every node that promoted the same head under the same
scope derives the same value for every key. -/
theorem scoped_view_deterministic {v₁ v₂ : ValueRef} (canon : Canonical c)
    (h₁ : ScopedView c s r key v₁) (h₂ : ScopedView c s r key v₂) : v₁ = v₂ :=
  view_deterministic canon h₁.2 h₂.2

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
  rcases reach_or_boundary hc hat [] hroot (by simpa using hadm) with hr | ⟨p', x', hpre, hr', hb⟩
  · simp only [List.nil_append] at hr
    rcases (hc _ _ hr).1 with hheld | hb
    · exact Or.inl ⟨p, x, hat, hk, hheld⟩
    · exact Or.inr ⟨p, x, hp, hr, hb⟩
  · simp only [List.nil_append] at hpre
    exact Or.inr ⟨p', x', hpre.trans hp, hr', hb⟩

/-! ## The fetch terminates, and a stuck fetch is complete -/

variable {heads : Hash → Prop}

/-- `reconcile.rs::fetch_pending`, `learned`: one round commits what the
responder served for the positions the walk asked about.  Each step is one
such item — a node, a refusal, or a value — and is a `ScopedSync.Learn` step,
so everything `reachable_confined` says holds of a fetching delegate. -/
@[rust_impl "mpt-fetch-progress"]
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

/-- The positions under a root, with what sits at each. -/
def positions (c : Content) (root : Hash) : Set (Path × Hash) :=
  { px | At c root px.1 px.2 }

/-- The origin's trie is finite: finitely many positions under the root. -/
def Bounded (c : Content) (root : Hash) : Prop := (positions c root).Finite

/-- The nodes under the root not yet held. -/
def missingNodes (c : Content) (root : Hash) (st : Store) : Set Hash :=
  { x | (∃ p, At c root p x) ∧ ¬ st.held x }

/-- The positions under the root not yet refused. -/
def missingRefusals (c : Content) (root : Hash) (st : Store) : Set (Path × Hash) :=
  { px | At c root px.1 px.2 ∧ ¬ st.redacted px.1 px.2 }

/-- The out-of-line values under the root not yet held. -/
def missingValues (c : Content) (root : Hash) (st : Store) : Set Hash :=
  { v | (∃ p x n, At c root p x ∧ c x = some n ∧ n.valueHash = some v) ∧ ¬ st.heldValue v }

theorem Bounded.missingNodes_finite (b : Bounded c r) (st : Store) :
    (missingNodes c r st).Finite :=
  (b.image Prod.snd).subset fun x ⟨⟨p, hat⟩, _⟩ => ⟨(p, x), hat, rfl⟩

theorem Bounded.missingRefusals_finite (b : Bounded c r) (st : Store) :
    (missingRefusals c r st).Finite :=
  b.subset fun _ h => h.1

theorem Bounded.missingValues_finite (b : Bounded c r) (st : Store) :
    (missingValues c r st).Finite := by
  have himage : ((fun px : Path × Hash => (c px.2).bind Node.valueHash) '' positions c r).Finite :=
    b.image _
  refine (himage.preimage (Option.some_injective _).injOn).subset ?_
  rintro v ⟨⟨p, x, n, hat, hcn, hv⟩, _⟩
  exact ⟨(p, x), hat, by simp [hcn, hv]⟩

/-- How much a fetch has left to learn. -/
noncomputable def remaining (c : Content) (root : Hash) (st : Store) : ℕ :=
  (missingNodes c root st).ncard + (missingRefusals c root st).ncard +
    (missingValues c root st).ncard

/-- One learned item removes exactly itself from what is missing, and nothing
else changes. -/
theorem remaining_lt {st st' : Store} (b : Bounded c r) (hstep : FetchStep c s heads r st st') :
    remaining c r st' < remaining c r st := by
  cases hstep with
  | @node p x n hr hheld _ =>
    have hsub : missingNodes c r { st with held := fun y => y = x ∨ st.held y } ⊆
        missingNodes c r st :=
      fun y ⟨hat, hy⟩ => ⟨hat, fun h => hy (Or.inr h)⟩
    have hss : missingNodes c r { st with held := fun y => y = x ∨ st.held y } ⊂
        missingNodes c r st :=
      (Set.ssubset_iff_of_subset hsub).mpr ⟨x, ⟨⟨p, hr.at⟩, hheld⟩, fun h => h.2 (Or.inl rfl)⟩
    have := Set.ncard_lt_ncard hss (b.missingNodes_finite st)
    simp only [remaining, missingNodes, missingRefusals, missingValues] at this ⊢
    omega
  | @redact p x hr _ hred _ =>
    have hsub : missingRefusals c r
        { st with redacted := fun q y => (q = p ∧ y = x) ∨ st.redacted q y } ⊆
        missingRefusals c r st :=
      fun y ⟨hat, hy⟩ => ⟨hat, fun h => hy (Or.inr h)⟩
    have hss : missingRefusals c r
        { st with redacted := fun q y => (q = p ∧ y = x) ∨ st.redacted q y } ⊂
        missingRefusals c r st :=
      (Set.ssubset_iff_of_subset hsub).mpr ⟨(p, x), ⟨hr.at, hred⟩, fun h => h.2 (Or.inl ⟨rfl, rfl⟩)⟩
    have := Set.ncard_lt_ncard hss (b.missingRefusals_finite st)
    simp only [remaining, missingNodes, missingRefusals, missingValues] at this ⊢
    omega
  | @value p x n v hr _ hcn hv hval _ =>
    have hsub : missingValues c r { st with heldValue := fun y => y = v ∨ st.heldValue y } ⊆
        missingValues c r st :=
      fun y ⟨hat, hy⟩ => ⟨hat, fun h => hy (Or.inr h)⟩
    have hss : missingValues c r { st with heldValue := fun y => y = v ∨ st.heldValue y } ⊂
        missingValues c r st :=
      (Set.ssubset_iff_of_subset hsub).mpr
        ⟨v, ⟨⟨p, x, n, hr.at, hcn, hv⟩, hval⟩, fun h => h.2 (Or.inl rfl)⟩
    have := Set.ncard_lt_ncard hss (b.missingValues_finite st)
    simp only [remaining, missingNodes, missingRefusals, missingValues] at this ⊢
    omega

/-- **The fetch terminates.**  Over a finite trie, the fetch relation is
well-founded: every step learns something the bound counts. -/
theorem fetchStep_wf (b : Bounded c r) :
    WellFounded (fun st' st : Store => FetchStep c s heads r st st') :=
  Subrelation.wf (fun h => remaining_lt b h) (InvImage.wf (remaining c r) Nat.lt_wfRel.wf)

/-- No infinite sequence of fetch steps exists over a finite trie. -/
theorem fetch_terminates (b : Bounded c r) :
    ¬ ∃ f : ℕ → Store, ∀ i, FetchStep c s heads r (f i) (f (i + 1)) := by
  rintro ⟨f, hf⟩
  obtain ⟨n, hn⟩ := @WellFounded.not_rel_apply_succ _ _ ⟨fetchStep_wf (s := s) (heads := heads) b⟩ f
  exact hn (hf n)

/-- The origin's trie is whole: every position under the root names a node. -/
def Whole (c : Content) (root : Hash) : Prop := ∀ p x, At c root p x → ∃ n, c x = some n

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
    · by_cases hred : st.redacted p x
      · exact ⟨hheld, fun inside => hn (no_redaction_inside_grant inside n), hred⟩
      · exact absurd
          (FetchStep.redact hr hheld hred ⟨honest_want_admitted hhead hr, n, hcn, hn⟩)
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
    by_cases hs : s.IsFull
    · unfold Scope.IsFull at hs; rw [hs]; trivial
    · obtain ⟨_, hp⟩ := Scope.prefixes_of_not_full hs
      rw [hp]
      exact ⟨x, n, honest_value_want_admitted hs hhead hr v, hcn, hv, hadm _ _ _ hr hheld hcn⟩

/-- The promotion `try_promote` performs once the fetch has nothing left: with
the root's `complete` bit read as `CompleteWithin` — the memo the drained walk
writes — a stuck fetch enables `MptGc.Promote`, whose other premises are the
slot state `offer_head` wrote. -/
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

/-! ## The three pieces together -/

/-- **Convergence.**  Two nodes that have heard the same heads select the same
head; if each has fetched that head's root under the same scope until no step
is left, each holds a trie complete within the scope, every admitted key has
the same value on both, and each can read it or finds it under a boundary its
peer refused.  The hypotheses are the assumptions listed in the module
comment, and nothing else. -/
theorem converge {l₁ l₂ : List Head} {h : Head} {st₁ st₂ : Store}
    (canon : Canonical c)
    (heard : ∀ x, x ∈ l₁ ↔ x ∈ l₂) (hsel : select l₁ = some h)
    (hhead : heads h.root) (hwhole : Whole c h.root)
    (hadm₁ : ∀ p x n, Reach c st₁ s h.root p x → st₁.held x → c x = some n → AdmitsNode s p n)
    (hadm₂ : ∀ p x n, Reach c st₂ s h.root p x → st₂.held x → c x = some n → AdmitsNode s p n)
    (hstuck₁ : ∀ st', ¬ FetchStep c s heads h.root st₁ st')
    (hstuck₂ : ∀ st', ¬ FetchStep c s heads h.root st₂ st') :
    select l₂ = some h ∧
    CompleteWithin c st₁ s h.root ∧ CompleteWithin c st₂ s h.root ∧
    (∀ key v₁ v₂, ScopedView c s h.root key v₁ → ScopedView c s h.root key v₂ → v₁ = v₂) ∧
    (∀ key v, ScopedView c s h.root key v →
      ((∃ p x, At c h.root p x ∧ CarriesKey c x p key v ∧ st₁.held x) ∨
        ∃ p' x', p' <+: key ∧ Reach c st₁ s h.root p' x' ∧ Boundary s st₁ p' x') ∧
      ((∃ p x, At c h.root p x ∧ CarriesKey c x p key v ∧ st₂.held x) ∨
        ∃ p' x', p' <+: key ∧ Reach c st₂ s h.root p' x' ∧ Boundary s st₂ p' x')) :=
  have hc₁ := stuck_complete hhead hwhole hadm₁ hstuck₁
  have hc₂ := stuck_complete hhead hwhole hadm₂ hstuck₂
  ⟨(select_eq_of_mem_iff heard).symm.trans hsel, hc₁, hc₂,
    fun _ _ _ h₁ h₂ => scoped_view_deterministic canon h₁ h₂,
    fun _ _ hv => ⟨admitted_key_readable hc₁ hv.1 hv.2, admitted_key_readable hc₂ hv.1 hv.2⟩⟩

end Synchronicity.Convergence

#lint
