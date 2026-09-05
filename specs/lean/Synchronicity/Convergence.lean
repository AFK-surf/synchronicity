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
   alone is about: ties in `seq` need `root` to break them.  `offer` is the
   node-level step — the heard list and every root's `MptGc` bits together —
   and `offer_step` says it is `MptGc.OfferPending` at the head's root when
   the head supersedes and `MptGc.Retain` when it does not.

2. **The derived view is a function of root and scope.**  `HasValue` is
   `Trie::get`; `view_deterministic` says a key has one value under a root, and
   `ScopedView` — what `materialize_diff` derives under a read scope — is
   therefore the same on every node that promoted the same head under the same
   scope. `ReadableOrRefused` distinguishes a held carrier from a refused
   boundary; it is not actual readability. `complete_reads_unobstructed`
   establishes `Readable`, including payload availability, when no refusal
   blocks the key. `Materialization` separately proves actual row equality.

3. **The fetch terminates, and a fetch that can take no step is complete.**
   `FetchStep` is one learned item — a node, a refusal, or a value — for a
   position the scoped walk is asking about, served by a peer holding the
   root.  `fetchStep_wf` bounds every fetch by the size of the origin's trie
   (`Bounded`: finitely many positions under the root); `stuck_complete` says
   a fetch with no step left has established `CompleteWithin`, which is the
   premise `try_promote` flips on (`stuck_fetch_promotes`).

What is assumed, and stated as hypotheses rather than proved: that a peer
holding the root's head stays reachable and answers; that the origin's trie
is whole (`Whole`) and finite (`Bounded`). `fetch_reaches_complete` proves a
finite successful trace exists. It does not prove delivery or fairness of the
network scheduler. Payload requests are key-authorized, so no separate
`Productive` admission assumption is needed. Rust's bounded retry/abandonment
policy remains outside this progress relation.
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
def key (h : Head) : ℕ ×ₗ Hash := toLex (h.seq, h.root)

theorem key_injective : Function.Injective key := by
  intro a b h
  cases a; cases b
  simpa [key] using h

/-- `SignedHead::supersedes` is the strict order of `(seq, root)`. -/
instance : LinearOrder Head := LinearOrder.lift' key key_injective

theorem lt_iff {a b : Head} : a < b ↔ a.seq < b.seq ∨ (a.seq = b.seq ∧ a.root < b.root) :=
  Prod.Lex.lt_iff

end Head

/-- `SignedHead::supersedes(floor)`: no floor, or strictly above it. -/
def Supersedes : Option Head → Head → Prop
  | none, _ => True
  | some f, h => f < h

instance : DecidableRel Supersedes := fun floor h =>
  match floor with
  | none => isTrue trivial
  | some f => inferInstanceAs (Decidable (f < h))

/-- `reconcile.rs::offer_head`, `supersedes(floor)`: a head takes the slot
when it strictly beats the greatest head recorded, and is otherwise only
retained. -/
@[rust_impl "mpt-head-adopt"]
def adopt (floor : Option Head) (h : Head) : Option Head :=
  if Supersedes floor h then some h else floor

/-- The head a node holds after hearing `heads` in that order. -/
def select (heads : List Head) : Option Head := heads.foldl adopt none

/-- Adoption over a floor is `max`. -/
theorem adopt_some (f h : Head) : adopt (some f) h = some (max f h) := by
  by_cases hlt : f < h
  · simp [adopt, Supersedes, hlt, max_eq_right hlt.le]
  · simp [adopt, Supersedes, hlt, max_eq_left (not_lt.mp hlt)]

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

/-- The roots a node holds a head for: those of the heads it heard.  This is
the `heads` the responder in `ScopedSync` consults. -/
def HeardRoots (l : List Head) : Hash → Prop := fun r => ∃ h ∈ l, h.root = r

theorem heardRoots_of_select (h : select l = some m) : HeardRoots l m.root :=
  ⟨m, (select_max h).1, rfl⟩

/-! ### The node: heard heads and every root's slots -/

/-- A node's head state: the heads it has heard, and each root's `MptGc`
bits. -/
structure NodeState where
  /-- The heads heard, in order. -/
  heard : List Head := []
  /-- Each root's slots. -/
  roots : Hash → MptGc.State := fun _ => {}

/-- `reconcile.rs::offer_head`, whole: the head is recorded, and its root takes
the pending slot or is merely retained according to `supersedes`. -/
def offer (n : NodeState) (h : Head) : NodeState where
  heard := n.heard ++ [h]
  roots := update n.roots h.root
    (if Supersedes (select n.heard) h then MptGc.OfferPending.post (n.roots h.root)
      else MptGc.Retain.post (n.roots h.root))

/-- Hearing one more head adopts it over the floor. -/
theorem offer_select (n : NodeState) (h : Head) :
    select (offer n h).heard = adopt (select n.heard) h := by
  simp [select, offer, List.foldl_append]

/-- A head that supersedes the floor is selected, and its root takes the
pending slot: `MptGc.OfferPending`. -/
theorem offer_supersedes {n : NodeState} {h : Head} (hs : Supersedes (select n.heard) h) :
    select (offer n h).heard = some h ∧
      MptGc.OfferPending.rel (n.roots h.root) ((offer n h).roots h.root) :=
  ⟨by rw [offer_select]; simp [adopt, hs], trivial, by simp [offer, hs]⟩

/-- A head that does not supersede the floor leaves it standing, and its root
is only retained: `MptGc.Retain`. -/
theorem offer_retains {n : NodeState} {h : Head} (hs : ¬ Supersedes (select n.heard) h) :
    select (offer n h).heard = select n.heard ∧
      MptGc.Retain.rel (n.roots h.root) ((offer n h).roots h.root) :=
  ⟨by rw [offer_select]; simp [adopt, hs], trivial, by simp [offer, hs]⟩

/-- Either way, hearing a head is a head-preserving `MptGc` step at its root
and leaves every other root alone. -/
theorem offer_step (n : NodeState) (h : Head) :
    MptGc.SyncStep (n.roots h.root) ((offer n h).roots h.root) ∧
      ∀ r, r ≠ h.root → (offer n h).roots r = n.roots r := by
  refine ⟨?_, fun r hr => Function.update_of_ne hr _ _⟩
  by_cases hs : Supersedes (select n.heard) h
  · exact ⟨.offerPending, rfl, (offer_supersedes hs).2⟩
  · exact ⟨.retain, rfl, (offer_retains hs).2⟩

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

/-- The structural outcome for a key: its carrier is held, or a peer refused
a boundary above it. This does not assert that its payload is readable. -/
def ReadableOrRefused (c : Content) (st : Store) (s : Scope) (root : Hash) (key : Path) (v : ValueRef) :
    Prop :=
  (∃ p x, At c root p x ∧ CarriesKey c x p key v ∧ x ∈ st.held) ∨
    ∃ p' x', p' <+: key ∧ Reach c st s root p' x' ∧ Boundary s st p' x'

/-- Under a complete scoped root, each admitted value has a held carrier or
a refused boundary. Actual readability is proved separately below. -/
theorem admitted_key_readable_or_refused {v : ValueRef} (hc : CompleteWithin c st s r)
    (hkey : s.AdmitsKey key) (hv : HasValue c r key v) : ReadableOrRefused c st s r key v := by
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
      Reach c st s root p x → x ∉ st.held → ServeNode c s heads ⟨root, p, x⟩ x n →
      FetchStep c s heads root st { st with held := insert x st.held }
  | redact {st : Store} {p : Path} {x : Hash} :
      Reach c st s root p x → x ∉ st.held → (p, x) ∉ st.redacted →
      Redacts c s heads ⟨root, p, x⟩ x →
      FetchStep c s heads root st { st with redacted := insert (p, x) st.redacted }
  | value {st : Store} {p : Path} {x : Hash} {n : Node} {v : Hash} :
      Reach c st s root p x → x ∈ st.held → c x = some n → n.valueHash = some v →
      v ∉ st.heldValue → ServeValue c s heads ⟨root, p, v⟩ v →
      FetchStep c s heads root st { st with heldValue := insert v st.heldValue }

theorem FetchStep.learn {st st' : Store} (h : FetchStep c s heads r st st') :
    Learn c s heads st st' := by
  cases h with
  | node _ _ served => exact Learn.node served
  | redact _ _ _ refused => exact Learn.redacted refused
  | value _ _ _ _ _ served => exact Learn.value served

/-- The positions under a root, with what sits at each. -/
def positions (c : Content) (root : Hash) : Set (Path × Hash) :=
  { px | At c root px.1 px.2 }

/-- The nodes under a root. -/
def nodes (c : Content) (root : Hash) : Set Hash := Prod.snd '' positions c root

/-- The out-of-line values under a root. -/
def values (c : Content) (root : Hash) : Set Hash :=
  { v | ∃ x ∈ nodes c root, ∃ n, c x = some n ∧ n.valueHash = some v }

/-- The origin's trie is finite: finitely many positions under the root. -/
def Bounded (c : Content) (root : Hash) : Prop := (positions c root).Finite

theorem Bounded.nodes_finite (b : Bounded c r) : (nodes c r).Finite := b.image _

theorem Bounded.values_finite (b : Bounded c r) : (values c r).Finite := by
  have himage : ((fun x => (c x).bind Node.valueHash) '' Convergence.nodes c r).Finite :=
    b.nodes_finite.image _
  refine (himage.preimage (Option.some_injective _).injOn).subset ?_
  rintro v ⟨x, hx, n, hcn, hv⟩
  exact ⟨x, hx, by simp [hcn, hv]⟩

/-- How much a fetch has left to learn: the nodes, positions and values under
the root it does not yet hold, refuse or hold. -/
noncomputable def remaining (c : Content) (root : Hash) (st : Store) : ℕ :=
  (nodes c root \ st.held).ncard + (positions c root \ st.redacted).ncard +
    (values c root \ st.heldValue).ncard

/-- Learning one item of a finite set of wanted items leaves fewer wanted. -/
theorem ncard_diff_insert_lt {α : Type} {S T : Set α} {a : α} (hS : S.Finite) (ha : a ∈ S)
    (hna : a ∉ T) : (S \ insert a T).ncard < (S \ T).ncard := by
  have : S \ insert a T = (S \ T) \ {a} := by
    ext; simp only [Set.mem_diff, Set.mem_insert_iff, Set.mem_singleton_iff]; tauto
  rw [this]
  exact Set.ncard_diff_singleton_lt_of_mem ⟨ha, hna⟩ hS.diff

/-- One learned item removes exactly itself from what is missing, and nothing
else changes. -/
theorem remaining_lt {st st' : Store} (b : Bounded c r) (hstep : FetchStep c s heads r st st') :
    remaining c r st' < remaining c r st := by
  cases hstep with
  | @node p x n hr hheld _ =>
    have := ncard_diff_insert_lt b.nodes_finite (a := x) ⟨(p, x), hr.at, rfl⟩ hheld
    simp only [remaining]; omega
  | @redact p x hr _ hred _ =>
    have := ncard_diff_insert_lt b (a := (p, x)) hr.at hred
    simp only [remaining]; omega
  | @value p x n v hr hheld hcn hv hval _ =>
    have := ncard_diff_insert_lt b.values_finite (a := v) ⟨x, ⟨(p, x), hr.at, rfl⟩, n, hcn, hv⟩ hval
    simp only [remaining]; omega

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
complete within the scope. -/
theorem stuck_complete (hhead : heads r) (hwhole : Whole c r)
    (hstuck : ∀ st', ¬ FetchStep c s heads r st st') : CompleteWithin c st s r := by
  intro p x hr
  have settle : x ∉ st.held → Boundary s st p x := by
    intro hheld
    obtain ⟨n, hcn⟩ := hwhole _ _ hr.at
    by_cases hn : AdmitsNode s p n
    · exact absurd (FetchStep.node hr hheld ⟨honest_want_admitted hhead hr, hcn, hn⟩) (hstuck _)
    · by_cases hred : (p, x) ∈ st.redacted
      · exact ⟨hheld, fun inside => hn (no_redaction_inside_grant inside n), hred⟩
      · exact absurd
          (FetchStep.redact hr hheld hred ⟨honest_want_admitted hhead hr, n, hcn, hn⟩)
          (hstuck _)
  refine ⟨?_, fun hnb n v hcn hv ha => ?_⟩
  · by_cases hheld : x ∈ st.held
    · exact Or.inl hheld
    · exact Or.inr (settle hheld)
  · have hheld : x ∈ st.held := by
      by_cases hheld : x ∈ st.held
      · exact hheld
      · exact absurd (settle hheld) hnb
    by_cases hval : v ∈ st.heldValue
    · exact hval
    exfalso
    refine hstuck _ (FetchStep.value hr hheld hcn hv hval ⟨rfl, fun hs => ?_⟩)
    exact ⟨x, n, honest_value_want_admitted hs hhead hr v, hcn, hv, ha⟩

/-- The promotion `try_promote` performs once the fetch has nothing left: with
the root's `complete` bit read as `CompleteWithin` — the memo the drained walk
writes — a stuck fetch enables `MptGc.Promote`, whose other premises are the
slot state `offer_head` wrote. -/
theorem stuck_fetch_promotes (m : MptGc.State) (hp : m.pending) (hret : m.retained)
    (hhead : heads r) (hwhole : Whole c r)
    (hstuck : ∀ st', ¬ FetchStep c s heads r st st') :
    MptGc.Promote.rel { m with complete := CompleteWithin c st s r }
      (MptGc.Promote.post { m with complete := CompleteWithin c st s r }) :=
  ⟨⟨hp, hret, stuck_complete hhead hwhole hstuck⟩, rfl⟩

/-! ## The three pieces together -/

/-- **Convergence.**  Two nodes that have heard the same heads select the same
head; if each has fetched that head's root under the same scope, from peers
that heard the same heads, until no step is left, each holds a trie complete
within the scope, and the abstract view is deterministic. Each value's carrier
is held or a boundary was refused; this last disjunction is not a successful
read. Actual readability additionally needs `Unobstructed` below. -/
theorem converge {l₁ l₂ : List Head} {h : Head} {st₁ st₂ : Store}
    (canon : Canonical c)
    (heard : ∀ x, x ∈ l₁ ↔ x ∈ l₂) (hsel : select l₁ = some h) (hwhole : Whole c h.root)
    (hstuck₁ : ∀ st', ¬ FetchStep c s (HeardRoots l₁) h.root st₁ st')
    (hstuck₂ : ∀ st', ¬ FetchStep c s (HeardRoots l₂) h.root st₂ st') :
    select l₂ = some h ∧
    CompleteWithin c st₁ s h.root ∧ CompleteWithin c st₂ s h.root ∧
    (∀ key v₁ v₂, ScopedView c s h.root key v₁ → ScopedView c s h.root key v₂ → v₁ = v₂) ∧
    (∀ key v, ScopedView c s h.root key v →
      ReadableOrRefused c st₁ s h.root key v ∧ ReadableOrRefused c st₂ s h.root key v) :=
  have hsel₂ : select l₂ = some h := (select_eq_of_mem_iff heard).symm.trans hsel
  have hc₁ := stuck_complete (heardRoots_of_select hsel) hwhole hstuck₁
  have hc₂ := stuck_complete (heardRoots_of_select hsel₂) hwhole hstuck₂
  ⟨hsel₂, hc₁, hc₂, fun _ _ _ h₁ h₂ => scoped_view_deterministic canon h₁ h₂,
    fun _ _ hv => ⟨admitted_key_readable_or_refused hc₁ hv.1 hv.2, admitted_key_readable_or_refused hc₂ hv.1 hv.2⟩⟩

/-- A finite fetch has a reachable terminal state, not just no infinite trace.
Network scheduling must eventually execute enabled steps for this existential
progress result to imply wall-clock convergence. -/
theorem fetch_reaches_complete (b : Bounded c r) (hhead : heads r) (whole : Whole c r)
    (start : Store) : ∃ finish, Relation.ReflTransGen (FetchStep c s heads r) start finish ∧
      CompleteWithin c finish s r := by
  classical
  induction start using (fetchStep_wf (s := s) (heads := heads) b).induction with
  | h st ih =>
    by_cases stuck : ∀ st', ¬ FetchStep c s heads r st st'
    · exact ⟨st, .refl, stuck_complete hhead whole stuck⟩
    · push Not at stuck
      obtain ⟨next, step⟩ := stuck
      obtain ⟨finish, trace, complete⟩ := ih next step
      exact ⟨finish, (Relation.ReflTransGen.single step).trans trace, complete⟩

/-- Actual readability includes the out-of-line bytes; a refusal is not a read. -/
def Readable (c : Content) (st : Store) (s : Scope) (root : Hash) (key : Path)
    (v : ValueRef) : Prop :=
  s.AdmitsKey key ∧ ∃ p x, At c root p x ∧ CarriesKey c x p key v ∧ x ∈ st.held ∧
    ∀ h, v = .outOfLine h → h ∈ st.heldValue

/-- No refused spine position blocks this key. This is an explicit availability
condition, not a consequence of permission to read the key. -/
def Unobstructed (c : Content) (st : Store) (s : Scope) (root : Hash) (key : Path) : Prop :=
  ∀ p x, p <+: key → Reach c st s root p x → ¬ Boundary s st p x

/-- Completeness gives a real read for an admitted key with no refused spine. -/
theorem complete_reads_unobstructed {v : ValueRef} (hc : CompleteWithin c st s r)
    (hkey : s.AdmitsKey key) (hv : HasValue c r key v)
    (clear : Unobstructed c st s r key) : Readable c st s r key v := by
  obtain ⟨p, x, hat, hk⟩ := hv
  have hp := carries_prefix hk
  have hadm := Scope.admitsPath_of_prefix (Scope.admitsPath_of_admitsKey hkey) hp
  have hr₀ : Reach c st s r [] r := .root (Scope.admitsPath_of_prefix hadm List.nil_prefix)
  rcases reach_or_boundary hc hat [] hr₀ (by simpa using hadm) with hr | ⟨q, y, hq, hreach, hb⟩
  · simp only [List.nil_append] at hr
    have nb := clear p x hp hr
    have held := (hc p x hr).1.resolve_right nb
    refine ⟨hkey, p, x, hat, hk, held, ?_⟩
    intro h eq
    subst v
    rcases hk with ⟨rest, hn, rfl⟩ | ⟨children, hn, rfl⟩
    · exact (hc _ x hr).2 nb _ h hn rfl hkey
    · exact (hc _ x hr).2 nb _ h hn rfl hkey
  · exact False.elim (clear q y (by simpa using hq.trans hp) hreach hb)

end Synchronicity.Convergence

#lint
