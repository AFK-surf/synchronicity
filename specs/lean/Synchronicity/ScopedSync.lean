import Synchronicity.Scope

/-!
mptsync over partial tries: the scoped fetch walk, its reference pruning, the
responder's authorization by position, and what a delegate can end up holding
(§5.2, §5.5).

`MptGc` abstracts a trie to one `complete` bit; this file is what that bit
means for a node reading under a scope, and why it may be believed:

- `At c root path hash` is the verified trie: content addressing (`c`) gives
  every hash one meaning, and a position is a descent through branch slots and
  extension prefixes exactly as `Trie::resolve_paths` performs it.
- `Reach` is the scoped `MissingWalk`, positionally: a child position is
  visited when its parent was visited, held, not a redaction boundary, and the
  child's position is admitted.  `CompleteWithin` is the walk draining with
  nothing missing — the fact `is_complete_scoped` memoizes.
- `ReachRef` is the same walk pruning against a reference root, and
  `prune_sound` is the §5.5 claim that the pruned walk may still write the
  completeness memo.  Its premise is that pruning happens only at positions
  the reference root's own scoped walk reached; `paired_reaches` discharges it
  for the pairing `paired_children` computes, because a held node is never a
  boundary (`held_not_boundary`).
- `Admit`/`ServeNode`/`ServeValue`/`Redacts` are the responder.  A scoped
  peer's claimed hash is never consulted (`admit_ignores_claim`); what is served
  sits at the claimed position of a root this node holds a head for, and reveals
  no key material outside the scope (`served_reveals_within_scope`).
- `Learn` is a delegate's store growing only by what scoped responders hand it,
  and `reachable_confined` is the privacy theorem: everything it holds was
  served at an admitted position with admitted coverage.

The model is positional, and so is Rust: `note_redacted` remembers a refusal
by hash *and position*, `next_batch` treats a refused position as a boundary
only when the node is absent — a held node, whatever a peer refused at some
position, is expanded wherever the walk meets it (`Boundary`) — and
`MissingWalk::seen` deduplicates expansions by hash inside the grant, where
`children_inside_grant_admitted` makes expansion position-independent, and by
hash and position above it.
-/

namespace Synchronicity.ScopedSync

open Synchronicity (Path Scope)

abbrev Hash := Nat

inductive ValueRef where
  | inline (bytes : Nat)
  | outOfLine (hash : Hash)

/-- `TrieNode`.  A branch's children are a partial map from slot to hash. -/
inductive Node where
  | leaf (keyRest : Path) (value : ValueRef)
  | ext (pre : Path) (child : Hash)
  | branch (children : Nat → Option Hash) (value : Option ValueRef)

/-- The out-of-line value a node references, if any (`value_hashes`). -/
def Node.valueHash : Node → Option Hash
  | .leaf _ (.outOfLine h) => some h
  | .branch _ (some (.outOfLine h)) => some h
  | _ => none

/-- What every hash names.  A node is verified against the hash it was requested
by, so one hash has one meaning everywhere. -/
abbrev Content := Hash → Option Node

variable {c : Content} {s : Scope} {r a b d x y k : Hash} {path p q rest stp key t : Path}
  {n : Node}

/-- `check_invariants`: an extension prefix is never empty.  This is the one
canonicality fact the positional reading needs — without it one position could
name two hashes. -/
def Canonical (c : Content) : Prop :=
  ∀ x pre child, c x = some (.ext pre child) → pre ≠ []

/-- `ChildOf node step child`: `child` hangs off `node` along the nibbles `step`
— one slot for a branch, the whole prefix for an extension. -/
inductive ChildOf : Node → Path → Hash → Prop where
  | branch {children : Nat → Option Hash} {value : Option ValueRef} {i : Nat} {child : Hash} :
      children i = some child → ChildOf (.branch children value) [i] child
  | ext {pre : Path} {child : Hash} : ChildOf (.ext pre child) pre child

/- RUST-IMPL: mpt-resolve-position — `trie.rs::Trie::resolve_paths`.  What
   stands at a position under a root, by descending the store and nothing
   else. -/
inductive At (c : Content) : Hash → Path → Hash → Prop where
  | here {root : Hash} : At c root [] root
  | step {root : Hash} {node : Node} {stp : Path} {child : Hash} {rest : Path} {hash : Hash} :
      c root = some node → ChildOf node stp child → At c child rest hash →
      At c root (stp ++ rest) hash

theorem At.ofChild (hc : c r = some n) (hchild : ChildOf n stp k) : At c r stp k := by
  simpa using At.step hc hchild At.here

theorem At.append (h₁ : At c a p b) (h₂ : At c b q d) : At c a (p ++ q) d := by
  induction h₁ with
  | here => simpa using h₂
  | step hc hchild _ ih => rw [List.append_assoc]; exact At.step hc hchild (ih h₂)

theorem At.inv (h : At c r path x) :
    (path = [] ∧ x = r) ∨
      ∃ n stp k rest, c r = some n ∧ ChildOf n stp k ∧ path = stp ++ rest ∧ At c k rest x := by
  cases h with
  | here => exact Or.inl ⟨rfl, rfl⟩
  | step hc hchild hrest => exact Or.inr ⟨_, _, _, _, hc, hchild, rfl, hrest⟩

/-- A position names one hash.  This is why a responder can answer "what sits
here" rather than "is this hash yours", and why a lie about a position resolves
to whatever genuinely sits there. -/
theorem At.unique (canon : Canonical c) (h₁ : At c r path a) (h₂ : At c r path b) : a = b := by
  induction h₁ generalizing b with
  | here =>
    rcases h₂.inv with ⟨_, rfl⟩ | ⟨n, stp, k, rest, hc, hchild, heq, _⟩
    · rfl
    · obtain ⟨hstp, _⟩ := List.append_eq_nil_iff.mp heq.symm
      subst hstp
      cases hchild with
      | ext => exact absurd rfl (canon _ _ _ hc)
  | step hc hchild _ ih =>
    rcases h₂.inv with ⟨heq, rfl⟩ | ⟨n', stp', k', rest', hc', hchild', heq, hrest'⟩
    · obtain ⟨hstp, _⟩ := List.append_eq_nil_iff.mp heq
      subst hstp
      cases hchild with
      | ext => exact absurd rfl (canon _ _ _ hc)
    · rw [hc] at hc'
      injection hc' with hnode
      subst hnode
      cases hchild with
      | branch hi =>
        cases hchild' with
        | branch hi' =>
          simp only [List.singleton_append, List.cons.injEq] at heq
          obtain ⟨rfl, rfl⟩ := heq
          rw [hi] at hi'
          injection hi' with hk
          subst hk
          exact ih hrest'
      | ext =>
        cases hchild' with
        | ext =>
          have := List.append_cancel_left heq
          subst this
          exact ih hrest'

/-- Descending one step is deterministic: what lies below `k` along `t` is what
lies below `r` along `stp ++ t`. -/
theorem At.step_inv (canon : Canonical c) (hc : c r = some n) (hchild : ChildOf n stp k)
    (h : At c r (stp ++ t) y) : At c k t y := by
  rcases h.inv with ⟨heq, rfl⟩ | ⟨n', stp', k', rest', hc', hchild', heq, hrest'⟩
  · obtain ⟨hstp, _⟩ := List.append_eq_nil_iff.mp heq
    subst hstp
    cases hchild with
    | ext => exact absurd rfl (canon _ _ _ hc)
  · rw [hc] at hc'
    injection hc' with hnode
    subst hnode
    cases hchild with
    | branch hi =>
      cases hchild' with
      | branch hi' =>
        simp only [List.singleton_append, List.cons.injEq] at heq
        obtain ⟨rfl, rfl⟩ := heq
        rw [hi] at hi'
        injection hi' with hk
        subst hk
        exact hrest'
    | ext =>
      cases hchild' with
      | ext =>
        have := List.append_cancel_left heq
        subst this
        exact hrest'

/-- A position below another is reached through it. -/
theorem At.split (canon : Canonical c) (h₂ : At c r p x) :
    ∀ {y : Hash}, At c r (p ++ q) y → At c x q y := by
  induction h₂ with
  | here => intro y h₁; simpa using h₁
  | step hc hchild _ ih =>
    intro y h₁
    rw [List.append_assoc] at h₁
    exact ih (At.step_inv canon hc hchild h₁)

/-- Nothing lies below a leaf. -/
theorem At.leaf_nil {value : ValueRef} (h : At c x q y) (hc : c x = some (.leaf rest value)) :
    q = [] ∧ y = x := by
  rcases h.inv with ⟨rfl, rfl⟩ | ⟨_, _, _, _, hc', hchild, _, _⟩
  · exact ⟨rfl, rfl⟩
  · rw [hc] at hc'
    injection hc' with hn
    subst hn
    cases hchild

/-! ## What a node reveals -/

/-- `Reveals path node q`: key material the node at `path` carries beyond its
child hashes.  A leaf spells a whole key, an inline branch value sits at a whole
key, an extension spells the position of its child.  A branch's out-of-line
value contributes only a hash, like every redacted child, and is not here. -/
inductive Reveals : Path → Node → Path → Prop where
  | leaf {path rest : Path} {value : ValueRef} : Reveals path (.leaf rest value) (path ++ rest)
  | ext {path pre : Path} {child : Hash} : Reveals path (.ext pre child) (path ++ pre)
  | branchValue {path : Path} {children : Nat → Option Hash} {bytes : Nat} :
      Reveals path (.branch children (some (.inline bytes))) path

/-- The keys whose record a node at `path` carries in the node itself: a leaf's
key, and an inline branch value's key. -/
inductive RevealsRecord : Path → Node → Path → Prop where
  | leaf {path rest : Path} {value : ValueRef} : RevealsRecord path (.leaf rest value) (path ++ rest)
  | branchValue {path : Path} {children : Nat → Option Hash} {bytes : Nat} :
      RevealsRecord path (.branch children (some (.inline bytes))) path

/-- Every key at which a node at `path` holds a value, however the value is
carried (`first_key_outside`'s question about a delegated origin's trie). -/
inductive SpellsKey : Path → Node → Path → Prop where
  | leaf {path rest : Path} {value : ValueRef} : SpellsKey path (.leaf rest value) (path ++ rest)
  | branchValue {path : Path} {children : Nat → Option Hash} {value : ValueRef} :
      SpellsKey path (.branch children (some value)) path

/- RUST-IMPL: mpt-scope-admits-node — `scope.rs::Scope::admits_node`.  A node
   is judged by what it reveals, not only by where it sits: a branch's child
   hashes are the spine itself and travel; an inline value, an extension
   prefix, and a leaf's key are key material and must be in scope. -/
def AdmitsNode (s : Scope) (path : Path) : Node → Prop
  | .branch _ none => True
  | .branch _ (some (.outOfLine _)) => True
  | .branch _ (some (.inline _)) => s.AdmitsKey path
  | .ext pre _ => s.AdmitsPath (path ++ pre)
  | .leaf keyRest _ => s.AdmitsKey (path ++ keyRest)

theorem admitsNode_of_full (h : s.IsFull) (path : Path) (n : Node) : AdmitsNode s path n := by
  cases n with
  | leaf rest value => exact Scope.admitsKey_of_containsSubtree (Scope.containsSubtree_of_full h _)
  | ext pre child => exact Scope.admitsPath_of_full h _
  | branch children value =>
    rcases value with _ | ⟨_ | _⟩
    · trivial
    · exact Scope.admitsKey_of_containsSubtree (Scope.containsSubtree_of_full h _)
    · trivial

/-- Inside the grant nothing is ever refused: once a position sits under a
granted prefix, every key its node spells does too.  This is what lets the walk
consult the redaction memo only above the grant. -/
theorem no_redaction_inside_grant (h : s.ContainsSubtree path) (n : Node) :
    AdmitsNode s path n := by
  cases n with
  | leaf rest value => exact Or.inl (Scope.containsSubtree_append h rest)
  | ext pre child => exact Scope.admitsPath_of_containsSubtree (Scope.containsSubtree_append h pre)
  | branch children value =>
    rcases value with _ | ⟨_ | _⟩
    · trivial
    · exact Or.inl h
    · trivial

/-- An admitted node reveals only admitted positions … -/
theorem reveals_admitted (hnode : AdmitsNode s path n) (hrev : Reveals path n q) :
    s.AdmitsPath q := by
  cases hrev with
  | leaf => exact Scope.admitsPath_of_admitsKey hnode
  | ext => exact hnode
  | branchValue => exact Scope.admitsPath_of_admitsKey hnode

/-- … and carries records only for admitted keys. -/
theorem revealsRecord_admitted (hnode : AdmitsNode s path n) (hrev : RevealsRecord path n key) :
    s.AdmitsKey key := by
  cases hrev with
  | leaf => exact hnode
  | branchValue => exact hnode

/- RUST-IMPL: mpt-first-key-outside — `trie.rs::Trie::first_key_outside`
   skips every position already inside a granted prefix.  Sound because no key
   spelled at or below such a position can leave the grant. -/
theorem keys_below_grant_admitted (h : s.ContainsSubtree path)
    (hkey : SpellsKey (path ++ q) n key) : s.AdmitsKey key := by
  cases hkey with
  | leaf => exact Or.inl (Scope.containsSubtree_append (Scope.containsSubtree_append h q) _)
  | branchValue => exact Or.inl (Scope.containsSubtree_append h q)

/-! ## The scoped walk -/

/-- A local store: nodes, out-of-line values, and the positions peers refused
a hash at (`redacted_nodes`, keyed by hash and path). -/
structure Store where
  held : Hash → Prop
  heldValue : Hash → Prop
  redacted : Path → Hash → Prop

variable {st : Store}

/- RUST-IMPL: mpt-walk-boundary — `trie.rs::MissingWalk::next_batch`, the
   `contains_subtree`/`is_redacted` skip on a failed load.  An absent hash
   refused at this position is satisfied rather than missing, but only above
   the grant.  A held node is never a boundary: a node refused at one position
   may be held from another it shares by structure, and holding it is what the
   walk is establishing. -/
def Boundary (s : Scope) (st : Store) (path : Path) (x : Hash) : Prop :=
  ¬ st.held x ∧ ¬ s.ContainsSubtree path ∧ st.redacted path x

theorem held_not_boundary (h : st.held x) : ¬ Boundary s st path x :=
  fun hb => hb.1 h

/- RUST-IMPL: mpt-walk-seen — `trie.rs::MissingWalk::seen_key`.  Inside the
   grant every child position is admitted, so expanding a node there does not
   depend on which of its positions the walk met it at; one expansion per hash
   is one per subtree.  Above the grant the key carries the position. -/
theorem children_inside_grant_admitted (h : s.ContainsSubtree path) (stp : Path) :
    s.AdmitsPath (path ++ stp) :=
  Scope.admitsPath_of_containsSubtree (Scope.containsSubtree_append h stp)

/- RUST-IMPL: mpt-walk-scoped — `trie.rs::MissingWalk::scoped` with no
   reference, and the child filter in `next_batch`: the root is on the frontier
   when its position is admitted, and a child is pushed when its position is.
   Stated positionally; see the module comment for `seen`. -/
inductive Reach (c : Content) (st : Store) (s : Scope) (root : Hash) : Path → Hash → Prop where
  | root : s.AdmitsPath [] → Reach c st s root [] root
  | child {path : Path} {hash : Hash} {node : Node} {stp : Path} {k : Hash} :
      Reach c st s root path hash → st.held hash → ¬ Boundary s st path hash →
      c hash = some node → ChildOf node stp k → s.AdmitsPath (path ++ stp) →
      Reach c st s root (path ++ stp) k

/-- An honest walk never asks for a position its scope does not admit, so an
out-of-scope request is a probe and not a race. -/
theorem Reach.admits (h : Reach c st s r path x) : s.AdmitsPath path := by
  cases h with
  | root h => exact h
  | child _ _ _ _ _ h => exact h

/-- Every position the walk claims is real: it resolves under the root to the
hash claimed for it (`a_claimed_position_resolves_to_what_is_really_there`). -/
theorem Reach.at (h : Reach c st s r path x) : At c r path x := by
  induction h with
  | root => exact At.here
  | child _ _ _ hc hchild _ ih => exact ih.append (At.ofChild hc hchild)

/- RUST-IMPL: mpt-complete-scoped — `trie.rs::Trie::is_complete_scoped`.  The
   walk drains with nothing missing: every position it reaches is held or a
   boundary, and every node it expands has its out-of-line value. -/
def CompleteWithin (c : Content) (st : Store) (s : Scope) (root : Hash) : Prop :=
  ∀ path x, Reach c st s root path x →
    (st.held x ∨ Boundary s st path x) ∧
    (¬ Boundary s st path x → ∀ n v, c x = some n → n.valueHash = some v → st.heldValue v)

/- RUST-IMPL: mpt-walk-prune-reference — `trie.rs::MissingWalk::next_batch`,
   `reference == Some(hash)`.  The walk with a reference: a position whose
   wanted hash the reference pairing also names is skipped, and nothing below
   it is visited. -/
inductive ReachRef (c : Content) (st : Store) (s : Scope) (prune : Path → Hash → Prop)
    (root : Hash) : Path → Hash → Prop where
  | root : s.AdmitsPath [] → ¬ prune [] root → ReachRef c st s prune root [] root
  | child {path : Path} {hash : Hash} {node : Node} {stp : Path} {k : Hash} :
      ReachRef c st s prune root path hash → st.held hash → ¬ Boundary s st path hash →
      c hash = some node → ChildOf node stp k → s.AdmitsPath (path ++ stp) →
      ¬ prune (path ++ stp) k →
      ReachRef c st s prune root (path ++ stp) k

variable {prune : Path → Hash → Prop}

/-- The pruned walk visits a subset of the unpruned one, so its requests are
honest too. -/
theorem ReachRef.reach (h : ReachRef c st s prune r path x) : Reach c st s r path x := by
  induction h with
  | root h _ => exact Reach.root h
  | child _ hheld hb hc hchild hadm _ ih => exact Reach.child ih hheld hb hc hchild hadm

/-- `fetch_pending`'s walk drained: nothing missing among the positions the
pruned walk visited. -/
def DrainedWithin (c : Content) (st : Store) (s : Scope) (prune : Path → Hash → Prop)
    (root : Hash) : Prop :=
  ∀ path x, ReachRef c st s prune root path x →
    (st.held x ∨ Boundary s st path x) ∧
    (¬ Boundary s st path x → ∀ n v, c x = some n → n.valueHash = some v → st.heldValue v)

/-- Every position the unpruned walk over `H` reaches is either reached by the
pruned walk, or reached by the reference root's own walk. -/
theorem reach_of_pruned_or_reference {R H : Hash}
    (hprune : ∀ path x, prune path x → Reach c st s R path x)
    (h : Reach c st s H path x) :
    ReachRef c st s prune H path x ∨ Reach c st s R path x := by
  induction h with
  | root hadm =>
    by_cases hp : prune [] H
    · exact Or.inr (hprune _ _ hp)
    · exact Or.inl (ReachRef.root hadm hp)
  | @child path _ _ stp k _ hheld hb hc hchild hadm ih =>
    rcases ih with viaH | viaR
    · by_cases hp : prune (path ++ stp) k
      · exact Or.inr (hprune _ _ hp)
      · exact Or.inl (ReachRef.child viaH hheld hb hc hchild hadm hp)
    · exact Or.inr (Reach.child viaR hheld hb hc hchild hadm)

/- RUST-IMPL: mpt-complete-memo — `reconcile.rs::fetch_pending`, the
   `note_complete(scope.memo_key(pending.root))` after a pruned walk drains.
   The §5.5 soundness claim: pruning against a root held whole within the scope
   is sound because every boundary the walk stops at is a scope edge — here,
   because everything pruned lies under a position the reference root's own
   scoped walk reached, and that walk found nothing missing. -/
theorem prune_sound {R H : Hash}
    (hR : CompleteWithin c st s R)
    (hprune : ∀ path x, prune path x → Reach c st s R path x)
    (hH : DrainedWithin c st s prune H) :
    CompleteWithin c st s H := by
  intro path x h
  rcases reach_of_pruned_or_reference hprune h with viaH | viaR
  · exact hH _ _ viaH
  · exact hR _ _ viaR

/- RUST-IMPL: mpt-walk-paired-children — `trie.rs::paired_children`, and the
   `reference_node` load in `next_batch`.  The reference hash carried for a
   position: the reference root descended through *held* nodes along the same
   steps (same branch slot, equal extension prefix); a shape mismatch or an
   absent node ends the pairing. -/
inductive Paired (c : Content) (st : Store) (s : Scope) (R : Hash) : Path → Hash → Prop where
  | root : s.AdmitsPath [] → Paired c st s R [] R
  | child {path : Path} {ref : Hash} {node : Node} {stp : Path} {k : Hash} :
      Paired c st s R path ref → st.held ref → c ref = some node → ChildOf node stp k →
      s.AdmitsPath (path ++ stp) → Paired c st s R (path ++ stp) k

theorem Paired.at (h : Paired c st s r path x) : At c r path x := by
  induction h with
  | root => exact At.here
  | child _ _ hc hchild _ ih => exact ih.append (At.ofChild hc hchild)

/-- Rust's pairing walks positions the reference root's scoped walk reached:
the pairing loads each reference node, and a held node is never a boundary. -/
theorem paired_reaches (h : Paired c st s r path x) : Reach c st s r path x := by
  induction h with
  | root hadm => exact Reach.root hadm
  | child _ hheld hc hchild hadm ih =>
    exact Reach.child ih hheld (held_not_boundary hheld) hc hchild hadm

/- RUST-IMPL: mpt-fetch-reference — `reconcile.rs::fetch_pending`, the
   reference chosen only when `is_complete_scoped(head.root, scope)`.  With the
   pairing Rust computes, the memo written after the pruned walk is true. -/
theorem prune_sound_paired {R H : Hash}
    (hR : CompleteWithin c st s R)
    (hH : DrainedWithin c st s (Paired c st s R) H) :
    CompleteWithin c st s H :=
  prune_sound hR (fun _ _ hp => paired_reaches hp) hH

/-- The completeness the memo records is exactly what promotion needs: every
admitted position under the root is held or under a boundary, so a scoped
reader finds nothing missing (`MptGc.State.complete` for a scoped node). -/
theorem complete_position_held (hc : CompleteWithin c st s r) (h : Reach c st s r path x) :
    st.held x ∨ Boundary s st path x :=
  (hc _ _ h).1

/-! ## The scoped diff -/

/- RUST-IMPL: mpt-diff-scoped — `diff.rs::Trie::diff_walk`, the `admits_path`
   skip, and `Trie::cursor_at` reading a redacted absence as empty.  The
   positions the promotion diff reads under one root: children of admitted
   positions whose node loaded.  Pruning at equal hashes only removes
   positions, so this over-approximates what the diff touches. -/
inductive DiffReach (c : Content) (st : Store) (s : Scope) (root : Hash) : Path → Hash → Prop where
  | root : s.AdmitsPath [] → DiffReach c st s root [] root
  | child {path : Path} {hash : Hash} {node : Node} {stp : Path} {k : Hash} :
      DiffReach c st s root path hash → st.held hash → c hash = some node → ChildOf node stp k →
      s.AdmitsPath (path ++ stp) → DiffReach c st s root (path ++ stp) k

theorem diffReach_reaches (h : DiffReach c st s r path x) : Reach c st s r path x := by
  induction h with
  | root hadm => exact Reach.root hadm
  | child _ hheld hc hchild hadm ih =>
    exact Reach.child ih hheld (held_not_boundary hheld) hc hchild hadm

/-- Promotion's materialization never fails on an absence that is the design
working: over a root complete within the scope, every position the scoped diff
reads is held, or is an absent hash refused at some position, which `cursor_at`
asks about (`is_redacted(hash, None)`) and reads as empty. -/
theorem diff_never_misses (hcomplete : CompleteWithin c st s r)
    (h : DiffReach c st s r path x) : st.held x ∨ (¬ st.held x ∧ ∃ p, st.redacted p x) := by
  rcases (hcomplete _ _ (diffReach_reaches h)).1 with held | ⟨absent, _, redacted⟩
  · exact Or.inl held
  · exact Or.inr ⟨absent, _, redacted⟩

/-! ## The responder -/

/-- One want of `GetNodes`/`GetValues`: the root, the position claimed, and the
hash claimed to sit there. -/
structure Want where
  root : Hash
  path : Path
  claimed : Hash

variable {heads : Hash → Prop} {w : Want}

/- RUST-IMPL: mpt-serve-admit — `net/mpt.rs::admit`.  For an unscoped peer the
   claimed hash is the answer.  For a scoped peer the position is the only
   authorization: the root must be one this node holds a head for, the position
   must be admitted, and what is served is what the descent finds there. -/
def Admit (c : Content) (s : Scope) (heads : Hash → Prop) (w : Want) (x : Hash) : Prop :=
  match s.prefixes with
  | none => x = w.claimed
  | some _ => heads w.root ∧ s.AdmitsPath w.path ∧ At c w.root w.path x

/- RUST-IMPL: mpt-serve-node — `net/mpt.rs`, the `GetNodes` arm: an admitted
   position's node travels only if what it reveals is in scope. -/
def ServeNode (c : Content) (s : Scope) (heads : Hash → Prop) (w : Want) (x : Hash) (n : Node) :
    Prop :=
  Admit c s heads w x ∧ c x = some n ∧ AdmitsNode s w.path n

/-- The `GetNodes` arm's `redacted`: an admitted position whose node reveals
key material outside the scope. -/
def Redacts (c : Content) (s : Scope) (heads : Hash → Prop) (w : Want) (x : Hash) : Prop :=
  ¬ s.IsFull ∧ Admit c s heads w x ∧ ∃ n, c x = some n ∧ ¬ AdmitsNode s w.path n

/- RUST-IMPL: mpt-serve-value — `net/mpt.rs`, the `GetValues` arm: a value is
   authorized by the node that carries it, resolved at the claimed position and
   judged by what it reveals. -/
def ServeValue (c : Content) (s : Scope) (heads : Hash → Prop) (w : Want) (v : Hash) : Prop :=
  v = w.claimed ∧
    match s.prefixes with
    | none => True
    | some _ => ∃ x n, Admit c s heads w x ∧ c x = some n ∧ n.valueHash = some v ∧
        AdmitsNode s w.path n

/-- A hash cannot be authorized; a position can.  For a scoped peer the answer
does not depend on the hash it claimed. -/
theorem admit_ignores_claim {prefixes : List Path} (h : s.prefixes = some prefixes) :
    Admit c s heads ⟨r, path, a⟩ x ↔ Admit c s heads ⟨r, path, b⟩ x := by
  unfold Admit; rw [h]

/-- The root a request names must be one this node holds a head for. -/
theorem admit_requires_head {prefixes : List Path} (h : s.prefixes = some prefixes)
    (ha : Admit c s heads w x) : heads w.root := by
  unfold Admit at ha; rw [h] at ha; exact ha.1

/-- What is served sits at the claimed position of a head root. -/
theorem admit_resolves {prefixes : List Path} (h : s.prefixes = some prefixes)
    (ha : Admit c s heads w x) : s.AdmitsPath w.path ∧ At c w.root w.path x := by
  unfold Admit at ha; rw [h] at ha; exact ha.2

/-- A lie about the position resolves to whatever genuinely sits there, and to
nothing else. -/
theorem admit_unique {prefixes : List Path} (canon : Canonical c) (h : s.prefixes = some prefixes)
    (ha : Admit c s heads w a) (hb : Admit c s heads w b) : a = b :=
  At.unique canon (admit_resolves h ha).2 (admit_resolves h hb).2

/-- Redaction is a boundary, never an absence inside the grant. -/
theorem redacts_only_above_grant (h : Redacts c s heads w x) : ¬ s.ContainsSubtree w.path :=
  fun inside =>
    let ⟨_, _, n, _, refused⟩ := h
    refused (no_redaction_inside_grant inside n)

/-- Nothing served to a scoped peer spells a key or a position outside its
scope … -/
theorem served_reveals_within_scope (h : ServeNode c s heads w x n) (hrev : Reveals w.path n q) :
    s.AdmitsPath q :=
  reveals_admitted h.2.2 hrev

/-- … and no record it carries belongs to a key outside it. -/
theorem served_records_within_scope (h : ServeNode c s heads w x n)
    (hrec : RevealsRecord w.path n key) : s.AdmitsKey key :=
  revealsRecord_admitted h.2.2 hrec

/-- An honest walk's want is admitted by a peer that holds the root's head:
the position it claims is in scope and really holds the hash it claims. -/
theorem honest_want_admitted (hhead : heads r) (h : Reach c st s r path x) :
    Admit c s heads ⟨r, path, x⟩ x := by
  unfold Admit
  split
  · rfl
  · exact ⟨hhead, h.admits, h.at⟩

/-! ## What a delegate can hold -/

/- RUST-IMPL: mpt-learn-scoped — `reconcile.rs::fetch_pending`: `put_node`
   and `put_value` of what the responder served, and `note_redacted` of what it
   refused.  A delegate's foreign nodes come from nowhere else. -/
inductive Learn (c : Content) (s : Scope) (heads : Hash → Prop) : Store → Store → Prop where
  | node {st : Store} {w : Want} {x : Hash} {n : Node} :
      ServeNode c s heads w x n →
      Learn c s heads st { st with held := fun y => y = x ∨ st.held y }
  | value {st : Store} {w : Want} {v : Hash} :
      ServeValue c s heads w v →
      Learn c s heads st { st with heldValue := fun y => y = v ∨ st.heldValue y }
  | redacted {st : Store} {w : Want} {x : Hash} :
      Redacts c s heads w x →
      Learn c s heads st
        { st with redacted := fun p y => (p = w.path ∧ y = x) ∨ st.redacted p y }

def Initial : Store := ⟨fun _ => False, fun _ => False, fun _ _ => False⟩

inductive Reachable (c : Content) (s : Scope) (heads : Hash → Prop) : Store → Prop where
  | initial : Reachable c s heads Initial
  | next {st st' : Store} : Reachable c s heads st → Learn c s heads st st' → Reachable c s heads st'

/-- Everything a delegate holds was served or refused by the rules above. -/
def Confined (c : Content) (s : Scope) (heads : Hash → Prop) (st : Store) : Prop :=
  (∀ x, st.held x → ∃ w n, ServeNode c s heads w x n) ∧
  (∀ v, st.heldValue v → ∃ w, ServeValue c s heads w v) ∧
  (∀ p x, st.redacted p x → ∃ w, w.path = p ∧ Redacts c s heads w x)

theorem initial_confined : Confined c s heads Initial :=
  ⟨fun _ h => h.elim, fun _ h => h.elim, fun _ _ h => h.elim⟩

theorem confined_step {st' : Store} (hinv : Confined c s heads st) (hstep : Learn c s heads st st') :
    Confined c s heads st' := by
  obtain ⟨nodes, values, refusals⟩ := hinv
  cases hstep with
  | node served =>
    refine ⟨fun y h => ?_, values, refusals⟩
    rcases h with rfl | old
    · exact ⟨_, _, served⟩
    · exact nodes _ old
  | value served =>
    refine ⟨nodes, fun y h => ?_, refusals⟩
    rcases h with rfl | old
    · exact ⟨_, served⟩
    · exact values _ old
  | redacted refused =>
    refine ⟨nodes, values, fun p y h => ?_⟩
    rcases h with ⟨rfl, rfl⟩ | old
    · exact ⟨_, rfl, refused⟩
    · exact refusals _ _ old

theorem reachable_confined (h : Reachable c s heads st) : Confined c s heads st := by
  induction h with
  | initial => exact initial_confined
  | next _ step ih => exact confined_step ih step

/-- The privacy theorem.  Every node a scoped delegate holds sits at an admitted
position of a root the server holds a head for, and spells no key material
outside the delegate's scope. -/
theorem held_within_scope {prefixes : List Path} (hs : s.prefixes = some prefixes)
    (h : Reachable c s heads st) (hheld : st.held x) :
    ∃ root path n, heads root ∧ s.AdmitsPath path ∧ At c root path x ∧ c x = some n ∧
      (∀ q, Reveals path n q → s.AdmitsPath q) ∧
      (∀ key, RevealsRecord path n key → s.AdmitsKey key) := by
  obtain ⟨w, n, served⟩ := (reachable_confined h).1 x hheld
  obtain ⟨hadm, hat⟩ := admit_resolves hs served.1
  exact ⟨w.root, w.path, n, admit_requires_head hs served.1, hadm, hat, served.2.1,
    fun _ hrev => served_reveals_within_scope served hrev,
    fun _ hrec => served_records_within_scope served hrec⟩

/-- Every out-of-line value a scoped delegate holds belongs to a node it was
served, at an admitted position. -/
theorem held_value_within_scope {prefixes : List Path} (hs : s.prefixes = some prefixes)
    (h : Reachable c s heads st) {v : Hash} (hheld : st.heldValue v) :
    ∃ root path x n, heads root ∧ s.AdmitsPath path ∧ At c root path x ∧ c x = some n ∧
      n.valueHash = some v ∧ AdmitsNode s path n := by
  obtain ⟨w, served⟩ := (reachable_confined h).2.1 v hheld
  have carried := served.2
  rw [hs] at carried
  obtain ⟨x, n, hadmit, hc, hv, hnode⟩ := carried
  obtain ⟨hadm, hat⟩ := admit_resolves hs hadmit
  exact ⟨w.root, w.path, x, n, admit_requires_head hs hadmit, hadm, hat, hc, hv, hnode⟩

/-- Every redaction a delegate remembers was a refusal at an above-grant
position, which is the only place the walk consults it. -/
theorem redacted_is_refusal (h : Reachable c s heads st) (hred : st.redacted path x) :
    ∃ w, w.path = path ∧ Redacts c s heads w x ∧ ¬ s.ContainsSubtree path := by
  obtain ⟨w, rfl, refused⟩ := (reachable_confined h).2.2 path x hred
  exact ⟨w, rfl, refused, redacts_only_above_grant refused⟩

end Synchronicity.ScopedSync
