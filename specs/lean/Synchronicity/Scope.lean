/-!
The positional scope predicates of §5.5, as `synch-mpt/src/scope.rs` states them.

A scope is a statement about *where* a node sits, never about which node it
is.  Every predicate here takes a nibble path — a `List Nat`; the radix is
irrelevant to anything proved — and the lemmas are the facts both sides of a
scoped fetch rely on: the spine above an admitted position is admitted, nothing
below a granted prefix can leave it, and a node sitting inside the grant is
never refused.
-/

namespace Synchronicity

abbrev Path := List Nat

/-- `Scope::prefixes` and `Scope::exact`: `none` is the whole keyspace. -/
structure Scope where
  prefixes : Option (List Path)
  exact : List Path

namespace Scope

variable {s : Scope} {path rest p q key k : Path}

def full : Scope := ⟨none, []⟩

def IsFull (s : Scope) : Prop := s.prefixes = none

/- RUST-IMPL: mpt-scope-admits-path — `scope.rs::Scope::admits_path`.  A node at
   `path` commits to every key beginning with `path`, so it is in scope as an
   ancestor of a granted prefix or inside one; an exact key admits the spine
   down to it and the key itself, never a position below it. -/
def AdmitsPath (s : Scope) (path : Path) : Prop :=
  match s.prefixes with
  | none => True
  | some prefixes =>
      (∃ p ∈ prefixes, path <+: p ∨ p <+: path) ∨ ∃ k ∈ s.exact, path <+: k

/- RUST-IMPL: mpt-scope-contains-subtree — `scope.rs::Scope::contains_subtree`.
   Everything below `path` is inside the grant. -/
def ContainsSubtree (s : Scope) (path : Path) : Prop :=
  match s.prefixes with
  | none => True
  | some prefixes => ∃ p ∈ prefixes, p <+: path

/-- `scope.rs::Scope::admits_key_path`: a whole key lies inside the scope. -/
def AdmitsKey (s : Scope) (key : Path) : Prop :=
  s.ContainsSubtree key ∨ key ∈ s.exact

theorem admitsPath_of_full (h : s.IsFull) (path : Path) : s.AdmitsPath path := by
  unfold AdmitsPath; rw [h]; trivial

theorem containsSubtree_of_full (h : s.IsFull) (path : Path) : s.ContainsSubtree path := by
  unfold ContainsSubtree; rw [h]; trivial

/-- Inside the grant is admitted. -/
theorem admitsPath_of_containsSubtree (h : s.ContainsSubtree path) : s.AdmitsPath path := by
  unfold ContainsSubtree at h
  unfold AdmitsPath
  split at h
  · trivial
  · rename_i prefixes _
    obtain ⟨p, hp, hpre⟩ := h
    exact Or.inl ⟨p, hp, Or.inr hpre⟩

/-- Once inside a granted prefix, no descent leaves it. -/
theorem containsSubtree_append (h : s.ContainsSubtree path) (rest : Path) :
    s.ContainsSubtree (path ++ rest) := by
  unfold ContainsSubtree at h ⊢
  split at h
  · trivial
  · obtain ⟨p, hp, hpre⟩ := h
    exact ⟨p, hp, hpre.trans (List.prefix_append path rest)⟩

/-- The spine: every ancestor of an admitted position is admitted.  This is what
lets a scoped peer recompute the signed root, and what makes "the boundary is
the child hash inside the last in-scope node" well defined. -/
theorem admitsPath_of_append (h : s.AdmitsPath (path ++ rest)) : s.AdmitsPath path := by
  unfold AdmitsPath at h ⊢
  split at h
  · trivial
  · have self : path <+: path ++ rest := List.prefix_append path rest
    rcases h with ⟨p, hp, below | above⟩ | ⟨k, hk, hpre⟩
    · exact Or.inl ⟨p, hp, Or.inl (self.trans below)⟩
    · rcases List.prefix_or_prefix_of_prefix above self with h | h
      · exact Or.inl ⟨p, hp, Or.inr h⟩
      · exact Or.inl ⟨p, hp, Or.inl h⟩
    · exact Or.inr ⟨k, hk, self.trans hpre⟩

theorem admitsPath_of_prefix (h : s.AdmitsPath q) (hpre : p <+: q) : s.AdmitsPath p := by
  obtain ⟨rest, rfl⟩ := hpre
  exact admitsPath_of_append h

/-- A key the scope admits is a position it admits. -/
theorem admitsPath_of_admitsKey (h : s.AdmitsKey key) : s.AdmitsPath key := by
  rcases h with inside | exact
  · exact admitsPath_of_containsSubtree inside
  · unfold AdmitsPath
    split
    · trivial
    · exact Or.inr ⟨key, exact, List.prefix_refl key⟩

theorem admitsKey_of_containsSubtree (h : s.ContainsSubtree key) : s.AdmitsKey key :=
  Or.inl h

/-- Contrapositive of the spine lemma: nothing below a refused position is
admitted, so a walk that stops at the boundary loses nothing it was granted. -/
theorem not_admitsPath_append (h : ¬ s.AdmitsPath path) (rest : Path) :
    ¬ s.AdmitsPath (path ++ rest) :=
  fun h' => h (admitsPath_of_append h')

end Scope

end Synchronicity
