import Synchronicity.ScopedSync

/-!
Provenance: why structural sharing must not cross the delegation boundary, and
the rule that keeps it from doing so (§5.5, issue #115).

`ScopedSync.held_within_scope` says every node a delegate holds sits at an
admitted position of *some* head root.  That is true and too weak.  A confined
origin holds the hash of every subtree withheld from it — the hash sits in the
branch that makes the signed root recompute — and may publish a trie placing
that hash at an in-scope position.  A member fetching that head already holds
the nodes from the issuer's trie, so presence alone calls the head complete,
and the member then serves the withheld subtree to every delegate at an
in-scope position of the grafting origin's root.  Every position is admitted;
the *content* was never that origin's to publish.

This module has several participants, each with a store, and asks a stronger
question: is a node **legitimately** a reader's, given the scope it reads
under?  `Legit` says yes for any node when the reader is rooted, for a node
under a rooted origin's head at an admitted position, for a node an origin
authored, and for a node under a confined origin's head at an admitted position
*provided that origin legitimately held it*.  `Sound` is the system invariant
that every held node is legitimate for its holder and every provenance row is
legitimate for the origin it names.

- `step_sound`: the rule Rust now runs preserves `Sound`.  A responder vouches
  for a node under a root only if the root's origin is rooted, or the responder
  was itself served the node as that origin's, or the responder *is* that
  origin and holds the node (`Vouched`, `Vouch::covers`); a member records what
  it was served as the origin's (`owned`, `note_owned`); and a walk over a
  confined origin's root reads presence through `view` (`load_owned_raw`).
- `old_rule_leaks`: the rule Rust ran before — serve any held node at an
  admitted position — does not preserve `Sound`.  The witness is the graft of
  #115 in four nodes: a state satisfying `Sound`, one old-rule step, and a
  delegate holding a record it was never granted (`Leak`).
- `confined_head_vouched`: a member that finds a confined origin's root
  complete through `view` has found only nodes that origin legitimately held,
  and `grafted_root_incomplete` is that theorem on the witness: the grafted
  root never completes.

Like `ScopedSync`, this is about nodes.  Values follow the node that carries
them (`GetValues` serves a value only with a vouched holder), and heads are
taken as verified.
-/

namespace Synchronicity.Provenance

open Synchronicity (Path Scope)
open Synchronicity.ScopedSync

abbrev Origin := Nat

/-- The cluster as this model sees it: one content addressing, each origin's
read scope, each origin's verified heads, and what each origin built itself. -/
structure World where
  c : Content
  scopeOf : Origin → Scope
  headOf : Origin → Hash → Prop
  authored : Origin → Hash → Prop

/- RUST-IMPL: mpt-provenance-owner — `bindings.rs::Store::provenance_owner`:
   an origin whose tries are judged with provenance is one that is not rooted.
   Rust also exempts the node's own origin, whose trie it built; here an origin
   serving its own root is the third `Vouched` clause. -/
def World.Confined (w : World) (o : Origin) : Prop := ¬ (w.scopeOf o).IsFull

/-- A participant's store: the shared node store, and the provenance rows. -/
structure Store where
  base : ScopedSync.Store
  owned : Origin → Hash → Prop

/- RUST-IMPL: mpt-walk-owned — `trie.rs::MissingWalk::for_origin` and
   `Trie::load_owned_raw`: the store a walk over a confined origin's root reads
   presence from is the shared store cut down to what was served as that
   origin's. -/
def view (w : World) (st : Store) (o : Origin) : ScopedSync.Store :=
  { st.base with held := fun x => st.base.held x ∧ (¬ w.Confined o ∨ st.owned o x) }

variable {w : World} {st : Store} {o p q : Origin} {x : Hash} {s : Scope}

/- RUST-IMPL: mpt-owned-node — `NodeStore::owns_node`/`note_owned`: a
   provenance row is what presence through `view` adds to holding the node. -/
theorem view_owned (hc : w.Confined o) (h : (view w st o).held x) : st.owned o x :=
  h.2.resolve_left (fun h' => h' hc)

/- RUST-IMPL: mpt-serve-vouched — `net/mpt.rs::Vouch::covers`.  Participant
   `p` vouches for `x` under `o`'s root if `o` is rooted, or `p` was served `x`
   as `o`'s, or `p` is `o` and holds `x`. -/
def Vouched (w : World) (p : Origin) (st : Store) (o : Origin) (x : Hash) : Prop :=
  ¬ w.Confined o ∨ st.owned o x ∨ (p = o ∧ st.base.held x)

/-- What participant `p` may serve a reader of scope `s` under `o`'s root `r`
at `path`: the `ScopedSync` responder for `o`'s heads, over a node `p` holds
and vouches for. -/
def ServeNode (w : World) (p : Origin) (st : Store) (s : Scope) (o : Origin) (r : Hash)
    (path : Path) (x : Hash) (n : Node) : Prop :=
  ScopedSync.ServeNode w.c s (w.headOf o) ⟨r, path, x⟩ x n ∧ st.base.held x ∧
    Vouched w p st o x

/-- The rule before #115 was closed: the same, without vouching. -/
def ServeNodeOld (w : World) (st : Store) (s : Scope) (o : Origin) (r : Hash) (path : Path)
    (x : Hash) (n : Node) : Prop :=
  ScopedSync.ServeNode w.c s (w.headOf o) ⟨r, path, x⟩ x n ∧ st.base.held x

/-- The system: every participant's store, indexed by its origin. -/
abbrev Sys := Origin → Store

def update (sys : Sys) (q : Origin) (st : Store) : Sys :=
  fun q' => if q' = q then st else sys q'

/- RUST-IMPL: mpt-learn-owned — `reconcile.rs::fetch_pending`, the node batch:
   `put_node` and, for a confined origin, `note_owned` in one transaction. -/
def learn (w : World) (st : Store) (o : Origin) (x : Hash) : Store :=
  { base := { st.base with held := fun y => y = x ∨ st.base.held y }
    owned := fun o' y => (o' = o ∧ y = x ∧ w.Confined o) ∨ st.owned o' y }

/-- An origin building a node of its own trie. -/
def author (st : Store) (x : Hash) : Store :=
  { st with base := { st.base with held := fun y => y = x ∨ st.base.held y } }

/-- The system's steps: a participant learns a node the responder serves it
under some origin's root, or an origin authors a node. -/
inductive Step (w : World) : Sys → Sys → Prop where
  | learn {sys : Sys} {q p o : Origin} {r : Hash} {path : Path} {x : Hash} {n : Node} :
      ServeNode w p (sys p) (w.scopeOf q) o r path x n →
      Step w sys (update sys q (learn w (sys q) o x))
  | author {sys : Sys} {o : Origin} {x : Hash} :
      w.authored o x → Step w sys (update sys o (author (sys o) x))

/-- The old system, serving without vouching. -/
inductive StepOld (w : World) : Sys → Sys → Prop where
  | learn {sys : Sys} {q p o : Origin} {r : Hash} {path : Path} {x : Hash} {n : Node} :
      ServeNodeOld w (sys p) (w.scopeOf q) o r path x n →
      StepOld w sys (update sys q (learn w (sys q) o x))
  | author {sys : Sys} {o : Origin} {x : Hash} :
      w.authored o x → StepOld w sys (update sys o (author (sys o) x))

/-- A node is legitimately a reader's, for the scope it reads under. -/
inductive Legit (w : World) : Scope → Hash → Prop where
  | full {s : Scope} {x : Hash} : s.IsFull → Legit w s x
  | rooted {s : Scope} {o : Origin} {r : Hash} {path : Path} {x : Hash} {n : Node} :
      w.headOf o r → ¬ w.Confined o → s.AdmitsPath path → At w.c r path x →
      w.c x = some n → AdmitsNode s path n → Legit w s x
  | confined {s : Scope} {o : Origin} {r : Hash} {path : Path} {x : Hash} {n : Node} :
      w.headOf o r → w.Confined o → s.AdmitsPath path → At w.c r path x →
      w.c x = some n → AdmitsNode s path n → Legit w (w.scopeOf o) x → Legit w s x
  | authored {o : Origin} {x : Hash} : w.authored o x → Legit w (w.scopeOf o) x

/-- The invariant: every node a participant holds is legitimately its, and
every provenance row it keeps for a confined origin names a node legitimately
that origin's. -/
def Sound (w : World) (sys : Sys) : Prop :=
  (∀ q x, (sys q).base.held x → Legit w (w.scopeOf q) x) ∧
  (∀ q o x, w.Confined o → (sys q).owned o x → Legit w (w.scopeOf o) x)

/-- What vouching buys: a vouched node under a confined origin's root is
legitimately that origin's, given the responder is sound. -/
theorem vouched_legit (hsound : Sound w sys) (hc : w.Confined o) (hv : Vouched w p (sys p) o x) :
    Legit w (w.scopeOf o) x := by
  rcases hv with rooted | owned | ⟨rfl, held⟩
  · exact absurd hc rooted
  · exact hsound.2 p o x hc owned
  · exact hsound.1 p x held

/-- A served node is legitimately the reader's. -/
theorem serve_legit (hsound : Sound w sys) {r : Hash} {path : Path} {n : Node}
    (h : ServeNode w p (sys p) (w.scopeOf q) o r path x n) : Legit w (w.scopeOf q) x := by
  obtain ⟨⟨hadmit, hcn, hnode⟩, _, hv⟩ := h
  by_cases hfull : (w.scopeOf q).IsFull
  · exact Legit.full hfull
  · have hs : ∃ prefixes, (w.scopeOf q).prefixes = some prefixes := by
      cases hp : (w.scopeOf q).prefixes with
      | none => exact absurd hp hfull
      | some prefixes => exact ⟨prefixes, rfl⟩
    obtain ⟨prefixes, hs⟩ := hs
    have hhead := admit_requires_head hs hadmit
    obtain ⟨hadm, hat⟩ := admit_resolves hs hadmit
    by_cases hc : w.Confined o
    · exact Legit.confined hhead hc hadm hat hcn hnode (vouched_legit hsound hc hv)
    · exact Legit.rooted hhead hc hadm hat hcn hnode

/- RUST-IMPL: mpt-complete-owned — `trie.rs::Trie::is_complete_scoped_for` and
   its use in `try_promote` (`mpt-complete-owned-promote`): what a member
   establishes about a confined origin's root, through `view`, is that every
   node it vouches for is legitimately that origin's. -/
theorem step_sound {sys sys' : Sys} (hsound : Sound w sys) (hstep : Step w sys sys') :
    Sound w sys' := by
  cases hstep with
  | @learn q p o r path x n served =>
    refine ⟨fun q' y hy => ?_, fun q' o' y hc' hy => ?_⟩
    · unfold update at hy
      split at hy
      · rename_i hq
        subst hq
        rcases hy with rfl | old
        · exact serve_legit hsound served
        · exact hsound.1 q' y old
      · exact hsound.1 q' y hy
    · unfold update at hy
      split at hy
      · rename_i hq
        subst hq
        rcases hy with ⟨rfl, rfl, hc⟩ | old
        · exact vouched_legit hsound hc served.2.2
        · exact hsound.2 q' o' y hc' old
      · exact hsound.2 q' o' y hc' hy
  | @author o x hauth =>
    refine ⟨fun q' y hy => ?_, fun q' o' y hc' hy => ?_⟩
    · unfold update at hy
      split at hy
      · rename_i hq
        subst hq
        rcases hy with rfl | old
        · exact Legit.authored hauth
        · exact hsound.1 q' y old
      · exact hsound.1 q' y hy
    · unfold update at hy
      split at hy
      · rename_i hq
        subst hq
        exact hsound.2 q' o' y hc' hy
      · exact hsound.2 q' o' y hc' hy

/- RUST-IMPL: mpt-complete-owned-promote — `reconcile.rs::try_promote`: the
   completeness a member requires of a confined origin's head is completeness
   through `view`, so every node it then vouches for is legitimately that
   origin's. -/
theorem confined_head_vouched {sys : Sys} (hsound : Sound w sys) (hc : w.Confined o) {r : Hash}
    (hcomplete : CompleteWithin w.c (view w (sys q) o) s r) {path : Path}
    (hr : Reach w.c (view w (sys q) o) s r path x) (hnb : ¬ Boundary s (view w (sys q) o) path x) :
    Legit w (w.scopeOf o) x := by
  rcases (hcomplete _ _ hr).1 with held | hb
  · exact hsound.2 q o x hc (view_owned hc held)
  · exact absurd hb hnb

/-! ## The witness: the graft of #115 -/

namespace Graft

/-- Nodes: the issuer's root, its photos leaf, its finance leaf, and the
grafter's root — an extension placing the finance leaf at an in-scope
position. -/
@[simp] def R : Hash := 1
@[simp] def P : Hash := 2
@[simp] def F : Hash := 3
@[simp] def G : Hash := 4

@[simp] def photosSlot : Nat := 6
@[simp] def financeSlot : Nat := 7

def content : Content := fun x =>
  if x = R then some (.branch (fun i => if i = photosSlot then some P
                                         else if i = financeSlot then some F else none) none)
  else if x = P then some (.leaf [] (.inline 1))
  else if x = F then some (.leaf [] (.inline 2))
  else if x = G then some (.ext [photosSlot] F)
  else none

/-- The delegates' grant: everything under the photos slot. -/
def photos : Scope := ⟨some [[photosSlot]], []⟩

/-- Origins: the issuer (rooted), the grafter and the reader (both confined to
photos). -/
@[simp] def issuer : Origin := 0
@[simp] def grafter : Origin := 1
@[simp] def reader : Origin := 2

def world : World :=
  { c := content
    scopeOf := fun o => if o = issuer then Scope.full else photos
    headOf := fun o r => (o = issuer ∧ r = R) ∨ (o = grafter ∧ r = G)
    authored := fun o x => (o = issuer ∧ (x = R ∨ x = P ∨ x = F)) ∨ (o = grafter ∧ x = G) }

def emptyBase : ScopedSync.Store := ⟨fun _ => False, fun _ => False, fun _ _ => False⟩

/-- Before the step: the issuer holds its own trie and the grafter's root,
served by the grafter and owned as the grafter's; the grafter holds its root;
the reader holds nothing. -/
def before : Sys := fun q =>
  if q = issuer then
    { base := { emptyBase with held := fun x => x = R ∨ x = P ∨ x = F ∨ x = G }
      owned := fun o x => o = grafter ∧ x = G }
  else if q = grafter then
    { base := { emptyBase with held := fun x => x = G }, owned := fun _ _ => False }
  else { base := emptyBase, owned := fun _ _ => False }

/-- The reader holds the finance leaf. -/
def Leak (sys : Sys) : Prop := (sys reader).base.held F

theorem photos_not_full : ¬ photos.IsFull := by
  intro h
  simp [photos, Scope.IsFull] at h

theorem full_ne_photos : Scope.full ≠ photos := by
  intro h
  simp [Scope.full, photos] at h

theorem confined_grafter : world.Confined grafter := by
  show ¬ (if grafter = issuer then Scope.full else photos).IsFull
  simp
  exact photos_not_full

theorem not_confined_issuer : ¬ world.Confined issuer := by
  show ¬ ¬ (if issuer = issuer then Scope.full else photos).IsFull
  simp [Scope.IsFull, Scope.full]

/-- Where the finance leaf sits under the issuer's root: the finance slot. -/
theorem finance_position {path : Path} (h : At content R path F) : path = [financeSlot] := by
  rcases h.inv with ⟨_, hF⟩ | ⟨n, stp, k, rest, hc, hchild, rfl, hrest⟩
  · exact absurd hF (by decide)
  · have hn : n = .branch (fun i => if i = photosSlot then some P
        else if i = financeSlot then some F else none) none := by
      simp [content] at hc
      exact hc.symm
    subst hn
    cases hchild with
    | branch hi =>
      rename_i i
      by_cases h6 : i = photosSlot
      · subst h6
        have hk : k = P := by simpa using hi.symm
        subst hk
        obtain ⟨_, hPF⟩ :=
          At.leaf_nil (rest := []) (value := .inline 1) hrest (by simp [content])
        exact absurd hPF (by decide)
      · by_cases h7 : i = financeSlot
        · subst h7
          have hk : k = F := by simpa [h6] using hi.symm
          subst hk
          obtain ⟨rfl, _⟩ :=
            At.leaf_nil (rest := []) (value := .inline 2) hrest (by simp [content])
          rfl
        · simp at h6 h7
          simp [h6, h7] at hi

theorem photos_rejects_finance : ¬ photos.AdmitsPath [financeSlot] := by
  intro h
  unfold Scope.AdmitsPath at h
  simp [photos, List.cons_prefix_cons] at h

/-- The finance leaf is nobody's to hold under the photos grant. -/
theorem finance_not_legit : ∀ s x, Legit world s x → s = photos → x = F → False := by
  intro s x h
  induction h with
  | full hfull =>
    rintro rfl _
    exact photos_not_full hfull
  | @rooted s o r path x n hhead hnc hadm hat _ _ =>
    rintro rfl rfl
    rcases hhead with ⟨_, rfl⟩ | ⟨rfl, _⟩
    · rw [finance_position hat] at hadm
      exact photos_rejects_finance hadm
    · exact hnc confined_grafter
  | @confined s o r path x n hhead hconf _ _ _ _ _ ih =>
    rintro rfl rfl
    rcases hhead with ⟨rfl, _⟩ | ⟨rfl, _⟩
    · exact absurd hconf not_confined_issuer
    · exact ih (by simp [world]) rfl
  | @authored o x hauth =>
    intro hs rfl
    have ho : o ≠ issuer := by
      intro rfl
      exact full_ne_photos (by simpa [world] using hs)
    rcases hauth with ⟨rfl, _⟩ | ⟨_, hG⟩
    · exact ho rfl
    · exact absurd hG (by decide)

theorem before_sound : Sound world before := by
  refine ⟨fun q x hx => ?_, fun q o x hc hx => ?_⟩
  · unfold before at hx
    split at hx
    · rename_i hq
      subst hq
      exact Legit.full (by simp [world, Scope.IsFull, Scope.full])
    · split at hx
      · rename_i _ hq
        subst hq
        have hxG : x = G := hx
        subst hxG
        exact Legit.authored (o := grafter) (Or.inr ⟨rfl, rfl⟩)
      · exact hx.elim
  · unfold before at hx
    split at hx
    · obtain ⟨rfl, rfl⟩ := hx
      exact Legit.authored (o := grafter) (Or.inr ⟨rfl, rfl⟩)
    · split at hx
      · exact hx.elim
      · exact hx.elim

/-- One old-rule step: the reader fetches, from the issuer, position
`[photosSlot]` under the grafter's root — and is served the finance leaf. -/
def after : Sys := update before reader (learn world (before reader) grafter F)

theorem old_step : StepOld world before after := by
  refine StepOld.learn (p := issuer) (r := G) (path := [photosSlot]) (n := .leaf [] (.inline 2)) ?_
  refine ⟨⟨?_, by simp [world, content], ?_⟩, ?_⟩
  · -- `Admit`, for the reader's photos scope
    show Admit content (world.scopeOf reader) (world.headOf grafter) ⟨G, [photosSlot], F⟩ F
    have hs : (world.scopeOf reader).prefixes = some [[photosSlot]] := by
      simp [world, photos]
    unfold Admit
    rw [hs]
    refine ⟨Or.inr ⟨rfl, rfl⟩, ?_, ?_⟩
    · exact Scope.admitsPath_of_containsSubtree ⟨[photosSlot], by simp, List.prefix_refl _⟩
    · exact At.ofChild (by simp [content]) ChildOf.ext
  · -- the leaf spells the key `[photosSlot]`, inside the grant
    show AdmitsNode (world.scopeOf reader) [photosSlot] (.leaf [] (.inline 2))
    have : world.scopeOf reader = photos := by simp [world]
    rw [this]
    exact Or.inl ⟨[photosSlot], by simp, List.prefix_refl _⟩
  · -- the issuer holds the finance leaf
    show (before issuer).base.held F
    simp [before]

theorem after_leaks : Leak after := by
  show (update before reader (learn world (before reader) grafter F) reader).base.held F
  simp [update, learn]

theorem after_unsound : ¬ Sound world after := by
  intro h
  have hlegit := h.1 reader F after_leaks
  exact finance_not_legit _ _ hlegit (by simp [world]) rfl

/-- **The old rule leaks.**  A sound state, one step the old responder allows,
and a delegate holding a record outside its grant. -/
theorem old_rule_leaks :
    ∃ (sys sys' : Sys), Sound world sys ∧ StepOld world sys sys' ∧ Leak sys' ∧ ¬ Sound world sys' :=
  ⟨before, after, before_sound, old_step, after_leaks, after_unsound⟩

/-- **The new rule does not.**  The same step is not available: no participant
vouches for the finance leaf under the grafter's root. -/
theorem new_rule_refuses {r : Hash} {path : Path} {n : Node} (hp : Sound world before) :
    ¬ ServeNode world p (before p) (world.scopeOf reader) grafter r path F n := by
  intro ⟨_, _, hv⟩
  exact finance_not_legit _ _ (vouched_legit hp confined_grafter hv) rfl rfl

/-- **The grafted root never completes.**  Judged through `view`, the issuer's
copy of the grafter's trie is missing the finance leaf, whatever the scope. -/
theorem grafted_root_incomplete (s : Scope) (hs : s.AdmitsPath [photosSlot]) :
    ¬ CompleteWithin content (view world (before issuer) grafter) s G := by
  intro hcomplete
  have hroot : Reach content (view world (before issuer) grafter) s G [] G :=
    Reach.root (Scope.admitsPath_of_prefix hs List.nil_prefix)
  have hheldG : (view world (before issuer) grafter).held G := by
    refine ⟨by simp [before], Or.inr ?_⟩
    simp [before]
  have hF : Reach content (view world (before issuer) grafter) s G [photosSlot] F :=
    Reach.child hroot hheldG (held_not_boundary hheldG) (by simp [content]) ChildOf.ext
      (by simpa using hs)
  rcases (hcomplete _ _ hF).1 with held | ⟨_, _, hred⟩
  · have := view_owned confined_grafter held
    simp [before] at this
  · exact hred

end Graft

end Synchronicity.Provenance
