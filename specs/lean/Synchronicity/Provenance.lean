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

- `step_sound`: the vouching rule preserves `Sound`.  A responder vouches for
  a node under a root only if the root's origin is rooted, or the responder was
  itself served the node as that origin's, or the responder *is* that origin
  and holds the node (`Vouched`, `Vouch::covers`); a member records what it was
  served as the origin's (`owned`, `note_owned`); and a walk over a confined
  origin's root reads presence through `view` (`load_owned_raw`).
- `confined_head_vouched`: a member that finds a confined origin's root
  complete through `view` has found only nodes that origin legitimately held.
- `Withheld` is content no rooted trie exposes to a scope and no origin of
  that scope authored.  `withheld_not_legit`, `withheld_not_served`, and
  `withheld_root_incomplete` say that, in any sound system, such content is
  never legitimately a confined reader's, is never served under a confined
  origin's root, and keeps every confined root that reaches it from
  completing — whatever trie it is grafted into.
- `Graft` is the graft of #115 in four nodes, instantiating those theorems so
  the invariant is seen to be strong enough: the finance leaf is `Withheld`
  from every confined scope, so the reader cannot be served it and the grafted
  root never completes.  Before vouching, the responder served any held node
  at an admitted position, one step from `Graft.before` to a state `Sound`
  rejects; that rule is gone and is not modelled.

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

/-! ## The theorem: privacy and integrity of confined tries -/

/-- Every participant starts holding nothing. -/
def Initial : Sys := fun _ =>
  { base := ⟨fun _ => False, fun _ => False, fun _ _ => False⟩, owned := fun _ _ => False }

inductive Reachable (w : World) : Sys → Prop where
  | initial : Reachable w Initial
  | next {sys sys' : Sys} : Reachable w sys → Step w sys sys' → Reachable w sys'

theorem initial_sound : Sound w Initial :=
  ⟨fun _ _ h => h.elim, fun _ _ _ _ h => h.elim⟩

theorem reachable_sound {sys : Sys} (h : Reachable w sys) : Sound w sys := by
  induction h with
  | initial => exact initial_sound
  | next _ step ih => exact step_sound ih step

/-- **Privacy.**  In every reachable state, a confined participant holds only
nodes that are legitimately its: exposed to its scope by a rooted origin's
trie at an admitted position, authored by it, or published by a confined origin
that legitimately held them. -/
theorem privacy {sys : Sys} (h : Reachable w sys) (hx : (sys q).base.held x) :
    Legit w (w.scopeOf q) x :=
  (reachable_sound h).1 q x hx

/-- **Integrity.**  In every reachable state, a member that finds a confined
origin's root complete through `view` — the premise on which it promotes the
head, materializes its records, and advertises it — has found only nodes
legitimately that origin's. -/
theorem integrity {sys : Sys} {r : Hash} {path : Path} (h : Reachable w sys) (hc : w.Confined o)
    (hcomplete : CompleteWithin w.c (view w (sys q) o) s r)
    (hr : Reach w.c (view w (sys q) o) s r path x) (hnb : ¬ Boundary s (view w (sys q) o) path x) :
    Legit w (w.scopeOf o) x :=
  confined_head_vouched (reachable_sound h) hc hcomplete hr hnb

/-! ## Withheld content stays withheld -/

/-- No rooted origin's trie exposes `x` to scope `s` — wherever `x` sits under a
rooted head at a position `s` admits, its node reveals something `s` does not
— and no origin reading under `s` authored it. -/
def Withheld (w : World) (s : Scope) (x : Hash) : Prop :=
  (∀ o r path n, w.headOf o r → ¬ w.Confined o → At w.c r path x → w.c x = some n →
    s.AdmitsPath path → ¬ AdmitsNode s path n) ∧
  (∀ o, w.authored o x → w.scopeOf o ≠ s)

/-- Content withheld from every confined scope is legitimately no confined
reader's: every `Legit` derivation bottoms out in a rooted exposure or an
authoring, and passes only through confined scopes on the way.  With
`privacy`, this is the negative form of the theorem: such content never
reaches a confined participant (`privacy_withheld`). -/
theorem withheld_not_legit (hw : ∀ o, w.Confined o → Withheld w (w.scopeOf o) x) :
    ∀ s, Legit w s x → (∃ o, w.Confined o ∧ s = w.scopeOf o) → False := by
  intro s h
  induction h with
  | full hfull =>
    rintro ⟨o, hc, rfl⟩
    exact hc hfull
  | @rooted s o r path x n hhead hnc hadm hat hcn hnode =>
    rintro ⟨o', hc', rfl⟩
    exact (hw o' hc').1 o r path n hhead hnc hat hcn hadm hnode
  | @confined s o r path x n _ hc _ _ _ _ _ ih =>
    intro _
    exact ih hw ⟨o, hc, rfl⟩
  | @authored o x hauth =>
    rintro ⟨o', hc', heq⟩
    exact (hw o' hc').2 o hauth heq

/-- Withheld content never reaches a confined participant, in any reachable
state. -/
theorem privacy_withheld {sys : Sys} (h : Reachable w sys) (hq : w.Confined q)
    (hw : ∀ o, w.Confined o → Withheld w (w.scopeOf o) x) : ¬ (sys q).base.held x :=
  fun hx => withheld_not_legit hw _ (privacy h hx) ⟨q, hq, rfl⟩

/-- Nobody in a sound system vouches for withheld content under a confined
origin's root, so no reader is served it there — wherever the origin placed
its hash. -/
theorem withheld_not_served {sys : Sys} {r : Hash} {path : Path} {n : Node}
    (hsound : Sound w sys) (hc : w.Confined o)
    (hw : ∀ o', w.Confined o' → Withheld w (w.scopeOf o') x) :
    ¬ ServeNode w p (sys p) s o r path x n :=
  fun h => withheld_not_legit hw _ (vouched_legit hsound hc h.2.2) ⟨o, hc, rfl⟩

/-- A confined origin's root that reaches withheld content never completes
through `view` on any sound member: the member never comes to own the node as
that origin's, and Rust's fetch abandons the head. -/
theorem withheld_root_incomplete {sys : Sys} {r : Hash} {path : Path}
    (hsound : Sound w sys) (hc : w.Confined o)
    (hw : ∀ o', w.Confined o' → Withheld w (w.scopeOf o') x)
    (hr : Reach w.c (view w (sys q) o) s r path x) (hnb : ¬ Boundary s (view w (sys q) o) path x) :
    ¬ CompleteWithin w.c (view w (sys q) o) s r :=
  fun hcomplete =>
    withheld_not_legit hw _ (confined_head_vouched hsound hc hcomplete hr hnb) ⟨o, hc, rfl⟩

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

/-- Every confined origin here reads under `photos`. -/
theorem confined_scope (hc : world.Confined o) : world.scopeOf o = photos := by
  by_cases ho : o = issuer
  · subst ho
    exact absurd hc not_confined_issuer
  · simp [world, show o ≠ 0 from ho]

/-- The finance leaf is withheld from every confined scope: under the one
rooted head it sits only at the finance slot, and only the issuer authored it. -/
theorem finance_withheld : ∀ o, world.Confined o → Withheld world (world.scopeOf o) F := by
  intro o hc
  rw [confined_scope hc]
  refine ⟨fun o' r path n hhead hnc hat _ hadm => ?_, fun o' hauth heq => ?_⟩
  · rcases hhead with ⟨_, rfl⟩ | ⟨rfl, _⟩
    · rw [finance_position hat] at hadm
      exact absurd hadm photos_rejects_finance
    · exact absurd confined_grafter hnc
  · rcases hauth with ⟨rfl, _⟩ | ⟨_, hG⟩
    · exact full_ne_photos (by simpa [world] using heq)
    · exact absurd hG (by decide)

/-- The finance leaf is nobody's to hold under the photos grant. -/
theorem finance_not_legit : ¬ Legit world photos F :=
  fun h => withheld_not_legit finance_withheld _ h ⟨grafter, confined_grafter, by simp [world]⟩

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

/-- **Nobody vouches for the graft.**  The issuer holds the finance leaf and
the grafter's root, and no participant serves the leaf to any reader under
that root. -/
theorem new_rule_refuses {r : Hash} {path : Path} {n : Node} :
    ¬ ServeNode world p (before p) s grafter r path F n :=
  withheld_not_served before_sound confined_grafter finance_withheld

/-- **The grafted root never completes.**  Judged through `view`, the issuer's
copy of the grafter's trie is missing the finance leaf, under any scope that
admits the photos slot. -/
theorem grafted_root_incomplete (s : Scope) (hs : s.AdmitsPath [photosSlot]) :
    ¬ CompleteWithin content (view world (before issuer) grafter) s G := by
  have hroot : Reach content (view world (before issuer) grafter) s G [] G :=
    Reach.root (Scope.admitsPath_of_prefix hs List.nil_prefix)
  have hheldG : (view world (before issuer) grafter).held G := by
    refine ⟨by simp [before], Or.inr ?_⟩
    simp [before]
  have hF : Reach content (view world (before issuer) grafter) s G [photosSlot] F :=
    Reach.child hroot hheldG (held_not_boundary hheldG) (by simp [content]) ChildOf.ext
      (by simpa using hs)
  exact withheld_root_incomplete before_sound confined_grafter finance_withheld hF
    (fun hb => hb.2.2)

end Graft

end Synchronicity.Provenance
