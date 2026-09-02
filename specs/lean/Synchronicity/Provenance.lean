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
  that scope authored.  `privacy_withheld`, `withheld_not_served`, and
  `withheld_root_incomplete` say that such content never reaches a confined
  participant, is never served under a confined origin's root, and keeps every
  confined root that reaches it from completing — whatever trie its hash is
  placed in.  This is the negative form of the theorem, and the one #115
  violated: a subtree withheld from a delegate was reachable through the
  delegate's own trie.  The Rust test
  `a_delegate_cannot_launder_a_withheld_subtree_through_its_own_trie` is that
  instance over real endpoints; here it is a corollary.
- `LegitVia` makes the chain of custody a `Legit` derivation follows explicit:
  the confined origins whose heads a node passed through on its way to a
  reader.  `privacy_chain` is `privacy` with the chain in hand: every link
  legitimately held the node.  This is why the `withheld_*` theorems quantify
  over every confined scope — a confined origin may re-publish, under its own
  root, what it legitimately holds, and a wider confined origin's grant may
  legitimately carry a node to a narrower one.  Re-publication along a
  delegation chain is the design working, not a leak; what the theorems
  exclude is content that no chain can legitimately begin with.

Like `ScopedSync`, this is about nodes.  Values follow the node that carries
them (`GetValues` serves a value only with a vouched holder), and heads are
taken as verified.
-/

namespace Synchronicity.Provenance

open Synchronicity (Path Scope)
open Synchronicity.ScopedSync

/-- A participant, named by its origin. -/
abbrev Origin := Nat

/-- The cluster as this model sees it: one content addressing, each origin's
read scope, each origin's verified heads, and what each origin built itself. -/
structure World where
  /-- Content addressing. -/
  c : Content
  /-- Each origin's read scope. -/
  scopeOf : Origin → Scope
  /-- Each origin's verified head roots. -/
  headOf : Origin → Hash → Prop
  /-- The nodes each origin built itself. -/
  authored : Origin → Hash → Prop

/-- `bindings.rs::Store::provenance_owner`: an origin whose tries are judged
with provenance is one that is not rooted.  Rust also exempts the node's own
origin, whose trie it built; here an origin serving its own root is the third
`Vouched` clause. -/
@[rust_impl "mpt-provenance-owner"]
def World.Confined (w : World) (o : Origin) : Prop := ¬ (w.scopeOf o).IsFull

/-- A participant's store: the shared node store, and the provenance rows. -/
structure Store where
  /-- The shared node store. -/
  base : ScopedSync.Store
  /-- The provenance rows: which nodes were served as which origin's. -/
  owned : Origin → Hash → Prop

/-- `trie.rs::MissingWalk::for_origin` and `Trie::load_owned_raw`: the store a
walk over a confined origin's root reads presence from is the shared store cut
down to what was served as that origin's. -/
@[rust_impl "mpt-walk-owned"]
def view (w : World) (st : Store) (o : Origin) : ScopedSync.Store :=
  { st.base with held := fun x => st.base.held x ∧ (¬ w.Confined o ∨ st.owned o x) }

variable {w : World} {st : Store} {o p q : Origin} {x : Hash} {s : Scope}

/-- `NodeStore::owns_node`/`note_owned`: a provenance row is what presence
through `view` adds to holding the node. -/
@[rust_impl "mpt-owned-node"]
theorem view_owned (hc : w.Confined o) (h : (view w st o).held x) : st.owned o x :=
  h.2.resolve_left (fun h' => h' hc)

/-- `net/mpt.rs::Vouch::covers`.  Participant `p` vouches for `x` under `o`'s
root if `o` is rooted, or `p` was served `x` as `o`'s, or `p` is `o` and holds
`x`. -/
@[rust_impl "mpt-serve-vouched"]
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

/-- `reconcile.rs::fetch_pending`, the node batch: `put_node` and, for a
confined origin, `note_owned` in one transaction. -/
@[rust_impl "mpt-learn-owned"]
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
theorem vouched_legit {sys : Sys} (hsound : Sound w sys) (hc : w.Confined o)
    (hv : Vouched w p (sys p) o x) : Legit w (w.scopeOf o) x := by
  rcases hv with rooted | owned | ⟨rfl, held⟩
  · exact absurd hc rooted
  · exact hsound.2 p o x hc owned
  · exact hsound.1 p x held

/-- A served node is legitimately the reader's. -/
theorem serve_legit {sys : Sys} (hsound : Sound w sys) {r : Hash} {path : Path} {n : Node}
    (h : ServeNode w p (sys p) (w.scopeOf q) o r path x n) : Legit w (w.scopeOf q) x := by
  obtain ⟨⟨hadmit, hcn, hnode⟩, _, hv⟩ := h
  by_cases hfull : (w.scopeOf q).IsFull
  · exact Legit.full hfull
  · have hhead := admit_requires_head hfull hadmit
    obtain ⟨hadm, hat⟩ := admit_resolves hfull hadmit
    by_cases hc : w.Confined o
    · exact Legit.confined hhead hc hadm hat hcn hnode (vouched_legit hsound hc hv)
    · exact Legit.rooted hhead hc hadm hat hcn hnode

/-- `trie.rs::Trie::is_complete_scoped_for` and its use in `try_promote`
(`mpt-complete-owned-promote`): what a member establishes about a confined
origin's root, through `view`, is that every node it vouches for is
legitimately that origin's. -/
@[rust_impl "mpt-complete-owned"]
theorem step_sound {sys sys' : Sys} (hsound : Sound w sys) (hstep : Step w sys sys') :
    Sound w sys' := by
  cases hstep with
  | @learn q p o r path x n served =>
    refine ⟨fun q' y hy => ?_, fun q' o' y hc' hy => ?_⟩
    · by_cases hq : q' = q
      · subst hq
        simp only [Function.update_self] at hy
        rcases hy with rfl | old
        · exact serve_legit hsound served
        · exact hsound.1 q' y old
      · simp only [Function.update_of_ne hq] at hy
        exact hsound.1 q' y hy
    · by_cases hq : q' = q
      · subst hq
        simp only [Function.update_self] at hy
        rcases hy with ⟨rfl, rfl, hc⟩ | old
        · exact vouched_legit hsound hc served.2.2
        · exact hsound.2 q' o' y hc' old
      · simp only [Function.update_of_ne hq] at hy
        exact hsound.2 q' o' y hc' hy
  | @author o x hauth =>
    refine ⟨fun q' y hy => ?_, fun q' o' y hc' hy => ?_⟩
    · by_cases hq : q' = o
      · subst hq
        simp only [Function.update_self] at hy
        rcases hy with rfl | old
        · exact Legit.authored hauth
        · exact hsound.1 q' y old
      · simp only [Function.update_of_ne hq] at hy
        exact hsound.1 q' y hy
    · by_cases hq : q' = o
      · subst hq
        simp only [Function.update_self] at hy
        exact hsound.2 q' o' y hc' hy
      · simp only [Function.update_of_ne hq] at hy
        exact hsound.2 q' o' y hc' hy

/-- `reconcile.rs::try_promote`: the completeness a member requires of a
confined origin's head is completeness through `view`, so every node it then
vouches for is legitimately that origin's. -/
@[rust_impl "mpt-complete-owned-promote"]
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

/-- The multi-party system. -/
def system (w : World) : System Sys := ⟨Initial, Step w⟩

/-- The states the cluster reaches. -/
abbrev Reachable (w : World) (sys : Sys) : Prop := (system w).Reachable sys

theorem initial_sound : Sound w Initial :=
  ⟨fun _ _ h => h.elim, fun _ _ _ _ h => h.elim⟩

theorem reachable_sound {sys : Sys} (h : Reachable w sys) : Sound w sys :=
  h.invariant initial_sound step_sound

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

/-! ## The chain of custody -/

/-- A `Legit` derivation with its chain of custody: the confined origins whose
heads the node passed through, the reader's nearest first. -/
inductive LegitVia (w : World) : List Origin → Scope → Hash → Prop where
  | full {s : Scope} {x : Hash} : s.IsFull → LegitVia w [] s x
  | rooted {s : Scope} {o : Origin} {r : Hash} {path : Path} {x : Hash} {n : Node} :
      w.headOf o r → ¬ w.Confined o → s.AdmitsPath path → At w.c r path x →
      w.c x = some n → AdmitsNode s path n → LegitVia w [] s x
  | confined {s : Scope} {o : Origin} {r : Hash} {path : Path} {x : Hash} {n : Node}
      {chain : List Origin} :
      w.headOf o r → w.Confined o → s.AdmitsPath path → At w.c r path x →
      w.c x = some n → AdmitsNode s path n → LegitVia w chain (w.scopeOf o) x →
      LegitVia w (o :: chain) s x
  | authored {o : Origin} {x : Hash} : w.authored o x → LegitVia w [] (w.scopeOf o) x

theorem LegitVia.legit {chain : List Origin} (h : LegitVia w chain s x) : Legit w s x := by
  induction h with
  | full hfull => exact .full hfull
  | rooted hhead hnc hadm hat hcn hnode => exact .rooted hhead hnc hadm hat hcn hnode
  | confined hhead hc hadm hat hcn hnode _ ih => exact .confined hhead hc hadm hat hcn hnode ih
  | authored hauth => exact .authored hauth

theorem Legit.via (h : Legit w s x) : ∃ chain, LegitVia w chain s x := by
  induction h with
  | full hfull => exact ⟨[], .full hfull⟩
  | rooted hhead hnc hadm hat hcn hnode => exact ⟨[], .rooted hhead hnc hadm hat hcn hnode⟩
  | confined hhead hc hadm hat hcn hnode _ ih =>
    obtain ⟨chain, hchain⟩ := ih
    exact ⟨_, .confined hhead hc hadm hat hcn hnode hchain⟩
  | authored hauth => exact ⟨[], .authored hauth⟩

/-- Every origin on the chain is confined and legitimately held the node. -/
theorem LegitVia.links {chain : List Origin} (h : LegitVia w chain s x) :
    ∀ o ∈ chain, w.Confined o ∧ Legit w (w.scopeOf o) x := by
  induction h with
  | @confined _ o _ _ _ _ _ _ hc _ _ _ _ hrest ih =>
    intro o' ho'
    rcases List.mem_cons.mp ho' with rfl | ho'
    · exact ⟨hc, hrest.legit⟩
    · exact ih o' ho'
  | _ => intro _ h; exact absurd h List.not_mem_nil

/-- **Privacy, with the chain in hand.**  Every node a participant holds came
to it along a chain of confined origins each of which legitimately held it,
from a rooted exposure or an authoring at the far end. -/
theorem privacy_chain {sys : Sys} (h : Reachable w sys) (hx : (sys q).base.held x) :
    ∃ chain, LegitVia w chain (w.scopeOf q) x ∧
      ∀ o ∈ chain, w.Confined o ∧ Legit w (w.scopeOf o) x :=
  let ⟨chain, hchain⟩ := (privacy h hx).via
  ⟨chain, hchain, hchain.links⟩

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
authoring, and passes only through confined scopes on the way. -/
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
through `view` on any sound member — wherever the origin placed the hash: the
member never comes to own the node as that origin's, and Rust's fetch abandons
the head. -/
theorem withheld_root_incomplete {sys : Sys} {r : Hash} {path : Path}
    (hsound : Sound w sys) (hc : w.Confined o)
    (hw : ∀ o', w.Confined o' → Withheld w (w.scopeOf o') x)
    (hr : Reach w.c (view w (sys q) o) s r path x) (hnb : ¬ Boundary s (view w (sys q) o) path x) :
    ¬ CompleteWithin w.c (view w (sys q) o) s r :=
  fun hcomplete =>
    withheld_not_legit hw _ (confined_head_vouched hsound hc hcomplete hr hnb) ⟨o, hc, rfl⟩

end Synchronicity.Provenance

#lint
