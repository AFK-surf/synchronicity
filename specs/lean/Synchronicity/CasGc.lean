import Synchronicity.SystemSafety

/-!
The compact, single-root protocol explanation: `Cas` read at `H := Unit`.

With one holder there is one pin, one want and one live leaf per cell, and
the theorems read the way the CAS safety claim is usually stated — a pinned
object is available, GC respects entries, pins and write leases, publication
commits one closed state, promotion commits a pin or a want.  Nothing here is
proved separately: every statement instantiates `SystemSafety` at the trivial
holder, which is why this file carries no Rust anchors of its own.
-/

namespace Synchronicity.CasGc

open Cas

/-- The single holder is a role: a source or a replica, never the operator. -/
instance : Roles Unit := ⟨fun _ => True⟩

abbrev State := Cell Unit

variable {c c' : State}

/-- One pin, one want, one leaf of each kind. -/
def Pinned (c : State) : Prop := c.pin ()
def Wanted (c : State) : Prop := c.want ()
def SourceLeaf (c : State) : Prop := c.sourceLive ()
def ReplicaLeaf (c : State) : Prop := c.replicaLive ()

theorem promised_content_is_safe {s : Cas.State Unit} {root : Root}
    (h : SystemSafety.Reachable s) (pinned : Pinned (s root)) : Available (s root) :=
  ((SystemSafety.reachable_invariant h root).2.pin_available () pinned)

theorem gc_respects_protection (hgc : GcCommit c c')
    (guarded : c.entry ∨ Pinned c ∨ c.writing) : False :=
  Cas.gc_respects_protection hgc
    (guarded.elim Or.inl (fun g => g.elim (fun p => Or.inr (Or.inl ⟨(), p⟩)) (Or.inr ∘ Or.inr)))

theorem write_lease_excludes_gc (writing : c.writing) (hgc : GcCommit c c') : False :=
  Cas.write_lease_excludes_gc writing hgc

theorem source_publish_is_closed (h : SourcePublish () c c') :
    c'.entry ∧ Pinned c' ∧ Available c' :=
  Cas.source_publish_is_closed h

theorem replica_promotion_is_total (h : ReplicaPromote () c c') :
    c'.entry ∧ ((Pinned c' ∧ Available c') ∨ Wanted c') :=
  Cas.replica_promotion_is_total h

theorem possession_is_atomic (h : TakePossession () c c') :
    Pinned c' ∧ ¬Wanted c' ∧ Available c' :=
  Cas.possession_is_atomic h

end Synchronicity.CasGc
