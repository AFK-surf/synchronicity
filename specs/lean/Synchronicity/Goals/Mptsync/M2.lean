import Synchronicity.AdvertisementSelection

/-! # M2 — advertisement order and duplication do not change selection

This goal observes the actual `Exchange.plan` inputs and result.  Pull origins
are interpreted as their greatest remote advertised heads, and push positions
are resolved back through the actual servable input.  Thus the property is
about selected origins and versions, not incidental list positions.

`ValidAdvertisement` is the native 32-byte root contract and does not assume an
acceptance result.  Signature and authorization checks happen later in
`Reconcile.accept`; eventual observation, delivery, acceptance and promotion
belong to the remaining convergence goals rather than this planner theorem.
-/
namespace Synchronicity.Goals.Mptsync.M2
open VerifiedCore.Replication.Exchange
open AdvertisementSelection

/-- Reordering or duplicating the same valid planner inputs preserves the sets
of greatest heads selected for pulling and concrete heads selected for pushing. -/
def SelectionInvariant (ours ours' theirs theirs' served served' : List Advertised) : Prop :=
  Equivalent theirs theirs' served served'
    (plan ours theirs served) (plan ours' theirs' served')

/-- **M2.** The production exchange planner's semantic selection is invariant
under advertisement order and duplication at the checked native boundary. -/
theorem selection_invariant
    (localSet : SameValidAdvertisements ours ours')
    (remote : SameValidAdvertisements theirs theirs')
    (servable : SameValidAdvertisements served served')
    (leftBound : served.length ≤ UInt64.size)
    (rightBound : served'.length ≤ UInt64.size) :
    SelectionInvariant ours ours' theirs theirs' served served' :=
  plans_equivalent localSet remote servable leftBound rightBound

end Synchronicity.Goals.Mptsync.M2
