import Synchronicity.ContactExecution

/-! # M6 — failed peers do not starve healthy peers in completed rounds

This goal covers the Lean-owned cyclic contact planner and the explicit narrow
runtime contract recorded by `ContactExecution.Execution`.  Every planned
attempt may succeed, fail, or time out.  The conclusion is an actual bounded
attempt for each healthy peer, not a successful exchange, completed Fetch, or
eventual promotion.

Starting future rounds, dynamic eligibility, cancellation of a whole round and
delivery of useful work remain obligations of the outer scheduler/convergence
composition.  A cancelled round is deliberately not a `CompletedRound`, so it
cannot advance the modeled persisted cursor.
-/
namespace Synchronicity.Goals.Mptsync.M6
open VerifiedCore.Replication.Contact
open ContactExecution

/-- Under a fixed eligible set, each healthy peer occurs in the attempts of a
bounded completed round, regardless of every attempt outcome. -/
def BoundedService (healthy : ByteArray → Prop)
    (execution : Execution eligible maximum deadline rounds) : Prop :=
  HealthyPeersAttempted healthy execution

/-- **M6 (fixed eligible set).** Actual completed production contact rounds do
not let failing or timing-out peers consume a healthy peer's cyclic turn. -/
theorem bounded_service
    (execution : Execution eligible maximum deadline rounds)
    (width : ∀ peer ∈ eligible, peer.size = 32)
    (within : eligible.length ≤ UInt64.size)
    (positive : 0 < maximum)
    (enough : (index eligible).toList.length ≤ rounds * maximum)
    (healthy : ByteArray → Prop) :
    BoundedService healthy execution :=
  healthy_peers_receive_bounded_attempts execution width within positive enough healthy

end Synchronicity.Goals.Mptsync.M6
