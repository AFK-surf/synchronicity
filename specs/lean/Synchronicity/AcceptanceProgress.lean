import Synchronicity.ReconciliationAcceptance

/-! A positive execution theorem for reconciliation acceptance.  Unlike the
existing consequences of a successful acceptance, this module obtains that
success from independently inspectable host, crypto, authorization, and raw
database facts.

The first theorem deliberately covers a fresh origin: neither complete nor
pending has a stored pointer and no history signature can conflict with the
candidate.  Nonempty floors require the analogous raw joined-head decoding
conditions and are kept out of this statement rather than hidden in an
assumption that `accept` already returned `.pending`. -/
namespace Synchronicity.AcceptanceProgress
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
open Synchronicity.SimulatedHost

/-- The concrete rooted authorization record audited by `FreshReady`.  It is
the same nine-column raw representation consumed by `Authorization.readBindings`. -/
def staticBindingRow (head : Head) (addedAt : Int64) : Fields :=
  [("origin_id", .text (Origin.canonical head.origin)),
   ("node_id", .blob head.signedBy),
   ("source", .text "static"),
   ("domain", .null),
   ("issuer", .text ""),
   ("spaces", .null),
   ("note", .null),
   ("added_at", .integer addedAt),
   ("expires_at", .null)]

/-- Independently checkable facts and actual suboperation certificates for a
fresh host. `originSyntax` and the raw relation expose the authorization input;
`authorizationExecution` certifies that the production reader decoded that
input and found the binding.  The certificate is deliberately an execution of
`liveForKey`, not a premise about the result of `Reconcile.accept` itself.

The later certificates expose history compatibility, empty complete/pending
floors, the candidate write, trimming, and commit separately.  This makes the
remaining boundary explicit until raw-row positive execution lemmas discharge
those certificates automatically. -/
structure FreshReady (state : State) (head : Head) (addedAt : Int64) where
  noOpenTransaction : state.pending = none
  noFailures : state.faults = []
  noScanFailure : state.scanFault = none
  signatureValid :
    state.verifySignature head.signedBy (Reconcile.signingInput head) head.signature = true
  signingKeyWidth : head.signedBy.size = 32
  signingKeyValid : state.validateKey head.signedBy.data.toList = true
  originSyntax : Origin.parseSyntax (Origin.canonical head.origin) = .ok head.origin
  originKeyValid : ∀ bytes, head.origin = .key bytes → state.validateKey bytes = true
  authorizationRows : rows state.db "bindings" = [staticBindingRow head addedAt]
  noClockFloor : rows state.db "config" = []
  noHeads : rows state.db "heads" = []
  noHistory : rows state.db "head_history" = []
  representableSequence : head.seq ≤ 9223372036854775807
  instant : Int64
  afterClock : State
  live : List Authorization.Binding
  afterAuthorization : State
  afterRecord : State
  afterComplete : State
  afterPending : State
  afterWrite : State
  afterTrim : State
  afterCommit : State
  clockExecution :
    execute (within Reconcile.authorizationError
      (Authorization.trustInstant state.nextTx state.now) : History.Action Int64)
      (SimulatedHost.record
        { SimulatedHost.record state "verifySignature" with
          pending := some (state.nextTx, state.db), nextTx := state.nextTx + 1 }
        "begin") = (.ok instant, afterClock)
  authorizationExecution :
    execute (within Reconcile.authorizationError
      (Authorization.liveForKey state.nextTx head.signedBy instant) :
        History.Action (List Authorization.Binding)) afterClock =
      (.ok live, afterAuthorization)
  originBound : live.any (·.origin == head.origin) = true
  recordExecution :
    execute (Reconcile.record state.nextTx head state.now) afterAuthorization =
      (.ok (), afterRecord)
  completeExecution :
    execute (History.readSlot state.nextTx (Origin.canonical head.origin) "complete") afterRecord =
      (.ok [], afterComplete)
  pendingExecution :
    execute (History.readSlot state.nextTx (Origin.canonical head.origin) "pending") afterComplete =
      (.ok [], afterPending)
  writeExecution :
    execute (Reconcile.putSlot state.nextTx "pending" head state.now state.now) afterPending =
      (.ok (), afterWrite)
  trimExecution :
    execute (Reconcile.trimForks state.nextTx (Origin.canonical head.origin) head.seq 0) afterWrite =
      (.ok (), afterTrim)
  commitExecution :
    (Interpreter.handle
      (Inject.inject (F := History.Effects) (Storage.commit state.nextTx)) afterTrim) =
      (.ok (), afterCommit)

/-- A valid, rooted advertisement for a fresh origin takes the actual
`Reconcile.accept` execution through commit and returns `.pending`. -/
theorem fresh_accepts (head : Head) (addedAt : Int64) (state : State)
    (ready : FreshReady state head addedAt) :
    (execute (Reconcile.accept head state.now 0) state).1 = .ok .pending := by
  have verified :
      execute (raise History.Error.host
        (Crypto.verifyEd25519 head.signedBy (Reconcile.signingInput head) head.signature) :
          History.Action Bool) state =
        (.ok true, SimulatedHost.record state "verifySignature") := by
    simp [raise, performOver, ExceptT.mk, Except.mapError,
      Inject.inject, Interpreter.handle, execute, SimulatedHost.crypto,
      SimulatedHost.reply, SimulatedHost.fault, ready.noFailures, ready.signatureValid]
  have opened :
      Interpreter.handle (Inject.inject (F := History.Effects) Storage.begin)
        (SimulatedHost.record state "verifySignature") =
      (.ok state.nextTx,
        SimulatedHost.record
          { SimulatedHost.record state "verifySignature" with
            pending := some (state.nextTx, state.db), nextTx := state.nextTx + 1 }
          "begin") := by
    simp [Inject.inject, Interpreter.handle, SimulatedHost.storage, SimulatedHost.reply,
      SimulatedHost.fault, ready.noFailures, ready.noOpenTransaction,
      SimulatedHost.record]
  unfold Reconcile.accept
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
  rw [verified]
  dsimp only
  simp only [Bool.not_true, Bool.false_eq_true, if_false, transactionOver, ExceptT.mk,
    bind, Program.bind, execute]
  rw [opened]
  rw [execute_bind]
  dsimp only [ExceptT.run]
  rw [execute_bind]
  rw [ready.clockExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind]
  rw [ready.authorizationExecution]
  dsimp only [ExceptT.bindCont]
  simp only [ready.originBound, Bool.not_true, Bool.false_eq_true, if_false]
  rw [execute_bind]
  rw [ready.recordExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind]
  rw [ready.completeExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind]
  rw [ready.pendingExecution]
  dsimp only [ExceptT.bindCont]
  simp only [List.nil_append, List.all_nil, ↓reduceIte]
  rw [execute_bind]
  rw [ready.writeExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind]
  rw [ready.trimExecution]
  dsimp only [ExceptT.bindCont]
  have returned : execute (pure Acceptance.pending : History.Action Acceptance)
      ready.afterTrim = (.ok .pending, ready.afterTrim) := rfl
  rw [returned]
  dsimp only
  unfold execute
  rw [ready.commitExecution]
  rfl

/-- The positive execution theorem also establishes the durable observable
effect: after commit, the unique pending row for this origin points at the
candidate. -/
theorem fresh_installs_pending (head : Head) (addedAt : Int64) (state : State)
    (ready : FreshReady state head addedAt) :
    let table := rows (execute (Reconcile.accept head state.now 0) state).2.db "heads"
    (∃ row ∈ table,
      ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = true) ∧
    (∀ row ∈ table,
      ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = true →
      ReconciliationSlots.pointsTo row head) := by
  exact ReconciliationAcceptance.accepted_installs_pending head state.now 0 state
    (fresh_accepts head addedAt state ready)

end Synchronicity.AcceptanceProgress
