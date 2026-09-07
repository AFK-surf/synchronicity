import Synchronicity.CasReceiveProofs
import Synchronicity.CasStorePromises

/-! Receive/read composition over the same persisted database and files.
The Bao decoder remains trusted for the physical bytes it writes, independently
of the metadata planner and the read operation. -/
namespace Synchronicity.CasReceivePromises
open VerifiedCore VerifiedCore.Host VerifiedCore.Cas.Receive SimulatedHost
open CasReceiveProofs

/-- Receiving a slice commits its actual decoder output to the raw file later
opened by Read; row publication and physical backing share one state. -/
theorem slice_persists_payload (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (fresh : rows state.db "blobs" = []) (unleased : state.counters = [])
    (large : ¬ size ≤ inlineMax) (nonempty : window size served ≠ [])
    (verifies : state.decodeSlice root size (Cas.Serve.pairsOf (window size served)) 0 = true) :
    let result := SimulatedHost.run (writeSlice root size served 0 now tier) state
    result.1 = .ok (Cas.Serve.pairsOf (window size served)) ∧
    rows result.2.db "blobs" = [committed root size (window size served) none now tier] ∧
    lookupFile result.2.files ("cas_payload", root) = some
      (state.decodedPayload root size (Cas.Serve.pairsOf (window size served)) 0
        ((lookupFile state.files ("cas_payload", root)).getD ByteArray.empty)) ∧
    result.2.faults = [] := by
  cases finished : (Cas.IngestCommit.plan none size (window size served)).complete <;>
    simp [SimulatedHost.run, writeSlice, leased, admit, commit, metadata?, settle,
    VerifiedCore.Cas.Receive.access, VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
    Cas.IngestCommit.admit, Cas.IngestCommit.commitGroups, Cas.IngestCommit.commitIn,
    Cas.IngestCommit.decodeClaim, Cas.IngestCommit.claimColumns, committed,
    within, ensure, transactionOver, raise, performOver, Inject.inject, Program.mapEffects,
    execute, Interpreter.handle, storage, SimulatedHost.access, upsert, SimulatedHost.lease,
    SimulatedHost.bao, SimulatedHost.transaction, reply, fault, record, quiet, idle, clean,
    scanFailure, fresh, query, large, nonempty, verifies, fresh_accepted, finished, unleased, counter, setCounter,
    lookupFile, writeFile, upsertRows, Except.mapError, Except.map,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]


/-- Further receives settle against the existing raw row at the same size,
merge its persisted coverage, and retain the actual updated payload. -/
theorem further_slice_persists_payload (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (bitmap : Option ByteArray) (previousNow now : Int64) (tier : Cas.IngestCommit.Tier)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (existing : rows state.db "blobs" =
      [Cas.IngestCommit.values root size false bitmap none previousNow .local])
    (width : root.size = 32) (unleased : state.counters = [])
    (large : ¬ size ≤ inlineMax) (nonempty : window size served ≠ [])
    (verifies : state.decodeSlice root size (Cas.Serve.pairsOf (window size served)) 0 = true) :
    let result := SimulatedHost.run (writeSlice root size served 0 now tier) state
    result.1 = .ok (Cas.Serve.pairsOf (window size served)) ∧
    rows result.2.db "blobs" =
      [(Cas.IngestCommit.values root size
        (Cas.IngestCommit.plan (some ⟨size, false, false, bitmap⟩) size (window size served)).complete
        (let decided := Cas.IngestCommit.plan (some ⟨size, false, false, bitmap⟩) size (window size served)
         if decided.complete || decided.spans.isEmpty then none
         else some (Cas.Codec.encodeRawBitmap decided.spans)) none now tier).drop 1 ++ [("root", .blob root)]] ∧
    lookupFile result.2.files ("cas_payload", root) = some
      (state.decodedPayload root size (Cas.Serve.pairsOf (window size served)) 0
        ((lookupFile state.files ("cas_payload", root)).getD ByteArray.empty)) ∧
    result.2.faults = [] := by
  have accepted (incoming : List GroupSpan) :
      (Cas.IngestCommit.plan (some ⟨size, false, false, bitmap⟩) size incoming).accepted = true := by
    simp [Cas.IngestCommit.plan, planCasCommit, settleSize]
  cases finished : (Cas.IngestCommit.plan (some ⟨size, false, false, bitmap⟩) size (window size served)).complete <;>
    cases bitmap <;> cases tier <;>
    simp [SimulatedHost.run, writeSlice, leased, admit, commit, metadata?, settle,
    VerifiedCore.Cas.Receive.access, VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
    Cas.IngestCommit.admit, Cas.IngestCommit.commitGroups, Cas.IngestCommit.commitIn,
    Cas.IngestCommit.decodeClaim, Cas.IngestCommit.claimColumns,
    within, ensure, transactionOver, raise, performOver, Inject.inject, Program.mapEffects,
    execute, Interpreter.handle, storage, SimulatedHost.access, upsert, SimulatedHost.lease,
    SimulatedHost.bao, SimulatedHost.transaction, reply, fault, record, quiet, idle, clean,
    scanFailure, existing, query, large, nonempty, verifies, accepted, finished, unleased, counter, setCounter,
    Cas.IngestCommit.values, Cas.IngestCommit.assignments, project, selects, equals,
    Cas.Read.decodeRow, Cas.Read.blobField, Cas.Read.integerField, Cas.Read.optionalBlobField,
    Cas.Codec.blobField, Cas.Codec.integerField, Cas.Codec.optionalBlobField,
    conflict, conflictValue, assign, cell, width,
    lookupFile, writeFile, upsertRows, Except.mapError, Except.map, Except.bind, Except.pure,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]
  all_goals decide +kernel

/-- The actual receive row is the metadata later consumed by Read. -/
theorem recorded_metadata (state : State) (root : ByteArray) (size : UInt64)
    (complete : Bool) (bitmap inline : Option ByteArray) (now : Int64)
    (tier : Cas.IngestCommit.Tier) (width : root.size = 32)
    (stored : rows state.db "blobs" =
      [Cas.IngestCommit.values root size complete bitmap inline now tier]) :
    ∃ raw rest, CasReadPromises.observation state root = raw :: rest ∧
      Cas.Read.decodeRow raw = .ok ⟨size, complete, bitmap, inline⟩ := by
  refine ⟨project ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"]
    (Cas.IngestCommit.values root size complete bitmap inline now tier), [], ?_, ?_⟩
  · simp [CasReadPromises.observation, stored, selects, equals, project,
      Cas.IngestCommit.values, cell]
  · cases complete <;> cases bitmap <;> cases inline <;> cases tier <;>
      simp [project, Cas.IngestCommit.values, cell, Cas.Read.decodeRow,
        Cas.Read.blobField, Cas.Read.integerField, Cas.Read.optionalBlobField,
        Cas.Codec.blobField, Cas.Codec.integerField, Cas.Codec.optionalBlobField,
        width, bind, pure, Except.bind, Except.pure]

/-- A fully received verified object reads back as exactly that content. Bao's
contract specifies physical bytes independently of the read operation. The
same final state, including the raw committed row, is passed to Read. -/
theorem fully_received_content_reads_exactly (state : State) (root content : ByteArray)
    (served : List (UInt64 × UInt64)) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (fresh : rows state.db "blobs" = []) (unleased : state.counters = [])
    (width : root.size = 32) (fits : content.size < UInt64.size)
    (large : ¬ content.size.toUInt64 ≤ inlineMax)
    (nonempty : window content.size.toUInt64 served ≠ [])
    (verifies : state.decodeSlice root content.size.toUInt64
      (Cas.Serve.pairsOf (window content.size.toUInt64 served)) 0 = true)
    (decoded : state.decodedPayload root content.size.toUInt64
      (Cas.Serve.pairsOf (window content.size.toUInt64 served)) 0
      ((lookupFile state.files ("cas_payload", root)).getD ByteArray.empty) = content)
    (allReceived : (Cas.IngestCommit.plan none content.size.toUInt64
      (window content.size.toUInt64 served)).complete = true) :
    let received := SimulatedHost.run (writeSlice root content.size.toUInt64 served 0 now tier) state
    received.1 = .ok (Cas.Serve.pairsOf (window content.size.toUInt64 served)) ∧
    CasReadPromises.readResult received.2 root .all = .ok content.data.toList := by
  have facts := slice_persists_payload state root content.size.toUInt64 served now tier
    quiet idle clean fresh unleased large nonempty verifies
  refine ⟨facts.1, CasReadPromises.full_read_returns_content _ root
    ⟨content.size.toUInt64, true, none, none⟩ content facts.2.2.2 ?_ rfl⟩
  refine CasStorePromises.committed_row_represents _ root content false now tier width fits ?_ ?_
  · simpa [committed, allReceived] using facts.2.1
  · intro _
    simpa [decoded] using facts.2.2.1

end Synchronicity.CasReceivePromises
