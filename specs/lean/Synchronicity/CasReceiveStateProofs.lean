import Synchronicity.CasReceivePromises

/-! Actual receive execution over arbitrary shared raw databases. -/
namespace Synchronicity.CasReceiveStateProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Cas.Receive SimulatedHost


/-- A receive over any existing raw database commits the actual row planner
and decoder output. Unrelated objects, field order, prior leases and prior
receives are unrestricted; hypotheses describe the two real metadata reads. -/
theorem existing_receive_execution (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (input : UInt64) (now : Int64)
    (tier : Cas.IngestCommit.Tier) (claim : Cas.IngestCommit.Claim)
    (row : Cas.Read.Metadata) (raw : Row) (rest : List Row)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (observedClaim : Cas.IngestCommit.decodeClaim
      (query state.db "blobs" Cas.IngestCommit.claimColumns [("root", .blob root)] [] []) = .ok (some claim))
    (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row)
    (incomplete : row.complete = false)
    (admitted : (Cas.IngestCommit.plan (some claim) size []).accepted = true)
    (accepted : (Cas.IngestCommit.plan (some claim) size (window size served)).accepted = true)
    (large : ¬ size ≤ inlineMax) (nonempty : window size served ≠ [])
    (verifies : state.decodeSlice root size (Cas.Serve.pairsOf (window size served)) input = true) :
    let result := SimulatedHost.run (writeSlice root size served input now tier) state
    let planned := Cas.IngestCommit.plan (some claim) size (window size served)
    result.1 = .ok (Cas.Serve.pairsOf (window size served)) ∧
    rows result.2.db "blobs" = upsertRows (rows state.db "blobs")
      (Cas.IngestCommit.values root size planned.complete
        (if planned.complete || planned.spans.isEmpty then none
         else some (Cas.Codec.encodeRawBitmap planned.spans)) none now tier)
      ["root"] Cas.IngestCommit.assignments ∧
    lookupFile result.2.files ("cas_payload", root) = some
      (state.decodedPayload root size (Cas.Serve.pairsOf (window size served)) input
        ((lookupFile state.files ("cas_payload", root)).getD ByteArray.empty)) ∧
    result.2.faults = [] ∧ result.2.pending = none ∧
    result.2.hash = state.hash ∧ result.2.decodeSlice = state.decodeSlice ∧
    result.2.decodedPayload = state.decodedPayload ∧ result.2.decodeSliceFailure = state.decodeSliceFailure ∧
    result.2.scanFault = state.scanFault := by
  have selected (table : String) (fields : Fields) :
      selects ⟨table, fields, [], []⟩ = fun row => equals row fields := by
    funext row
    simp [selects]
  simp only [unordered_query] at observedClaim
  simp only [CasReadPromises.observation, selected] at observed
  cases finished : (Cas.IngestCommit.plan (some claim) size (window size served)).complete <;>
    simp [SimulatedHost.run, writeSlice, leased, admit, commit, metadata?, settle,
      VerifiedCore.Cas.Receive.access, VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
      Cas.IngestCommit.admit, Cas.IngestCommit.commitGroups, Cas.IngestCommit.commitIn,
      within, ensure, transactionOver, raise, performOver, Inject.inject, Program.mapEffects,
      execute, Interpreter.handle, storage, SimulatedHost.access, upsert, SimulatedHost.lease,
      SimulatedHost.bao, SimulatedHost.transaction, reply, fault, record, quiet, idle, clean,
      scanFailure, observedClaim, observed, decoded, incomplete, admitted, accepted,
      unordered_query, selected, large, nonempty, verifies, finished, counter, setCounter,
      lookupFile, writeFile, Except.mapError, Except.map,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- The first slice can start among unrelated objects and arbitrary lease
counters. The actual inserted metadata and physical bytes share one result;
the decoder contract remains available for all subsequent transfers. -/
theorem fresh_receive_execution (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (input : UInt64) (now : Int64)
    (tier : Cas.IngestCommit.Tier)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (absent : (rows state.db "blobs").filter (fun row => equals row [("root", .blob root)]) = [])
    (large : ¬ size ≤ inlineMax) (nonempty : window size served ≠ [])
    (verifies : state.decodeSlice root size (Cas.Serve.pairsOf (window size served)) input = true) :
    let result := SimulatedHost.run (writeSlice root size served input now tier) state
    let planned := Cas.IngestCommit.plan none size (window size served)
    result.1 = .ok (Cas.Serve.pairsOf (window size served)) ∧
    rows result.2.db "blobs" = upsertRows (rows state.db "blobs")
      (Cas.IngestCommit.values root size planned.complete
        (if planned.complete || planned.spans.isEmpty then none
         else some (Cas.Codec.encodeRawBitmap planned.spans)) none now tier)
      ["root"] Cas.IngestCommit.assignments ∧
    lookupFile result.2.files ("cas_payload", root) = some
      (state.decodedPayload root size (Cas.Serve.pairsOf (window size served)) input
        ((lookupFile state.files ("cas_payload", root)).getD ByteArray.empty)) ∧
    result.2.faults = [] ∧ result.2.pending = none ∧
    result.2.hash = state.hash ∧ result.2.decodeSlice = state.decodeSlice ∧
    result.2.decodedPayload = state.decodedPayload ∧ result.2.decodeSliceFailure = state.decodeSliceFailure ∧
    result.2.scanFault = state.scanFault := by
  have selected (table : String) (fields : Fields) :
      selects ⟨table, fields, [], []⟩ = fun row => equals row fields := by
    funext row
    simp [selects]
  cases finished : (Cas.IngestCommit.plan none size (window size served)).complete <;>
    simp [SimulatedHost.run, writeSlice, leased, admit, commit, metadata?, settle,
      VerifiedCore.Cas.Receive.access, VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
      Cas.IngestCommit.admit, Cas.IngestCommit.commitGroups, Cas.IngestCommit.commitIn,
      within, ensure, transactionOver, raise, performOver, Inject.inject, Program.mapEffects,
      execute, Interpreter.handle, storage, SimulatedHost.access, upsert, SimulatedHost.lease,
      SimulatedHost.bao, SimulatedHost.transaction, reply, fault, record, quiet, idle, clean,
      scanFailure, absent, Cas.IngestCommit.decodeClaim, CasReceiveProofs.fresh_accepted,
      unordered_query, selected, large, nonempty, verifies, finished, counter, setCounter,
      lookupFile, writeFile, Except.mapError, Except.map,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- Receiving another slice of an already complete version does not rewrite
its saved bytes or metadata. Empty requests also make no storage change. -/
theorem complete_receive_execution (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (input : UInt64) (now : Int64)
    (tier : Cas.IngestCommit.Tier) (claim : Cas.IngestCommit.Claim)
    (row : Cas.Read.Metadata) (raw : Row) (rest : List Row)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observedClaim : Cas.IngestCommit.decodeClaim
      (query state.db "blobs" Cas.IngestCommit.claimColumns [("root", .blob root)] [] []) = .ok (some claim))
    (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row)
    (complete : row.complete = true)
    (admitted : (Cas.IngestCommit.plan (some claim) size []).accepted = true) :
    let result := SimulatedHost.run (writeSlice root size served input now tier) state
    result.1 = .ok [] ∧ result.2.db = state.db ∧ result.2.files = state.files ∧
    result.2.faults = [] ∧ result.2.pending = none ∧ result.2.hash = state.hash ∧
    result.2.decodeSlice = state.decodeSlice ∧ result.2.decodedPayload = state.decodedPayload ∧
    result.2.decodeSliceFailure = state.decodeSliceFailure ∧ result.2.scanFault = state.scanFault := by
  have selected (table : String) (fields : Fields) :
      selects ⟨table, fields, [], []⟩ = fun row => equals row fields := by
    funext row
    simp [selects]
  simp only [unordered_query] at observedClaim
  simp only [CasReadPromises.observation, selected] at observed
  by_cases empty : window size served = []
  · simp [SimulatedHost.run, writeSlice, empty, execute, pure, ExceptT.pure, ExceptT.run, ExceptT.mk, quiet, idle]
  · simp [SimulatedHost.run, writeSlice, leased, admit, metadata?,
      VerifiedCore.Cas.Receive.access, VerifiedCore.Cas.Receive.lease,
      Cas.IngestCommit.admit, within, ensure, raise, performOver, Inject.inject, Program.mapEffects,
      execute, Interpreter.handle, SimulatedHost.access, SimulatedHost.lease,
      reply, fault, record, quiet, idle, observedClaim, observed, decoded, complete, admitted,
      selected, empty, counter, setCounter, Except.mapError, Except.map,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- A decoder may write a verified prefix and then fail. The failed receive
keeps the committed coverage unchanged; its physical prefix remains in the
same raw file for retry. Byte preservation is a separate Bao contract. -/
theorem interrupted_decoder_keeps_committed_metadata (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (input : UInt64) (now : Int64)
    (tier : Cas.IngestCommit.Tier) (claim : Cas.IngestCommit.Claim)
    (row : Cas.Read.Metadata) (raw : Row) (rest : List Row)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (observedClaim : Cas.IngestCommit.decodeClaim
      (query state.db "blobs" Cas.IngestCommit.claimColumns [("root", .blob root)] [] []) = .ok (some claim))
    (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row)
    (incomplete : row.complete = false)
    (admitted : (Cas.IngestCommit.plan (some claim) size []).accepted = true)
    (large : ¬ size ≤ inlineMax) (nonempty : window size served ≠ [])
    (interrupted : state.decodeSlice root size (Cas.Serve.pairsOf (window size served)) input = false) :
    let result := SimulatedHost.run (writeSlice root size served input now tier) state
    result.1 = .error (.host state.decodeSliceFailure) ∧
    result.2.db = state.db ∧
    lookupFile result.2.files ("cas_payload", root) = some
      (state.decodedPayload root size (Cas.Serve.pairsOf (window size served)) input
        ((lookupFile state.files ("cas_payload", root)).getD ByteArray.empty)) ∧
    result.2.faults = [] ∧ result.2.pending = none ∧
    result.2.hash = state.hash ∧ result.2.decodeSlice = state.decodeSlice ∧
    result.2.decodedPayload = state.decodedPayload ∧ result.2.decodeSliceFailure = state.decodeSliceFailure ∧
    result.2.scanFault = state.scanFault := by
  have selected (table : String) (fields : Fields) :
      selects ⟨table, fields, [], []⟩ = fun row => equals row fields := by
    funext row
    simp [selects]
  simp only [unordered_query] at observedClaim
  simp only [CasReadPromises.observation, selected] at observed
  simp [SimulatedHost.run, writeSlice, leased, admit, commit, metadata?, settle,
      VerifiedCore.Cas.Receive.access, VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
      Cas.IngestCommit.admit, Cas.IngestCommit.commitGroups, Cas.IngestCommit.commitIn,
      within, ensure, transactionOver, raise, performOver, Inject.inject, Program.mapEffects,
      execute, Interpreter.handle, SimulatedHost.access, SimulatedHost.lease,
      SimulatedHost.bao, reply, fault, record, quiet, idle, clean,
      scanFailure, observedClaim, observed, decoded, incomplete, admitted,
      selected, large, nonempty, interrupted, counter, setCounter,
      lookupFile, writeFile, Except.mapError, Except.map,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- An unsuccessful attempt before the first committed slice may leave
physical decoder writes, but leaves the object absent and permits a retry on
that same raw state. Empty requests have the same metadata behavior. -/
theorem unverified_fresh_receive (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (input : UInt64) (now : Int64)
    (tier : Cas.IngestCommit.Tier)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (absent : (rows state.db "blobs").filter (fun row => equals row [("root", .blob root)]) = [])
    (large : ¬ size ≤ inlineMax)
    (unverified : window size served = [] ∨
      state.decodeSlice root size (Cas.Serve.pairsOf (window size served)) input = false) :
    let result := SimulatedHost.run (writeSlice root size served input now tier) state
    result.2.db = state.db ∧ result.2.faults = [] ∧ result.2.pending = none ∧
    result.2.hash = state.hash ∧ result.2.decodeSlice = state.decodeSlice ∧
    result.2.decodedPayload = state.decodedPayload ∧ result.2.scanFault = state.scanFault := by
  by_cases empty : window size served = []
  · simp [SimulatedHost.run, writeSlice, empty, execute, pure, ExceptT.pure, ExceptT.run, ExceptT.mk, quiet, idle]
  · have interrupted := unverified.resolve_left empty
    have selected (table : String) (fields : Fields) :
        selects ⟨table, fields, [], []⟩ = fun row => equals row fields := by
      funext row
      simp [selects]
    simp [SimulatedHost.run, writeSlice, leased, admit, metadata?,
      VerifiedCore.Cas.Receive.access, VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
      Cas.IngestCommit.admit, Cas.IngestCommit.decodeClaim,
      within, ensure, raise, performOver, Inject.inject, Program.mapEffects,
      execute, Interpreter.handle, SimulatedHost.access, SimulatedHost.lease,
      SimulatedHost.bao, reply, fault, record, quiet, idle, clean,
      scanFailure, absent, CasReceiveProofs.fresh_accepted,
      selected, large, empty, interrupted, counter, setCounter, Except.mapError, Except.map,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

end Synchronicity.CasReceiveStateProofs
