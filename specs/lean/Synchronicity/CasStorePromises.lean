import Synchronicity.IngestCommitProofs
import Synchronicity.CasReadPromises
import VerifiedCore.Cas.Input

/-! Store/read composition uses SimulatedHost.State directly. No reader adapter
or operation-specific interpreter appears in these proofs. -/
namespace Synchronicity.CasStorePromises
open VerifiedCore VerifiedCore.Host SimulatedHost

private theorem fresh_complete (size : UInt64) :
    (Cas.IngestCommit.completePlan none size).accepted = true ∧
    (Cas.IngestCommit.completePlan none size).complete = true := by
  have accepted : (Cas.IngestCommit.completePlan none size).accepted = true := by
    simp [Cas.IngestCommit.completePlan, Cas.IngestCommit.plan, planCasCommit, settleSize]
  exact ⟨accepted, IngestCommitProofs.complete_plan_accepted_complete none size accepted⟩

/-- Generic raw query/decoder bridge for a newly committed complete row. -/
theorem committed_row_represents (state : State) (root bytes : ByteArray) (inline : Bool)
    (now : Int64) (tier : Cas.IngestCommit.Tier) (width : root.size = 32)
    (fits : bytes.size < UInt64.size)
    (stored : rows state.db "blobs" = [Cas.IngestCommit.values root bytes.size.toUInt64 true none
      (if inline then some bytes else none) now tier])
    (physical : inline = false → lookupFile state.files ("cas_payload", root) = some bytes) :
    CasReadPromises.Represents state root
      ⟨bytes.size.toUInt64, true, none, if inline then some bytes else none⟩ bytes := by
  constructor
  · refine ⟨project ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"]
        (Cas.IngestCommit.values root bytes.size.toUInt64 true none (if inline then some bytes else none) now tier),
      [], ?_, ?_⟩
    · simp [CasReadPromises.observation, stored, selects, equals, project,
        Cas.IngestCommit.values, cell]
    · cases inline <;> cases tier <;>
        simp [project, Cas.IngestCommit.values, cell, Cas.Read.decodeRow,
          Cas.Read.blobField, Cas.Read.integerField, Cas.Read.optionalBlobField,
          Cas.Codec.blobField, Cas.Codec.integerField, Cas.Codec.optionalBlobField,
          width, bind, pure, Except.bind, Except.pure]
  · constructor
    · exact UInt64.toNat_ofNat_of_lt' fits
    · cases inline <;> simp_all

/-- A successful inline store establishes the shared state's read invariant. -/
theorem inline_store (state : State) (bytes : ByteArray) (now : Int64)
    (tier : Cas.IngestCommit.Tier) (fresh : rows state.db "blobs" = [])
    (idle : state.pending = none) (quiet : state.faults = [])
    (width : (state.hash bytes).size = 32) :
    let result := SimulatedHost.run (Cas.Input.inlineBytes bytes now tier) state
    result.1 = .ok ⟨state.hash bytes, bytes.size.toUInt64⟩ ∧
    rows result.2.db "blobs" = [Cas.IngestCommit.values (state.hash bytes) bytes.size.toUInt64 true none (some bytes) now tier] ∧
    result.2.faults = [] := by
  have accepted := (fresh_complete bytes.size.toUInt64).1
  have complete := (fresh_complete bytes.size.toUInt64).2
  simp only [Cas.IngestCommit.completePlan] at accepted complete
  simp [SimulatedHost.run, Cas.Input.inlineBytes, Cas.Input.hashInline,
    Cas.IngestCommit.commitComplete, Cas.IngestCommit.commitCompleteIn, Cas.IngestCommit.commitIn,
    transactionOver, within, raise, performOver, Inject.inject, Program.mapEffects,
    execute, Interpreter.handle, construct, storage, upsert, SimulatedHost.transaction, reply, fault, record,
    quiet, idle, query, fresh, upsertRows, width,
    Cas.IngestCommit.decodeClaim, accepted, complete, Except.mapError,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- You get back what you stored: read runs on the actual final State. This
allows arbitrary unrelated tables/files and arbitrary inline byte contents. -/
theorem you_get_back_what_you_stored_inline (state : State) (bytes : ByteArray)
    (now : Int64) (tier : Cas.IngestCommit.Tier) (fresh : rows state.db "blobs" = [])
    (idle : state.pending = none) (quiet : state.faults = [])
    (width : (state.hash bytes).size = 32) (fits : bytes.size < UInt64.size) :
    let stored := SimulatedHost.run (Cas.Input.inlineBytes bytes now tier) state
    stored.1 = .ok ⟨state.hash bytes, bytes.size.toUInt64⟩ ∧
    CasReadPromises.readResult stored.2 (state.hash bytes) .all = .ok bytes.data.toList := by
  have facts := inline_store state bytes now tier fresh idle quiet width
  exact ⟨facts.1, CasReadPromises.full_read_returns_content _ _ _ _ facts.2.2
    (committed_row_represents _ _ bytes true now tier width fits facts.2.1 (by simp)) rfl⟩



/-- Raw immutable command input in the shared filesystem. -/
def inputState (bytes : ByteArray) (hash : ByteArray → ByteArray) : State :=
  { files := [(("input", ByteArray.empty), bytes)], hash }

/-- Full byte ingestion leaves its actual committed row and backing bytes in
the same state later consumed by read. No result is reconstructed by a host. -/
theorem bytes_store (bytes : ByteArray) (hash : ByteArray → ByteArray)
    (now : Int64) (tier : Cas.IngestCommit.Tier) (policy : Cas.Ingest.DirectoryPolicy)
    (width : (hash bytes).size = 32) (fits : bytes.size < UInt64.size) :
    let result := SimulatedHost.run (Cas.Input.run (.bytes bytes.size.toUInt64) now tier policy) (inputState bytes hash)
    result.1 = .ok ⟨hash bytes, bytes.size.toUInt64⟩ ∧
    rows result.2.db "blobs" = [Cas.IngestCommit.values (hash bytes) bytes.size.toUInt64 true none
      (if bytes.size ≤ 16384 then some bytes else none) now tier] ∧
    (bytes.size > 16384 → lookupFile result.2.files ("cas_payload", hash bytes) = some bytes) ∧
    result.2.faults = [] := by
  have accepted := (fresh_complete bytes.size.toUInt64).1
  have complete := (fresh_complete bytes.size.toUInt64).2
  simp only [Cas.IngestCommit.completePlan] at accepted complete
  by_cases small : bytes.size ≤ 16384
  all_goals simp [SimulatedHost.run, inputState,
    Cas.Input.run, Cas.Input.openSource, Cas.Input.file, Cas.Input.closeSource,
    Cas.Input.readExact, Cas.Input.capturedBytes, Cas.Input.inlineBytes, Cas.Input.hashInline,
    Cas.Input.captured, Cas.Ingest.run, Cas.Ingest.construct, Cas.Ingest.closeSource,
    Cas.Ingest.resource, Cas.Ingest.lease, Cas.Ingest.publish, Cas.Ingest.syncParent, Cas.Ingest.commit,
    Cas.IngestCommit.commitComplete, Cas.IngestCommit.commitCompleteIn, Cas.IngestCommit.commitIn,
    transactionOver, within, ensure, onFailure, raise, performOver, observe, Inject.inject,
    Program.mapEffects, execute, Interpreter.handle, file, construct, resources, lease,
    storage, upsert, SimulatedHost.transaction, reply, fileReply, fault, record, opened,
    temporary, putTemporary, lookupFile, writeFile, counter, setCounter, query, rows,
    upsertRows, setRows, width, Cas.IngestCommit.decodeClaim,
    accepted, complete, Except.mapError, Except.map,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk, UInt64.le_iff_toNat_le, UInt64.toNat_ofNat_of_lt' fits, small, Nat.not_lt.mpr, beq_iff_eq]

theorem you_get_back_what_you_stored (bytes : ByteArray) (hash : ByteArray → ByteArray)
    (now : Int64) (tier : Cas.IngestCommit.Tier) (policy : Cas.Ingest.DirectoryPolicy)
    (width : (hash bytes).size = 32) (fits : bytes.size < UInt64.size) :
    let stored := SimulatedHost.run (Cas.Input.run (.bytes bytes.size.toUInt64) now tier policy) (inputState bytes hash)
    stored.1 = .ok ⟨hash bytes, bytes.size.toUInt64⟩ ∧
    CasReadPromises.readResult stored.2 (hash bytes) .all = .ok bytes.data.toList := by
  have facts := bytes_store bytes hash now tier policy width fits
  refine ⟨facts.1, CasReadPromises.full_read_returns_content _ _
    ⟨bytes.size.toUInt64, true, none, if bytes.size ≤ 16384 then some bytes else none⟩
    _ facts.2.2.2 ?_ rfl⟩
  by_cases small : bytes.size ≤ 16384
  · simpa [small] using committed_row_represents _ (hash bytes) bytes true now tier width fits
      (by simpa [small] using facts.2.1) (by simp)
  · simpa [small] using committed_row_represents _ (hash bytes) bytes false now tier width fits
      (by simpa [small] using facts.2.1) (fun _ => facts.2.2.1 (by omega))

end Synchronicity.CasStorePromises
