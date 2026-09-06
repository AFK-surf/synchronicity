import VerifiedCore.Cas.Input
import Synchronicity.IngestCommitProofs
import Synchronicity.CasReadPromises

/-! Store/read composition on a fresh object. The host interprets raw effects;
metadata is read back from the fields actually written by the Lean program.
Construction/hashing is trusted to return the supplied root for supplied bytes. -/
namespace Synchronicity.CasStorePromises
open VerifiedCore VerifiedCore.Host
noncomputable section
local instance (p : Prop) : Decidable p := Classical.propDecidable p

structure State where
  fields : Fields := []
  temporary : ByteArray := ByteArray.empty
  payload : ByteArray := ByteArray.empty

/-- Successful raw capabilities for one fresh object, with exact request guards.
Other objects are outside this invocation's state and remain untouched. -/
structure Host where
  root : ByteArray
  bytes : ByteArray

def cell (fields : Fields) (column : String) : Cell :=
  ((fields.find? fun field => field.1 == column).map Prod.snd).getD .null

def projection (fields : Fields) : Row :=
  ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"].map (cell fields)

def storage (host : Host) : {A : Type} → Storage A → State → Option (A × State)
  | _, .begin, state => some (.ok 7, state)
  | _, .commit tx, state => if tx = 7 then some (.ok (), state) else none
  | _, .readRows tx relation columns equals order joins, state =>
      if tx = 7 ∧ relation = "blobs" ∧ columns = Cas.IngestCommit.claimColumns ∧
          equals = [("root", .blob host.root)] ∧ order = [] ∧ joins = [] ∧ state.fields = [] then
        some (.ok [], state) else none
  | _, _, _ => none

def upsert (host : Host) : {A : Type} → Upsert A → State → Option (A × State)
  | _, .write tx relation fields conflicts assignments, state =>
      if tx = 7 ∧ relation = "blobs" ∧ conflicts = ["root"] ∧
          assignments = Cas.IngestCommit.assignments ∧ state.fields = [] ∧
          cell fields "root" = .blob host.root then
        some (.ok (), { state with fields }) else none

def commitStep (host : Host) : {A : Type} → Cas.IngestCommit.Effects A → State → Option (A × State)
  | _, .left effect, state => storage host effect state
  | _, .right (.left effect), state => upsert host effect state
  | _, .right (.right _), _ => none

/-- A generic interpreter; no CAS policy is implemented here. -/
def execute (step : {B : Type} → E B → State → Option (B × State)) :
    Program E A → State → Option (A × State)
  | .pure value, state => some (value, state)
  | .request effect resume, state => do
      let (reply, state) ← step effect state
      execute step (resume reply) state

private theorem fresh_complete (size : UInt64) :
    (Cas.IngestCommit.completePlan none size).accepted = true ∧
    (Cas.IngestCommit.completePlan none size).complete = true := by
  have accepted : (Cas.IngestCommit.completePlan none size).accepted = true := by
    simp [Cas.IngestCommit.completePlan, Cas.IngestCommit.plan, planCasCommit, settleSize]
  exact ⟨accepted, IngestCommitProofs.complete_plan_accepted_complete none size accepted⟩

/-- The actual metadata commit writes exactly the fields subsequently read. -/
theorem fresh_commit (host : Host) (size : UInt64) (inline : Option ByteArray)
    (now : Int64) (tier : Cas.IngestCommit.Tier) (state : State) (fresh : state.fields = []) :
    execute (commitStep host) (Cas.IngestCommit.commitComplete host.root size inline now tier).run state =
      some (.ok (), { state with fields := Cas.IngestCommit.values host.root size true none inline now tier }) := by
  have accepted := (fresh_complete size).1
  have complete := (fresh_complete size).2
  simp only [Cas.IngestCommit.completePlan] at accepted complete
  simp [Cas.IngestCommit.commitComplete, Cas.IngestCommit.commitCompleteIn,
    Cas.IngestCommit.commitIn, transactionOver, raise, performOver, Inject.inject,
    execute, commitStep, storage, upsert, fresh, Cas.IngestCommit.decodeClaim,
    accepted, complete, Cas.IngestCommit.values, cell, Except.mapError,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]

/-- Decode the row written by the commit, without assuming a decoded snapshot. -/
theorem committed_row_decodes (host : Host) (size : UInt64) (inline : Option ByteArray)
    (now : Int64) (tier : Cas.IngestCommit.Tier) (width : host.root.size = 32) :
    Cas.Read.decodeRow (projection (Cas.IngestCommit.values host.root size true none inline now tier)) =
      .ok ⟨size, true, none, inline⟩ := by
  cases inline <;> cases tier <;>
    simp [projection, cell, Cas.IngestCommit.values, Cas.Read.decodeRow,
      Cas.Read.blobField, Cas.Read.integerField, Cas.Read.optionalBlobField,
      Cas.Codec.blobField, Cas.Codec.integerField, Cas.Codec.optionalBlobField,
      width, bind, pure, Except.bind, Except.pure]

def file (host : Host) : {A : Type} → FileIO A → State → Option (A × State)
  | _, .open space key, state =>
      if space = "input" ∧ key = ByteArray.empty then some (.ok 9, state) else none
  | _, .readAt handle offset count, state =>
      if handle = 9 ∧ offset = 0 ∧ count = host.bytes.size.toUInt64 then
        some (.ok host.bytes, state) else none
  | _, .close handle, state => if handle = 9 then some (.ok (), state) else none
  | _, _, _ => none

def construct (host : Host) : {A : Type} → Construct A → State → Option (A × State)
  | _, .hash bytes, state =>
      if bytes = host.bytes then some (.ok host.root, state) else none
  | _, .build source payload outboard size, state =>
      if source = 9 ∧ payload = 10 ∧ outboard = 11 ∧ size = host.bytes.size.toUInt64 then
        some (.ok host.root, { state with temporary := host.bytes }) else none

def resources (host : Host) : {A : Type} → Resources A → State → Option (A × State)
  | _, .createTemporary space, state =>
      if space = "cas_payload" then some (.ok 10, state)
      else if space = "cas_outboard" then some (.ok 11, state) else none
  | _, .flush handle, state =>
      if handle = 10 ∨ handle = 11 then some (.ok (), state) else none
  | _, .replace handle space key, state =>
      if key = host.root ∧ handle = 10 ∧ space = "cas_payload" then
        some (.ok (), { state with payload := state.temporary })
      else if key = host.root ∧ handle = 11 ∧ space = "cas_outboard" then
        some (.ok (), state) else none
  | _, .syncParent space key, state =>
      if key = host.root ∧ (space = "cas_payload" ∨ space = "cas_outboard") then
        some (.ok .synced, state) else none
  | _, .discard handle, state =>
      if handle = 10 ∨ handle = 11 then some (.ok (), state) else none

def lease (host : Host) : {A : Type} → Lease A → State → Option (A × State)
  | _, .acquire space key, state =>
      if space = "cas_writers" ∧ key = host.root then some (.ok 12, state) else none
  | _, .release token, state => if token = 12 then some (.ok (), state) else none

def ingestStep (host : Host) : {A : Type} → Cas.Ingest.Effects A → State → Option (A × State)
  | _, .left (.left effect), state => file host effect state
  | _, .left (.right effect), state => construct host effect state
  | _, .right (.left effect), state => commitStep host effect state
  | _, .right (.right (.left effect)), state => resources host effect state
  | _, .right (.right (.right effect)), state => lease host effect state

def source (host : Host) : {A : Type} → SourceIO A → State → Option (A × State)
  | _, .freeze bytes, state => if bytes = host.bytes then some (.ok 9, state) else none
  | _, _, _ => none

def inputStep (host : Host) : {A : Type} → Cas.Input.Effects A → State → Option (A × State)
  | _, .left effect, state => ingestStep host effect state
  | _, .right effect, state => source host effect state

/-- The captured-source ingestion operation publishes the constructed bytes
before committing the metadata which makes them readable. -/
theorem captured_store (host : Host) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (policy : Cas.Ingest.DirectoryPolicy) (state : State) (fresh : state.fields = [])
    (width : host.root.size = 32) :
    execute (ingestStep host) (Cas.Ingest.run 9 host.bytes.size.toUInt64 now tier policy).run state =
      some (.ok host.root,
        { fields := Cas.IngestCommit.values host.root host.bytes.size.toUInt64 true none none now tier,
          temporary := host.bytes, payload := host.bytes }) := by
  have accepted := (fresh_complete host.bytes.size.toUInt64).1
  have complete := (fresh_complete host.bytes.size.toUInt64).2
  simp only [Cas.IngestCommit.completePlan] at accepted complete
  simp [Cas.Ingest.run, Cas.Ingest.construct, Cas.Ingest.closeSource, Cas.Ingest.resource,
    Cas.Ingest.lease, Cas.Ingest.publish, Cas.Ingest.syncParent, Cas.Ingest.commit,
    Cas.IngestCommit.commitComplete, Cas.IngestCommit.commitCompleteIn, Cas.IngestCommit.commitIn,
    transactionOver, within, ensure, onFailure, raise, performOver, Inject.inject,
    Program.mapEffects, execute, ingestStep, file, construct, resources, lease,
    commitStep, storage, upsert, fresh, width, Cas.IngestCommit.decodeClaim,
    accepted, complete, Cas.IngestCommit.values, cell, Except.mapError, Except.map,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]

/-- Inline ingestion writes the actual bytes passed to the hashing effect. -/
theorem inline_store (host : Host) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (state : State) (fresh : state.fields = []) (width : host.root.size = 32) :
    execute (inputStep host) (Cas.Input.inlineBytes host.bytes now tier).run state =
      some (.ok ⟨host.root, host.bytes.size.toUInt64⟩,
        { state with fields := (Cas.IngestCommit.values host.root host.bytes.size.toUInt64
            true none (some host.bytes) now tier) }) := by
  have accepted := (fresh_complete host.bytes.size.toUInt64).1
  have complete := (fresh_complete host.bytes.size.toUInt64).2
  simp only [Cas.IngestCommit.completePlan] at accepted complete
  simp [Cas.Input.inlineBytes, Cas.Input.hashInline,
    Cas.IngestCommit.commitComplete, Cas.IngestCommit.commitCompleteIn, Cas.IngestCommit.commitIn,
    transactionOver, within, raise, performOver, Inject.inject, Program.mapEffects,
    execute, inputStep, ingestStep, construct, commitStep, storage, upsert,
    fresh, width, Cas.IngestCommit.decodeClaim, accepted, complete, Cas.IngestCommit.values,
    cell, Except.mapError, bind, pure, Program.bind,
    ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- The read host is constructed from the actual committed fields and files. -/
def reader (state : State) : CasReadPromises.Host := ⟨projection state.fields, state.payload⟩

/-- You get back what you stored: the complete captured-source program followed
by the actual full read, for arbitrary bytes and either backend tier. -/
theorem you_get_back_what_you_stored_captured (host : Host) (now : Int64)
    (tier : Cas.IngestCommit.Tier) (policy : Cas.Ingest.DirectoryPolicy)
    (before after : State) (fresh : before.fields = []) (width : host.root.size = 32)
    (fits : host.bytes.size < UInt64.size)
    (stored : execute (ingestStep host)
      (Cas.Ingest.run 9 host.bytes.size.toUInt64 now tier policy).run before = some (.ok host.root, after)) :
    CasReadPromises.run (reader after) host.root .all = .ok host.bytes.data.toList := by
  rw [captured_store host now tier policy before fresh width] at stored
  cases stored
  apply CasReadPromises.full_read_returns_content _ _
    ⟨host.bytes.size.toUInt64, true, none, none⟩ _ _ rfl
  exact ⟨committed_row_decodes host _ none now tier width,
    UInt64.toNat_ofNat_of_lt' fits, rfl⟩

/-- The same store/read law for inline ingestion, using the persisted inline
cell rather than assuming a correct read snapshot. -/
theorem you_get_back_what_you_stored_inline (host : Host) (now : Int64)
    (tier : Cas.IngestCommit.Tier) (before after : State) (fresh : before.fields = [])
    (width : host.root.size = 32) (fits : host.bytes.size < UInt64.size)
    (stored : execute (inputStep host) (Cas.Input.inlineBytes host.bytes now tier).run before =
      some (.ok ⟨host.root, host.bytes.size.toUInt64⟩, after)) :
    CasReadPromises.run (reader after) host.root .all = .ok host.bytes.data.toList := by
  rw [inline_store host now tier before fresh width] at stored
  cases stored
  apply CasReadPromises.full_read_returns_content _ _
    ⟨host.bytes.size.toUInt64, true, none, some host.bytes⟩ _ _ rfl
  exact ⟨committed_row_decodes host _ (some host.bytes) now tier width,
    UInt64.toNat_ofNat_of_lt' fits, rfl⟩

/-- The entire immutable-byte input command, including its own choice of inline
or captured storage. The host never chooses that representation. -/
theorem bytes_store (host : Host) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (policy : Cas.Ingest.DirectoryPolicy) (state : State) (fresh : state.fields = [])
    (width : host.root.size = 32) (fits : host.bytes.size < UInt64.size) :
    execute (inputStep host) (Cas.Input.run (.bytes host.bytes.size.toUInt64) now tier policy).run state =
      some (.ok ⟨host.root, host.bytes.size.toUInt64⟩,
        if host.bytes.size ≤ 16384 then
          { state with fields := (Cas.IngestCommit.values host.root host.bytes.size.toUInt64
              true none (some host.bytes) now tier) }
        else
          { fields := Cas.IngestCommit.values host.root host.bytes.size.toUInt64 true none none now tier,
            temporary := host.bytes, payload := host.bytes }) := by
  have accepted := (fresh_complete host.bytes.size.toUInt64).1
  have complete := (fresh_complete host.bytes.size.toUInt64).2
  simp only [Cas.IngestCommit.completePlan] at accepted complete
  by_cases small : host.bytes.size ≤ 16384
  all_goals simp [Cas.Input.run, Cas.Input.openSource, Cas.Input.file, Cas.Input.closeSource,
    Cas.Input.readExact, Cas.Input.capturedBytes, Cas.Input.inlineBytes, Cas.Input.hashInline,
    Cas.Input.captured, Cas.Ingest.run, Cas.Ingest.construct, Cas.Ingest.closeSource,
    Cas.Ingest.resource, Cas.Ingest.lease, Cas.Ingest.publish, Cas.Ingest.syncParent, Cas.Ingest.commit,
    Cas.IngestCommit.commitComplete, Cas.IngestCommit.commitCompleteIn, Cas.IngestCommit.commitIn,
    transactionOver, within, ensure, onFailure, raise, performOver, observe, Inject.inject,
    Program.mapEffects, execute, inputStep, ingestStep, file, construct, resources, lease,
    commitStep, storage, upsert, fresh, width, Cas.IngestCommit.decodeClaim,
    accepted, complete, Cas.IngestCommit.values, cell, Except.mapError, Except.map,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk, UInt64.le_iff_toNat_le, UInt64.toNat_ofNat_of_lt' fits, small]

/-- You get back what you stored, through the public immutable-byte command and
full read, for every representable input length (including zero). The initial
object is fresh; failures and overwrite/corruption recovery are separate laws. -/
theorem you_get_back_what_you_stored (host : Host) (now : Int64)
    (tier : Cas.IngestCommit.Tier) (policy : Cas.Ingest.DirectoryPolicy)
    (before after : State) (fresh : before.fields = []) (width : host.root.size = 32)
    (fits : host.bytes.size < UInt64.size)
    (stored : execute (inputStep host)
      (Cas.Input.run (.bytes host.bytes.size.toUInt64) now tier policy).run before =
        some (.ok ⟨host.root, host.bytes.size.toUInt64⟩, after)) :
    CasReadPromises.run (reader after) host.root .all = .ok host.bytes.data.toList := by
  rw [bytes_store host now tier policy before fresh width fits] at stored
  by_cases small : host.bytes.size ≤ 16384
  · rw [if_pos small] at stored
    cases stored
    apply CasReadPromises.full_read_returns_content _ _
      ⟨host.bytes.size.toUInt64, true, none, some host.bytes⟩ _ _ rfl
    exact ⟨committed_row_decodes host _ (some host.bytes) now tier width,
      UInt64.toNat_ofNat_of_lt' fits, rfl⟩
  · rw [if_neg small] at stored
    cases stored
    apply CasReadPromises.full_read_returns_content _ _
      ⟨host.bytes.size.toUInt64, true, none, none⟩ _ _ rfl
    exact ⟨committed_row_decodes host _ none now tier width,
      UInt64.toNat_ofNat_of_lt' fits, rfl⟩

end
end Synchronicity.CasStorePromises
