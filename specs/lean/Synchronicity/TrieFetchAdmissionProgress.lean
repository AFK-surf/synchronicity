import Synchronicity.TrieFetchCompletion
import Synchronicity.TrieFetchProofs

/-! Actual admission executions refine the operation-independent evidence
model.  This module starts with one-item responses, which already cross the
transactional host boundary; batched responses require a separate fold-level
preservation theorem for the database interpreter. -/
namespace Synchronicity.TrieFetchAdmissionProgress
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open SimulatedHost TrieFetchCompletion

/-- The replica facts observed by the production missing-data operations.
Trie byte relations use the same successful raw byte accessor; provenance is
the exact row predicate queried by `Missing.rowPresent`. -/
def replicaOfState (state : SimulatedHost.State) : Replica where
  records := readableBytes state
  owns := fun owner hash =>
    (rows state.db "trie_node_origins").any fun row =>
      equals row [("origin_id", .text owner), ("hash", .blob hash)]

private theorem readableBytes_eq_some_iff (state : SimulatedHost.State)
    (space : String) (key bytes : ByteArray) :
    readableBytes state space key = some bytes ↔
      readByteObject state space key = .ok (some bytes) := by
  unfold readableBytes
  cases readByteObject state space key <;> simp

local instance : LawfulHashable ByteArray :=
  ⟨fun {a b} (same : (a == b) = true) => by rw [eq_of_beq same]⟩

private theorem relationBytes_upsert_doNothing_preserves (db : Database)
    (relation : String) (incoming : Fields) (conflicts : List String)
    (key bytes : ByteArray) (held : relationBytes db relation key = .ok (some bytes)) :
    relationBytes
      (setRows db relation (upsertRows (rows db relation) incoming conflicts []))
      relation key = .ok (some bytes) := by
  rw [upsertRows_doNothing]
  split
  · simpa [relationBytes] using held
  · simp only [relationBytes, rows_setRows, List.find?_append]
    simp only [relationBytes] at held
    cases found : (rows db relation).find?
        (fun row => cell row "hash" == .blob key) with
    | none => simp [found] at held
    | some row =>
      rw [found] at held
      simp
      exact held

private theorem relationBytes_upsert_doNothing_other (db : Database)
    (relation other : String) (incoming : Fields) (conflicts : List String)
    (different : relation ≠ other) (key : ByteArray) :
    relationBytes
      (setRows db relation (upsertRows (rows db relation) incoming conflicts []))
      other key = relationBytes db other key := by
  simp [relationBytes, rows_setRows_other, different]

private theorem fresh_byte_row_is_readable (db : Database) (relation : String)
    (hash payload : ByteArray) (fresh : relationBytes db relation hash = .ok none) :
    relationBytes (setRows db relation
      (upsertRows (rows db relation)
        [("hash", .blob hash), ("data", .blob payload)] ["hash"] []))
      relation hash = .ok (some payload) := by
  have missing : (rows db relation).find?
      (fun row => cell row "hash" == .blob hash) = none := by
    cases found : (rows db relation).find?
        (fun row => cell row "hash" == .blob hash) with
    | none => rfl
    | some row =>
      simp only [relationBytes, found] at fresh
      cases data : cell row "data" <;> simp_all
  have distinct : ∀ row ∈ rows db relation, cell row "hash" ≠ .blob hash := by
    simpa using (List.find?_eq_none.mp missing)
  have noConflict : (rows db relation).any
      (conflict ["hash"] [("hash", .blob hash), ("data", .blob payload)]) = false := by
    apply List.any_eq_false.mpr
    intro row member
    have different := distinct row member
    simp only [conflict, List.all_cons, List.all_nil, Bool.and_true, cell,
      List.find?_cons, beq_self_eq_true, Option.map_some, Option.getD_some]
    change ¬ equalCell (.blob hash) (cell row "hash") = true
    generalize cell row "hash" = value at different ⊢
    cases value <;> simp [equalCell, beq_iff_eq] at different ⊢
    exact Ne.symm different
  simp only [relationBytes, rows_setRows, upsertRows_doNothing, noConflict,
    Bool.false_eq_true, ↓reduceIte, List.find?_append, missing]
  simp [cell]

private theorem any_upsert_doNothing_preserves (table : List Fields)
    (incoming : Fields) (conflicts : List String) (predicate : Fields → Bool)
    (held : table.any predicate = true) :
    (upsertRows table incoming conflicts []).any predicate = true := by
  rw [upsertRows_doNothing]
  split
  · exact held
  · simp [held]

private theorem fresh_owned_row_is_present (db : Database) (origin : String)
    (hash : ByteArray)
    (fresh : (rows db "trie_node_origins").any
      (conflict ["origin_id", "hash"]
        [("origin_id", .text origin), ("hash", .blob hash)]) = false) :
    (rows (setRows db "trie_node_origins"
      (upsertRows (rows db "trie_node_origins")
        [("origin_id", .text origin), ("hash", .blob hash)]
        ["origin_id", "hash"] [])) "trie_node_origins").any
      (fun row => equals row
        [("origin_id", .text origin), ("hash", .blob hash)]) = true := by
  simp only [rows_setRows, upsertRows_doNothing, fresh, Bool.false_eq_true, ↓reduceIte,
    List.any_append]
  simp [equals, isCell, equalCell, cell]

private theorem value_admission_execution (target : Fetch.Target)
    (holder hash payload : ByteArray) (state : SimulatedHost.State)
    (quiet : state.faults = []) (idle : state.pending = none)
    (valid : state.hash payload = hash)
    (large : inlineValueMax < payload.size) (bounded : payload.size ≤ maxValueBytes) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target true [(holder, hash)] [(hash, payload)]) state
    result.1 = .ok 1 ∧ result.2.db = setRows state.db valueSpace
      (upsertRows (rows state.db valueSpace)
        [("hash", .blob hash), ("data", .blob payload)] ["hash"] []) ∧
      result.2.pending = none ∧ result.2.byteRelations = state.byteRelations ∧
      result.2.files = state.files := by
  simp [SimulatedHost.run, Fetch.admit, transactionOver, Fetch.request,
    raise, performOver, Inject.inject, bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.mk, ExceptT.run, execute, Program.bind, Interpreter.handle,
    storage, SimulatedHost.transaction, reply, fault, quiet, idle, record,
    Missing.WorkSet.empty, Missing.WorkSet.contains, Missing.WorkSet.insert,
    Missing.WorkSet.erase, pure, ExceptT.pure, Except.mapError,
    SimulatedHost.digest, valid, large, bounded]

/-- A successful production value admission preserves every previously
verified node, value and provenance fact, and establishes the fresh requested
value itself. -/
theorem admitted_single_value_includes_evidence (target : Fetch.Target)
    (holder hash payload : ByteArray) (state : SimulatedHost.State)
    (quiet : state.faults = []) (idle : state.pending = none)
    (valid : state.hash payload = hash)
    (large : inlineValueMax < payload.size) (bounded : payload.size ≤ maxValueBytes)
    (nodesBackend : state.byteRelations.contains nodeSpace = true)
    (valuesBackend : state.byteRelations.contains valueSpace = true)
    (fresh : relationBytes state.db valueSpace hash = .ok none) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target true [(holder, hash)] [(hash, payload)]) state
    result.1 = .ok 1 ∧
      EvidenceIncluded (replicaOfState state) (replicaOfState result.2) ∧
      Verified (replicaOfState result.2) (.value hash payload) := by
  dsimp
  let result := SimulatedHost.run
    (Fetch.admit (H := Std.HashSet ByteArray) target true [(holder, hash)] [(hash, payload)]) state
  obtain ⟨accepted, database, closed, backend, files⟩ :=
    value_admission_execution target holder hash payload state quiet idle valid large bounded
  obtain ⟨_, added, _, _, _⟩ :=
    TrieFetchProofs.admitted_value_is_readable_by_the_next_inspection
      target holder hash payload state quiet idle valid large bounded
      nodesBackend valuesBackend fresh
  have nodesMember : nodeSpace ∈ state.byteRelations := by simpa using nodesBackend
  have valuesMember : valueSpace ∈ state.byteRelations := by simpa using valuesBackend
  have resultNodesBackend : result.2.byteRelations.contains nodeSpace = true := by
    rw [backend]
    exact nodesBackend
  have resultValuesBackend : result.2.byteRelations.contains valueSpace = true := by
    rw [backend]
    exact valuesBackend
  refine ⟨accepted, ?_, ?_⟩
  · intro evidence previously
    cases evidence with
    | node oldHash oldRaw =>
      change readableBytes state nodeSpace oldHash = some oldRaw at previously
      change readableBytes result.2 nodeSpace oldHash = some oldRaw
      have held : relationBytes state.db nodeSpace oldHash = .ok (some oldRaw) := by
        have := (readableBytes_eq_some_iff _ _ _ _).mp previously
        simpa [readByteObject, idle, nodesMember] using this
      have retained : relationBytes result.2.db nodeSpace oldHash = .ok (some oldRaw) := by
        rw [database]
        rw [relationBytes_upsert_doNothing_other _ valueSpace nodeSpace _ _ (by decide)]
        exact held
      apply (readableBytes_eq_some_iff _ _ _ _).mpr
      rw [readByteObject, if_pos resultNodesBackend, closed]
      exact retained
    | value oldHash oldBytes =>
      change readableBytes state valueSpace oldHash = some oldBytes at previously
      change readableBytes result.2 valueSpace oldHash = some oldBytes
      have held : relationBytes state.db valueSpace oldHash = .ok (some oldBytes) := by
        have := (readableBytes_eq_some_iff _ _ _ _).mp previously
        simpa [readByteObject, idle, valuesMember] using this
      have retained : relationBytes result.2.db valueSpace oldHash = .ok (some oldBytes) := by
        rw [database]
        exact relationBytes_upsert_doNothing_preserves _ _ _ _ _ _ held
      apply (readableBytes_eq_some_iff _ _ _ _).mpr
      rw [readByteObject, if_pos resultValuesBackend, closed]
      exact retained
    | provenance oldOwner oldHash =>
      change (rows state.db "trie_node_origins").any
        (fun row => equals row [("origin_id", .text oldOwner), ("hash", .blob oldHash)]) = true
        at previously
      change (rows result.2.db "trie_node_origins").any
        (fun row => equals row [("origin_id", .text oldOwner), ("hash", .blob oldHash)]) = true
      rw [database, rows_setRows_other]
      · exact previously
      · decide
  · change readableBytes result.2 valueSpace hash = some payload
    exact (readableBytes_eq_some_iff _ _ _ _).mpr added

private theorem owned_node_admission_execution (target : Fetch.Target)
    (origin : String) (holder hash raw : ByteArray) (node : Node)
    (state : SimulatedHost.State) (quiet : state.faults = [])
    (idle : state.pending = none) (targetOwner : target.context.owner = some origin)
    (decoded : Trie.admit raw = .ok node)
    (valid : state.hash (tagOf node ++ raw) = hash) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target false
        [(holder, hash)] [(hash, raw)]) state
    let nodeDb := setRows state.db nodeSpace
      (upsertRows (rows state.db nodeSpace)
        [("hash", .blob hash), ("data", .blob raw)] ["hash"] [])
    result.1 = .ok 1 ∧ result.2.db = setRows nodeDb "trie_node_origins"
      (upsertRows (rows nodeDb "trie_node_origins")
        [("origin_id", .text origin), ("hash", .blob hash)]
        ["origin_id", "hash"] []) ∧
      result.2.pending = none ∧ result.2.byteRelations = state.byteRelations ∧
      result.2.files = state.files := by
  simp [SimulatedHost.run, Fetch.admit, transactionOver, Fetch.request,
    raise, performOver, Inject.inject, bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.mk, ExceptT.run, execute, Program.bind, Interpreter.handle,
    storage, SimulatedHost.transaction, reply, fault, quiet, idle, record,
    Missing.WorkSet.empty, Missing.WorkSet.contains, Missing.WorkSet.insert,
    Missing.WorkSet.erase, pure, ExceptT.pure, Except.mapError,
    within, Program.mapEffects, Trie.verify, Trie.digest, decoded,
    SimulatedHost.digest, valid, targetOwner]

/-- A successfully verified production node response commits the node and its
captured owner provenance in one transaction while retaining all older
evidence. -/
theorem admitted_single_owned_node_includes_evidence (target : Fetch.Target)
    (origin : String) (holder hash raw : ByteArray) (node : Node)
    (state : SimulatedHost.State) (quiet : state.faults = [])
    (idle : state.pending = none) (targetOwner : target.context.owner = some origin)
    (decoded : Trie.admit raw = .ok node)
    (valid : state.hash (tagOf node ++ raw) = hash)
    (nodesBackend : state.byteRelations.contains nodeSpace = true)
    (valuesBackend : state.byteRelations.contains valueSpace = true)
    (freshNode : relationBytes state.db nodeSpace hash = .ok none)
    (freshOwner : (rows state.db "trie_node_origins").any
      (conflict ["origin_id", "hash"]
        [("origin_id", .text origin), ("hash", .blob hash)]) = false) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target false
        [(holder, hash)] [(hash, raw)]) state
    result.1 = .ok 1 ∧
      EvidenceIncluded (replicaOfState state) (replicaOfState result.2) ∧
      Verified (replicaOfState result.2) (.node hash raw) ∧
      Verified (replicaOfState result.2) (.provenance origin hash) := by
  dsimp
  let result := SimulatedHost.run
    (Fetch.admit (H := Std.HashSet ByteArray) target false
      [(holder, hash)] [(hash, raw)]) state
  let nodeDb := setRows state.db nodeSpace
    (upsertRows (rows state.db nodeSpace)
      [("hash", .blob hash), ("data", .blob raw)] ["hash"] [])
  obtain ⟨accepted, database, closed, backend, files⟩ :=
    owned_node_admission_execution target origin holder hash raw node state
      quiet idle targetOwner decoded valid
  have nodesMember : nodeSpace ∈ state.byteRelations := by simpa using nodesBackend
  have valuesMember : valueSpace ∈ state.byteRelations := by simpa using valuesBackend
  have resultNodesBackend : result.2.byteRelations.contains nodeSpace = true := by
    rw [backend]
    exact nodesBackend
  have resultValuesBackend : result.2.byteRelations.contains valueSpace = true := by
    rw [backend]
    exact valuesBackend
  refine ⟨accepted, ?_, ?_, ?_⟩
  · intro evidence previously
    cases evidence with
    | node oldHash oldRaw =>
      change readableBytes state nodeSpace oldHash = some oldRaw at previously
      change readableBytes result.2 nodeSpace oldHash = some oldRaw
      have held : relationBytes state.db nodeSpace oldHash = .ok (some oldRaw) := by
        have := (readableBytes_eq_some_iff _ _ _ _).mp previously
        simpa [readByteObject, idle, nodesMember] using this
      have retainedAtNodeDb : relationBytes nodeDb nodeSpace oldHash = .ok (some oldRaw) :=
        relationBytes_upsert_doNothing_preserves _ _ _ _ _ _ held
      have retained : relationBytes result.2.db nodeSpace oldHash = .ok (some oldRaw) := by
        rw [database]
        rw [relationBytes_upsert_doNothing_other _ "trie_node_origins" nodeSpace _ _
          (by decide)]
        exact retainedAtNodeDb
      apply (readableBytes_eq_some_iff _ _ _ _).mpr
      rw [readByteObject, if_pos resultNodesBackend, closed]
      exact retained
    | value oldHash oldBytes =>
      change readableBytes state valueSpace oldHash = some oldBytes at previously
      change readableBytes result.2 valueSpace oldHash = some oldBytes
      have held : relationBytes state.db valueSpace oldHash = .ok (some oldBytes) := by
        have := (readableBytes_eq_some_iff _ _ _ _).mp previously
        simpa [readByteObject, idle, valuesMember] using this
      have retainedAtNodeDb : relationBytes nodeDb valueSpace oldHash = .ok (some oldBytes) := by
        simp only [nodeDb]
        rw [relationBytes_upsert_doNothing_other _ nodeSpace valueSpace _ _ (by decide)]
        exact held
      have retained : relationBytes result.2.db valueSpace oldHash = .ok (some oldBytes) := by
        rw [database]
        rw [relationBytes_upsert_doNothing_other _ "trie_node_origins" valueSpace _ _
          (by decide)]
        exact retainedAtNodeDb
      apply (readableBytes_eq_some_iff _ _ _ _).mpr
      rw [readByteObject, if_pos resultValuesBackend, closed]
      exact retained
    | provenance oldOwner oldHash =>
      change (rows state.db "trie_node_origins").any
        (fun row => equals row
          [("origin_id", .text oldOwner), ("hash", .blob oldHash)]) = true at previously
      change (rows result.2.db "trie_node_origins").any
        (fun row => equals row
          [("origin_id", .text oldOwner), ("hash", .blob oldHash)]) = true
      have atNodeDb : (rows nodeDb "trie_node_origins").any
          (fun row => equals row
            [("origin_id", .text oldOwner), ("hash", .blob oldHash)]) = true := by
        simp only [nodeDb, rows_setRows_other _ nodeSpace "trie_node_origins" _ (by decide)]
        exact previously
      rw [database, rows_setRows]
      exact any_upsert_doNothing_preserves _ _ _ _ atNodeDb
  · change readableBytes result.2 nodeSpace hash = some raw
    apply (readableBytes_eq_some_iff _ _ _ _).mpr
    rw [readByteObject, if_pos resultNodesBackend, closed, database]
    simp only [Option.map_none, Option.getD_none]
    rw [relationBytes_upsert_doNothing_other _ "trie_node_origins" nodeSpace _ _
      (by decide)]
    exact fresh_byte_row_is_readable _ _ _ _ freshNode
  · change (rows result.2.db "trie_node_origins").any
      (fun row => equals row [("origin_id", .text origin), ("hash", .blob hash)]) = true
    rw [database]
    apply fresh_owned_row_is_present
    simp only [rows_setRows_other _ nodeSpace "trie_node_origins" _ (by decide)]
    exact freshOwner

/-- The successful singleton response is an actual strict progress step when
its value is one of the finite semantic requirements and was not verified
before the call. -/
theorem admitted_single_value_strict_progress
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope} {owner : Option String}
    {root : ByteArray} (requirements : FiniteRequirements publisher scope owner root)
    (target : Fetch.Target) (holder hash payload : ByteArray)
    (state : SimulatedHost.State) (quiet : state.faults = [])
    (idle : state.pending = none) (valid : state.hash payload = hash)
    (large : inlineValueMax < payload.size) (bounded : payload.size ≤ maxValueBytes)
    (nodesBackend : state.byteRelations.contains nodeSpace = true)
    (valuesBackend : state.byteRelations.contains valueSpace = true)
    (fresh : relationBytes state.db valueSpace hash = .ok none)
    (needed : Needs publisher scope owner root [] (.value hash payload))
    (absent : ¬ Verified (replicaOfState state) (.value hash payload)) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target true
        [(holder, hash)] [(hash, payload)]) state
    result.1 = .ok 1 ∧
      missingEvidence requirements.items (replicaOfState result.2) <
        missingEvidence requirements.items (replicaOfState state) := by
  dsimp
  obtain ⟨accepted, included, added⟩ :=
    admitted_single_value_includes_evidence target holder hash payload state quiet idle
      valid large bounded nodesBackend valuesBackend fresh
  exact ⟨accepted,
    finite_measure_strict_of_added requirements needed absent included added⟩

/-- The node half of an owned singleton response strictly reduces the same
persistent measure when that node requirement was outstanding. -/
theorem admitted_single_owned_node_strict_progress
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope} {root : ByteArray}
    (origin : String) (requirements : FiniteRequirements publisher scope (some origin) root)
    (target : Fetch.Target) (holder hash raw : ByteArray)
    (node : Node) (state : SimulatedHost.State) (quiet : state.faults = [])
    (idle : state.pending = none) (targetOwner : target.context.owner = some origin)
    (decoded : Trie.admit raw = .ok node)
    (valid : state.hash (tagOf node ++ raw) = hash)
    (nodesBackend : state.byteRelations.contains nodeSpace = true)
    (valuesBackend : state.byteRelations.contains valueSpace = true)
    (freshNode : relationBytes state.db nodeSpace hash = .ok none)
    (freshOwner : (rows state.db "trie_node_origins").any
      (conflict ["origin_id", "hash"]
        [("origin_id", .text origin), ("hash", .blob hash)]) = false)
    (needed : Needs publisher scope (some origin) root [] (.node hash raw))
    (absent : ¬ Verified (replicaOfState state) (.node hash raw)) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target false
        [(holder, hash)] [(hash, raw)]) state
    result.1 = .ok 1 ∧
      missingEvidence requirements.items (replicaOfState result.2) <
        missingEvidence requirements.items (replicaOfState state) := by
  dsimp
  obtain ⟨accepted, included, added, _⟩ :=
    admitted_single_owned_node_includes_evidence target origin holder hash raw node state
      quiet idle targetOwner decoded valid nodesBackend valuesBackend freshNode freshOwner
  exact ⟨accepted,
    finite_measure_strict_of_added requirements needed absent included added⟩

/-- The same actual owned-node admission also makes strict progress when its
outstanding semantic requirement is the captured owner provenance. -/
theorem admitted_single_owned_node_provenance_strict_progress
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope} {root : ByteArray}
    (origin : String) (requirements : FiniteRequirements publisher scope (some origin) root)
    (target : Fetch.Target) (holder hash raw : ByteArray)
    (node : Node) (state : SimulatedHost.State) (quiet : state.faults = [])
    (idle : state.pending = none) (targetOwner : target.context.owner = some origin)
    (decoded : Trie.admit raw = .ok node)
    (valid : state.hash (tagOf node ++ raw) = hash)
    (nodesBackend : state.byteRelations.contains nodeSpace = true)
    (valuesBackend : state.byteRelations.contains valueSpace = true)
    (freshNode : relationBytes state.db nodeSpace hash = .ok none)
    (freshOwner : (rows state.db "trie_node_origins").any
      (conflict ["origin_id", "hash"]
        [("origin_id", .text origin), ("hash", .blob hash)]) = false)
    (needed : Needs publisher scope (some origin) root [] (.provenance origin hash))
    (absent : ¬ Verified (replicaOfState state) (.provenance origin hash)) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target false
        [(holder, hash)] [(hash, raw)]) state
    result.1 = .ok 1 ∧
      missingEvidence requirements.items (replicaOfState result.2) <
        missingEvidence requirements.items (replicaOfState state) := by
  dsimp
  obtain ⟨accepted, included, _, added⟩ :=
    admitted_single_owned_node_includes_evidence target origin holder hash raw node state
      quiet idle targetOwner decoded valid nodesBackend valuesBackend freshNode freshOwner
  exact ⟨accepted,
    finite_measure_strict_of_added requirements needed absent included added⟩

end Synchronicity.TrieFetchAdmissionProgress
