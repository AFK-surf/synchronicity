import Synchronicity.TrieFetchAdmissionProgress
import Synchronicity.TrieServeEvidence

/-! Composition of an authority-checked production serving response with the
receiving production admission.  The remaining premises are the explicit
content-addressing/storage contracts at the receiver; no requester-success or
completion result is assumed.
-/
namespace Synchronicity.AuthorizedFetchProgress
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie SimulatedHost
open TrieFetchCompletion TrieFetchAdmissionProgress TrieServeEvidence

private theorem need_node_provenance
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {origin : String} {root : ByteArray}
    {path : List UInt8} {evidence : Evidence}
    (needed : Needs publisher scope owner root path evidence) :
    ∀ hash raw, evidence = .node hash raw → owner = some origin →
      Needs publisher scope (some origin) root path (.provenance origin hash) := by
  induction needed with
  | node admitted held =>
    intro hash raw evidenceEq owned
    cases evidenceEq
    exact .provenance admitted held
  | provenance admitted held => simp
  | value heldNode decoded admitted named heldValue => simp
  | extension held decoded nonempty below ih =>
    intro hash raw evidenceEq owned
    exact .extension held decoded nonempty (ih hash raw evidenceEq owned)
  | branch held decoded edge below ih =>
    intro hash raw evidenceEq owned
    exact .branch held decoded edge (ih hash raw evidenceEq owned)
  | route held decoded edge below ih =>
    intro hash raw evidenceEq owned
    exact .route held decoded edge (ih hash raw evidenceEq owned)

/-- An owned node requirement also requires provenance for the same address,
at the same position in the publisher graph. -/
theorem node_need_implies_provenance
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {origin : String} {root hash raw : ByteArray}
    {path : List UInt8}
    (needed : Needs publisher scope owner root path (.node hash raw))
    (owned : owner = some origin) :
    Needs publisher scope (some origin) root path (.provenance origin hash) :=
  need_node_provenance needed hash raw rfl owned

/-- One actual authorized node response, followed by its actual singleton
admission, strictly reduces the finite semantic deficit whenever either the
node bytes or their captured-owner provenance was absent. -/
theorem usable_owned_node_admission_strict
    {publisher : TrieProgramProofs.RawSnapshot} {root path hash raw : ByteArray}
    {origin : String} {serverInitial : State} {peerKey : ByteArray}
    {publisherOrigin : Origin.Parsed} {reading : Int64}
    (authority : ServingAuthority serverInitial peerKey publisherOrigin reading)
    (response : UsableResponse publisher (some origin) root authority path (.node hash raw))
    (requirements : FiniteRequirements publisher authority.scope (some origin) root)
    (target : Fetch.Target) (node : Node) (receiver : State)
    (quiet : receiver.faults = []) (idle : receiver.pending = none)
    (targetOwner : target.context.owner = some origin)
    (decoded : Trie.admit raw = .ok node)
    (valid : receiver.hash (tagOf node ++ raw) = hash)
    (nodesBackend : receiver.byteRelations.contains nodeSpace = true)
    (valuesBackend : receiver.byteRelations.contains valueSpace = true)
    (freshNode : relationBytes receiver.db nodeSpace hash = .ok none)
    (freshOwner : (rows receiver.db "trie_node_origins").any
      (conflict ["origin_id", "hash"]
        [("origin_id", .text origin), ("hash", .blob hash)]) = false)
    (outstanding :
      ¬ Verified (replicaOfState receiver) (.node hash raw) ∨
      ¬ Verified (replicaOfState receiver) (.provenance origin hash)) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target false
        [(path, hash)] [(hash, raw)]) receiver
    result.1 = .ok 1 ∧
      missingEvidence requirements.items (replicaOfState result.2) <
        missingEvidence requirements.items (replicaOfState receiver) := by
  rcases outstanding with nodeMissing | provenanceMissing
  · exact admitted_single_owned_node_strict_progress origin requirements target path hash raw
      node receiver quiet idle targetOwner decoded valid nodesBackend valuesBackend
      freshNode freshOwner response.needed nodeMissing
  · exact admitted_single_owned_node_provenance_strict_progress origin requirements target
      path hash raw node receiver quiet idle targetOwner decoded valid nodesBackend valuesBackend
      freshNode freshOwner (node_need_implies_provenance response.needed rfl) provenanceMissing

/-- The value half of the same handoff.  Scope/authority and publisher backing
come from the actual serving response; digest and supported-size facts remain
the receiver's explicit cryptographic/native contracts. -/
theorem usable_value_admission_strict
    {publisher : TrieProgramProofs.RawSnapshot} {root path hash bytes : ByteArray}
    {owner : Option String} {serverInitial : State} {peerKey : ByteArray}
    {publisherOrigin : Origin.Parsed} {reading : Int64}
    (authority : ServingAuthority serverInitial peerKey publisherOrigin reading)
    (response : UsableResponse publisher owner root authority path (.value hash bytes))
    (requirements : FiniteRequirements publisher authority.scope owner root)
    (target : Fetch.Target) (receiver : State)
    (quiet : receiver.faults = []) (idle : receiver.pending = none)
    (valid : receiver.hash bytes = hash)
    (large : inlineValueMax < bytes.size) (bounded : bytes.size ≤ maxValueBytes)
    (nodesBackend : receiver.byteRelations.contains nodeSpace = true)
    (valuesBackend : receiver.byteRelations.contains valueSpace = true)
    (fresh : relationBytes receiver.db valueSpace hash = .ok none)
    (outstanding : ¬ Verified (replicaOfState receiver) (.value hash bytes)) :
    let result := SimulatedHost.run
      (Fetch.admit (H := Std.HashSet ByteArray) target true
        [(path, hash)] [(hash, bytes)]) receiver
    result.1 = .ok 1 ∧
      missingEvidence requirements.items (replicaOfState result.2) <
        missingEvidence requirements.items (replicaOfState receiver) := by
  exact admitted_single_value_strict_progress requirements target path hash bytes receiver
    quiet idle valid large bounded nodesBackend valuesBackend fresh response.needed outstanding

end Synchronicity.AuthorizedFetchProgress
