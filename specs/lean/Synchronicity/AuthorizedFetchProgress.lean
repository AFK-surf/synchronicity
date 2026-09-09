import Synchronicity.TrieFetchAdmissionProgress
import Synchronicity.TrieServeEvidence
import Synchronicity.TrieFetchConvergence

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

/-- One committed actual admission justified by an authority-checked serving
response.  Constructors expose the production `Fetch.admit` call and every raw
host/cryptographic premise; the successor state is definitionally that call's
state, rather than an abstract evidence transition. -/
inductive Admission : {publisher : TrieProgramProofs.RawSnapshot} →
    {scope : Serve.Scope} → {owner : Option String} → {root : ByteArray} →
    FiniteRequirements publisher scope owner root → State → State → Prop where
  | node
      {publisher : TrieProgramProofs.RawSnapshot} {root path hash raw : ByteArray}
      {origin : String} {serverInitial : State} {peerKey : ByteArray}
      {publisherOrigin : Origin.Parsed} {reading : Int64}
      (authority : ServingAuthority serverInitial peerKey publisherOrigin reading)
      (response : UsableResponse publisher (some origin) root authority path (.node hash raw))
      (requirements : FiniteRequirements publisher authority.scope (some origin) root)
      (target : Fetch.Target) (decodedNode : Node) (receiver : State)
      (quiet : receiver.faults = []) (idle : receiver.pending = none)
      (targetOwner : target.context.owner = some origin)
      (decoded : Trie.admit raw = .ok decodedNode)
      (valid : receiver.hash (tagOf decodedNode ++ raw) = hash)
      (nodesBackend : receiver.byteRelations.contains nodeSpace = true)
      (valuesBackend : receiver.byteRelations.contains valueSpace = true)
      (freshNode : relationBytes receiver.db nodeSpace hash = .ok none)
      (freshOwner : (rows receiver.db "trie_node_origins").any
        (conflict ["origin_id", "hash"]
          [("origin_id", .text origin), ("hash", .blob hash)]) = false)
      (outstanding :
        ¬ Verified (replicaOfState receiver) (.node hash raw) ∨
        ¬ Verified (replicaOfState receiver) (.provenance origin hash)) :
      Admission requirements receiver
        (SimulatedHost.run (Fetch.admit (H := Std.HashSet ByteArray) target false
          [(path, hash)] [(hash, raw)]) receiver).2
  | value
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
      Admission requirements receiver
        (SimulatedHost.run (Fetch.admit (H := Std.HashSet ByteArray) target true
          [(path, hash)] [(hash, bytes)]) receiver).2

theorem Admission.strict
    (admission : Admission requirements before after) :
    missingEvidence requirements.items (replicaOfState after) <
      missingEvidence requirements.items (replicaOfState before) := by
  refine Admission.rec (motive := fun requirements before after _ =>
    missingEvidence requirements.items (replicaOfState after) <
      missingEvidence requirements.items (replicaOfState before)) ?_ ?_ admission
  · intro root path hash raw origin serverInitial peerKey publisherOrigin reading
      authority response requirements target decodedNode receiver quiet idle targetOwner
      decoded valid nodesBackend valuesBackend freshNode freshOwner outstanding
    exact (usable_owned_node_admission_strict authority response requirements target
      decodedNode receiver quiet idle targetOwner decoded valid nodesBackend valuesBackend
      freshNode freshOwner outstanding).2
  · intro root path hash bytes owner serverInitial peerKey publisherOrigin reading
      authority response requirements target receiver quiet idle valid large bounded
      nodesBackend valuesBackend fresh outstanding
    exact (usable_value_admission_strict authority response requirements target receiver
      quiet idle valid large bounded nodesBackend valuesBackend fresh outstanding).2

/-- Every remaining deficit is eventually followed by one concrete authorized
`Fetch.admit` transition in the observed runtime state trace. -/
def SufficientResponses
    (requirements : FiniteRequirements publisher scope owner root)
    (states : Nat → State) : Prop :=
  ∀ now, 0 < missingEvidence requirements.items (replicaOfState (states now)) →
    ∃ later, now < later ∧ Admission requirements (states now) (states later)

theorem sufficientResponses_productive
    (requirements : FiniteRequirements publisher scope owner root)
    (states : Nat → State) (sufficient : SufficientResponses requirements states) :
    TrieFetchConvergence.ProductiveAdmissions requirements (replicaOfState ∘ states) := by
  intro now missing
  obtain ⟨later, after, admission⟩ := sufficient now missing
  exact ⟨later, after, admission.strict⟩

/-- Actual authorized responses discharge the abstract productivity premise
used by the finite convergence theorem.  Only durability of intervening
commits remains a separate runtime storage condition. -/
theorem sufficient_responses_converge
    (requirements : FiniteRequirements publisher scope owner root)
    (states : Nat → State)
    (persistent : TrieFetchConvergence.PersistentEvidence (replicaOfState ∘ states))
    (sufficient : SufficientResponses requirements states) (start : Nat) :
    ∃ finish, start ≤ finish ∧ ∀ now, finish ≤ now →
      PermittedComplete publisher scope owner root (replicaOfState (states now)) := by
  exact TrieFetchConvergence.finite_fetch_converges requirements
    (replicaOfState ∘ states) persistent
    (sufficientResponses_productive requirements states sufficient) start

end Synchronicity.AuthorizedFetchProgress
