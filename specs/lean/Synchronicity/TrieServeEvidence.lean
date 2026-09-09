import Synchronicity.TrieFetchCompletion
import Synchronicity.TrieServePrivacyProofs
import VerifiedCore.Authorization.Operations

/-! Bridge from production authorization/serving executions to the persistent
evidence specification used by fetch progress.  Network delivery and storage
availability remain explicit host contracts: this module does not claim that
`Fetch.fetch` succeeds merely because a server produced one useful answer. -/
namespace Synchronicity.TrieServeEvidence
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open Synchronicity.SimulatedHost
open TrieProgramProofs TrieServeProofs TriePublicationRouting
open TrieFetchCompletion TrieServePrivacyProofs

/-- The actual authorization reads used to construct the inputs of one serve
request.  This is the single-publisher specialization of native
`serving_inputs`: a peer authority supplies its read scope and own origins;
the root publisher's authority decides whether provenance is confined. -/
structure ServingAuthority (initial : State) (peerKey : ByteArray)
    (publisherOrigin : Origin.Parsed) (reading : Int64) where
  peer : Authorization.PeerAuthority
  publisher : Authorization.OriginAuthority
  afterPeer : State
  afterPublisher : State
  peerRead :
    execute (Authorization.peerAuthority peerKey reading) initial = (.ok peer, afterPeer)
  publisherRead :
    execute (Authorization.originAuthority publisherOrigin reading) afterPeer =
      (.ok publisher, afterPublisher)

def ServingAuthority.scope (authority : ServingAuthority initial peerKey publisherOrigin reading) :
    Serve.Scope := authority.peer.serving

def ServingAuthority.peerOrigins
    (authority : ServingAuthority initial peerKey publisherOrigin reading) : List String :=
  authority.peer.origins.map Origin.canonical

def ServingAuthority.confined
    (authority : ServingAuthority initial peerKey publisherOrigin reading) : List String :=
  if authority.publisher.provenance.isSome then [Origin.canonical publisherOrigin] else []

/-- Lift a node requirement back through the publisher's stored route.  The
requirement is independent of the serving walk: it is constructed solely from
the immutable publisher snapshot, its path, and the fixed grant. -/
theorem needs_node_along_route (publisher : RawSnapshot) (scope : Serve.Scope)
    (owner : Option String) (root found raw : ByteArray) (base suffix : List UInt8)
    (reaches : Reaches (publisher nodeSpace) root suffix found)
    (admitted : scope.admitsPath (base ++ suffix) = true)
    (held : publisher nodeSpace found = some raw) :
    Needs publisher scope owner root base (.node found raw) := by
  induction reaches generalizing base with
  | here hash =>
    simpa using Needs.node (owner := owner) admitted held
  | extension hash ownRaw segment child found rest parentHeld decoded nonempty below ih =>
    apply Needs.extension parentHeld decoded nonempty
    apply ih (base := base ++ segment.toList)
    simpa only [List.append_assoc] using admitted
    exact held
  | branch hash ownRaw child found children value nibble rest parentHeld decoded edge below ih =>
    apply Needs.branch parentHeld decoded edge
    apply ih (base := base ++ [nibble])
    simpa only [List.append_assoc, List.singleton_append] using admitted
    exact held
  | route hash ownRaw child found children value nibble rest parentHeld decoded edge below ih =>
    apply Needs.route parentHeld decoded edge
    apply ih (base := base ++ [nibble])
    simpa only [List.append_assoc, List.singleton_append] using admitted
    exact held

/-- A returned payload carries exactly the persistent node evidence named by
the response. -/
def CarriesNode (answer : Serve.NodeAnswer) (hash raw : ByteArray) : Prop :=
  (hash, raw) ∈ answer.nodes

/-- One useful response item is tied both to its actual authority/serve
executions and to the independent publisher-derived requirement it satisfies.
`private` states the batch-wide non-leakage guarantee, not merely a fact about
the selected item. -/
structure UsableEvidenceResponse (publisher : RawSnapshot) (owner : Option String)
    (root : ByteArray) {initial : State} {peerKey : ByteArray}
    {publisherOrigin : Origin.Parsed} {reading : Int64}
    (authority : ServingAuthority initial peerKey publisherOrigin reading)
    (path hash raw : ByteArray) (answer : Serve.NodeAnswer) : Prop where
  serveExecution :
    (SimulatedHost.run
      (Serve.serveNodes root [(path, hash)] authority.scope authority.peerOrigins authority.confined)
      authority.afterPublisher).1 = .ok answer
  carries : CarriesNode answer hash raw
  needed : Needs publisher authority.scope owner root [] (.node hash raw)
  publisherBacked : PublisherBacks publisher (.node hash raw)
  publicationFormat : ∃ node, decode raw = .ok node ∧
    authority.scope.admitsNode path.toList node = true
  scopePrivate : ∀ served bytes, (served, bytes) ∈ answer.nodes →
    ∃ requested claimed node,
      (requested, claimed) ∈ [(path, hash)] ∧
      authority.scope.admitsPath requested.toList = true ∧
      decode bytes = .ok node ∧ authority.scope.admitsNode requested.toList node = true

/-- A single actual scoped node response over a routed publication is usable
publisher-backed evidence.  The successful serve execution is the explicit
network/storage contract; authority is supplied only by the two actual reads
in `ServingAuthority`. -/
theorem single_node_response (publisher : RawSnapshot) (owner : Option String)
    (root path hash raw : ByteArray) {initial : State} {peerKey : ByteArray}
    {publisherOrigin : Origin.Parsed} {reading : Int64}
    (authority : ServingAuthority initial peerKey publisherOrigin reading)
    (answer : Serve.NodeAnswer)
    (bounded : authority.scope.isFull = false)
    (compatible : BoundaryCompatible authority.scope)
    (routed : RoutedAt publisher [] root)
    (reaches : Reaches (publisher nodeSpace) root path.toList hash)
    (held : publisher nodeSpace hash = some raw)
    (served : (SimulatedHost.run
      (Serve.serveNodes root [(path, hash)] authority.scope authority.peerOrigins authority.confined)
      authority.afterPublisher).1 = .ok answer)
    (carries : CarriesNode answer hash raw) :
    UsableEvidenceResponse publisher owner root authority path hash raw answer := by
  have privacy := serveNodes_private root [(path, hash)] authority.scope authority.peerOrigins
    authority.confined authority.afterPublisher answer bounded served
  obtain ⟨requested, claimed, node, wanted, admitted, decoded, revealed⟩ :=
    privacy hash raw carries
  simp only [List.mem_singleton] at wanted
  have requestedPath : requested = path := congrArg Prod.fst wanted
  subst requested
  have need : Needs publisher authority.scope owner root [] (.node hash raw) :=
    needs_node_along_route publisher authority.scope owner root hash raw [] path.toList
      reaches (by simpa using admitted) held
  have format : authority.scope.admitsNode path.toList node = true :=
    routed_nodes_are_admitted compatible routed reaches admitted held decoded
  refine ⟨served, carries, need, needs_publisher_backing need, ⟨node, decoded, format⟩, ?_⟩
  exact privacy

/-- The publication-format assumptions are productive, rather than decorative:
the routed path's returned node is revealable at the granted position. -/
theorem single_node_format_is_serviceable (publisher : RawSnapshot)
    (scope : Serve.Scope) (root path hash raw : ByteArray) (node : Node)
    (compatible : BoundaryCompatible scope) (routed : RoutedAt publisher [] root)
    (reaches : Reaches (publisher nodeSpace) root path.toList hash)
    (admitted : scope.admitsPath path.toList = true)
    (held : publisher nodeSpace hash = some raw) (decoded : decode raw = .ok node) :
    scope.admitsNode path.toList node = true := by
  simpa using routed_nodes_are_admitted compatible routed reaches admitted held decoded

end Synchronicity.TrieServeEvidence
