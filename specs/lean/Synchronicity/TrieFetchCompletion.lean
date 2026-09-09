import Synchronicity.TriePublicationRouting

/-! An operation-independent meaning for the metadata evidence a scoped fetch
must retain.  Requirements are derived from the publisher's stored graph and
the fixed scope, not from the requesting walk's queue.  A finite enumeration
then gives a store-only progress measure which survives loss of a continuation.

This module deliberately does not interpret `Trie.Fetch.fetch`'s Boolean
result.  That result asks replication to perform a fresh promotion check; it is
not itself a completeness certificate. -/
namespace Synchronicity.TrieFetchCompletion
open VerifiedCore VerifiedCore.Trie
open TrieProgramProofs TrieSnapshotProofs TrieSnapshotClosure TrieServeProofs

/-- Persistent facts on which a later requesting walk can rely.  Node bytes
and payload bytes are content addressed.  Provenance is separate: possessing a
node for one origin does not make it owned by another. -/
inductive Evidence where
  | node (hash raw : ByteArray)
  | value (hash bytes : ByteArray)
  | provenance (owner : String) (hash : ByteArray)
  deriving BEq, DecidableEq

/-- The persistent part of a replica relevant to metadata completion.  This is
not an execution state: transactions, queues, retry counters and memo entries
are intentionally absent. -/
structure Replica where
  records : RawSnapshot
  owns : String → ByteArray → Bool

variable {publisher : RawSnapshot} {scope : Serve.Scope} {owner : Option String}
variable {root hash raw bytes address segment child : ByteArray} {path tail : List UInt8}
variable {origin : String} {node : Node} {value : Value}
variable {children : List (Option ByteArray)} {nibble : UInt8} {evidence : Evidence}
variable {before after replica : Replica}

def Verified (replica : Replica) : Evidence → Prop
  | .node hash raw => replica.records nodeSpace hash = some raw
  | .value hash bytes => replica.records valueSpace hash = some bytes
  | .provenance owner hash => replica.owns owner hash = true

instance (replica : Replica) (evidence : Evidence) : Decidable (Verified replica evidence) := by
  unfold Verified
  split <;> infer_instance

/-- Evidence required below a publisher node at a particular nibble path.
Only admitted child positions are able to introduce requirements.  Out-of-line
payloads are required only where the node's value belongs to an admitted key.

The recursive constructors describe the publisher graph, rather than an
algorithmic frontier.  In particular, neither refusal nor a queue entry is
evidence. -/
inductive Needs (publisher : RawSnapshot) (scope : Serve.Scope) :
    Option String → ByteArray → List UInt8 → Evidence → Prop where
  | node {owner : Option String} {hash raw : ByteArray} {path : List UInt8}
      (admitted : scope.admitsPath path = true)
      (held : publisher nodeSpace hash = some raw) :
      Needs publisher scope owner hash path (.node hash raw)
  | provenance {origin : String} {hash raw : ByteArray} {path : List UInt8}
      (admitted : scope.admitsPath path = true)
      (held : publisher nodeSpace hash = some raw) :
      Needs publisher scope (some origin) hash path (.provenance origin hash)
  | value {owner : Option String} {hash raw address bytes : ByteArray}
      {path : List UInt8} {node : Node}
      (heldNode : publisher nodeSpace hash = some raw)
      (decoded : decode raw = .ok node) (admitted : scope.admitsValue path node = true)
      (named : address ∈ node.valueHashes) (heldValue : publisher valueSpace address = some bytes) :
      Needs publisher scope owner hash path (.value address bytes)
  | extension {owner : Option String} {hash raw segment child : ByteArray}
      {path : List UInt8} {evidence : Evidence}
      (held : publisher nodeSpace hash = some raw)
      (decoded : decode raw = .ok (.extension segment child))
      (nonempty : segment.toList ≠ [])
      (below : Needs publisher scope owner child (path ++ segment.toList) evidence) :
      Needs publisher scope owner hash path evidence
  | branch {owner : Option String} {hash raw child : ByteArray}
      {path : List UInt8} {evidence : Evidence}
      {children : List (Option ByteArray)} {branchValue : Option Value} {nibble : UInt8}
      (held : publisher nodeSpace hash = some raw)
      (decoded : decode raw = .ok (.branch children branchValue))
      (edge : children[nibble.toNat]? = some (some child))
      (below : Needs publisher scope owner child (path ++ [nibble]) evidence) :
      Needs publisher scope owner hash path evidence
  | route {owner : Option String} {hash raw child : ByteArray}
      {path : List UInt8} {evidence : Evidence}
      {children : List (Option ByteArray)} {routeValue : Option ByteArray} {nibble : UInt8}
      (held : publisher nodeSpace hash = some raw)
      (decoded : decode raw = .ok (.route children routeValue))
      (edge : children[nibble.toNat]? = some (some child))
      (below : Needs publisher scope owner child (path ++ [nibble]) evidence) :
      Needs publisher scope owner hash path evidence

/-- All independently specified requirements below this position are present
in the replica. -/
def CompleteAt (publisher : RawSnapshot) (scope : Serve.Scope) (owner : Option String)
    (root : ByteArray) (path : List UInt8) (replica : Replica) : Prop :=
  ∀ evidence, Needs publisher scope owner root path evidence → Verified replica evidence

/-- Completion of the selected root starts at the root position. -/
def PermittedComplete (publisher : RawSnapshot) (scope : Serve.Scope) (owner : Option String)
    (root : ByteArray) (replica : Replica) : Prop :=
  CompleteAt publisher scope owner root [] replica

/-- A finite, duplicate-free enumeration of the operation-independent
requirements.  Keeping the enumeration explicit avoids defining a second
fuelled graph traversal merely to state the specification. -/
structure FiniteRequirements (publisher : RawSnapshot) (scope : Serve.Scope)
    (owner : Option String) (root : ByteArray) where
  items : List Evidence
  nodup : items.Nodup
  exact : ∀ evidence, evidence ∈ items ↔ Needs publisher scope owner root [] evidence

/-- Number of independently required facts not yet verified.  It depends only
on persistent evidence, never on the size of a frontier which may grow when a
node is expanded. -/
def missingEvidence (requirements : List Evidence) (replica : Replica) : Nat :=
  requirements.countP fun evidence => !decide (Verified replica evidence)

/-- Previously verified evidence remains verified. -/
def EvidenceIncluded (before after : Replica) : Prop :=
  ∀ evidence, Verified before evidence → Verified after evidence

theorem verified_mono (included : EvidenceIncluded before after)
    (verified : Verified before evidence) : Verified after evidence :=
  included evidence verified

theorem EvidenceIncluded.refl (replica : Replica) : EvidenceIncluded replica replica :=
  fun _ verified => verified

theorem EvidenceIncluded.trans {first second third : Replica}
    (left : EvidenceIncluded first second) (right : EvidenceIncluded second third) :
    EvidenceIncluded first third :=
  fun evidence verified => right evidence (left evidence verified)

theorem missingEvidence_mono (requirements : List Evidence)
    (included : EvidenceIncluded before after) :
    missingEvidence requirements after ≤ missingEvidence requirements before := by
  induction requirements with
  | nil => simp [missingEvidence]
  | cons evidence rest ih =>
    have tail : List.countP (fun evidence => !decide (Verified after evidence)) rest ≤
        List.countP (fun evidence => !decide (Verified before evidence)) rest := by
      simpa [missingEvidence] using ih
    by_cases old : Verified before evidence
    · have new := included evidence old
      simpa [missingEvidence, old, new] using tail
    · by_cases new : Verified after evidence
      · simp [missingEvidence, old, new]
        exact Nat.le_succ_of_le tail
      · simp [missingEvidence, old, new, tail]

/-- Adding one required fact which was genuinely absent strictly decreases the
measure, provided no earlier evidence is lost.  This is the algebraic lemma an
actual atomic `Fetch.admit` execution must instantiate. -/
theorem missingEvidence_strict_of_added (requirements : List Evidence)
    (needed : evidence ∈ requirements) (absent : ¬ Verified before evidence)
    (included : EvidenceIncluded before after) (added : Verified after evidence) :
    missingEvidence requirements after < missingEvidence requirements before := by
  induction requirements with
  | nil => cases needed
  | cons head rest ih =>
    rcases List.mem_cons.mp needed with same | later
    · subst head
      have tail := missingEvidence_mono rest included
      simp [missingEvidence, absent, added]
      simpa [missingEvidence] using Nat.lt_succ_of_le tail
    · have strict := ih later
      by_cases old : Verified before head
      · have new := included head old
        simpa [missingEvidence, old, new] using strict
      · by_cases new : Verified after head
        · simp [missingEvidence, old, new]
          simpa [missingEvidence] using Nat.lt_trans strict (Nat.lt_succ_self _)
        · simpa [missingEvidence, old, new] using Nat.succ_lt_succ strict

/-- The exact finite enumeration turns the preceding algebraic result into a
strict decrease for any newly added semantic requirement. -/
theorem finite_measure_strict_of_added
    (requirements : FiniteRequirements publisher scope owner root)
    (needed : Needs publisher scope owner root [] evidence)
    (absent : ¬ Verified before evidence) (included : EvidenceIncluded before after)
    (added : Verified after evidence) :
    missingEvidence requirements.items after < missingEvidence requirements.items before :=
  missingEvidence_strict_of_added requirements.items ((requirements.exact evidence).2 needed)
    absent included added

theorem missingEvidence_eq_zero_iff_all_verified (requirements : List Evidence) :
    missingEvidence requirements replica = 0 ↔
      ∀ evidence ∈ requirements, Verified replica evidence := by
  induction requirements with
  | nil => simp [missingEvidence]
  | cons head tail ih =>
    by_cases verified : Verified replica head <;>
      simp [missingEvidence, verified]

/-- The measure reaches zero exactly at semantic completion; zero is not a
statement about an empty transient frontier. -/
theorem finite_measure_eq_zero_iff_complete
    (requirements : FiniteRequirements publisher scope owner root) :
    missingEvidence requirements.items replica = 0 ↔
      PermittedComplete publisher scope owner root replica := by
  rw [missingEvidence_eq_zero_iff_all_verified]
  constructor
  · intro all evidence needed
    exact all evidence ((requirements.exact evidence).2 needed)
  · intro complete evidence member
    exact complete evidence ((requirements.exact evidence).1 member)

theorem completion_mono (complete : PermittedComplete publisher scope owner root before)
    (included : EvidenceIncluded before after) :
    PermittedComplete publisher scope owner root after := by
  intro evidence needed
  exact included evidence (complete evidence needed)

/-- Every requirement names bytes really present in the publisher, or names
provenance for a publisher node.  Child lifting cannot manufacture evidence. -/
def PublisherBacks (publisher : RawSnapshot) : Evidence → Prop
  | .node hash raw => publisher nodeSpace hash = some raw
  | .value hash bytes => publisher valueSpace hash = some bytes
  | .provenance _ hash => ∃ raw, publisher nodeSpace hash = some raw

theorem needs_publisher_backing (needed : Needs publisher scope owner root path evidence) :
    PublisherBacks publisher evidence := by
  induction needed with
  | node admitted held => simpa [PublisherBacks] using held
  | provenance admitted held => exact ⟨_, held⟩
  | value heldNode decoded admitted named heldValue => simpa [PublisherBacks] using heldValue
  | extension held decoded nonempty below ih => exact ih
  | branch held decoded edge below ih => exact ih
  | route held decoded edge below ih => exact ih

/-- A closed publisher root always contributes its root node when that position
is admitted.  This connects the existing finite stored-snapshot property to the
new requirements without treating `Closed` itself as a completion flag. -/
theorem closed_root_needs_node (closed : Closed publisher root)
    (admitted : scope.admitsPath path = true) :
    ∃ raw, Needs publisher scope owner root path (.node root raw) := by
  cases closed with
  | leaf held decoded payload => exact ⟨_, .node admitted held⟩
  | extension held decoded nonempty below => exact ⟨_, .node admitted held⟩
  | branch held decoded payload below => exact ⟨_, .node admitted held⟩
  | route held decoded payload below => exact ⟨_, .node admitted held⟩

private theorem admitted_position (scope : Serve.Scope) (path tail : List UInt8)
    (granted : scope.admitsKeyPath (path ++ tail) = true) : scope.admitsPath path = true :=
  admitsPath_of_append scope path tail (admitsPath_of_admitsKeyPath scope (path ++ tail) granted)

private theorem value_denotes_of_complete
    (complete : CompleteAt publisher scope owner hash path replica)
    (heldNode : publisher nodeSpace hash = some raw) (decoded : decode raw = .ok node)
    (admitted : scope.admitsValue path node = true) (named : address ∈ node.valueHashes)
    (denotes : ValueDenotes publisher value bytes) (addressed : value = .hash address) :
    ValueDenotes replica.records value bytes := by
  subst value
  cases denotes with
  | stored _ _ heldValue =>
    exact .stored _ _ (complete (.value address bytes)
      (.value heldNode decoded admitted named heldValue))

/-- Semantic adequacy of completion.  Every publisher entry selected by the
scope is also an entry of the replica with exactly the same bytes.  The proof
reconstructs the independent `GraphValue` relation; it does not run the missing
walk or inspect a memo flag. -/
theorem graphValue_of_complete
    (complete : CompleteAt publisher scope owner root path replica)
    (entry : GraphValue publisher root tail bytes)
    (granted : scope.admitsKeyPath (path ++ tail) = true) :
    GraphValue replica.records root tail bytes := by
  induction entry generalizing path with
  | leaf address raw suffix value bytes held decoded denotes =>
    have admitted := admitted_position scope path suffix.toList granted
    have localNode := complete (.node address raw) (.node admitted held)
    have valueGranted : scope.admitsValue path (.leaf suffix value) = true := by
      simpa [Serve.Scope.admitsValue] using granted
    have localValue : ValueDenotes replica.records value bytes := by
      cases denotes with
      | inline inline => exact .inline _
      | stored valueHash valueBytes heldValue =>
        exact value_denotes_of_complete complete held decoded valueGranted
          (by simp [Node.valueHashes]) (.stored _ _ heldValue) rfl
    exact .leaf _ _ _ _ _ localNode decoded localValue
  | branchValue address raw children value bytes held decoded denotes =>
    have admitted := admitted_position scope path [] (by simpa using granted)
    have localNode := complete (.node address raw) (.node admitted held)
    have valueGranted : scope.admitsValue path (.branch children (some value)) = true := by
      simpa [Serve.Scope.admitsValue] using granted
    have localValue : ValueDenotes replica.records value bytes := by
      cases denotes with
      | inline inline => exact .inline _
      | stored valueHash valueBytes heldValue =>
        exact value_denotes_of_complete complete held decoded valueGranted
          (by simp [Node.valueHashes]) (.stored _ _ heldValue) rfl
    exact .branchValue _ _ _ _ _ localNode decoded localValue
  | extension address raw segment child tail bytes held decoded nonempty below ih =>
    have admitted := admitted_position scope path (segment.toList ++ tail) granted
    have localNode := complete (.node address raw) (.node admitted held)
    have childComplete : CompleteAt publisher scope owner child (path ++ segment.toList) replica :=
      fun evidence needed => complete evidence (.extension held decoded nonempty needed)
    have childGranted : scope.admitsKeyPath ((path ++ segment.toList) ++ tail) = true := by
      simpa only [List.append_assoc] using granted
    exact .extension _ _ _ _ _ _ localNode decoded nonempty (ih childComplete childGranted)
  | branchChild address raw children value nibble child tail bytes held decoded edge below ih =>
    have admitted := admitted_position scope path (nibble :: tail) granted
    have localNode := complete (.node address raw) (.node admitted held)
    have childComplete : CompleteAt publisher scope owner child (path ++ [nibble]) replica :=
      fun evidence needed => complete evidence (.branch held decoded edge needed)
    have childGranted : scope.admitsKeyPath ((path ++ [nibble]) ++ tail) = true := by
      simpa only [List.append_assoc, List.singleton_append] using granted
    exact .branchChild _ _ _ _ _ _ _ _ localNode decoded edge (ih childComplete childGranted)
  | routeValue address raw children value bytes held decoded denotes =>
    have admitted := admitted_position scope path [] (by simpa using granted)
    have localNode := complete (.node address raw) (.node admitted held)
    have valueGranted : scope.admitsValue path (.route children (some value)) = true := by
      simpa [Serve.Scope.admitsValue] using granted
    have localValue := value_denotes_of_complete complete held decoded valueGranted
      (by simp [Node.valueHashes])
      denotes rfl
    exact .routeValue _ _ _ _ _ localNode decoded localValue
  | routeChild address raw children value nibble child tail bytes held decoded edge below ih =>
    have admitted := admitted_position scope path (nibble :: tail) granted
    have localNode := complete (.node address raw) (.node admitted held)
    have childComplete : CompleteAt publisher scope owner child (path ++ [nibble]) replica :=
      fun evidence needed => complete evidence (.route held decoded edge needed)
    have childGranted : scope.admitsKeyPath ((path ++ [nibble]) ++ tail) = true := by
      simpa only [List.append_assoc, List.singleton_append] using granted
    exact .routeChild _ _ _ _ _ _ _ _ localNode decoded edge (ih childComplete childGranted)

/-- User-facing positive-entry consequence at the selected root.  Exact
absence additionally needs the frontier/exhaustion theorem which proves this
module's `PermittedComplete` predicate. -/
theorem completion_covers_permitted_entries
    (complete : PermittedComplete publisher scope owner root replica)
    (entry : Entry publisher root key bytes)
    (granted : scope.admitsKeyPath (keyNibbles key) = true) :
    Entry replica.records root key bytes := by
  refine ⟨entry.1, entry.2.1, ?_⟩
  exact graphValue_of_complete complete entry.2.2 (by simpa using granted)

end Synchronicity.TrieFetchCompletion
