import Synchronicity.SnapshotDelta
import Synchronicity.MaterializationRetention

/-! The independent metadata-view specification used by publication proofs.
Rows are observed by domain key and record columns, not physical field order,
timestamps belonging to the receiver, traversal completion or callback counts.
The immutable graph supplies the expected published records. -/
namespace Synchronicity.MaterializedView
open VerifiedCore VerifiedCore.Host Replication TrieProgramProofs TrieSnapshotProofs SimulatedHost

inductive Address where
  | file (space path : String)
  | provider (root : ByteArray)
  | delegation (key : ByteArray)

def Address.table : Address → String
  | .file .. => "entries"
  | .provider .. => "blob_providers"
  | .delegation .. => "bindings"

def Address.key (origin : String) : Address → Fields
  | .file space path => [("origin_id", .text origin), ("space", .text space), ("path", .text path)]
  | .provider root => [("object_root", .blob root), ("origin_id", .text origin)]
  | .delegation key => [("origin_id", .text (Origin.canonical (.key key.toList))),
      ("node_id", .blob key), ("source", .text "delegated"), ("issuer", .text origin)]

def Address.columns : Address → List String
  | .file .. => ["kind", "size", "mtime_ns", "unix_mode", "content", "seq", "prev", "symlink_target"]
  | .provider .. => ["size", "complete", "spans"]
  | .delegation .. => ["spaces", "expires_at", "note"]

/-- The same primitive key-validity and Unicode contracts used at the host
boundary; these functions do not decide any publication or retention policy. -/
structure Services where
  nfc : String → Bool
  ed25519 : List UInt8 → Bool

/-- Domain interpretation of a published metadata key. Unknown keys have
no projection, while invalid file paths and invalid delegation keys are ignored.
The format's file/provider decoding errors are not successful SQL updates. -/
def Addresses (services : Services) (key : ByteArray) : Address → Prop
  | .file space path => key[0]? = some 102 ∧ Records.fileKey key = some (space, path) ∧ services.nfc path = true
  | .provider root => key.size = 34 ∧ key[0]? = some 98 ∧ key[1]? = some 58 ∧ key.extract 2 34 = root
  | .delegation publicKey => key.size = 34 ∧ key[0]? = some 100 ∧ key[1]? = some 58 ∧
      key.extract 2 34 = publicKey ∧ services.ed25519 publicKey.toList = true

def Decoded (address : Address) (bytes : ByteArray) (values : List Cell) : Prop :=
  match address with
  | .file _ _ => ∃ record rest, Records.file (bytes, 0) = .ok (record, rest) ∧
      project address.columns record.fields = values
  | .provider _ => ∃ fields rest, Records.blob (bytes, 0) = .ok (fields, rest) ∧
      project address.columns fields = values
  | .delegation _ => ∃ fields rest, Records.delegation (bytes, 0) = .ok (fields, rest) ∧
      project address.columns fields = values

/-- An immutable snapshot's permitted, well-formed domain records. -/
def Expected (services : Services) (snapshot : RawSnapshot) (root : ByteArray)
    (allowed : ByteArray → Prop) (address : Address) (values : List Cell) : Prop :=
  ∃ key bytes, allowed key ∧ Entry snapshot root key bytes ∧
    Addresses services key address ∧ Decoded address bytes values

/-- Observable receiver rows, ignoring storage order and receiver-owned
creation times. Existence does not stand in for correct record contents. -/
def Observed (db : Database) (origin : String) (address : Address) (values : List Cell) : Prop :=
  ∃ row ∈ rows db address.table, equals row (address.key origin) = true ∧ project address.columns row = values

def Exact (services : Services) (snapshot : RawSnapshot) (root : ByteArray)
    (allowed : ByteArray → Prop) (db : Database) (origin : String) : Prop :=
  ∀ address values, Observed db origin address values ↔ Expected services snapshot root allowed address values

/-- Replacing one domain record gives exactly the newly published contents
(or absence), while every unselected row retains all receiver-owned fields. -/
def ReplacesRecord (before after : Database) (origin : String) (address : Address)
    (value : Option ByteArray) : Prop :=
  (∀ values, Observed after origin address values ↔
    ∃ bytes, value = some bytes ∧ Decoded address bytes values) ∧
  (∀ row, equals row (address.key origin) = false →
    (row ∈ rows after address.table ↔ row ∈ rows before address.table))

/-- Current file references need a live hold or a persistent acquisition
request. Download completion itself is not a requirement of metadata sync. -/
def CurrentRequirements (replicas : List Materialize.Target) (db : Database) : Prop :=
  ∀ target ∈ replicas, ∀ row ∈ rows db "entries", isCell (cell row "space") (.text target.space) = true →
    ∀ root, cell row "content" = .blob root → MaterializationRetention.Required db root target.holder

/-- Historical forever requirements cannot disappear when entries change. -/
def ForeverRequirements (replicas : List Materialize.Target) (before after : Database) : Prop :=
  ∀ target ∈ replicas, target.releases = false → ∀ root,
    MaterializationRetention.Required before root target.holder → MaterializationRetention.Required after root target.holder

/-- Canonical published keys identify one domain record each. This is a
format/schema condition, independent of either view's correctness. -/
def UniqueAddresses (services : Services) (keys : ByteArray → Prop) : Prop :=
  ∀ left right address, keys left → keys right →
    Addresses services left address → Addresses services right address → left = right

end Synchronicity.MaterializedView
