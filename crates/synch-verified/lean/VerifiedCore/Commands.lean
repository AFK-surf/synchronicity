import VerifiedCore.Cas
import VerifiedCore.Cas.Codec
import VerifiedCore.Cas.Program
import VerifiedCore.Cas.Input
import VerifiedCore.Origin
import VerifiedCore.Trie.Program
import VerifiedCore.Trie.Verify
import VerifiedCore.Trie.Mutate
import VerifiedCore.Cas.Durable
import VerifiedCore.Cas.Serve
import VerifiedCore.Cas.Receive
import VerifiedCore.Cas.Collect
import VerifiedCore.Cas.Project

/-! The shapes that cross the command boundary: what a caller asks for and
what a finished command reports. `hostgen` derives the codecs of every type
here on both sides (`Commands/Generated.lean`, `src/generated.rs`), so a
command's arguments and outcomes are declared once, in Lean.

Outcome types are flat: a host failure is never one of their constructors,
because the host's own error travels back as the failure terminal, and a
protocol violation as the protocol failure. `Entry` maps each operation's
domain errors onto these. -/
namespace VerifiedCore.Commands

/-- Every command the host can start. The arguments are the command's whole
input apart from the borrowed byte inputs (`Storage.readInput`) a run supplies. -/
inductive Command where
  /-- Pin or take possession of an object for a holder. -/
  | acquire (root : ByteArray) (holder : String) (now : Int64) (possession : Bool)
  /-- Delete an object, or only collect it when unused since `before`. -/
  | delete (root : ByteArray) (before : Option Int64)
  /-- Release one holder's claim. -/
  | unpin (root : ByteArray) (holder : Cas.PinHolder)
  /-- Expire due claims, for one holder or for all. -/
  | expire (holder : Option Cas.PinHolder) (now : Int64)
  /-- Read the whole object or a range of it into the run's output sink. -/
  | read (root : ByteArray) (range : Option (UInt64 × UInt64))
  /-- Ingest the run's `input` capability as a whole object. -/
  | ingest (input : Cas.Input.Kind) (now : Int64) (cache allowUnsupported : Bool)
  /-- Commit verified groups of an object. -/
  | commitGroups (root : ByteArray) (spans : List (UInt64 × UInt64)) (size : UInt64)
      (inline : Option ByteArray) (now : Int64) (cache : Bool)
  /-- Refuse a size the object's row cannot yield to. -/
  | admitSize (root : ByteArray) (size : UInt64)
  /-- Look a key up in a trie; the key is the run's first byte input. -/
  | trieGet (root : ByteArray) (keySize : UInt64)
  /-- Admit node bytes (the run's first byte input) at the canonical ingress
  boundary and answer the hash they are stored under, or the refusal. -/
  | trieAdmit (size : UInt64)
  /-- Decide whether served node bytes (the run's first byte input) are the
  node `expected` names and, when they are not, whose fault that is. -/
  | trieVerify (expected : ByteArray) (size : UInt64)
  /-- Insert or replace a key (the run's first byte input) with a value (the
  second), answering the new root. -/
  | trieInsert (root : ByteArray) (keySize valueSize : UInt64)
  /-- Remove a key (the run's first byte input), answering the new root. -/
  | trieRemove (root : ByteArray) (keySize : UInt64)
  /-- Retire head history of an origin recorded before `before`. -/
  | pruneHistory (origin : String) (before : Int64)
  /-- Record that the backend holds the complete object; only after its
  acknowledgement, which is the caller's obligation. -/
  | casMarkDurable (root : ByteArray)
  /-- Reconstruct a cold durable row once the backend confirmed the final pair. -/
  | casAdoptDurable (root : ByteArray) (size : UInt64) (now : Int64)
  /-- The backend answered that the object is not there: withdraw the durable
  claim and turn machine roles into repair intents. -/
  | casHealMissing (root : ByteArray)
  /-- Reconcile cache claims with an ephemeral scratch generation marker. -/
  | casReconcileScratch (marker : String)
  /-- Drop reconstructible local bytes while keeping a remote durable claim. -/
  | casClearCache (root : ByteArray)
  /-- Serve a Bao slice of the requested group spans into the run's output
  sink: what the row holds, clamped to one exchange's window. -/
  | casEncodeSlice (root : ByteArray) (requested : List (UInt64 × UInt64))
  /-- Serve the interior tree over the requested group spans, no deeper than
  `level`, refused whole beyond `budget` nodes. -/
  | casEncodeProof (root : ByteArray) (requested : List (UInt64 × UInt64)) (level budget : UInt64)
  /-- Decode a received slice (the run's first byte input) of the served
  spans and commit exactly the groups it verified. -/
  | casWriteSlice (root : ByteArray) (size : UInt64) (served : List (UInt64 × UInt64))
      (now : Int64) (cache : Bool)
  /-- Verify a received proof (the run's first byte input) over the served
  spans at `level` and record its tree. -/
  | casWriteProof (root : ByteArray) (size : UInt64) (served : List (UInt64 × UInt64))
      (level : UInt64) (now : Int64) (cache : Bool)
  /-- Promote the donor's bytes for every proven subtree its tree agrees with. -/
  | casPromote (donor root : ByteArray) (size : UInt64) (proven : List Cas.Receive.ProvenSubtree)
      (now : Int64) (cache : Bool)
  /-- Advance an object's access clock, coalesced to once a minute; answers
  whether it moved. -/
  | casTouch (root : ByteArray)
  /-- Evict cached durable objects by least recent use until the cache is
  within `limit` bytes and `shortfall` bytes more are free. -/
  | casEvict (limit : Option UInt64) (shortfall : UInt64)
  /-- Collect every unreferenced, unpinned object untouched since `before`. -/
  | casGcContent (before : Int64)
  /-- Remove object files no row accounts for, once older than `before` and
  held by no writer. -/
  | casGcOrphans (before : Int64)
  /-- One object's index row, with whether any claim stands on it. -/
  | casBlob (root : ByteArray)
  /-- Every index row, most recently accessed first. -/
  | casBlobs
  /-- Every row's summary without its payload, most recently accessed first. -/
  | casBlobCandidates
  /-- Every claim on one object, or on all, by object and then by holder. -/
  | casPins (root : Option ByteArray)
  /-- Every pinned object, in root order. -/
  | casPinnedBlobs

/-- Malformed metadata or a column of the wrong storage class, as pin
acquisition and deletion report it. -/
inductive LifecycleDomainError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  deriving BEq, DecidableEq

inductive IngestDomainError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  /-- The row's claim cannot yield to the offered size. -/
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  /-- The platform cannot synchronize directories and the policy requires it. -/
  | directorySyncUnsupported
  deriving BEq, DecidableEq

inductive ReadDomainError where
  | missingBlob
  | range (start stop size : UInt64)
  | unavailable
  | shortInline
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | column (column : String) (reason : String)
  deriving BEq, DecidableEq

/-- How a durability transition refuses: a malformed row, or a row whose
recorded size disagrees with the size the backend confirmed. -/
inductive DurableDomainError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  deriving BEq, DecidableEq

/-- How serving refuses: no row, a malformed row, or a proof that does not
fit the node budget. -/
inductive ServeDomainError where
  | missingBlob
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | column (column : String) (reason : String)
  | overBudget (level budget : UInt64)
  deriving BEq, DecidableEq

/-- How receiving refuses: a malformed row, or a claim the row cannot yield to. -/
inductive ReceiveDomainError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | column (column : String) (reason : String)
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  deriving BEq, DecidableEq

/-- How a projection refuses: a malformed row, a column of the wrong class,
or a column whose value is not a root or a holder. -/
inductive ProjectDomainError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | column (column : String) (reason : String)
  deriving BEq, DecidableEq

/-- How a sweep refuses: a malformed row, or a claim a row cannot yield to. -/
inductive CollectDomainError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  deriving BEq, DecidableEq

inductive HistoryDomainError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | invalidText (bytes : ByteArray)
  | column (column : String) (reason : String)
  | origin (error : Origin.Error)
  deriving BEq, DecidableEq

/-- A whole ingested object. -/
structure Ingested where
  root : ByteArray
  size : UInt64
  deriving BEq, DecidableEq

/-- What a commit settled: the size the row records now, and whether every
group of the object is present. -/
structure Committed where
  size : UInt64
  complete : Bool
  deriving BEq, DecidableEq

/-- What one exchange served: the bytes appended to the output sink and the
group spans they cover. -/
structure Served where
  count : UInt64
  spans : List (UInt64 × UInt64)
  deriving BEq, DecidableEq

/-- What an eviction pass took: the entries cleared and the bytes they freed. -/
structure Evicted where
  entries : UInt64
  freed : UInt64
  deriving BEq, DecidableEq

end VerifiedCore.Commands
