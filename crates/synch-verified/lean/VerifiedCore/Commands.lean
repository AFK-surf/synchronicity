import VerifiedCore.Authorization.Operations
import VerifiedCore.Cas
import VerifiedCore.Cas.Codec
import VerifiedCore.Cas.Program
import VerifiedCore.Cas.Input
import VerifiedCore.Origin
import VerifiedCore.Trie.Program
import VerifiedCore.Trie.Verify
import VerifiedCore.Trie.Mutate
import VerifiedCore.Trie.Normalize
import VerifiedCore.Cas.Durable
import VerifiedCore.Cas.Serve
import VerifiedCore.Cas.Receive
import VerifiedCore.Cas.Collect
import VerifiedCore.Cas.Project
import VerifiedCore.Cas.Cloud
import VerifiedCore.Trie.Serve
import VerifiedCore.Trie.Collect
import VerifiedCore.Trie.Walk
import VerifiedCore.Trie.ScopeCheck
import VerifiedCore.Trie.Diff
import VerifiedCore.Trie.Proof
import VerifiedCore.Trie.Complete
import VerifiedCore.Trie.Fetch
import VerifiedCore.Host.Peer
import VerifiedCore.Replication.Exchange
import VerifiedCore.Replication.Contact
import VerifiedCore.Replication.OriginSchedule
import VerifiedCore.Replication.ScopeChange
import VerifiedCore.Replication.Types

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
  | acceptHead (head : Replication.Head) (now : Int64) (keep : Nat)
  | promoteHead (origin : Origin.Parsed) (now : Int64)
      (refused : List (UInt64 × ByteArray × ByteArray))
  | materializeView (tx : UInt64) (origin : Origin.Parsed) (oldRoot newRoot : ByteArray)
  | fetchPending (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
      (refused : List (UInt64 × ByteArray × ByteArray)) (maximum retryLimit : Nat)
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
  /-- Serve the nodes a peer asked for by `(nibble path, claimed hash)` under
  a root: positions a scoped peer may see, what stands there, what a node
  reveals, one answer's budget. The scope and the confined origins are the
  Authorization domain's inputs. -/
  | trieServeNodes (root : ByteArray) (wants : List (ByteArray × ByteArray))
      (prefixes : Option (List ByteArray)) (exact : List ByteArray) (peerOrigins confined : List String)
  /-- Serve the out-of-line values a peer asked for, each authorized by the
  position of the node that holds it when the view is scoped. -/
  | trieServeValues (root : ByteArray) (wants : List (ByteArray × ByteArray))
      (prefixes : Option (List ByteArray)) (exact : List ByteArray) (peerOrigins confined : List String)
  /-- What stands at each nibble position under a root. -/
  | trieResolve (root : ByteArray) (paths : List ByteArray)
  /-- Sweep every trie node, provenance row and out-of-line value no retained
  head reaches, keeping the completeness certificates of the retained roots
  under the local scope (`prefixes`, `exact`), all in one transaction. -/
  | trieCollect (prefixes : Option (List ByteArray)) (exact : List ByteArray)
  /-- The key a completeness answer for `root` under a scope, and as
  `owner`'s own when given, is memoized under. -/
  | trieMemoKey (root : ByteArray) (prefixes : Option (List ByteArray)) (exact : List ByteArray)
      (owner : Option String)
  /-- Every pair under a root whose key starts with `keyPrefix`, in key
  order, optionally resuming strictly after `startAfter` and capped at `limit`. -/
  | trieScan (root keyPrefix : ByteArray) (startAfter : Option ByteArray) (limit : Option UInt64)
  /-- Every differing key between two roots, in key order. -/
  | trieDiff (oldRoot newRoot : ByteArray)
  /-- Hand every change between two roots that the scope admits to the
  materializer, one at a time with its new value resolved; answers how many. -/
  | trieMaterialize (oldRoot newRoot : ByteArray) (prefixes : Option (List ByteArray))
      (exact : List ByteArray)
  /-- The Merkle proof for a key (the run's first byte input) against a root:
  the nodes on its path and the out-of-line payload, if any. -/
  | trieProve (root : ByteArray) (keySize : UInt64)
  /-- Verify a proof against a root for a key: the lookup over the proof's
  nodes, answering the proved value or an absence. -/
  | trieVerifyProof (root key : ByteArray) (nodes : List ByteArray) (value : Option ByteArray)
  /-- The suspending runner's self-test: two peer round trips, inside a
  transaction when told to. -/
  | peerProbe (root : ByteArray) (wants : List (ByteArray × ByteArray)) (inTransaction : Bool)
  | providerProbe (key : ByteArray) (mode : UInt64)
  | cloudEnsureCached (root : ByteArray) (size : UInt64)
  | cloudEnsureRanges (root : ByteArray) (size : UInt64) (ranges : List (UInt64 × UInt64))
  | cloudHydrate (root : ByteArray) (size : UInt64) (ranges : List (UInt64 × UInt64))
  | cloudOutboard (root : ByteArray) (force : Bool)
  /-- Whether every scope-admitted position and value is held, with the
  requested provenance, guarded by the completeness memo's generation. -/
  | trieComplete (root : ByteArray) (prefixes : Option (List ByteArray)) (exact : List ByteArray)
      (owner : Option String)
  /-- Plan both directions of one metadata head exchange. -/
  | planExchange (ours theirs servable : List Replication.Exchange.Advertised)
  /-- Fetch a named pending version, retaining its requesting walk across peer waits. -/
  | trieFetch (root : ByteArray) (origin : String) (seq : UInt64)
      (prefixes : Option (List ByteArray)) (exact : List ByteArray) (owner : Option String)
      (reference : Option ByteArray) (maximum retryLimit : UInt64)

  /-- Prepare routing spines for a private scoped publication. -/
  | trieNormalize (root : ByteArray)
  /-- Read one complete CAS projection within a transaction owned by the caller. -/
  | casBlobIn (tx : UInt64) (root : ByteArray)
  /-- Select the next bounded batch of eligible peers in cyclic order. -/
  | planContact (peers : List ByteArray) (cursor : Option ByteArray) (maximum : UInt64)
  | planOrigins (items : List Replication.OriginSchedule.Item)
      (cursor : Option String) (maximum : UInt64)

  /-- Check that a confined publisher introduces no entries outside its grant. -/
  | trieFirstOutside (root : ByteArray) (prefixes : Option (List ByteArray)) (exact : List ByteArray)

  /-- Complete origin parsing, including primitive key-point validation. -/
  | originParse (text : String)
  /-- Validate and normalize both named-origin components in one operation. -/
  | originNamed (id domain : String)
  | originNormalizeLabel (text : String)
  | originNormalizeDomain (text : String)
  | originCanonical (value : Origin.Parsed)
  | authBindings (selection : Authorization.BindingSelection) (onlyLive : Bool) (reading : Int64)
  | authBindingStatuses (reading : Int64)
  | authTrustedKeys (reading : Int64)
  | authTrustedOrigins (reading : Int64)
  | authTrustedKey (key : ByteArray) (reading : Int64)
  | authBound (origin : Origin.Parsed) (key : ByteArray) (reading : Int64)
  | authPeerAuthority (key : ByteArray) (reading : Int64)
  | authOriginPublication (origin : Origin.Parsed) (reading : Int64)
  | authOriginAuthority (origin : Origin.Parsed) (reading : Int64)
  | authOriginAuthorityIn (tx : UInt64) (origin : Origin.Parsed) (reading : Int64)
  | authLocalAuthority (reading : Int64)
  | authLocalSpaces
  | authLocalScope
  | authLocalScopeIn (tx : UInt64)
  | authMaterializationScope (origin : Origin.Parsed)
  | authMaterializationScopeIn (tx : UInt64) (origin : Origin.Parsed)
  | authMetadataPeer (key : ByteArray) (reading : Int64)
  | authSocketAuthority (key : ByteArray) (reading : Int64)
  | authSoleDnsHintSource (key : ByteArray) (domain : String) (reading : Int64)
  | authHasDelegations
  | authExpireDns (reading : Int64)
  /-- Atomically replace the local read scope and invalidate all derived
  foreign views and completion claims made under the prior permission. -/
  | authChangeScope (spaces : Option (List String)) (now : Int64)


inductive AuthorizationDomainError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | invalidText (bytes : ByteArray)
  | column (column : String) (reason : String)
  | origin (column : String) (error : Origin.Error)
  deriving BEq, DecidableEq

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

/-- How serving a trie refuses: a root a scoped peer may not read positions
of, a stored node that does not decode, or a malformed head row. -/
inductive TrieServeDomainError where
  | unvouchedRoot
  | decode (message : String)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | column (column : String) (reason : String)
  deriving BEq, DecidableEq

/-- How a trie sweep refuses: a stored node that does not decode, a malformed
head row, or a mark walk that outran its budget, in which case nothing is
swept. -/
inductive TrieCollectDomainError where
  | decode (message : String)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | column (column : String) (reason : String)
  | origin (error : Origin.Error)
  | exhausted
  deriving BEq, DecidableEq

/-- The requesting walk's stored-shape refusals. Host failures retain their
original token rather than being translated into one of these verdicts. -/
inductive TrieMissingDomainError where
  | decode (message : String)
  | nodeDepth (depth : Nat)
  | valueDepth (depth : Nat)
  | expectedBranch (hash : ByteArray)
  | exhausted
  | valueLength (hash : ByteArray) (size : Nat) (routing : Bool)
  deriving BEq, DecidableEq

inductive TrieFetchDomainError where
  | walk (error : TrieMissingDomainError)
  | origin (refusal : Trie.Refusal)
  | nodeHash (hash : ByteArray)
  | valueHash (hash : ByteArray)
  | unsolicited (value : Bool) (hash : ByteArray)
  | exhausted
  deriving BEq, DecidableEq

/-- How a walk refuses: a node or value the walk needs and the store does
not hold, a node that does not decode, a value at a depth no byte key ends
at, or more positions than a trie of the permitted size has. -/
inductive TrieWalkDomainError where
  | missingNode (hash : ByteArray)
  | missingValue (hash : ByteArray)
  | decode (message : String)
  | oddDepthValue
  | ceiling
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

/-- Cloud restoration refusals; original host failures use the host terminal. -/
inductive CloudDomainError where
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | column (column reason : String)
  | missingBlob (root : ByteArray)
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  | cacheBusy
  | invalidRange (start stop size : UInt64)
  | unalignedRange
  | incompleteInline
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

/-- What a trie sweep took, and how many retained roots it marked from. -/
structure Collected where
  nodes : UInt64
  values : UInt64
  roots : UInt64
  deriving BEq, DecidableEq

inductive ReconcileDomainError where
  | history (error : HistoryDomainError)
  | walk (error : TrieWalkDomainError)
  | missing (error : TrieMissingDomainError)
  | fetch (error : TrieFetchDomainError)
  deriving BEq, DecidableEq

structure PromotionReport where
  promotion : Replication.Promotion
  failure : Option ReconcileDomainError
  refused : Option (UInt64 × ByteArray × ByteArray)
  deriving BEq, DecidableEq

structure FetchReport where
  report : PromotionReport
  abandoned : Bool
  deriving BEq, DecidableEq

end VerifiedCore.Commands
