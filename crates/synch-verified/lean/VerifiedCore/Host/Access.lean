import VerifiedCore.Host

/-! Additional raw capabilities needed by complete local reads and repair.
No callback parses domain metadata or decides recovery policy. -/
namespace VerifiedCore.Host

/-- A raw selection. Equality terms are conjunctive; a nonempty `likeAny`
adds one disjunction of SQL LIKE terms, with the backend's existing semantics;
`notEquals` terms exclude rows whose stored cell is the value (`IS NOT`), so
NULL is a value like any other. -/
structure Selection where
  relation : String
  equals : Fields
  likeAny : List (String × String) := []
  notEquals : Fields := []
  deriving BEq

/-- Literal values or columns of the selected source row, never SQL text. -/
inductive SourceValue where
  | literal (value : Cell)
  | column (name : String)
  deriving BEq

/-- Raw operations not requiring application-prepared rows. Snapshot reads
release their connection scope when the statement finishes. Transactional
mutations use the token established by Storage.begin. Bulk transfer and delete
are each one statement, not a host scan followed by per-row callbacks. -/
inductive Access : Type → Type where
  | snapshot (selection : Selection) (columns : List String) : Access (Reply Scan)
  /-- A snapshot of the rows the selection admits and no exclusion matches:
  each exclusion is the same correlated `NOT EXISTS` a delete's blockers
  evaluate, in the same statement as the selection. -/
  | snapshotExcluding (selection : Selection) (columns : List String)
      (excluding : List Exclusion) : Access (Reply Scan)
  | update (tx : Transaction) (selection : Selection) (values : Fields) : Access (Reply Nat)
  /-- Atomic INSERT SELECT with ON CONFLICT on these columns DO NOTHING.
  Existing rows retain every field; no replacement/update is permitted. -/
  | copyRows (tx : Transaction) (target : String) (source : Selection)
      (values : List (String × SourceValue)) (conflicts : List String) : Access (Reply Nat)
  | delete (tx : Transaction) (selection : Selection) : Access (Reply Nat)

/-- Generic I/O classification alongside the opaque original error. -/
inductive FileFailureKind where
  | missing | shortRead | other
  deriving BEq, DecidableEq

structure FileFailure where
  failure : Failure
  kind : FileFailureKind
  deriving BEq, DecidableEq

abbrev FileReply (A : Type) := Except FileFailure A

/-- One opened object remains the same file across positioned reads.
Close consumes the handle; abandonment must release it through host RAII.
Successful `readAt` replies contain exactly the requested byte count.
`transfer` appends exactly `count` bytes read at `offset` to the
invocation's private output buffer without routing them through the
program: the bytes never become a Lean value. A short file is a `shortRead`
failure that leaves the buffer as it was. -/
inductive FileIO : Type → Type where
  | open (space : String) (key : ByteArray) : FileIO (FileReply UInt64)
  | readAt (handle offset count : UInt64) : FileIO (FileReply ByteArray)
  | transfer (handle offset count : UInt64) : FileIO (FileReply Unit)
  | close (handle : UInt64) : FileIO (Reply Unit)

inductive Clock : Type → Type where
  | nowNs : Clock (Reply Int64)

/-- Append to one invocation-private result buffer. The host keeps this buffer
unpublished until the command terminates successfully, and discards it on any
failure or abandonment. This is raw byte storage, not CAS read policy; bytes
of an opened file reach the same buffer through `FileIO.transfer`. -/
inductive Output : Type → Type where
  | append (bytes : ByteArray) : Output (Reply Unit)

end VerifiedCore.Host
