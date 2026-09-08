import Lean
import VerifiedCore.Host
import VerifiedCore.Crypto
import VerifiedCore.Host.Access
import VerifiedCore.Host.Construct
import VerifiedCore.Host.Upsert
import VerifiedCore.Host.Resources
import VerifiedCore.Host.Source
import VerifiedCore.Host.Digest
import VerifiedCore.Host.Bao
import VerifiedCore.Host.Sweep
import VerifiedCore.Host.Memo
import VerifiedCore.Host.Walk
import VerifiedCore.Host.Peer
import VerifiedCore.Host.Provider
import VerifiedCore.Host.CacheIO
import VerifiedCore.Host.Writes
import VerifiedCore.Commands

/-! `hostgen` reads the executable core's effect algebras and command types
and prints the two sides of the host boundary from them: the Lean request
encoders, reply decoders and command codecs (`VerifiedCore/Host/Generated.lean`,
`VerifiedCore/Commands/Generated.lean`, kept in the tree) and the Rust frames,
decoder, dispatch, host traits, mirrored types, external-wait conversions
and test-double stubs
(`generated.rs`, printed into Cargo's output directory by `build.rs`). Wire
tags, effect routing and public API name mappings are explicit; shapes come
from the Lean inductives and operation types. Run it after changing an algebra
or a command type; `build.rs` and CI run it with `--check`. -/
open Lean Meta

namespace Hostgen

/-- The raw types that cross the boundary. -/
inductive Ty where
  | u64 | nat | int64 | string | bytes | bool | unit
  | cell | order | join | exclusion | selection | sourceValue | conflictValue | scan | syncStatus
  | list (t : Ty) | prod (a b : Ty) | option (t : Ty)
  /-- A message type declared in Lean and mirrored in Rust under `rust`. -/
  | message (rust : String) (lean : Name)
  deriving BEq, Repr

inductive Wrapper where
  | reply | fileReply
  deriving BEq

structure Field where
  name : String
  ty : Ty

structure Ctor where
  short : String
  full : Name
  doc : Option String
  fields : Array Field
  wrapper : Wrapper
  result : Ty
  tag : Nat

structure Algebra where
  short : String
  full : Name
  doc : Option String
  ctors : Array Ctor

/-- Where a Rust frame is served: by the relational host, by an optional
capability, an external wait, or by hand in the interpreter loop. -/
inductive Route where
  | storage
  | capability (field trait : String)
  | external
  | special

def algebras : List Name := [
  ``VerifiedCore.Host.Storage, ``VerifiedCore.Host.Crypto, ``VerifiedCore.Host.Access,
  ``VerifiedCore.Host.Unicode,
  ``VerifiedCore.Host.FileIO, ``VerifiedCore.Host.Clock, ``VerifiedCore.Host.Output,
  ``VerifiedCore.Host.Construct, ``VerifiedCore.Host.Upsert, ``VerifiedCore.Host.Resources,
  ``VerifiedCore.Host.Lease, ``VerifiedCore.Host.SourceIO, ``VerifiedCore.Host.Digest,
  ``VerifiedCore.Host.ByteWrites, ``VerifiedCore.Host.Bao, ``VerifiedCore.Host.Sweep,
  ``VerifiedCore.Host.Memo, ``VerifiedCore.Host.Redaction, ``VerifiedCore.Host.Apply,
  ``VerifiedCore.Host.Peer, ``VerifiedCore.Host.Provider, ``VerifiedCore.Host.CacheIO]

/-- The types that cross the command boundary: what a caller asks for and
what a finished command reports. Each gets Lean `Encode`/`Decode` instances
and a Rust mirror with the same codecs; order is by dependency. -/
def messages : List Name := [
  ``VerifiedCore.Host.Probed, ``VerifiedCore.Host.ProviderProbed,
  ``VerifiedCore.Replication.Exchange.Advertised,
  ``VerifiedCore.Replication.Exchange.ExchangePlan,
  ``VerifiedCore.Replication.Contact.ContactPlan,
  ``VerifiedCore.Cas.Codec.CellType, ``VerifiedCore.Cas.PinHolder, ``VerifiedCore.Cas.Input.Kind,
  ``VerifiedCore.Cas.Outcome, ``VerifiedCore.Origin.Error,
  ``VerifiedCore.Origin.Named, ``VerifiedCore.Origin.Parsed, ``VerifiedCore.Trie.LookupError,
  ``VerifiedCore.Replication.Head, ``VerifiedCore.Replication.Acceptance,
  ``VerifiedCore.Replication.Promotion,
  ``VerifiedCore.Trie.Value, ``VerifiedCore.Trie.Diff.Change, ``VerifiedCore.Trie.Proof.Proof,
  ``VerifiedCore.Trie.Refusal, ``VerifiedCore.Trie.Verdict, ``VerifiedCore.Trie.MutationError,
  ``VerifiedCore.Trie.Proof.VerifyError,
  ``VerifiedCore.Cas.Receive.ProvenSubtree, ``VerifiedCore.Cas.Project.Blob,
  ``VerifiedCore.Cas.Project.Summary, ``VerifiedCore.Cas.Project.Pin,
  ``VerifiedCore.Trie.Serve.NodeAnswer, ``VerifiedCore.Trie.Serve.ValueAnswer,
  ``VerifiedCore.Commands.LifecycleDomainError, ``VerifiedCore.Commands.IngestDomainError,
  ``VerifiedCore.Commands.ReadDomainError, ``VerifiedCore.Commands.HistoryDomainError,
  ``VerifiedCore.Commands.DurableDomainError, ``VerifiedCore.Commands.ServeDomainError,
  ``VerifiedCore.Commands.ReceiveDomainError, ``VerifiedCore.Commands.CollectDomainError,
  ``VerifiedCore.Commands.ProjectDomainError, ``VerifiedCore.Commands.CloudDomainError, ``VerifiedCore.Commands.TrieServeDomainError,
  ``VerifiedCore.Commands.TrieCollectDomainError, ``VerifiedCore.Commands.TrieWalkDomainError,
  ``VerifiedCore.Commands.TrieMissingDomainError,
  ``VerifiedCore.Commands.TrieFetchDomainError,
  ``VerifiedCore.Commands.ReconcileDomainError, ``VerifiedCore.Commands.PromotionReport,
  ``VerifiedCore.Commands.FetchReport,
  ``VerifiedCore.Trie.Serve.Scope,
  ``VerifiedCore.Authorization.Source, ``VerifiedCore.Authorization.Binding,
  ``VerifiedCore.Authorization.PublishScope, ``VerifiedCore.Authorization.PeerAuthority,
  ``VerifiedCore.Authorization.OriginAuthority, ``VerifiedCore.Authorization.BindingSelection,
  ``VerifiedCore.Authorization.BindingStatus, ``VerifiedCore.Authorization.SocketAuthority,
  ``VerifiedCore.Authorization.LocalAuthority, ``VerifiedCore.Authorization.MetadataRefusal,
  ``VerifiedCore.Commands.AuthorizationDomainError,
  ``VerifiedCore.Commands.Ingested, ``VerifiedCore.Commands.Committed, ``VerifiedCore.Commands.Served,
  ``VerifiedCore.Commands.Evicted, ``VerifiedCore.Commands.Collected, ``VerifiedCore.Commands.Command]

/-- Rust spellings that differ from the Lean short name. -/
def rustName (name : Name) : String :=
  match name with
  | ``VerifiedCore.Trie.Serve.Scope => "AuthorizationTrieScope"
  | ``VerifiedCore.Authorization.Source => "AuthorizationSource"
  | ``VerifiedCore.Authorization.Binding => "AuthorizationBinding"
  | ``VerifiedCore.Authorization.PublishScope => "AuthorizationPublishScope"
  | ``VerifiedCore.Cas.Input.Kind => "IngestInput"
  | ``VerifiedCore.Origin.Error => "OriginError"
  | ``VerifiedCore.Origin.Named => "NamedOrigin"
  | ``VerifiedCore.Origin.Parsed => "ParsedOrigin"
  | ``VerifiedCore.Trie.LookupError => "LookupDomainError"
  | ``VerifiedCore.Trie.Refusal => "NodeRefusal"
  | ``VerifiedCore.Trie.Verdict => "NodeVerdict"
  | ``VerifiedCore.Trie.MutationError => "MutationDomainError"
  | ``VerifiedCore.Cas.Project.Blob => "ProjectedBlob"
  | ``VerifiedCore.Cas.Project.Summary => "ProjectedSummary"
  | ``VerifiedCore.Cas.Project.Pin => "ProjectedPin"
  | ``VerifiedCore.Trie.Value => "TrieValue"
  | ``VerifiedCore.Trie.Diff.Change => "TrieChange"
  | ``VerifiedCore.Trie.Proof.Proof => "TrieProof"
  | ``VerifiedCore.Trie.Proof.VerifyError => "ProofVerifyError"
  | _ => name.getString!

/-- The private transport's tags. Numbering is historical, so it is a table
rather than declaration order; every constructor of every algebra must have
exactly one, and the generator refuses to run otherwise. -/
def tags : List (String × Nat) := [
  ("Storage.begin", 16), ("Storage.commit", 17), ("Storage.rollback", 18),
  ("Storage.readRows", 19), ("Storage.upsert", 20), ("Storage.deleteRows", 21),
  ("Storage.readBytes", 22), ("Storage.readInput", 23), ("Storage.readCounter", 24),
  ("Storage.removeFile", 25), ("Storage.existsRows", 26), ("Storage.scanRows", 28),
  ("Crypto.validateEd25519", 27),
  ("Crypto.verifyEd25519", 89),
  ("Unicode.isNfc", 90),
  ("Access.snapshot", 29), ("Access.update", 30), ("Access.copyRows", 31), ("Access.delete", 32),
  ("FileIO.open", 33), ("FileIO.readAt", 34), ("FileIO.close", 35), ("FileIO.transfer", 52),
  ("Clock.nowNs", 36), ("Output.append", 37),
  ("Construct.build", 38), ("Construct.hash", 39),
  ("Upsert.write", 41),
  ("Resources.createTemporary", 42), ("Resources.flush", 43), ("Resources.replace", 44),
  ("Resources.discard", 45), ("Resources.syncParent", 46),
  ("Lease.acquire", 47), ("Lease.release", 48),
  ("SourceIO.stat", 49), ("SourceIO.readSome", 50), ("SourceIO.freeze", 51),
  ("Digest.blake3", 53), ("ByteWrites.putBytes", 54),
  ("Bao.encodeSlice", 55), ("Bao.encodeProof", 56), ("Bao.decodeInline", 57),
  ("Bao.decodeSlice", 58), ("Bao.flushObject", 59), ("Bao.trimObject", 60),
  ("Bao.writeProof", 61), ("Bao.promoteRun", 62),
  ("Lease.order", 63), ("Access.snapshotExcluding", 64),
  ("Sweep.fileBytes", 65), ("Sweep.fileModified", 66), ("Sweep.listObjects", 67),
  ("Storage.deleteExcept", 68), ("Memo.forgetExcept", 69),
  ("Redaction.isRedacted", 70), ("Apply.applyChange", 71),
  ("Peer.fetchNodes", 72), ("Peer.fetchValues", 73),
  ("Memo.isKnown", 74), ("Memo.generation", 75), ("Memo.certify", 76),
  ("Provider.stat", 77), ("Provider.readAll", 78), ("Provider.readRange", 79),
  ("CacheIO.isFile", 80), ("CacheIO.writeAt", 81), ("CacheIO.flush", 82),
  ("CacheIO.writeTemporary", 83)]

/-- Which Rust service answers an algebra by default. -/
def defaultRoute : String → Route
  | "Storage" | "Access" | "Upsert" => .storage
  | "Crypto" => .capability "crypto" "Crypto"
  | "Unicode" => .capability "unicode" "Unicode"
  | "FileIO" => .capability "files" "FileIO"
  | "Clock" => .capability "clock" "Clock"
  | "Output" => .capability "output" "Output"
  | "Construct" => .capability "construct" "Construct"
  | "Resources" => .capability "temporary" "TemporaryFiles"
  | "Lease" => .capability "leases" "Lease"
  | "SourceIO" => .capability "source" "SourceIO"
  | "Digest" => .capability "digest" "Digest"
  | "ByteWrites" => .capability "writes" "ByteWrites"
  | "Bao" => .capability "bao" "Bao"
  | "Sweep" => .capability "sweep" "Sweep"
  | "Memo" => .capability "memo" "Memo"
  | "Redaction" => .capability "redaction" "Redaction"
  | "Apply" => .capability "apply" "Apply"
  | "CacheIO" => .capability "cache" "CacheIO"
  | "Peer" | "Provider" => .external
  | _ => .special

/-- Which Rust service each effect belongs to. The command inputs, the
transfer into the output sink and the Bao encodings that land in it are not
trait methods derived from the algebra: the interpreter loop serves them from
the run's own resources (the Bao trait's methods are written by hand below,
because they hand their bytes to the sink). -/
def route (algebra ctor : String) : Route :=
  match algebra ++ "." ++ ctor with
  | "Storage.readCounter" | "Storage.removeFile" => .capability "resources" "Resources"
  | "Storage.readInput" | "FileIO.transfer" | "Bao.encodeSlice" | "Bao.encodeProof"
  | "Bao.decodeInline" | "Bao.decodeSlice" | "Bao.writeProof" => .special
  | _ => defaultRoute algebra

/-- Effects the interpreter loop dispatches by hand even though their service
is a trait: the sink append carries the interpreter's own error type. -/
def handledByLoop : List String := ["Output.append"]

/-- Rust-side contract text that has no Lean counterpart, per trait. -/
def traitDoc : String → String
  | "Storage" => "/// The relational host: transactions, raw projections, mutations and byte\n/// reads. The interpreter executes requests literally; algorithms, metadata\n/// interpretation and operation sequencing remain in Lean.\n///\n/// Transaction handles are local to one interpreter session. A failed commit\n/// does not acknowledge success. Dropping a session must release its resources\n/// and roll back any transaction it still owns."
  | "Resources" => "/// Non-transactional raw resources, separate from the relational capability.\n/// Callers retain any required ordering guards for the entire operation."
  | "FileIO" => "/// Session-local raw file handles. Dropping the host releases outstanding handles."
  | "Output" => "/// Operation-local byte sink. Appended bytes are provisional until the whole\n/// operation succeeds; the caller discards the sink on failure."
  | "TemporaryFiles" => "/// Invocation-owned staging resources. Abandonment releases handles and\n/// removes unpublished temporary names; replacement consumes temporary ownership."
  | "Lease" => "/// Opaque counted resource leases ordered against competing deletion, and\n/// the remover's critical section they are ordered against. Host abandonment\n/// releases outstanding tokens; policy chooses their lifetime."
  | "Sweep" => "/// The object store as a directory: what each object's files cost on disk,\n/// when they were written, and which objects have files at all. The layout is\n/// this host's; what is evicted, collected or unlinked is the operation's."
  | "Redaction" => "/// The refusals a peer recorded: whether this store may see a node at a\n/// position, or at any. What a walk does with a refused position is the\n/// operation's."
  | "Apply" => "/// The materializer of a head promotion: takes each change as the walk\n/// finds it, in walk order, inside the transaction the flip runs in. A\n/// refusal is this host's failure and stops the walk."
  | "Memo" => "/// The completeness memo. Forgetting is bound to the mutating transaction as\n/// a lease is: certification stays disabled until that transaction's edge,\n/// commit or rollback, so a reader that started before the mutation cannot\n/// certify its stale snapshot afterwards."
  | "SourceIO" => "/// Raw input observations. Successful bounded reads may be short at EOF;\n/// freeze retains an immutable copy under an invocation-owned input handle."
  | "Construct" => "/// Bulk object construction over resources the requesting operation owns.\n///\n/// The operation decides what is built, from which opened source and into\n/// which owned temporaries; the host streams the bytes, hashes them into the\n/// BLAKE3 tree and lays out the Bao outboard. Neither call publishes, flushes\n/// or records anything."
  | "Clock" => "/// Wall-clock input; the operation chooses when to observe it."
  | "Crypto" => "/// Primitive cryptography, separate from storage and domain validation."
  | "Digest" => "/// Primitive hashing of exactly the bytes the operation supplies, domain tag\n/// included. What is hashed and what a digest's equality means are the\n/// operation's decisions."
  | "ByteWrites" => "/// Raw content-addressed writes: the operation names the namespace, the\n/// address and the bytes, and has proved the address covers them."
  | "Bao" => "/// The Bao tree as a service: slice and proof encodings of exactly the group\n/// spans the operation names, which it has read from the row's own record.\n/// The tree, its chaining values and both formats are a trust assumption on\n/// `bao-tree`/`blake3`; the interpreter appends what is encoded to the\n/// operation's output sink, so a served window is never a Lean value."
  | _ => ""

/-- Trait methods the interpreter needs beyond the algebra's effects. -/
def traitExtras : String → String
  | "FileIO" => "    /// Fill `buffer` from `offset`, returning `ShortRead` at EOF. The\n    /// interpreter hands over the tail of the operation's output sink, so a\n    /// transfer costs one read into the bytes the caller receives.\n    fn read_into(\n        &mut self,\n        handle: u64,\n        offset: u64,\n        buffer: &mut [u8],\n    ) -> Result<(), FileFailure<Self::Error>>;\n"
  | "Bao" => "    /// Encode the Bao slice of exactly these half-open group spans of the\n    /// object, from its inline bytes or its payload and outboard files,\n    /// validating the local copy against the root.\n    fn encode_slice(\n        &mut self,\n        root: &[u8],\n        size: u64,\n        inline: Option<&[u8]>,\n        spans: &[(u64, u64)],\n    ) -> Result<Vec<u8>, Self::Error>;\n    /// Encode the interior tree nodes over these group spans, no deeper than\n    /// `level`, or answer `None` when the walk would exceed `budget` nodes.\n    fn encode_proof(\n        &mut self,\n        root: &[u8],\n        size: u64,\n        spans: &[(u64, u64)],\n        level: u64,\n        budget: u64,\n    ) -> Result<Option<Vec<u8>>, Self::Error>;\n    /// Decode `input`, a slice of exactly these spans, against the root into\n    /// the object's inline buffer: `inline` when the row already holds one,\n    /// otherwise zeroes, filled out to `size`. A slice that does not verify\n    /// is this host's failure.\n    fn decode_inline(\n        &mut self,\n        root: &[u8],\n        size: u64,\n        inline: Option<&[u8]>,\n        spans: &[(u64, u64)],\n        input: &[u8],\n    ) -> Result<Vec<u8>, Self::Error>;\n    /// Decode `input`, a slice of exactly these spans, against the root into\n    /// the object's payload and outboard files, created as needed, grown only\n    /// as verified groups land and never shrunk, left unflushed.\n    fn decode_slice(\n        &mut self,\n        root: &[u8],\n        size: u64,\n        spans: &[(u64, u64)],\n        input: &[u8],\n    ) -> Result<(), Self::Error>;\n    /// Verify the run's byte input `input`, a proof over these spans no deeper\n    /// than `level`, by recomputation up to the root, and write its interior\n    /// nodes into the outboard as far as they reach, unflushed. Answers\n    /// whether any node was written and the subtrees proven: start, groups,\n    /// chaining value, whole.\n    fn write_proof(\n        &mut self,\n        root: &[u8],\n        size: u64,\n        spans: &[(u64, u64)],\n        level: u64,\n        input: &[u8],\n    ) -> Result<(bool, Vec<(u64, u64, Vec<u8>, bool)>), Self::Error>;\n"
  | "Output" => "    /// Extend the sink by `count` bytes and hand them back for an in-place\n    /// fill, so a file transfer lands directly in the result.\n    fn grow(&mut self, count: u64) -> Result<&mut [u8], Self::Error>;\n    /// Take back the last `count` bytes after a fill failed.\n    fn shrink(&mut self, count: u64);\n"
  | _ => ""

def traitOrder : List String :=
  ["Storage", "Resources", "Crypto", "Unicode", "FileIO", "Clock", "Output", "Construct", "TemporaryFiles", "CacheIO",
    "Lease", "SourceIO", "Digest", "ByteWrites", "Bao", "Sweep", "Memo", "Redaction", "Apply"]

def baseTy : Name → Option Ty
  | ``UInt64 | ``VerifiedCore.Host.Transaction => some .u64
  | ``Nat => some .nat
  | ``Int64 => some .int64
  | ``String => some .string
  | ``ByteArray => some .bytes
  | ``Bool => some .bool
  | ``Unit | ``PUnit => some .unit
  | ``VerifiedCore.Host.Cell => some .cell
  | ``VerifiedCore.Host.Row => some (.list .cell)
  | ``VerifiedCore.Host.Fields => some (.list (.prod .string .cell))
  | ``VerifiedCore.Host.Order => some .order
  | ``VerifiedCore.Host.Join => some .join
  | ``VerifiedCore.Host.Exclusion => some .exclusion
  | ``VerifiedCore.Host.Selection => some .selection
  | ``VerifiedCore.Host.SourceValue => some .sourceValue
  | ``VerifiedCore.Host.ConflictValue => some .conflictValue
  | ``VerifiedCore.Host.Scan => some .scan
  | ``VerifiedCore.Host.SyncStatus => some .syncStatus
  | _ => none

partial def parseTy (e : Expr) : MetaM Ty := do
  let e ← instantiateMVars e
  -- A defaulted binder is the same field on the wire.
  if e.isAppOfArity ``optParam 2 then return ← parseTy e.appFn!.appArg!
  match e.getAppFn, e.getAppArgs with
  | .const n _, #[] =>
    match baseTy n with
    | some t => return t
    | none =>
      if messages.contains n then return .message (rustName n) n
      throwError "hostgen: no wire representation for {n}"
  | .const ``List _, #[t] => do
    -- Raw key octets are one length-prefixed field, like a byte array.
    if t.isConstOf ``UInt8 then return .bytes
    let inner ← parseTy t
    if inner == .nat then throwError "hostgen: lists of Nat do not cross the boundary"
    return .list inner
  | .const ``Prod _, #[a, b] => return .prod (← parseTy a) (← parseTy b)
  | .const ``Option _, #[t] => return .option (← parseTy t)
  | _, _ => throwError "hostgen: no wire representation for {e}"

def snake (name : String) : String := Id.run do
  let mut out := ""
  for c in name.toList do
    if c.isUpper then out := out ++ "_" ++ toString c.toLower else out := out.push c
  return out

def pascal (name : String) : String :=
  match name.toList with
  | c :: rest => String.ofList (c.toUpper :: rest)
  | [] => name

def readAlgebra (name : Name) : MetaM Algebra := do
  let env ← getEnv
  let info ← getConstInfoInduct name
  let short := name.getString!
  let mut ctors : Array Ctor := #[]
  for ctorName in info.ctors do
    let ctor ← getConstInfoCtor ctorName
    let ctorShort := ctorName.getString!
    let key := short ++ "." ++ ctorShort
    let some tag := tags.lookup key
      | throwError "hostgen: {key} has no wire tag"
    let (fields, wrapper, result) ← forallTelescope ctor.type fun xs body => do
      let mut fields : Array Field := #[]
      for x in xs[ctor.numParams:] do
        let decl ← x.fvarId!.getDecl
        if decl.binderInfo.isExplicit then
          let ty ← parseTy decl.type
          fields := fields.push { name := decl.userName.getString!, ty := ty }
      let index := body.getAppArgs.back!
      let wrapper ← match index.getAppFn with
        | .const ``VerifiedCore.Host.Reply _ => pure Wrapper.reply
        | .const ``VerifiedCore.Host.FileReply _ => pure Wrapper.fileReply
        | _ => throwError "hostgen: {ctorName} does not reply with Reply or FileReply"
      let result ← parseTy index.getAppArgs.back!
      return (fields, wrapper, result)
    let doc ← findDocString? env ctorName
    let entry : Ctor := { short := ctorShort, full := ctorName, doc, fields, wrapper, result, tag }
    ctors := ctors.push entry
  let doc ← findDocString? env name
  let algebra : Algebra := { short, full := name, doc, ctors }
  return algebra

def checkTags (all : Array Algebra) : MetaM Unit := do
  let mut seen : List Nat := []
  let mut keys : List String := []
  for algebra in all do
    for ctor in algebra.ctors do
      if seen.contains ctor.tag then throwError "hostgen: tag {ctor.tag} is used twice"
      seen := ctor.tag :: seen
      keys := (algebra.short ++ "." ++ ctor.short) :: keys
  for (key, _) in tags do
    unless keys.contains key do throwError "hostgen: tag table names unknown effect {key}"

/-! ## Lean output -/

def leanPattern (ctor : Ctor) (bind : Bool) : String :=
  let fields := ctor.fields.toList.zipIdx.map fun (_, i) => if bind then s!"a{i}" else "_"
  String.intercalate " " (("." ++ ctor.short) :: fields)

def leanAlgebra (algebra : Algebra) : String := Id.run do
  let name := algebra.short
  let mut out := s!"def {name}.tag : {name} A → UInt8\n"
  for ctor in algebra.ctors do
    out := out ++ s!"  | {leanPattern ctor false} => {ctor.tag}\n"
  out := out ++ s!"\ndef {name}.name : {name} A → String\n"
  for ctor in algebra.ctors do
    out := out ++ s!"  | {leanPattern ctor false} => \"{ctor.short}\"\n"
  out := out ++ s!"\ndef {name}.request : {name} A → ByteArray\n"
  for ctor in algebra.ctors do
    let body := ctor.fields.toList.zipIdx.foldl
      (fun acc (_, i) => s!"{acc} |>.put a{i}") s!"header {ctor.tag}"
    out := out ++ s!"  | {leanPattern ctor true} => {body}\n"
  out := out ++ s!"\ndef {name}.reply (effect : {name} A) (input : ByteArray) : A :=\n  match effect with\n"
  for ctor in algebra.ctors do
    let decoder := match ctor.wrapper with
      | .reply => "decodeReply"
      | .fileReply => "decodeFileReply"
    out := out ++ s!"  | {leanPattern ctor false} => {decoder} {ctor.tag} Decode.decode input\n"
  out := out ++ s!"\ninstance : WireEffect {name} := ⟨{name}.request, {name}.reply⟩\n"
  return out

def leanFile (all : Array Algebra) : String := Id.run do
  let mut out := "import VerifiedCore.Host.Codec\nimport VerifiedCore.Crypto\nimport VerifiedCore.Host.Construct\nimport VerifiedCore.Host.Source\nimport VerifiedCore.Host.Digest\nimport VerifiedCore.Host.Writes\nimport VerifiedCore.Host.Bao\nimport VerifiedCore.Host.Sweep\nimport VerifiedCore.Host.Memo\nimport VerifiedCore.Host.Walk\nimport VerifiedCore.Host.Peer\nimport VerifiedCore.Host.Provider\nimport VerifiedCore.Host.CacheIO\n\n"
  out := out ++ "/-! GENERATED by `hostgen` from the effect algebras; do not edit. Each\nalgebra's tags, names, request encoder, reply decoder and `WireEffect`\ninstance follow from its constructors and the tag table. -/\nnamespace VerifiedCore.Host\nopen Wire\n"
  for algebra in all do
    out := out ++ "\n" ++ leanAlgebra algebra
  return out ++ "\nend VerifiedCore.Host\n"

/-! ## Rust output -/

/-- The owned type a decoded frame holds; bytes stay borrowed from the packet. -/
partial def rustOwned : Ty → String
  | .u64 => "u64"
  | .nat => "u64"
  | .int64 => "i64"
  | .string => "String"
  | .bytes => "&'a [u8]"
  | .bool => "bool"
  | .unit => "()"
  | .cell => "Cell"
  | .order => "Order"
  | .join => "Join"
  | .exclusion => "Exclusion"
  | .selection => "Selection"
  | .sourceValue => "SourceValue"
  | .conflictValue => "ConflictValue"
  | .scan => "Scan<E>"
  | .syncStatus => "SyncStatus"
  | .list (.prod .string .cell) => "Fields"
  | .list .u64 => "Vec<u64>"
  | .list t => s!"Vec<{rustOwned t}>"
  | .prod a b => s!"({rustOwned a}, {rustOwned b})"
  | .option t => s!"Option<{rustOwned t}>"
  | .message rust _ => rust

/-- Bytes are one field on the wire and one slice in Rust. -/
def rustFrameTy : Ty → String
  | .list .bytes => "Vec<&'a [u8]>"
  | t => rustOwned t

/-- How a trait receives an argument. -/
def rustParamTy : Ty → String
  | .u64 => "u64"
  | .bool => "bool"
  | .string => "&str"
  | .bytes => "&[u8]"
  | .option .bytes => "Option<&[u8]>"
  | .list .bytes => "&[&[u8]]"
  | .list (.prod .string .cell) => "&Fields"
  | .list t => s!"&[{rustOwned t}]"
  | .selection => "&Selection"
  | t => s!"&{rustOwned t}"

/-- What a trait returns, with the host error threaded through scans. -/
def rustResultTy : Ty → String
  | .scan => "Scan<Self::Error>"
  | .bytes => "Vec<u8>"
  | .option .bytes => "Option<Vec<u8>>"
  | .list .cell => "Row"
  | .list (.list .cell) => "Vec<Row>"
  | t => rustOwned t

/-- Passing a frame field to a trait method. -/
def rustArg (index : Nat) : Ty → String
  | .u64 | .bool | .bytes | .option .bytes => s!"a{index}"
  | _ => s!"&a{index}"

/-- Reading one field out of a request packet. -/
partial def rustDecoder : Ty → String
  | .u64 => "r.word()?"
  | .string => "r.string()?"
  | .bytes => "r.byte_slice()?"
  | .bool => "r.boolean()?"
  | .cell => "r.cell()?"
  | .order => "r.order()?"
  | .join => "r.join()?"
  | .exclusion => "r.exclusion()?"
  | .selection => "r.selection()?"
  | .sourceValue => "r.source_value()?"
  | .conflictValue => "r.conflict_value()?"
  | .list (.prod .string .cell) => "r.fields()?"
  | .list (.prod .string .conflictValue) => "r.assignments()?"
  | .list t =>
    let inner := rustDecoder t
    -- A plain reader method is passed by name; clippy rejects `|r| Ok(x?)`.
    if inner.startsWith "r." && inner.endsWith "()?" then
      s!"r.list(Reader::{((inner.drop 2).dropEnd 3).toString})?"
    else s!"r.list(|r| Ok({inner}))?"
  | .prod a b => s!"({rustDecoder a}, {rustDecoder b})"
  | .option t =>
    let inner := rustDecoder t
    if inner.startsWith "r." && inner.endsWith "()?" then
      s!"r.option(Reader::{((inner.drop 2).dropEnd 3).toString})?"
    else s!"r.option(|r| Ok({inner}))?"
  | t => panic! s!"hostgen: no request decoder for {repr t}"

def rustTypeAll (all : Array Algebra) (route : Algebra → Ctor → Route) : List (String × Array (Algebra × Ctor)) := Id.run do
  let mut groups : List (String × Array (Algebra × Ctor)) := traitOrder.map fun t => (t, #[])
  for algebra in all do
    for ctor in algebra.ctors do
      let trait := match route algebra ctor with
        | .storage => some "Storage"
        | .capability _ trait => some trait
        | .external | .special => none
      if let some trait := trait then
        groups := groups.map fun (name, members) =>
          if name == trait then (name, members.push (algebra, ctor)) else (name, members)
  return groups

def docLines (indent : String) (doc : Option String) : String :=
  match doc with
  | none => ""
  | some doc => String.intercalate "" ((doc.trimAsciiEnd.toString.splitOn "\n").map fun line =>
      indent ++ "/// " ++ line.trimAsciiEnd.toString ++ "\n")

def rustMethod (ctor : Ctor) : String := Id.run do
  let params := ctor.fields.toList.map fun field => s!"{snake field.name}: {rustParamTy field.ty}"
  let result := match ctor.wrapper with
    | .reply => s!"Result<{rustResultTy ctor.result}, Self::Error>"
    | .fileReply => s!"Result<{rustResultTy ctor.result}, FileFailure<Self::Error>>"
  let signature := s!"fn {snake ctor.short}(&mut self{String.join (params.map (", " ++ ·))}) -> {result}"
  docLines "    " ctor.doc ++ s!"    {signature};\n"

def rustTraits (all : Array Algebra) : String := Id.run do
  let mut out := ""
  for (trait, members) in rustTypeAll all (fun a c => route a.short c.short) do
    out := out ++ traitDoc trait ++ "\n#[allow(clippy::too_many_arguments, clippy::type_complexity)]\n" ++ s!"pub trait {trait} \{\n"
    out := out ++ "    /// Original host error, retained without converting it into a policy result.\n    type Error;\n"
    for (_, ctor) in members do
      out := out ++ rustMethod ctor
    out := out ++ traitExtras trait ++ "}\n\n"
  -- A narrowed view of the existing snapshot effect, for byte-backed
  -- callers that cannot open transactions or mutate relational storage.
  -- Its signature still comes from the algebra, never a second schema.
  out := out ++ "/// Raw row snapshots without transaction or mutation capabilities. The\n/// supplied view may already be inside a caller-owned transaction.\npub trait Snapshots {\n    type Error;\n"
  for algebra in all do
    for ctor in algebra.ctors do
      if algebra.short == "Access" && ctor.short == "snapshot" then
        out := out ++ rustMethod ctor
  out := out ++ "}\n\n"
  return out

def rustUnexpected (all : Array Algebra) : String := Id.run do
  let mut out := "/// Fills a test double's `impl` with the host methods the operation under\n/// test never requests; each panics with its name if it is reached.\n#[macro_export]\nmacro_rules! host_unexpected {\n"
  for (_, members) in rustTypeAll all (fun a c => route a.short c.short) do
    for (_, ctor) in members do
      let params := ctor.fields.toList.map fun field => s!"_: {rustParamTy field.ty}"
      let result := match ctor.wrapper with
        | .reply => s!"Result<{rustResultTy ctor.result}, Self::Error>"
        | .fileReply => s!"Result<{rustResultTy ctor.result}, $crate::host::FileFailure<Self::Error>>"
      let params := String.join (params.map (", " ++ ·))
      out := out ++ s!"    ({snake ctor.short}) => \{\n        fn {snake ctor.short}(&mut self{params}) -> {result} \{\n            panic!(\"unexpected {snake ctor.short}\")\n        }\n    };\n"
  -- The macro is defined by `include!`, so the crate itself may only name it
  -- textually, never by path: the list arm recurses by bare name, and a
  -- caller in another crate brings the name into scope with `use`.
  out := out ++ "    ($($method:ident),+ $(,)?) => {\n        $(host_unexpected!($method);)+\n    };\n}\n"
  -- Trait names in the macro must be absolute for external test crates.
  return out.replace "Result<Scan<Self::Error>" "Result<$crate::host::Scan<Self::Error>"
    |>.replace "&Fields" "&$crate::host::Fields" |>.replace "&Selection" "&$crate::host::Selection"
    |>.replace "&[Order]" "&[$crate::host::Order]" |>.replace "&[Join]" "&[$crate::host::Join]"
    |>.replace "&[Exclusion]" "&[$crate::host::Exclusion]"
    |>.replace "&[(String, SourceValue)]" "&[(String, $crate::host::SourceValue)]"
    |>.replace "&[(String, ConflictValue)]" "&[(String, $crate::host::ConflictValue)]"
    |>.replace "Result<Vec<Row>" "Result<Vec<$crate::host::Row>"
    |>.replace "Result<SyncStatus" "Result<$crate::host::SyncStatus"

/-- Preserve existing frame spellings while distinguishing raw provider/cache methods. -/
def frameName (algebra : Algebra) (ctor : Ctor) : String :=
  (if algebra.short == "Provider" then "Provider"
    else if algebra.short == "CacheIO" then "Cache" else "") ++ pascal ctor.short

def rustFrames (all : Array Algebra) : String := Id.run do
  let mut out := "/// One decoded request packet. Terminal packets carry the operation's\n/// result or failure; every other frame is one effect of one algebra.\n#[derive(Debug)]\npub(crate) enum Frame<'a> {\n    Done(&'a [u8]),\n    Failure(u64, u64),\n"
  for algebra in all do
    for ctor in algebra.ctors do
      let fields := ctor.fields.toList.map fun field => rustFrameTy field.ty
      out := out ++ s!"    {frameName algebra ctor}" ++
        (if fields.isEmpty then "" else s!"({String.intercalate ", " fields})") ++ ",\n"
  out := out ++ "}\n\n"
  out := out ++ "pub(crate) fn decode(packet: &[u8]) -> Result<Frame<'_>, ()> {\n    let mut r = Reader(packet);\n    if r.byte()? != 1 {\n        return Err(());\n    }\n    let frame = match r.byte()? {\n        0 => Frame::Done(r.byte_slice()?),\n        1 => Frame::Failure(r.word()?, r.word()?),\n"
  for algebra in all do
    for ctor in algebra.ctors do
      let fields := ctor.fields.toList.map fun field => rustDecoder field.ty
      out := out ++ s!"        {ctor.tag} => Frame::{frameName algebra ctor}" ++
        (if fields.isEmpty then "" else s!"({String.intercalate ", " fields})") ++ ",\n"
  out := out ++ "        _ => return Err(()),\n    };\n    r.end()?;\n    Ok(frame)\n}\n\n"
  return out

def rustDispatch (all : Array Algebra) : String := Id.run do
  let mut out := "/// Serve one effect frame with the host it routes to. Terminal frames and\n/// the effects the interpreter loop serves itself are refused here.\npub(crate) fn dispatch<S: Storage>(\n    storage: &mut S,\n    capabilities: &mut Capabilities<'_, S::Error>,\n    frame: Frame<'_>,\n    errors: &mut Vec<Option<S::Error>>,\n) -> Result<Vec<u8>, OperationError<S::Error>> {\n    Ok(match frame {\n"
  for algebra in all do
    for ctor in algebra.ctors do
      let binders := ctor.fields.toList.zipIdx.map fun (_, i) => s!"a{i}"
      let pattern := s!"Frame::{frameName algebra ctor}" ++
        (if binders.isEmpty then "" else s!"({String.intercalate ", " binders})")
      let args := String.intercalate ", " (ctor.fields.toList.zipIdx.map fun (field, i) => rustArg i field.ty)
      let (receiver, prelude) := match route algebra.short ctor.short with
        | .storage => ("storage", "")
        | .capability field _ =>
          ("host", s!"            let host = capabilities.{field}.as_deref_mut().ok_or(OperationError::Protocol)?;\n")
        | .external | .special => ("", "")
      if receiver.isEmpty || handledByLoop.contains (algebra.short ++ "." ++ ctor.short) then continue
      let call := s!"{receiver}.{snake ctor.short}({args})"
      let body := match ctor.wrapper, ctor.result with
        | .reply, .scan => s!"scan_reply({ctor.tag}, {call}, errors)"
        | .reply, _ => s!"reply({ctor.tag}, {call}, errors, EncodeReply::encode)"
        | .fileReply, _ => s!"file_reply({ctor.tag}, {call}, errors, EncodeReply::encode)"
      out := out ++ s!"        {pattern} => \{\n{prelude}            {body}\n        }\n"
  out := out ++ "        _ => return Err(OperationError::Protocol),\n    })\n}\n"
  return out

structure MessageCtor where
  short : String
  doc : Option String
  fields : Array Field
  deriving Inhabited

structure Message where
  full : Name
  rust : String
  doc : Option String
  isStructure : Bool
  ctors : Array MessageCtor

def readMessage (name : Name) : MetaM Message := do
  let env ← getEnv
  let info ← getConstInfoInduct name
  let mut ctors : Array MessageCtor := #[]
  for ctorName in info.ctors do
    let ctor ← getConstInfoCtor ctorName
    let fields ← forallTelescope ctor.type fun xs _ => do
      let mut fields : Array Field := #[]
      for x in xs[ctor.numParams:] do
        let decl ← x.fvarId!.getDecl
        if decl.binderInfo.isExplicit then
          let ty ← parseTy decl.type
          fields := fields.push { name := decl.userName.getString!, ty := ty }
      return fields
    let doc ← findDocString? env ctorName
    ctors := ctors.push { short := ctorName.getString!, doc, fields }
  let doc ← findDocString? env name
  let message : Message := { full := name, rust := rustName name, doc, isStructure := isStructure env name, ctors }
  return message

/-- A message's name as `Commands/Generated.lean` spells it, inside `VerifiedCore`. -/
def leanRelative (name : Name) : String :=
  toString (name.replacePrefix `VerifiedCore .anonymous)

def leanMessage (message : Message) : String := Id.run do
  let name := leanRelative message.full
  let mut out := s!"instance : Encode {name} where\n  encode out value := match value with\n"
  for ctor in message.ctors, index in [:message.ctors.size] do
    let binders := ctor.fields.toList.zipIdx.map fun (_, i) => s!"a{i}"
    let pattern := String.intercalate " " (("." ++ ctor.short) :: binders)
    let start := if message.isStructure then "out" else s!"out.push {index}"
    let body := binders.foldl (fun acc b => s!"{acc} |>.put {b}") start
    out := out ++ s!"    | {pattern} => {body}\n"
  out := out ++ s!"\ninstance : Decode {name} where\n  decode := do\n"
  if message.isStructure then
    let ctor := message.ctors[0]!
    for i in [:ctor.fields.size] do
      out := out ++ s!"    let a{i} ← Decode.decode\n"
    let args := String.intercalate " " ((List.range ctor.fields.size).map fun i => s!"a{i}")
    out := out ++ s!"    return .{ctor.short} {args}\n"
  else
    out := out ++ "    match ← readByte with\n"
    for ctor in message.ctors, index in [:message.ctors.size] do
      let args := String.intercalate "" (ctor.fields.toList.map fun _ => " (← Decode.decode)")
      out := out ++ s!"    | {index} => return .{ctor.short}{args}\n"
    out := out ++ "    | _ => throw ()\n"
  return out

def leanCommandsFile (all : Array Message) : String := Id.run do
  let mut out := "import VerifiedCore.Host.Codec\nimport VerifiedCore.Commands\n\n"
  out := out ++ "/-! GENERATED by `hostgen` from the command and outcome types; do not edit. -/\nnamespace VerifiedCore\nopen Host.Wire\n"
  for message in all do
    out := out ++ "\n" ++ leanMessage message
  return out ++ "\nend VerifiedCore\n"

/-- A message field as Rust owns it. -/
partial def rustMessageTy : Ty → String
  | .bytes => "Vec<u8>"
  | .list t => s!"Vec<{rustMessageTy t}>"
  | .prod a b => s!"({rustMessageTy a}, {rustMessageTy b})"
  | .option t => s!"Option<{rustMessageTy t}>"
  | .message rust _ => rust
  | t => rustOwned t

/-- Preserve public API names; field types and wire order come from Lean. -/
def externalVariant (ctor : Ctor) : String :=
  pascal (if ctor.short.startsWith "fetch" then (ctor.short.drop 5).toString else ctor.short)

def externalFields : String → List String
  | "Peer.fetchNodes" => ["served", "missing", "redacted"]
  | "Peer.fetchValues" => ["served", "missing"]
  | _ => []

/-- Named success fields follow the right-associated Lean product. -/
def productFields : Ty → List Ty
  | .prod a b => a :: productFields b
  | t => [t]

/-- Copy a borrowed frame field into a request that can outlive its packet. -/
partial def ownFrame (ty : Ty) (value : String) (borrowed := true) : String :=
  match ty with
  | .bytes => s!"({value}).to_vec()"
  | .u64 | .nat | .int64 | .bool | .unit => if borrowed then s!"*({value})" else value
  | .list t => s!"({value}).iter().map(|value| {ownFrame t "value"}).collect()"
  | .option t => s!"({value}).as_ref().map(|value| {ownFrame t "value"})"
  | .prod a b => s!"({ownFrame a s!"({value}).0" false}, {ownFrame b s!"({value}).1" false})"
  | _ => s!"({value}).clone()"

def externalFailure : Wrapper → String
  | .reply => "crate::operation::protocol_failure()"
  | .fileReply => "crate::operation::file_protocol_failure()"

/-- Generate the owned requests, typed replies, conversions and rejection
packets of external services. The runner still owns suspension and cleanup. -/
def rustExternal (all : Array Algebra) : MetaM String := do
  let mut out := ""
  let mut refused := "pub(crate) fn external_failure(frame: &Frame<'_>) -> Option<Vec<u8>> {\n    match frame {\n"
  for algebra in all do
    let ctors := algebra.ctors.filter fun ctor => match route algebra.short ctor.short with
      | .external => true
      | _ => false
    if ctors.isEmpty then continue
    let request := algebra.short ++ "Request"
    let response := algebra.short ++ "Reply"
    let service := snake algebra.short |>.drop 1 |>.toString
    let mut replies := s!"/// Replies to {request}; failures retain their original host error.\n#[derive(Debug)]\npub enum {response}<E> \{\n"
    let mut decode := s!"pub(crate) fn {service}_request(frame: &Frame<'_>) -> Option<{request}> \{\n    match frame \{\n"
    let mut encode := s!"pub(crate) fn {service}_reply<E>(request: &{request}, answer: {response}<E>, errors: &mut Vec<Option<E>>) -> Vec<u8> \{\n    match (request, answer) \{\n"
    let mut failures := ""
    out := out ++ docLines "" algebra.doc ++ s!"#[derive(Debug, Clone, PartialEq, Eq)]\npub enum {request} \{\n"
    for ctor in ctors do
      let variant := externalVariant ctor
      let names := externalFields (algebra.short ++ "." ++ ctor.short)
      let fields := productFields ctor.result
      if !names.isEmpty && (names.length != fields.length || ctor.wrapper != .reply) then
        throwError "hostgen: external reply names do not match {ctor.full}"
      out := out ++ docLines "    " ctor.doc ++ s!"    {variant} \{\n"
      for field in ctor.fields do
        out := out ++ s!"        {snake field.name}: {rustMessageTy field.ty},\n"
      out := out ++ "    },\n"
      let binders := ctor.fields.toList.zipIdx.map fun (_, i) => s!"a{i}"
      let frame := s!"Frame::{frameName algebra ctor}" ++
        (if binders.isEmpty then "" else s!"({String.intercalate ", " binders})")
      decode := decode ++ s!"        {frame} => Some({request}::{variant} \{\n"
      for field in ctor.fields, i in [:ctor.fields.size] do
        decode := decode ++ s!"            {snake field.name}: {ownFrame field.ty s!"a{i}"},\n"
      decode := decode ++ "        }),\n"
      let expected := s!"{request}::{variant} \{ .. }"
      if names.isEmpty then
        let error := if ctor.wrapper == .fileReply then "FileFailure<E>" else "E"
        replies := replies ++ s!"    {variant}(Result<{rustMessageTy ctor.result}, {error}>),\n"
        let envelope := if ctor.wrapper == .fileReply then "file_reply" else "reply"
        encode := encode ++ s!"        ({expected}, {response}::{variant}(value)) => {envelope}({ctor.tag}, value, errors, |out, value| value.encode(out)),\n"
      else
        replies := replies ++ s!"    {variant} \{\n"
        for (name, ty) in names.zip fields do
          replies := replies ++ s!"        {name}: {rustMessageTy ty},\n"
        replies := replies ++ "    },\n"
        encode := encode ++ s!"        ({expected}, {response}::{variant} \{ {String.intercalate ", " names} }) => reply({ctor.tag}, Ok::<(), E>(()), errors, |out, ()| \{\n"
        for name in names do
          encode := encode ++ s!"            {name}.encode(out);\n"
        encode := encode ++ "        }),\n"
      if ctor.wrapper == .reply then
        encode := encode ++ s!"        ({expected}, {response}::Failed(error)) => reply({ctor.tag}, Err::<(), _>(error), errors, |_, ()| \{}),\n"
      failures := failures ++ s!"        ({expected}, _) => {externalFailure ctor.wrapper},\n"
      let pattern := s!"Frame::{frameName algebra ctor}" ++ (if binders.isEmpty then "" else "(..)")
      refused := refused ++ s!"        {pattern} => Some({externalFailure ctor.wrapper}),\n"
    if ctors.any (·.wrapper == .reply) then replies := replies ++ "    Failed(E),\n"
    out := out ++ "}\n\n" ++ replies ++ "}\n\n" ++ decode ++ "        _ => None,\n    }\n}\n\n"
    out := out ++ encode ++ failures ++ "    }\n}\n\n"
  return out ++ refused ++ "        _ => None,\n    }\n}\n"

/-- Messages only this crate constructs. -/
def crateOnly : List Name := [``VerifiedCore.Commands.Command]

def rustMessage (message : Message) : String := Id.run do
  let name := message.rust
  let visibility := if crateOnly.contains message.full then "pub(crate)" else "pub"
  let plain := message.ctors.all fun ctor => ctor.fields.isEmpty
  let derive := if plain then "#[derive(Debug, Clone, Copy, PartialEq, Eq)]" else "#[derive(Debug, Clone, PartialEq, Eq)]"
  let mut out := docLines "" message.doc ++ derive ++ "\n"
  if message.isStructure then
    let ctor := message.ctors[0]!
    out := out ++ s!"{visibility} struct {name} \{\n"
    for field in ctor.fields do
      out := out ++ s!"    pub {snake field.name}: {rustMessageTy field.ty},\n"
    out := out ++ "}\n\n"
    out := out ++ s!"impl Encode for {name} \{\n    fn encode(&self, out: &mut Vec<u8>) \{\n"
    for field in ctor.fields do
      out := out ++ s!"        self.{snake field.name}.encode(out);\n"
    out := out ++ "    }\n}\n\n"
    out := out ++ s!"impl Decode for {name} \{\n    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> \{\n        Ok(Self \{\n"
    for field in ctor.fields do
      out := out ++ s!"            {snake field.name}: Decode::decode(r)?,\n"
    out := out ++ "        })\n    }\n}\n\n"
    return out
  out := out ++ s!"{visibility} enum {name} \{\n"
  for ctor in message.ctors do
    out := out ++ docLines "    " ctor.doc
    let variant := pascal ctor.short
    match ctor.fields.toList with
    | [] => out := out ++ s!"    {variant},\n"
    | [field] => out := out ++ s!"    {variant}({rustMessageTy field.ty}),\n"
    | fields =>
      out := out ++ s!"    {variant} \{\n"
      for field in fields do
        out := out ++ s!"        {snake field.name}: {rustMessageTy field.ty},\n"
      out := out ++ "    },\n"
  out := out ++ "}\n\n"
  out := out ++ s!"impl Encode for {name} \{\n    fn encode(&self, out: &mut Vec<u8>) \{\n        match self \{\n"
  for ctor in message.ctors, index in [:message.ctors.size] do
    let variant := pascal ctor.short
    match ctor.fields.toList with
    | [] => out := out ++ s!"            Self::{variant} => out.push({index}),\n"
    | [_] => out := out ++ s!"            Self::{variant}(a0) => \{\n                out.push({index});\n                a0.encode(out);\n            }\n"
    | fields =>
      let names := String.intercalate ", " (fields.map fun field => snake field.name)
      out := out ++ s!"            Self::{variant} \{ {names} } => \{\n                out.push({index});\n"
      for field in fields do
        out := out ++ s!"                {snake field.name}.encode(out);\n"
      out := out ++ "            }\n"
  out := out ++ "        }\n    }\n}\n\n"
  out := out ++ s!"impl Decode for {name} \{\n    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> \{\n        Ok(match r.byte()? \{\n"
  for ctor in message.ctors, index in [:message.ctors.size] do
    let variant := pascal ctor.short
    match ctor.fields.toList with
    | [] => out := out ++ s!"            {index} => Self::{variant},\n"
    | [_] => out := out ++ s!"            {index} => Self::{variant}(Decode::decode(r)?),\n"
    | fields =>
      out := out ++ s!"            {index} => Self::{variant} \{\n"
      for field in fields do
        out := out ++ s!"                {snake field.name}: Decode::decode(r)?,\n"
      out := out ++ "            },\n"
  out := out ++ "            _ => return Err(()),\n        })\n    }\n}\n\n"
  return out

def rustMessages (all : Array Message) : String :=
  String.join (all.toList.map rustMessage)

/-- Storage-only CAS entry points. Argument and success types are read from
both the command constructor and the production operation; the table only
associates names. These commands share Entry.projecting's domain error. -/
def projections : List (String × Name) := [
  ("casBlob", ``VerifiedCore.Cas.Project.blob),
  ("casBlobIn", ``VerifiedCore.Cas.Project.blobIn),
  ("casBlobs", ``VerifiedCore.Cas.Project.blobs),
  ("casBlobCandidates", ``VerifiedCore.Cas.Project.candidates),
  ("casPins", ``VerifiedCore.Cas.Project.pins),
  ("casPinnedBlobs", ``VerifiedCore.Cas.Project.pinnedBlobs)]

/-- The public projection API accepts content addresses, never arbitrary bytes. -/
def projectionParam (field : Field) : MetaM (String × String) := do
  let name := snake field.name
  match field.ty with
  | .bytes => return (s!"{name}: &[u8; 32]", s!"{name}.to_vec()")
  | .option .bytes => return (s!"{name}: Option<&[u8; 32]>", s!"{name}.map(|value| value.to_vec())")
  | .u64 => return (s!"{name}: u64", name)
  | _ => throwError "hostgen: unsupported projection argument {field.name}"

def rustProjections (messages : Array Message) : MetaM String := do
  let some commands := messages.find? (·.full == ``VerifiedCore.Commands.Command)
    | throwError "hostgen: command message missing"
  let mut out := "pub(crate) mod cas_projection {\n    use super::*;\n\n"
  for (name, operation) in projections do
    let some ctor := commands.ctors.find? (·.short == name)
      | throwError "hostgen: projection command {name} missing"
    let info ← getConstInfo operation
    let result ← forallTelescope info.type fun args result => do
      unless result.isAppOfArity ``VerifiedCore.Cas.Project.Action 1 do
        throwError "hostgen: {operation} is not a storage-only projection"
      unless args.size == ctor.fields.size do
        throwError "hostgen: {operation} arguments differ from {name}"
      for arg in args, field in ctor.fields do
        let ty ← inferType arg
        -- Transaction is a UInt64 alias, not a separate wire type.
        let ty := if ty.isConstOf ``VerifiedCore.Host.Transaction then mkConst ``UInt64 else ty
        unless (← parseTy ty) == field.ty do
          throwError "hostgen: {operation} argument {field.name} differs from {name}"
      parseTy result.getAppArgs.back!
    let params ← ctor.fields.mapM projectionParam
    let signature := String.intercalate ", " ("storage: &mut S" :: params.toList.map Prod.fst)
    let variant := "Command::" ++ pascal name
    let command := match ctor.fields.toList, params.toList with
      | [], _ => variant
      | [_], [(_, value)] => s!"{variant}({value})"
      | fields, params =>
        let values := (fields.zip params).map fun (pair : Field × (String × String)) =>
          if snake pair.1.name == pair.2.2 then pair.2.2 else s!"{snake pair.1.name}: {pair.2.2}"
        variant ++ " { " ++ String.intercalate ", " values ++ " }"
    let publicName := ((snake name).drop 4).toString
    let doc ← findDocString? (← getEnv) operation
    out := out ++ docLines "    " (doc.or ctor.doc)
    out := out ++ s!"    pub fn {publicName}<S: Storage>({signature}) -> Result<{rustMessageTy result}, crate::cas::ProjectError<S::Error>> \{\n"
    out := out ++ s!"        crate::CommandError::finish(crate::operation::run(storage, Capabilities::default(), &[], &{command}))\n    }\n\n"
  return out ++ "}\n"

def rustFile (all : Array Algebra) (messages : Array Message) (projections external : String) : String :=
  "// Printed by lean/Hostgen.lean at build time from the Lean effect algebras\n// and command types; included from lib.rs, never edited or committed.\n\nuse crate::host::*;\nuse crate::operation::{\n    file_reply, reply, scan_reply, Capabilities, Decode, Encode, EncodeReply, OperationError,\n    Reader,\n};\n\n"
  ++ rustTraits all ++ rustFrames all ++ rustDispatch all ++ "\n" ++ rustUnexpected all ++ "\n"
  ++ (rustMessages messages).trimAsciiEnd.toString ++ "\n\n" ++ projections ++ "\n" ++ external

end Hostgen

/-! Usage, from `crates/synch-verified/lean`:

    lake env lean --run Hostgen.lean [--check] [--rust FILE]

The Lean codecs live in the tree, at `VerifiedCore/Host/Generated.lean` and
`VerifiedCore/Commands/Generated.lean`: they are rewritten, or under `--check`
compared with what the algebras and commands now say, exiting 1 when stale.
The Rust glue is a build product, written only where `--rust` says: Cargo's
build script prints it into its output directory and `lib.rs` includes it. -/
open Hostgen in
def main (args : List String) : IO UInt32 := do
  let check := args.contains "--check"
  let rustPath? := match args.dropWhile (· != "--rust") with
    | _ :: path :: _ => some path
    | _ => none
  initSearchPath (← findSysroot)
  let modules : Array Name := #[`VerifiedCore.Host, `VerifiedCore.Crypto, `VerifiedCore.Host.Access,
    `VerifiedCore.Host.Construct, `VerifiedCore.Host.Upsert, `VerifiedCore.Host.Resources,
    `VerifiedCore.Host.Source, `VerifiedCore.Host.Digest, `VerifiedCore.Host.Writes,
    `VerifiedCore.Host.Bao, `VerifiedCore.Host.Sweep, `VerifiedCore.Host.Memo, `VerifiedCore.Host.Walk,
    `VerifiedCore.Host.Peer, `VerifiedCore.Host.Provider, `VerifiedCore.Host.CacheIO,
    `VerifiedCore.Commands]
  let env ← importModules (modules.map fun module => ({ module } : Import)) {} 0
  let (lean, commands, rust) ← Prod.fst <$> (Meta.MetaM.toIO (do
      let all ← algebras.toArray.mapM readAlgebra
      checkTags all
      let messages ← messages.toArray.mapM readMessage
      let projections ← rustProjections messages
      let external ← rustExternal all
      return (leanFile all, leanCommandsFile messages, rustFile all messages projections external))
    { fileName := "<hostgen>", fileMap := default } { env })
  let mut stale := false
  for (path, text) in [("VerifiedCore/Host/Generated.lean", lean),
      ("VerifiedCore/Commands/Generated.lean", commands)] do
    let current ← IO.FS.readFile path <|> pure ""
    if current == text then continue
    if check then
      IO.eprintln s!"{path} is out of date; run `lake env lean --run Hostgen.lean` in crates/synch-verified/lean"
      stale := true
    else
      IO.FS.writeFile path text
      IO.println s!"wrote {path}"
  if let some path := rustPath? then
    IO.FS.writeFile path rust
  return (if stale then 1 else 0 : UInt32)
