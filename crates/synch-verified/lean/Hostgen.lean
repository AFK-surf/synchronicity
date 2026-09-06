import Lean
import VerifiedCore.Host
import VerifiedCore.Crypto
import VerifiedCore.Host.Access
import VerifiedCore.Host.Construct
import VerifiedCore.Host.Upsert
import VerifiedCore.Host.Resources
import VerifiedCore.Host.Source
import VerifiedCore.Host.Digest
import VerifiedCore.Commands

/-! `hostgen` reads the executable core's effect algebras and command types
and prints the two sides of the host boundary from them: the Lean request
encoders, reply decoders and command codecs (`VerifiedCore/Host/Generated.lean`,
`VerifiedCore/Commands/Generated.lean`, kept in the tree) and the Rust frames,
decoder, dispatch, host traits, mirrored types and test-double stubs
(`generated.rs`, printed into Cargo's output directory by `build.rs`). Wire
tags and the routing of each effect to a Rust service are the only tables it
holds; the shapes come from the inductives. Run it after changing an algebra
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
capability, or by hand in the interpreter loop. -/
inductive Route where
  | storage
  | capability (field trait : String)
  | special

def algebras : List Name := [
  ``VerifiedCore.Host.Storage, ``VerifiedCore.Host.Crypto, ``VerifiedCore.Host.Access,
  ``VerifiedCore.Host.FileIO, ``VerifiedCore.Host.Clock, ``VerifiedCore.Host.Output,
  ``VerifiedCore.Host.Construct, ``VerifiedCore.Host.Upsert, ``VerifiedCore.Host.Resources,
  ``VerifiedCore.Host.Lease, ``VerifiedCore.Host.SourceIO, ``VerifiedCore.Host.Digest]

/-- The types that cross the command boundary: what a caller asks for and
what a finished command reports. Each gets Lean `Encode`/`Decode` instances
and a Rust mirror with the same codecs; order is by dependency. -/
def messages : List Name := [
  ``VerifiedCore.Cas.Codec.CellType, ``VerifiedCore.Cas.PinHolder, ``VerifiedCore.Cas.Input.Kind,
  ``VerifiedCore.Cas.Outcome, ``VerifiedCore.Origin.Error, ``VerifiedCore.Trie.LookupError,
  ``VerifiedCore.Trie.Refusal, ``VerifiedCore.Trie.Verdict,
  ``VerifiedCore.Commands.LifecycleDomainError, ``VerifiedCore.Commands.IngestDomainError,
  ``VerifiedCore.Commands.ReadDomainError, ``VerifiedCore.Commands.HistoryDomainError,
  ``VerifiedCore.Commands.Ingested, ``VerifiedCore.Commands.Committed,
  ``VerifiedCore.Commands.Command]

/-- Rust spellings that differ from the Lean short name. -/
def rustName (name : Name) : String :=
  match name with
  | ``VerifiedCore.Cas.Input.Kind => "IngestInput"
  | ``VerifiedCore.Origin.Error => "OriginError"
  | ``VerifiedCore.Trie.LookupError => "LookupDomainError"
  | ``VerifiedCore.Trie.Refusal => "NodeRefusal"
  | ``VerifiedCore.Trie.Verdict => "NodeVerdict"
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
  ("Access.snapshot", 29), ("Access.update", 30), ("Access.copyRows", 31), ("Access.delete", 32),
  ("FileIO.open", 33), ("FileIO.readAt", 34), ("FileIO.close", 35), ("FileIO.transfer", 52),
  ("Clock.nowNs", 36), ("Output.append", 37),
  ("Construct.build", 38), ("Construct.hash", 39),
  ("Upsert.write", 41),
  ("Resources.createTemporary", 42), ("Resources.flush", 43), ("Resources.replace", 44),
  ("Resources.discard", 45), ("Resources.syncParent", 46),
  ("Lease.acquire", 47), ("Lease.release", 48),
  ("SourceIO.stat", 49), ("SourceIO.readSome", 50), ("SourceIO.freeze", 51),
  ("Digest.blake3", 53)]

/-- Which Rust service answers an algebra by default. -/
def defaultRoute : String → Route
  | "Storage" | "Access" | "Upsert" => .storage
  | "Crypto" => .capability "crypto" "Crypto"
  | "FileIO" => .capability "files" "FileIO"
  | "Clock" => .capability "clock" "Clock"
  | "Output" => .capability "output" "Output"
  | "Construct" => .capability "construct" "Construct"
  | "Resources" => .capability "temporary" "TemporaryFiles"
  | "Lease" => .capability "leases" "Lease"
  | "SourceIO" => .capability "source" "SourceIO"
  | "Digest" => .capability "digest" "Digest"
  | _ => .special

/-- Which Rust service each effect belongs to. The command inputs and the
transfer into the output sink are not trait methods at all: the interpreter
loop serves them from the run's own resources. -/
def route (algebra ctor : String) : Route :=
  match algebra ++ "." ++ ctor with
  | "Storage.readCounter" | "Storage.removeFile" => .capability "resources" "Resources"
  | "Storage.readInput" | "FileIO.transfer" => .special
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
  | "Lease" => "/// Opaque counted resource leases ordered against competing deletion. Host\n/// abandonment releases outstanding tokens; policy chooses their lifetime."
  | "SourceIO" => "/// Raw input observations. Successful bounded reads may be short at EOF;\n/// freeze retains an immutable copy under an invocation-owned input handle."
  | "Construct" => "/// Bulk object construction over resources the requesting operation owns.\n///\n/// The operation decides what is built, from which opened source and into\n/// which owned temporaries; the host streams the bytes, hashes them into the\n/// BLAKE3 tree and lays out the Bao outboard. Neither call publishes, flushes\n/// or records anything."
  | "Clock" => "/// Wall-clock input; the operation chooses when to observe it."
  | "Crypto" => "/// Primitive cryptography, separate from storage and domain validation."
  | "Digest" => "/// Primitive hashing of exactly the bytes the operation supplies, domain tag\n/// included. What is hashed and what a digest's equality means are the\n/// operation's decisions."
  | _ => ""

/-- Trait methods the interpreter needs beyond the algebra's effects. -/
def traitExtras : String → String
  | "FileIO" => "    /// Fill `buffer` from `offset`, returning `ShortRead` at EOF. The\n    /// interpreter hands over the tail of the operation's output sink, so a\n    /// transfer costs one read into the bytes the caller receives.\n    fn read_into(\n        &mut self,\n        handle: u64,\n        offset: u64,\n        buffer: &mut [u8],\n    ) -> Result<(), FileFailure<Self::Error>>;\n"
  | "Output" => "    /// Extend the sink by `count` bytes and hand them back for an in-place\n    /// fill, so a file transfer lands directly in the result.\n    fn grow(&mut self, count: u64) -> Result<&mut [u8], Self::Error>;\n    /// Take back the last `count` bytes after a fill failed.\n    fn shrink(&mut self, count: u64);\n"
  | _ => ""

def traitOrder : List String :=
  ["Storage", "Resources", "Crypto", "FileIO", "Clock", "Output", "Construct", "TemporaryFiles",
    "Lease", "SourceIO", "Digest"]

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
  let mut out := "import VerifiedCore.Host.Codec\nimport VerifiedCore.Crypto\nimport VerifiedCore.Host.Construct\nimport VerifiedCore.Host.Source\nimport VerifiedCore.Host.Digest\n\n"
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
  | .u64 | .bool | .bytes => s!"a{index}"
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
  | t => panic! s!"hostgen: no request decoder for {repr t}"

def rustTypeAll (all : Array Algebra) (route : Algebra → Ctor → Route) : List (String × Array (Algebra × Ctor)) := Id.run do
  let mut groups : List (String × Array (Algebra × Ctor)) := traitOrder.map fun t => (t, #[])
  for algebra in all do
    for ctor in algebra.ctors do
      let trait := match route algebra ctor with
        | .storage => some "Storage"
        | .capability _ trait => some trait
        | .special => none
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
    out := out ++ traitDoc trait ++ "\n" ++ s!"pub trait {trait} \{\n"
    out := out ++ "    /// Original host error, retained without converting it into a policy result.\n    type Error;\n"
    for (_, ctor) in members do
      out := out ++ rustMethod ctor
    out := out ++ traitExtras trait ++ "}\n\n"
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

def rustFrames (all : Array Algebra) : String := Id.run do
  let mut out := "/// One decoded request packet. Terminal packets carry the operation's\n/// result or failure; every other frame is one effect of one algebra.\n#[derive(Debug)]\npub(crate) enum Frame<'a> {\n    Done(&'a [u8]),\n    Failure(u64, u64),\n"
  for algebra in all do
    for ctor in algebra.ctors do
      let fields := ctor.fields.toList.map fun field => rustFrameTy field.ty
      out := out ++ s!"    {pascal ctor.short}" ++
        (if fields.isEmpty then "" else s!"({String.intercalate ", " fields})") ++ ",\n"
  out := out ++ "}\n\n"
  out := out ++ "pub(crate) fn decode(packet: &[u8]) -> Result<Frame<'_>, ()> {\n    let mut r = Reader(packet);\n    if r.byte()? != 1 {\n        return Err(());\n    }\n    let frame = match r.byte()? {\n        0 => Frame::Done(r.byte_slice()?),\n        1 => Frame::Failure(r.word()?, r.word()?),\n"
  for algebra in all do
    for ctor in algebra.ctors do
      let fields := ctor.fields.toList.map fun field => rustDecoder field.ty
      out := out ++ s!"        {ctor.tag} => Frame::{pascal ctor.short}" ++
        (if fields.isEmpty then "" else s!"({String.intercalate ", " fields})") ++ ",\n"
  out := out ++ "        _ => return Err(()),\n    };\n    r.end()?;\n    Ok(frame)\n}\n\n"
  return out

def rustDispatch (all : Array Algebra) : String := Id.run do
  let mut out := "/// Serve one effect frame with the host it routes to. Terminal frames and\n/// the effects the interpreter loop serves itself are refused here.\npub(crate) fn dispatch<S: Storage>(\n    storage: &mut S,\n    capabilities: &mut Capabilities<'_, S::Error>,\n    frame: Frame<'_>,\n    errors: &mut Vec<Option<S::Error>>,\n) -> Result<Vec<u8>, OperationError<S::Error>> {\n    Ok(match frame {\n"
  for algebra in all do
    for ctor in algebra.ctors do
      let binders := ctor.fields.toList.zipIdx.map fun (_, i) => s!"a{i}"
      let pattern := s!"Frame::{pascal ctor.short}" ++
        (if binders.isEmpty then "" else s!"({String.intercalate ", " binders})")
      let args := String.intercalate ", " (ctor.fields.toList.zipIdx.map fun (field, i) => rustArg i field.ty)
      let (receiver, prelude) := match route algebra.short ctor.short with
        | .storage => ("storage", "")
        | .capability field _ =>
          ("host", s!"            let host = capabilities.{field}.as_deref_mut().ok_or(OperationError::Protocol)?;\n")
        | .special => ("", "")
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

def rustFile (all : Array Algebra) (messages : Array Message) : String :=
  "// Printed by lean/Hostgen.lean at build time from the Lean effect algebras\n// and command types; included from lib.rs, never edited or committed.\n\nuse crate::host::*;\nuse crate::operation::{\n    file_reply, reply, scan_reply, Capabilities, Decode, Encode, EncodeReply, OperationError,\n    Reader,\n};\n\n"
  ++ rustTraits all ++ rustFrames all ++ rustDispatch all ++ "\n" ++ rustUnexpected all ++ "\n"
  ++ (rustMessages messages).trimAsciiEnd.toString ++ "\n"

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
    `VerifiedCore.Host.Source, `VerifiedCore.Host.Digest, `VerifiedCore.Commands]
  let env ← importModules (modules.map fun module => ({ module } : Import)) {} 0
  let (lean, commands, rust) ← Prod.fst <$> (Meta.MetaM.toIO (do
      let all ← algebras.toArray.mapM readAlgebra
      checkTags all
      let messages ← messages.toArray.mapM readMessage
      return (leanFile all, leanCommandsFile messages, rustFile all messages))
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
