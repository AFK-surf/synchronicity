import VerifiedCore.Crypto
import VerifiedCore.Origin
import VerifiedCore.Cas.Codec
import VerifiedCore.Trie.Serve

/-! Authorization's data and scope construction. Raw SQL cells and primitive
point validation are observations; source, expiry, delegation, and grant
interpretation belong to this executable domain. -/
namespace VerifiedCore.Authorization
open Host

inductive Error where
  | host (failure : Failure)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | invalidText (bytes : List UInt8)
  | column (column : String) (reason : String)
  | origin (column : String) (error : Origin.Error)
  deriving BEq, DecidableEq

abbrev Effects := EffectSum Storage Crypto
abbrev Action (A : Type) := OperationOver Effects Error A

def storage (effect : Storage (Reply A)) : Action A := raise Error.host effect

def validateKey (bytes : List UInt8) : Action Bool := raise Error.host (Crypto.validateEd25519 bytes)

def transaction (body : Transaction → Action A) : Action A :=
  transactionOver Inject.inject Error.host body

def checked (value : Except Error A) : Action A :=
  match value with | .ok value => pure value | .error error => throw error

inductive Source where
  | static | dns | delegated
  deriving BEq, DecidableEq

def Source.rooted : Source → Bool
  | .static | .dns => true
  | .delegated => false

def parseSource (text : String) : Except Error Source :=
  match text with
  | "static" => .ok .static
  | "dns" => .ok .dns
  | "delegated" => .ok .delegated
  | other => .error (.column "bindings.source" other)

/-- A delegated binding carries two space lists. `spaces` is read-write: the
key reads the space and publishes into it. `readOnly` is read alone: served
exactly like a read-write space, and refused at head promotion exactly like
a space outside the grant. Both are empty for a rooted binding. -/
structure Binding where
  origin : Origin.Parsed
  nodeId : ByteArray
  source : Source
  domain : Option String
  issuer : Option Origin.Parsed
  spaces : List String
  readOnly : List String
  note : Option String
  addedAt : Int64
  expiresAt : Option Int64
  deriving BEq, DecidableEq

/-- Every space a binding lets its key read: read-write and read-only alike.
Publication asks `spaces` alone. -/
def Binding.readable (binding : Binding) : List String := binding.spaces ++ binding.readOnly

inductive PublishScope where
  | untrusted
  | unrestricted
  | confined (spaces : List String)
  deriving BEq, DecidableEq

/-- Rust's stored i64 text syntax: optional sign, ASCII digits, no separators
or surrounding whitespace, and no wraparound on overflow. Malformed floors
have always meant zero; they never create a new clock authority. -/
def parseI64 (text : String) : Option Int64 := do
  let (negative, digits) := match text.toList with
    | '-' :: rest => (true, rest)
    | '+' :: rest => (false, rest)
    | rest => (false, rest)
  if digits.isEmpty || !digits.all (fun c => '0' ≤ c && c ≤ '9') then none else do
    let magnitude := digits.foldl (fun total c => total * 10 + (c.toNat - '0'.toNat)) 0
    let integer : Int := if negative then -(Int.ofNat magnitude) else Int.ofNat magnitude
    if integer < -9223372036854775808 || integer > 9223372036854775807 then none
    else some (Int64.ofInt integer)

def minTrustedNs : Int64 := 1735689600000000000

def clockTrusted (now : Int64) : Bool := now ≥ minTrustedNs

def liveAt (expiresAt : Option Int64) (now : Int64) : Bool :=
  match expiresAt with
  | none => true
  | some expiry => clockTrusted now && now < expiry

def Binding.datedLive (binding : Binding) (now : Int64) : Bool := liveAt binding.expiresAt now

/-- Unicode Cc consists precisely of the C0 and C1 control ranges. Space
identifiers permit other Unicode characters; the persisted bound is bytes. -/
def validSpace (space : String) : Bool :=
  !space.isEmpty && space.utf8ByteSize ≤ 63 &&
    space.toList.all (fun c => c != '/' && !(c.toNat ≤ 31 || (127 ≤ c.toNat && c.toNat ≤ 159)))

def decodeSpaces (text : String) : List String :=
  (text.toList.splitOn '\n').map String.ofList |>.filter validSpace

def nibbleBytes (text : String) : ByteArray := ⟨(Trie.keyNibbles text.toUTF8).toArray⟩

def scopeOf (publicNamespace : String) (spaces : List String) : Trie.Serve.Scope :=
  let spaces := spaces.filter validSpace
  ⟨some (nibbleBytes publicNamespace :: spaces.map (fun space => nibbleBytes ("f:" ++ space ++ "/"))),
    nibbleBytes "m:self" :: spaces.flatMap (fun space =>
      [nibbleBytes ("m:space/" ++ space), nibbleBytes ("r:" ++ space)])⟩

def readScope (spaces : List String) : Trie.Serve.Scope := scopeOf "d:" spaces

/-- What a confined origin may hold in its own trie. A read-only space
contributes its `r:` claim alone: replicating a space is holding its content,
which a read-only grant permits, while its `f:` subtree and `m:space/` record
describe the tree and stay refused. -/
def publicationScope (spaces readOnly : List String) : Trie.Serve.Scope :=
  let base := scopeOf "b:" spaces
  ⟨base.prefixes, base.exact ++ (readOnly.filter validSpace).map (fun space => nibbleBytes ("r:" ++ space))⟩

def fullScope : Trie.Serve.Scope := ⟨none, []⟩

def integerField (index : Nat) (column : String) : Cell → Except Error Int64 :=
  Cas.Codec.integerField (.columnType index column)

def blobField (index : Nat) (column : String) : Cell → Except Error ByteArray :=
  Cas.Codec.blobField (.columnType index column)

def textField (index : Nat) (column : String) : Cell → Except Error String
  | .text value => .ok value
  | .rawText bytes => match String.fromUTF8? bytes with
    | some value => .ok value
    | none => .error (.invalidText bytes.toList)
  | value => .error (.columnType index column (Cas.Codec.cellType value))

def optionalText (index : Nat) (column : String) : Cell → Except Error (Option String)
  | .null => .ok none
  | value => (textField index column value).map some

def optionalInteger (index : Nat) (column : String) : Cell → Except Error (Option Int64)
  | .null => .ok none
  | value => (integerField index column value).map some

def originField (column text : String) : Action Origin.Parsed := do
  match ← Origin.parse validateKey text with
  | .ok value => return value
  | .error error => throw (.origin column error)

def keyField (column : String) (bytes : ByteArray) : Action ByteArray := do
  if bytes.size != 32 then throw (.column column "not 32 bytes")
  if !(← validateKey bytes.data.toList) then throw (.column column "data is not a valid public key")
  return bytes

/-- All SQL type conversions precede domain parsing. The issuer, origin,
public key and source retain their original first-error order. -/
def decodeBinding (row : Row) : Action Binding := do
  match row with
  | [origin, nodeId, source, domain, issuer, spaces, readOnly, note, addedAt, expiresAt] =>
    let origin ← checked (textField 0 "origin_id" origin)
    let nodeId ← checked (blobField 1 "node_id" nodeId)
    let source ← checked (textField 2 "source" source)
    let domain ← checked (optionalText 3 "domain" domain)
    let issuer ← checked (textField 4 "issuer" issuer)
    let spaces ← checked (optionalText 5 "spaces" spaces)
    let readOnly ← checked (optionalText 6 "read_only" readOnly)
    let note ← checked (optionalText 7 "note" note)
    let addedAt ← checked (integerField 8 "added_at" addedAt)
    let expiresAt ← checked (optionalInteger 9 "expires_at" expiresAt)
    let issuer ← if issuer.isEmpty then pure none else do pure (some (← originField "bindings.issuer" issuer))
    let origin ← originField "bindings.origin_id" origin
    let nodeId ← keyField "bindings.node_id" nodeId
    let source ← checked (parseSource source)
    return ⟨origin, nodeId, source, domain.filter (!·.isEmpty), issuer,
      spaces.map decodeSpaces |>.getD [], readOnly.map decodeSpaces |>.getD [], note, addedAt, expiresAt⟩
  | _ => throw .malformed

end VerifiedCore.Authorization
