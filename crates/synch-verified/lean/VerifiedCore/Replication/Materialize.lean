import VerifiedCore.Replication.Records
import VerifiedCore.Replication.Reconcile
import VerifiedCore.Authorization.Operations
import VerifiedCore.Trie.Diff

/-! The derived view and retention delta run inside the publication transaction.
Only one resolved changed value is live at a time. Raw SQL and Unicode services
do not choose entries, authority, possession, wants, or release policy. -/
namespace VerifiedCore.Replication.Materialize
open Host Trie.Walk
inductive Error where
  | host (failure : Failure)
  | walk (error : Trie.Walk.Error)
  | metadata (error : History.Error)
  | decode (message : String)
abbrev Effects := EffectSum Storage (EffectSum Crypto (EffectSum Access
  (EffectSum Digest (EffectSum Redaction (EffectSum Clock Unicode)))))
abbrev Action (A : Type) := OperationOver Effects Error A

def authError : Authorization.Error → Error
  | .host e => .host e
  | e => .metadata (Reconcile.authorizationError e)
def auth (p : Authorization.Action A) : Action A := within authError p
def raw (e : Storage (Reply A)) : Action A := raise Error.host e
def checked (value : Except String A) : Action A := ExceptT.mk (pure (value.mapError Error.decode))
def metadata (result : Except History.Error A) : Action A := ExceptT.mk (pure (result.mapError Error.metadata))
def text (value : Cell) : Action String := metadata (History.textField 0 "materialization" value)
def int (value : Cell) : Action Int64 := metadata (History.integerField 0 "materialization" value)
def write (tx : Transaction) (table : String) (key values : Fields) (preserve : Bool := false) : Action Unit :=
  raw (.upsert tx table (key ++ values) (key.map (·.1)) (if preserve then [] else values.map (·.1)))
def erase (tx : Transaction) (table : String) (key : Fields) : Action Unit := do
  let _ ← raw (.deleteRows tx table key)
def update (tx : Transaction) (table : String) (key values : Fields) : Action Unit := do
  let _ ← raise Error.host (Access.update tx ⟨table, key, [], []⟩ values)

structure Target where
  space : String
  grace : Int64
  releases : Bool
  floor : Int64
def Target.holder (t : Target) : String := "replica:" ++ t.space
def saturate (n : Int) : Int64 := Int64.ofInt (max (-9223372036854775808) (min 9223372036854775807 n))
def targets (tx : Transaction) : Action (List Target) := do
  let floor := ((← auth (Authorization.config tx "replica.release_floor")).bind Authorization.parseI64).getD 1
  let rows ← raw (.readRows tx "replicas" ["space", "retention", "grace_seconds", "budget_bytes", "checkout_path"] [])
  rows.mapM fun row => do
    match row with
    | [space, retention, grace, budget, checkout] =>
      let space ← text space
      let retention ← text retention
      if retention != "current" && retention != "forever" then throw (.metadata .malformed)
      let grace ← match grace with | .null => pure 2592000 | value => int value
      match budget with | .null => pure () | value => let _ ← int value; pure ()
      match checkout with | .null => pure () | value => let _ ← text value; pure ()
      return ⟨space, saturate (grace.toInt * 1000000000), retention == "current", floor⟩
    | _ => throw (.metadata .malformed)

def rootField : Cell → Action (Option ByteArray)
  | .null => pure none
  | .blob root => some <$> metadata (History.hashField "entries.content" root)
  | value => throw (.metadata (.columnType 0 "content" (History.cellType value)))
def current (tx : Transaction) (key : Fields) : Action (Option ByteArray) := do
  match ← raw (.readRows tx "entries" ["content"] key) with
  | [] => return none
  | [value] :: _ => rootField value
  | _ => throw (.metadata .malformed)

def wants (tx : Transaction) (target : Target) (file : Records.File) (root : ByteArray) (now : Int64) : Action Unit := do
  let key := [("root", .blob root), ("holder", .text target.holder)]
  update tx "pins" key [("release_after", .null)]
  let blobs ← raw (.readRows tx "blobs" ["durable"] [("root", .blob root)])
  let durable : Bool ← match blobs with
    | [] => pure false
    | [value] :: _ => (fun n => n != 0) <$> int value
    | _ => throw (.metadata .malformed)
  if durable then
    -- Preserve the first claim's creation time, including reappearance.
    write tx "pins" key [("created_at", .integer now), ("release_after", .null)] true
  if ← raw (.existsRows tx "pins" key) then erase tx "content_want" key
  else write tx "content_want" key [("size", .integer file.size.toUInt64.toInt64),
    ("prev", Records.nullable .blob file.prev), ("first_wanted", .integer now)] true

def release (tx : Transaction) (target : Target) (root : ByteArray) (now : Int64) : Action Unit := do
  if !target.releases then return
  if ← raw (.existsRows tx "entries" [("content", .blob root)]) then return
  if target.floor > 0 then
    let own := (← auth (Authorization.config tx "self_origin_id")).getD ""
    let rows ← raw (.readRows tx "blob_providers" ["origin_id", "complete"] [("object_root", .blob root)])
    let holders ← rows.foldlM (fun count row => do
      match row with
      | [origin, complete] => return count + if (← text origin) != own && (← int complete) != 0 then 1 else 0
      | _ => throw (.metadata .malformed)) (0 : Nat)
    if holders < target.floor.toInt.toNat then return
  let key := [("root", .blob root), ("holder", .text target.holder)]
  erase tx "content_want" key
  update tx "pins" (key ++ [("release_after", .null)])
    [("release_after", .integer (saturate (now.toInt + target.grace.toInt)))]

def decode (label : String) (parser : Records.Decoder A) (bytes : ByteArray) : Action A :=
  checked (((parser (bytes, 0)).map (·.1)).mapError (fun e => label ++ ": " ++ e))

def apply (tx : Transaction) (origin : String) (now releaseNow : Int64) (replicas : List Target)
    (key : ByteArray) (kind : UInt64) (value : Option ByteArray) : Action Unit := do
  if key[0]? == some 102 then
    let some (space, path) := Records.fileKey key | return
    if !(← raise Error.host (Unicode.isNfc path)) then return
    let fields := [("origin_id", .text origin), ("space", .text space), ("path", .text path)]
    let target := replicas.find? (·.space == space)
    let previous ← if target.isSome && kind != 0 then current tx fields else pure none
    match value with
    | none =>
      erase tx "entries" fields
      if let some target := target then
        if let some root := previous then release tx target root releaseNow
    | some bytes =>
      let file ← decode "f: record" Records.file bytes
      write tx "entries" fields file.fields
      if let some target := target then
        if let some root := file.content then wants tx target file root now
        if let some old := previous then
          if some old != file.content then release tx target old releaseNow
  else if key.size == 34 && key[1]? == some 58 then
    let payload := key.extract 2 34
    if key[0]? == some 98 then
      let fields := [("object_root", .blob payload), ("origin_id", .text origin)]
      match value with
      | none => erase tx "blob_providers" fields
      | some bytes => write tx "blob_providers" fields (← decode "b: record" Records.blob bytes)
    else if key[0]? == some 100 then
      if !(← raise Error.host (Crypto.validateEd25519 payload.toList)) then return
      let fields := [("origin_id", .text (Origin.canonical (.key payload.toList))),
        ("node_id", .blob payload), ("source", .text "delegated"), ("issuer", .text origin)]
      let decoded := value.bind (fun bytes => (Records.delegation (bytes, 0)).toOption.map (·.1))
      match decoded with
      | none => erase tx "bindings" fields
      | some record =>
        let key := fields ++ [("domain", .text "")]
        write tx "bindings" key (record ++ [("added_at", .integer now)]) true
        update tx "bindings" key record

def redactionIn (tx : Transaction) : Redaction A → Storage A
  | .isRedacted hash path => .existsRows tx "redacted_nodes"
      ([("hash", .blob hash)] ++ (path.map (fun p => [("path", .blob p)])).getD [])
def fromWalk : Trie.Walk.Error → Error
  | .host e => .host e
  | e => .walk e

/-- Consume the structural walk's stream inside Lean. No Apply request crosses
the host boundary; metadata errors stop the walk and remain distinct from bad
published records, so fixing local policy does not require clearing a refusal. -/
def runDiff (tx : Transaction) (emit : ByteArray → UInt64 → Option ByteArray → Action Unit) :
    Program Trie.Diff.Effects (Except Trie.Walk.Error A) → Action A
  | .pure result => ExceptT.mk (pure (result.mapError fromWalk))
  | .request (.left e) next => do
    let answer ← observe e
    runDiff tx emit (next answer)
  | .request (.right (.left e)) next => do
    let answer ← observe (redactionIn tx e)
    runDiff tx emit (next answer)
  | .request (.right (.right (.left e))) next => do
    let answer ← observe e
    runDiff tx emit (next answer)
  | .request (.right (.right (.right (.applyChange key kind value)))) next => do
    emit key kind value
    runDiff tx emit (next (.ok ()))

def materializeIn (tx : Transaction) (origin : Origin.Parsed) (oldRoot newRoot : ByteArray) : Action UInt64 := do
  let scope ← auth (Authorization.materializationScopeIn tx origin)
  let now ← raise Error.host Clock.nowNs
  let replicas ← targets tx
  let floor := ((← auth (Authorization.config tx "trust_clock_floor")).bind Authorization.parseI64).getD 0
  let releaseNow := max (← raise Error.host Clock.nowNs) floor
  runDiff tx (apply tx (Origin.canonical origin) now releaseNow replicas)
    (Trie.Diff.materialize (E := Trie.Diff.Effects) scope oldRoot newRoot).run

def materialize (tx : Transaction) (origin : Origin.Parsed) (oldRoot newRoot : ByteArray) : Action UInt64 :=
  materializeIn tx origin oldRoot newRoot

end VerifiedCore.Replication.Materialize
