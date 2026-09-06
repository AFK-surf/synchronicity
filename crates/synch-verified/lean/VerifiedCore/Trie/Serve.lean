import VerifiedCore.Trie.Program
import VerifiedCore.Host.Access
import VerifiedCore.Cas.Codec

/-! Serving trie nodes and values to a peer: which positions of a root this
node vouches for the peer may see, what really stands at each claimed
position, whether a node's own contents run out of the peer's scope, and how
much one answer carries. The scope a peer reads under, and which origins are
confined, are Authorization-domain inputs; every other fact is read here. -/
namespace VerifiedCore.Trie.Serve

open Host

/-- A position in a trie, one nibble per element. -/
abbrev Path := List UInt8

/-- Which part of a trie a peer may see: allowed nibble prefixes, or every
prefix when `none`, and exact keys, which admit their spine and themselves
but nothing below. -/
structure Scope where
  prefixes : Option (List ByteArray)
  exact : List ByteArray
  deriving BEq, DecidableEq

def Scope.isFull (scope : Scope) : Bool := scope.prefixes.isNone

/-- A node at `path` commits to every key beginning with it, so it may be
served as an ancestor of an allowed prefix or inside one, or on the spine
down to an exact key. -/
def Scope.admitsPath (scope : Scope) (path : Path) : Bool :=
  match scope.prefixes with
  | none => true
  | some prefixes =>
    prefixes.any (fun granted => path.isPrefixOf granted.toList || granted.toList.isPrefixOf path)
      || scope.exact.any (fun key => path.isPrefixOf key.toList)

/-- Everything below `path` lies inside the scope: a position inside a
granted prefix cannot lead out of it. Exact keys grant nothing below. -/
def Scope.containsSubtree (scope : Scope) (path : Path) : Bool :=
  match scope.prefixes with
  | none => true
  | some prefixes => prefixes.any (fun granted => granted.toList.isPrefixOf path)

/-- A whole key, as a nibble path, lies inside the scope. -/
def Scope.admitsKeyPath (scope : Scope) (key : Path) : Bool :=
  scope.containsSubtree key || scope.exact.any (fun exact => exact.toList == key)

/-- A node at `path` may travel whole, given what it reveals: a branch only
its child hashes unless it carries an inline value, an extension the nibbles
it spells, a leaf the rest of its key and its value. -/
def Scope.admitsNode (scope : Scope) (path : Path) : Node → Bool
  | .branch _ value => scope.isFull || match value with
    | none => true
    | some (.hash _) => true
    | some (.inline _) => scope.admitsKeyPath path
  | .extension segment _ => scope.isFull || scope.admitsPath (path ++ segment.toList)
  | .leaf suffix _ => scope.isFull || scope.admitsKeyPath (path ++ suffix.toList)

/-- The value a node carries belongs to a granted key; a branch may travel
on the spine without granting the value at the branch itself. -/
def Scope.admitsValue (scope : Scope) (path : Path) : Node → Bool
  | .leaf suffix _ => scope.admitsKeyPath (path ++ suffix.toList)
  | .branch _ _ => scope.admitsKeyPath path
  | .extension _ _ => false

/-- The out-of-line values a node references. -/
def _root_.VerifiedCore.Trie.Node.valueHashes : Node → List ByteArray
  | .leaf _ (.hash address) => [address]
  | .branch _ (some (.hash address)) => [address]
  | _ => []

inductive Error where
  | host (failure : Failure)
  /-- A scoped peer asked about a root this node holds no head for, or only
  the peer's own: positions in it authorize nothing. -/
  | unvouchedRoot
  /-- A stored node on the descent does not decode. -/
  | decode (message : String)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Cas.Codec.CellType)
  | column (column : String) (reason : String)
  deriving BEq, DecidableEq

abbrev Effects := EffectSum Storage Access
abbrev Action (A : Type) := OperationOver Effects Error A

def storage (effect : Storage (Reply A)) : Action A := raise Error.host effect
def access (effect : Access (Reply A)) : Action A := raise Error.host effect

/-- One answer carries at most this many payload bytes: half a frame. -/
def answerBudget : Nat := 8388608

/-- Every nonterminal step consumes a nibble, so a descent is bounded by the
deepest key; the budget only retains the corrupted-store behaviour. -/
def descentFuel : Nat := maxKeyBytes * 2 + 1

/-- The zero root is the empty trie. -/
def rootOf (root : ByteArray) : Option ByteArray :=
  if root.data.all (· == 0) then none else some root

/-! ## Positions -/

/-- What stands `rest` below `current`, recording each position reached as
`(nibbles consumed, hash)` on the trail. A path continuing past a leaf, off
a branch, or along an extension it does not spell names nothing, and so does
an extension spelling nothing at all. -/
def descend : Nat → Nat → Option ByteArray → Path → List (Nat × ByteArray) →
    Action (Option ByteArray × List (Nat × ByteArray))
  | 0, _, _, _, trail => pure (none, trail)
  | _ + 1, _, none, _, trail => pure (none, trail)
  | fuel + 1, consumed, some hash, rest, trail => do
    if rest.isEmpty then return (some hash, trail)
    match ← storage (.readBytes nodeSpace hash) with
    | none => return (none, trail)
    | some raw =>
      match decode raw with
      | .error message => throw (.decode message)
      | .ok (.leaf _ _) => return (none, trail)
      | .ok (.extension segment child) =>
        let spelled := segment.toList
        if spelled.isEmpty || !spelled.isPrefixOf rest then return (none, trail)
        let consumed := consumed + spelled.length
        descend fuel consumed (some child) (rest.drop spelled.length) (trail ++ [(consumed, child)])
      | .ok (.branch children _) =>
        match rest with
        | [] => return (some hash, trail)
        | nibble :: below =>
          if nibble.toNat ≥ 16 then return (none, trail)
          match (children[nibble.toNat]?).getD none with
          | none => return (none, trail)
          | some child => descend fuel (consumed + 1) (some child) below (trail ++ [(consumed + 1, child)])

def commonPrefix : Path → Path → Nat
  | a :: as, b :: bs => if a == b then commonPrefix as bs + 1 else 0
  | _, _ => 0

/-- Lexicographic order on positions, so a batch is one merged descent. -/
def before : Path → Path → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => if a == b then before as bs else a < b

def insertByPath (want : Nat × Path) : List (Nat × Path) → List (Nat × Path)
  | [] => [want]
  | head :: rest =>
    if before want.2 head.2 || want.2 == head.2 then want :: head :: rest
    else head :: insertByPath want rest

def sortByPath : List (Nat × Path) → List (Nat × Path)
  | [] => []
  | want :: rest => insertByPath want (sortByPath rest)

/-- Resolve the sorted positions in turn, each descent resuming from the
deepest point of the previous one that the path still agrees with. -/
def resolveSorted (root : Option ByteArray) : List (Nat × Path) → Path → List (Nat × ByteArray) →
    Action (List (Nat × Option ByteArray))
  | [], _, _ => pure []
  | (index, path) :: rest, walked, trail => do
    let agree := commonPrefix walked path
    let trail := trail.filter (fun step => step.1 ≤ agree)
    let (consumed, current) := match trail.getLast? with
      | some (depth, hash) => (depth, some hash)
      | none => (0, root)
    let (found, trail) ← descend descentFuel consumed current (path.drop consumed) trail
    let others ← resolveSorted root rest path trail
    return (index, found) :: others

/-- What stands at each claimed position of the root, in the caller's order. -/
def resolvePaths (root : ByteArray) (paths : List Path) : Action (List (Option ByteArray)) := do
  let sorted := sortByPath (paths.zipIdx.map fun (path, index) => (index, path))
  let resolved ← resolveSorted (rootOf root) sorted [] []
  return (List.range paths.length).map fun index =>
    ((resolved.find? fun entry => entry.1 == index).map Prod.snd).getD none

/-! ## Vouching -/

def decodeOrigin : Row → Except Error String
  | [.text origin] => .ok origin
  | [.rawText _] => .error (.column "head_history.origin_id" "not valid UTF-8")
  | [cell] => .error (.columnType 0 "origin_id" (Cas.Codec.cellType cell))
  | _ => .error .malformed

/-- The origins this node holds `root` as a verified head of. -/
def headOrigins (root : ByteArray) : Action (List String) := do
  let scan ← access (.snapshot ⟨"head_history", [("root", .blob root)], [], []⟩ ["origin_id"])
  let origins ← ExceptT.mk (.pure (scan.rows.mapM decodeOrigin))
  match scan.failure with
  | some failure => throw (.host failure)
  | none => return origins

/-- Whether this store was served the node as the origin's. -/
def ownsNode (origin : String) (hash : ByteArray) : Action Bool := do
  let scan ← access (.snapshot ⟨"trie_node_origins",
    [("origin_id", .text origin), ("hash", .blob hash)], [], []⟩ ["hash"])
  if scan.rows.isEmpty then
    match scan.failure with
    | some failure => throw (.host failure)
    | none => return false
  else return true

/-- Whether a node under the root is legitimately the reader's to hold: a
root no origin signed demands nothing, an unconfined origin vouches for
everything, and a confined one only for what this store was served as its. -/
def covers (origins confined : List String) (hash : ByteArray) : Action Bool := do
  if origins.isEmpty then return true
  if origins.any (fun origin => !confined.contains origin) then return true
  origins.anyM (fun origin => ownsNode origin hash)

/-! ## Admission -/

/-- What stands at each claimed position, for a peer whose view is scoped:
the root must be a head of some origin other than the peer's own, a
position outside the scope is refused, and what is answered is what the
descent found, never what was claimed. An unscoped peer is answered by hash. -/
def admit (scope : Scope) (root : ByteArray) (origins peerOrigins : List String)
    (wants : List (ByteArray × ByteArray)) : Action (List (Option ByteArray)) := do
  if scope.isFull then return wants.map fun (_, claimed) => some claimed
  if !origins.any (fun origin => !peerOrigins.contains origin) then throw .unvouchedRoot
  let admitted := wants.map fun (path, _) => scope.admitsPath path.toList
  let resolved ← resolvePaths root (wants.map fun (path, _) => path.toList)
  return (resolved.zip admitted).map fun (found, ok) => if ok then found else none

/-- The hashes a list names, each once, in first-seen order. -/
def distinct (list : List ByteArray) (hash : ByteArray) : List ByteArray :=
  if list.contains hash then list else list ++ [hash]

/-- One bounded answer: payloads under the budget, one per distinct hash,
and one payload always, whatever its size. -/
structure Answer where
  budget : Nat := answerBudget
  answered : List ByteArray := []
  payloads : List (ByteArray × ByteArray) := []
  full : Bool := false

def Answer.served (answer : Answer) (hash : ByteArray) : Bool := answer.answered.contains hash

def Answer.push (answer : Answer) (hash data : ByteArray) : Answer :=
  let answered := hash :: answer.answered
  if data.size ≤ answer.budget then
    { answer with answered, budget := answer.budget - data.size, payloads := answer.payloads ++ [(hash, data)] }
  else if answer.payloads.isEmpty then
    { answer with answered, payloads := [(hash, data)], full := true }
  else { answer with answered, full := true }

structure NodeAnswer where
  nodes : List (ByteArray × ByteArray)
  missing : List ByteArray
  redacted : List ByteArray
  deriving BEq, DecidableEq

structure ValueAnswer where
  values : List (ByteArray × ByteArray)
  missing : List ByteArray
  deriving BEq, DecidableEq

/-- Judge every position; stop once the answer is full. -/
def answerNodes (scope : Scope) (origins confined : List String) :
    List (Option ByteArray × (ByteArray × ByteArray)) → Answer → List ByteArray → List ByteArray →
    Action NodeAnswer
  | [], answer, missing, redacted => pure ⟨answer.payloads, missing, redacted⟩
  | (found, (path, claimed)) :: rest, answer, missing, redacted => do
    match found with
    | none => answerNodes scope origins confined rest answer (distinct missing claimed) redacted
    | some hash =>
      match ← storage (.readBytes nodeSpace hash) with
      | none => answerNodes scope origins confined rest answer (distinct missing hash) redacted
      | some data =>
        if !(← covers origins confined hash) then
          answerNodes scope origins confined rest answer (distinct missing hash) redacted
        else
          let revealed := scope.isFull || match decode data with
            | .ok node => scope.admitsNode path.toList node
            | .error _ => false
          if !revealed then
            answerNodes scope origins confined rest answer missing (distinct redacted hash)
          else if answer.served hash then
            answerNodes scope origins confined rest answer missing redacted
          else
            let answer := answer.push hash data
            if answer.full then pure ⟨answer.payloads, missing, redacted⟩
            else answerNodes scope origins confined rest answer missing redacted

/-- The nodes a peer asked for by position under a root. -/
def serveNodes (root : ByteArray) (wants : List (ByteArray × ByteArray)) (scope : Scope)
    (peerOrigins confined : List String) : Action NodeAnswer := do
  let origins ← headOrigins root
  let admitted ← admit scope root origins peerOrigins wants
  answerNodes scope origins confined (admitted.zip wants) {} [] []

/-- Whether the node at a holder position genuinely carries the value and
may reveal it: coverage, not just position. -/
def carried (scope : Scope) (origins confined : List String) (holder : Option ByteArray)
    (path : Path) (wanted : ByteArray) : Action Bool := do
  match holder with
  | none => return false
  | some hash =>
    if !(← covers origins confined hash) then return false
    match ← storage (.readBytes nodeSpace hash) with
    | none => return false
    | some data =>
      match decode data with
      | .error _ => return false
      | .ok node => return node.valueHashes.contains wanted && scope.admitsValue path node

def answerValues (scope : Scope) (origins confined : List String) :
    List (Option (Option ByteArray) × (ByteArray × ByteArray)) → Answer → List ByteArray →
    Action ValueAnswer
  | [], answer, missing => pure ⟨answer.payloads, missing⟩
  | (holder, (path, wanted)) :: rest, answer, missing => do
    if answer.served wanted then answerValues scope origins confined rest answer missing
    else
      let allowed ← match holder with
        | none => pure true
        | some holder => carried scope origins confined holder path.toList wanted
      if !allowed then answerValues scope origins confined rest answer (distinct missing wanted)
      else
        match ← storage (.readBytes valueSpace wanted) with
        | none => answerValues scope origins confined rest answer (distinct missing wanted)
        | some data =>
          let answer := answer.push wanted data
          if answer.full then pure ⟨answer.payloads, missing⟩
          else answerValues scope origins confined rest answer missing

/-- The out-of-line values a peer asked for, each authorized by the position
of the node that holds it when the peer's view is scoped. -/
def serveValues (root : ByteArray) (wants : List (ByteArray × ByteArray)) (scope : Scope)
    (peerOrigins confined : List String) : Action ValueAnswer := do
  let origins ← headOrigins root
  let holders ← if scope.isFull then pure (wants.map fun _ => none)
    else (admit scope root origins peerOrigins wants).map (·.map some)
  answerValues scope origins confined (holders.zip wants) {} []

end VerifiedCore.Trie.Serve
