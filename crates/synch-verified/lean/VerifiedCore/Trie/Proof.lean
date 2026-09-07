import VerifiedCore.Trie.Program
import VerifiedCore.Trie.Verify

/-! Merkle proofs for single keys: the node path from the root down to where
a key resolves, or to where it provably dead-ends, with the out-of-line
payload when the value is one. Proving is the lookup with its node trace;
verifying is the lookup again, over the proof's own nodes as a raw snapshot
addressed by their digests, so a prover cannot claim absence by omission: a
path the proof does not cover is a missing node, not an absence. -/
namespace VerifiedCore.Trie.Proof

open Host

/-- The encoded nodes on the path from the root, root first, and the
out-of-line payload when the proved value is not inline. -/
structure Proof where
  nodes : List ByteArray
  value : Option ByteArray
  deriving BEq, DecidableEq

abbrev Result := Except LookupError Proof

/-- The proof ends where a value was found: the payload travels with it
when it is out of line. -/
def found (value : Value) (nodes : List ByteArray) : Operation Result := do
  match value with
  | .inline _ => return .ok ⟨nodes.reverse, none⟩
  | .hash address =>
    match ← perform (.readBytes valueSpace address) with
    | none => return .error (.missingValue address)
    | some bytes => return .ok ⟨nodes.reverse, some bytes⟩

/-- `lookup`, recording each node it reads. The nodes are accumulated
newest first and reversed once. -/
def proveAt : Nat → Option ByteArray → List UInt8 → List ByteArray → Operation Result
  | 0, _, _, _ => pure (.error .depthExceeded)
  | _ + 1, none, _, nodes => pure (.ok ⟨nodes.reverse, none⟩)
  | fuel + 1, some address, rest, nodes => do
    match ← perform (.readBytes nodeSpace address) with
    | none => return .error (.missingNode address)
    | some raw =>
      let nodes := raw :: nodes
      match decode raw with
      | .error message => return .error (.decode message)
      | .ok (.leaf suffix value) =>
        if suffix.toList == rest then found value nodes else return .ok ⟨nodes.reverse, none⟩
      | .ok (.extension segment child) =>
        let path := segment.toList
        if path.isEmpty || !path.isPrefixOf rest then return .ok ⟨nodes.reverse, none⟩
        proveAt fuel (some child) (rest.drop path.length) nodes
      | .ok (.branch children value) =>
        match rest with
        | [] =>
          match value with
          | none => return .ok ⟨nodes.reverse, none⟩
          | some value => found value nodes
        | nibble :: rest => proveAt fuel ((children[nibble.toNat]?).getD none) rest nodes
      | .ok (.route children value) =>
        match rest with
        | [] =>
          match value with
          | none => return .ok ⟨nodes.reverse, none⟩
          | some address => found (.hash address) nodes
        | nibble :: rest => proveAt fuel ((children[nibble.toNat]?).getD none) rest nodes

/-- The proof for a key against a root: the same descent as `get`, under
the same bounds, with every node it read. -/
def prove (root key : ByteArray) : Operation Result :=
  if key.size > maxKeyBytes then pure (.error (.keyTooLong key.size))
  else proveAt (maxKeyBytes * 2 + 1) (rootOf root) (keyNibbles key) []

/-- The native command borrows its key, as `getInput` does. -/
def proveInput (root : ByteArray) (handle keySize : UInt64) : Operation Result := do
  if keySize.toNat > maxKeyBytes then return .error (.keyTooLong keySize.toNat)
  let key ← perform (.readInput handle 0 keySize)
  if key.size != keySize.toNat then throw ⟨3, 0⟩
  prove root key

/-! ## Verification -/

/-- Why a proof does not verify: one of its nodes is not a canonical node
at all, or the lookup over its nodes fails, a truncated path reading as a
missing node and a substituted payload as a missing value. -/
inductive VerifyError where
  | refused (refusal : Refusal)
  | lookup (error : LookupError)

/-- A raw snapshot: what a byte read answers, by namespace and key. -/
abbrev RawSnapshot := String → ByteArray → Option ByteArray

/-- Runs a program that only reads bytes against a raw snapshot, within a
budget of reads; any other effect, or a budget spent, is no answer. -/
def executeReads (store : RawSnapshot) : Nat → Program Storage A → Option A
  | _, .pure result => some result
  | 0, .request _ _ => none
  | fuel + 1, .request (.readBytes space key) next =>
    executeReads store fuel (next (.ok (store space key)))
  | _ + 1, .request .begin _ => none
  | _ + 1, .request (.commit _) _ => none
  | _ + 1, .request (.rollback _) _ => none
  | _ + 1, .request (.readRows _ _ _ _ _ _) _ => none
  | _ + 1, .request (.scanRows _ _ _ _ _ _) _ => none
  | _ + 1, .request (.upsert _ _ _ _ _) _ => none
  | _ + 1, .request (.deleteRows _ _ _ _ _) _ => none
  | _ + 1, .request (.readInput _ _ _) _ => none
  | _ + 1, .request (.readCounter _ _) _ => none
  | _ + 1, .request (.removeFile _ _) _ => none
  | _ + 1, .request (.existsRows _ _ _) _ => none
  | _ + 1, .request (.deleteExcept _ _ _ _) _ => none

/-- The snapshot a proof stands for: each node under its address, the
payload under its digest, nothing else. -/
def snapshotOf (nodes : List (ByteArray × ByteArray)) (payload : Option (ByteArray × ByteArray)) :
    RawSnapshot := fun space key =>
  if space == nodeSpace then (nodes.find? fun entry => entry.1 == key).map (·.2)
  else if space == valueSpace then
    payload.bind fun entry => if entry.1 == key then some entry.2 else none
  else none

/-- What a lookup answers over a proof's snapshot; a budget the lookup
cannot spend, since it reads at most one node per nibble and one payload. -/
def check (root key : ByteArray) (nodes : List (ByteArray × ByteArray))
    (payload : Option (ByteArray × ByteArray)) : Option (Reply LookupResult) :=
  executeReads (snapshotOf nodes payload) (maxKeyBytes * 2 + 2) (get root key).run

def digest [Inject Digest E] (bytes : ByteArray) : OperationOver E Failure ByteArray :=
  raise id (Digest.blake3 bytes)

/-- Each node under the address its bytes are stored under: the digest of
its kind's tag and the bytes, once the bytes are admitted as a canonical
node. A node that is not one refuses the proof whole. -/
def addressNodes [Inject Digest E] : List ByteArray →
    OperationOver E Failure (Except Refusal (List (ByteArray × ByteArray)))
  | [] => pure (.ok [])
  | raw :: rest => do
    match admit raw with
    | .error refusal => return .error refusal
    | .ok node =>
      let hash ← digest (tagOf node ++ raw)
      match ← addressNodes rest with
      | .error refusal => return .error refusal
      | .ok addressed => return .ok ((hash, raw) :: addressed)

/-- Verifies a proof against a root for a key: the lookup over the proof's
nodes as a raw snapshot, answering the proved value or an absence. -/
def verify [Inject Digest E] (root key : ByteArray) (nodes : List ByteArray) (value : Option ByteArray) :
    OperationOver E Failure (Except VerifyError (Option ByteArray)) := do
  let addressed ← match ← addressNodes nodes with
    | .error refusal => return .error (.refused refusal)
    | .ok addressed => pure addressed
  let payload : Option (ByteArray × ByteArray) ← match value with
    | none => pure none
    | some bytes => do
      let hash ← digest bytes
      pure (some (hash, bytes))
  match check root key addressed payload with
  | some (.ok result) => return result.mapError .lookup
  | some (.error failure) => throw failure
  | none => throw ⟨3, 0⟩

end VerifiedCore.Trie.Proof
