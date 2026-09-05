import Synchronicity.TrieProgramProofs

/-! Executable wire and storage traces for the actual linked lookup program.
Fixtures use the established postcard bytes, not a Rust policy oracle. -/
namespace Synchronicity.TrieProgramTests
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie

private def b (bytes : List UInt8) : ByteArray := ⟨bytes.toArray⟩
private def address (value : UInt8) : ByteArray := b (List.replicate 32 value)
private def root : ByteArray := address 1

private def resultView : Reply LookupResult → Nat × List UInt8
  | .error failure => (100 + failure.code.toNat, [])
  | .ok (.error (.keyTooLong _)) => (2, [])
  | .ok (.error (.missingNode h)) => (3, h.toList)
  | .ok (.error (.missingValue h)) => (4, h.toList)
  | .ok (.error (.decode _)) => (5, [])
  | .ok (.error .depthExceeded) => (6, [])
  | .ok (.ok none) => (0, [])
  | .ok (.ok (some bytes)) => (1, bytes.toList)

/-- A script must consume exactly its replies. Unexpected non-read effects,
extra reads, or extra supplied replies all make the test fail. -/
private def run : List (Reply (Option ByteArray)) → Program Storage (Reply LookupResult) →
    Option ((Nat × List UInt8) × List (String × List UInt8))
  | [], .pure answer => some (resultView answer, [])
  | _ :: _, .pure _ => none
  | [], .request _ _ => none
  | reply :: replies, .request (.readBytes space key) next => do
    let (answer, trace) ← run replies (next reply)
    return (answer, (space, key.toList) :: trace)
  | _ :: _, .request .begin _ => none
  | _ :: _, .request (.commit _) _ => none
  | _ :: _, .request (.rollback _) _ => none
  | _ :: _, .request (.readRows _ _ _ _) _ => none
  | _ :: _, .request (.upsert _ _ _ _ _) _ => none
  | _ :: _, .request (.deleteRows _ _ _) _ => none
  | _ :: _, .request (.readInput _ _ _) _ => none

private def succeeds (key : List UInt8) (nodes : List ByteArray)
    (payload : List UInt8) (trace : List (String × ByteArray)) : Bool :=
  run (nodes.map (fun bytes => .ok (some bytes))) (Trie.get root (b key)).run ==
    some ((1, payload), trace.map (fun (space, hash) => (space, hash.toList)))

-- Leaf with a two-nibble key [10,11], inline value "xy".
#guard succeeds [171] [b [0, 2, 10, 11, 0, 2, 120, 121]] [120, 121]
  [(nodeSpace, root)]

-- Enum and length varints may be nonminimal in local persisted data.
-- Trailing bytes are ignored locally, never at the canonical ingest boundary.
#guard succeeds [171] [b [128, 0, 130, 0, 10, 11, 0, 1, 7, 99]] [7]
  [(nodeSpace, root)]

-- Out-of-line resolution is a second raw read, not a host-supplied shape.
#guard succeeds [] [b ([0, 0, 1] ++ (address 8).toList), b [9, 8, 7]] [9, 8, 7]
  [(nodeSpace, root), (valueSpace, address 8)]

-- Extension consumes a nibble, branch consumes another, leaf resolves.
private def branch : ByteArray :=
  b ([2] ++ List.replicate 11 0 ++ [1] ++ (address 3).toList ++ List.replicate 4 0 ++ [0])
#guard succeeds [171]
  [b ([1, 1, 10] ++ (address 2).toList), branch, b [0, 0, 0, 1, 42]] [42]
  [(nodeSpace, root), (nodeSpace, address 2), (nodeSpace, address 3)]

-- A branch value does not require descent when the whole key is consumed.
#guard succeeds [] [b ([2] ++ List.replicate 16 0 ++ [1, 0, 1, 9])] [9]
  [(nodeSpace, root)]

-- Zero-valued children are addresses, although a zero root means empty.
#guard succeeds [16]
  [b ([1, 2, 1, 0] ++ (address 0).toList), b [0, 0, 0, 1, 42]] [42]
  [(nodeSpace, root), (nodeSpace, address 0)]
#guard run [] (Trie.get (address 0) (b [])).run == some ((0, []), [])

-- An empty extension is refused by lookup without fetching its child.
#guard run [.ok (some (b ([1, 0] ++ (address 2).toList)))]
  (Trie.get root (b [])).run == some ((0, []), [(nodeSpace, root.toList)])

-- Missing and failed node/value reads remain distinct.
#guard run [.ok none] (Trie.get root (b [])).run ==
  some ((3, root.toList), [(nodeSpace, root.toList)])
#guard run [.ok (some (b ([0, 0, 1] ++ (address 8).toList))), .ok none]
  (Trie.get root (b [])).run ==
  some ((4, (address 8).toList), [(nodeSpace, root.toList), (valueSpace, (address 8).toList)])
#guard run [.error ⟨7, 19⟩] (Trie.get root (b [])).run ==
  some ((107, []), [(nodeSpace, root.toList)])

-- Invalid nibble, u32 variant overflow, usize overflow and truncated hashes.
private def malformed (raw : List UInt8) : Bool :=
  run [.ok (some (b raw))] (Trie.get root (b [])).run ==
    some ((5, []), [(nodeSpace, root.toList)])
#guard malformed [0, 1, 16, 0, 0]
#guard malformed [128, 128, 128, 128, 16]
#guard malformed ([0] ++ List.replicate 9 128 ++ [2])
#guard malformed [0, 0, 1, 2]
#guard malformed [2, 3]

-- Bounds are checked before reading even a nonzero root.
#guard run [] (Trie.get root (b (List.replicate 4097 0))).run == some ((2, []), [])

-- Encoder fixtures pin the hash-covered existing bytes without using serde.
#guard (encode (.leaf (b [10, 11]) (.inline (b [120, 121])))).toList ==
  [0, 2, 10, 11, 0, 2, 120, 121]
#guard (encode (.extension (b [10]) (address 2))).toList ==
  [1, 1, 10] ++ (address 2).toList

end Synchronicity.TrieProgramTests
