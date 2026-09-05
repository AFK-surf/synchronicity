/-!
The trie domain's existing postcard representation. This is internal domain
code, not a codec service exposed to Rust. Local reads deliberately accept
non-minimal varints and trailing bytes, as postcard::from_bytes does. Ingress
canonicality additionally requires equality with `encode`.
-/
namespace VerifiedCore.Trie

inductive Value where
  | inline (bytes : ByteArray)
  | hash (address : ByteArray)

inductive Node where
  | leaf (suffix : ByteArray) (value : Value)
  | extension (segment : ByteArray) (child : ByteArray)
  | branch (children : List (Option ByteArray)) (value : Option Value)

private structure Cursor where
  bytes : ByteArray
  offset : Nat := 0

private abbrev Parser := StateT Cursor (Except String)

private def bytes (count : Nat) : Parser ByteArray := do
  let c ← get
  if c.offset + count > c.bytes.size then
    throw "unexpected end of node"
  set { c with offset := c.offset + count }
  return c.bytes.extract c.offset (c.offset + count)

private def byte : Parser UInt8 := do
  let c ← get
  if c.offset >= c.bytes.size then throw "unexpected end of node"
  set { c with offset := c.offset + 1 }
  return c.bytes[c.offset]!

/-- Postcard uses a bounded unsigned LEB128 for lengths and enum tags. -/
private def varintAux : Nat → Nat → Nat → Nat → Parser Nat
  | 0, _, _, _ => throw "varint overflow"
  | fuel + 1, limit, shift, acc => do
    let b := (← byte).toNat
    if b > limit then throw "varint overflow"
    let acc := acc + (b % 128) * 2 ^ shift
    if b < 128 then return acc
    varintAux fuel (if fuel == 1 then 1 else 255) (shift + 7) acc

private def length : Parser Nat := varintAux 10 255 0 0

/-- Enum variants are encoded as u32, not as host-sized lengths. -/
private def tagAux : Nat → Nat → Nat → Parser Nat
  | 0, _, _ => throw "variant overflow"
  | fuel + 1, shift, acc => do
    let b := (← byte).toNat
    if fuel == 0 && b > 15 then throw "variant overflow"
    let acc := acc + (b % 128) * 2 ^ shift
    if b < 128 then return acc
    tagAux fuel (shift + 7) acc

private def tag : Parser Nat := tagAux 5 0 0

private def sequence : Parser ByteArray := do bytes (← length)

private def nibbles : Parser ByteArray := do
  let ns ← sequence
  if ns.data.any (fun n => n.toNat > 15) then
    throw "nibble is outside the radix-16 alphabet"
  return ns

private def optional (p : Parser α) : Parser (Option α) := do
  match (← byte).toNat with
  | 0 => return none
  | 1 => return some (← p)
  | _ => throw "invalid option tag"

private def value : Parser Value := do
  match ← tag with
  | 0 => return .inline (← sequence)
  | 1 => return .hash (← bytes 32)
  | _ => throw "invalid value variant"

private def children : Nat → Parser (List (Option ByteArray))
  | 0 => return []
  | n + 1 => do
    let child ← optional (bytes 32)
    return child :: (← children n)

private def node : Parser Node := do
  match ← tag with
  | 0 => return .leaf (← nibbles) (← value)
  | 1 => return .extension (← nibbles) (← bytes 32)
  | 2 => return .branch (← children 16) (← optional value)
  | _ => throw "invalid node variant"

/-- Local storage decoding: unused input is intentionally ignored. -/
def decode (input : ByteArray) : Except String Node :=
  (node.run ⟨input, 0⟩).map Prod.fst

private def encodeNat (n : Nat) : List UInt8 :=
  if h : n < 128 then [UInt8.ofNat n]
  else UInt8.ofNat (n % 128 + 128) :: encodeNat (n / 128)
termination_by n
decreasing_by omega

private def encodeSequence (b : ByteArray) : List UInt8 :=
  encodeNat b.size ++ b.toList

private def encodeValue : Value → List UInt8
  | .inline b => 0 :: encodeSequence b
  | .hash h => 1 :: h.toList

private def encodeOption (f : α → List UInt8) : Option α → List UInt8
  | none => [0]
  | some a => 1 :: f a

/-- Canonical bytes for the existing wire format; malformed internal nodes
must not be constructed by callers (hashes have 32 bytes and branches 16 slots).
-/
def encode : Node → ByteArray
  | .leaf suffix v => ⟨(0 :: (encodeSequence suffix ++ encodeValue v)).toArray⟩
  | .extension segment child =>
    ⟨(1 :: (encodeSequence segment ++ child.toList)).toArray⟩
  | .branch cs v =>
    ⟨(2 :: (cs.flatMap (encodeOption ByteArray.toList) ++ encodeOption encodeValue v)).toArray⟩

end VerifiedCore.Trie
