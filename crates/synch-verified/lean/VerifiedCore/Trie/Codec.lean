/-!
The trie domain's existing postcard representation, both directions. This is
internal domain code, not a codec service exposed to Rust. Local reads
deliberately accept non-minimal varints and trailing bytes, as
postcard::from_bytes does; the canonical ingress check (`Trie/Verify.lean`)
re-encodes what it decoded and refuses anything that differs.

Parsers consume a list of octets and return what remains, so the proofs about
them are ordinary structural inductions rather than cursor arithmetic.
-/
namespace VerifiedCore.Trie

inductive Value where
  | inline (bytes : ByteArray)
  | hash (address : ByteArray)
  deriving BEq, DecidableEq

inductive Node where
  | leaf (suffix : ByteArray) (value : Value)
  | extension (segment : ByteArray) (child : ByteArray)
  | branch (children : List (Option ByteArray)) (value : Option Value)
  deriving BEq, DecidableEq

/-- A parser answers its value and the octets after it, or why it stopped. -/
abbrev Parser (α : Type) := List UInt8 → Except String (α × List UInt8)

def parseByte : Parser UInt8
  | [] => .error "unexpected end of node"
  | b :: rest => .ok (b, rest)

def takeOctets : Nat → Parser (List UInt8)
  | 0, input => .ok ([], input)
  | _ + 1, [] => .error "unexpected end of node"
  | n + 1, b :: rest => (takeOctets n rest).map fun (bs, rest) => (b :: bs, rest)

/-- Postcard uses a bounded unsigned LEB128 for lengths and enum tags. The
tenth byte of a length may carry only the top bit of a u64. -/
def varintAux : Nat → Nat → Nat → Nat → Parser Nat
  | 0, _, _, _, _ => .error "varint overflow"
  | fuel + 1, limit, shift, acc, input => do
    let (b, rest) ← parseByte input
    let b := b.toNat
    if b > limit then .error "varint overflow"
    else
      let acc := acc + (b % 128) * 2 ^ shift
      if b < 128 then .ok (acc, rest)
      else varintAux fuel (if fuel == 1 then 1 else 255) (shift + 7) acc rest

def parseLength : Parser Nat := varintAux 10 255 0 0

/-- Enum variants are encoded as u32, not as host-sized lengths. -/
def tagAux : Nat → Nat → Nat → Parser Nat
  | 0, _, _, _ => .error "variant overflow"
  | fuel + 1, shift, acc, input => do
    let (b, rest) ← parseByte input
    let b := b.toNat
    if fuel == 0 && b > 15 then .error "variant overflow"
    else
      let acc := acc + (b % 128) * 2 ^ shift
      if b < 128 then .ok (acc, rest)
      else tagAux fuel (shift + 7) acc rest

def parseTag : Parser Nat := tagAux 5 0 0

def parseSequence : Parser (List UInt8) := fun input => do
  let (count, rest) ← parseLength input
  takeOctets count rest

def parseNibbles : Parser ByteArray := fun input => do
  let (ns, rest) ← parseSequence input
  if ns.any (fun n => n.toNat > 15) then .error "nibble is outside the radix-16 alphabet"
  else .ok (⟨ns.toArray⟩, rest)

def parseOptional (p : Parser α) : Parser (Option α) := fun input => do
  let (b, rest) ← parseByte input
  match b.toNat with
  | 0 => .ok (none, rest)
  | 1 => (p rest).map fun (v, rest) => (some v, rest)
  | _ => .error "invalid option tag"

def parseAddress : Parser ByteArray := fun input =>
  (takeOctets 32 input).map fun (bs, rest) => (⟨bs.toArray⟩, rest)

def parseValue : Parser Value := fun input => do
  let (t, rest) ← parseTag input
  match t with
  | 0 => (parseSequence rest).map fun (bs, rest) => (.inline ⟨bs.toArray⟩, rest)
  | 1 => (parseAddress rest).map fun (h, rest) => (.hash h, rest)
  | _ => .error "invalid value variant"

def parseChildren : Nat → Parser (List (Option ByteArray))
  | 0, input => .ok ([], input)
  | n + 1, input => do
    let (child, rest) ← parseOptional parseAddress input
    let (more, rest) ← parseChildren n rest
    .ok (child :: more, rest)

def parseNode : Parser Node := fun input => do
  let (t, rest) ← parseTag input
  match t with
  | 0 => do
    let (suffix, rest) ← parseNibbles rest
    let (v, rest) ← parseValue rest
    .ok (.leaf suffix v, rest)
  | 1 => do
    let (segment, rest) ← parseNibbles rest
    let (child, rest) ← parseAddress rest
    .ok (.extension segment child, rest)
  | 2 => do
    let (cs, rest) ← parseChildren 16 rest
    let (v, rest) ← parseOptional parseValue rest
    .ok (.branch cs v, rest)
  | _ => .error "invalid node variant"

/-- Local storage decoding: unused input is intentionally ignored. -/
def decode (input : ByteArray) : Except String Node :=
  (parseNode input.data.toList).map Prod.fst

/-! ## The encoder

What the write path stores and what the ingress boundary compares against.
Minimal LEB128 lengths, u32 enum tags, one byte per option, raw 32-byte
addresses: the postcard bytes `synch-mpt`'s derived `Serialize` produces. -/

def leb128 (n : Nat) : List UInt8 :=
  if n < 128 then [n.toUInt8] else (n % 128 + 128).toUInt8 :: leb128 (n / 128)
termination_by n
decreasing_by omega

def encodeValue : Value → List UInt8
  | .inline bytes => 0 :: (leb128 bytes.size ++ bytes.data.toList)
  | .hash address => 1 :: address.data.toList

def encodeChildren : List (Option ByteArray) → List UInt8
  | [] => []
  | none :: rest => 0 :: encodeChildren rest
  | some child :: rest => 1 :: (child.data.toList ++ encodeChildren rest)

def encodeNode : Node → List UInt8
  | .leaf suffix v => 0 :: (leb128 suffix.size ++ suffix.data.toList ++ encodeValue v)
  | .extension segment child =>
    1 :: (leb128 segment.size ++ segment.data.toList ++ child.data.toList)
  | .branch cs v =>
    2 :: (encodeChildren cs ++ (match v with
      | none => [0]
      | some v => 1 :: encodeValue v))

def encode (n : Node) : ByteArray := ⟨(encodeNode n).toArray⟩

/-! ## Well-formed nodes

The nodes the encoder can produce a decodable image of: nibbles inside the
radix-16 alphabet, lengths representable on the wire, addresses of the fixed
width, and exactly sixteen child slots. Every node the decoder returns is
well formed; the roundtrip theorems quantify over this predicate. -/

def nibblesWf (ns : ByteArray) : Prop :=
  ns.size < 2 ^ 64 ∧ ∀ n ∈ ns.data.toList, n.toNat ≤ 15

def Value.wf : Value → Prop
  | .inline bytes => bytes.size < 2 ^ 64
  | .hash address => address.size = 32

def Node.wf : Node → Prop
  | .leaf suffix v => nibblesWf suffix ∧ v.wf
  | .extension segment child => nibblesWf segment ∧ child.size = 32
  | .branch cs v =>
    cs.length = 16 ∧ (∀ child ∈ cs, ∀ h, child = some h → h.size = 32) ∧
      (∀ x, v = some x → x.wf)

end VerifiedCore.Trie
