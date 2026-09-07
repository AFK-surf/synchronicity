/-! Shared postcard unsigned integers and vectors. The parser accepts
non-minimal encodings and leaves trailing bytes to its caller. The tenth
byte of an unsigned integer may carry only its highest bit. -/
namespace VerifiedCore.Postcard

/-- A parser answers its value and the octets after it, or why it stopped. -/
abbrev Parser (α : Type) := List UInt8 → Except String (α × List UInt8)

def parseByte : Parser UInt8
  | [] => .error "unexpected end of node"
  | b :: rest => .ok (b, rest)

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

def leb128 (n : Nat) : List UInt8 :=
  if n < 128 then [n.toUInt8] else (n % 128 + 128).toUInt8 :: leb128 (n / 128)
termination_by n
decreasing_by omega

/-- A vector of unsigned pairs, including its postcard length prefix. The
byte-count check rejects impossible counts before allocating or recursing. -/
def parsePairsInto : Nat → List (Nat × Nat) → Parser (List (Nat × Nat))
  | 0, acc, input => .ok (acc.reverse, input)
  | n + 1, acc, input => do
    let (first, rest) ← parseLength input
    let (second, rest) ← parseLength rest
    parsePairsInto n ((first, second) :: acc) rest

def parsePairs (count : Nat) : Parser (List (Nat × Nat)) := parsePairsInto count []

def parsePairList : Parser (List (Nat × Nat)) := fun input => do
  let (count, rest) ← parseLength input
  if count > rest.length / 2 then .error "impossible pair count"
  else parsePairs count rest

def encodePairs (pairs : List (Nat × Nat)) : List UInt8 :=
  pairs.flatMap fun (first, second) => leb128 first ++ leb128 second

def encodePairList (pairs : List (Nat × Nat)) : List UInt8 :=
  leb128 pairs.length ++ encodePairs pairs

end VerifiedCore.Postcard
