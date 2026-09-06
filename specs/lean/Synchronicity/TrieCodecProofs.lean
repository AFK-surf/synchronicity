import VerifiedCore.Trie.Codec

/-! The trie codec both ways: the encoder the write path and the ingress
boundary share produces exactly what the permissive decoder reads back, for
every well-formed node. These are proofs about the executable parsers, by
structural induction over the octets they consume. -/
namespace Synchronicity.TrieCodecProofs
open VerifiedCore.Trie

@[simp] theorem bind_ok (a : α) (f : α → Except ε β) : (Except.ok a >>= f) = f a := rfl
@[simp] theorem map_ok (f : α → β) (a : α) : Except.map f (.ok a : Except ε α) = .ok (f a) := rfl

theorem toNat_ofNat_of_lt {n : Nat} (h : n < 256) : (UInt8.ofNat n).toNat = n :=
  UInt8.toNat_ofNat_of_lt' h

/-! ## Octets -/

theorem byte_cons (b : UInt8) (rest : List UInt8) : parseByte (b :: rest) = .ok (b, rest) := rfl

theorem takeOctets_append (bs rest : List UInt8) : takeOctets bs.length (bs ++ rest) = .ok (bs, rest) := by
  induction bs with
  | nil => rfl
  | cons b bs ih => simp [takeOctets, ih]

/-! ## Varints -/

/-- How large a value a varint of `fuel` remaining bytes may still carry: the
last byte may only carry the top bit of a u64. -/
def bound : Nat → Nat
  | 0 => 1
  | 1 => 2
  | k + 2 => 128 * bound (k + 1)

theorem bound_ten : bound 10 = 2 ^ 64 := by decide

theorem leb128_small {n : Nat} (h : n < 128) : leb128 n = [n.toUInt8] := by
  rw [leb128]; simp [h]

theorem leb128_large {n : Nat} (h : 128 ≤ n) :
    leb128 n = (n % 128 + 128).toUInt8 :: leb128 (n / 128) := by
  rw [leb128]; simp [Nat.not_lt.mpr h]

theorem varint_roundtrip (fuel : Nat) : ∀ (n shift acc : Nat) (rest : List UInt8),
    1 ≤ fuel → n < bound fuel →
    varintAux fuel (if fuel == 1 then 1 else 255) shift acc (leb128 n ++ rest) =
      .ok (acc + n * 2 ^ shift, rest) := by
  induction fuel with
  | zero => intro _ _ _ _ h; omega
  | succ fuel ih =>
    intro n shift acc rest _ small
    cases fuel with
    | zero =>
      -- The last byte: at most the top bit of a u64.
      simp only [bound] at small
      have lt : n < 128 := by omega
      have mod : n % 128 = n := Nat.mod_eq_of_lt lt
      show varintAux 1 1 shift acc (leb128 n ++ rest) = _
      rw [leb128_small lt, varintAux]
      simp only [List.cons_append, byte_cons, bind_ok, toNat_ofNat_of_lt (by omega : n < 256)]
      simp [show ¬ (1 < n) by omega, lt, mod]
    | succ fuel =>
      simp only [bound] at small
      show varintAux (fuel + 2) 255 shift acc (leb128 n ++ rest) = _
      by_cases lt : n < 128
      · have mod : n % 128 = n := Nat.mod_eq_of_lt lt
        rw [leb128_small lt, varintAux]
        simp only [List.cons_append, byte_cons, bind_ok, toNat_ofNat_of_lt (by omega : n < 256)]
        simp [show ¬ (255 < n) by omega, lt, mod]
      · have ge : 128 ≤ n := Nat.not_lt.mp lt
        have head : n % 128 + 128 < 256 := by omega
        have below : n / 128 < bound (fuel + 1) := by omega
        have step := ih (n / 128) (shift + 7) (acc + (n % 128 + 128) % 128 * 2 ^ shift) rest
          (by omega) below
        rw [leb128_large ge, varintAux]
        simp only [List.cons_append, byte_cons, bind_ok, toNat_ofNat_of_lt head]
        simp only [show ¬ (n % 128 + 128 > 255) by omega, show ¬ (n % 128 + 128 < 128) by omega,
          ↓reduceIte]
        rw [step]
        congr 2
        have mod : (n % 128 + 128) % 128 = n % 128 := by omega
        have split : n = n % 128 + 128 * (n / 128) := (Nat.mod_add_div n 128).symm
        rw [mod, Nat.pow_add]
        conv => rhs; rw [split]
        rw [Nat.add_mul, Nat.add_assoc, show (2 : Nat) ^ 7 = 128 by decide]
        ac_rfl

theorem length_roundtrip {n : Nat} (h : n < 2 ^ 64) (rest : List UInt8) :
    parseLength (leb128 n ++ rest) = .ok (n, rest) := by
  have := varint_roundtrip 10 n 0 0 rest (by omega) (by rw [bound_ten]; exact h)
  simpa [parseLength] using this

theorem tag_small {t : Nat} (h : t < 16) (rest : List UInt8) :
    parseTag (t.toUInt8 :: rest) = .ok (t, rest) := by
  have mod : t % 128 = t := Nat.mod_eq_of_lt (by omega)
  rw [parseTag, tagAux]
  simp only [byte_cons, bind_ok, toNat_ofNat_of_lt (by omega : t < 256)]
  simp [show t < 128 by omega, mod]

/-! ## Fields -/

theorem sequence_roundtrip {bs : List UInt8} (h : bs.length < 2 ^ 64) (rest : List UInt8) :
    parseSequence (leb128 bs.length ++ bs ++ rest) = .ok (bs, rest) := by
  simp only [parseSequence, List.append_assoc, length_roundtrip h, bind_ok, takeOctets_append]

theorem nibbles_roundtrip {ns : ByteArray} (wf : nibblesWf ns) (rest : List UInt8) :
    parseNibbles (leb128 ns.size ++ ns.data.toList ++ rest) = .ok (ns, rest) := by
  obtain ⟨small, alphabet⟩ := wf
  have len : ns.data.toList.length = ns.size := Array.length_toList
  have seq := sequence_roundtrip (bs := ns.data.toList) (by rw [len]; exact small) rest
  rw [len] at seq
  simp only [parseNibbles, seq, bind_ok]
  have none : ns.data.toList.any (fun n => n.toNat > 15) = false := by
    rw [List.any_eq_false]
    intro n mem
    have := alphabet n mem
    simp; omega
  simp [none]

theorem optional_none (p : Parser α) (rest : List UInt8) :
    parseOptional p (0 :: rest) = .ok (none, rest) := rfl

theorem optional_some (p : Parser α) (input : List UInt8) :
    parseOptional p (1 :: input) =
      (p input).map fun (v, rest) => (some v, rest) := rfl

theorem address_roundtrip {h : ByteArray} (width : h.size = 32) (rest : List UInt8) :
    parseAddress (h.data.toList ++ rest) = .ok (h, rest) := by
  have len : h.data.toList.length = 32 := by rw [Array.length_toList]; exact width
  simp only [parseAddress]
  rw [← len, takeOctets_append]
  simp

theorem value_roundtrip {v : Value} (wf : v.wf) (rest : List UInt8) :
    parseValue (encodeValue v ++ rest) = .ok (v, rest) := by
  cases v with
  | inline bytes =>
    simp only [Value.wf] at wf
    have len : bytes.data.toList.length = bytes.size := Array.length_toList
    have seq := sequence_roundtrip (bs := bytes.data.toList) (by rw [len]; exact wf) rest
    rw [len] at seq
    simp only [encodeValue, List.cons_append]
    rw [show (0 : UInt8) = (0 : Nat).toUInt8 from rfl, parseValue, tag_small (by omega)]
    simp only [bind_ok]
    rw [seq]
    simp
  | hash h =>
    simp only [Value.wf] at wf
    simp only [encodeValue, List.cons_append]
    rw [show (1 : UInt8) = (1 : Nat).toUInt8 from rfl, parseValue, tag_small (by omega)]
    simp [address_roundtrip wf]

theorem children_roundtrip (cs : List (Option ByteArray))
    (wf : ∀ child ∈ cs, ∀ h, child = some h → h.size = 32) (rest : List UInt8) :
    parseChildren cs.length (encodeChildren cs ++ rest) = .ok (cs, rest) := by
  induction cs with
  | nil => rfl
  | cons child cs ih =>
    have tail := ih (fun c mem h eq => wf c (List.mem_cons_of_mem _ mem) h eq)
    cases child with
    | none =>
      simp only [encodeChildren, List.length_cons, parseChildren, List.cons_append, optional_none,
        bind_ok]
      simp [tail]
    | some h =>
      have width := wf (some h) (List.mem_cons_self ..) h rfl
      simp only [encodeChildren, List.length_cons, parseChildren, List.cons_append, optional_some,
        List.append_assoc, address_roundtrip width, map_ok, bind_ok]
      simp [tail]

/-! ## Nodes -/

theorem node_roundtrip {n : Node} (wf : n.wf) (rest : List UInt8) :
    parseNode (encodeNode n ++ rest) = .ok (n, rest) := by
  cases n with
  | leaf suffix v =>
    obtain ⟨nib, val⟩ := wf
    simp only [encodeNode, List.cons_append, List.append_assoc]
    rw [show (0 : UInt8) = (0 : Nat).toUInt8 from rfl, parseNode, tag_small (by omega)]
    simp only [bind_ok]
    rw [← List.append_assoc, nibbles_roundtrip nib]
    simp [value_roundtrip val]
  | extension segment child =>
    obtain ⟨nib, width⟩ := wf
    simp only [encodeNode, List.cons_append, List.append_assoc]
    rw [show (1 : UInt8) = (1 : Nat).toUInt8 from rfl, parseNode, tag_small (by omega)]
    simp only [bind_ok]
    rw [← List.append_assoc, nibbles_roundtrip nib]
    simp [address_roundtrip width]
  | branch cs v =>
    obtain ⟨len, widths, val⟩ := wf
    simp only [encodeNode, List.cons_append, List.append_assoc]
    rw [show (2 : UInt8) = (2 : Nat).toUInt8 from rfl, parseNode, tag_small (by omega)]
    simp only [bind_ok]
    have kids := children_roundtrip cs widths
    rw [len] at kids
    cases v with
    | none => simp [kids, optional_none]
    | some v =>
      have := value_roundtrip (val v rfl) rest
      simp [kids, optional_some, this]

/-- The decoder reads back exactly what the encoder wrote, for every
well-formed node. -/
theorem decode_encode {n : Node} (wf : n.wf) : decode (encode n) = .ok n := by
  simp only [decode, encode, List.toList_toArray]
  rw [← List.append_nil (encodeNode n), node_roundtrip wf]
  rfl

end Synchronicity.TrieCodecProofs
