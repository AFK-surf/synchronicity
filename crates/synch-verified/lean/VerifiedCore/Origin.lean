import Std

/-! Origin syntax and base32 decoding are Lean domain logic. `parse` composes
them with a primitive Ed25519 point-validation action; it never asks the host
to parse or normalize an origin. History supplies the separate crypto capability
in production. `parseSyntax` alone does not establish key validity. -/
namespace VerifiedCore.Origin

inductive Error where
  | label (original : String)
  | domain (original : String)
  | keyDecode
  | keyData
  | shape (original : String)
  deriving BEq, DecidableEq

structure Named where
  id : String
  domain : String
  deriving BEq, DecidableEq

def memberChar (c : Char) : Bool :=
  ('a' ≤ c && c ≤ 'z') || ('0' ≤ c && c ≤ '9') || c == '-'

def labelValid (s : String) : Bool :=
  !s.isEmpty && s.utf8ByteSize ≤ 63 && s.toList.all memberChar

def domainLabelValid (s : String) : Bool :=
  labelValid s && s.toList.head? != some '-' && s.toList.getLast? != some '-'

def domainValid (s : String) : Bool :=
  !s.isEmpty && s.utf8ByteSize ≤ 253 &&
    (s.toList.splitOn '.').all (fun cs => domainLabelValid (String.ofList cs))

/-- ASCII-only case conversion preserves non-ASCII inputs for rejection. -/
def lower (s : String) : String := String.ofList (s.toList.map Char.toLower)

def normalizeLabel (s : String) : Except Error String :=
  let normalized := lower s
  if labelValid normalized then .ok normalized else .error (.label s)

/-- All trailing dots are stripped, not merely the last one. Diagnostics retain
the unmodified input, and label validation precedes domain validation. -/
def normalizeDomain (s : String) : Except Error String :=
  let normalized := lower (String.ofList (s.toList.reverse.dropWhile (· == '.')).reverse)
  if domainValid normalized then .ok normalized else .error (.domain s)

def named (id domain : String) : Except Error Named := do
  let id ← normalizeLabel id
  let domain ← normalizeDomain domain
  return ⟨id, domain⟩

/-- Alphabet is case-sensitive, with no padding, ignored bytes or aliases. -/
def alphabet : List Char := "ybndrfg8ejkmcpqxot1uwisza345h769".toList

def decodeDigits : List Char → Nat → Nat → List UInt8 → Except Error (List UInt8)
  | [], _, pending, output =>
    if pending == 0 then .ok output.reverse else .error .keyDecode
  | c :: rest, bits, pending, output =>
    let digit := alphabet.idxOf c
    if digit ≥ 32 then .error .keyDecode else
    let bits := bits + 5
    let pending := pending * 32 + digit
    if bits ≥ 8 then
      let remaining := bits - 8
      let divisor := 2 ^ remaining
      decodeDigits rest remaining (pending % divisor)
        ((pending / divisor).toUInt8 :: output)
    else decodeDigits rest bits pending output

/-- Strict unpadded base32 lengths and zero trailing bits precede the key-width
check, preserving malformed-encoding versus invalid-key diagnostics. -/
def decodeKey (text : List Char) : Except Error (List UInt8) := do
  if !([0, 2, 4, 5, 7].contains (text.length % 8)) then throw .keyDecode
  let bytes ← decodeDigits text 0 0 []
  if bytes.length != 32 then throw .keyData
  return bytes

inductive Parsed where
  | named (value : Named)
  | key (bytes : List UInt8)
  deriving BEq, DecidableEq

def prefixed (s : String) : Bool := ['k', 'e', 'y', ':'].isPrefixOf s.toList

/-- Syntax only: key bytes still require primitive point validation. Literal
`key:` wins over `@`; bare key failures are reported as original-input shape
errors, unlike explicitly prefixed key failures. -/
def parseSyntax (s : String) : Except Error Parsed :=
  if prefixed s then (decodeKey (s.toList.drop 4)).map Parsed.key
  else
    let id := s.toList.takeWhile (· != '@')
    match s.toList.dropWhile (· != '@') with
    | [] => ((decodeKey s.toList).mapError (fun _ => .shape s)).map Parsed.key
    | _ :: domain => (named (String.ofList id) (String.ofList domain)).map Parsed.named

/-- Complete origin parsing composed in Lean. Only byte-level point validity
is delegated; syntax, normalization, diagnostic choice and sequencing stay here.
Host I/O failures belong to the surrounding monad, not to a false key result. -/
def parse [Monad m] (validate : List UInt8 → m Bool) (s : String) :
    m (Except Error Parsed) := do
  match parseSyntax s with
  | .error error => return .error error
  | .ok (.named value) => return .ok (.named value)
  | .ok (.key bytes) =>
    if ← validate bytes then return .ok (.key bytes)
    else return .error (if prefixed s then .keyData else .shape s)

def checkSyntax (s : String) : Except Error Unit := (parseSyntax s).map (fun _ => ())

end VerifiedCore.Origin
