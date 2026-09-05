import Std

/-! Origin syntax is domain logic, shared by Lean operations rather than supplied
as a host validation service. Key decoding/curve validation is not implemented
here yet; `checkNamedText` deliberately checks only the named branch. -/
namespace VerifiedCore.Origin

inductive Error where
  | label (original : String)
  | domain (original : String)
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

/-- Preserve parser precedence: literal `key:` wins over an embedded `@`.
Only the first `@` separates the member from its domain. Key and bare forms
must additionally pass key decoding/validation before production cutover. -/
def checkNamedText (s : String) : Except Error Unit :=
  if ['k', 'e', 'y', ':'].isPrefixOf s.toList then .ok ()
  else
    let id := s.toList.takeWhile (· != '@')
    match s.toList.dropWhile (· != '@') with
    | [] => .ok ()
    | _ :: domain => (named (String.ofList id) (String.ofList domain)).map (fun _ => ())

end VerifiedCore.Origin
