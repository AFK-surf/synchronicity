import Init

/-! Domain-neutral, executable host effects. No storage policy belongs here. -/
namespace VerifiedCore.Host

inductive Program (E : Type → Type) (A : Type) : Type 1 where
  | pure (value : A)
  | request {B : Type} (effect : E B) (resume : B → Program E A)

def Program.bind (program : Program E A) (next : A → Program E B) : Program E B :=
  match program with
  | .pure value => next value
  | .request effect resume => .request effect (fun reply => (resume reply).bind next)

instance : Monad (Program E) where
  pure := Program.pure
  bind := Program.bind

/-- Code 1 tokens identify original host errors retained by the interpreter.
Code 2 uses the token as domain error detail (zero for an unspecified malformed
record), never as a host-error registry index. Code 3 is a protocol failure. -/
structure Failure where
  code : UInt32
  token : UInt64
  deriving BEq, DecidableEq, Repr

abbrev Reply (A : Type) := Except Failure A
abbrev Transaction := UInt64

inductive Cell where
  | null
  | integer (value : Int64)
  | text (value : String)
  | blob (value : ByteArray)
  deriving BEq

abbrev Row := List Cell
abbrev Fields := List (String × Cell)

/-- Identifiers are host-whitelisted storage names, never executable SQL.
Read projections preserve absent rows, NULL, types and order of columns.
An empty equality filter scans the relation; it does not infer domain policy. -/
inductive Storage : Type → Type where
  | begin : Storage (Reply Transaction)
  | commit (tx : Transaction) : Storage (Reply Unit)
  | rollback (tx : Transaction) : Storage (Reply Unit)
  | readRows (tx : Transaction) (relation : String)
      (columns : List String) (equals : Fields) : Storage (Reply (List Row))
  | upsert (tx : Transaction) (relation : String) (values : Fields)
      (conflictColumns updateColumns : List String) : Storage (Reply Unit)
  | deleteRows (tx : Transaction) (relation : String)
      (equals : Fields) : Storage (Reply Nat)
  | readBytes (space : String) (key : ByteArray) : Storage (Reply (Option ByteArray))
  /-- Bounded access to an immutable command input, borrowed for this run. -/
  | readInput (handle offset count : UInt64) : Storage (Reply ByteArray)
  | readCounter (space : String) (key : ByteArray) : Storage (Reply UInt64)
  | removeFile (space : String) (key : ByteArray) : Storage (Reply Unit)
  | existsRows (tx : Transaction) (relation : String) (equals : Fields) : Storage (Reply Bool)

abbrev Operation (A : Type) := ExceptT Failure (Program Storage) A

def perform (effect : Storage (Reply A)) : Operation A :=
  ExceptT.mk (.request effect .pure)

/-- Immediate transaction. A failed body or commit requests rollback, whose
failure must not replace the primary failure. Host RAII handles abandonment;
it does not choose domain recovery or report a failed commit as success. -/
def transaction (body : Transaction → Operation A) : Operation A := ExceptT.mk do
  match ← (perform .begin).run with
  | .error failure => pure (.error failure)
  | .ok tx =>
    match ← (body tx).run with
    | .error failure =>
      let _ ← (perform (.rollback tx)).run
      pure (.error failure)
    | .ok value =>
      match ← (perform (.commit tx)).run with
      | .ok () => pure (.ok value)
      | .error failure =>
        let _ ← (perform (.rollback tx)).run
        pure (.error failure)

end VerifiedCore.Host
