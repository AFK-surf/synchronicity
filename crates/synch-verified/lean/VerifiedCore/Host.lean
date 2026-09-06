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

/-- Inject capabilities without interpreting effects or changing continuations. -/
def Program.mapEffects (inject : {B : Type} → E B → F B) : Program E A → Program F A
  | .pure value => .pure value
  | .request effect resume => .request (inject effect)
      (fun reply => (resume reply).mapEffects inject)

/-- Capabilities compose without adding one subsystem's services to another's
algebra. Injections preserve the requested reply type. -/
inductive EffectSum (Left Right : Type → Type) : Type → Type where
  | left {A : Type} (effect : Left A) : EffectSum Left Right A
  | right {A : Type} (effect : Right A) : EffectSum Left Right A

/-- `E` is one of the capabilities `F` composes, or a sum of some of them.
Injection is by position in `F`; every capability appears at most once in an
operation's algebra, so the position is unique and the instances below never
disagree. A sum injects leaf by leaf, so a whole sub-operation lifts into a
larger algebra with `Inject.inject`. -/
class Inject (E F : Type → Type) where
  inject : E A → F A

instance : Inject E E := ⟨fun effect => effect⟩
instance [Inject E F] : Inject E (EffectSum F G) := ⟨fun effect => .left (Inject.inject effect)⟩
instance [Inject E G] : Inject E (EffectSum F G) := ⟨fun effect => .right (Inject.inject effect)⟩
instance [Inject L F] [Inject R F] : Inject (EffectSum L R) F :=
  ⟨fun | .left effect => Inject.inject effect | .right effect => Inject.inject effect⟩

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
  /-- Observed IEEE-754 bits; interpretation belongs to the domain decoder. -/
  | real (bits : UInt64)
  /-- Text bytes that have not been converted to a Lean string. -/
  | rawText (bytes : ByteArray)
  deriving BEq

abbrev Row := List Cell
abbrev Fields := List (String × Cell)

/-- Raw rows observed before a scan failed. Domains validate the prefix before
observing the trailing failure, preserving sequential-reader error ordering. -/
structure Scan where
  rows : List Row
  failure : Option Failure := none

/-- Literal storage ordering, using the host column's stored type. -/
structure Order where
  column : String
  descending : Bool
  deriving BEq

/-- A raw relational exclusion evaluated by the same mutation statement. -/
structure Exclusion where
  relation : String
  equals : Fields
  /-- Base-column to excluded-column equality, evaluated for each candidate row. -/
  keys : List (String × String) := []
  deriving BEq

/-- Inner equality join from the base relation to another raw relation.
Projected names may qualify a column with its relation; no SQL text is supplied. -/
structure Join where
  relation : String
  keys : List (String × String)
  deriving BEq

/-- Identifiers are host-whitelisted storage names, never executable SQL.
Read projections preserve absent rows, NULL, types and order of columns.
An empty equality filter scans the relation; it does not infer domain policy. -/
inductive Storage : Type → Type where
  | begin : Storage (Reply Transaction)
  | commit (tx : Transaction) : Storage (Reply Unit)
  | rollback (tx : Transaction) : Storage (Reply Unit)
  | readRows (tx : Transaction) (relation : String)
      (columns : List String) (equals : Fields) (order : List Order := [])
      (joins : List Join := []) : Storage (Reply (List Row))
  | scanRows (tx : Transaction) (relation : String)
      (columns : List String) (equals : Fields) (order : List Order := [])
      (joins : List Join := []) : Storage (Reply Scan)
  | upsert (tx : Transaction) (relation : String) (values : Fields)
      (conflictColumns updateColumns : List String) : Storage (Reply Unit)
  | deleteRows (tx : Transaction) (relation : String)
      (equals : Fields) (blockers : List Exclusion := [])
      (atMost : Fields := []) : Storage (Reply Nat)
  /-- Delete every row of the relation whose key column names none of
  `keys`, in one statement over a host-side set, and answer how many went. -/
  | deleteExcept (tx : Transaction) (relation column : String) (keys : List ByteArray) :
      Storage (Reply Nat)
  | readBytes (space : String) (key : ByteArray) : Storage (Reply (Option ByteArray))
  /-- Bounded access to an immutable command input, borrowed for this run. -/
  | readInput (handle offset count : UInt64) : Storage (Reply ByteArray)
  | readCounter (space : String) (key : ByteArray) : Storage (Reply UInt64)
  | removeFile (space : String) (key : ByteArray) : Storage (Reply Unit)
  | existsRows (tx : Transaction) (relation : String) (equals : Fields) : Storage (Reply Bool)

abbrev OperationOver (E : Type → Type) (Error A : Type) := ExceptT Error (Program E) A
abbrev OperationWith (Error A : Type) := OperationOver Storage Error A
abbrev Operation (A : Type) := OperationWith Failure A

def perform (effect : Storage (Reply A)) : Operation A :=
  ExceptT.mk (.request effect .pure)

/-- Lift a raw host failure into the domain's own error type, without losing
the original failure token or exposing domain errors to the host interpreter. -/
def performWith (hostError : Failure → Error) (effect : Storage (Reply A)) : OperationWith Error A :=
  ExceptT.mk (.request effect (fun result => .pure (result.mapError hostError)))

def performOver (hostError : Failure → Error) (effect : E (Reply A)) : OperationOver E Error A :=
  ExceptT.mk (.request effect (fun result => .pure (result.mapError hostError)))

/-- Request one capability's effect from inside a composed algebra, lifting a
host failure into the operation's error. -/
def raise [Inject E F] (hostError : Failure → Error) (effect : E (Reply A)) :
    OperationOver F Error A :=
  performOver hostError (Inject.inject effect)

/-- Request an effect whose reply is not a plain host reply (a file reply, for
instance); the operation interprets it itself. -/
def observe [Inject E F] (effect : E B) : OperationOver F Error B :=
  ExceptT.mk (.request (Inject.inject effect) (fun reply => .pure (.ok reply)))

/-- Run a sub-operation inside a larger algebra, translating its error. -/
def within [Inject E F] (translate : ε → Error) (program : OperationOver E ε A) :
    OperationOver F Error A :=
  ExceptT.mk (program.run.mapEffects Inject.inject |>.bind
    (fun result => .pure (result.mapError translate)))

/-- Immediate transaction. A failed body or commit requests rollback, whose
failure must not replace the primary failure. Host RAII handles abandonment;
it does not choose domain recovery or report a failed commit as success. -/
def transactionOver (storage : {B : Type} → Storage B → E B) (hostError : Failure → Error)
    (body : Transaction → OperationOver E Error A) : OperationOver E Error A := ExceptT.mk do
  match ← Program.request (storage .begin) Program.pure with
  | .error failure => pure (.error (hostError failure))
  | .ok tx =>
    match ← (body tx).run with
    | .error failure =>
      let _ ← Program.request (storage (.rollback tx)) Program.pure
      pure (.error failure)
    | .ok value =>
      match ← Program.request (storage (.commit tx)) Program.pure with
      | .ok () => pure (.ok value)
      | .error failure =>
        let _ ← Program.request (storage (.rollback tx)) Program.pure
        pure (.error (hostError failure))

/-- Storage-only specialization; composition uses the same transaction algorithm. -/
def transactionWith (hostError : Failure → Error)
    (body : Transaction → OperationWith Error A) : OperationWith Error A :=
  transactionOver (fun effect => effect) hostError body

/-- Host-error-only specialization of the shared transaction program. -/
def transaction (body : Transaction → Operation A) : Operation A :=
  transactionWith id body

end VerifiedCore.Host
