import Synchronicity.SimulatedHost
import VerifiedCore.Cas.Read
import VerifiedCore.Cas.Program
import VerifiedCore.Cas.Input

/-! Raw test data only. All effect interpretation lives in SimulatedHost. -/
deriving instance DecidableEq for VerifiedCore.Cas.Outcome

namespace Synchronicity.CasFixtures
open VerifiedCore.Host SimulatedHost

def root : ByteArray := ⟨Array.replicate 32 0⟩
def otherRoot : ByteArray := ⟨Array.replicate 32 1⟩
def bytes : ByteArray := ⟨#[10, 20, 30, 40]⟩
def primary : Failure := ⟨1, 71⟩
def secondary : Failure := ⟨1, 72⟩

def blob (key : ByteArray := root) (size : Int64 := 4) (complete : Int64 := 1)
    (inline : Cell := .null) (bitmap : Cell := .null) (durable : Int64 := 1) : Fields :=
  [("root", .blob key), ("size", .integer size), ("complete", .integer complete),
   ("bitmap", bitmap), ("inline", inline), ("last_access", .integer 0), ("durable", .integer durable)]

def pin (key : ByteArray := root) (holder : String := "source:media") (release : Cell := .null) : Fields :=
  [("root", .blob key), ("holder", .text holder), ("created_at", .integer 7), ("release_after", release)]

def want (key : ByteArray := root) (holder : String := "source:media") (size : Int64 := 4)
    (prev : Cell := .null) (now : Int64 := 5) : Fields :=
  [("root", .blob key), ("holder", .text holder), ("size", .integer size),
   ("prev", prev), ("first_wanted", .integer now)]

def entry (key : ByteArray := root) (space : String := "media") : Fields :=
  [("content", .blob key), ("space", .text space)]

def stored : State :=
  { db := [("blobs", [blob])], files := [(("cas_payload", root), bytes)], now := 123 }

def repairing : State :=
  { stored with db := [("blobs", [blob]), ("pins", [pin, pin root "operator"])] }

def fail (state : State) (index : Nat) (failure : Failure := primary) : State :=
  { state with faults := state.faults ++ [(index, failure)] }

/-- Observation, not a second evaluator. The next command can use result.2. -/
def traceResult [Interpreter E] (op : OperationOver E ε A) (state : State) : Except ε A × List String :=
  let result := SimulatedHost.run op state
  (result.1, result.2.trace)

def readResult (state : State := stored) (request : VerifiedCore.Cas.Read.Request := .all) :=
  let result := SimulatedHost.run (VerifiedCore.Cas.Read.read root request) state
  (publish VerifiedCore.Cas.Read.Error.protocol result.1 result.2, result.2.trace)

def failed : Except ε A → Bool
  | .error _ => true
  | .ok _ => false

end Synchronicity.CasFixtures
