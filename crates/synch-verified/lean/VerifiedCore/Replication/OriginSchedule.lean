import Std.Data.TreeMap.Basic

/-! Cyclic bounded work over stable origin groups.

Callers supply one item per origin in canonical ascending order. A weight is
the number of wire records that must travel atomically for that origin (one or
two for head summaries, one for pending Fetch). The cursor names the last
completed group; cancellation is represented by retaining the old cursor. -/
namespace VerifiedCore.Replication.OriginSchedule

structure Item where
  origin : String
  weight : UInt64
  deriving DecidableEq

instance : BEq Item := instBEqOfDecidableEq
instance : LawfulBEq Item where
  rfl := by simp [BEq.beq]
  eq_of_beq := by
    intro left right equal
    simpa [BEq.beq] using equal

structure Plan where
  positions : List UInt64
  cursor : Option String

def key (origin : String) : Nat :=
  1 + origin.toUTF8.data.foldl (fun value byte => value * 256 + byte.toNat) 0

def after (cursor origin : String) : Bool :=
  key cursor < key origin

abbrev Index := Std.TreeMap Nat (Nat × Item)

def index (items : List Item) : Index :=
  items.zipIdx.foldl (fun result (item, position) =>
    result.insert (key item.origin) (position, item)) {}

def cycleAt (items : List (Nat × (Nat × Item))) (cursor : Nat) :
    List (Nat × (Nat × Item)) :=
  items.filter (fun item => cursor < item.1) ++
    items.filter (fun item => item.1 ≤ cursor)

def cycle (items : List Item) (cursor : Option String) : List (Nat × (Nat × Item)) :=
  cycleAt (index items).toList (cursor.map key |>.getD 0)

def take (remaining : Nat) :
    List (Nat × (Nat × Item)) → List (Nat × (Nat × Item))
  | [] => []
  | item :: rest =>
    if item.2.2.weight.toNat ≤ remaining then
      item :: take (remaining - item.2.2.weight.toNat) rest
    else []

def plan (items : List Item) (cursor : Option String) (maximum : Nat) : Plan :=
  let selected := take maximum (cycle items cursor)
  { positions := selected.map (fun item => item.2.1.toUInt64)
    cursor := match selected.getLast? with
      | none => cursor
      | some item => some item.2.2.origin }

end VerifiedCore.Replication.OriginSchedule
