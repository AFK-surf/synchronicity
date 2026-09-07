import Std.Data.TreeMap.Basic

/-! A complete bounded contact plan. Persist the returned cursor only after
all planned attempts finish, including failed attempts. A successful exchange
does not discard the other peers' turns. Stable eligible peers therefore
receive cyclic service rather than depending on clock-derived randomness. -/
namespace VerifiedCore.Replication.Contact

structure ContactPlan where
  positions : List UInt64
  cursor : Option ByteArray

/-- Peer identifiers have exactly 32 bytes at the native boundary. -/
def key (peer : ByteArray) : Nat :=
  1 + peer.data.foldl (fun value byte => value * 256 + byte.toNat) 0

abbrev Index := Std.TreeMap Nat (Nat × ByteArray)

def index (peers : List ByteArray) : Index :=
  peers.zipIdx.foldl (fun result (peer, position) =>
    result.insert (key peer) (position, peer)) {}

/-- The cyclic order begins strictly after the previous completed plan's
last peer. Removing that peer from eligibility does not reset everybody's
turn; adding peers does not rely on a stable input-list ordering. -/
def cycleAt (ordered : List (Nat × α)) (last : Nat) : List (Nat × α) :=
  ordered.filter (fun entry => last < entry.1) ++
    ordered.filter (fun entry => entry.1 ≤ last)

def cycle (peers : Index) (cursor : Option ByteArray) : List (Nat × (Nat × ByteArray)) :=
  cycleAt peers.toList (cursor.map key |>.getD 0)

def plan (peers : List ByteArray) (cursor : Option ByteArray) (maximum : Nat) : ContactPlan :=
  let selected := (cycle (index peers) cursor).take maximum
  { positions := selected.map (fun entry => entry.2.1.toUInt64)
    cursor := match selected.getLast? with
      | none => cursor
      | some entry => some entry.2.2 }

end VerifiedCore.Replication.Contact
