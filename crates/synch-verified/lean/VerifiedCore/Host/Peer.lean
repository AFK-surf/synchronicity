import VerifiedCore.Host

/-! A peer as a host service: the round trips a fetch makes. These are the
effects a program suspends on. The host does not answer them from a service
it holds; it hands the request out to whoever is driving the program, keeps
the continuation as an owned value until the reply comes back, and refuses
the request outright while a storage transaction is open, so no connection
is held across a network wait. What a reply means is the program's to
decide: the served bytes are admitted at the ingress boundary, the absences
and refusals are boundaries or progress, never trusted as they stand. -/
namespace VerifiedCore.Host

/-- What a peer answered for a batch of wanted nodes: the pairs it served,
the hashes it did not have, and the hashes it holds and may not show. -/
abbrev PeerNodes := List (ByteArray × ByteArray) × List ByteArray × List ByteArray

/-- What a peer answered for a batch of wanted values: the pairs it served
and the hashes it did not have. -/
abbrev PeerValues := List (ByteArray × ByteArray) × List ByteArray

/-- A want names the position asked at and the hash expected there. The
replies are spelled out so the generator sees their wire shape. -/
inductive Peer : Type → Type where
  | fetchNodes (root : ByteArray) (wants : List (ByteArray × ByteArray)) :
      Peer (Reply (List (ByteArray × ByteArray) × List ByteArray × List ByteArray))
  | fetchValues (root : ByteArray) (wants : List (ByteArray × ByteArray)) :
      Peer (Reply (List (ByteArray × ByteArray) × List ByteArray))

/-- What the runner's self-test answers. -/
structure Probed where
  served : UInt64
  missing : UInt64
  deriving BEq

/-- The suspending runner's self-test: asks a peer for `wants` under `root`
across two suspensions and counts what came back; inside a transaction when
told to, which the runner must refuse rather than hold a connection across
the wait, and the refusal then rolls the transaction back. -/
def Peer.probe (root : ByteArray) (wants : List (ByteArray × ByteArray)) (inTransaction : Bool) :
    OperationOver (EffectSum Storage Peer) Failure Probed :=
  let ask : OperationOver (EffectSum Storage Peer) Failure Probed := do
    let (servedNodes, missingNodes, _) ← raise id (Peer.fetchNodes root wants)
    let (servedValues, missingValues) ← raise id (Peer.fetchValues root wants)
    return ⟨(servedNodes.length + servedValues.length).toUInt64,
      (missingNodes.length + missingValues.length).toUInt64⟩
  if inTransaction then transactionOver Inject.inject id fun _ => ask else ask

end VerifiedCore.Host
