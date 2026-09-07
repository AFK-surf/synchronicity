import VerifiedCore.Host.Peer
import Synchronicity.SimulatedHost

/-! What the suspending runner promises and what it asks of a program. The
runner hands a peer request out with the program's continuation and answers
it later, from another storage session if need be; it refuses to do so while
a storage transaction is open, so no connection is ever held across the
wait. `Balanced` is the program-side statement of that discipline: tracking
whether a transaction is open along every path of replies, a suspending
effect is only ever raised while none is. A program that is `Suspending` is
one the runner never refuses. The probe command is the fixture: it is
suspending outside a transaction, and the simulated host, which refuses a
peer request inside one the way the runner does, answers the counts on one
side and the protocol failure with the rollback on the other. -/
namespace Synchronicity.SuspensionProofs
open VerifiedCore.Host
open Synchronicity.SimulatedHost (State execute)

/-- How an algebra bears on the guard: which effects open or close a
transaction, with the test of a reply that did, and which suspend. -/
structure Guard (F : Type → Type) where
  opens : {B : Type} → F B → Option (B → Bool)
  closes : {B : Type} → F B → Option (B → Bool)
  suspends : {B : Type} → F B → Bool

/-- Whether a transaction is open after an effect's reply: opened by a begin
that succeeded, closed by a commit or rollback that succeeded, kept by a
close that failed, so the runner refuses a later suspension. -/
def Guard.after (g : Guard F) (effect : F B) (reply : B) (isOpen : Bool) : Bool :=
  match g.opens effect with
  | some ok => isOpen || ok reply
  | none =>
    match g.closes effect with
    | some ok => isOpen && !ok reply
    | none => isOpen

/-- Along every path of replies from a transaction state, a suspending
effect is raised only while no transaction is open, and the program ends in
a state `post` allows for its value. -/
inductive Balanced (g : Guard F) : Bool → Program F A → (A → Bool → Prop) → Prop
  | pure {isOpen : Bool} {post : A → Bool → Prop} {value : A} :
      post value isOpen → Balanced g isOpen (.pure value) post
  | request {isOpen : Bool} {post : A → Bool → Prop} {B : Type} {effect : F B}
      {resume : B → Program F A} :
      (g.suspends effect = true → isOpen = false) →
      (∀ reply, Balanced g (g.after effect reply isOpen) (resume reply) post) →
      Balanced g isOpen (.request effect resume) post

theorem Balanced.weaken {g : Guard F} {program : Program F A}
    (balanced : Balanced g isOpen program post) (imp : ∀ value isOpen, post value isOpen → post' value isOpen) :
    Balanced g isOpen program post' := by
  induction balanced with
  | pure holds => exact .pure (imp _ _ holds)
  | request guard _ ih => exact .request guard fun reply => ih reply imp

/-- A sequence is balanced when its head is and its continuation is from
every state the head may end in. -/
theorem Balanced.bind {g : Guard F} {program : Program F A} {next : A → Program F B}
    (head : Balanced g isOpen program post₁)
    (tail : ∀ value isOpen, post₁ value isOpen → Balanced g isOpen (next value) post) :
    Balanced g isOpen (program.bind next) post := by
  induction head with
  | pure holds => exact tail _ _ holds
  | request guard _ ih => exact .request guard fun reply => ih reply tail

/-- A raised effect that neither opens, closes nor suspends leaves the
transaction state alone. -/
theorem Balanced.raise_neutral {g : Guard F} [Inject E F] (hostError : Failure → ε)
    (effect : E (Reply A)) (opens : g.opens (Inject.inject effect) = none)
    (closes : g.closes (Inject.inject effect) = none)
    (suspends : g.suspends (Inject.inject effect) = false) :
    Balanced g isOpen (raise (F := F) hostError effect).run (fun _ isOpen' => isOpen' = isOpen) := by
  refine .request (by simp [suspends]) fun reply => ?_
  simp only [Guard.after, opens, closes]
  exact .pure rfl

/-- A raised effect that suspends is balanced only outside a transaction. -/
theorem Balanced.raise_suspending {g : Guard F} [Inject E F] (hostError : Failure → ε)
    (effect : E (Reply A)) (opens : g.opens (Inject.inject effect) = none)
    (closes : g.closes (Inject.inject effect) = none) :
    Balanced g false (raise (F := F) hostError effect).run (fun _ isOpen' => isOpen' = false) := by
  refine .request (fun _ => rfl) fun reply => ?_
  simp only [Guard.after, opens, closes]
  exact .pure rfl

/-- An operation the runner never refuses: from outside a transaction, it
suspends only outside one, and a transaction is open at its end only when it
failed, where nothing runs on. -/
def Suspending (g : Guard F) (operation : OperationOver F ε A) : Prop :=
  Balanced g false operation.run fun result isOpen => ∀ value, result = .ok value → isOpen = false

theorem Suspending.ofPure {g : Guard F} (value : A) :
    Suspending g (pure value : OperationOver F ε A) :=
  Balanced.pure fun _ _ => rfl

theorem Suspending.seq {g : Guard F} {operation : OperationOver F ε A}
    {next : A → OperationOver F ε B} (head : Suspending g operation)
    (tail : ∀ value, Suspending g (next value)) : Suspending g (operation >>= next) := by
  refine Balanced.bind head fun result isOpen holds => ?_
  cases result with
  | error failure => exact Balanced.pure fun _ h => nomatch h
  | ok value =>
    have closed := holds value rfl
    subst closed
    exact tail value

theorem Suspending.ofRaise {g : Guard F} [Inject E F] (hostError : Failure → ε) (effect : E (Reply A))
    (opens : g.opens (Inject.inject effect) = none) (closes : g.closes (Inject.inject effect) = none) :
    Suspending g (raise (F := F) hostError effect) :=
  (Balanced.raise_suspending hostError effect opens closes).weaken fun _ _ h _ _ => h

/-- A transaction whose body is nested (it keeps the transaction open and
never suspends) is suspending: the transaction is closed on the paths that
succeed, and the paths that roll back, whatever the rollback answers, are
failures, so nothing runs on after them. -/
theorem Suspending.ofTransaction {g : Guard F} (storage : {B : Type} → Storage B → F B)
    (hostError : Failure → ε) (body : Transaction → OperationOver F ε A)
    (begins : g.opens (storage .begin) = some fun reply => reply.toBool)
    (commits : ∀ tx, g.closes (storage (.commit tx)) = some fun reply => reply.toBool)
    (commitOpens : ∀ tx, g.opens (storage (.commit tx)) = none)
    (quiet : ∀ {B} (effect : Storage B), g.suspends (storage effect) = false)
    (nested : ∀ tx, Balanced g true (body tx).run fun _ isOpen => isOpen = true) :
    Suspending g (transactionOver storage hostError body) := by
  unfold Suspending VerifiedCore.Host.transactionOver
  refine .request (by simp [quiet]) fun reply => ?_
  simp only [Guard.after, begins]
  cases reply with
  | error failure => exact .pure fun _ h => nomatch h
  | ok tx =>
    change Balanced g true ((body tx).run.bind _) _
    refine Balanced.bind (nested tx) fun result isOpen holds => ?_
    subst holds
    cases result with
    | error failure =>
      refine .request (by simp [quiet]) fun reply => ?_
      exact .pure fun _ h => nomatch h
    | ok value =>
      refine .request (by simp [quiet]) fun reply => ?_
      simp only [Guard.after, commits, commitOpens]
      cases reply with
      | ok _ => exact .pure fun _ _ => rfl
      | error failure =>
        refine .request (by simp [quiet]) fun reply => ?_
        exact .pure fun _ h => nomatch h

/-! ## Storage and a peer -/

/-- The guard over storage with a peer: begins open, commits and rollbacks
close, and every peer effect suspends. -/
def opensStorage : Storage B → Option (B → Bool)
  | .begin => some fun reply => reply.toBool
  | _ => none

def closesStorage : Storage B → Option (B → Bool)
  | .commit _ => some fun reply => reply.toBool
  | .rollback _ => some fun reply => reply.toBool
  | _ => none

def opensStoragePeer : EffectSum Storage Peer B → Option (B → Bool)
  | .left effect => opensStorage effect
  | .right _ => none

def closesStoragePeer : EffectSum Storage Peer B → Option (B → Bool)
  | .left effect => closesStorage effect
  | .right _ => none

def suspendsStoragePeer : EffectSum Storage Peer B → Bool
  | .right _ => true
  | .left _ => false

def storagePeer : Guard (EffectSum Storage Peer) :=
  ⟨opensStoragePeer, closesStoragePeer, suspendsStoragePeer⟩

/-- The probe outside a transaction is a program the runner never refuses. -/
theorem probe_suspending (root : ByteArray) (wants : List (ByteArray × ByteArray)) :
    Suspending storagePeer (Peer.probe root wants false) := by
  unfold Peer.probe
  simp only [Bool.false_eq_true, ↓reduceIte]
  refine Suspending.seq (Suspending.ofRaise _ _ rfl rfl) fun nodes => ?_
  obtain ⟨_, _, _⟩ := nodes
  refine Suspending.seq (Suspending.ofRaise _ _ rfl rfl) fun values => ?_
  obtain ⟨_, _⟩ := values
  exact Suspending.ofPure _

/-- The probe inside a transaction is not: the first reply that opens the
transaction leads straight to a peer request inside it. -/
theorem probe_in_transaction_not_suspending (root : ByteArray) (wants : List (ByteArray × ByteArray)) :
    ¬ Suspending storagePeer (Peer.probe root wants true) := by
  intro suspending
  change Balanced _ false (Program.request (E := EffectSum Storage Peer) (.left .begin) _) _
    at suspending
  cases suspending with
  | request _ replies =>
    have opened := replies (.ok 1)
    change Balanced _ true
      (Program.request (E := EffectSum Storage Peer) (.right (Peer.fetchNodes root wants)) _) _
      at opened
    cases opened with
    | request guard _ => exact nomatch guard rfl

/-! ## On the simulated host -/

open Synchronicity.SimulatedHost in
/-- Outside a transaction the host answers both round trips from what the
peer holds, and the probe counts them. -/
theorem probe_counts (root : ByteArray) (wants : List (ByteArray × ByteArray)) (state : State)
    (quiet : state.faults = []) (idle : state.pending = none) :
    SimulatedHost.run (Peer.probe root wants false) state =
      (.ok ⟨((peerAnswer state.peerNodes wants).1.length +
          (peerAnswer state.peerValues wants).1.length).toUInt64,
        ((peerAnswer state.peerNodes wants).2.filter
            (fun hash => !state.peerRedacted.contains hash)).length.toUInt64 +
          (peerAnswer state.peerValues wants).2.length.toUInt64⟩,
        { state with output := [], trace := state.trace ++ ["peer:nodes", "peer:values"] }) := by
  simp [SimulatedHost.run, Peer.probe, raise, performOver, Inject.inject, bind, ExceptT.bind,
    ExceptT.bindCont, ExceptT.run, ExceptT.mk, execute, Program.bind, Interpreter.handle, peer,
    reply, fault, quiet, idle, record, pure, ExceptT.pure, Except.mapError]

open Synchronicity.SimulatedHost in
/-- Inside a transaction the host refuses the first round trip the way the
runner does, the transaction is rolled back, and the probe fails as a
protocol failure. -/
theorem probe_in_transaction_refused (root : ByteArray) (wants : List (ByteArray × ByteArray))
    (state : State) (quiet : state.faults = []) (idle : state.pending = none) :
    (SimulatedHost.run (Peer.probe root wants true) state).1 = .error invalid ∧
      (SimulatedHost.run (Peer.probe root wants true) state).2.trace =
        state.trace ++ ["begin", "peer:nodes", "rollback"] ∧
      (SimulatedHost.run (Peer.probe root wants true) state).2.pending = none := by
  simp [SimulatedHost.run, Peer.probe, transactionOver, raise, performOver, Inject.inject, bind,
    ExceptT.bind, ExceptT.bindCont, ExceptT.run, ExceptT.mk, execute, Program.bind,
    Interpreter.handle, peer, storage, reply, fault, quiet, idle, record, pure, ExceptT.pure,
    Except.mapError]

end Synchronicity.SuspensionProofs
