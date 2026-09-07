import Synchronicity.CasFixtures
import Synchronicity.TrieProgramProofs
import Synchronicity.TrieServeProofs
import VerifiedCore.Trie.Proof

/-! Merkle proofs, as executed: verification is the lookup over the proof's
own nodes as a raw snapshot, so a verified value is a path through those
nodes and nothing else; a proof is always answered, never a protocol
failure; on a store addressed by its digests, the proof `prove` builds
verifies to exactly what `get` answers on the store (the round trip); and
on a concrete trie the proofs of two present keys and an absent one, their
verification, and the refusals a truncated path, a substituted payload and
a foreign root earn. -/
namespace Synchronicity.TrieMerkleProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Trie.Proof SimulatedHost CasFixtures
open Synchronicity.TrieProgramProofs (GraphValue ReadBound get_semantic_sound get_read_bound)
open Synchronicity.TrieVerifyProofs (byteArray_beq_iff byteArray_beq_self)

deriving instance BEq, DecidableEq for VerifiedCore.Trie.LookupError
deriving instance BEq, DecidableEq for VerifiedCore.Trie.Proof.VerifyError

/-! ## The evaluator

The core's snapshot evaluator is the one the lookup's semantics are stated
over. -/

theorem executeReads_eq (store : RawSnapshot) (fuel : Nat) (program : Program Storage A) :
    Proof.executeReads store fuel program = TrieProgramProofs.executeReads store fuel program := by
  induction program generalizing fuel with
  | pure value => cases fuel <;> rfl
  | request effect next ih =>
    cases fuel with
    | zero => rfl
    | succ fuel => cases effect <;> simp [Proof.executeReads, TrieProgramProofs.executeReads, ih]

/-- Verification is the lookup over the proof's snapshot, by definition. -/
theorem check_is_get (root key : ByteArray) (nodes : List (ByteArray × ByteArray))
    (payload : Option (ByteArray × ByteArray)) :
    check root key nodes payload =
      TrieProgramProofs.executeReads (snapshotOf nodes payload) (maxKeyBytes * 2 + 2) (get root key).run :=
  executeReads_eq _ _ _

/-- A value a proof verifies to is a root-to-key path through the proof's
own nodes, with its payload: nothing outside the proof is consulted, and no
membership can be invented. -/
theorem verified_value_is_a_path (root key : ByteArray) (nodes : List (ByteArray × ByteArray))
    (payload : Option (ByteArray × ByteArray)) (bytes : ByteArray)
    (verified : check root key nodes payload = some (.ok (.ok (some bytes)))) :
    GraphValue (snapshotOf nodes payload) root (keyNibbles key) bytes :=
  (get_semantic_sound _ _ root key bytes (check_is_get root key nodes payload ▸ verified)).2.2

/-! ## A proof is always answered -/

theorem executeReads_of_readBound (store : RawSnapshot) {n : Nat} {program : Program Storage A}
    (bound : ReadBound n program) : ∃ value, Proof.executeReads store n program = some value := by
  induction bound with
  | done value => exact ⟨value, by simp [Proof.executeReads]⟩
  | read space key _ next _ ih =>
    obtain ⟨value, ran⟩ := ih (.ok (store space key))
    exact ⟨value, by simp only [Proof.executeReads]; exact ran⟩

/-- Over a snapshot, whose reads never fail, a value resolution answers a
domain result, never a host failure. -/
theorem resolve_ok (store : RawSnapshot) (value : Value) (budget : Nat) (answer : Reply LookupResult)
    (ran : Proof.executeReads store budget (resolveValue value).run = some answer) :
    ∃ result, answer = .ok result := by
  cases value with
  | inline bytes =>
    change Proof.executeReads store budget (.pure (.ok (.ok (some bytes)) : Reply LookupResult)) = _ at ran
    simp [Proof.executeReads] at ran
    exact ⟨_, ran.symm⟩
  | hash address =>
    cases budget with
    | zero =>
      change Proof.executeReads store 0 (.request (.readBytes valueSpace address) _) = _ at ran
      simp [Proof.executeReads] at ran
    | succ budget =>
      change Proof.executeReads store (budget + 1) (.request (.readBytes valueSpace address) _) = _ at ran
      rw [Proof.executeReads] at ran
      dsimp only [Program.bind, ExceptT.bindCont] at ran
      cases held : store valueSpace address with
      | none =>
        simp only [held] at ran
        change Proof.executeReads store budget (.pure (.ok (.error (.missingValue address)) : Reply LookupResult)) = _ at ran
        simp [Proof.executeReads] at ran
        exact ⟨_, ran.symm⟩
      | some bytes =>
        simp only [held] at ran
        change Proof.executeReads store budget (.pure (.ok (.ok (some bytes)) : Reply LookupResult)) = _ at ran
        simp [Proof.executeReads] at ran
        exact ⟨_, ran.symm⟩

theorem lookup_ok (store : RawSnapshot) (fuel : Nat) : ∀ (address : Option ByteArray) (key : List UInt8)
    (budget : Nat) (answer : Reply LookupResult),
    Proof.executeReads store budget (lookup fuel address key).run = some answer → ∃ result, answer = .ok result := by
  induction fuel with
  | zero =>
    intro address key budget answer ran
    change Proof.executeReads store budget (.pure (.ok (.error .depthExceeded) : Reply LookupResult)) = _ at ran
    simp [Proof.executeReads] at ran
    exact ⟨_, ran.symm⟩
  | succ fuel ih =>
    intro address key budget answer ran
    cases address with
    | none =>
      change Proof.executeReads store budget (.pure (.ok (.ok none) : Reply LookupResult)) = _ at ran
      simp [Proof.executeReads] at ran
      exact ⟨_, ran.symm⟩
    | some address =>
      cases budget with
      | zero => contradiction
      | succ budget =>
        change Proof.executeReads store (budget + 1) (.request (.readBytes nodeSpace address) _) = _ at ran
        rw [Proof.executeReads] at ran
        dsimp only [Program.bind, ExceptT.bindCont] at ran
        cases held : store nodeSpace address with
        | none =>
          simp only [held] at ran
          change Proof.executeReads store budget (.pure (.ok (.error (.missingNode address)) : Reply LookupResult)) = _ at ran
          simp [Proof.executeReads] at ran
          exact ⟨_, ran.symm⟩
        | some raw =>
          simp only [held] at ran
          cases decoded : decode raw with
          | error message =>
            simp only [decoded] at ran
            change Proof.executeReads store budget (.pure (.ok (.error (.decode message)) : Reply LookupResult)) = _ at ran
            simp [Proof.executeReads] at ran
            exact ⟨_, ran.symm⟩
          | ok node =>
            cases node with
            | leaf suffix value =>
              simp only [decoded] at ran
              split at ran
              · exact resolve_ok store value budget answer ran
              · change Proof.executeReads store budget (.pure (.ok (.ok none) : Reply LookupResult)) = _ at ran
                simp [Proof.executeReads] at ran
                exact ⟨_, ran.symm⟩
            | extension segment child =>
              simp only [decoded] at ran
              split at ran
              · change Proof.executeReads store budget (.pure (.ok (.ok none) : Reply LookupResult)) = _ at ran
                simp [Proof.executeReads] at ran
                exact ⟨_, ran.symm⟩
              · exact ih _ _ budget answer ran
            | branch children value =>
              simp only [decoded] at ran
              cases key with
              | nil =>
                cases value with
                | none =>
                  change Proof.executeReads store budget (.pure (.ok (.ok none) : Reply LookupResult)) = _ at ran
                  simp [Proof.executeReads] at ran
                  exact ⟨_, ran.symm⟩
                | some value => exact resolve_ok store value budget answer ran
              | cons nibble rest => exact ih _ _ budget answer ran

/-- Over any snapshot the lookup is answered within the budget verification
grants it, with a domain result: verification never reaches its protocol
refusal. -/
theorem check_answers (root key : ByteArray) (nodes : List (ByteArray × ByteArray))
    (payload : Option (ByteArray × ByteArray)) :
    ∃ result, check root key nodes payload = some (.ok result) := by
  obtain ⟨answer, ran⟩ := executeReads_of_readBound (snapshotOf nodes payload) (get_read_bound root key)
  unfold check
  rw [ran]
  unfold Trie.get at ran
  split at ran
  · exact ⟨.error (.keyTooLong key.size), by rw [← ran]; rfl⟩
  · obtain ⟨result, same⟩ := lookup_ok _ _ _ _ _ _ ran
    exact ⟨result, by rw [same]⟩

/-! ## Verification, purely

What `verify` computes once its digests are answered: the pure model the
simulated host's execution is shown to equal, and the round trip is stated
over. -/

def addressWith (hash : ByteArray → ByteArray) : List ByteArray → Except Refusal (List (ByteArray × ByteArray))
  | [] => .ok []
  | raw :: rest =>
    match admit raw with
    | .error refusal => .error refusal
    | .ok node =>
      match addressWith hash rest with
      | .error refusal => .error refusal
      | .ok addressed => .ok ((hash (tagOf node ++ raw), raw) :: addressed)

def verifyWith (hash : ByteArray → ByteArray) (root key : ByteArray) (nodes : List ByteArray)
    (value : Option ByteArray) : Except VerifyError (Option ByteArray) :=
  match addressWith hash nodes with
  | .error refusal => .error (.refused refusal)
  | .ok addressed =>
    match check root key addressed (value.map fun bytes => (hash bytes, bytes)) with
    | some (.ok result) => result.mapError .lookup
    | _ => .error (.lookup .depthExceeded)

theorem addressNodes_run (nodes : List ByteArray) : ∀ (state : State), state.faults = [] →
    (execute (addressNodes (E := Digest) nodes).run state).1 = .ok (addressWith state.hash nodes) ∧
    (execute (addressNodes (E := Digest) nodes).run state).2.hash = state.hash ∧
    (execute (addressNodes (E := Digest) nodes).run state).2.faults = [] := by
  induction nodes with
  | nil => intro state quiet; simp [addressNodes, pure, ExceptT.pure, ExceptT.run, ExceptT.mk, execute, addressWith, quiet]
  | cons raw rest ih =>
    intro state quiet
    simp only [addressNodes, addressWith]
    cases admit raw with
    | error refusal =>
      simp [pure, ExceptT.pure, ExceptT.run, ExceptT.mk, execute, quiet]
    | ok node =>
      simp only [Proof.digest, raise, performOver, Inject.inject, bind, ExceptT.bind, ExceptT.bindCont,
        ExceptT.mk, ExceptT.run, Program.bind, execute, Interpreter.handle, SimulatedHost.digest, reply,
        fault, quiet, List.find?_nil, Option.map_none, Except.mapError]
      rw [execute_bind]
      have step := ih (record state "digest") (by simp [record, quiet])
      simp only [record, ExceptT.run] at step ⊢
      generalize execute (addressNodes (E := Digest) rest) { state with trace := state.trace ++ ["digest"] } =
        rested at step ⊢
      obtain ⟨result, state'⟩ := rested
      simp only at step
      obtain ⟨answer, hashed, quiet'⟩ := step
      subst answer
      cases addressWith state.hash rest <;> simp [ExceptT.bindCont, pure, ExceptT.pure, ExceptT.mk, execute, hashed, quiet']

/-- On a host that answers its digests, verifying is the pure model over
the host's digest: the refusal of a node that is no node, or the lookup
over the proof's snapshot. -/
theorem verify_run (root key : ByteArray) (nodes : List ByteArray) (value : Option ByteArray)
    (state : State) (quiet : state.faults = []) :
    (SimulatedHost.run (Proof.verify (E := Digest) root key nodes value) state).1 =
      .ok (verifyWith state.hash root key nodes value) := by
  unfold SimulatedHost.run Proof.verify verifyWith
  have addressed := addressNodes_run nodes { state with output := [] } (by simpa using quiet)
  simp only [ExceptT.run] at addressed
  simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run]
  rw [execute_bind]
  generalize execute (addressNodes (E := Digest) nodes) { state with output := [] } = ran at addressed ⊢
  obtain ⟨answer, state'⟩ := ran
  simp only at addressed
  obtain ⟨answer, hashed, quiet'⟩ := addressed
  subst answer
  cases addressWith state.hash nodes with
  | error refusal => simp [ExceptT.bindCont, pure, ExceptT.pure, ExceptT.mk, execute]
  | ok addressedNodes =>
    simp only [ExceptT.bindCont, pure, ExceptT.pure, ExceptT.mk, Program.bind]
    cases value with
    | none =>
      obtain ⟨result, answered⟩ := check_answers root key addressedNodes none
      simp [answered, execute, Option.map_none]
    | some bytes =>
      simp only [Proof.digest, raise, performOver, Inject.inject, ExceptT.bindCont, ExceptT.mk, Program.bind,
        execute, Interpreter.handle, SimulatedHost.digest, reply, fault, quiet', List.find?_nil, Option.map_none,
        Except.mapError, hashed, Option.map_some]
      obtain ⟨result, answered⟩ := check_answers root key addressedNodes (some (state.hash bytes, bytes))
      simp [answered, execute]

/-! ## The round trip

On a store addressed by its digests, the proof `prove` builds verifies to
exactly what `get` answers on the store. -/

/-- Every node of the store is canonical and stored under the digest of its
tag and bytes; every payload under its digest. -/
def Addressed (store : RawSnapshot) (hash : ByteArray → ByteArray) : Prop :=
  (∀ address raw, store nodeSpace address = some raw →
    ∃ node, admit raw = .ok node ∧ hash (tagOf node ++ raw) = address) ∧
  ∀ address bytes, store valueSpace address = some bytes → hash bytes = address

/-- A snapshot holds every node and the payload of a proof at the store's
addresses for them. -/
def Covers (store snapshot : RawSnapshot) (proof : Proof) : Prop :=
  (∀ raw ∈ proof.nodes, ∀ address, store nodeSpace address = some raw → snapshot nodeSpace address = some raw) ∧
  ∀ bytes, proof.value = some bytes → ∀ address, store valueSpace address = some bytes →
    snapshot valueSpace address = some bytes

/-- What every node and the payload of a proof are: read from the store. -/
def Stored (store : RawSnapshot) (proof : Proof) : Prop :=
  (∀ raw ∈ proof.nodes, ∃ address, store nodeSpace address = some raw) ∧
  ∀ bytes, proof.value = some bytes → ∃ address, store valueSpace address = some bytes

theorem resolve_agrees (store snapshot : RawSnapshot) (value : Value)
    (proved : ∀ address, value = .hash address → ∃ bytes, store valueSpace address = some bytes ∧
      snapshot valueSpace address = some bytes) (budget : Nat) :
    Proof.executeReads snapshot budget (resolveValue value).run =
      Proof.executeReads store budget (resolveValue value).run := by
  cases value with
  | inline b =>
    change Proof.executeReads snapshot budget (.pure (.ok (.ok (some b)) : Reply LookupResult)) =
      Proof.executeReads store budget (.pure (.ok (.ok (some b)) : Reply LookupResult))
    cases budget <;> rfl
  | hash address =>
    cases budget with
    | zero => rfl
    | succ budget =>
      obtain ⟨bytes, held, covered⟩ := proved address rfl
      change Proof.executeReads snapshot (budget + 1) (.request (.readBytes valueSpace address) _) =
        Proof.executeReads store (budget + 1) (.request (.readBytes valueSpace address) _)
      rw [Proof.executeReads, Proof.executeReads, held, covered]
      dsimp only [Program.bind, ExceptT.bindCont]
      cases budget <;> rfl

/-- `found` answers exactly the payload the value names, read from the store. -/
theorem found_run (store : RawSnapshot) (value : Value) (nodes : List ByteArray) (budget : Nat) (proof : Proof)
    (ran : Proof.executeReads store budget (found value nodes).run = some (.ok (.ok proof))) :
    proof.nodes = nodes.reverse ∧
      ∀ address, value = .hash address → ∃ bytes, proof.value = some bytes ∧ store valueSpace address = some bytes := by
  cases value with
  | inline _ =>
    change Proof.executeReads store budget (.pure (.ok (.ok ⟨nodes.reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
    simp [Proof.executeReads] at ran
    exact ⟨by rw [← ran], fun _ h => by cases h⟩
  | hash address =>
    cases budget with
    | zero =>
      change Proof.executeReads store 0 (.request (.readBytes valueSpace address) _) = _ at ran
      simp [Proof.executeReads] at ran
    | succ budget =>
      change Proof.executeReads store (budget + 1) (.request (.readBytes valueSpace address) _) = _ at ran
      rw [Proof.executeReads] at ran
      dsimp only [Program.bind, ExceptT.bindCont] at ran
      cases held : store valueSpace address with
      | none =>
        simp only [held] at ran
        change Proof.executeReads store budget (.pure (.ok (.error (.missingValue address))) : Program Storage (Reply Result)) = _ at ran
        simp [Proof.executeReads] at ran
      | some bytes =>
        simp only [held] at ran
        change Proof.executeReads store budget (.pure (.ok (.ok ⟨nodes.reverse, some bytes⟩)) : Program Storage (Reply Result)) = _ at ran
        simp [Proof.executeReads] at ran
        subst ran
        exact ⟨rfl, fun _ h => by cases h; exact ⟨bytes, rfl, held⟩⟩

theorem mem_pushed {raw raw' : ByteArray} {acc : List ByteArray} (mem : raw' ∈ raw :: acc) :
    raw' ∈ acc.reverse ++ [raw] := by
  rw [← List.reverse_cons]; exact List.mem_reverse.mpr mem

theorem mem_of_pushed {raw raw' : ByteArray} {acc : List ByteArray} (mem : raw' ∈ acc.reverse ++ [raw]) :
    raw' ∈ raw :: acc := by
  rw [← List.reverse_cons] at mem; exact List.mem_reverse.mp mem

/-- Whatever the descent accumulated so far is in the proof it answers. -/
theorem proveAt_keeps (store : RawSnapshot) (fuel : Nat) : ∀ (address : Option ByteArray) (rest : List UInt8)
    (acc : List ByteArray) (budget : Nat) (proof : Proof),
    Proof.executeReads store budget (proveAt fuel address rest acc).run = some (.ok (.ok proof)) →
    ∀ raw ∈ acc, raw ∈ proof.nodes := by
  induction fuel with
  | zero =>
    intro address rest acc budget proof ran
    change Proof.executeReads store budget (.pure (.ok (.error .depthExceeded)) : Program Storage (Reply Result)) = _ at ran
    simp [Proof.executeReads] at ran
  | succ fuel ih =>
    intro address rest acc budget proof ran
    cases address with
    | none =>
      change Proof.executeReads store budget (.pure (.ok (.ok ⟨acc.reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
      simp [Proof.executeReads] at ran
      subst ran
      exact fun raw mem => List.mem_reverse.mpr mem
    | some address =>
      cases budget with
      | zero => contradiction
      | succ budget =>
        change Proof.executeReads store (budget + 1) (.request (.readBytes nodeSpace address) _) = _ at ran
        rw [Proof.executeReads] at ran
        dsimp only [Program.bind, ExceptT.bindCont] at ran
        cases held : store nodeSpace address with
        | none =>
          simp only [held] at ran
          change Proof.executeReads store budget (.pure (.ok (.error (.missingNode address))) : Program Storage (Reply Result)) = _ at ran
          simp [Proof.executeReads] at ran
        | some raw =>
          simp only [held] at ran
          have tail : ∀ raw' ∈ acc, raw' ∈ raw :: acc := fun raw' mem => List.mem_cons_of_mem _ mem
          cases decoded : decode raw with
          | error message =>
            simp only [decoded] at ran
            change Proof.executeReads store budget (.pure (.ok (.error (.decode message))) : Program Storage (Reply Result)) = _ at ran
            simp [Proof.executeReads] at ran
          | ok node =>
            cases node with
            | leaf suffix value =>
              simp only [decoded] at ran
              split at ran
              · obtain ⟨nodes, _⟩ := found_run store value (raw :: acc) budget proof ran
                intro raw' mem
                rw [nodes]
                exact List.mem_reverse.mpr (tail raw' mem)
              · change Proof.executeReads store budget (.pure (.ok (.ok ⟨(raw :: acc).reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
                simp [Proof.executeReads] at ran
                subst ran
                exact fun raw' mem => mem_pushed (tail raw' mem)
            | extension segment child =>
              simp only [decoded] at ran
              split at ran
              · change Proof.executeReads store budget (.pure (.ok (.ok ⟨(raw :: acc).reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
                simp [Proof.executeReads] at ran
                subst ran
                exact fun raw' mem => mem_pushed (tail raw' mem)
              · exact fun raw' mem => ih _ _ _ budget proof ran raw' (tail raw' mem)
            | branch children value =>
              simp only [decoded] at ran
              cases rest with
              | nil =>
                cases value with
                | none =>
                  change Proof.executeReads store budget (.pure (.ok (.ok ⟨(raw :: acc).reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
                  simp [Proof.executeReads] at ran
                  subst ran
                  exact fun raw' mem => mem_pushed (tail raw' mem)
                | some value =>
                  obtain ⟨nodes, _⟩ := found_run store value (raw :: acc) budget proof ran
                  intro raw' mem
                  rw [nodes]
                  exact List.mem_reverse.mpr (tail raw' mem)
              | cons nibble rest => exact fun raw' mem => ih _ _ _ budget proof ran raw' (tail raw' mem)

/-- The lookup over a covering snapshot reads the node the store holds at
`address`, then continues as the lookup over the store does. -/
theorem lookup_step (store snapshot : RawSnapshot) (address raw : ByteArray)
    (held : store nodeSpace address = some raw) (covered : snapshot nodeSpace address = some raw)
    (program : Program Storage (Reply LookupResult)) (next : Reply (Option ByteArray) → Program Storage (Reply LookupResult))
    (shape : program = .request (.readBytes nodeSpace address) next)
    (continues : ∀ budget', Proof.executeReads snapshot budget' (next (.ok (some raw))) =
      Proof.executeReads store budget' (next (.ok (some raw)))) (budget : Nat) :
    Proof.executeReads snapshot budget program = Proof.executeReads store budget program := by
  subst shape
  cases budget with
  | zero => rfl
  | succ budget =>
    rw [Proof.executeReads, Proof.executeReads, held, covered]
    exact continues budget

/-- The descent with its trace reads exactly what the lookup reads: every
node and the payload of the proof are the store's, and over any snapshot
covering them the lookup answers as it does on the store. -/
theorem proveAt_lookup (store : RawSnapshot) (fuel : Nat) : ∀ (address : Option ByteArray) (rest : List UInt8)
    (acc : List ByteArray) (budget : Nat) (proof : Proof),
    (∀ raw ∈ acc, ∃ address, store nodeSpace address = some raw) →
    Proof.executeReads store budget (proveAt fuel address rest acc).run = some (.ok (.ok proof)) →
    Stored store proof ∧ ∀ snapshot, Covers store snapshot proof → ∀ budget',
      Proof.executeReads snapshot budget' (lookup fuel address rest).run =
        Proof.executeReads store budget' (lookup fuel address rest).run := by
  induction fuel with
  | zero =>
    intro address rest acc budget proof _ ran
    change Proof.executeReads store budget (.pure (.ok (.error .depthExceeded)) : Program Storage (Reply Result)) = _ at ran
    simp [Proof.executeReads] at ran
  | succ fuel ih =>
    intro address rest acc budget proof stored ran
    cases address with
    | none =>
      change Proof.executeReads store budget (.pure (.ok (.ok ⟨acc.reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
      simp [Proof.executeReads] at ran
      subst ran
      refine ⟨⟨fun raw mem => stored raw (List.mem_reverse.mp mem), fun _ h => by cases h⟩,
        fun _ _ budget' => ?_⟩
      change Proof.executeReads _ budget' (.pure (.ok (.ok none) : Reply LookupResult)) =
        Proof.executeReads _ budget' (.pure (.ok (.ok none) : Reply LookupResult))
      cases budget' <;> rfl
    | some address =>
      cases budget with
      | zero => contradiction
      | succ budget =>
        change Proof.executeReads store (budget + 1) (.request (.readBytes nodeSpace address) _) = _ at ran
        rw [Proof.executeReads] at ran
        dsimp only [Program.bind, ExceptT.bindCont] at ran
        cases held : store nodeSpace address with
        | none =>
          simp only [held] at ran
          change Proof.executeReads store budget (.pure (.ok (.error (.missingNode address))) : Program Storage (Reply Result)) = _ at ran
          simp [Proof.executeReads] at ran
        | some raw =>
          simp only [held] at ran
          have stored' : ∀ raw' ∈ raw :: acc, ∃ address, store nodeSpace address = some raw' := fun raw' mem => by
            rcases List.mem_cons.mp mem with here | there
            · exact ⟨address, here ▸ held⟩
            · exact stored raw' there
          cases decoded : decode raw with
          | error message =>
            simp only [decoded] at ran
            change Proof.executeReads store budget (.pure (.ok (.error (.decode message))) : Program Storage (Reply Result)) = _ at ran
            simp [Proof.executeReads] at ran
          | ok node =>
            -- A proof that ends here, with no payload: the nodes so far, reversed.
            have ended : ∀ (proof : Proof), proof = ⟨(raw :: acc).reverse, none⟩ → Stored store proof ∧
                ∀ snapshot, Covers store snapshot proof → raw ∈ proof.nodes ∧ snapshot nodeSpace address = some raw := by
              intro proof shape
              subst shape
              refine ⟨⟨fun raw' mem => stored' raw' (List.mem_reverse.mp mem), fun _ h => by cases h⟩,
                fun snapshot covers => ?_⟩
              have mem : raw ∈ (raw :: acc).reverse := List.mem_reverse.mpr (List.mem_cons_self ..)
              exact ⟨mem, covers.1 raw mem address held⟩
            -- A proof that ends at a value found here.
            have valued : ∀ (value : Value) (proof : Proof),
                Proof.executeReads store budget (found value (raw :: acc)).run = some (.ok (.ok proof)) →
                Stored store proof ∧ ∀ snapshot, Covers store snapshot proof →
                  raw ∈ proof.nodes ∧ snapshot nodeSpace address = some raw ∧ ∀ budget',
                    Proof.executeReads snapshot budget' (resolveValue value).run =
                      Proof.executeReads store budget' (resolveValue value).run := by
              intro value proof ran
              obtain ⟨nodes, payload⟩ := found_run store value (raw :: acc) budget proof ran
              have mem : raw ∈ proof.nodes := by rw [nodes]; exact List.mem_reverse.mpr (List.mem_cons_self ..)
              refine ⟨⟨fun raw' mem' => stored' raw' (by rw [nodes] at mem'; exact List.mem_reverse.mp mem'),
                fun bytes h => ?_⟩, fun snapshot covers => ⟨mem, covers.1 raw mem address held, fun budget' => ?_⟩⟩
              · cases value with
                | inline _ =>
                  have : proof.value = none := by
                    change Proof.executeReads store budget (.pure (.ok (.ok ⟨(raw :: acc).reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
                    simp [Proof.executeReads] at ran
                    rw [← ran]
                  rw [this] at h; cases h
                | hash a =>
                  obtain ⟨bytes', same', held'⟩ := payload a rfl
                  rw [same'] at h; cases h
                  exact ⟨a, held'⟩
              · apply resolve_agrees
                intro a hv
                obtain ⟨bytes, same', held'⟩ := payload a hv
                exact ⟨bytes, held', covers.2 bytes same' a held'⟩
            cases node with
            | leaf suffix value =>
              simp only [decoded] at ran
              split at ran
              next same =>
                obtain ⟨stored'', rest'⟩ := valued value proof ran
                refine ⟨stored'', fun snapshot covers budget' => ?_⟩
                obtain ⟨_, covered, agrees⟩ := rest' snapshot covers
                refine lookup_step store snapshot address raw held covered _ _ rfl (fun budget'' => ?_) budget'
                dsimp only [Program.bind, ExceptT.bindCont]
                rw [decoded]
                dsimp only
                simp only [same, if_true]
                exact agrees budget''
              next differ =>
                change Proof.executeReads store budget (.pure (.ok (.ok ⟨(raw :: acc).reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
                simp [Proof.executeReads] at ran
                obtain ⟨stored'', rest'⟩ := ended proof (by rw [← ran]; simp)
                refine ⟨stored'', fun snapshot covers budget' => ?_⟩
                obtain ⟨_, covered⟩ := rest' snapshot covers
                refine lookup_step store snapshot address raw held covered _ _ rfl (fun budget'' => ?_) budget'
                dsimp only [Program.bind, ExceptT.bindCont]
                rw [decoded]
                dsimp only
                simp only [differ]
                change Proof.executeReads _ budget'' (.pure (.ok (.ok none) : Reply LookupResult)) =
                  Proof.executeReads _ budget'' (.pure (.ok (.ok none) : Reply LookupResult))
                cases budget'' <;> rfl
            | extension segment child =>
              simp only [decoded] at ran
              split at ran
              next dead =>
                change Proof.executeReads store budget (.pure (.ok (.ok ⟨(raw :: acc).reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
                simp [Proof.executeReads] at ran
                obtain ⟨stored'', rest'⟩ := ended proof (by rw [← ran]; simp)
                refine ⟨stored'', fun snapshot covers budget' => ?_⟩
                obtain ⟨_, covered⟩ := rest' snapshot covers
                refine lookup_step store snapshot address raw held covered _ _ rfl (fun budget'' => ?_) budget'
                dsimp only [Program.bind, ExceptT.bindCont]
                rw [decoded]
                dsimp only
                simp only [dead, if_true]
                change Proof.executeReads _ budget'' (.pure (.ok (.ok none) : Reply LookupResult)) =
                  Proof.executeReads _ budget'' (.pure (.ok (.ok none) : Reply LookupResult))
                cases budget'' <;> rfl
              next alive =>
                obtain ⟨stored'', agrees⟩ :=
                  ih (some child) (rest.drop segment.toList.length) (raw :: acc) budget proof stored' ran
                refine ⟨stored'', fun snapshot covers budget' => ?_⟩
                have inProof : raw ∈ proof.nodes :=
                  proveAt_keeps store fuel (some child) _ (raw :: acc) budget proof ran raw (List.mem_cons_self ..)
                refine lookup_step store snapshot address raw held (covers.1 raw inProof address held) _ _ rfl
                  (fun budget'' => ?_) budget'
                dsimp only [Program.bind, ExceptT.bindCont]
                rw [decoded]
                dsimp only
                simp only [alive]
                exact agrees snapshot covers budget''
            | branch children value =>
              simp only [decoded] at ran
              cases rest with
              | nil =>
                cases value with
                | none =>
                  change Proof.executeReads store budget (.pure (.ok (.ok ⟨(raw :: acc).reverse, none⟩)) : Program Storage (Reply Result)) = _ at ran
                  simp [Proof.executeReads] at ran
                  obtain ⟨stored'', rest'⟩ := ended proof (by rw [← ran]; simp)
                  refine ⟨stored'', fun snapshot covers budget' => ?_⟩
                  obtain ⟨_, covered⟩ := rest' snapshot covers
                  refine lookup_step store snapshot address raw held covered _ _ rfl (fun budget'' => ?_) budget'
                  dsimp only [Program.bind, ExceptT.bindCont]
                  rw [decoded]
                  dsimp only
                  change Proof.executeReads _ budget'' (.pure (.ok (.ok none) : Reply LookupResult)) =
                    Proof.executeReads _ budget'' (.pure (.ok (.ok none) : Reply LookupResult))
                  cases budget'' <;> rfl
                | some value =>
                  obtain ⟨stored'', rest'⟩ := valued value proof ran
                  refine ⟨stored'', fun snapshot covers budget' => ?_⟩
                  obtain ⟨_, covered, agrees⟩ := rest' snapshot covers
                  refine lookup_step store snapshot address raw held covered _ _ rfl (fun budget'' => ?_) budget'
                  dsimp only [Program.bind, ExceptT.bindCont]
                  rw [decoded]
                  dsimp only
                  exact agrees budget''
              | cons nibble rest =>
                obtain ⟨stored'', agrees⟩ :=
                  ih ((children[nibble.toNat]?).getD none) rest (raw :: acc) budget proof stored' ran
                refine ⟨stored'', fun snapshot covers budget' => ?_⟩
                have inProof : raw ∈ proof.nodes :=
                  proveAt_keeps store fuel _ rest (raw :: acc) budget proof ran raw (List.mem_cons_self ..)
                refine lookup_step store snapshot address raw held (covers.1 raw inProof address held) _ _ rfl
                  (fun budget'' => ?_) budget'
                dsimp only [Program.bind, ExceptT.bindCont]
                rw [decoded]
                dsimp only
                exact agrees snapshot covers budget''

/-- On an addressed store, addressing the nodes of a proof drawn from it
succeeds and lists each node under the address the store holds it at. -/
theorem addressWith_stored (store : RawSnapshot) (hash : ByteArray → ByteArray)
    (addressed : Addressed store hash) : ∀ (nodes : List ByteArray),
    (∀ raw ∈ nodes, ∃ address, store nodeSpace address = some raw) →
    ∃ listed, addressWith hash nodes = .ok listed ∧
      (∀ raw ∈ nodes, ∀ address, store nodeSpace address = some raw → (address, raw) ∈ listed) ∧
      ∀ entry ∈ listed, store nodeSpace entry.1 = some entry.2 := by
  intro nodes
  induction nodes with
  | nil => intro _; exact ⟨[], rfl, fun _ mem => (List.not_mem_nil mem).elim, fun _ mem => (List.not_mem_nil mem).elim⟩
  | cons raw rest ih =>
    intro stored
    obtain ⟨address, held⟩ := stored raw (List.mem_cons_self ..)
    obtain ⟨node, admitted, hashed⟩ := addressed.1 address raw held
    obtain ⟨listed, ok, mem, sound⟩ := ih fun raw' mem => stored raw' (List.mem_cons_of_mem _ mem)
    refine ⟨(hash (tagOf node ++ raw), raw) :: listed, ?_, fun raw' mem' address' held' => ?_, fun entry mem' => ?_⟩
    · simp only [addressWith, admitted, ok]
    · rcases List.mem_cons.mp mem' with here | there
      · subst here
        obtain ⟨node', admitted', hashed'⟩ := addressed.1 address' raw' held'
        rw [admitted] at admitted'
        cases admitted'
        rw [hashed']
        exact List.mem_cons_self ..
      · exact List.mem_cons_of_mem _ (mem raw' there address' held')
    · rcases List.mem_cons.mp mem' with here | there
      · subst here
        simp only [hashed]
        exact held
      · exact sound entry there

/-- The first entry a snapshot finds under an address it holds a stored
node at is that node. -/
theorem find_stored (store : RawSnapshot) (listed : List (ByteArray × ByteArray)) (address raw : ByteArray)
    (mem : (address, raw) ∈ listed) (sound : ∀ entry ∈ listed, store nodeSpace entry.1 = some entry.2)
    (held : store nodeSpace address = some raw) :
    (listed.find? fun entry => entry.1 == address).map (·.2) = some raw := by
  cases found : listed.find? fun entry => entry.1 == address with
  | none =>
    have := List.find?_eq_none.mp found (address, raw) mem
    simp at this
  | some entry =>
    have pred := List.find?_some found
    have same : entry.1 = address := (byteArray_beq_iff _ _).mp pred
    have stored := sound entry (List.mem_of_find?_eq_some found)
    rw [same, held] at stored
    simp only [Option.map_some, Option.some.injEq]
    exact (Option.some.inj stored).symm

/-- The round trip: on a store addressed by its digests, the proof `prove`
builds for a key verifies to exactly what `get` answers for it. -/
theorem prove_verifies (store : RawSnapshot) (hash : ByteArray → ByteArray) (addressed : Addressed store hash)
    (root key : ByteArray) (budget : Nat) (proof : Proof)
    (proved : Proof.executeReads store budget (prove root key).run = some (.ok (.ok proof))) :
    ∃ result, Proof.executeReads store (maxKeyBytes * 2 + 2) (get root key).run = some (.ok result) ∧
      verifyWith hash root key proof.nodes proof.value = result.mapError .lookup := by
  unfold prove at proved
  split at proved
  · change Proof.executeReads store budget (.pure (.ok (.error (.keyTooLong key.size))) : Program Storage (Reply Result)) = _ at proved
    simp [Proof.executeReads] at proved
  · rename_i bounded
    obtain ⟨stored, agrees⟩ := proveAt_lookup store _ (rootOf root) (keyNibbles key) [] budget proof
      (fun _ mem => (List.not_mem_nil mem).elim) proved
    obtain ⟨listed, ok, mem, sound⟩ := addressWith_stored store hash addressed proof.nodes stored.1
    have covers : Covers store (snapshotOf listed (proof.value.map fun bytes => (hash bytes, bytes))) proof := by
      refine ⟨fun raw mem' address held => ?_, fun bytes valued address held => ?_⟩
      · unfold snapshotOf
        simp only [beq_self_eq_true, if_true]
        exact find_stored store listed address raw (mem raw mem' address held) sound held
      · unfold snapshotOf
        have distinct : (valueSpace == nodeSpace) = false := by decide
        simp only [distinct, Bool.false_eq_true, if_false, beq_self_eq_true, if_true, valued, Option.map_some,
          Option.bind_some, addressed.2 address bytes held]
    obtain ⟨result, answered⟩ := check_answers root key listed (proof.value.map fun bytes => (hash bytes, bytes))
    have same := agrees _ covers (maxKeyBytes * 2 + 2)
    simp only [rootOf] at same
    have answeredGet := answered
    unfold check Trie.get at answered
    rw [if_neg bounded] at answered
    refine ⟨result, ?_, ?_⟩
    · unfold Trie.get
      rw [if_neg bounded, ← same]
      exact answered
    · unfold verifyWith
      rw [ok]
      dsimp only
      rw [answeredGet]

/-! ## A concrete trie

The five nodes of `TrieServeProofs` under a canonical root: a branch with
the extension at nibble 6 and a leaf spelling the key `50` at nibble 5, so
every node admits. The host's digest names each node's address and the
payload's. -/

open TrieServeProofs (bytes address extHash lowerHash leafAHash leafBHash valueHash slots extNode lowerNode
  leafANode leafBNode payload graph reads)

private def keyA : ByteArray := bytes [0x67, 0x01, 0x11]
private def keyB : ByteArray := bytes [0x67, 0x02, 0x22]
private def keyC : ByteArray := bytes [0x50]
private def absent : ByteArray := bytes [0x67, 0x03]
private def valueA : ByteArray := bytes [97]
private def valueC : ByteArray := bytes [42]
private def leafCHash := address 14
private def topHash := address 15
private def leafCNode : Node := .leaf (bytes [0]) (.inline valueC)
private def topNode : Node := .branch (slots [(5, leafCHash), (6, extHash)]) none

private def fixtureHash (bytes : ByteArray) : ByteArray :=
  if bytes == branchTag ++ encode topNode then topHash
  else if bytes == extensionTag ++ encode extNode then extHash
  else if bytes == branchTag ++ encode lowerNode then lowerHash
  else if bytes == leafTag ++ encode leafANode then leafAHash
  else if bytes == leafTag ++ encode leafBNode then leafBHash
  else if bytes == leafTag ++ encode leafCNode then leafCHash
  else if bytes == payload then valueHash
  else address 0

/-- The store, addressed by `fixtureHash`. -/
private def canon : State :=
  { graph with
    hash := fixtureHash,
    files := graph.files ++ [((nodeSpace, leafCHash), encode leafCNode), ((nodeSpace, topHash), encode topNode)] }

/-- A verifier holds nothing but the digest. -/
private def verifier : State := { hash := fixtureHash }

private def spine : List ByteArray := [encode topNode, encode extNode, encode lowerNode]
private def digests (count : Nat) : List String := List.replicate count "digest"

/-- A proof is the path read down to the key: the nodes on it, root first,
and the payload when the value is out of line; an absent key's proof ends
where the path does; the empty root proves nothing with no read. -/
theorem a_proof_is_the_path_read :
    (let result := SimulatedHost.run (prove topHash keyA) canon
     (result.1, result.2.trace) == (.ok (.ok ⟨spine ++ [encode leafANode], none⟩), reads 4)) ∧
    (let result := SimulatedHost.run (prove topHash keyB) canon
     (result.1, result.2.trace) ==
       (.ok (.ok ⟨spine ++ [encode leafBNode], some payload⟩), reads 4 ++ ["bytes:" ++ valueSpace])) ∧
    (let result := SimulatedHost.run (prove topHash keyC) canon
     (result.1, result.2.trace) == (.ok (.ok ⟨[encode topNode, encode leafCNode], none⟩), reads 2)) ∧
    (let result := SimulatedHost.run (prove topHash absent) canon
     (result.1, result.2.trace) == (.ok (.ok ⟨spine, none⟩), reads 3)) ∧
    (let result := SimulatedHost.run (prove (address 0) keyA) canon
     (result.1, result.2.trace) == (.ok (.ok ⟨[], none⟩), [])) := by
  decide +kernel

/-- Each proof verifies to what the store holds, with one digest per node
and one for the payload, and nothing read from anywhere. -/
theorem a_proof_verifies_to_what_the_store_holds :
    (let result := SimulatedHost.run (Proof.verify (E := Digest) topHash keyA (spine ++ [encode leafANode]) none) verifier
     (result.1, result.2.trace) == (.ok (.ok (some valueA)), digests 4)) ∧
    (let result := SimulatedHost.run (Proof.verify (E := Digest) topHash keyB (spine ++ [encode leafBNode]) (some payload))
       verifier
     (result.1, result.2.trace) == (.ok (.ok (some payload)), digests 5)) ∧
    (let result := SimulatedHost.run (Proof.verify (E := Digest) topHash keyC [encode topNode, encode leafCNode] none)
       verifier
     (result.1, result.2.trace) == (.ok (.ok (some valueC)), digests 2)) ∧
    (let result := SimulatedHost.run (Proof.verify (E := Digest) topHash absent spine none) verifier
     (result.1, result.2.trace) == (.ok (.ok none), digests 3)) ∧
    (let result := SimulatedHost.run (Proof.verify (E := Digest) (address 0) keyA [] none) verifier
     (result.1, result.2.trace) == (.ok (.ok none), [])) := by
  decide +kernel

/-- Absence cannot be claimed by omission: the spine alone, offered for a
key that is there, is a missing node, not an absence; a substituted payload
is a missing value; a proof is bound to the root it was made against; and
bytes that are no node refuse the proof whole. -/
theorem a_tampered_proof_never_verifies :
    (let result := SimulatedHost.run (Proof.verify (E := Digest) topHash keyA spine none) verifier
     (result.1, result.2.trace) == (.ok (.error (.lookup (.missingNode leafAHash))), digests 3)) ∧
    (let result := SimulatedHost.run (Proof.verify (E := Digest) topHash keyB (spine ++ [encode leafBNode])
       (some (bytes [9]))) verifier
     (result.1, result.2.trace) == (.ok (.error (.lookup (.missingValue valueHash))), digests 5)) ∧
    (let result := SimulatedHost.run (Proof.verify (E := Digest) (address 9) keyA (spine ++ [encode leafANode]) none)
       verifier
     (result.1, result.2.trace) == (.ok (.error (.lookup (.missingNode (address 9)))), digests 4)) ∧
    (let result := SimulatedHost.run (Proof.verify (E := Digest) topHash keyA (spine ++ [bytes [0xFF]]) none) verifier
     (result.1, result.2.trace) == (.ok (.error (.refused (.decode "unexpected end of node"))), digests 3)) := by
  decide +kernel

/-- Proving and verifying write nothing: a failure at any effect is the
answer, and the store is exactly as it was. -/
theorem every_failed_proof_effect_changes_nothing :
    ((List.range 5).all fun index =>
      let result := SimulatedHost.run (prove topHash keyB) (fail canon index)
      failed result.1 && result.2.files == canon.files) = true ∧
    ((List.range 5).all fun index =>
      let result := SimulatedHost.run (Proof.verify (E := Digest) topHash keyB (spine ++ [encode leafBNode])
        (some payload)) (fail verifier index)
      failed result.1 && result.2.files == verifier.files) = true := by
  decide +kernel

end Synchronicity.TrieMerkleProofs
