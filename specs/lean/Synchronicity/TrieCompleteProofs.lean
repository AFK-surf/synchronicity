import VerifiedCore.Trie.Complete
import Synchronicity.TrieMissingProofs

/-! Completeness composes the requesting walk and the raw memo guard. These
theorems identify exhaustion and the exact generation under which it is
certified, including every host failure. They do not yet prove the missing
walk's exhaustion/coverage theorem or concurrent refinement of the host. -/
namespace Synchronicity.TrieCompleteProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Trie.Missing
  VerifiedCore.Trie.Complete SimulatedHost
open TrieServePrivacyProofs (bind_ok)

/-- Once generation and walk have succeeded, the operation returns exactly
the memo's verdict on that ticket if exhausted, and false otherwise. -/
theorem recheck_after_walk [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root key : ByteArray) (state started walked : State)
    (generation : UInt64) (frontier : Frontier V H) (batch : Batch)
    (ticket : execute (Complete.memo .generation) state = (.ok generation, started))
    (walk : execute (inspectRoot V H context root) started = (.ok (frontier, .ok batch), walked)) :
    execute (recheck V H context root key) state =
      if frontier.isExhausted then execute (Complete.memo (.certify key generation)) walked
      else (.ok false, walked) := by
  simp only [recheck, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind, ticket, walk]
  split <;> rfl

/-- Any successful new certificate is offered only after exhaustion, and
uses the ticket read before the walk, never a fresh ticket after it. -/
theorem recheck_true_has_original_ticket [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root key : ByteArray) (state : State)
    (ran : (execute (recheck V H context root key) state).1 = .ok true) :
    ∃ generation started walked frontier batch,
      execute (Complete.memo .generation) state = (.ok generation, started) ∧
      execute (inspectRoot V H context root) started = (.ok (frontier, .ok batch), walked) ∧
      frontier.isExhausted = true ∧
      (execute (Complete.memo (.certify key generation)) walked).1 = .ok true := by
  unfold recheck at ran
  obtain ⟨generation, started, ticket, ran⟩ := bind_ok _ _ state true ran
  obtain ⟨⟨frontier, result⟩, walked, walk, ran⟩ := bind_ok _ _ started true ran
  cases result with
  | error error => cases ran
  | ok batch =>
    cases exhausted : frontier.isExhausted with
    | false => simp only [exhausted, Bool.false_eq_true, ↓reduceIte] at ran; cases ran
    | true =>
      simp only [exhausted, ↓reduceIte] at ran
      exact ⟨generation, started, walked, frontier, batch, ticket, walk, exhausted, ran⟩

/-- A successful completeness answer either uses an existing certificate
under the computed scope/owner key or comes from the guarded walk under
that same key. The memo never sees the bare root substituted for it. -/
theorem complete_true_uses_its_key [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) (state : State)
    (ran : (execute (isComplete V H context root) state).1 = .ok true) :
    ∃ key keyed checked known,
      execute (Memo.keyFor (E := Complete.Effects) Missing.Error.host context.scope root context.owner) state =
        (.ok key, keyed) ∧
      execute (Complete.memo (.isKnown key)) keyed = (.ok known, checked) ∧
      (known = true ∨ (execute (recheck V H context root key) checked).1 = .ok true) := by
  unfold isComplete at ran
  obtain ⟨key, keyed, keyRun, ran⟩ := bind_ok _ _ state true ran
  obtain ⟨known, checked, knownRun, ran⟩ := bind_ok _ _ keyed true ran
  refine ⟨key, keyed, checked, known, keyRun, knownRun, ?_⟩
  cases known with
  | true => exact .inl rfl
  | false => exact .inr ran

/-- The memo's decision for an ordinary store: no cached success during an
invalidating mutation, after a generation change, or at the terminal epoch.
A transactional view can validate its ticket without caching its writes. -/
theorem certification_guard (key : ByteArray) (generation : UInt64) (state : State)
    (quiet : state.faults = []) :
    (execute (Complete.memo (.certify key generation)) state).1 =
      .ok (generation == state.memoGeneration &&
        (!state.memoWritable || (!state.memoBlocked && generation != 18446744073709551615))) := by
  simp [Complete.memo, raise, performOver, Inject.inject, ExceptT.mk, execute, Interpreter.handle,
    SimulatedHost.memo, reply, fault, quiet, Except.mapError]

/-! ## Histories on the shared raw host -/
open TrieServeProofs TrieMissingProofs

def complete (context : Context) (root : ByteArray) : Complete.Action Bool :=
  isComplete (List Visit) (List ByteArray) context root

theorem a_known_root_is_answered_without_walking :
    let result := SimulatedHost.run (complete full rootHash) { certified := [rootHash] }
    result.1 == .ok true && result.2.trace == ["memo:known"] := by
  decide +kernel

theorem a_new_certificate_follows_the_walk :
    let result := SimulatedHost.run (complete full rootHash) withValue
    result.1 == .ok true && result.2.certified == [rootHash] &&
      result.2.trace == ["memo:known", "memo:generation", "bytes:" ++ nodeSpace,
        "bytes:" ++ nodeSpace, "bytes:" ++ nodeSpace, "bytes:" ++ nodeSpace,
        "bytes:" ++ nodeSpace, "snapshot:" ++ valueSpace, "bytes:" ++ nodeSpace, "memo:certify"] := by
  decide +kernel

theorem a_missing_value_prevents_certification :
    let result := SimulatedHost.run (complete full rootHash) withoutValue
    result.1 == .ok false && result.2.certified == [] && !result.2.trace.contains "memo:certify" := by
  decide +kernel

theorem a_transactional_answer_does_not_cache_uncommitted_rows :
    let result := SimulatedHost.run (complete full rootHash) { withValue with memoWritable := false }
    result.1 == .ok true && result.2.certified == [] := by
  decide +kernel

theorem a_blocked_or_terminal_memo_refuses_a_new_certificate :
    (let result := SimulatedHost.run (complete full rootHash)
       { withValue with memoBlocked := true, certified := [rootHash] }
     result.1 == .ok false && result.2.trace.contains "memo:certify") ∧
    (let result := SimulatedHost.run (complete full rootHash)
       { withValue with memoGeneration := 18446744073709551615 }
     result.1 == .ok false && result.2.certified == []) := by
  decide +kernel

theorem stale_ticket_never_certifies :
    let result := SimulatedHost.run (Complete.memo (.certify rootHash 5)) { memoGeneration := 7 }
    result.1 == .ok false && result.2.certified == [] := by
  decide +kernel

/-- Every failing effect of a full walk, including the final certification,
preserves the store and leaves no new certificate. -/
theorem every_failed_effect_leaves_no_certificate :
    (List.range 10).all (fun index =>
      let result := SimulatedHost.run (complete full rootHash) (CasFixtures.fail withValue index)
      CasFixtures.failed result.1 && result.2.certified == [] &&
        result.2.files == withValue.files && result.2.db == withValue.db) = true := by
  decide +kernel

end Synchronicity.TrieCompleteProofs
