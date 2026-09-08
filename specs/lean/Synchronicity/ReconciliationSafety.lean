import Synchronicity.AcceptanceProtection
import Synchronicity.FetchLifecycle

/-! M3: obsolete work cannot damage newer selections or accepted versions.

The observations are raw heads rows and the backed relational slot invariant,
not an assumed decision of the reconciler. The main obligations are:

* `ReconciliationFailure.obsolete_preserves_heads`: an obsolete advertisement
  leaves every committed head unchanged on every outcome.
* `AcceptanceProtection.complete_retained`: even a newly accepted advertisement
  cannot change a complete row.
* `PromotionCommand.promote_preserves_complete_floor`: the whole promotion keeps
  a backed complete version present, or replaces it only by a newer version.
* `PromotionCommand.prepare_pending_floor`: promotion selects the pending version
  in its own transaction snapshot; readiness checks do not replace that snapshot.
* `FetchHeadSafety.every_resumption_preserves` and
  `RetirementProtection.every_resumption_preserves`: all residual programs and
  execution prefixes retain every row outside their captured full pending key,
  in an arbitrary new resumption database, with arbitrary injected failures.
* `fetch_cannot_bypass_current_promotion`: the whole outer Fetch can change a
  complete row only by executing a new promotion, with that row still present
  immediately before it. Its final state is that actual promotion's final state.

`StaleHistory` composes the non-publication obligations over any finite ordering
of actual commands and suspended continuations. Each segment may come from a
different requesting task. Universal resumption quantification also lets a
scheduler select a newly installed row after every intervening fresh command;
it does not require the database to remain equal to the old selection snapshot.

Transactions are exclusive raw-host transactions. Backed slots agree on their
pointer (the ordinary primary-key schema); orphan/corrupt-pointer recovery is
not claimed. SQLite/concurrent refinement remains the tested host contract.
M3 is safety, not exact-view readiness, convergence, fairness or M4. -/
namespace Synchronicity.ReconciliationSafety
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication SimulatedHost PrivateDatabase

/-- The constructors are actual stale operations, not arbitrary transitions
assumed to preserve the desired invariant. Target mismatch is a raw full-key
comparison, so a replacement at the same sequence but another root is protected. -/
inductive StaleStep (row : Fields) : State → State → Prop where
  | advertisement (head : Head) (now : Int64) (keep : Nat) (state : State)
      (slot : String) (which : slot = "complete" ∨ slot = "pending") (seq : Int64) (root : ByteArray)
      (stored : ReconciliationRead.StoredFloor state.db (Origin.canonical head.origin) slot seq root)
      (obsolete : Reconcile.newer head.seq head.root ⟨seq.toUInt64, root⟩ = false) :
      StaleStep row state (execute (Reconcile.accept head now keep) state).2
  | request (target : Trie.Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat)
      (continuation rest : Program Trie.Fetch.Effects (Except Trie.Fetch.Error Bool))
      (reachable : Continuation (Trie.Fetch.fetch (Std.HashSet Trie.Missing.Visit)
        (Std.HashSet ByteArray) target reference maximum retryLimit).run continuation)
      (state final : State) (closed : state.pending = none)
      (path : Prefix continuation state rest final)
      (different : equals row (Trie.Fetch.targetRows target) = false) : StaleStep row state final
  | retirement (pending : Promote.Pending)
      (continuation rest : Program Promote.Effects (Except Promote.Error Unit))
      (reachable : Continuation (Promote.retire pending).run continuation)
      (state final : State) (closed : state.pending = none)
      (path : Prefix continuation state rest final)
      (different : equals row (RetirementProtection.key pending) = false) : StaleStep row state final
  | selection (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
      (state : State) (closed : state.pending = none) :
      StaleStep row state (execute (FetchLifecycle.select origin expected) state).2
  | settlement (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
      (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray)
      (result : Except Promote.Error Bool) (notComplete : result ≠ .ok true)
      (state : State) (closed : state.pending = none)
      (different : equals row (Trie.Fetch.targetRows target) = false) :
      StaleStep row state (execute (FetchLifecycle.settle origin refused target key result) state).2

theorem StaleStep.retains (step : StaleStep row state final)
    (present : row ∈ rows state.db "heads") : row ∈ rows final.db "heads" := by
  cases step with
  | advertisement head now keep state slot which seq root stored obsolete =>
    rwa [ReconciliationFailure.obsolete_preserves_heads head now keep state slot which seq root stored obsolete]
  | request target reference maximum retryLimit continuation rest reachable state final closed path different =>
    exact FetchHeadSafety.every_resumption_preserves _ _ target reference maximum retryLimit
      continuation rest reachable state final closed path row present different
  | retirement pending continuation rest reachable state final closed path different =>
    exact RetirementProtection.every_resumption_preserves pending continuation rest reachable state final closed path row present different
  | selection origin expected state closed =>
    exact ((FetchLifecycle.select_only row origin expected).invariant (ProtectedHead.retained row)
      (FetchLifecycle.effects_retain row) state (ProtectedHead.initial row state closed present)).1
  | settlement origin refused target key result notComplete state closed different =>
    exact ((FetchLifecycle.settle_without_publication row origin refused target key result notComplete different).invariant
      (ProtectedHead.retained row) (FetchLifecycle.effects_retain row) state
      (ProtectedHead.initial row state closed present)).1

inductive StaleHistory (row : Fields) : State → State → Prop where
  | nil (state : State) : StaleHistory row state state
  | cons {state next final : State} :
      StaleStep row state next → StaleHistory row next final → StaleHistory row state final

/-- Arbitrarily many reordered/duplicated obsolete advertisements, requester
resumptions and post-rollback cleanups cannot overwrite or clear a newer row. -/
theorem stale_history_retains (history : StaleHistory row state final)
    (present : row ∈ rows state.db "heads") : row ∈ rows final.db "heads" := by
  induction history with
  | nil _ => exact present
  | cons step rest ih => exact ih (step.retains present)

theorem fetch_cannot_bypass_current_promotion (row : Fields) (rowOrigin : String)
    (complete : ReconciliationSlots.names row rowOrigin "complete" = true)
    (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
    (refused : List (UInt64 × ByteArray × ByteArray)) (maximum retryLimit : Nat)
    (state : State) (closed : state.pending = none) (present : row ∈ rows state.db "heads")
    (changed : row ∉ rows (execute (Fetch.fetch origin expected refused maximum retryLimit) state).2.db "heads") :
    ∃ now current,
      ProtectedHead.retained row current ∧
      (execute (Promote.promote origin now refused) current).2 =
        (execute (Fetch.fetch origin expected refused maximum retryLimit) state).2 ∧
      row ∉ rows (execute (Promote.promote origin now refused) current).2.db "heads" :=
  (FetchLifecycle.fetch_complete_phases row rowOrigin complete origin expected refused maximum retryLimit).loss_requires_fresh
    state (ProtectedHead.initial row state closed present) changed

end Synchronicity.ReconciliationSafety
