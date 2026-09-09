import Synchronicity.PromotionTransition
import Synchronicity.FetchLifecycle

namespace Synchronicity.FetchTransition
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication SimulatedHost PrivateDatabase

theorem selection (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
    (state : State) (closed : state.pending = none)
    (before : HeadView.Represents state.db view)
    (after : HeadView.Represents (execute (FetchLifecycle.select origin expected) state).2.db nextView) :
    HeadTransition [] view nextView := by
  apply HeadView.refines_retained before after
  intro row present
  exact ((FetchLifecycle.select_only row origin expected).invariant (ProtectedHead.retained row)
    (FetchLifecycle.effects_retain row) state (ProtectedHead.initial row state closed present)).1

theorem empty_unmatched (target : Trie.Fetch.Target) : equals [] (Trie.Fetch.targetRows target) = false := by
  simp [Trie.Fetch.targetRows, equals, cell, isCell, equalCell, BEq.beq, instBEqCell.beq]

theorem abandonment (target : Trie.Fetch.Target) (state : State) (closed : state.pending = none)
    (before : HeadView.Represents state.db view)
    (after : HeadView.Represents
      (execute (within Fetch.fetchError (Trie.Fetch.abandon target) : Fetch.Action Unit) state).2.db nextView) :
    HeadTransition [TargetTransition.fetchKey target] view nextView := by
  apply TargetTransition.refines _ before after
  · exact HeadKeyFrame.no_new_keys _ (FetchLifecycle.abandon_only [] target (empty_unmatched target))
      (fun predicate => FetchLifecycle.effects_preserve_keys predicate []) state closed
  · intro row present different
    rw [TargetTransition.fetch_fields] at different
    exact ((FetchLifecycle.abandon_only row target different).invariant (ProtectedHead.retained row)
      (FetchLifecycle.effects_retain row) state (ProtectedHead.initial row state closed present)).1

theorem incomplete_settlement (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
    (scope : Trie.Serve.Scope) (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray)
    (result : Except Promote.Error Bool)
    (notComplete : result ≠ .ok true) (state : State) (closed : state.pending = none)
    (before : HeadView.Represents state.db view)
    (after : HeadView.Represents (execute (FetchLifecycle.settle origin refused scope target key result) state).2.db nextView) :
    HeadTransition [TargetTransition.fetchKey target] view nextView := by
  apply TargetTransition.refines _ before after
  · exact HeadKeyFrame.no_new_keys _
      (FetchLifecycle.settle_without_publication [] origin refused scope target key result notComplete (empty_unmatched target))
      (fun predicate => FetchLifecycle.effects_preserve_keys predicate []) state closed
  · intro row present different
    rw [TargetTransition.fetch_fields] at different
    exact ((FetchLifecycle.settle_without_publication row origin refused scope target key result notComplete different).invariant
      (ProtectedHead.retained row) (FetchLifecycle.effects_retain row) state (ProtectedHead.initial row state closed present)).1

/-- Publication captures the freshly read pending head, never the requester's
old target. A failed clock grants no consumption permission. -/
def publicationCaptures (origin : Origin.Parsed) (state : State) : List CapturedHead :=
  match execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state with
  | (.error _, _) => []
  | (.ok now, current) => PromotionTransition.captures origin now current

theorem completed_settlement (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
    (scope : Trie.Serve.Scope) (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray)
    (state : State) (closed : state.pending = none)
    (before : HeadView.Represents state.db view) (backed : HeadView.Backed state.db view)
    (after : HeadView.Represents (execute (FetchLifecycle.settle origin refused scope target key (.ok true)) state).2.db nextView) :
    HeadTransition (publicationCaptures origin state) view nextView := by
  have dbFrame : (execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state).2.db = state.db := by
    apply reply_preserves_db
    intro s
    rfl
  have pendingFrame : (execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state).2.pending = state.pending := by
    apply ReconciliationReadOnly.reply_pending
    intro s
    rfl
  unfold FetchLifecycle.settle at after
  simp only [bind, ExceptT.bind, ExceptT.mk, execute_bind] at after
  unfold publicationCaptures
  generalize clockRead : execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state = result at dbFrame pendingFrame after ⊢
  obtain ⟨result, current⟩ := result
  cases result with
  | error error =>
    change HeadView.Represents current.db nextView at after
    rw [dbFrame] at after
    exact HeadView.refines_retained before after (fun _ member => member)
  | ok now =>
    dsimp only
    apply PromotionTransition.refines origin now refused current (pendingFrame.trans closed)
    · rwa [dbFrame]
    · rwa [dbFrame]
    · dsimp only [ExceptT.bindCont, ExceptT.run] at after
      rw [execute_bind] at after
      simp only [Fetch.lift] at after
      rw [OperationExecution.within_eq FetchLifecycle.promote_agrees] at after
      generalize promoted : execute (Promote.promote origin now refused) current = result at after ⊢
      obtain ⟨result, final⟩ := result
      cases result <;> exact after

def captures (origin : Origin.Parsed) (target : Trie.Fetch.Target)
    (result : Except Promote.Error Bool) (state : State) : List CapturedHead :=
  match result with
  | .ok true => publicationCaptures origin state
  | _ => [TargetTransition.fetchKey target]

theorem settlement (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
    (scope : Trie.Serve.Scope) (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray)
    (result : Except Promote.Error Bool)
    (state : State) (closed : state.pending = none)
    (before : HeadView.Represents state.db view) (backed : HeadView.Backed state.db view)
    (after : HeadView.Represents (execute (FetchLifecycle.settle origin refused scope target key result) state).2.db nextView) :
    HeadTransition (captures origin target result state) view nextView := by
  cases result with
  | error error => exact incomplete_settlement origin refused scope target key _ (by simp) state closed before after
  | ok result =>
    cases result with
    | false => exact incomplete_settlement origin refused scope target key _ (by simp) state closed before after
    | true => exact completed_settlement origin refused scope target key state closed before backed after

end Synchronicity.FetchTransition
