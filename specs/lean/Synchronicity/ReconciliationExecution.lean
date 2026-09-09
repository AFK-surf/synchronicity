import Synchronicity.AcceptanceTransition
import Synchronicity.RetirementTransition
import Synchronicity.FetchTransition

/-! Actual command/resumption traces and their refinement to the M3 head
transition relation. Constructors carry execution facts only; neither version
comparisons nor the required postcondition restrict which steps are admitted.

The outer Fetch decomposition is checked by FetchLifecycle.fetch_decomposes.
A requester/retirement may resume in a different database, with arbitrary replies.
Transactions are exclusive: each command/resumption starts closed; a finite
prefix may end inside its own transaction, but another task cannot start there. -/
namespace Synchronicity.ReconciliationExecution
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication SimulatedHost PrivateDatabase

inductive Event where
  | advertisement (head : Head) (now : Int64) (keep : Nat)
  | promotion (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
  | request (target : Trie.Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat)
  | retirement (pending : Promote.Pending)
  | selection (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
  | abandonment (target : Trie.Fetch.Target)
  | settlement (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
      (scope : Trie.Serve.Scope) (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray)
      (result : Except Promote.Error Bool)

/-- Only execution facts belong here. In particular, no "safe", "newer",
successful-result or target-mismatch premise is required to take a step. -/
inductive Step : Event → State → State → Prop where
  | advertisement (head : Head) (now : Int64) (keep : Nat) (state : State)
      (closed : state.pending = none) :
      Step (.advertisement head now keep) state (execute (Reconcile.accept head now keep) state).2
  | promotion (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
      (state : State) (closed : state.pending = none) :
      Step (.promotion origin now refused) state (execute (Promote.promote origin now refused) state).2
  | request (target : Trie.Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat)
      (continuation rest : Program Trie.Fetch.Effects (Except Trie.Fetch.Error Bool))
      (reachable : Continuation (Trie.Fetch.fetch (Std.HashSet Trie.Missing.Visit)
        (Std.HashSet ByteArray) target reference maximum retryLimit).run continuation)
      (state final : State) (closed : state.pending = none)
      (path : Prefix continuation state rest final) :
      Step (.request target reference maximum retryLimit) state final
  | retirement (pending : Promote.Pending)
      (continuation rest : Program Promote.Effects (Except Promote.Error Unit))
      (reachable : Continuation (Promote.retire pending).run continuation)
      (state final : State) (closed : state.pending = none)
      (path : Prefix continuation state rest final) : Step (.retirement pending) state final
  | selection (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
      (state : State) (closed : state.pending = none) :
      Step (.selection origin expected) state (execute (FetchLifecycle.select origin expected) state).2
  | abandonment (target : Trie.Fetch.Target) (state : State) (closed : state.pending = none) :
      Step (.abandonment target) state
        (execute (within Fetch.fetchError (Trie.Fetch.abandon target) : Fetch.Action Unit) state).2
  | settlement (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
      (scope : Trie.Serve.Scope) (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray)
      (result : Except Promote.Error Bool)
      (state : State) (closed : state.pending = none) :
      Step (.settlement origin refused scope target key result) state
        (execute (FetchLifecycle.settle origin refused scope target key result) state).2

structure Observation where
  event : Event
  before : State
  after : State

/-- Linked production executions, with no safe-outcome filter. Arbitrary finite
ordering, duplication and interleaving of task resumptions is permitted. -/
inductive Execution : State → List Observation → State → Prop where
  | nil (state : State) : Execution state [] state
  | cons {event : Event} {state next final : State} {rest : List Observation} :
      Step event state next → Execution next rest final →
      Execution state (⟨event, state, next⟩ :: rest) final

/-- Consumption credentials are derived from the real command's captured
target, or from promotion's actual begin/preparation reads. They are not supplied
by the caller of the refinement theorem. -/
def captures (event : Event) (state : State) : List CapturedHead :=
  match event with
  | .advertisement .. | .selection .. => []
  | .promotion origin now _ => PromotionTransition.captures origin now state
  | .request target .. | .abandonment target => [TargetTransition.fetchKey target]
  | .retirement pending => [TargetTransition.pendingKey pending]
  | .settlement origin _ _ target _ result => FetchTransition.captures origin target result state

/-- Every actual operation refines the same operation-independent relation. -/
theorem Step.refines (step : Step event state final)
    (before : HeadView.Represents state.db view) (backed : HeadView.Backed state.db view)
    (after : HeadView.Represents final.db nextView) :
    HeadTransition (captures event state) view nextView := by
  cases step with
  | advertisement head now keep state closed =>
    exact AcceptanceTransition.refines head now keep state closed before backed after
  | promotion origin now refused state closed =>
    exact PromotionTransition.refines origin now refused state closed before backed after
  | request target reference maximum retryLimit continuation rest reachable state final closed path =>
    exact TargetTransition.requester target reference maximum retryLimit continuation rest reachable state final closed path before after
  | retirement pending continuation rest reachable state final closed path =>
    exact RetirementTransition.refines pending continuation rest reachable state final closed path before after
  | selection origin expected state closed =>
    exact FetchTransition.selection origin expected state closed before after
  | abandonment target state closed =>
    exact FetchTransition.abandonment target state closed before after
  | settlement origin refused scope target key result state closed =>
    exact FetchTransition.settlement origin refused scope target key result state closed before backed after

end Synchronicity.ReconciliationExecution
