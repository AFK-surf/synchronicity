import Synchronicity.ReconciliationSafety

/-! # M3 — delayed replies and obsolete work cannot damage newer versions

This is the goal-level entry point corresponding to M3 in `docs/LEAN.md`.
`Safety` is the property; `safety` proves it for every `Execution`.

An execution records actual production commands and requesting/retirement
resumptions. It permits new as well as obsolete advertisements, normal promotion,
and every settlement result. Unlike `StaleHistory`, admissibility does not assume
that advertisements are obsolete or that captured targets differ from live rows.
Those comparisons occur in the definition of a violation, not in the execution
constructors. No transition is admitted by assuming its postcondition.

The outer Fetch's selection/request/settlement decomposition is definitionally
checked by `FetchLifecycle.fetch_decomposes`; its cached-refusal branch uses the
abandonment command below. Publication settlement executes a new promotion, not
the captured candidate. Requesters may be from different tasks, use any reachable
continuation and receive arbitrary replies; their raw database at resumption is
the current database in the trace. Transactions are exclusive: a resumption or
new command starts with no open transaction. A finite requesting prefix may end
inside its private transaction, but another task cannot start there.

Raw backed-slot/consistent-pointer conditions delimit version comparisons, as
in the component theorems. Failure outcomes are unrestricted. This is a safety
trace at command and resumption boundaries, not a proof of the native scheduler,
corrupt-pointer recovery, eventual convergence, or M4's exact-view correctness.
-/
namespace Synchronicity.Goals.Mptsync.M3
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication SimulatedHost PrivateDatabase

inductive Event where
  | advertisement (head : Head) (now : Int64) (keep : Nat)
  | promotion (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
  | request (target : Trie.Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat)
  | retirement (pending : Promote.Pending)
  | selection (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
  | abandonment (target : Trie.Fetch.Target)
  | settlement (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
      (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray) (result : Except Promote.Error Bool)

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
      (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray) (result : Except Promote.Error Bool)
      (state : State) (closed : state.pending = none) :
      Step (.settlement origin refused target key result) state
        (execute (FetchLifecycle.settle origin refused target key result) state).2

/-- Observable bad transitions forbidden by M3. These refer to raw committed
rows, version floors and the work's captured key, independently of its reads,
policy decisions, return value or internal proof certificates. -/
inductive Violation : Event → State → State → Prop where
  | obsoleteAdvertisement (head : Head) (now : Int64) (keep : Nat) (state final : State)
      (slot : String) (which : slot = "complete" ∨ slot = "pending") (seq : Int64) (root : ByteArray)
      (stored : ReconciliationRead.StoredFloor state.db (Origin.canonical head.origin) slot seq root)
      (obsolete : Reconcile.newer head.seq head.root ⟨seq.toUInt64, root⟩ = false)
      (changed : rows final.db "heads" ≠ rows state.db "heads") :
      Violation (.advertisement head now keep) state final
  | acceptedComplete (head : Head) (now : Int64) (keep : Nat) (state final : State)
      (row : Fields) (rowOrigin : String) (present : row ∈ rows state.db "heads")
      (complete : ReconciliationSlots.names row rowOrigin "complete" = true)
      (lost : row ∉ rows final.db "heads") : Violation (.advertisement head now keep) state final
  | promotionRegression (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
      (state final : State) (seq : Int64) (root : ByteArray)
      (stored : ReconciliationRead.StoredFloor state.db (Origin.canonical origin) "complete" seq root)
      (regressed : ¬ PromotionBound.good (Origin.canonical origin) ⟨seq.toUInt64, root⟩ (rows final.db "heads")) :
      Violation (.promotion origin now refused) state final
  | delayedRequest (target : Trie.Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat)
      (state final : State) (row : Fields) (present : row ∈ rows state.db "heads")
      (different : equals row (Trie.Fetch.targetRows target) = false) (lost : row ∉ rows final.db "heads") :
      Violation (.request target reference maximum retryLimit) state final
  | delayedRetirement (pending : Promote.Pending) (state final : State) (row : Fields)
      (present : row ∈ rows state.db "heads")
      (different : equals row (RetirementProtection.key pending) = false) (lost : row ∉ rows final.db "heads") :
      Violation (.retirement pending) state final
  | selectionWrite (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
      (state final : State) (row : Fields) (present : row ∈ rows state.db "heads")
      (lost : row ∉ rows final.db "heads") : Violation (.selection origin expected) state final
  | delayedAbandonment (target : Trie.Fetch.Target) (state final : State) (row : Fields)
      (present : row ∈ rows state.db "heads") (different : equals row (Trie.Fetch.targetRows target) = false)
      (lost : row ∉ rows final.db "heads") : Violation (.abandonment target) state final
  | delayedSettlement (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
      (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray) (result : Except Promote.Error Bool)
      (notComplete : result ≠ .ok true) (state final : State) (row : Fields)
      (present : row ∈ rows state.db "heads") (different : equals row (Trie.Fetch.targetRows target) = false)
      (lost : row ∉ rows final.db "heads") : Violation (.settlement origin refused target key result) state final
  | settlementRegression (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
      (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray) (state final : State)
      (seq : Int64) (root : ByteArray)
      (stored : ReconciliationRead.StoredFloor state.db (Origin.canonical origin) "complete" seq root)
      (regressed : ¬ PromotionBound.good (Origin.canonical origin) ⟨seq.toUInt64, root⟩ (rows final.db "heads")) :
      Violation (.settlement origin refused target key (.ok true)) state final
  | settlementBypass (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
      (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray) (state final : State)
      (row : Fields) (present : row ∈ rows state.db "heads") (lost : row ∉ rows final.db "heads")
      (bypassed : ¬ ∃ now current,
        execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state = (.ok now, current) ∧
        current.db = state.db ∧ (execute (Promote.promote origin now refused) current).2 = final) :
      Violation (.settlement origin refused target key (.ok true)) state final

theorem Step.no_violation (step : Step event state final) : ¬ Violation event state final := by
  intro violation
  cases violation with
  | obsoleteAdvertisement head now keep state final slot which seq root stored obsolete changed =>
    cases step
    exact changed (ReconciliationFailure.obsolete_preserves_heads head now keep state slot which seq root stored obsolete)
  | acceptedComplete head now keep state final row rowOrigin present complete lost =>
    cases step with
    | advertisement _ _ _ _ closed =>
      have different := PromotionBound.complete_not_pending row rowOrigin complete (Origin.canonical head.origin)
      exact lost (((AcceptanceProtection.accept_only row head now keep different).invariant (ProtectedHead.retained row)
        (AcceptanceProtection.effects_retain row) state (ProtectedHead.initial row state closed present)).1)
  | promotionRegression origin now refused state final seq root stored regressed =>
    cases step with
    | promotion _ _ _ _ closed =>
      exact regressed (PromotionCommand.promote_preserves_complete_floor origin now refused state closed seq root stored)
  | delayedRequest target reference maximum retryLimit state final row present different lost =>
    cases step with
    | request _ _ _ _ continuation rest reachable _ _ closed path =>
      exact lost (FetchHeadSafety.every_resumption_preserves _ _ target reference maximum retryLimit
        continuation rest reachable state final closed path row present different)
  | delayedRetirement pending state final row present different lost =>
    cases step with
    | retirement _ continuation rest reachable _ _ closed path =>
      exact lost (RetirementProtection.every_resumption_preserves pending continuation rest reachable state final closed path row present different)
  | selectionWrite origin expected state final row present lost =>
    cases step with
    | selection _ _ _ closed =>
      exact lost (((FetchLifecycle.select_only row origin expected).invariant (ProtectedHead.retained row)
        (FetchLifecycle.effects_retain row) state (ProtectedHead.initial row state closed present)).1)
  | delayedAbandonment target state final row present different lost =>
    cases step with
    | abandonment _ _ closed =>
      exact lost (((FetchLifecycle.abandon_only row target different).invariant (ProtectedHead.retained row)
        (FetchLifecycle.effects_retain row) state (ProtectedHead.initial row state closed present)).1)
  | delayedSettlement origin refused target key result notComplete state final row present different lost =>
    cases step with
    | settlement _ _ _ _ _ _ closed =>
      exact lost (((FetchLifecycle.settle_without_publication row origin refused target key result notComplete different).invariant
        (ProtectedHead.retained row) (FetchLifecycle.effects_retain row) state (ProtectedHead.initial row state closed present)).1)
  | settlementRegression origin refused target key state final seq root stored regressed =>
    cases step with
    | settlement _ _ _ _ _ _ closed =>
      exact regressed (FetchLifecycle.completed_settlement_bound origin refused target key state closed seq root stored)
  | settlementBypass origin refused target key state final row present lost bypassed =>
    cases step
    exact bypassed (FetchLifecycle.completed_settlement_changes_recheck origin refused target key state row present lost)

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

/-- M3 as a trace safety property: no observed transition damages a protected
newer target or moves an accepted complete version backwards. Quantifying over
all observations also covers every finite prefix of the trace. -/
def Safety (trace : List Observation) : Prop :=
  ∀ observation ∈ trace, ¬ Violation observation.event observation.before observation.after

/-- **M3.** Every finite production-command/resumption execution satisfies M3,
including executions containing new advertisements and fresh promotions. -/
theorem safety (execution : Execution initial trace final) : Safety trace := by
  induction execution with
  | nil _ => intro observation member; cases member
  | cons step rest ih =>
    intro observation member
    rcases List.mem_cons.mp member with same | member
    · subst observation
      exact step.no_violation
    · exact ih observation member

end Synchronicity.Goals.Mptsync.M3
