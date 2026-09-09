import Synchronicity.TrieMissingCompletion
import Synchronicity.PromotionProgress

/-! A positive execution certificate for the production completeness walk.
Unlike a premise that merely assumes `isComplete = true`, `WalkOpportunity`
records the finite sequence of actual host replies consumed by
`Program.iterate`.  Its terminal condition is the concrete empty production
work queues, and its step index must fit the production fuel bound. -/
namespace Synchronicity.TrieCompleteConverse
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open VerifiedCore.Trie.Missing SimulatedHost
open TrieFetchCompletion TrieFetchAdmissionProgress TrieMissingCompletion

/-- A finite, host-specific opportunity for an effect-counted trampoline to
reach an ordinary batch result with no pending or retryable positions.  It
does not contain an execution of `nextBatch`, `inspectRoot`, or `isComplete`.
Requests are justified one primitive host reply at a time. -/
inductive WalkOpportunity [Interpreter E]
    (body : Work V H → Program E (Except Missing.Error (Work V H ⊕ BatchResult V H))) :
    Nat → Program E (Except Missing.Error (Work V H ⊕ BatchResult V H)) →
      SimulatedHost.State → Frontier V H → Batch → SimulatedHost.State → Prop where
  | stopped (state : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch) :
      WalkOpportunity body 1 (.pure (.ok (.inr (frontier, .ok batch))))
        state frontier batch state
  | continued (next : Work V H) (state : SimulatedHost.State)
      (plan : WalkOpportunity body steps (body next) state frontier batch final) :
      WalkOpportunity body (steps + 1) (.pure (.ok (.inl next)))
        state frontier batch final
  | requested (effect : E A) (resume : A →
      Program E (Except Missing.Error (Work V H ⊕ BatchResult V H)))
      (state after : SimulatedHost.State) (reply : A)
      (handled : Interpreter.handle effect state = (reply, after))
      (plan : WalkOpportunity body steps (resume reply) after frontier batch final) :
      WalkOpportunity body (steps + 1) (.request effect resume)
        state frontier batch final

theorem WalkOpportunity.execute {body : Work V H →
    Program E (Except Missing.Error (Work V H ⊕ BatchResult V H))}
    [Interpreter E]
    (plan : WalkOpportunity body steps program state frontier batch final)
    (fits : steps ≤ fuel) :
    execute (Program.iterate body Missing.Error.exhausted fuel program) state =
      (.ok (frontier, .ok batch), final) := by
  induction plan generalizing fuel with
  | stopped state frontier batch =>
    cases fuel with
    | zero => omega
    | succ fuel => rfl
  | continued next state plan ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      simp only [Program.iterate]
      exact ih (Nat.le_of_succ_le_succ fits)
  | requested effect resume state after reply handled plan ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [SimulatedHost.execute_iterate_request, handled]
      exact ih (Nat.le_of_succ_le_succ fits)

abbrev MissingWalkOpportunity [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) (steps : Nat)
    (state : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (final : SimulatedHost.State) : Prop :=
  let initialWork : Work V H :=
    ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩
  WalkOpportunity (fun work => (batchStep context 1 work).run) steps
    (batchStep context 1 initialWork).run state frontier batch final

theorem nextBatch_exec_of_opportunity [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) (steps : Nat)
    (state final : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (plan : MissingWalkOpportunity context root steps state frontier batch final)
    (fits : steps ≤ batchFuel) :
    execute (nextBatch context (initial (V := V) (H := H) context none root) 1) state =
      (.ok (frontier, .ok batch), final) := by
  unfold MissingWalkOpportunity at plan
  unfold nextBatch OperationOver.iterate
  exact plan.execute fits

theorem inspectRoot_exec_of_opportunity [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) (steps : Nat)
    (state final : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (plan : MissingWalkOpportunity context root steps state frontier batch final)
    (fits : steps ≤ batchFuel) :
    execute (Complete.inspectRoot V H context root) state =
      (.ok (frontier, .ok batch), final) := by
  have missingRun := nextBatch_exec_of_opportunity context root steps state final
    frontier batch plan fits
  unfold Complete.inspectRoot
  calc
    execute ((nextBatch context (initial (V := V) (H := H) context none root) 1).run.mapEffects
      (fun {A} (effect : Missing.Effects A) =>
        (Inject.inject effect : Complete.Effects A))) state =
        execute (nextBatch context (initial (V := V) (H := H) context none root) 1).run state :=
      SimulatedHost.execute_mapEffects (E := Missing.Effects) (F := Complete.Effects)
        Inject.inject (fun effect state => by
          cases effect with
          | left storageEffect => rfl
          | right other => cases other <;> rfl) _ _
    _ = (.ok (frontier, .ok batch), final) := missingRun

private theorem mapEffects_iterate
    {E F : Type → Type}
    (body : S → Program E (Except ε (S ⊕ R))) (exhausted : ε)
    (inject : {A : Type} → E A → F A) : ∀ fuel program,
    (Program.iterate body exhausted fuel program).mapEffects inject =
      Program.iterate (fun next => (body next).mapEffects inject) exhausted fuel
        (program.mapEffects inject) := by
  intro fuel
  induction fuel with
  | zero => intro program; rfl
  | succ fuel ih =>
    intro program
    cases program with
    | pure result =>
      rcases result with error | result
      · rfl
      · rcases result with next | answer
        · exact ih _
        · rfl
    | request effect resume =>
      simp only [Program.iterate, Program.mapEffects]
      congr 1
      funext reply
      exact ih _

private theorem mapEffects_compose {E F G : Type → Type}
    (first : {A : Type} → E A → F A)
    (second : {A : Type} → F A → G A) : ∀ (program : Program E A),
    (program.mapEffects first).mapEffects second =
      program.mapEffects (fun effect => second (first effect)) := by
  intro program
  induction program with
  | pure value => rfl
  | request effect resume ih =>
    simp only [Program.mapEffects]
    congr 1
    funext reply
    exact ih reply

private theorem mapEffects_bind {E F : Type → Type}
    (inject : {A : Type} → E A → F A) :
    ∀ (program : Program E A) (next : A → Program E B),
      (program.bind next).mapEffects inject =
        (program.mapEffects inject).bind (fun answer => (next answer).mapEffects inject) := by
  intro program next
  induction program with
  | pure value => rfl
  | request effect resume ih =>
    simp only [Program.bind, Program.mapEffects]
    congr 1
    funext reply
    exact ih reply

private theorem execute_mapped_bind_ok {E F : Type → Type} [Interpreter F]
    (inject : {A : Type} → E A → F A)
    (operation : OperationOver E ε A) (next : A → OperationOver E ε B)
    (state middle : SimulatedHost.State) (answer : A)
    (ran : execute (operation.run.mapEffects inject) state = (.ok answer, middle)) :
    execute ((operation >>= next).run.mapEffects inject) state =
      execute ((next answer).run.mapEffects inject) middle := by
  change execute ((operation.run.bind (ExceptT.bindCont next)).mapEffects inject) state = _
  rw [mapEffects_bind, SimulatedHost.execute_bind, ran]
  rfl

private def promoteMissing (tx : Transaction) :
    {A : Type} → Missing.Effects A → Replication.Promote.Effects A :=
  fun effect => Replication.Promote.inTransaction tx
    (Inject.inject effect : Complete.Effects _)

abbrev PromotionWalkOpportunity [WorkSet Visit V] [WorkSet ByteArray H]
    (tx : Transaction) (context : Context) (root : ByteArray) (steps : Nat)
    (state : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (final : SimulatedHost.State) : Prop :=
  let initialWork : Work V H :=
    ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩
  WalkOpportunity
    (fun work => (batchStep context 1 work).run.mapEffects (promoteMissing tx)) steps
    ((batchStep context 1 initialWork).run.mapEffects (promoteMissing tx))
    state frontier batch final

theorem promotion_inspectRoot_exec_of_opportunity
    [WorkSet Visit V] [WorkSet ByteArray H]
    (tx : Transaction) (context : Context) (root : ByteArray) (steps : Nat)
    (state final : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (plan : PromotionWalkOpportunity tx context root steps state frontier batch final)
    (fits : steps ≤ batchFuel) :
    execute ((Complete.inspectRoot V H context root).run.mapEffects
      (Replication.Promote.inTransaction tx)) state =
        (.ok (frontier, .ok batch), final) := by
  unfold PromotionWalkOpportunity at plan
  have ran := plan.execute fits
  have lifted : (Complete.inspectRoot V H context root).run.mapEffects
      (Replication.Promote.inTransaction tx) =
      Program.iterate
        (fun work => (batchStep context 1 work).run.mapEffects (promoteMissing tx))
        Missing.Error.exhausted batchFuel
        ((batchStep context 1
          ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩).run.mapEffects
            (promoteMissing tx)) := by
    unfold Complete.inspectRoot nextBatch OperationOver.iterate
    change
      ((Program.iterate (fun work => (batchStep context 1 work).run)
        Missing.Error.exhausted batchFuel
        (batchStep context 1
          ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩).run).mapEffects
          (fun {A} (effect : Missing.Effects A) =>
            (Inject.inject effect : Complete.Effects A))).mapEffects
          (Replication.Promote.inTransaction tx) = _
    rw [mapEffects_compose, mapEffects_iterate]
    rfl
  rw [lifted]
  exact ran

/-- Every local obligation represented by a production position is also an
obligation of the selected root.  This is the forward structural invariant
needed by the positive walk; unlike frontier accounting it rules out a
spurious missing request once the root is semantically complete. -/
def PositionInherited (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) (position : Position) : Prop :=
  ∀ evidence, TrieMissingCompletion.PositionRequires publisher context position evidence →
    Needs publisher context.scope context.owner root [] evidence

def FrontierInherited (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) (frontier : Frontier V H) : Prop :=
  (∀ position ∈ frontier.positions, PositionInherited publisher context root position) ∧
    ∀ position ∈ frontier.deferred, PositionInherited publisher context root position

/-- Operational state maintained while semantic completion rules out every
missing-node/value branch.  Empty batch/deferred fields are consequences to
preserve, not a terminal result supplied by an opportunity. -/
def CompleteWork (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) (work : Work V H) : Prop :=
  work.frontier.fault = none ∧ work.frontier.deferred = [] ∧
    work.batch = {} ∧ FrontierInherited publisher context root work.frontier

theorem initial_completeWork [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context) (root : ByteArray)
    (rooted : rootOf root = some root) (admitted : context.scope.admitsPath [] = true) :
    CompleteWork publisher context root
      ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩ := by
  refine ⟨rfl, rfl, rfl, ?_⟩
  constructor
  · intro position member evidence required
    simp only [initial, rooted, admitted, ↓reduceIte, List.mem_cons,
      List.not_mem_nil, or_false] at member
    subst position
    simpa [TrieMissingCompletion.PositionRequires] using required
  · intro position member
    simp [initial] at member

/-- Healthy transaction-lifted raw reads for one fully present position.
The contract is deliberately local: it says neither that the whole walk
terminates nor that its final frontier is exhausted.  Its returned shape is
the production `inspect`/`commit` step, and it is available only after the
semantic proof establishes that the inspected position is settled. -/
structure PromotionReadOpportunity (publisher : TrieProgramProofs.RawSnapshot)
    (tx : Transaction) (context : Context) (root : ByteArray) : Prop where
  inspect : ∀ (state : SimulatedHost.State)
      (work : Work (Std.HashSet Visit) (Std.HashSet ByteArray))
      (position : Position) (rest : List Position),
    work.frontier.positions = position :: rest →
    position.finish = false →
    CompleteWork publisher context root work →
    TrieMissingCompletion.PositionSettled publisher context
      (replicaOfState state) position →
    ∃ checked after,
      execute ((Missing.inspect context work.frontier position).run.mapEffects
        (promoteMissing tx)) state = (.ok checked, after) ∧
      replicaOfState after = replicaOfState state ∧
      ((checked = .skip ∧
          CompleteWork publisher context root (commit context work position rest checked)) ∨
        ∃ children pending routing,
          checked = .expand children pending [] routing ∧
          CompleteWork publisher context root (commit context work position rest checked))

private theorem promotion_batchStep_complete
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (context : Context) (root : ByteArray)
    (reads : PromotionReadOpportunity publisher tx context root)
    {state final : SimulatedHost.State}
    {work : Work (Std.HashSet Visit) (Std.HashSet ByteArray)}
    {result : Work (Std.HashSet Visit) (Std.HashSet ByteArray) ⊕
      BatchResult (Std.HashSet Visit) (Std.HashSet ByteArray)}
    (complete : PermittedComplete publisher context.scope context.owner root
      (replicaOfState state))
    (good : CompleteWork publisher context root work)
    (ran : execute ((batchStep context 1 work).run.mapEffects (promoteMissing tx)) state =
      (.ok result, final)) :
    match result with
    | .inl next => CompleteWork publisher context root next ∧
        PermittedComplete publisher context.scope context.owner root
          (replicaOfState final)
    | .inr (frontier, .ok _batch) => frontier.isExhausted = true
    | .inr (_, .error _) => False := by
  unfold batchStep at ran
  simp only [good.1] at ran
  cases pending : work.frontier.positions with
  | nil =>
    simp only [pending, pure, ExceptT.pure, ExceptT.mk, ExceptT.run,
      Program.mapEffects, execute, Except.ok.injEq, Prod.mk.injEq] at ran
    rcases ran with ⟨rfl, rfl⟩
    simp [finished, Frontier.isExhausted, pending, good.2.1, good.1]
  | cons position rest =>
    simp only [pending] at ran
    cases finish : position.finish with
    | true =>
      simp only [finish, ↓reduceIte, pure, ExceptT.pure, ExceptT.mk,
        ExceptT.run, Program.mapEffects, execute, Except.ok.injEq,
        Prod.mk.injEq] at ran
      rcases ran with ⟨rfl, rfl⟩
      refine ⟨?_, complete⟩
      unfold CompleteWork at good ⊢
      rw [settle, good.2.1]
      simp only [List.isEmpty_nil, ↓reduceIte]
      refine ⟨good.1, good.2.1, good.2.2.1, ?_⟩
      constructor
      · exact fun probe member => good.2.2.2.1 probe (by
          rw [pending]
          exact List.mem_cons_of_mem _ member)
      · exact good.2.2.2.2
    | false =>
      have noBatch : (work.batch.size ≥ 1) = false := by
        rw [good.2.2.1]
        decide
      simp only [finish, Bool.false_eq_true, noBatch, ↓reduceIte] at ran
      have inherited := good.2.2.2.1 position (by rw [pending]; simp)
      have settled : TrieMissingCompletion.PositionSettled publisher context
          (replicaOfState state) position := fun evidence required =>
        complete evidence (inherited evidence required)
      obtain ⟨checked, after, inspected, replicaEq, shape⟩ :=
        reads.inspect state work position rest pending finish good settled
      simp only [ExceptT.run] at inspected
      simp only [ExceptT.mk, ExceptT.run, bind] at ran
      rw [mapEffects_bind, SimulatedHost.execute_bind, inspected] at ran
      have completeAfter : PermittedComplete publisher context.scope context.owner root
          (replicaOfState after) := by simpa [replicaEq] using complete
      cases ran
      rcases shape with ⟨rfl, kept⟩ | ⟨children, pendingBranch, routing, rfl, kept⟩
      · exact ⟨kept, completeAfter⟩
      · exact ⟨kept, completeAfter⟩

private theorem iterate_complete [Interpreter E]
    (body : S → Program E (Except ε (S ⊕ R))) (exhausted : ε)
    (P : SimulatedHost.State → S → Prop)
    (Q : SimulatedHost.State → R → Prop)
    (kept : ∀ state start next final, P state start →
      execute (body start) state = (.ok (.inl next), final) → P final next)
    (stopped : ∀ state start answer final, P state start →
      execute (body start) state = (.ok (.inr answer), final) → Q final answer)
    (fuel : Nat) : ∀ (program : Program E (Except ε (S ⊕ R))) state,
    (∀ next final, execute program state = (.ok (.inl next), final) → P final next) →
    (∀ answer final, execute program state = (.ok (.inr answer), final) → Q final answer) →
    ∀ answer final,
      execute (Program.iterate body exhausted fuel program) state = (.ok answer, final) →
      Q final answer := by
  induction fuel with
  | zero => intro program state _ _ answer final ran; cases ran
  | succ fuel ih =>
    intro program state keeps stops answer final ran
    match program with
    | .pure (.error error) => cases ran
    | .pure (.ok (.inr result)) => cases ran; exact stops _ state rfl
    | .pure (.ok (.inl next)) =>
      exact ih (body next) state
        (fun next' final => kept state next next' final (keeps next state rfl))
        (fun result final => stopped state next result final (keeps next state rfl))
        answer final ran
    | .request effect resume =>
      rw [execute_iterate_request] at ran
      cases effectState : Interpreter.handle effect state with
      | mk reply after =>
        simp only [execute, effectState] at keeps stops
        simp only [effectState] at ran
        exact ih (resume reply) after keeps stops answer final ran

/-- Semantic completion turns a finite sequence of primitive production read
replies into an exhausted frontier.  Exhaustion is proved here; it is not a
field of the opportunity. -/
theorem promotion_walk_exhausted_of_complete
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (context : Context) (root : ByteArray) (steps : Nat)
    (state final : SimulatedHost.State)
    (frontier : Frontier (Std.HashSet Visit) (Std.HashSet ByteArray))
    (batch : Batch)
    (rooted : rootOf root = some root)
    (admitted : context.scope.admitsPath [] = true)
    (reads : PromotionReadOpportunity publisher tx context root)
    (complete : PermittedComplete publisher context.scope context.owner root
      (replicaOfState state))
    (plan : PromotionWalkOpportunity tx context root steps state frontier batch final)
    (fits : steps ≤ batchFuel) :
    frontier.isExhausted = true := by
  let initialWork : Work (Std.HashSet Visit) (Std.HashSet ByteArray) :=
    ⟨initial context none root, {}, WorkSet.empty ByteArray⟩
  let P : SimulatedHost.State → Work (Std.HashSet Visit) (Std.HashSet ByteArray) → Prop :=
    fun observed work => CompleteWork publisher context root work ∧
      PermittedComplete publisher context.scope context.owner root
        (replicaOfState observed)
  let Q : SimulatedHost.State →
      BatchResult (Std.HashSet Visit) (Std.HashSet ByteArray) → Prop :=
    fun _ answer => match answer with
      | (frontier, .ok _) => frontier.isExhausted = true
      | (_, .error _) => False
  have initialHeld : P state initialWork :=
    ⟨initial_completeWork publisher context root rooted admitted, complete⟩
  have keeps : ∀ observed work next after, P observed work →
      execute ((batchStep context 1 work).run.mapEffects (promoteMissing tx)) observed =
        (.ok (.inl next), after) → P after next := by
    intro observed work next after held ran
    exact promotion_batchStep_complete publisher tx context root reads held.2 held.1 ran
  have stops : ∀ observed work answer after, P observed work →
      execute ((batchStep context 1 work).run.mapEffects (promoteMissing tx)) observed =
        (.ok (.inr answer), after) → Q after answer := by
    intro observed work answer after held ran
    rcases answer with ⟨answerFrontier, answerBatch⟩
    cases answerBatch with
    | error error =>
        exact promotion_batchStep_complete publisher tx context root reads held.2 held.1 ran
    | ok answerBatch =>
        exact promotion_batchStep_complete publisher tx context root reads held.2 held.1 ran
  unfold PromotionWalkOpportunity at plan
  have ran := plan.execute fits
  exact iterate_complete
    (fun work => (batchStep context 1 work).run.mapEffects (promoteMissing tx))
    Missing.Error.exhausted P Q keeps stops
    batchFuel _ state
    (fun next after ran => keeps state initialWork next after initialHeld ran)
    (fun answer after ran => stops state initialWork answer after initialHeld ran)
    (frontier, .ok batch) final ran

/-- Transaction-lifted counterpart of `FreshOpportunity`, matching the exact
effect map in `PromotionReads.complete`.  Every field is a primitive phase or
finite walk reply, never the result of the enclosing completeness call. -/
structure PromotionFreshOpportunity
    (tx : Transaction) (context : Context) (root : ByteArray)
    (state : SimulatedHost.State) where
  quiet : state.faults = []
  key : ByteArray
  keyed : SimulatedHost.State
  checked : SimulatedHost.State
  generation : UInt64
  started : SimulatedHost.State
  walked : SimulatedHost.State
  final : SimulatedHost.State
  steps : Nat
  frontier : Frontier (Std.HashSet Visit) (Std.HashSet ByteArray)
  batch : Batch
  rooted : rootOf root = some root
  admitted : context.scope.admitsPath [] = true
  startedReplica : replicaOfState started = replicaOfState state
  keyRun : execute ((Memo.keyFor (E := Complete.Effects) Missing.Error.host
    context.scope root context.owner).run.mapEffects
      (Replication.Promote.inTransaction tx)) state = (.ok key, keyed)
  unknownRun : execute ((Complete.memo (.isKnown key)).run.mapEffects
    (Replication.Promote.inTransaction tx)) keyed = (.ok false, checked)
  generationRun : execute ((Complete.memo .generation).run.mapEffects
    (Replication.Promote.inTransaction tx)) checked = (.ok generation, started)
  walk : PromotionWalkOpportunity tx context root steps started frontier batch walked
  withinFuel : steps ≤ batchFuel
  certifyRun : execute ((Complete.memo (.certify key generation)).run.mapEffects
    (Replication.Promote.inTransaction tx)) walked = (.ok true, final)

theorem promotion_isComplete_mapped_exec
    (publisher : TrieProgramProofs.RawSnapshot)
    (tx : Transaction) (context : Context) (root : ByteArray)
    (state : SimulatedHost.State)
    (reads : PromotionReadOpportunity publisher tx context root)
    (complete : PermittedComplete publisher context.scope context.owner root
      (replicaOfState state))
    (ready : PromotionFreshOpportunity tx context root state) :
    execute ((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
      context root).run.mapEffects (Replication.Promote.inTransaction tx)) state =
        (.ok true, ready.final) := by
  have walkRun := promotion_inspectRoot_exec_of_opportunity tx context root ready.steps
    ready.started ready.walked ready.frontier ready.batch ready.walk ready.withinFuel
  have completeStarted : PermittedComplete publisher context.scope context.owner root
      (replicaOfState ready.started) := by
    simpa only [ready.startedReplica] using complete
  have exhausted := promotion_walk_exhausted_of_complete publisher tx context root
    ready.steps ready.started ready.walked ready.frontier ready.batch ready.rooted
      ready.admitted reads completeStarted ready.walk ready.withinFuel
  let afterWalk : Frontier (Std.HashSet Visit) (Std.HashSet ByteArray) ×
      Except Missing.Error Batch → Complete.Action Bool := fun answer =>
    match answer.2 with
    | .error error => throw error
    | .ok _ => if answer.1.isExhausted then
        Complete.memo (.certify ready.key ready.generation) else pure false
  let afterGeneration : UInt64 → Complete.Action Bool := fun generation =>
    Complete.inspectRoot (Std.HashSet Visit) (Std.HashSet ByteArray) context root >>=
      fun answer =>
        match answer.2 with
        | .error error => throw error
        | .ok _ => if answer.1.isExhausted then
            Complete.memo (.certify ready.key generation) else pure false
  have generationTail := execute_mapped_bind_ok (Replication.Promote.inTransaction tx)
    (Complete.memo .generation) afterGeneration ready.checked ready.started
      ready.generation ready.generationRun
  have walkTail := execute_mapped_bind_ok (Replication.Promote.inTransaction tx)
    (Complete.inspectRoot (Std.HashSet Visit) (Std.HashSet ByteArray) context root)
      afterWalk ready.started ready.walked (ready.frontier, .ok ready.batch) walkRun
  have recheckRun : execute ((Complete.recheck (Std.HashSet Visit) (Std.HashSet ByteArray)
      context root ready.key).run.mapEffects (Replication.Promote.inTransaction tx)) ready.checked =
      (.ok true, ready.final) := by
    rw [show Complete.recheck (Std.HashSet Visit) (Std.HashSet ByteArray)
        context root ready.key = Complete.memo .generation >>= afterGeneration by
      rfl]
    rw [generationTail]
    rw [show afterGeneration ready.generation =
        Complete.inspectRoot (Std.HashSet Visit) (Std.HashSet ByteArray) context root >>=
          afterWalk by rfl]
    rw [walkTail]
    simp only [afterWalk, exhausted, ↓reduceIte]
    exact ready.certifyRun
  let afterKnown : Bool → Complete.Action Bool := fun known =>
    if known then pure true else Complete.recheck (Std.HashSet Visit)
      (Std.HashSet ByteArray) context root ready.key
  let afterKey : ByteArray → Complete.Action Bool := fun key =>
    Complete.memo (.isKnown key) >>= fun known =>
      if known then pure true else Complete.recheck (Std.HashSet Visit)
        (Std.HashSet ByteArray) context root key
  have keyTail := execute_mapped_bind_ok (Replication.Promote.inTransaction tx)
    (Memo.keyFor (E := Complete.Effects) Missing.Error.host
      context.scope root context.owner) afterKey
      state ready.keyed ready.key ready.keyRun
  have knownTail := execute_mapped_bind_ok (Replication.Promote.inTransaction tx)
    (Complete.memo (.isKnown ready.key)) afterKnown ready.keyed ready.checked false
      ready.unknownRun
  rw [show Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray) context root =
      Memo.keyFor (E := Complete.Effects) Missing.Error.host
        context.scope root context.owner >>= afterKey by rfl]
  rw [keyTail]
  rw [show afterKey ready.key = Complete.memo (.isKnown ready.key) >>= afterKnown by rfl]
  rw [knownTail]
  exact recheckRun

/-- Exact positive execution required by `PromotionProgress.BodyReady`'s
`completeExecution` field, constructed from primitive transaction-lifted host
replies and finite walk fuel. -/
theorem promotion_complete_exec_of_opportunity
    (publisher : TrieProgramProofs.RawSnapshot)
    (tx : Transaction) (context : Context) (root : ByteArray)
    (state : SimulatedHost.State)
    (reads : PromotionReadOpportunity publisher tx context root)
    (complete : PermittedComplete publisher context.scope context.owner root
      (replicaOfState state))
    (ready : PromotionFreshOpportunity tx context root state) :
    execute (PromotionReads.complete tx context root) state = (.ok true, ready.final) := by
  have completed := promotion_isComplete_mapped_exec publisher tx context root state
    reads complete ready
  unfold PromotionReads.complete
  change execute (Program.bind
    ((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
      context root).run.mapEffects (Replication.Promote.inTransaction tx))
    (fun answer => pure (Except.mapError Replication.Promote.missingError answer))) state = _
  rw [SimulatedHost.execute_bind, completed]
  rfl

theorem bodyReady_completeExecution_of_opportunity
    (publisher : TrieProgramProofs.RawSnapshot)
    (tx : Transaction) (scope : Serve.Scope)
    (authority : Authorization.OriginAuthority)
    (pending : Replication.Promote.Pending) (state : SimulatedHost.State)
    (reads : PromotionReadOpportunity publisher tx
      ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root)
    (complete : PermittedComplete publisher scope
      (authority.provenance.map Origin.canonical) pending.head.root
      (replicaOfState state))
    (ready : PromotionFreshOpportunity tx
      ⟨scope, authority.provenance.map Origin.canonical⟩
      pending.head.root state) :
    execute (((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
      ⟨scope, authority.provenance.map Origin.canonical⟩
      pending.head.root).run.mapEffects (Replication.Promote.inTransaction tx)
      |> fun program => Except.mapError Replication.Promote.missingError <$> program)) state =
        (.ok true, ready.final) := by
  have completed := promotion_isComplete_mapped_exec publisher tx
    ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root state
      reads complete ready
  change execute (Program.bind
    ((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
      ⟨scope, authority.provenance.map Origin.canonical⟩
      pending.head.root).run.mapEffects (Replication.Promote.inTransaction tx))
    (fun answer => pure (Except.mapError Replication.Promote.missingError answer))) state = _
  rw [SimulatedHost.execute_bind, completed]
  rfl

/-- Direct M1 input: zero finite semantic deficit plus a bounded sequence of
actual transaction-lifted host replies supplies both semantic completion and
the exact `BodyReady.completeExecution` value. -/
theorem finite_promotion_complete_execution
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (scope : Serve.Scope) (authority : Authorization.OriginAuthority)
    (pending : Replication.Promote.Pending) (state : SimulatedHost.State)
    (requirements : FiniteRequirements publisher scope
      (authority.provenance.map Origin.canonical) pending.head.root)
    (complete : missingEvidence requirements.items (replicaOfState state) = 0)
    (reads : PromotionReadOpportunity publisher tx
      ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root)
    (ready : PromotionFreshOpportunity tx
      ⟨scope, authority.provenance.map Origin.canonical⟩
      pending.head.root state) :
    PermittedComplete publisher scope
        (authority.provenance.map Origin.canonical)
        pending.head.root (replicaOfState state) ∧
      execute (((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
        ⟨scope, authority.provenance.map Origin.canonical⟩
        pending.head.root).run.mapEffects (Replication.Promote.inTransaction tx)
        |> fun program => Except.mapError Replication.Promote.missingError <$> program)) state =
          (.ok true, ready.final) :=
  ⟨(TrieFetchCompletion.finite_measure_eq_zero_iff_complete requirements).mp complete,
    bodyReady_completeExecution_of_opportunity publisher tx scope authority pending state
      reads ((TrieFetchCompletion.finite_measure_eq_zero_iff_complete requirements).mp complete)
      ready⟩

/-- All independent positive promotion phases, replacing only the old opaque
`BodyReady.completeExecution` field with primitive memo replies and a finite
transaction-lifted trie walk. -/
structure PromotionOpportunity (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state : SimulatedHost.State) where
  tx : Transaction
  opened : SimulatedHost.State
  prepared : SimulatedHost.State
  scope : Serve.Scope
  replicas : List Replication.Materialize.Target
  authority : Authorization.OriginAuthority
  pending : Replication.Promote.Pending
  old : Option Replication.Promote.Pending
  began : execute (Replication.Promote.raw .begin) state = (.ok tx, opened)
  preparation : execute (PromotionCommand.prepare tx origin now) opened =
    (.ok (scope, authority, some pending, old), prepared)
  policy : MaterializationInputs.ReadPolicy state.db origin scope replicas
  policyUnique : ∀ actualScope actualReplicas,
    MaterializationInputs.ReadPolicy state.db origin actualScope actualReplicas →
      actualScope = scope ∧ actualReplicas = replicas
  notRefused : (pending.head.seq, pending.head.root,
    old.map (·.head.root) |>.getD Trie.emptyRoot) ∉ refused
  newer : old.any (fun old => !Replication.Reconcile.newer
    pending.head.seq pending.head.root ⟨old.head.seq, old.head.root⟩) = false
  completion : PromotionFreshOpportunity tx
    ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root prepared
  authorized : SimulatedHost.State
  written : SimulatedHost.State
  cleared : SimulatedHost.State
  staged : SimulatedHost.State
  count : UInt64
  permittedExecution :
    execute (PromotionPublication.permitted tx pending authority) completion.final =
      (.ok true, authorized)
  writeExecution : execute (Replication.Promote.history
    (Replication.Reconcile.putSlot tx "complete" pending.head pending.received now)) authorized =
      (.ok (), written)
  clearExecution : execute (Replication.Promote.clear tx origin) written = (.ok (), cleared)
  materializeExecution : execute (Replication.Materialize.materialize tx origin
    (old.map (·.head.root) |>.getD Trie.emptyRoot) pending.head.root) cleared =
      (.ok count, staged)
  final : SimulatedHost.State
  committed : execute (Replication.Promote.raw (.commit tx)) staged = (.ok (), final)

def PromotionOpportunity.bodyReady
    (ready : PromotionOpportunity origin now refused state)
    (publisher : TrieProgramProofs.RawSnapshot)
    (reads : PromotionReadOpportunity publisher ready.tx
      ⟨ready.scope, ready.authority.provenance.map Origin.canonical⟩
      ready.pending.head.root)
    (complete : PermittedComplete publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root
      (replicaOfState ready.prepared)) :
    PromotionProgress.BodyReady ready.tx origin now ready.pending ready.old
      ready.scope ready.authority ready.prepared where
  newer := ready.newer
  checked := ready.completion.final
  authorized := ready.authorized
  written := ready.written
  cleared := ready.cleared
  staged := ready.staged
  count := ready.count
  completeExecution := bodyReady_completeExecution_of_opportunity publisher ready.tx ready.scope
    ready.authority ready.pending ready.prepared reads complete ready.completion
  permittedExecution := ready.permittedExecution
  writeExecution := ready.writeExecution
  clearExecution := ready.clearExecution
  materializeExecution := ready.materializeExecution

/-- Constructor consumed directly by M1: actual begin/prepare, finite
completeness host opportunity, publication/materialization phases and commit
produce the existing positive `PromotionProgress.Ready` witness. -/
def ready_of_opportunity
    (ready : PromotionOpportunity origin now refused state)
    (publisher : TrieProgramProofs.RawSnapshot)
    (reads : PromotionReadOpportunity publisher ready.tx
      ⟨ready.scope, ready.authority.provenance.map Origin.canonical⟩
      ready.pending.head.root)
    (complete : PermittedComplete publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root
      (replicaOfState ready.prepared)) :
    PromotionProgress.Ready origin now refused state where
  tx := ready.tx
  opened := ready.opened
  prepared := ready.prepared
  scope := ready.scope
  replicas := ready.replicas
  authority := ready.authority
  pending := ready.pending
  old := ready.old
  began := ready.began
  preparation := ready.preparation
  policy := ready.policy
  policyUnique := ready.policyUnique
  notRefused := ready.notRefused
  body := ready.bodyReady publisher reads complete
  final := ready.final
  committed := ready.committed

/-- A historical promotion opportunity paired with the semantic completion
and local read contract that make its production completion phase positive.
Keeping these witnesses beside the raw opportunity prevents historical view
proofs from rebuilding `Ready` from host replies alone. -/
structure CompletedPromotionOpportunity (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray))
    (state : SimulatedHost.State) where
  raw : PromotionOpportunity origin now refused state
  publisher : TrieProgramProofs.RawSnapshot
  reads : PromotionReadOpportunity publisher raw.tx
    ⟨raw.scope, raw.authority.provenance.map Origin.canonical⟩ raw.pending.head.root
  complete : PermittedComplete publisher raw.scope
    (raw.authority.provenance.map Origin.canonical) raw.pending.head.root
    (replicaOfState raw.prepared)

def CompletedPromotionOpportunity.ready
    (opportunity : CompletedPromotionOpportunity origin now refused state) :
    PromotionProgress.Ready origin now refused state :=
  ready_of_opportunity opportunity.raw opportunity.publisher opportunity.reads
    opportunity.complete

/-- Fetch convergence and the later promotion attempt are joined by durable
evidence inclusion.  Semantic completion at an earlier committed observation
therefore supplies the zero deficit used to build the exact production
completeness execution inside `PromotionProgress.Ready`. -/
def ready_of_semantic_completion
    (ready : PromotionOpportunity origin now refused state)
    (publisher : TrieProgramProofs.RawSnapshot)
    (requirements : FiniteRequirements publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root)
    (complete : PermittedComplete publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root before)
    (carried : EvidenceIncluded before (replicaOfState ready.prepared))
    (reads : PromotionReadOpportunity publisher ready.tx
      ⟨ready.scope, ready.authority.provenance.map Origin.canonical⟩
      ready.pending.head.root) :
    PromotionProgress.Ready origin now refused state := by
  have preparedComplete : PermittedComplete publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root
      (replicaOfState ready.prepared) :=
    TrieFetchCompletion.completion_mono complete carried
  have zero : missingEvidence requirements.items (replicaOfState ready.prepared) = 0 :=
    (TrieFetchCompletion.finite_measure_eq_zero_iff_complete requirements).mpr preparedComplete
  have completed := (finite_promotion_complete_execution publisher ready.tx ready.scope
    ready.authority ready.pending ready.prepared requirements zero reads ready.completion).2
  let body : PromotionProgress.BodyReady ready.tx origin now ready.pending ready.old
      ready.scope ready.authority ready.prepared :=
    { newer := ready.newer
      checked := ready.completion.final
      authorized := ready.authorized
      written := ready.written
      cleared := ready.cleared
      staged := ready.staged
      count := ready.count
      completeExecution := completed
      permittedExecution := ready.permittedExecution
      writeExecution := ready.writeExecution
      clearExecution := ready.clearExecution
      materializeExecution := ready.materializeExecution }
  exact
    { tx := ready.tx
      opened := ready.opened
      prepared := ready.prepared
      scope := ready.scope
      replicas := ready.replicas
      authority := ready.authority
      pending := ready.pending
      old := ready.old
      began := ready.began
      preparation := ready.preparation
      policy := ready.policy
      policyUnique := ready.policyUnique
      notRefused := ready.notRefused
      body := body
      final := ready.final
      committed := ready.committed }

end Synchronicity.TrieCompleteConverse
