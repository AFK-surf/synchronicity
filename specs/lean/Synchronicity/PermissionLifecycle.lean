import VerifiedCore.Replication.ScopeChange

/-! An operation-independent permission lifecycle for M8.

A signed pending version remains useful when permission changes, but neither a
completion/refusal derived under the old permission nor its suspended work may
answer the new question.  The generation is a logical credential: production
derives it by re-reading `materializationScopeIn` before destructive Fetch
settlement, while the atomic scope-change command clears complete/refusal state
and requeues the signed target. -/
namespace Synchronicity.PermissionLifecycle
open VerifiedCore

structure Version where
  seq : UInt64
  root : ByteArray
  deriving BEq, DecidableEq

structure Credential (A : Type) where
  generation : Nat
  value : A

structure Work where
  generation : Nat
  target : Version

structure State where
  scope : Trie.Serve.Scope
  generation : Nat
  complete : Option (Credential Version) := none
  pending : Option Version := none
  refusals : List (Credential Version) := []

/-- Every cached conclusion that can suppress or expose work belongs to the
currently applicable permission. Pending is deliberately not a credential: it
is a signed target which must begin fresh work before it can settle. -/
def Fresh (state : State) : Prop :=
  (∀ completion, state.complete = some completion → completion.generation = state.generation) ∧
  ∀ refusal ∈ state.refusals, refusal.generation = state.generation

/-- A captured requester may settle only the exact still-pending target under
the permission generation from which it was started. -/
def Applicable (state : State) (work : Work) : Prop :=
  work.generation = state.generation ∧ state.pending = some work.target

instance (state : State) (work : Work) : Decidable (Applicable state work) := by
  unfold Applicable
  infer_instance

/-- The same unsigned sequence/root order used by production reconciliation.
It makes the pending target retained by a permission change independent of
arrival order. -/
def newer (candidate floor : Version) : Bool :=
  Replication.Reconcile.newer candidate.seq candidate.root ⟨floor.seq, floor.root⟩

/-- Requeue the old complete signed target unless an existing pending target
already outranks it. This mirrors `ScopeChange.demote`; scope changes preserve
the best known synchronization target, not necessarily the old pending slot. -/
def retainedPending (state : State) : Option Version :=
  match state.complete, state.pending with
  | none, pending => pending
  | some completion, none => some completion.value
  | some completion, some pending =>
      if newer completion.value pending then some completion.value else some pending

def ofPointer (pointer : Replication.History.Pointer) : Version :=
  ⟨pointer.seq, pointer.root⟩

/-- Per-origin state reconstructed from the typed rows actually consumed by a
successful production demotion. The generation/refusal fields are proof
credentials; the version fields come only from the report's joined rows. -/
def ofDemotion (scope : Trie.Serve.Scope) (generation : Nat)
    (refusals : List (Credential Version))
    (decision : Replication.ScopeChange.Demotion) : State :=
  { scope
    generation
    complete := some ⟨generation, ofPointer decision.complete.pointer⟩
    pending := decision.pending.map fun head => ofPointer head.pointer
    refusals }

def change (state : State) (next : Trie.Serve.Scope) : State :=
  if next = state.scope then state else
    { state with
      scope := next
      generation := state.generation + 1
      complete := none
      pending := retainedPending state
      refusals := [] }

/-- The generic production decision and the common domain model select the
same pending target for every typed complete/pending pair. -/
theorem production_demotion_retains_max (decision : Replication.ScopeChange.Demotion)
    (scope next : Trie.Serve.Scope) (generation : Nat)
    (refusals : List (Credential Version)) (changed : next ≠ scope) :
    (change (ofDemotion scope generation refusals decision) next).pending =
      some (ofPointer decision.selected) := by
  simp only [change, ofDemotion, changed, ↓reduceIte, retainedPending,
    Replication.ScopeChange.Demotion.selected, Replication.ScopeChange.selectedPending]
  cases pending : decision.pending with
  | none => simp [Replication.ScopeChange.shouldRequeue, ofPointer]
  | some current =>
    simp only [Option.map_some]
    unfold Replication.ScopeChange.shouldRequeue
    simp only [Option.all_some]
    split <;> rename_i order
    · rw [if_pos (by simpa [newer, ofPointer] using order)]
    · rw [if_neg (by simpa [newer, ofPointer] using order)]
      rfl

def begin (state : State) (target : Version) : Work := ⟨state.generation, target⟩

def finish (state : State) (work : Work) : State :=
  if Applicable state work then
    { state with complete := some ⟨state.generation, work.target⟩, pending := none }
  else state

def refuse (state : State) (work : Work) : State :=
  if Applicable state work then
    { state with refusals := ⟨state.generation, work.target⟩ :: state.refusals }
  else state

inductive Event where
  | permission (next : Trie.Serve.Scope)
  | completed (work : Work)
  | refused (work : Work)

/-- Domain transitions contain inputs and captured provenance, not a claimed
safety result. They are shared by widening, narrowing, expiry and revocation. -/
inductive Step : Event → State → State → Prop where
  | permission (state : State) (next : Trie.Serve.Scope) :
      Step (.permission next) state (change state next)
  | completed (state : State) (work : Work) :
      Step (.completed work) state (finish state work)
  | refused (state : State) (work : Work) :
      Step (.refused work) state (refuse state work)

structure Observation where
  event : Event
  before : State
  after : State

inductive Execution : State → List Observation → State → Prop where
  | nil (state : State) : Execution state [] state
  | cons {event state next final rest} :
      Step event state next → Execution next rest final →
      Execution state (⟨event, state, next⟩ :: rest) final

theorem change_fresh (state : State) (next : Trie.Serve.Scope) (fresh : Fresh state) :
    Fresh (change state next) := by
  unfold change
  split
  · exact fresh
  · constructor <;> simp

theorem finish_fresh (state : State) (work : Work) (fresh : Fresh state) :
    Fresh (finish state work) := by
  unfold finish
  split <;> rename_i applicable
  · constructor
    · intro completion same
      simp only [Option.some.injEq] at same
      subst completion
      rfl
    · simpa using fresh.2
  · exact fresh

theorem refuse_fresh (state : State) (work : Work) (fresh : Fresh state) :
    Fresh (refuse state work) := by
  unfold refuse
  split <;> rename_i applicable
  · constructor
    · exact fresh.1
    · intro refusal member
      simp only [List.mem_cons] at member
      rcases member with same | old
      · subst refusal; rfl
      · exact fresh.2 refusal old
  · exact fresh

theorem Step.preserves_fresh (step : Step event before after) (fresh : Fresh before) :
    Fresh after := by
  cases step with
  | permission => exact change_fresh _ _ fresh
  | completed => exact finish_fresh _ _ fresh
  | refused => exact refuse_fresh _ _ fresh

/-- Work captured before a changed permission is inert: it can neither create
completion nor install a refusal that suppresses rebuilding. -/
theorem stale_work_is_inert (work : Work) (state : State)
    (stale : work.generation ≠ state.generation) :
    finish state work = state ∧ refuse state work = state := by
  have inapplicable : ¬Applicable state work := fun applicable => stale applicable.1
  constructor <;> simp [finish, refuse, inapplicable]

/-- A real permission change preserves the signed pending target for reuse but
removes every old authorization-bearing conclusion. -/
def InvalidatesOld (before after : State) (next : Trie.Serve.Scope) : Prop :=
  next ≠ before.scope →
    after.scope = next ∧ after.generation = before.generation + 1 ∧
    after.complete = none ∧ after.refusals = [] ∧
    after.pending = retainedPending before

theorem change_invalidates (state : State) (next : Trie.Serve.Scope) :
    InvalidatesOld state (change state next) next := by
  intro different
  simp [change, different]

def Safety (trace : List Observation) : Prop :=
  ∀ observation ∈ trace,
    Fresh observation.before → Fresh observation.after ∧
    (∀ next, observation.event = .permission next →
      InvalidatesOld observation.before observation.after next) ∧
    (∀ work, observation.event = .completed work ∨ observation.event = .refused work →
      ¬Applicable observation.before work → observation.after = observation.before)

theorem Step.refines (step : Step event before after) :
    Fresh before → Fresh after ∧
    (∀ next, event = .permission next → InvalidatesOld before after next) ∧
    (∀ work, event = .completed work ∨ event = .refused work →
      ¬Applicable before work → after = before) := by
  intro fresh
  constructor
  · exact step.preserves_fresh fresh
  · constructor
    · cases step with
      | permission state next =>
        intro named same
        cases same
        exact change_invalidates _ _
      | completed state work => intro next impossible; cases impossible
      | refused state work => intro next impossible; cases impossible
    · cases step with
    | permission state next =>
      intro work impossible
      rcases impossible with impossible | impossible <;> cases impossible
    | completed state work =>
      intro named eventName notApplicable
      rcases eventName with same | impossible
      · cases same
        unfold finish
        split <;> rename_i applies
        · exact False.elim (notApplicable applies)
        · rfl
      · cases impossible
    | refused state work =>
      intro named eventName notApplicable
      rcases eventName with impossible | same
      · cases impossible
      · cases same
        unfold refuse
        split <;> rename_i applies
        · exact False.elim (notApplicable applies)
        · rfl

theorem execution_safe (execution : Execution initial trace final) : Safety trace := by
  induction execution with
  | nil _ => intro observation member; cases member
  | cons step rest ih =>
    intro observation member fresh
    rcases List.mem_cons.mp member with same | later
    · subst observation
      exact step.refines fresh
    · exact ih observation later fresh

theorem Execution.preserves_fresh (execution : Execution initial trace final)
    (fresh : Fresh initial) : Fresh final := by
  induction execution with
  | nil _ => exact fresh
  | cons step rest ih => exact ih (step.preserves_fresh fresh)

/-- The fixed-scope state required by fixed-permission convergence: the signed
target has been rebuilt by current work and no stale pending task remains. -/
def Ready (state : State) (target : Version) : Prop :=
  state.pending = none ∧
  ∃ completion, state.complete = some completion ∧
    completion.generation = state.generation ∧ completion.value = target

structure StableOpportunity (state : State) (target : Version) : Prop where
  pending : state.pending = some target

/-- Once permission is stable, one sufficient usable synchronization
opportunity starts with the current credential and re-enters the fixed-scope
ready state. Scheduling and service must establish that opportunity; it is not
smuggled in as pre-existing completion. -/
theorem stable_rebuild (opportunity : StableOpportunity state target) :
    let work := begin state target
    Step (.completed work) state (finish state work) ∧ Ready (finish state work) target := by
  let work := begin state target
  constructor
  · exact .completed state work
  · have applicable : Applicable state (begin state target) := by
      exact ⟨rfl, opportunity.pending⟩
    unfold finish
    rw [if_pos applicable]
    exact ⟨rfl, ⟨⟨state.generation, target⟩, rfl, rfl, rfl⟩⟩

end Synchronicity.PermissionLifecycle
