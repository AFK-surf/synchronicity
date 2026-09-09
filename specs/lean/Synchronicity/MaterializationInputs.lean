import Synchronicity.MaterializationExactFiles
import Synchronicity.MaterializationWholeRetention
import Synchronicity.HostProgramProofs

/-! The materializer's scope, replica policies and timestamps come from its
actual read-only preparation. That preparation cannot alter the old view,
content obligations, immutable graph or primitive interpretation. -/
namespace Synchronicity.MaterializationInputs
open VerifiedCore VerifiedCore.Host Replication SimulatedHost PrivateDatabase

def observation (state : State) : State := {state with trace := []}

def storageRead : Storage A → Prop
  | .begin | .commit _ | .rollback _ | .upsert .. | .deleteRows .. | .deleteExcept .. | .removeFile .. => False
  | _ => True

def allowed (A : Type) : Materialize.Effects A → Prop
  | .left effect => storageRead effect
  | .right (.right (.left effect)) => TrieReadEffects.accessRead effect
  | _ => True

def authAllowed (A : Type) : Authorization.Effects A → Prop
  | .left effect => storageRead effect
  | _ => True

theorem reply_observation (state : State) (event : String) (action : State → Result (Reply A))
    (consume : Bool) (kept : ∀ s, observation (action s).2 = observation s) :
    observation (reply state event action consume).2 = observation state := by
  unfold reply
  split
  · cases consume
    · rfl
    · simpa only [observation, record, ↓reduceIte] using kept state
  · simpa only [observation, record] using kept state

theorem transaction_observation (state : State) (tx : Transaction) (query : Database → A) :
    observation (SimulatedHost.transaction state tx (fun db => (query db, db))).2 = observation state := by
  unfold SimulatedHost.transaction
  split
  · rename_i token db opened
    split
    · simp only [observation, opened]
    · rfl
  · rfl

theorem storage_observation (effect : Storage A) (safe : storageRead effect) (state : State) :
    observation (storage effect state).2 = observation state := by
  cases effect <;> simp only [storage]
  all_goals first | contradiction | (apply reply_observation; intro s)
  all_goals first | exact transaction_observation .. | rfl | (repeat' first | rfl | split)

theorem effects_observation (effect : Materialize.Effects A) (safe : allowed _ effect) (state : State) :
    observation (Interpreter.handle effect state).2 = observation state := by
  cases effect with
  | left effect => exact storage_observation effect safe state
  | right effect =>
    rcases effect with effect | effect
    · cases effect <;> apply reply_observation <;> intro s <;> rfl
    · rcases effect with effect | effect
      · cases effect <;> first
          | contradiction
          | (apply reply_observation; intro s; rfl)
      · rcases effect with effect | effect
        · cases effect; apply reply_observation; intro s; rfl
        · rcases effect with effect | effect
          · cases effect; apply reply_observation; intro s; rfl
          · rcases effect with effect | effect
            · cases effect; apply reply_observation; intro s; rfl
            · cases effect; apply reply_observation; intro s; rfl

theorem config_only (tx : Transaction) (key : String) : Only authAllowed (Authorization.config tx key).run := by
  unfold Authorization.config
  refine Only.seq (Only.raise _ _ trivial) fun result => ?_
  repeat' first
    | exact .done _
    | (refine Only.seq ?_ fun _ => .done _)
    | (unfold Authorization.checked; split)
    | split

theorem origin_only (column text : String) : Only authAllowed (Authorization.originField column text).run := by
  unfold Authorization.originField
  refine Only.seq ?_ fun result => ?_
  · unfold Origin.parse
    repeat' first
      | exact .done _
      | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
      | split
  · cases result <;> exact .done _

theorem scope_source_only (tx : Transaction) (origin : Origin.Parsed) :
    Only authAllowed (Authorization.materializationScopeIn tx origin).run := by
  unfold Authorization.materializationScopeIn Authorization.ownOrigin
  refine Only.seq ?_ fun own => ?_
  · refine Only.seq (config_only tx _) fun own => ?_
    cases own with
    | none => exact .done _
    | some text => exact Only.seq (origin_only _ text) fun _ => .done _
  · split
    · exact .done _
    · unfold Authorization.localSpacesIn
      exact Only.seq (Only.seq (config_only tx _) fun _ => .done _) fun _ => .done _

theorem auth_only (operation : Authorization.Action A) (safe : Only authAllowed operation.run) :
    Only allowed (Materialize.auth operation).run := by
  apply Only.within _ _ safe
  intro B effect good
  cases effect <;> exact good

theorem pure_only (result : Except Materialize.Error A) : Only allowed (ExceptT.mk (Program.pure result)).run := .done _

theorem targets_only (tx : Transaction) : Only allowed (Materialize.targets tx).run := by
  unfold Materialize.targets
  refine Only.seq (auth_only _ (config_only tx _)) fun floor => ?_
  refine Only.seq (Only.raise _ _ trivial) fun rows => ?_
  apply Only.mapM
  intro row
  repeat' first
    | exact .done _
    | (refine Only.seq (pure_only _) fun _ => ?_)
    | split

abbrev Values := Trie.Serve.Scope × Int64 × List Materialize.Target × Int64

def prepare (tx : Transaction) (origin : Origin.Parsed) : Materialize.Action Values := do
  let scope ← Materialize.auth (Authorization.materializationScopeIn tx origin)
  let now ← raise Materialize.Error.host Clock.nowNs
  let replicas ← Materialize.targets tx
  let floor := ((← Materialize.auth (Authorization.config tx "trust_clock_floor")).bind Authorization.parseI64).getD 0
  let releaseNow := max (← raise Materialize.Error.host Clock.nowNs) floor
  return (scope, now, replicas, releaseNow)

theorem prepare_only (tx : Transaction) (origin : Origin.Parsed) : Only allowed (prepare tx origin).run := by
  unfold prepare
  refine Only.seq (auth_only _ (scope_source_only tx origin)) fun _ => ?_
  refine Only.seq (Only.raise _ _ trivial) fun _ => ?_
  refine Only.seq (targets_only tx) fun _ => ?_
  refine Only.seq (auth_only _ (config_only tx _)) fun _ => ?_
  exact Only.seq (Only.raise _ _ trivial) fun _ => .done _

theorem prepare_preserves (tx : Transaction) (origin : Origin.Parsed) (state final : State) (values : Values)
    (ran : execute (prepare tx origin) state = (.ok values, final)) : observation final = observation state := by
  have same := (prepare_only tx origin).preserves_observation observation _ effects_observation state
  change observation (execute (prepare tx origin) state).2 = observation state at same
  simpa only [ran] using same

theorem materialize_decomposes (tx : Transaction) (origin : Origin.Parsed) (oldRoot newRoot : ByteArray) :
    Materialize.materialize tx origin oldRoot newRoot = (do
      let (scope, now, replicas, releaseNow) ← prepare tx origin
      Materialize.runDiff tx (Materialize.apply tx (Origin.canonical origin) now releaseNow replicas)
        (Trie.Diff.materialize (E := Trie.Diff.Effects) scope oldRoot newRoot).run) := by
  simp only [Materialize.materialize, Materialize.materializeIn, prepare,
    HostProgramProofs.operation_bind_assoc, HostProgramProofs.operation_pure_bind]

theorem materialize_inputs (tx : Transaction) (origin : Origin.Parsed) (oldRoot newRoot : ByteArray)
    (state final : State) (count : UInt64)
    (ran : execute (Materialize.materialize tx origin oldRoot newRoot) state = (.ok count, final)) :
    ∃ scope now replicas releaseNow ready,
      execute (prepare tx origin) state = (.ok (scope, now, replicas, releaseNow), ready) ∧
      observation ready = observation state ∧
      execute (Materialize.runDiff tx (Materialize.apply tx (Origin.canonical origin) now releaseNow replicas)
        (Trie.Diff.materialize (E := Trie.Diff.Effects) scope oldRoot newRoot).run) ready = (.ok count, final) := by
  rw [materialize_decomposes] at ran
  obtain ⟨⟨scope, now, replicas, releaseNow⟩, ready, prepared, streamed⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  exact ⟨scope, now, replicas, releaseNow, ready, prepared, prepare_preserves tx origin state ready _ prepared, streamed⟩

/-- Applicable local policy is witnessed by actual successful reads of this
configuration and replica-table snapshot. Neither view contents nor a proposed
publication result participates in this relation. -/
def ReadPolicy (db : Database) (origin : Origin.Parsed) (scope : Trie.Serve.Scope)
    (replicas : List Materialize.Target) : Prop :=
  ∃ tx state final now releaseNow source,
    state.pending = some (tx, source) ∧ rows source "config" = rows db "config" ∧
    rows source "replicas" = rows db "replicas" ∧
    execute (prepare tx origin) state = (.ok (scope, now, replicas, releaseNow), final)

theorem read_policy_frame (before after : Database)
    (config : rows after "config" = rows before "config") (replicas : rows after "replicas" = rows before "replicas")
    (read : ReadPolicy after origin scope targets) : ReadPolicy before origin scope targets := by
  obtain ⟨tx, state, final, now, releaseNow, source, opened, sameConfig, sameReplicas, ran⟩ := read
  exact ⟨tx, state, final, now, releaseNow, source, opened, sameConfig.trans config, sameReplicas.trans replicas, ran⟩

/-- The actual materialization entry point, including its policy reads, is
ready on success. Its initial-view contract is stated for policies compatible
with raw config/replica rows, not a caller-supplied scope or ready result. -/
theorem materialize_ready (tx : Transaction) (origin : Origin.Parsed) (oldRoot newRoot : ByteArray)
    (world : TrieDiffCoverage.World) (services : MaterializedView.Services)
    (unique : MaterializedView.UniqueAddresses services (SnapshotViewProgress.Relevant world.snapshot oldRoot newRoot))
    (supported : ∀ scope replicas, ReadPolicy db origin scope replicas → ∀ key,
      scope.admitsKeyPath (Trie.keyNibbles key) = true →
      SnapshotDelta.ChangedKey world.snapshot oldRoot newRoot key → key.size ≤ Trie.maxKeyBytes)
    (state final : State) (count : UInt64) (opened : state.pending = some (tx, db))
    (faithful : TrieDiffCoverage.Faithful world state) (normalization : state.isNfc = services.nfc)
    (schema : MaterializationKeySchema.Schema db)
    (initial : ∀ scope replicas, ReadPolicy db origin scope replicas →
      MaterializationRequirementFrame.PoliciesAgree replicas ∧ MaterializedView.CurrentRequirements replicas db ∧
      SnapshotViewProgress.ExactFiles services world.snapshot oldRoot
        (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) db (Origin.canonical origin))
    (ran : execute (Materialize.materialize tx origin oldRoot newRoot) state = (.ok count, final)) :
    ∃ scope replicas after, ReadPolicy db origin scope replicas ∧ final.pending = some (tx, after) ∧
      SnapshotViewProgress.ExactFiles services world.snapshot newRoot
        (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) after (Origin.canonical origin) ∧
      MaterializedView.CurrentRequirements replicas after ∧ MaterializedView.ForeverRequirements replicas db after := by
  obtain ⟨scope, now, replicas, releaseNow, ready, prepared, frame, streamed⟩ :=
    materialize_inputs tx origin oldRoot newRoot state final count ran
  have read : ReadPolicy db origin scope replicas :=
    ⟨tx, state, ready, now, releaseNow, db, opened, rfl, rfl, prepared⟩
  have readyTx : ready.pending = some (tx, db) := (congrArg State.pending frame).trans opened
  have readyNfc : ready.isNfc = services.nfc := (congrArg State.isNfc frame).trans normalization
  have readyFaithful : TrieDiffCoverage.Faithful world ready := by
    have bytes : readableBytes ready = readableBytes state := by
      have same := congrArg SimulatedHost.readableBytes frame
      exact same
    exact ⟨by rw [bytes]; exact faithful.1, (congrArg State.hash frame).trans faithful.2⟩
  obtain ⟨policy, current, exactOld⟩ := initial scope replicas read
  obtain ⟨after, pending, exactNew⟩ := MaterializationExactFiles.materialize_exact tx (Origin.canonical origin) services world
    scope oldRoot newRoot unique (supported scope replicas read) now releaseNow replicas ready final count db readyTx readyNfc readyFaithful exactOld streamed
  obtain ⟨heldDb, heldTx, _, holds, history⟩ := MaterializationWholeRetention.materialize_requirements
    tx (Origin.canonical origin) world scope oldRoot newRoot now releaseNow replicas policy ready final count db readyTx readyFaithful schema current streamed
  have same : after = heldDb := congrArg Prod.snd (Option.some.inj (pending.symm.trans heldTx))
  subst heldDb
  exact ⟨scope, replicas, after, read, pending, exactNew, holds, history⟩

end Synchronicity.MaterializationInputs
