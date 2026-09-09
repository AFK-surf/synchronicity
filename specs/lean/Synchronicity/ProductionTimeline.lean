import Synchronicity.MaterializationInputs
import Synchronicity.PromotionExecution
import Synchronicity.TrieFetchAdmissionProgress

/-! A shared production-state timeline for carrying persistent metadata evidence
between independently observed operations.  The promotion bridge below uses the
actual begin and preparation executions; callers do not supply an evidence frame. -/
namespace Synchronicity.ProductionTimeline
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
open SimulatedHost PrivateDatabase
open TrieFetchCompletion TrieFetchAdmissionProgress

/-- A production trace indexed by logical observation time. -/
structure Timeline where
  state : Nat → SimulatedHost.State

/-- Every adjacent state in the half-open interval `[from, to)` retains all
persistent trie evidence. -/
def StepwiseIncluded (timeline : Timeline) (start stop : Nat) : Prop :=
  ∀ now, start ≤ now → now < stop →
    EvidenceIncluded (replicaOfState (timeline.state now))
      (replicaOfState (timeline.state (now + 1)))

/-- Adjacent evidence frames compose over any finite forward interval. -/
theorem StepwiseIncluded.carries (timeline : Timeline) {start stop : Nat}
    (steps : StepwiseIncluded timeline start stop) (forward : start ≤ stop) :
    EvidenceIncluded (replicaOfState (timeline.state start))
      (replicaOfState (timeline.state stop)) := by
  obtain ⟨span, rfl⟩ := Nat.exists_eq_add_of_le forward
  induction span with
  | zero =>
    simpa using EvidenceIncluded.refl (replicaOfState (timeline.state start))
  | succ span ih =>
    rw [Nat.add_succ]
    have earlier : StepwiseIncluded timeline start (start + span) := by
      intro now lower upper
      exact steps now lower (Nat.lt_trans upper (Nat.lt_succ_self _))
    exact (ih earlier (Nat.le_add_right start span)).trans
      (steps (start + span) (Nat.le_add_right start span) (Nat.lt_add_one _))

private abbrev ReadAllowed (A : Type) := MaterializationInputs.authAllowed A

private theorem checked_only (value : Except Authorization.Error A) :
    Only ReadAllowed (Authorization.checked value).run := by
  cases value <;> exact .done _

private theorem keyField_only (column : String) (bytes : ByteArray) :
    Only ReadAllowed (Authorization.keyField column bytes).run := by
  unfold Authorization.keyField
  split
  · exact .done _
  · refine Only.seq (.request trivial fun _ => .done _) fun result => ?_
    split <;> exact .done _

private theorem decodeBinding_only (row : Row) :
    Only ReadAllowed (Authorization.decodeBinding row).run := by
  unfold Authorization.decodeBinding
  repeat' first
    | exact .done _
    | exact MaterializationInputs.origin_only ..
    | (refine Only.seq (checked_only _) fun _ => ?_)
    | (refine Only.seq (MaterializationInputs.origin_only ..) fun _ => ?_)
    | (refine Only.seq (keyField_only ..) fun _ => ?_)
    | (refine Only.seq ?_ fun _ => ?_)
    | split

private theorem readBindings_only (tx : Transaction) (fields : Fields) :
    Only ReadAllowed (Authorization.readBindings tx fields).run := by
  unfold Authorization.readBindings
  refine Only.seq (.request trivial fun _ => .done _) fun scan => ?_
  refine (Only.mapM _ _ decodeBinding_only).seq fun _ => ?_
  split <;> exact .done _

private theorem liveAmong_only (tx : Transaction)
    (bindings : List Authorization.Binding) (now : Int64) :
    Only ReadAllowed (Authorization.liveAmong tx bindings now).run := by
  unfold Authorization.liveAmong
  apply Only.seq
  · apply Only.forIn
    intro binding initial
    repeat' first
      | exact .done _
      | (refine Only.seq (readBindings_only ..) fun _ => ?_)
      | (refine Only.seq ?_ fun _ => ?_)
      | (dsimp only; split)
      | split
  · intro _
    exact .done _

private theorem trustInstant_only (tx : Transaction) (now : Int64) :
    Only ReadAllowed (Authorization.trustInstant tx now).run := by
  unfold Authorization.trustInstant
  split
  · exact .done _
  · exact (MaterializationInputs.config_only tx _).seq fun _ => .done _

private theorem liveForOrigin_only (tx : Transaction) (origin : String) (now : Int64) :
    Only ReadAllowed (Authorization.liveForOrigin tx origin now).run := by
  unfold Authorization.liveForOrigin
  exact (readBindings_only tx _).seq fun bindings => liveAmong_only tx bindings now

private theorem originAuthority_only (tx : Transaction) (origin : Origin.Parsed) (now : Int64) :
    Only ReadAllowed (Authorization.originAuthorityIn tx origin now).run := by
  unfold Authorization.originAuthorityIn
  refine (trustInstant_only tx now).seq fun instant => ?_
  refine (liveForOrigin_only tx _ instant).seq fun _ => ?_
  refine (MaterializationInputs.config_only tx _).seq fun own => ?_
  refine Only.seq ?_ fun _ => .done _
  cases own with
  | none => exact .done _
  | some text => exact Only.map _ _ (MaterializationInputs.origin_only _ text)

/-- Promotion effects admitted during preparation preserve the host observation
used by persistent trie evidence.  Memo effects are excluded from this phase. -/
private def PrepareAllowed (A : Type) : Promote.Effects A → Prop
  | .left effect => MaterializationInputs.allowed A effect
  | .right _ => False

private theorem prepare_effect_observation (effect : Promote.Effects A)
    (safe : PrepareAllowed A effect) (state : State) :
    MaterializationInputs.observation (Interpreter.handle effect state).2 =
      MaterializationInputs.observation state := by
  cases effect with
  | left effect => exact MaterializationInputs.effects_observation effect safe state
  | right _ => contradiction

private theorem auth_only (operation : Authorization.Action A)
    (safe : Only ReadAllowed operation.run) :
    Only PrepareAllowed (Promote.auth operation).run := by
  apply Only.within _ _ safe
  intro B effect good
  cases effect with
  | left effect =>
    cases effect <;> first | contradiction | exact good
  | right _ => trivial

private theorem history_only (operation : History.Action A)
    (safe : Only ReadAllowed operation.run) :
    Only PrepareAllowed (Promote.history operation).run := by
  apply Only.within _ _ safe
  intro B effect good
  cases effect with
  | left effect =>
    cases effect <;> first | contradiction | exact good
  | right _ => trivial

private theorem parse_only (validate : List UInt8 → OperationOver History.Effects ε Bool)
    (safe : ∀ bytes, Only ReadAllowed (validate bytes).run) (text : String) :
    Only ReadAllowed (Origin.parse validate text).run := by
  unfold Origin.parse
  repeat' first
    | exact .done _
    | (refine Only.seq (safe _) fun _ => ?_)
    | split

private theorem decodeJoinedHead_only (row : Row) :
    Only ReadAllowed (History.decodeJoinedHead row).run := by
  unfold History.decodeJoinedHead
  refine Only.seq (.done _) fun fields => ?_
  refine (parse_only History.validateKey
    (fun _ => .request trivial fun _ => .done _) fields.origin).seq fun _ => ?_
  repeat' first
    | exact .done _
    | (refine Only.seq (.done _) fun _ => ?_)
    | (refine Only.seq (.request trivial fun _ => .done _) fun _ => ?_)
    | split

private theorem slot_only (tx : Transaction) (origin : Origin.Parsed) (name : String) :
    Only PrepareAllowed (Promote.slot tx origin name).run := by
  unfold Promote.slot
  refine Only.seq (Only.raise _ _ trivial) fun scan => ?_
  repeat' first
    | exact .done _
    | (refine Only.seq (history_only _ (decodeJoinedHead_only _)) fun _ => ?_)
    | split

private theorem prepare_only (tx : Transaction) (origin : Origin.Parsed) (now : Int64) :
    Only PrepareAllowed (PromotionCommand.prepare tx origin now).run := by
  unfold PromotionCommand.prepare
  refine (auth_only _ (MaterializationInputs.scope_source_only tx origin)).seq fun _ => ?_
  refine (auth_only _ (originAuthority_only tx origin now)).seq fun _ => ?_
  refine (slot_only tx origin "pending").seq fun pending => ?_
  split
  · exact (slot_only tx origin "complete").seq fun _ => .done _
  · exact Only.seq (.done _) fun _ => .done _

private theorem prepare_preserves_observation (tx : Transaction) (origin : Origin.Parsed)
    (now : Int64) (opened prepared : State) (value : PromotionCommand.Prepared)
    (ran : execute (PromotionCommand.prepare tx origin now) opened = (.ok value, prepared)) :
    MaterializationInputs.observation prepared = MaterializationInputs.observation opened := by
  have kept := (prepare_only tx origin now).preserves_observation
    MaterializationInputs.observation _ prepare_effect_observation opened
  change MaterializationInputs.observation
    (execute (PromotionCommand.prepare tx origin now) opened).2 = _ at kept
  simpa only [ran] using kept

private theorem replica_observation (state : State) :
    replicaOfState (MaterializationInputs.observation state) = replicaOfState state := rfl

/-- A successful production transaction begin cannot lose persistent trie
evidence, even though it opens the database snapshot and advances the token. -/
theorem raw_begin_includes (state opened : State) (tx : Transaction)
    (began : execute (Promote.raw .begin) state = (.ok tx, opened)) :
    EvidenceIncluded (replicaOfState state) (replicaOfState opened) := by
  have raw : storage .begin state = (.ok tx, opened) :=
    OperationExecution.raise_success (fun _ _ => rfl) Promote.Error.host Storage.begin
      state opened tx began
  simp only [storage, reply] at raw
  split at raw
  · cases raw
  · split at raw
    · cases raw
    · cases raw
      have closed : state.pending = none := by
        cases pendingEq : state.pending with
        | none => rfl
        | some _ => simp [pendingEq] at *
      intro evidence verified
      cases evidence <;>
        simpa [replicaOfState, Verified, readableBytes, readByteObject, record, closed]
          using verified

/-- The real successful begin followed by the real read-only promotion
preparation carries all evidence from the promotion's starting state to the
prepared state.  No caller-provided evidence frame appears in the premises. -/
theorem promotion_prepare_includes (state opened prepared : State) (tx : Transaction)
    (origin : Origin.Parsed) (now : Int64) (value : PromotionCommand.Prepared)
    (began : execute (Promote.raw .begin) state = (.ok tx, opened))
    (read : execute (PromotionCommand.prepare tx origin now) opened = (.ok value, prepared)) :
    EvidenceIncluded (replicaOfState state) (replicaOfState prepared) := by
  have observed := prepare_preserves_observation tx origin now opened prepared value read
  have sameReplica : replicaOfState prepared = replicaOfState opened := by
    calc
      replicaOfState prepared =
          replicaOfState (MaterializationInputs.observation prepared) :=
        (replica_observation prepared).symm
      _ = replicaOfState (MaterializationInputs.observation opened) :=
        congrArg replicaOfState observed
      _ = replicaOfState opened := replica_observation opened
  rw [sameReplica]
  exact raw_begin_includes state opened tx began

end Synchronicity.ProductionTimeline
