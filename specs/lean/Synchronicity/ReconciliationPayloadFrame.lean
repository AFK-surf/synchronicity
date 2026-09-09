import Synchronicity.TableInvariant
import Synchronicity.ReconciliationFailure
import Synchronicity.MptsyncStableTail
import Synchronicity.FetchPayloadFrame

/-! Actual signed-head acceptance changes only heads/history bookkeeping.  The
materialized payload and retention tables are framed through every transaction
outcome. -/
namespace Synchronicity.ReconciliationPayloadFrame
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def Allowed (relation : String) (A : Type) : History.Effects A → Prop
  | .left effect => TableInvariant.StorageAllowed relation effect
  | .right _ => True

theorem effects (relation : String) (baseline : List Fields) (effect : History.Effects A)
    (safe : Allowed relation _ effect) : TableInvariant.EffectSafe relation baseline effect := by
  intro state initial
  cases effect with
  | left effect => exact TableInvariant.storage_safe relation baseline effect safe state initial
  | right effect =>
    cases effect <;> exact TableInvariant.reply_holds relation baseline state _ _ _
      (fun _ held => held) initial

theorem read_only (relation : String) (operation : History.Action A)
    (safe : Only ReconciliationReadOnly.allowed operation.run) :
    Only (Allowed relation) operation.run := by
  apply safe.mono
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem auth_only (relation : String) (operation : Authorization.Action A)
    (safe : Only ReconciliationReadOnly.allowed operation.run) :
    Only (Allowed relation) (within Reconcile.authorizationError operation : History.Action A).run := by
  apply Only.within _ _ safe
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem record_only (relation : String) (history : "head_history" ≠ relation)
    (tx : Transaction) (head : Head) (now : Int64) :
    Only (Allowed relation) (Reconcile.record tx head now).run := by
  unfold Reconcile.record
  split
  · exact .done _
  · refine Only.seq (Only.raise _ _ history) fun _ => ?_
    refine Only.seq (Only.raise _ _ trivial) fun _ => ?_
    split <;> exact .done _

theorem trim_only (relation : String) (history : "head_history" ≠ relation)
    (tx : Transaction) (origin : String) (seq : UInt64) (keep : Nat) :
    Only (Allowed relation) (Reconcile.trimForks tx origin seq keep).run := by
  unfold Reconcile.trimForks
  refine Only.seq (Only.raise _ _ trivial) fun result => ?_
  refine Only.seq (.done _) fun pointers => ?_
  refine Only.seq ?_ fun _ => .done _
  apply Only.forIn
  intro pointer initial
  exact Only.seq (Only.raise _ _ history) fun _ => .done _

theorem put_only (relation : String) (heads : "heads" ≠ relation)
    (history : "head_history" ≠ relation) (tx : Transaction) (slot : String)
    (head : Head) (received verified : Int64) :
    Only (Allowed relation) (Reconcile.putSlot tx slot head received verified).run := by
  unfold Reconcile.putSlot
  exact (record_only relation history tx head received).seq fun _ =>
    Only.request heads fun _ => .done _

theorem accept_only (relation : String) (heads : "heads" ≠ relation)
    (history : "head_history" ≠ relation) (head : Head) (now : Int64) (keep : Nat) :
    Only (Allowed relation) (Reconcile.accept head now keep).run := by
  unfold Reconcile.accept
  refine Only.seq (Only.raise _ _ trivial) fun valid => ?_
  split
  · exact .done _
  · apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
    intro tx
    refine (auth_only relation _ (ReconciliationReadOnly.trustInstant_only tx now)).seq fun instant => ?_
    refine (auth_only relation _ (ReconciliationReadOnly.liveForKey_only tx head.signedBy instant)).seq fun live => ?_
    split
    · exact .done _
    · refine (record_only relation history tx head now).seq fun _ => ?_
      refine (read_only relation _ (ReconciliationReadOnly.readSlot_only tx _ "complete")).seq fun complete => ?_
      refine (read_only relation _ (ReconciliationReadOnly.readSlot_only tx _ "pending")).seq fun pending => ?_
      dsimp only
      split
      · exact (put_only relation heads history tx "pending" head now now).seq fun _ =>
          (trim_only relation history tx _ head.seq keep).seq fun _ => .done _
      · exact (trim_only relation history tx _ head.seq keep).seq fun _ => .done _

theorem accept_relation (relation : String) (heads : "heads" ≠ relation)
    (history : "head_history" ≠ relation) (head : Head) (now : Int64) (keep : Nat)
    (state : State) (closed : state.pending = none) :
    rows (execute (Reconcile.accept head now keep) state).2.db relation = rows state.db relation := by
  have held := (accept_only relation heads history head now keep).invariant
    (TableInvariant.Holds relation (rows state.db relation))
    (fun effect good current initial => effects relation _ effect good current initial)
    state (TableInvariant.closed relation state closed)
  exact held.1

theorem accept_payload (head : Head) (now : Int64) (keep : Nat)
    (state : State) (closed : state.pending = none) :
    MptsyncStableTail.PayloadFrame state.db (execute (Reconcile.accept head now keep) state).2.db := by
  exact ⟨accept_relation "entries" (by decide) (by decide) head now keep state closed,
    accept_relation "pins" (by decide) (by decide) head now keep state closed,
    accept_relation "content_want" (by decide) (by decide) head now keep state closed⟩

def RetireAllowed (relation : String) (A : Type) : Promote.Effects A → Prop
  | .left (.left effect) => TableInvariant.StorageAllowed relation effect
  | _ => False

theorem retire_effects (relation : String) (baseline : List Fields)
    (effect : Promote.Effects A) (safe : RetireAllowed relation _ effect) :
    TableInvariant.EffectSafe relation baseline effect := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => exact TableInvariant.storage_effect relation baseline effect safe
    | right _ => contradiction
  | right _ => contradiction

theorem retire_only (relation : String) (heads : "heads" ≠ relation)
    (pending : Promote.Pending) :
    Only (RetireAllowed relation) (Promote.retire pending).run := by
  unfold Promote.retire
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  exact Only.seq (Only.raise _ _ heads) fun _ => .done _

theorem retire_relation (relation : String) (heads : "heads" ≠ relation)
    (pending : Promote.Pending)
    (continuation rest : Program Promote.Effects (Except Promote.Error Unit))
    (reachable : Continuation (Promote.retire pending).run continuation)
    (state final : State) (closed : state.pending = none)
    (path : Prefix continuation state rest final) :
    rows final.db relation = rows state.db relation := by
  exact TableInvariant.prefix_rows relation (Promote.retire pending).run rest
    ((retire_only relation heads pending).mono
      (fun effect good baseline => retire_effects relation baseline effect good))
    reachable state final closed path

theorem retire_payload (pending : Promote.Pending)
    (continuation rest : Program Promote.Effects (Except Promote.Error Unit))
    (reachable : Continuation (Promote.retire pending).run continuation)
    (state final : State) (closed : state.pending = none)
    (path : Prefix continuation state rest final) :
    MptsyncStableTail.PayloadFrame state.db final.db := by
  have framed (relation : String) (heads : "heads" ≠ relation) :=
    retire_relation relation heads pending continuation rest reachable state final closed path
  exact ⟨framed "entries" (by decide), framed "pins" (by decide),
    framed "content_want" (by decide)⟩

def PromoteAllowed (relation : String) (A : Type) : Promote.Effects A → Prop
  | .left (.left effect) => TableInvariant.StorageAllowed relation effect
  | .left (.right (.right (.left effect))) => TableInvariant.AccessAllowed relation effect
  | _ => True

private theorem holds_of_db_pending (held : TableInvariant.Holds relation baseline state)
    (db : next.db = state.db) (pending : next.pending = state.pending) :
    TableInvariant.Holds relation baseline next := by
  constructor
  · rw [db]
    exact held.1
  · intro tx staged opened
    rw [pending] at opened
    exact held.2 tx staged opened

theorem promote_effects (relation : String) (baseline : List Fields)
    (effect : Promote.Effects A) (safe : PromoteAllowed relation _ effect) :
    TableInvariant.EffectSafe relation baseline effect := by
  intro state initial
  by_cases read : PromotionReads.allowed _ effect
  · exact holds_of_db_pending initial (PromotionReads.effects_db effect read state)
      (PromotionReads.effects_pending effect read state)
  cases effect with
  | left effect =>
    cases effect with
    | left effect => exact TableInvariant.storage_safe relation baseline effect safe state initial
    | right effect =>
      rcases effect with effect | effect
      · cases effect <;> contradiction
      · rcases effect with effect | effect
        · exact TableInvariant.access_safe relation baseline effect safe state initial
        · contradiction
  | right _ => contradiction

theorem promote_read_only (relation : String) (operation : Promote.Action A)
    (safe : Only PromotionReads.allowed operation.run) :
    Only (PromoteAllowed relation) operation.run := by
  apply safe.mono
  intro B effect good
  cases effect with
  | left effect =>
    cases effect with
    | left effect => cases effect <;> first | contradiction | trivial
    | right effect =>
      rcases effect with effect | effect
      · trivial
      · rcases effect with effect | effect
        · cases effect <;> first | contradiction | trivial
        · trivial
  | right _ => trivial

def SelectAllowed (relation : String) (A : Type) : Fetch.Effects A → Prop
  | .left effect => PromoteAllowed relation _ effect
  | .right _ => False

theorem select_effects (relation : String) (baseline : List Fields)
    (effect : Fetch.Effects A) (safe : SelectAllowed relation _ effect) :
    TableInvariant.EffectSafe relation baseline effect := by
  cases effect with
  | left effect => exact promote_effects relation baseline effect safe
  | right _ => contradiction

theorem select_only (relation : String) (origin : Origin.Parsed)
    (expected : Option (UInt64 × ByteArray)) :
    Only (SelectAllowed relation) (FetchLifecycle.select origin expected).run := by
  unfold FetchLifecycle.select Fetch.lift
  apply Only.within (target := SelectAllowed relation) (allowed := PromoteAllowed relation)
  · apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
    intro tx
    refine (promote_read_only relation _
      (PromotionReads.slot_only tx origin "pending")).seq fun pending => ?_
    cases pending with
    | none => exact .done _
    | some pending =>
      dsimp only
      split
      · exact .done _
      · refine Only.seq (Only.raise _ _ trivial) fun now => ?_
        refine (promote_read_only relation _ (PromotionReads.auth_only _
          (ReconciliationReadOnly.scope_only tx origin))).seq fun _ => ?_
        refine (promote_read_only relation _
          (PromotionReads.slot_only tx origin "complete")).seq fun _ => ?_
        exact (promote_read_only relation _ (PromotionReads.auth_only _
          (ReconciliationReadOnly.originAuthority_only tx origin now))).seq fun _ => .done _
  · intro B effect good
    rcases effect with effect | effect
    · rcases effect with effect | effect
      · cases effect <;> exact good
      · rcases effect with effect | effect
        · cases effect <;> exact good
        · rcases effect with effect | effect
          · cases effect <;> exact good
          · rcases effect with effect | effect
            · cases effect <;> exact good
            · rcases effect with effect | effect
              · cases effect <;> exact good
              · cases effect <;> exact good
    · cases effect <;> exact good

theorem select_payload (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
    (state : State) (closed : state.pending = none) : MptsyncStableTail.PayloadFrame state.db
      (execute (FetchLifecycle.select origin expected) state).2.db := by
  have framed (relation : String) :=
    (select_only relation origin expected).invariant
      (TableInvariant.Holds relation (rows state.db relation))
      (fun effect good current initial => select_effects relation _ effect good current initial)
      state (TableInvariant.closed relation state closed)
  exact ⟨(framed "entries").1, (framed "pins").1, (framed "content_want").1⟩

def OuterAllowed (relation : String) (A : Type) : Fetch.Effects A → Prop
  | .left effect => PromoteAllowed relation _ effect
  | .right _ => True

theorem outer_effects (relation : String) (baseline : List Fields)
    (effect : Fetch.Effects A) (safe : OuterAllowed relation _ effect) :
    TableInvariant.EffectSafe relation baseline effect := by
  intro state initial
  cases effect with
  | left effect => exact promote_effects relation baseline effect safe state initial
  | right effect =>
    cases effect <;> exact TableInvariant.reply_holds relation baseline state _ _ _
      (by intro s held; split <;> simp_all) initial

theorem trie_mapped (relation : String) (effect : Trie.Fetch.Effects A)
    (safe : FetchPayloadFrame.Allowed relation _ effect) :
    OuterAllowed relation _ (Inject.inject effect : Fetch.Effects A) := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => cases effect <;> exact safe
    | right effect =>
      cases effect with
      | left effect => cases effect <;> exact safe
      | right effect => cases effect; trivial
  | right effect =>
    cases effect with
    | left effect => cases effect <;> trivial
    | right effect =>
      cases effect with
      | left effect => cases effect <;> trivial
      | right effect => cases effect <;> trivial

theorem abandon_only (relation : String) (heads : "heads" ≠ relation)
    (target : Trie.Fetch.Target) : Only (OuterAllowed relation)
      (within Fetch.fetchError (Trie.Fetch.abandon target) : Fetch.Action Unit).run :=
  Only.within _ _ (FetchPayloadFrame.abandon_only relation heads target) (trie_mapped relation)

theorem abandon_relation (relation : String) (heads : "heads" ≠ relation)
    (target : Trie.Fetch.Target) (state : State) (closed : state.pending = none) :
    rows (execute (within Fetch.fetchError (Trie.Fetch.abandon target) : Fetch.Action Unit) state).2.db relation =
      rows state.db relation := by
  have held := (abandon_only relation heads target).invariant
    (TableInvariant.Holds relation (rows state.db relation))
    (fun effect good current initial => outer_effects relation _ effect good current initial)
    state (TableInvariant.closed relation state closed)
  exact held.1

theorem abandon_payload (target : Trie.Fetch.Target) (state : State)
    (closed : state.pending = none) : MptsyncStableTail.PayloadFrame state.db
      (execute (within Fetch.fetchError (Trie.Fetch.abandon target) : Fetch.Action Unit) state).2.db := by
  exact ⟨abandon_relation "entries" (by decide) target state closed,
    abandon_relation "pins" (by decide) target state closed,
    abandon_relation "content_want" (by decide) target state closed⟩

theorem scope_applies_only (relation : String) (origin : Origin.Parsed)
    (scope : Trie.Serve.Scope) :
    Only (OuterAllowed relation) (Fetch.scopeApplies origin scope).run := by
  unfold Fetch.scopeApplies Fetch.lift
  apply Only.within (target := OuterAllowed relation) (allowed := PromoteAllowed relation)
  · apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
    intro tx
    exact (promote_read_only relation _ (PromotionReads.auth_only _
      (ReconciliationReadOnly.scope_only tx origin))).seq fun _ => .done _
  · intro B effect good
    rcases effect with effect | effect
    · rcases effect with effect | effect
      · cases effect <;> exact good
      · rcases effect with effect | effect
        · cases effect <;> exact good
        · rcases effect with effect | effect
          · cases effect <;> exact good
          · rcases effect with effect | effect
            · cases effect <;> exact good
            · rcases effect with effect | effect
              · cases effect <;> exact good
              · cases effect <;> exact good
    · cases effect <;> exact good

theorem settle_without_publication_only (relation : String) (heads : "heads" ≠ relation)
    (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
    (scope : Trie.Serve.Scope) (target : Trie.Fetch.Target)
    (key : UInt64 × ByteArray × ByteArray) (result : Except Promote.Error Bool)
    (notComplete : result ≠ .ok true) :
    Only (OuterAllowed relation)
      (FetchLifecycle.settle origin refused scope target key result).run := by
  unfold FetchLifecycle.settle
  cases result with
  | ok answer => cases answer with
    | false =>
      exact (scope_applies_only relation origin scope).seq fun applies => by
        cases applies <;> first | exact .done _ |
          exact (abandon_only relation heads target).seq fun _ => .done _
    | true => exact False.elim (notComplete rfl)
  | error error =>
    cases error with
    | host _ => exact .done _
    | domain error =>
      dsimp only
      split
      · exact (scope_applies_only relation origin scope).seq fun applies => by
          cases applies <;> first | exact .done _ |
            exact (abandon_only relation heads target).seq fun _ => .done _
      · exact .done _

theorem settle_without_publication_payload
    (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
    (scope : Trie.Serve.Scope) (target : Trie.Fetch.Target)
    (key : UInt64 × ByteArray × ByteArray) (result : Except Promote.Error Bool)
    (notComplete : result ≠ .ok true) (state : State) (closed : state.pending = none) :
    MptsyncStableTail.PayloadFrame state.db
      (execute (FetchLifecycle.settle origin refused scope target key result) state).2.db := by
  have framed (relation : String) (heads : "heads" ≠ relation) :=
    (settle_without_publication_only relation heads origin refused scope target key result
      notComplete).invariant (TableInvariant.Holds relation (rows state.db relation))
      (fun effect good current initial => outer_effects relation _ effect good current initial)
      state (TableInvariant.closed relation state closed)
  exact ⟨(framed "entries" (by decide)).1, (framed "pins" (by decide)).1,
    (framed "content_want" (by decide)).1⟩

def NonPublishing : ReconciliationExecution.Event → Prop
  | .promotion .. => False
  | .settlement _ _ _ _ _ (.ok true) => False
  | _ => True

/-- Every actual non-publication reconciliation step has a raw payload frame.
This covers failures and arbitrary requester/retirement resumptions. -/
theorem step_payload (step : ReconciliationExecution.Step event state final)
    (nonPublishing : NonPublishing event) :
    MptsyncStableTail.PayloadFrame state.db final.db := by
  cases step with
  | advertisement head now keep state closed =>
    exact accept_payload head now keep state closed
  | promotion => contradiction
  | request target reference maximum retryLimit continuation rest reachable state final closed path =>
    exact FetchPayloadFrame.request_payload target reference maximum retryLimit continuation rest
      reachable state final closed path
  | retirement pending continuation rest reachable state final closed path =>
    exact retire_payload pending continuation rest reachable state final closed path
  | selection origin expected state closed => exact select_payload origin expected state closed
  | abandonment target state closed => exact abandon_payload target state closed
  | settlement origin refused scope target key result state closed =>
    apply settle_without_publication_payload origin refused scope target key result _ state closed
    cases result with
    | error _ => simp
    | ok answer => cases answer <;> simp_all [NonPublishing]

end Synchronicity.ReconciliationPayloadFrame
