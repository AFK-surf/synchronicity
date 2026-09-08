import VerifiedCore.Replication.Promote
import Synchronicity.ReconciliationRead
import Synchronicity.ReconciliationReadOnly
import Synchronicity.TrieReadEffects
import Synchronicity.OperationExecution

/-! Promotion's preparation and readiness checks cannot change the snapshot
whose pending/complete pointers are compared. These are the actual commands. -/
namespace Synchronicity.PromotionReads
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def materializeRead (A : Type) : Materialize.Effects A → Prop
  | .left effect => ReconciliationReadOnly.storageAllowed effect
  | .right (.right (.left effect)) => TrieReadEffects.accessRead effect
  | _ => True

def allowed (A : Type) : Promote.Effects A → Prop
  | .left effect => materializeRead _ effect
  | .right _ => True

theorem materialize_pending (effect : Materialize.Effects A) (safe : materializeRead _ effect) (state : State) :
    (Interpreter.handle effect state).2.pending = state.pending := by
  cases effect with
  | left effect =>
    apply ReconciliationReadOnly.storage_pending effect _ state
    cases effect <;> first | contradiction | trivial
  | right effect =>
    rcases effect with effect | effect
    · cases effect <;> apply ReconciliationReadOnly.reply_pending <;> intro s <;> rfl
    · rcases effect with effect | effect
      · cases effect <;> first
          | contradiction
          | (apply ReconciliationReadOnly.reply_pending; intro s; rfl)
      · rcases effect with effect | effect
        · cases effect; apply ReconciliationReadOnly.reply_pending; intro s; rfl
        · rcases effect with effect | effect
          · cases effect; apply ReconciliationReadOnly.reply_pending; intro s; rfl
          · rcases effect with effect | effect
            · cases effect; apply ReconciliationReadOnly.reply_pending; intro s; rfl
            · cases effect; apply ReconciliationReadOnly.reply_pending; intro s; rfl

theorem effects_pending (effect : Promote.Effects A) (safe : allowed _ effect) (state : State) :
    (Interpreter.handle effect state).2.pending = state.pending := by
  cases effect with
  | left effect => exact materialize_pending effect safe state
  | right effect => cases effect <;> apply ReconciliationReadOnly.reply_pending <;> intro s <;> rfl

theorem effects_db (effect : Promote.Effects A) (safe : allowed _ effect) (state : State) :
    (Interpreter.handle effect state).2.db = state.db := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect =>
      apply storage_preserves_db effect _ state
      cases effect <;> first | contradiction | trivial
    | right effect =>
      rcases effect with effect | effect
      · cases effect <;> apply reply_preserves_db <;> intro s <;> rfl
      · rcases effect with effect | effect
        · cases effect <;> first | contradiction | (apply reply_preserves_db; intro s; rfl)
        · rcases effect with effect | effect
          · cases effect; apply reply_preserves_db; intro s; rfl
          · rcases effect with effect | effect
            · cases effect; apply reply_preserves_db; intro s; rfl
            · rcases effect with effect | effect
              · cases effect; apply reply_preserves_db; intro s; rfl
              · cases effect; apply reply_preserves_db; intro s; rfl
  | right effect => cases effect <;> apply reply_preserves_db <;> intro s <;> rfl

theorem history_only (operation : History.Action A) (safe : Only ReconciliationReadOnly.allowed operation.run) :
    Only allowed (Promote.history operation).run := by
  apply Only.within _ _ safe
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem auth_only (operation : Authorization.Action A) (safe : Only ReconciliationReadOnly.allowed operation.run) :
    Only allowed (Promote.auth operation).run := by
  apply Only.within _ _ safe
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem slot_only (tx : Transaction) (origin : Origin.Parsed) (name : String) :
    Only allowed (Promote.slot tx origin name).run := by
  unfold Promote.slot
  refine Only.seq (Only.raise _ _ trivial) fun scan => ?_
  repeat' first
    | exact .done _
    | (refine Only.seq (history_only _ (ReconciliationReadOnly.decodeJoinedHead_only _)) fun _ => ?_)
    | split

theorem executed_pending (operation : Promote.Action A) (safe : Only allowed operation.run)
    (state final : State) (answer : A) (executed : execute operation state = (.ok answer, final)) :
    final.pending = state.pending := by
  have kept := safe.preserves_observation State.pending _ effects_pending state
  change (execute operation state).2.pending = state.pending at kept
  simpa only [executed] using kept

theorem complete_mapped (tx : Transaction) (effect : Trie.Complete.Effects A)
    (safe : TrieReadEffects.completeRead _ effect) : allowed _ (Promote.inTransaction tx effect) := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => cases effect <;> first | contradiction | trivial
    | right effect =>
      cases effect with
      | left effect =>
        cases effect <;> first | contradiction | trivial | (simp only [Promote.inTransaction]; split <;> trivial)
      | right effect => cases effect; trivial
  | right effect => cases effect <;> trivial

def complete (tx : Transaction) (context : Trie.Missing.Context) (root : ByteArray) : Promote.Action Bool :=
  ExceptT.mk ((Trie.Complete.isComplete (Std.HashSet Trie.Missing.Visit) (Std.HashSet ByteArray)
    context root).run.mapEffects (Promote.inTransaction tx) |> fun program => Except.mapError Promote.missingError <$> program)

theorem complete_only (tx : Transaction) (context : Trie.Missing.Context) (root : ByteArray) :
    Only allowed (complete tx context root).run := by
  exact ((TrieReadEffects.isComplete _ _ context root).mapEffects _ (Promote.inTransaction tx)
    (complete_mapped tx)).bind fun _ => .done _

def scopeCheck (tx : Transaction) (root : ByteArray) (scope : Trie.Serve.Scope) : Promote.Action (Option ByteArray) :=
  within Promote.walkError (ExceptT.mk
    ((Trie.ScopeCheck.firstOutside root scope).run.mapEffects
      (fun {A} (effect : Trie.Walk.Effects A) => match effect with
        | .left e => Inject.inject e
        | .right e => Inject.inject (Materialize.redactionIn tx e)) : Program Materialize.Effects _))

theorem scopeCheck_only (tx : Transaction) (root : ByteArray) (scope : Trie.Serve.Scope) :
    Only allowed (scopeCheck tx root scope).run := by
  apply Only.within (target := allowed) (allowed := materializeRead)
  · apply (TrieReadEffects.firstOutside root scope).mapEffects
    intro B effect good
    cases effect with
    | left effect => cases effect <;> first | contradiction | trivial
    | right effect => cases effect; trivial
  · intro B effect good
    cases effect with
    | left _ => exact good
    | right effect =>
      rcases effect with effect | effect
      · exact good
      · rcases effect with effect | effect
        · exact good
        · rcases effect with effect | effect
          · exact good
          · rcases effect with effect | effect
            · exact good
            · cases effect <;> exact good

theorem scan_rows (tx : Transaction) (db : Database) (state : State)
    (opened : state.pending = some (tx, db)) (origin : Origin.Parsed) (name : String) (scan : Scan)
    (succeeded : (execute (Promote.raw (.scanRows tx "heads" History.headColumns
      [("origin_id", .text (Origin.canonical origin)), ("slot", .text name)] [] History.headJoin)) state).1 = .ok scan) :
    scan.rows = query db "heads" History.headColumns
      [("origin_id", .text (Origin.canonical origin)), ("slot", .text name)] [] History.headJoin := by
  change ((storage (.scanRows tx "heads" History.headColumns
    [("origin_id", .text (Origin.canonical origin)), ("slot", .text name)] [] History.headJoin) state).1.mapError
      Promote.Error.host) = .ok scan at succeeded
  simp only [storage, reply] at succeeded
  split at succeeded
  · cases succeeded
  · simp only [SimulatedHost.transaction, opened, beq_self_eq_true, ↓reduceIte, Except.mapError] at succeeded
    cases succeeded
    rfl

theorem history_agrees (effect : History.Effects A) (state : State) :
    Interpreter.handle (Inject.inject effect : Promote.Effects A) state = Interpreter.handle effect state := by
  cases effect <;> rfl

theorem materialize_agrees (effect : Materialize.Effects A) (state : State) :
    Interpreter.handle (Inject.inject effect : Promote.Effects A) state = Interpreter.handle effect state := by
  cases effect with
  | left _ => rfl
  | right effect =>
    rcases effect with effect | effect
    · rfl
    · rcases effect with effect | effect
      · rfl
      · rcases effect with effect | effect
        · rfl
        · rcases effect with effect | effect
          · rfl
          · cases effect <;> rfl

theorem slot_origin (tx : Transaction) (origin : Origin.Parsed) (name : String)
    (state : State) (pending : Promote.Pending)
    (succeeded : (execute (Promote.slot tx origin name) state).1 = .ok (some pending)) :
    pending.head.origin = origin := by
  unfold Promote.slot at succeeded
  obtain ⟨scan, _, _, succeeded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ succeeded
  split at succeeded
  · split at succeeded <;> cases succeeded
  · obtain ⟨fields, _, _, succeeded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ succeeded
    split at succeeded
    · have same := Option.some.inj (Except.ok.inj succeeded)
      subst pending
      rfl
    · cases succeeded

theorem slot_floor (tx : Transaction) (origin : Origin.Parsed) (name : String)
    (state : State) (db : Database) (opened : state.pending = some (tx, db))
    (seq : Int64) (root : ByteArray)
    (stored : ReconciliationRead.StoredFloor db (Origin.canonical origin) name seq root)
    (result : Option Promote.Pending)
    (succeeded : (execute (Promote.slot tx origin name) state).1 = .ok result) :
    ∃ pending, result = some pending ∧ pending.head.seq = seq.toUInt64 ∧ pending.head.root = root := by
  unfold Promote.slot at succeeded
  obtain ⟨scan, middle, scanned, succeeded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ succeeded
  have queried := scan_rows tx db state opened origin name scan (congrArg Prod.fst scanned)
  obtain ⟨nonempty, pointers⟩ := ReconciliationRead.query_has_floor db (Origin.canonical origin) name seq root stored
  rw [← queried] at nonempty pointers
  split at succeeded
  · rename_i empty
    exact False.elim (nonempty empty)
  · rename_i row rest nonemptyRows
    obtain ⟨fields, next, decoded, succeeded⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ succeeded
    have rawDecoded := OperationExecution.within_success history_agrees Promote.historyError
      (History.decodeJoinedHead row) middle next fields decoded
    have shape : ReconciliationRead.pointerProjection row seq root := by
      apply pointers
      rw [nonemptyRows]
      exact List.mem_cons_self
    have pointer := ReconciliationRead.decoded_head_pointer row seq root shape middle fields (congrArg Prod.fst rawDecoded)
    split at succeeded
    · refine ⟨_, (Except.ok.inj succeeded).symm, congrArg History.Pointer.seq pointer, congrArg History.Pointer.root pointer⟩
    · cases succeeded

end Synchronicity.PromotionReads
