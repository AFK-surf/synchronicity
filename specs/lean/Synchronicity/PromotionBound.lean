import Synchronicity.HeadInvariant
import Synchronicity.PromotionReads
import Synchronicity.OperationExecution

/-! An independent complete-version floor on raw heads rows. Promotion may
replace that version, but only with a strictly newer pointer. -/
namespace Synchronicity.PromotionBound
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase
open ReconciliationSlots (names pointsTo)

def atLeast (floor : History.Pointer) (row : Fields) : Prop :=
  ∃ seq root, cell row "seq" = .integer (UInt64.toInt64 seq) ∧ cell row "root" = .blob root ∧
    ((seq = floor.seq ∧ root = floor.root) ∨ Reconcile.newer seq root floor = true)

def good (origin : String) (floor : History.Pointer) (table : List Fields) : Prop :=
  (∃ row ∈ table, names row origin "complete" = true) ∧
    ∀ row ∈ table, names row origin "complete" = true → atLeast floor row

theorem stored_good (db : Database) (origin : String) (seq : Int64) (root : ByteArray)
    (stored : ReconciliationRead.StoredFloor db origin "complete" seq root) :
    good origin ⟨seq.toUInt64, root⟩ (rows db "heads") := by
  obtain ⟨row, member, named, _⟩ := stored.backed
  refine ⟨⟨row, member, named⟩, ?_⟩
  intro row member named
  obtain ⟨sequence, hash⟩ := stored.pointer row member named
  exact ⟨seq.toUInt64, root, sequence, hash, Or.inl ⟨rfl, rfl⟩⟩

theorem complete_not_pending (row : Fields) (origin : String)
    (complete : names row origin "complete" = true) (pendingOrigin : String) :
    equals row [("origin_id", .text pendingOrigin), ("slot", .text "pending")] = false := by
  simp only [names, equals, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] at complete
  obtain ⟨_, complete⟩ := complete
  have different : isCell (cell row "slot") (.text "pending") = false := by
    cases value : cell row "slot" <;> simp_all [isCell, equalCell, BEq.beq, instBEqCell.beq]
    rename_i bytes originMatched
    have same : bytes = "complete".toUTF8 := eq_of_beq complete
    subst bytes
    decide
  simp [equals, different]

theorem delete_pending_good (origin : String) (floor : History.Pointer) (db : Database)
    (fields : Fields) (onlyPending : ∀ row, names row origin "complete" = true → equals row fields = false)
    (blockers : List Exclusion) (bounds : Fields) (initial : good origin floor (rows db "heads")) :
    good origin floor ((rows db "heads").filter fun row => !deletable db fields blockers bounds row) := by
  constructor
  · obtain ⟨row, member, named⟩ := initial.1
    exact ⟨row, List.mem_filter.mpr ⟨member, by simp [deletable, onlyPending row named]⟩, named⟩
  · intro row member named
    exact initial.2 row (List.mem_filter.mp member).1 named

theorem upsert_complete_good (origin : String) (floor : History.Pointer) (head : Head)
    (sameOrigin : Origin.canonical head.origin = origin) (newer : Reconcile.newer head.seq head.root floor = true)
    (received verified : Int64) (table : List Fields) :
    good origin floor (upsertRows table (ReconciliationSlots.incoming head "complete" received verified)
      ["origin_id", "slot"] ((ReconciliationSlots.updates "complete").map fun column => (column, .excluded column))) := by
  subst origin
  obtain ⟨row, member, named, _⟩ := ReconciliationSlots.upsert_candidate_exists table head "complete" received verified
  refine ⟨⟨row, member, named⟩, ?_⟩
  intro row member named
  obtain ⟨sequence, hash⟩ := ReconciliationSlots.upsert_installs_candidate table head "complete" received verified row member named
  exact ⟨head.seq, head.root, sequence, hash, Or.inr newer⟩

def safe (origin : String) (floor : History.Pointer) := HeadInvariant.effectSafe (E := Promote.Effects) (good origin floor)

theorem read_safe (origin : String) (floor : History.Pointer) (effect : Promote.Effects A)
    (read : PromotionReads.allowed _ effect) : safe origin floor _ effect := by
  intro state initial
  apply HeadInvariant.unchanged _ state _ _ _ initial
  · rw [PromotionReads.effects_db effect read state]
  · unfold ReconciliationFrame.heads
    rw [PromotionReads.effects_pending effect read state]

theorem reads_only (origin : String) (floor : History.Pointer) (operation : Promote.Action A)
    (read : Only PromotionReads.allowed operation.run) : Only (safe origin floor) operation.run :=
  read.mono (read_safe origin floor)

theorem storage_frame_safe (origin : String) (floor : History.Pointer) (effect : Storage A)
    (frame : ReconciliationFrame.storageAllowed effect) : safe origin floor _ (Inject.inject effect) := by
  intro state initial
  apply HeadInvariant.unchanged _ state _ _ (ReconciliationFrame.storage_frame effect frame state) initial
  have privateEffect : storagePrivate effect := by cases effect <;> first | contradiction | trivial
  rw [storage_preserves_db effect privateEffect state]

theorem clear_only (origin : Origin.Parsed) (floor : History.Pointer) (tx : Transaction) :
    Only (safe (Origin.canonical origin) floor) (Promote.clear tx origin).run := by
  unfold Promote.clear
  refine Only.seq (Only.raise _ _ ?_) fun _ => .done _
  intro state initial
  apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
  intro s h
  apply HeadInvariant.transaction_holds _ _ _ _ _ h
  intro db prior
  rw [rows_setRows]
  exact delete_pending_good _ _ db _ (fun row named => complete_not_pending row _ named _) _ _ prior

theorem history_frame_only (origin : String) (floor : History.Pointer) (operation : History.Action A)
    (frame : Only ReconciliationFrame.allowed operation.run) :
    Only (safe origin floor) (Promote.history operation).run := by
  apply Only.within _ _ frame
  intro B effect good
  cases effect with
  | left effect => exact storage_frame_safe origin floor effect good
  | right effect =>
    intro state initial
    cases effect <;> apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;> intro s h <;> exact h

theorem putSlot_only (origin : Origin.Parsed) (floor : History.Pointer) (tx : Transaction)
    (head : Head) (sameOrigin : head.origin = origin) (newer : Reconcile.newer head.seq head.root floor = true)
    (received verified : Int64) :
    Only (safe (Origin.canonical origin) floor) (Promote.history (Reconcile.putSlot tx "complete" head received verified)).run := by
  unfold Promote.history Reconcile.putSlot
  apply Only.within (allowed := fun A effect => HeadInvariant.effectSafe (E := History.Effects) (good (Origin.canonical origin) floor) A effect)
  · apply Only.seq
    · apply (ReconciliationFrame.record_only tx head received).mono
      intro B effect frame
      cases effect with
      | left effect =>
        exact storage_frame_safe (Origin.canonical origin) floor effect frame
      | right effect =>
        intro state initial
        cases effect <;> apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;> intro s h <;> exact h
    · intro _
      apply Only.raise
      intro state initial
      apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
      intro s h
      apply HeadInvariant.transaction_holds _ _ _ _ _ h
      intro db _
      rw [rows_setRows]
      exact upsert_complete_good _ floor head (congrArg Origin.canonical sameOrigin) newer received verified _
  · intro B effect good
    cases effect <;> exact good

theorem materialize_only (origin : Origin.Parsed) (floor : History.Pointer) (tx : Transaction)
    (oldRoot newRoot : ByteArray) :
    Only (safe (Origin.canonical origin) floor)
      (within Promote.materializeError (Materialize.materialize tx origin oldRoot newRoot) : Promote.Action _).run := by
  apply Only.within _ _ (MaterializationPrivate.materialize_private tx origin oldRoot newRoot)
  intro B effect good state initial
  rw [PromotionReads.materialize_agrees]
  exact HeadInvariant.materialize_effect _ effect good state initial

/-- Even partially executed promotion preserves the complete-version floor.
Its candidate is allowed to replace complete only after the actual guard; the
materializer cannot subsequently alter heads. -/
theorem body_only (origin : Origin.Parsed) (floor : History.Pointer) (tx : Transaction) (now : Int64)
    (pending previous : Promote.Pending) (sameOrigin : pending.head.origin = origin)
    (previousPointer : (⟨previous.head.seq, previous.head.root⟩ : History.Pointer) = floor)
    (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority) :
    Only (safe (Origin.canonical origin) floor)
      (Promote.body tx origin now pending (some previous) scope authority).run := by
  unfold Promote.body
  split
  · exact (clear_only origin floor tx).seq fun _ => .done _
  · rename_i greater
    have newer : Reconcile.newer pending.head.seq pending.head.root floor = true := by
      simpa [Option.any, previousPointer] using greater
    refine Only.seq (reads_only _ _ _ (PromotionReads.complete_only tx _ _)) fun complete => ?_
    split
    · exact .done _
    · have tail (permitted : Bool) : Only (safe (Origin.canonical origin) floor)
          (do
            if !permitted then
              Promote.clear tx origin
              return Promotion.refused
            Promote.history (Reconcile.putSlot tx "complete" pending.head pending.received now)
            Promote.clear tx origin
            let _ ← within Promote.materializeError (Materialize.materialize tx origin previous.head.root pending.head.root)
            return Promotion.flipped : Promote.Action Promotion).run := by
        split
        · exact (clear_only origin floor tx).seq fun _ => .done _
        · refine (putSlot_only origin floor tx pending.head sameOrigin newer pending.received now).seq fun _ => ?_
          refine (clear_only origin floor tx).seq fun _ => ?_
          exact (materialize_only origin floor tx previous.head.root pending.head.root).seq fun _ => .done _
      cases authority.publication with
      | untrusted => exact Only.seq (.done _) tail
      | unrestricted => exact Only.seq (.done _) tail
      | confined _ => exact (Only.map _ _ (reads_only _ _ _ (PromotionReads.scopeCheck_only tx _ _))).seq tail

theorem retire_only (origin : String) (floor : History.Pointer) (pending : Promote.Pending) :
    Only (safe origin floor) (Promote.retire pending).run := by
  unfold Promote.retire
  apply Only.transaction
  · exact HeadInvariant.begin_holds (good origin floor)
  · intro tx; exact HeadInvariant.commit_holds (good origin floor) tx
  · intro tx; exact HeadInvariant.rollback_holds (good origin floor) tx
  · intro tx
    refine Only.seq (Only.raise _ _ ?_) fun _ => .done _
    intro state initial
    apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
    intro s h
    apply HeadInvariant.transaction_holds _ _ _ _ _ h
    intro db prior
    rw [rows_setRows]
    apply delete_pending_good _ _ db _ _ _ _ prior
    intro row named
    have unmatched := complete_not_pending row origin named (Origin.canonical pending.head.origin)
    simp only [equals, List.all_cons, List.all_nil, Bool.and_true] at unmatched ⊢
    simp only [Reconcile.headKey, List.cons_append, List.nil_append]
    simp only [List.all_cons, List.all_nil, Bool.and_true]
    cases originMatch : isCell (cell row "origin_id") (.text (Origin.canonical pending.head.origin)) <;>
      simp_all

theorem finish_only (origin : String) (floor : History.Pointer) (tx : Transaction)
    (pending : Option Promote.Pending) (key : Option (UInt64 × ByteArray × ByteArray))
    (result : Except Promote.Error Promotion) :
    Only (safe origin floor) (Promote.finish tx pending key result).run := by
  unfold Promote.finish
  cases result with
  | ok promotion =>
    refine Only.seq ?_ fun result => ?_
    · exact Only.bind (Only.raise Promote.Error.host (Storage.commit tx)
        (HeadInvariant.commit_holds (good origin floor) tx)) fun _ => .done _
    · cases result with
      | ok valueUnit => cases valueUnit; exact .done _
      | error _ =>
        exact Only.seq (Only.bind (Only.raise Promote.Error.host (Storage.rollback tx)
          (HeadInvariant.rollback_holds (good origin floor) tx)) fun _ => .done _) fun _ => .done _
  | error error =>
    refine Only.seq ?_ fun _ => ?_
    · exact Only.bind (Only.raise Promote.Error.host (Storage.rollback tx)
        (HeadInvariant.rollback_holds (good origin floor) tx)) fun _ => .done _
    · cases error with
      | host _ => exact .done _
      | domain failure =>
        repeat' first
          | exact .done _
          | (refine Only.seq (retire_only origin floor _) fun _ => .done _)
          | split

end Synchronicity.PromotionBound
