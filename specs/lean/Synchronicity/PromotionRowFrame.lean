import Synchronicity.PromotionKeyFrame

namespace Synchronicity.PromotionRowFrame
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def safe (row : Fields) := HeadInvariant.effectSafe (E := Promote.Effects) (fun table => row ∈ table)

theorem read_only (row : Fields) (operation : Promote.Action A)
    (read : Only PromotionReads.allowed operation.run) : Only (safe row) operation.run := by
  apply read.mono
  intro B effect good state initial
  apply HeadInvariant.unchanged _ state _ _ _ initial
  · rw [PromotionReads.effects_db effect good state]
  · unfold ReconciliationFrame.heads
    rw [PromotionReads.effects_pending effect good state]

theorem clear_only (row : Fields) (tx : Transaction) (origin : Origin.Parsed)
    (different : isCell (cell row "origin_id") (.text (Origin.canonical origin)) = false) :
    Only (safe row) (Promote.clear tx origin).run := by
  apply Only.seq (Only.raise _ _ ?_) fun _ => .done _
  exact ProtectedHead.storage_retains row _ (Or.inr (by simp [equals, different]))

theorem retire_only (row : Fields) (pending : Promote.Pending)
    (different : isCell (cell row "origin_id") (.text (Origin.canonical pending.head.origin)) = false) :
    Only (safe row) (Promote.retire pending).run := by
  unfold Promote.retire
  apply Only.transaction _ _ _ (HeadInvariant.begin_holds _) (HeadInvariant.commit_holds _) (HeadInvariant.rollback_holds _)
  intro tx
  exact Only.seq (Only.raise _ _ (ProtectedHead.storage_retains row _
    (Or.inr (by simp [equals, Reconcile.headKey, different])))) fun _ => .done _

theorem write_only (row : Fields) (tx : Transaction) (head : Head) (received verified : Int64)
    (different : isCell (cell row "origin_id") (.text (Origin.canonical head.origin)) = false) :
    Only (safe row) (Promote.history (Reconcile.putSlot tx "complete" head received verified)).run := by
  unfold Promote.history Reconcile.putSlot
  apply Only.within (allowed := fun A effect => HeadInvariant.effectSafe (E := History.Effects) (fun table => row ∈ table) A effect)
  · apply Only.seq
    · apply (ReconciliationFrame.record_only tx head received).mono
      intro B effect frame state initial
      cases effect with
      | left effect =>
        apply ProtectedHead.storage_retains row effect _ state initial
        cases effect <;> first | exact Or.inl frame | exact frame | contradiction | trivial
      | right effect => cases effect <;> apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;> intro s h <;> exact h
    · intro _
      apply Only.raise
      apply ProtectedHead.storage_retains row _
      apply Or.inr
      change conflict ["origin_id", "slot"] (ReconciliationSlots.incoming head "complete" received verified) row = false
      rw [ReconciliationSlots.conflicts_iff_names]
      simp [ReconciliationSlots.names, equals, different]
  · intro B effect good
    cases effect <;> exact good

theorem materialize_only (row : Fields) (tx : Transaction) (origin : Origin.Parsed) (oldRoot newRoot : ByteArray) :
    Only (safe row) (within Promote.materializeError (Materialize.materialize tx origin oldRoot newRoot) : Promote.Action _).run := by
  apply Only.within _ _ (MaterializationPrivate.materialize_private tx origin oldRoot newRoot)
  intro B effect good state initial
  rw [PromotionReads.materialize_agrees]
  exact HeadInvariant.materialize_effect _ effect good state initial

theorem publish_only (row : Fields) (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (pending old : Option Promote.Pending) (sameOrigin : ∀ candidate, pending = some candidate → candidate.head.origin = origin)
    (different : isCell (cell row "origin_id") (.text (Origin.canonical origin)) = false) :
    Only (safe row) (PromotionExecution.publish tx origin now refused (scope, authority, pending, old)).run := by
  apply PromotionCertificates.publish_only _ _ _ _ _ _ _ _ _ (clear_only row tx origin different)
  · intro candidate selected
    apply PromotionCertificates.body_only _ _ _ _ _ _ _ _ (clear_only row tx origin different) (read_only row)
    · apply write_only
      rwa [sameOrigin candidate selected]
    · exact materialize_only row tx origin _ _
  · intro key result
    apply PromotionCertificates.finish_only _ tx pending key result
      (HeadInvariant.commit_holds _ tx) (HeadInvariant.rollback_holds _ tx)
    intro candidate selected
    apply retire_only
    rwa [sameOrigin candidate selected]

/-- Promotion has no authority to change a row belonging to another origin. -/
theorem other_origin_retained (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
    (state : State) (row : Fields) (present : row ∈ rows state.db "heads")
    (different : isCell (cell row "origin_id") (.text (Origin.canonical origin)) = false) :
    row ∈ rows (execute (Promote.promote origin now refused) state).2.db "heads" := by
  rcases PromotionExecution.outcome origin now refused state with unchanged | ⟨prepared, executed⟩
  · rwa [unchanged]
  · obtain ⟨tx, opened, ready, ⟨scope, authority, pending, old⟩, began, read, snapshot, committed⟩ := prepared
    have sameOrigin := PromotionExecution.prepare_origin tx origin now opened ready scope authority pending old read
    have allowed := publish_only row tx origin now refused scope authority pending old sameOrigin different
    have initial : HeadInvariant.holds (fun table => row ∈ table) ready := by
      constructor
      · rwa [committed]
      · intro next staged same
        rw [snapshot] at same
        have same : tx = next ∧ state.db = staged := by simpa using same
        rwa [← same.2]
    have final := allowed.invariant (HeadInvariant.holds (fun table => row ∈ table)) (fun _ good => good) ready initial
    rw [executed]
    exact final.1

end Synchronicity.PromotionRowFrame
