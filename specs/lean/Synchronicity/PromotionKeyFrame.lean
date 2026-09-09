import Synchronicity.PromotionCertificates

namespace Synchronicity.PromotionKeyFrame
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost PrivateDatabase

def safe (predicate : List Cell → Prop) := HeadInvariant.effectSafe (E := Promote.Effects) (HeadKeyFrame.allKeys predicate)

theorem read_only (predicate : List Cell → Prop) (operation : Promote.Action A)
    (read : Only PromotionReads.allowed operation.run) : Only (safe predicate) operation.run := by
  apply read.mono
  intro B effect good state initial
  apply HeadInvariant.unchanged _ state _ _ _ initial
  · rw [PromotionReads.effects_db effect good state]
  · unfold ReconciliationFrame.heads
    rw [PromotionReads.effects_pending effect good state]

theorem clear_only (predicate : List Cell → Prop) (tx : Transaction) (origin : Origin.Parsed) :
    Only (safe predicate) (Promote.clear tx origin).run :=
  Only.seq (Only.raise _ _ (HeadKeyFrame.storage_safe predicate _ trivial)) fun _ => .done _

theorem retire_only (predicate : List Cell → Prop) (pending : Promote.Pending) :
    Only (safe predicate) (Promote.retire pending).run := by
  unfold Promote.retire
  apply Only.transaction _ _ _ (HeadInvariant.begin_holds _) (HeadInvariant.commit_holds _) (HeadInvariant.rollback_holds _)
  intro tx
  exact Only.seq (Only.raise _ _ (HeadKeyFrame.storage_safe predicate _ trivial)) fun _ => .done _

theorem upsert_complete (predicate : List Cell → Prop) (head : Head) (received verified : Int64)
    (accepts : ∀ row, ReconciliationSlots.names row (Origin.canonical head.origin) "complete" = true →
      ReconciliationSlots.pointsTo row head → predicate (HeadKeyFrame.key row))
    (table : List Fields) (initial : HeadKeyFrame.allKeys predicate table) :
    HeadKeyFrame.allKeys predicate (upsertRows table (ReconciliationSlots.incoming head "complete" received verified)
      ["origin_id", "slot"] ((ReconciliationSlots.updates "complete").map fun column => (column, .excluded column))) := by
  intro row member
  unfold upsertRows at member
  split at member
  · obtain ⟨old, priorMember, changed⟩ := List.mem_map.mp member
    split at changed
    · rename_i conflict
      subst row
      apply accepts
      · simp only [List.map_map, Function.comp_def]
        rw [ReconciliationSlots.assigned_names]
        exact (ReconciliationSlots.conflicts_iff_names head "complete" received verified old) ▸ conflict
      · simpa only [List.map_map, Function.comp_def] using
          ReconciliationSlots.assigned_points_to head "complete" received verified old
    · subst row
      exact initial old priorMember
  · rcases List.mem_append.mp member with old | new
    · exact initial row old
    · have same := List.mem_singleton.mp new
      subst row
      apply accepts
      · simp [ReconciliationSlots.names, ReconciliationSlots.incoming, Reconcile.headKey, equals, cell, equalCell]
      · simp [ReconciliationSlots.pointsTo, ReconciliationSlots.incoming, Reconcile.headKey, cell]

theorem write_only (predicate : List Cell → Prop) (tx : Transaction) (head : Head) (received verified : Int64)
    (accepts : ∀ row, ReconciliationSlots.names row (Origin.canonical head.origin) "complete" = true →
      ReconciliationSlots.pointsTo row head → predicate (HeadKeyFrame.key row)) :
    Only (safe predicate) (Promote.history (Reconcile.putSlot tx "complete" head received verified)).run := by
  unfold Promote.history Reconcile.putSlot
  apply Only.within (allowed := fun A effect => HeadInvariant.effectSafe (E := History.Effects) (HeadKeyFrame.allKeys predicate) A effect)
  · apply Only.seq
    · apply (ReconciliationFrame.record_only tx head received).mono
      intro B effect frame state initial
      cases effect with
      | left effect =>
        apply HeadKeyFrame.storage_safe predicate effect _ state initial
        cases effect <;> first | exact frame | contradiction | trivial
      | right effect => cases effect <;> apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;> intro s h <;> exact h
    · intro _
      apply Only.raise
      intro state initial
      apply HeadInvariant.reply_holds _ _ _ _ _ _ initial
      intro s h
      apply HeadInvariant.transaction_holds _ _ _ _ _ h
      intro db prior
      rw [rows_setRows]
      exact upsert_complete predicate head received verified accepts _ prior
  · intro B effect good
    cases effect <;> exact good

theorem materialize_only (predicate : List Cell → Prop) (tx : Transaction) (origin : Origin.Parsed)
    (oldRoot newRoot : ByteArray) :
    Only (safe predicate) (within Promote.materializeError (Materialize.materialize tx origin oldRoot newRoot) : Promote.Action _).run := by
  apply Only.within _ _ (MaterializationPrivate.materialize_private tx origin oldRoot newRoot)
  intro B effect good state initial
  rw [PromotionReads.materialize_agrees]
  exact HeadInvariant.materialize_effect _ effect good state initial

theorem publish_only (predicate : List Cell → Prop) (tx : Transaction) (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (scope : Trie.Serve.Scope) (authority : Authorization.OriginAuthority)
    (pending old : Option Promote.Pending) (sameOrigin : ∀ candidate, pending = some candidate → candidate.head.origin = origin)
    (accepts : ∀ candidate, pending = some candidate → ∀ row,
      ReconciliationSlots.names row (Origin.canonical origin) "complete" = true →
      ReconciliationSlots.pointsTo row candidate.head → predicate (HeadKeyFrame.key row)) :
    Only (safe predicate) (PromotionExecution.publish tx origin now refused (scope, authority, pending, old)).run := by
  apply PromotionCertificates.publish_only _ _ _ _ _ _ _ _ _ (clear_only predicate tx origin)
  · intro candidate selected
    apply PromotionCertificates.body_only _ _ _ _ _ _ _ _ (clear_only predicate tx origin) (read_only predicate)
    · apply write_only
      intro row named points
      exact accepts candidate selected row (by rwa [sameOrigin candidate selected] at named) points
    · exact materialize_only predicate tx origin _ _
  · intro key result
    exact PromotionCertificates.finish_only _ tx pending key result
      (HeadInvariant.commit_holds _ tx) (HeadInvariant.rollback_holds _ tx) (fun candidate _ => retire_only predicate candidate)

/-- Every final version key was already present, except a complete key for
the origin currently being promoted. Pending and other origins gain no keys. -/
theorem no_other_new_keys (origin : Origin.Parsed) (now : Int64) (refused : List (UInt64 × ByteArray × ByteArray))
    (state : State) :
    ∀ row ∈ rows (execute (Promote.promote origin now refused) state).2.db "heads",
      (∃ old ∈ rows state.db "heads", HeadKeyFrame.key row = HeadKeyFrame.key old) ∨
      ∃ complete, HeadKeyFrame.key row = HeadKeyFrame.key complete ∧
        ReconciliationSlots.names complete (Origin.canonical origin) "complete" = true := by
  rcases PromotionExecution.outcome origin now refused state with unchanged | ⟨prepared, executed⟩
  · intro row member
    exact Or.inl ⟨row, by rwa [unchanged] at member, rfl⟩
  · let predicate := fun key =>
      (∃ old ∈ rows state.db "heads", key = HeadKeyFrame.key old) ∨
      ∃ complete, key = HeadKeyFrame.key complete ∧ ReconciliationSlots.names complete (Origin.canonical origin) "complete" = true
    obtain ⟨tx, opened, ready, ⟨scope, authority, pending, old⟩, began, read, snapshot, committed⟩ := prepared
    have sameOrigin := PromotionExecution.prepare_origin tx origin now opened ready scope authority pending old read
    have allowed := publish_only predicate tx origin now refused scope authority pending old sameOrigin
      (fun candidate selected row complete _ => Or.inr ⟨row, rfl, complete⟩)
    have initial : HeadInvariant.holds (HeadKeyFrame.allKeys predicate) ready := by
      constructor
      · rw [committed]
        exact fun row member => Or.inl ⟨row, member, rfl⟩
      · intro next staged same
        rw [snapshot] at same
        have same : tx = next ∧ state.db = staged := by simpa using same
        rw [← same.2]
        exact fun row member => Or.inl ⟨row, member, rfl⟩
    have final := allowed.invariant (HeadInvariant.holds (HeadKeyFrame.allKeys predicate)) (fun _ good => good) ready initial
    rw [executed]
    exact final.1

end Synchronicity.PromotionKeyFrame
