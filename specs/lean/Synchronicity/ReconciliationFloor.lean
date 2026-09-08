import Synchronicity.ReconciliationRead
import Synchronicity.ReconciliationReadOnly

/-! Acceptance compares against backed floors from its initial database.
Authority reads preserve the whole private database, and recording an incoming
signature only extends history, so it cannot hide an existing floor. -/
namespace Synchronicity.ReconciliationFloor
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost
open TransactionSuccess (bind_success)
open ReconciliationRead

theorem begin_pending (state opened : State) (tx : Transaction)
    (started : storage .begin state = (.ok tx, opened)) :
    opened.pending = some (tx, state.db) := by
  simp only [storage, reply] at started
  split at started
  · cases started
  · split at started
    · cases started
    · cases started
      rfl

theorem request_upsert (tx : Transaction) (table : String) (fields : Fields)
    (conflicts columns : List String) (state final : State)
    (executed : execute (History.request (.upsert tx table fields conflicts columns)) state = (.ok (), final)) :
    ∃ db, state.pending = some (tx, db) ∧
      final.pending = some (tx, setRows db table (upsertRows (rows db table) fields conflicts
        (columns.map fun column => (column, .excluded column)))) := by
  have succeeded := congrArg Prod.fst executed
  change ((storage (.upsert tx table fields conflicts columns) state).1.mapError History.Error.host) = .ok () at succeeded
  have raw : (storage (.upsert tx table fields conflicts columns) state).1 = .ok () := by
    cases h : (storage (.upsert tx table fields conflicts columns) state).1 <;> simp_all [Except.mapError]
  obtain ⟨db, opened, changed, _⟩ := ReconciliationSlots.upsert_success _ _ _ _ _ state raw
  refine ⟨db, opened, ?_⟩
  have finalState : final = (storage (.upsert tx table fields conflicts columns) state).2 :=
    (congrArg Prod.snd executed).symm
  rw [finalState]
  exact changed

theorem record_retains (tx : Transaction) (head : Head) (now : Int64)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (executed : execute (Reconcile.record tx head now) state = (.ok (), final)) :
    ∃ next, final.pending = some (tx, next) ∧ rows next "heads" = rows db "heads" ∧
      ∀ row ∈ rows db "head_history", row ∈ rows next "head_history" := by
  unfold Reconcile.record at executed
  split at executed
  · cases executed
  · obtain ⟨_, writtenState, written, executed⟩ := bind_success _ _ _ _ _ executed
    obtain ⟨before, initial, staged⟩ := request_upsert tx "head_history" _ _ [] state writtenState written
    have same : before = db := by simpa [opened] using initial.symm
    subst before
    obtain ⟨_, checkedState, read, executed⟩ := bind_success _ _ _ _ _ executed
    have readFrame := ReconciliationReadOnly.executed_pending
      (History.request (.readRows tx "head_history" ["created_at", "signed_by", "sig"] (Reconcile.headKey head)))
      (.request trivial fun _ => .done _) writtenState checkedState _ read
    split at executed
    · cases executed
    · have same : checkedState = final := congrArg Prod.snd executed
      subst checkedState
      refine ⟨_, readFrame.trans staged, ?_, ?_⟩
      · exact rows_setRows_other _ _ _ _ (by decide)
      · intro row member
        rw [rows_setRows, List.map_nil, upsertRows_doNothing]
        split
        · exact member
        · exact List.mem_append_left _ member

theorem StoredFloor.extends {before after : Database} {origin slot : String} {seq : Int64} {root : ByteArray}
    (stored : StoredFloor before origin slot seq root)
    (sameHeads : rows after "heads" = rows before "heads")
    (history : ∀ row ∈ rows before "head_history", row ∈ rows after "head_history") :
    StoredFloor after origin slot seq root := by
  constructor
  · obtain ⟨row, member, named, backing, retained, linked⟩ := stored.backed
    exact ⟨row, by rwa [sameHeads], named, backing, history backing retained, linked⟩
  · intro row member named
    rw [sameHeads] at member
    exact stored.pointer row member named

/-- The actual acceptance command must beat every initially backed complete
or pending floor. StoredFloor is a raw key/backing invariant; validation and
successful reads are consequences of acceptance, not caller-supplied premises. -/
theorem accepted_beats_initial_floor (head : Head) (now : Int64) (keep : Nat) (state : State)
    (slot : String) (which : slot = "complete" ∨ slot = "pending") (seq : Int64) (root : ByteArray)
    (stored : StoredFloor state.db (Origin.canonical head.origin) slot seq root)
    (accepted : (execute (Reconcile.accept head now keep) state).1 = .ok .pending) :
    Reconcile.newer head.seq head.root ⟨seq.toUInt64, root⟩ = true := by
  unfold Reconcile.accept at accepted
  obtain ⟨signature, checked, verified, accepted⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ accepted
  have signatureFrame : checked.db = state.db := by
    have kept := ReconciliationFrame.signature_preserves_db head state
    simpa only [verified] using kept
  cases signature with
  | false => cases accepted
  | true =>
    obtain ⟨tx, opened, _, started, body, _⟩ :=
      TransactionSuccess.transaction_success _ _ _ checked _ accepted
    have initial := begin_pending checked opened tx started
    have accepted := congrArg Prod.fst body
    obtain ⟨instant, timed, timedRead, accepted⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ accepted
    have timedFrame := ReconciliationReadOnly.executed_pending _
      (ReconciliationReadOnly.auth_only _ (ReconciliationReadOnly.trustInstant_only tx now)) _ _ _ timedRead
    obtain ⟨live, bound, liveRead, accepted⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ accepted
    have liveFrame := ReconciliationReadOnly.executed_pending _
      (ReconciliationReadOnly.auth_only _ (ReconciliationReadOnly.liveForKey_only tx head.signedBy instant)) _ _ _ liveRead
    have boundDb : bound.pending = some (tx, state.db) := by
      rw [liveFrame, timedFrame, initial, signatureFrame]
    split at accepted
    · cases accepted
    · obtain ⟨_, beforeComplete, recorded, accepted⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ accepted
      obtain ⟨next, beforeRead, sameHeads, retained⟩ := record_retains tx head now
        bound beforeComplete state.db boundDb recorded
      have storedNext := StoredFloor.extends stored sameHeads retained
      obtain ⟨complete, beforePending, readComplete, accepted⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ accepted
      have completeFrame := ReconciliationReadOnly.executed_pending _
        (ReconciliationReadOnly.readSlot_only tx _ "complete") _ _ _ readComplete
      obtain ⟨pending, _, readPending, accepted⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ accepted
      dsimp only at accepted
      split at accepted
      · rename_i greater
        have greater := List.all_eq_true.mp greater
        rcases which with rfl | rfl
        · obtain ⟨old, exactList, pointer⟩ := readSlot_retains_floor tx next beforeComplete
            beforeRead _ "complete" seq root storedNext complete (congrArg Prod.fst readComplete)
          have compared := greater old (List.mem_append_left _ (by rw [exactList]; exact List.mem_cons_self))
          rwa [pointer] at compared
        · obtain ⟨old, exactList, pointer⟩ := readSlot_retains_floor tx next beforePending
            (completeFrame.trans beforeRead) _ "pending" seq root storedNext pending (congrArg Prod.fst readPending)
          have compared := greater old (List.mem_append_right _ (by rw [exactList]; exact List.mem_cons_self))
          rwa [pointer] at compared
      · obtain ⟨_, _, _, impossible⟩ := TrieServePrivacyProofs.bind_ok _ _ _ _ accepted
        cases impossible

/-- An obsolete advertisement cannot change any committed head when the
command returns normally. This covers rejected signatures and authority as
well as the not-newer result; history retention remains independent. -/
theorem obsolete_preserves_heads (head : Head) (now : Int64) (keep : Nat) (state : State)
    (slot : String) (which : slot = "complete" ∨ slot = "pending") (seq : Int64) (root : ByteArray)
    (stored : StoredFloor state.db (Origin.canonical head.origin) slot seq root)
    (obsolete : Reconcile.newer head.seq head.root ⟨seq.toUInt64, root⟩ = false)
    (answer : Acceptance) (returned : (execute (Reconcile.accept head now keep) state).1 = .ok answer) :
    rows (execute (Reconcile.accept head now keep) state).2.db "heads" = rows state.db "heads" := by
  apply ReconciliationRejection.nonacceptance_preserves_heads head now keep state answer _ returned
  intro same
  subst answer
  have newer := accepted_beats_initial_floor head now keep state slot which seq root stored returned
  rw [obsolete] at newer
  cases newer

end Synchronicity.ReconciliationFloor
