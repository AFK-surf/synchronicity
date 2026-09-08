import Synchronicity.HeadView
import Synchronicity.FetchHeadSafety

namespace Synchronicity.TargetTransition
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost

def fields (key : CapturedHead) : Fields :=
  [("origin_id", .text key.origin), ("slot", .text "pending"),
    ("seq", .integer key.version.seq.toInt64), ("root", .blob key.version.root)]

def fetchKey (target : Trie.Fetch.Target) : CapturedHead := ⟨target.origin, ⟨target.seq, target.root⟩⟩
def pendingKey (pending : Promote.Pending) : CapturedHead :=
  ⟨Origin.canonical pending.head.origin, ⟨pending.head.seq, pending.head.root⟩⟩

theorem fetch_fields (target : Trie.Fetch.Target) : fields (fetchKey target) = Trie.Fetch.targetRows target := by
  simp [fields, fetchKey, Trie.Fetch.targetRows]
  apply Int64.toBitVec_inj.mp
  simp

theorem match_key (key : CapturedHead) (row : Fields) (origin : String) (slot : HeadSlot) (version : HeadVersion)
    (named : ReconciliationSlots.names row origin (HeadView.slotName slot) = true)
    (stored : HeadView.points row version) (matched : equals row (fields key) = true) :
    slot = .pending ∧ CapturedHead.mk origin version = key := by
  simp only [fields, equals, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] at matched
  obtain ⟨originMatch, slotMatch, seqMatch, rootMatch⟩ := matched
  have originSame := HeadView.text_unique _ origin key.origin (HeadView.named_fields named).1 originMatch
  have slotSame := HeadView.text_unique _ (HeadView.slotName slot) "pending" (HeadView.named_fields named).2 slotMatch
  have slotSame : slot = .pending := by cases slot <;> first | rfl | contradiction
  have seqSame : version.seq.toInt64 = key.version.seq.toInt64 := by
    simpa [stored.1, isCell, equalCell, BEq.beq, instBEqCell.beq] using seqMatch
  have rootSame : version.root = key.version.root := by
    apply eq_of_beq
    simpa [stored.2, isCell, equalCell, BEq.beq, instBEqCell.beq] using rootMatch
  have versionSame : version = key.version := by
    apply HeadView.version_unique row version key.version stored
    exact ⟨stored.1.trans (congrArg Cell.integer seqSame), stored.2.trans (congrArg Cell.blob rootSame)⟩
  refine ⟨slotSame, ?_⟩
  rw [originSame, versionSame]

/-- A key-preserving operation that retains every noncaptured row refines the
same keep/advance/consume relation used for every other operation. No authority
to replace the captured version with another version is granted. -/
theorem refines (key : CapturedHead) (before : HeadView.Represents db view)
    (after : HeadView.Represents nextDb nextView)
    (noNew : ∀ row ∈ rows nextDb "heads", ∃ old ∈ rows db "heads", HeadKeyFrame.key row = HeadKeyFrame.key old)
    (retained : ∀ row ∈ rows db "heads", equals row (fields key) = false → row ∈ rows nextDb "heads") :
    HeadTransition [key] view nextView := by
  intro origin slot
  cases oldValue : view origin slot with
  | none => exact HeadView.initially_empty _
  | some old =>
    cases nextValue : nextView origin slot with
    | some next =>
      have same := HeadView.no_replacement before after noNew oldValue nextValue
      rw [same]
      exact .keep _ _
    | none =>
      obtain ⟨row, selected, stored⟩ := HeadView.existing before oldValue
      have matched : equals row (fields key) = true := by
        cases tested : equals row (fields key) with
        | true => rfl
        | false => exact False.elim (HeadView.absent after nextValue ⟨retained row selected.1 tested, selected.2⟩)
      obtain ⟨slotSame, keySame⟩ := match_key key row origin slot old selected.2 stored matched
      subst slot
      exact .consume old (by simp [keySame])

theorem requester (target : Trie.Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat)
    (continuation rest : Program Trie.Fetch.Effects (Except Trie.Fetch.Error Bool))
    (reachable : PrivateDatabase.Continuation (Trie.Fetch.fetch (Std.HashSet Trie.Missing.Visit)
      (Std.HashSet ByteArray) target reference maximum retryLimit).run continuation)
    (state final : State) (closed : state.pending = none)
    (path : PrivateDatabase.Prefix continuation state rest final)
    (before : HeadView.Represents state.db view) (after : HeadView.Represents final.db nextView) :
    HeadTransition [fetchKey target] view nextView := by
  apply refines _ before after
  · exact FetchHeadSafety.every_resumption_no_new_key _ _ target reference maximum retryLimit continuation rest reachable state final closed path
  · rw [fetch_fields]
    exact FetchHeadSafety.every_resumption_preserves _ _ target reference maximum retryLimit continuation rest reachable state final closed path

end Synchronicity.TargetTransition
