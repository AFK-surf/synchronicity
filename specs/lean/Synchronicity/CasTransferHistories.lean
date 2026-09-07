import Synchronicity.CasReceiveHistoryProofs

/-! Histories execute receive commands against the same saved files and rows.
No intermediate read result or reconstructed host adapter is assumed. -/
namespace Synchronicity.CasTransferHistories
open VerifiedCore VerifiedCore.Host SimulatedHost CasReceiveHistoryProofs

structure Transfer where
  served : List (UInt64 × UInt64)
  input : UInt64
  now : Int64
  tier : Cas.IngestCommit.Tier

structure Ready (state : State) : Prop where
  quiet : state.faults = []
  idle : state.pending = none
  clean : state.scanFault = none

abbrev receive (root : ByteArray) (size : UInt64) (transfer : Transfer) (state : State) :=
  SimulatedHost.run (Cas.Receive.writeSlice root size transfer.served transfer.input transfer.now transfer.tier) state

def verifiedGroups (state : State) (root : ByteArray) (size : UInt64) (transfer : Transfer) (group : Nat) : Bool :=
  state.decodeSlice root size (Cas.Serve.pairsOf (Cas.Receive.window size transfer.served)) transfer.input &&
    spansContain (Cas.Receive.window size transfer.served) group

private theorem decoder_preserved (state next : State) (root content : ByteArray) (size : UInt64)
    (correct : DecoderCorrect state root content size)
    (decision : next.decodeSlice = state.decodeSlice)
    (bytes : next.decodedPayload = state.decodedPayload) : DecoderCorrect next root content size := by
  simpa only [DecoderCorrect, decision, bytes] using correct

/-- One actual transfer preserves the saved version and adds exactly its
verified groups. The result is ready for the next actual transfer, including
a retry after verification fails or a duplicate after completion. -/
theorem transfer_preserves_version (saved : StoredFile state root content)
    (ready : Ready state) (correct : DecoderCorrect state root content saved.size) (transfer : Transfer) :
    let result := receive root saved.size transfer state
    ∃ next : StoredFile result.2 root content,
      next.size = saved.size ∧ Ready result.2 ∧ DecoderCorrect result.2 root content next.size ∧
      result.2.decodeSlice = state.decodeSlice ∧
      ∀ g, spansContain (Cas.Serve.held next.metadata) g =
        (spansContain (Cas.Serve.held saved.metadata) g || verifiedGroups state root saved.size transfer g) := by
  let result := receive root saved.size transfer state
  have finish (next : StoredFile result.2 root content) (same : next.size = saved.size)
      (quiet : result.2.faults = []) (idle : result.2.pending = none) (clean : result.2.scanFault = none)
      (decision : result.2.decodeSlice = state.decodeSlice) (bytes : result.2.decodedPayload = state.decodedPayload)
      (coverage : ∀ g, spansContain (Cas.Serve.held next.metadata) g =
        (spansContain (Cas.Serve.held saved.metadata) g || verifiedGroups state root saved.size transfer g)) :
      ∃ next : StoredFile result.2 root content,
        next.size = saved.size ∧ Ready result.2 ∧ DecoderCorrect result.2 root content next.size ∧
        result.2.decodeSlice = state.decodeSlice ∧
        ∀ g, spansContain (Cas.Serve.held next.metadata) g =
          (spansContain (Cas.Serve.held saved.metadata) g || verifiedGroups state root saved.size transfer g) := by
    refine ⟨next, same, ⟨quiet, idle, clean⟩, ?_, decision, coverage⟩
    rw [same]
    exact decoder_preserved state result.2 root content saved.size correct decision bytes
  by_cases empty : Cas.Receive.window saved.size transfer.served = []
  · have execution : result = (.ok [], { state with output := [] }) := by
      simp [result, SimulatedHost.run, Cas.Receive.writeSlice, empty, execute,
        pure, ExceptT.pure, ExceptT.run, ExceptT.mk]
    let next : StoredFile result.2 root content :=
      { saved with
        selected := by rw [execution]; exact saved.selected
        identity := by rw [execution]; exact saved.identity
        sound := by rw [execution]; exact saved.sound }
    apply finish next rfl (by rw [execution]; exact ready.quiet) (by rw [execution]; exact ready.idle)
      (by rw [execution]; exact ready.clean) (by rw [execution]) (by rw [execution])
    intro g
    simp [next, StoredFile.metadata, verifiedGroups, empty, spansContain]
  · obtain ⟨raw, observed, decoded⟩ := saved.observed
    have accepted (groups : List GroupSpan) : (Cas.IngestCommit.plan (some saved.claim) saved.size groups).accepted = true := by
      simp [Cas.IngestCommit.plan, StoredFile.claim, planCasCommit, settleSize]
    by_cases complete : saved.complete = true
    · have execution := CasReceiveStateProofs.complete_receive_execution state root saved.size
        transfer.served transfer.input transfer.now transfer.tier saved.claim saved.metadata raw []
        ready.quiet ready.idle saved.claimed observed decoded complete (accepted [])
      change result.1 = _ ∧ result.2.db = _ ∧ _ at execution
      obtain ⟨_, db, files, quiet, idle, hash, decision, bytes, _, clean⟩ := execution
      change result.2.hash = state.hash at hash
      change result.2.files = state.files at files
      let next : StoredFile result.2 root content :=
        { saved with
          selected := by rw [db]; exact saved.selected
          identity := by rw [hash]; exact saved.identity
          sound := by simpa only [payload, files] using saved.sound }
      apply finish next rfl quiet idle (clean.trans ready.clean) decision bytes
      intro g
      apply Bool.eq_iff_iff.mpr
      simp only [Bool.or_eq_true, verifiedGroups, Bool.and_eq_true]
      constructor
      · exact Or.inl
      · rintro (old | ⟨_, incoming⟩)
        · exact old
        · have inside := (CasPlanProofs.normalize_spans_membership _ _ _).1 incoming
          simp [next, StoredFile.metadata, Cas.Serve.held, complete, spansContain, inside.2]
    · have incomplete := Bool.eq_false_iff.mpr complete
      by_cases verifies : state.decodeSlice root saved.size
          (Cas.Serve.pairsOf (Cas.Receive.window saved.size transfer.served)) transfer.input = true
      · obtain ⟨_, next, metadata, _⟩ := successful_transfer_saves_verified_content saved correct
          transfer.served transfer.input transfer.now transfer.tier ready.quiet ready.idle ready.clean incomplete empty verifies
        have execution := CasReceiveStateProofs.existing_receive_execution state root saved.size
          transfer.served transfer.input transfer.now transfer.tier saved.claim saved.metadata raw []
          ready.quiet ready.idle ready.clean saved.claimed observed decoded incomplete (accepted [])
          (accepted _) saved.large empty verifies
        change result.1 = _ ∧ _ at execution
        obtain ⟨_, _, _, quiet, idle, _, decision, bytes, _, clean⟩ := execution
        have same : next.size = saved.size := congrArg Cas.Read.Metadata.size metadata
        apply finish next same quiet idle (clean.trans ready.clean) decision bytes
        intro g
        rw [metadata]
        change spansContain (Cas.Serve.held (CasBitmapProofs.metadata saved.size
          (planCasCommit true saved.claim.durable saved.complete saved.size saved.size
            (Cas.IngestCommit.oldSpans saved.claim) (Cas.Receive.window saved.size transfer.served)))) g = _
        have union := CasBitmapProofs.unchanged_size_coverage saved.size saved.complete
          saved.claim.durable saved.bitmap (Cas.Receive.window saved.size transfer.served) g
        change spansContain (Cas.Serve.held (CasBitmapProofs.metadata saved.size
          (planCasCommit true saved.claim.durable saved.complete saved.size saved.size
            (Cas.IngestCommit.oldSpans saved.claim) (Cas.Receive.window saved.size transfer.served)))) g =
          (spansContain (Cas.Serve.held saved.metadata) g ||
            (spansContain (Cas.Receive.window saved.size transfer.served) g && g < (groupCount saved.size).toNat)) at union
        rw [union]
        simp only [verifiedGroups, verifies, Bool.true_and]
        congr 1
        apply Bool.eq_iff_iff.mpr
        simp only [Bool.and_eq_true, decide_eq_true_eq]
        exact ⟨And.left, fun member => ⟨member, ((CasPlanProofs.normalize_spans_membership _ _ _).1 member).2⟩⟩
      · have failure := Bool.eq_false_iff.mpr verifies
        have execution := CasReceiveStateProofs.interrupted_decoder_keeps_committed_metadata state root saved.size
          transfer.served transfer.input transfer.now transfer.tier saved.claim saved.metadata raw []
          ready.quiet ready.idle ready.clean saved.claimed observed decoded incomplete (accepted []) saved.large empty failure
        change result.1 = _ ∧ result.2.db = _ ∧ _ at execution
        obtain ⟨_, db, physical, quiet, idle, hash, decision, bytes, _, clean⟩ := execution
        change result.2.hash = state.hash at hash
        change lookupFile result.2.files ("cas_payload", root) = _ at physical
        have preserved := (correct (Cas.Receive.window saved.size transfer.served) transfer.input (payload state root)
          (CasPlanProofs.normalize_spans_bounds _ _)).1 _ saved.sound
        let next : StoredFile result.2 root content :=
          { saved with
            selected := by rw [db]; exact saved.selected
            identity := by rw [hash]; exact saved.identity
            sound := by simpa only [payload, physical, Option.getD_some] using preserved }
        apply finish next rfl quiet idle (clean.trans ready.clean) decision bytes
        intro g
        simp [next, StoredFile.metadata, verifiedGroups, failure]

end Synchronicity.CasTransferHistories
