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

/-- Each invocation receives the previous invocation's actual stored state,
including physical writes left by a failed decoder. -/
def receiveAll (root : ByteArray) (size : UInt64) : List Transfer → State → State
  | [], state => state
  | transfer :: rest, state => receiveAll root size rest (receive root size transfer state).2

/-- Any finite history retains the named content and records exactly the
union of its previously saved groups and successfully verified transfers.
Failures and duplicates require no special reset or reconstructed host. -/
theorem history_preserves_version (saved : StoredFile state root content)
    (ready : Ready state) (correct : DecoderCorrect state root content saved.size) (transfers : List Transfer) :
    ∃ final : StoredFile (receiveAll root saved.size transfers state) root content,
      final.size = saved.size ∧ Ready (receiveAll root saved.size transfers state) ∧
      DecoderCorrect (receiveAll root saved.size transfers state) root content final.size ∧
      (receiveAll root saved.size transfers state).decodeSlice = state.decodeSlice ∧
      ∀ g, spansContain (Cas.Serve.held final.metadata) g =
        (spansContain (Cas.Serve.held saved.metadata) g ||
          transfers.any (fun transfer => verifiedGroups state root saved.size transfer g)) := by
  induction transfers generalizing state with
  | nil =>
    simp only [receiveAll]
    refine ⟨saved, rfl, ready, correct, True.intro, ?_⟩
    intro g
    simp
  | cons transfer rest ih =>
    simp only [receiveAll]
    obtain ⟨next, same, nextReady, nextCorrect, decision, coverage⟩ :=
      transfer_preserves_version saved ready correct transfer
    have tail := ih next nextReady nextCorrect
    rw [same] at tail
    obtain ⟨final, size, finalReady, finalCorrect, finalDecision, finalCoverage⟩ := tail
    refine ⟨final, size, finalReady, finalCorrect, finalDecision.trans decision, ?_⟩
    intro g
    rw [finalCoverage, coverage]
    simp only [verifiedGroups, decision, List.any_cons, Bool.or_assoc]

/-- Further transfers never take away readable content, even across a whole
history of failed, overlapping, repeated, or already-complete requests. The
read runs on the resulting files and rows, and returns the same exact bytes. -/
theorem transfers_preserve_readable_content (saved : StoredFile state root content)
    (ready : Ready state) (correct : DecoderCorrect state root content saved.size)
    (transfers : List Transfer) (offset length : UInt64)
    (valid : offset.toNat ≤ saved.size.toNat)
    (available : Cas.Read.covered saved.metadata offset
      (min (offset.toNat + length.toNat) saved.size.toNat).toUInt64 = true) :
    CasReadPromises.readResult (receiveAll root saved.size transfers state) root (.range offset length) = .ok
      (content.extract offset.toNat (min (offset.toNat + length.toNat) content.size)).data.toList := by
  obtain ⟨final, size, finalReady, _, _, coverage⟩ := history_preserves_version saved ready correct transfers
  apply final.reads offset length finalReady.quiet (by simpa only [size] using valid)
  rw [size]
  apply CasRangeProofs.additional_groups_preserve_readable_ranges saved.metadata final.metadata _ _ _ available
  intro g old
  rw [coverage]
  simp [old]

/-- An object absent from the database can enter an arbitrary receive
history through its first verified slice. The final raw state retains exactly
the groups verified by those transfers, including interrupted retries. -/
theorem first_transfer_and_history_save_content (state : State) (root content : ByteArray)
    (size : UInt64) (first : Transfer) (rest : List Transfer)
    (ready : Ready state)
    (absent : (rows state.db "blobs").filter (fun row => equals row [("root", .blob root)]) = [])
    (width : root.size = 32) (identity : state.hash content = root)
    (sameSize : size.toNat = content.size) (large : ¬ size ≤ Cas.Receive.inlineMax)
    (correct : DecoderCorrect state root content size)
    (nonempty : Cas.Receive.window size first.served ≠ [])
    (verifies : state.decodeSlice root size (Cas.Serve.pairsOf (Cas.Receive.window size first.served)) first.input = true) :
    ∃ final : StoredFile (receiveAll root size (first :: rest) state) root content,
      final.size = size ∧ Ready (receiveAll root size (first :: rest) state) ∧
      ∀ g, spansContain (Cas.Serve.held final.metadata) g =
        (first :: rest).any (fun transfer => verifiedGroups state root size transfer g) := by
  simp only [receiveAll]
  obtain ⟨saved, sizeSaved, _, coverage⟩ := first_transfer_saves_verified_content state root content size
    first.served first.input first.now first.tier ready.quiet ready.idle ready.clean absent width identity
    sameSize large correct nonempty verifies
  have execution := CasReceiveStateProofs.fresh_receive_execution state root size first.served first.input
    first.now first.tier ready.quiet ready.idle ready.clean absent large nonempty verifies
  obtain ⟨_, _, _, quiet, idle, _, decision, bytes, _, clean⟩ := execution
  have savedReady : Ready (receive root size first state).2 := ⟨quiet, idle, clean.trans ready.clean⟩
  have savedCorrect : DecoderCorrect (receive root size first state).2 root content saved.size := by
    rw [sizeSaved]
    exact decoder_preserved _ _ _ _ _ correct decision bytes
  have tail := history_preserves_version saved savedReady savedCorrect rest
  rw [sizeSaved] at tail
  obtain ⟨final, finalSize, finalReady, _, _, finalCoverage⟩ := tail
  refine ⟨final, finalSize, finalReady, ?_⟩
  intro g
  rw [finalCoverage, coverage]
  simp only [List.any_cons, verifiedGroups, decision, verifies, Bool.true_and]

/-- Initial interruptions do not require restarting from a clean file. As
soon as any transfer verifies content, the same actual history establishes a
saved version and exactly the union of its successful transfers. -/
theorem absent_history_saves_verified_content (state : State) (root content : ByteArray)
    (size : UInt64) (transfers : List Transfer) (ready : Ready state)
    (absent : (rows state.db "blobs").filter (fun row => equals row [("root", .blob root)]) = [])
    (width : root.size = 32) (identity : state.hash content = root)
    (sameSize : size.toNat = content.size) (large : ¬ size ≤ Cas.Receive.inlineMax)
    (correct : DecoderCorrect state root content size)
    (someVerified : ∃ g, transfers.any (fun transfer => verifiedGroups state root size transfer g) = true) :
    ∃ final : StoredFile (receiveAll root size transfers state) root content,
      final.size = size ∧ Ready (receiveAll root size transfers state) ∧
      ∀ g, spansContain (Cas.Serve.held final.metadata) g =
        transfers.any (fun transfer => verifiedGroups state root size transfer g) := by
  induction transfers generalizing state with
  | nil => simp at someVerified
  | cons first rest ih =>
    by_cases successful : Cas.Receive.window size first.served ≠ [] ∧
        state.decodeSlice root size (Cas.Serve.pairsOf (Cas.Receive.window size first.served)) first.input = true
    · exact first_transfer_and_history_save_content state root content size first rest ready absent width identity
        sameSize large correct successful.1 successful.2
    · have unverified : Cas.Receive.window size first.served = [] ∨
          state.decodeSlice root size (Cas.Serve.pairsOf (Cas.Receive.window size first.served)) first.input = false := by
        by_cases empty : Cas.Receive.window size first.served = []
        · exact Or.inl empty
        · exact Or.inr (Bool.eq_false_iff.mpr (fun verified => successful ⟨empty, verified⟩))
      have noneVerified (g : Nat) : verifiedGroups state root size first g = false := by
        rcases unverified with empty | interrupted
        · simp [verifiedGroups, empty, spansContain]
        · simp [verifiedGroups, interrupted]
      obtain ⟨db, quiet, idle, hash, decision, bytes, clean⟩ :=
        CasReceiveStateProofs.unverified_fresh_receive state root size first.served first.input first.now first.tier
          ready.quiet ready.idle ready.clean absent large unverified
      have nextReady : Ready (receive root size first state).2 := ⟨quiet, idle, clean.trans ready.clean⟩
      have nextAbsent : (rows (receive root size first state).2.db "blobs").filter
          (fun row => equals row [("root", .blob root)]) = [] := by rw [db]; exact absent
      have nextIdentity : (receive root size first state).2.hash content = root := by rw [hash]; exact identity
      have nextCorrect := decoder_preserved _ _ root content size correct decision bytes
      have tailVerified : ∃ g, rest.any (fun transfer => verifiedGroups (receive root size first state).2 root size transfer g) = true := by
        obtain ⟨g, verified⟩ := someVerified
        refine ⟨g, ?_⟩
        simp only [List.any_cons, noneVerified, Bool.false_or] at verified
        simpa only [verifiedGroups, decision] using verified
      obtain ⟨final, finalSize, finalReady, coverage⟩ := ih _ nextReady nextAbsent nextIdentity nextCorrect tailVerified
      simp only [receiveAll]
      refine ⟨final, finalSize, finalReady, ?_⟩
      intro g
      rw [coverage]
      simp only [List.any_cons, noneVerified, Bool.false_or]
      simp only [verifiedGroups, decision]

/-- Once successful transfers have covered the object, a whole-object read
returns exactly its named content, even if the history also contained failed,
overlapping or repeated transfers, including interrupted attempts before the
first successful slice. The object started absent. -/
theorem receiving_all_content_makes_the_whole_readable (state : State) (root content : ByteArray)
    (size : UInt64) (transfers : List Transfer) (ready : Ready state)
    (absent : (rows state.db "blobs").filter (fun row => equals row [("root", .blob root)]) = [])
    (width : root.size = 32) (identity : state.hash content = root)
    (sameSize : size.toNat = content.size) (large : ¬ size ≤ Cas.Receive.inlineMax)
    (correct : DecoderCorrect state root content size)
    (allReceived : ∀ g, g < (groupCount size).toNat →
      transfers.any (fun transfer => verifiedGroups state root size transfer g) = true) :
    CasReadPromises.readResult (receiveAll root size transfers state) root .all = .ok content.data.toList := by
  have someVerified : ∃ g, transfers.any (fun transfer => verifiedGroups state root size transfer g) = true := by
    refine ⟨0, allReceived 0 ?_⟩
    rw [CasPlanProofs.groupCount_spec]
    split
    · rename_i zero
      subst size
      simp [Cas.Receive.inlineMax] at large
    · omega
  obtain ⟨final, finalSize, finalReady, coverage⟩ := absent_history_saves_verified_content
    state root content size transfers ready absent width identity sameSize large correct someVerified
  obtain ⟨raw, observed, decoded⟩ := final.observed
  unfold CasReadPromises.readResult SimulatedHost.run
  rw [CasReadPromises.full_read_is_range { (receiveAll root size transfers state) with output := [] }
    root final.metadata raw [] finalReady.quiet observed decoded]
  change CasReadPromises.readResult _ root (.range 0 final.size) = _
  have available : Cas.Read.covered final.metadata 0 final.size = true := by
    have positive : (0 : UInt64) < final.size := by
      rw [finalSize]
      change 0 < size.toNat
      change ¬ size.toNat ≤ 16384 at large
      omega
    apply (CasRangeProofs.read_range_iff_groups _ _ _ positive).2
    intro g _ inside
    rw [coverage]
    apply allReceived
    rw [CasPlanProofs.groupCount_spec]
    split
    · rename_i zero
      subst size
      simp [finalSize] at positive
    · rw [finalSize] at inside
      have sizePositive : 0 < size.toNat := by
        change ¬ size.toNat ≤ 16384 at large
        omega
      omega
  have read := final.reads 0 final.size finalReady.quiet (by simp) (by simpa using available)
  simpa [final.sameSize] using read

private theorem read_throw (error : Cas.Read.Error) :
    (throw error : Cas.Read.Action A) = ExceptT.mk (Program.pure (.error error)) := rfl

private theorem invalid_read (saved : StoredFile state root content) (offset length : UInt64)
    (quiet : state.faults = []) (invalid : saved.size.toNat < offset.toNat) :
    CasReadPromises.readResult state root (.range offset length) =
      .error (.range offset (min (offset.toNat + length.toNat) saved.size.toNat).toUInt64 saved.size) := by
  obtain ⟨raw, observed, decoded⟩ := saved.observed
  unfold CasReadPromises.observation at observed
  simp [CasReadPromises.readResult, run, Cas.Read.read, Cas.Read.metadata,
    Cas.Read.requestAccess, raise, performOver, Inject.inject,
    execute, Interpreter.handle, access, reply, fault, record, quiet, observed, decoded,
    StoredFile.metadata, invalid, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.pure, read_throw, ExceptT.run, ExceptT.mk, Except.mapError, publish]

private theorem unavailable_read (saved : StoredFile state root content) (offset length : UInt64)
    (quiet : state.faults = []) (valid : offset.toNat ≤ saved.size.toNat)
    (nonempty : offset.toNat ≠ min (offset.toNat + length.toNat) saved.size.toNat)
    (unavailable : Cas.Read.covered saved.metadata offset
      (min (offset.toNat + length.toNat) saved.size.toNat).toUInt64 = false) :
    CasReadPromises.readResult state root (.range offset length) = .error .unavailable := by
  obtain ⟨raw, observed, decoded⟩ := saved.observed
  unfold CasReadPromises.observation at observed
  simp [CasReadPromises.readResult, run, Cas.Read.read, Cas.Read.metadata,
    Cas.Read.requestAccess, raise, performOver, Inject.inject,
    execute, Interpreter.handle, access, reply, fault, record, quiet, observed, decoded,
    Nat.not_lt.mpr valid, nonempty, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.pure, read_throw, ExceptT.run, ExceptT.mk, Except.mapError, publish, StoredFile.metadata]
  simp only [StoredFile.metadata] at unavailable
  simp [unavailable, execute]

/-- Equal saved coverage means identical public read results: the same exact
bytes, the same unavailable response, or the same invalid-range response. -/
private theorem equal_coverage_equal_reads (left : StoredFile before root content)
    (right : StoredFile after root content) (leftQuiet : before.faults = [])
    (rightQuiet : after.faults = [])
    (coverage : ∀ g, spansContain (Cas.Serve.held left.metadata) g =
      spansContain (Cas.Serve.held right.metadata) g) (offset length : UInt64) :
    CasReadPromises.readResult before root (.range offset length) =
      CasReadPromises.readResult after root (.range offset length) := by
  have size : right.size = left.size := UInt64.toNat_inj.mp (right.sameSize.trans left.sameSize.symm)
  by_cases valid : offset.toNat ≤ left.size.toNat
  · have covered : Cas.Read.covered left.metadata offset
        (min (offset.toNat + length.toNat) left.size.toNat).toUInt64 =
      Cas.Read.covered right.metadata offset
        (min (offset.toNat + length.toNat) left.size.toNat).toUInt64 := by
      apply Bool.eq_iff_iff.mpr
      constructor
      · apply CasRangeProofs.additional_groups_preserve_readable_ranges
        intro g member
        rw [← coverage]
        exact member
      · apply CasRangeProofs.additional_groups_preserve_readable_ranges
        intro g member
        rw [coverage]
        exact member
    by_cases available : Cas.Read.covered left.metadata offset
        (min (offset.toNat + length.toNat) left.size.toNat).toUInt64 = true
    · rw [left.reads offset length leftQuiet valid available,
        right.reads offset length rightQuiet (by simpa only [size] using valid)
          (by simpa only [size, ← covered] using available)]
    · have missing := Bool.eq_false_iff.mpr available
      have nonempty : offset.toNat ≠ min (offset.toNat + length.toNat) left.size.toNat := by
        intro empty
        have same : (min (offset.toNat + length.toNat) left.size.toNat).toUInt64 = offset := by
          rw [← empty]; simp
        simp [same, Cas.Read.covered] at missing
      rw [unavailable_read left offset length leftQuiet valid nonempty missing,
        unavailable_read right offset length rightQuiet (by simpa only [size] using valid)
          (by simpa only [size] using nonempty) (by simpa only [size, ← covered] using missing)]
  · rw [invalid_read left offset length leftQuiet (by omega),
      invalid_read right offset length rightQuiet (by rw [size]; omega), size]

/-- Reordering the same transfers does not change what any subsequent range
read returns, including failures and partially available content. -/
theorem transfer_order_does_not_change_reads (saved : StoredFile state root content)
    (ready : Ready state) (correct : DecoderCorrect state root content saved.size)
    (first second : List Transfer) (reordered : first.Perm second) (offset length : UInt64) :
    CasReadPromises.readResult (receiveAll root saved.size first state) root (.range offset length) =
      CasReadPromises.readResult (receiveAll root saved.size second state) root (.range offset length) := by
  obtain ⟨left, _, leftReady, _, _, leftCoverage⟩ := history_preserves_version saved ready correct first
  obtain ⟨right, _, rightReady, _, _, rightCoverage⟩ := history_preserves_version saved ready correct second
  apply equal_coverage_equal_reads left right leftReady.quiet rightReady.quiet _ offset length
  intro g
  rw [leftCoverage, rightCoverage, reordered.any_eq]

/-- Retrying an entire transfer history does not change subsequent read
results. Verified bytes may be rewritten, but remain the same named content. -/
theorem replaying_transfers_does_not_change_reads (saved : StoredFile state root content)
    (ready : Ready state) (correct : DecoderCorrect state root content saved.size)
    (transfers : List Transfer) (offset length : UInt64) :
    CasReadPromises.readResult (receiveAll root saved.size (transfers ++ transfers) state) root (.range offset length) =
      CasReadPromises.readResult (receiveAll root saved.size transfers state) root (.range offset length) := by
  obtain ⟨left, _, leftReady, _, _, leftCoverage⟩ := history_preserves_version saved ready correct (transfers ++ transfers)
  obtain ⟨right, _, rightReady, _, _, rightCoverage⟩ := history_preserves_version saved ready correct transfers
  apply equal_coverage_equal_reads left right leftReady.quiet rightReady.quiet _ offset length
  intro g
  rw [leftCoverage, rightCoverage]
  simp

end Synchronicity.CasTransferHistories
