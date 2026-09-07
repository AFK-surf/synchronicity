import Synchronicity.CasTransferHistories

/-! Small objects use the actual inline decoder and persisted SQL bytes.
Subsequent transfers run against that same state before the public read. -/
namespace Synchronicity.CasInlineHistories
open VerifiedCore VerifiedCore.Host SimulatedHost CasTransferHistories

private theorem small_group_count (size : UInt64) (small : size ≤ Cas.Receive.inlineMax) :
    (groupCount size).toNat = 1 := by
  rw [CasPlanProofs.groupCount_spec]
  split
  · rfl
  · change size.toNat ≤ 16384 at small
    omega

private theorem small_window (size : UInt64) (served : List (UInt64 × UInt64))
    (small : size ≤ Cas.Receive.inlineMax) (nonempty : Cas.Receive.window size served ≠ []) :
    Cas.Receive.window size served = Cas.IngestCommit.fullSpan size := by
  have bounded := CasPlanProofs.normalize_spans_bounds (groupCount size).toNat (Cas.Serve.spansOf served)
  have separated := CasPlanProofs.normalize_spans_separated (groupCount size).toNat (Cas.Serve.spansOf served)
  change ∀ span ∈ Cas.Receive.window size served, span.start < span.stop ∧ span.stop ≤ (groupCount size).toNat at bounded
  change (Cas.Receive.window size served).Pairwise _ at separated
  rw [small_group_count size small] at bounded
  cases window : Cas.Receive.window size served with
  | nil => exact False.elim (nonempty window)
  | cons head tail =>
    rw [window] at bounded separated
    have headBound := bounded head (by simp)
    have headEqual : head = ⟨0, 1⟩ := by cases head; simp_all only [GroupSpan.mk.injEq]; omega
    have tailEmpty : tail = [] := by
      cases tail with
      | nil => rfl
      | cons next rest =>
        have nextBound := bounded next (by simp)
        have gap := (List.pairwise_cons.mp separated).1 next (by simp)
        omega
    simp [headEqual, tailEmpty, Cas.IngestCommit.fullSpan, small_group_count size small]

/-- The first verified inline receive writes the exact decoder buffer into
its actual new row. No empty-table or fresh-lease assumption is needed. -/
theorem inline_receive_execution (state : State) (root content : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (input : UInt64) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (ready : Ready state)
    (absent : (rows state.db "blobs").filter (fun row => equals row [("root", .blob root)]) = [])
    (small : size ≤ Cas.Receive.inlineMax) (nonempty : Cas.Receive.window size served ≠ [])
    (decoded : state.decodeInline root size none (Cas.Serve.pairsOf (Cas.Receive.window size served)) input = some content) :
    let result := receive root size ⟨served, input, now, tier⟩ state
    result.1 = .ok (Cas.Serve.pairsOf (Cas.Receive.window size served)) ∧
    rows result.2.db "blobs" = upsertRows (rows state.db "blobs")
      (Cas.IngestCommit.values root size true none (some content) now tier)
      ["root"] Cas.IngestCommit.assignments ∧ Ready result.2 := by
  have complete : (Cas.IngestCommit.plan none size (Cas.Receive.window size served)).complete = true := by
    rw [small_window size served small nonempty]
    exact IngestCommitProofs.complete_plan_accepted_complete none size (CasReceiveProofs.fresh_accepted _ _)
  have selected (table : String) (fields : Fields) :
      selects ⟨table, fields, [], []⟩ = fun row => equals row fields := by
    funext row
    simp [selects]
  rcases ready with ⟨quiet, idle, clean⟩
  simp [receive, SimulatedHost.run, Cas.Receive.writeSlice, Cas.Receive.leased, Cas.Receive.admit,
    Cas.Receive.commit, Cas.Receive.metadata?, Cas.Receive.access, Cas.Receive.lease, Cas.Receive.bao,
    Cas.IngestCommit.admit, Cas.IngestCommit.commitGroups, Cas.IngestCommit.commitIn,
    Cas.IngestCommit.decodeClaim, within, ensure, transactionOver, raise, performOver, Inject.inject, Program.mapEffects,
    execute, Interpreter.handle, storage, SimulatedHost.access, upsert, SimulatedHost.lease,
    SimulatedHost.bao, SimulatedHost.transaction, reply, fault, record, quiet, idle, clean,
    scanFailure, absent, CasReceiveProofs.fresh_accepted, complete, unordered_query,
    selected, small, nonempty, decoded, counter, setCounter,
    Except.mapError, Except.map, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont,
    ExceptT.pure, ExceptT.run, ExceptT.mk]
  exact ⟨rfl, rfl, rfl⟩

private theorem complete_history_keeps_database (state : State) (root : ByteArray) (size : UInt64)
    (transfers : List Transfer) (claim : Cas.IngestCommit.Claim) (row : Cas.Read.Metadata)
    (raw : Row) (rest : List Row) (quiet : state.faults = []) (idle : state.pending = none)
    (claimed : Cas.IngestCommit.decodeClaim
      (query state.db "blobs" Cas.IngestCommit.claimColumns [("root", .blob root)] [] []) = .ok (some claim))
    (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row) (complete : row.complete = true)
    (accepted : (Cas.IngestCommit.plan (some claim) size []).accepted = true) :
    (receiveAll root size transfers state).db = state.db ∧
    (receiveAll root size transfers state).faults = [] := by
  induction transfers generalizing state with
  | nil => exact ⟨rfl, quiet⟩
  | cons first tail ih =>
    obtain ⟨_, db, _, quietAfter, idleAfter, _⟩ := CasReceiveStateProofs.complete_receive_execution
      state root size first.served first.input first.now first.tier claim row raw rest quiet idle claimed observed decoded complete accepted
    have nextClaimed : Cas.IngestCommit.decodeClaim
        (query (receive root size first state).2.db "blobs" Cas.IngestCommit.claimColumns [("root", .blob root)] [] []) = .ok (some claim) := by
      rw [db]; exact claimed
    have nextObserved : CasReadPromises.observation (receive root size first state).2 root = raw :: rest := by
      unfold CasReadPromises.observation
      rw [db]
      exact observed
    have result := ih _ quietAfter idleAfter nextClaimed nextObserved
    exact ⟨result.1.trans db, result.2⟩

/-- Inline bytes successfully received from a peer remain exactly readable
after any further transfers of that object, including repeated and empty
requests. The whole read uses the final database, not a separate read model. -/
theorem received_inline_content_remains_readable (state : State) (root content : ByteArray)
    (size : UInt64) (first : Transfer) (rest : List Transfer) (ready : Ready state)
    (absent : (rows state.db "blobs").filter (fun row => equals row [("root", .blob root)]) = [])
    (width : root.size = 32) (sameSize : size.toNat = content.size)
    (small : size ≤ Cas.Receive.inlineMax) (nonempty : Cas.Receive.window size first.served ≠ [])
    (decoded : state.decodeInline root size none (Cas.Serve.pairsOf (Cas.Receive.window size first.served)) first.input = some content) :
    CasReadPromises.readResult (receiveAll root size (first :: rest) state) root .all = .ok content.data.toList := by
  obtain ⟨_, stored, readyAfter⟩ := inline_receive_execution state root content size first.served first.input first.now first.tier
    ready absent small nonempty decoded
  let received := receive root size first state
  let values := Cas.IngestCommit.values root size true none (some content) first.now first.tier
  have selected : (rows received.2.db "blobs").filter (fun row => equals row [("root", .blob root)]) = [values] := by
    rw [stored]
    exact CasPersistenceProofs.receive_upsert_selects_new_record _ root size true none first.now first.tier absent (some content)
  let raw := project ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"] values
  have observed : CasReadPromises.observation received.2 root = [raw] := by
    have selectsRoot : selects ⟨"blobs", [("root", .blob root)], [], []⟩ = fun row => equals row [("root", .blob root)] := by
      funext row; simp [selects]
    simp [CasReadPromises.observation, selectsRoot, selected, raw]
  have typed : Cas.Read.decodeRow raw = .ok ⟨size, true, none, some content⟩ := by
    cases first.tier <;> simp [raw, values, project, Cas.IngestCommit.values, cell,
      Cas.Read.decodeRow, Cas.Read.blobField, Cas.Read.integerField, Cas.Read.optionalBlobField,
      Cas.Codec.blobField, Cas.Codec.integerField, Cas.Codec.optionalBlobField, width,
      bind, pure, Except.bind, Except.pure]
  let claim : Cas.IngestCommit.Claim := ⟨size, true, first.tier == .local, none⟩
  have claimed : Cas.IngestCommit.decodeClaim
      (query received.2.db "blobs" Cas.IngestCommit.claimColumns [("root", .blob root)] [] []) = .ok (some claim) := by
    rw [unordered_query, selected]
    cases tierCase : first.tier <;> simp [tierCase, Cas.IngestCommit.claimColumns, Cas.IngestCommit.decodeClaim, claim, project,
      values, Cas.IngestCommit.values, cell, Cas.Codec.integerField, Cas.Codec.optionalBlobField,
      bind, pure, Except.bind, Except.pure] <;> rfl
  have kept := complete_history_keeps_database received.2 root size rest claim _ raw [] readyAfter.quiet readyAfter.idle
    claimed observed typed rfl (by simp [claim, Cas.IngestCommit.plan, planCasCommit, settleSize])
  apply CasReadPromises.full_read_returns_content _ root ⟨size, true, none, some content⟩ content kept.2 _ rfl
  refine ⟨⟨raw, [], ?_, typed⟩, sameSize, rfl⟩
  unfold CasReadPromises.observation
  change (rows (receiveAll root size rest received.2).db "blobs" |>.filter _ |>.map _) = _
  rw [kept.1]
  exact observed

end Synchronicity.CasInlineHistories
