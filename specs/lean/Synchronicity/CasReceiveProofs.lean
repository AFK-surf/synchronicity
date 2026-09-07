import Synchronicity.CasFixtures
import Synchronicity.CasReadPromises
import VerifiedCore.Cas.Receive

/-! Receiving, on the shared simulated host. The execution theorems derive the
row a received slice or proof leaves and the order of the effects around it:
the lease brackets everything, the decoded bytes are flushed before the row
advances to cover them, and exactly the groups the program named are
committed. The fixtures run the same programs on concrete rows, with a
failure injected at each effect, and the promotion on a donor. -/
namespace Synchronicity.CasReceiveProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Cas.Receive SimulatedHost CasFixtures

/-! ## Eligibility -/

/-- A run asked of the donor never overlaps a group this node holds. -/
theorem eligible_disjoint (held : List GroupSpan) (size donorSize : UInt64) (donorHeld : List GroupSpan)
    (subtree : ProvenSubtree) (ok : eligible held size donorSize donorHeld subtree = true) :
    overlaps held subtree.start.toNat (subtree.start.toNat + subtree.groups.toNat) = false := by
  simp only [eligible, Bool.and_eq_true, Bool.not_eq_true'] at ok
  exact ok.1.1.1.1

/-- A run asked of the donor is one the donor holds entirely. -/
theorem eligible_covered (held : List GroupSpan) (size donorSize : UInt64) (donorHeld : List GroupSpan)
    (subtree : ProvenSubtree) (ok : eligible held size donorSize donorHeld subtree = true) :
    covers donorHeld subtree.start.toNat (subtree.start.toNat + subtree.groups.toNat) = true := by
  simp only [eligible, Bool.and_eq_true] at ok
  exact ok.1.2

/-- A multi-group run asked of the donor is a whole subtree: a power of two of
groups, aligned, entirely inside the object. -/
theorem eligible_whole (held : List GroupSpan) (size donorSize : UInt64) (donorHeld : List GroupSpan)
    (subtree : ProvenSubtree) (ok : eligible held size donorSize donorHeld subtree = true)
    (wide : 1 < subtree.groups.toNat) :
    isPowerOfTwo subtree.groups.toNat = true ∧ subtree.start.toNat % subtree.groups.toNat = 0 ∧
      (subtree.start.toNat + subtree.groups.toNat) * 16384 ≤ size.toNat := by
  simp only [eligible, Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq, beq_iff_eq] at ok
  rcases ok.1.1.1.2 with single | whole
  · omega
  · exact ⟨whole.1.1, whole.1.2, whole.2⟩

/-! ## Execution -/

@[simp] theorem throw_eq {A : Type} (error : Error) :
    (throw error : Action A) = ExceptT.mk (Program.pure (.error error)) := rfl

/-- A row that is not there admits any size and any groups. -/
@[simp] theorem fresh_accepted (size : UInt64) (spans : List GroupSpan) :
    (Cas.IngestCommit.plan none size spans).accepted = true := by
  simp [Cas.IngestCommit.plan, planCasCommit, settleSize]

/-- The row a fresh receive commits: what the planner settles for the object
with no prior claim and exactly the named spans. -/
def committed (root : ByteArray) (size : UInt64) (spans : List GroupSpan) (inline : Option ByteArray)
    (now : Int64) (tier : Cas.IngestCommit.Tier) : Fields :=
  let decided := Cas.IngestCommit.plan none size spans
  Cas.IngestCommit.values root size decided.complete
    (if decided.complete || decided.spans.isEmpty then none
      else some (Cas.Codec.encodeRawBitmap decided.spans)) inline now tier

/-- An empty window is answered without taking the lease. -/
theorem slice_of_empty_window (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (empty : window size served = []) :
    let result := SimulatedHost.run (writeSlice root size served 0 now tier) state
    result.1 = .ok [] ∧ result.2.db = state.db ∧ result.2.trace = state.trace := by
  simp [SimulatedHost.run, writeSlice, empty, execute, pure, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- A slice into a store holding nothing of the object, decoded into the
files: the lease brackets the whole, the decode and flush precede the
transaction, and the row commits exactly the window. -/
theorem slice_into_files (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (fresh : rows state.db "blobs" = []) (unleased : state.counters = [])
    (large : ¬ size ≤ inlineMax) (nonempty : window size served ≠ [])
    (verifies : state.decodeSlice root size (Cas.Serve.pairsOf (window size served)) 0 = true)
    (incomplete : (Cas.IngestCommit.plan none size (window size served)).complete = false) :
    let result := SimulatedHost.run (writeSlice root size served 0 now tier) state
    result.1 = .ok (Cas.Serve.pairsOf (window size served)) ∧
    rows result.2.db "blobs" = [committed root size (window size served) none now tier] ∧
    result.2.trace = state.trace ++ ["lease:cas_writers", "snapshot:blobs", "snapshot:blobs",
      "bao:decodeSlice", "bao:flush", "begin", "read:blobs", "upsert:blobs", "commit", "release"] ∧
    counter result.2 ("cas_writers", root) = 0 := by
  simp [SimulatedHost.run, writeSlice, leased, admit, commit, metadata?, settle,
    VerifiedCore.Cas.Receive.access, VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
    Cas.IngestCommit.admit, Cas.IngestCommit.commitGroups, Cas.IngestCommit.commitIn,
    Cas.IngestCommit.decodeClaim, Cas.IngestCommit.claimColumns, committed,
    within, ensure, transactionOver, raise, performOver, Inject.inject, Program.mapEffects,
    execute, Interpreter.handle, storage, SimulatedHost.access, upsert, SimulatedHost.lease,
    SimulatedHost.bao, SimulatedHost.transaction, reply, fault, record, quiet, idle, clean,
    scanFailure, fresh, query, large, nonempty, verifies, fresh_accepted, incomplete, unleased, counter, setCounter,
    upsertRows, Except.mapError, Except.map,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- A small object is decoded into its inline buffer and committed whole. -/
theorem slice_inline (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (buffer : ByteArray) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (fresh : rows state.db "blobs" = []) (small : size ≤ inlineMax)
    (nonempty : window size served ≠ [])
    (decodes : state.decodeInline root size none (Cas.Serve.pairsOf (window size served)) 0 = some buffer) :
    let result := SimulatedHost.run (writeSlice root size served 0 now tier) state
    result.1 = .ok (Cas.Serve.pairsOf (window size served)) ∧
    rows result.2.db "blobs" = [committed root size (window size served) (some buffer) now tier] ∧
    result.2.trace = state.trace ++ ["lease:cas_writers", "snapshot:blobs", "snapshot:blobs",
      "bao:decodeInline", "begin", "read:blobs", "upsert:blobs", "commit", "release"] := by
  simp [SimulatedHost.run, writeSlice, leased, admit, commit, metadata?,
    VerifiedCore.Cas.Receive.access, VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
    Cas.IngestCommit.admit, Cas.IngestCommit.commitGroups, Cas.IngestCommit.commitIn,
    Cas.IngestCommit.decodeClaim, Cas.IngestCommit.claimColumns, committed,
    within, ensure, transactionOver, raise, performOver, Inject.inject, Program.mapEffects,
    execute, Interpreter.handle, storage, SimulatedHost.access, upsert, SimulatedHost.lease,
    SimulatedHost.bao, SimulatedHost.transaction, reply, fault, record, quiet, idle, clean,
    scanFailure, fresh, query, small, nonempty, decodes, fresh_accepted, counter, setCounter,
    upsertRows, Except.mapError, Except.map,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-- A proof with interior nodes records a held-nothing row after its tree is
flushed; one without records nothing. Either way the subtrees it established
are answered. -/
theorem proof_records_held_nothing (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (level : UInt64) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (subtrees : List (UInt64 × UInt64 × ByteArray × Bool))
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (fresh : rows state.db "blobs" = [])
    (verifies : state.proven root size (Cas.Serve.pairsOf (window size served)) level 0 = some (true, subtrees))
    (incomplete : (Cas.IngestCommit.plan none size []).complete = false) :
    let result := SimulatedHost.run (writeProof root size served level 0 now tier) state
    result.1 = .ok (subtrees.map fun (start, groups, cv, whole) => ⟨start, groups, cv, whole⟩) ∧
    rows result.2.db "blobs" = [committed root size [] none now tier] ∧
    result.2.trace = state.trace ++ ["lease:cas_writers", "snapshot:blobs", "bao:writeProof",
      "bao:flush", "begin", "read:blobs", "upsert:blobs", "commit", "release"] := by
  simp [SimulatedHost.run, writeProof, leased, admit, commit,
    VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
    Cas.IngestCommit.admit, Cas.IngestCommit.commitGroups, Cas.IngestCommit.commitIn,
    Cas.IngestCommit.decodeClaim, Cas.IngestCommit.claimColumns, committed,
    within, ensure, transactionOver, raise, performOver, Inject.inject, Program.mapEffects,
    execute, Interpreter.handle, storage, SimulatedHost.access, upsert, SimulatedHost.lease,
    SimulatedHost.bao, SimulatedHost.transaction, reply, fault, record, quiet, idle, clean,
    scanFailure, fresh, query, verifies, fresh_accepted, incomplete, counter, setCounter,
    upsertRows, Except.mapError, Except.map,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

theorem proof_without_nodes_records_nothing (state : State) (root : ByteArray) (size : UInt64)
    (served : List (UInt64 × UInt64)) (level : UInt64) (now : Int64) (tier : Cas.IngestCommit.Tier)
    (subtrees : List (UInt64 × UInt64 × ByteArray × Bool))
    (quiet : state.faults = []) (clean : state.scanFault = none)
    (fresh : rows state.db "blobs" = [])
    (verifies : state.proven root size (Cas.Serve.pairsOf (window size served)) level 0 = some (false, subtrees)) :
    let result := SimulatedHost.run (writeProof root size served level 0 now tier) state
    result.1 = .ok (subtrees.map fun (start, groups, cv, whole) => ⟨start, groups, cv, whole⟩) ∧
    result.2.db = state.db ∧
    result.2.trace = state.trace ++ ["lease:cas_writers", "snapshot:blobs", "bao:writeProof", "release"] := by
  simp [SimulatedHost.run, writeProof, leased, admit,
    VerifiedCore.Cas.Receive.lease, VerifiedCore.Cas.Receive.bao,
    Cas.IngestCommit.admit, Cas.IngestCommit.decodeClaim, Cas.IngestCommit.claimColumns,
    within, ensure, raise, performOver, Inject.inject, Program.mapEffects,
    execute, Interpreter.handle, SimulatedHost.access, SimulatedHost.lease,
    SimulatedHost.bao, reply, fault, record, quiet, clean, scanFailure, fresh, verifies,
    fresh_accepted, counter, setCounter, Except.mapError, Except.map,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-! ## Fixtures -/

private def cv : ByteArray := ⟨Array.replicate 32 7⟩

/-- A three-group object nobody holds yet; the donor is a complete three-group
object whose tree agrees with the run at group 0 only. -/
private def receiving : State :=
  { db := [("blobs", [blob otherRoot 49152])],
    decodeInline := fun _ _ _ _ _ => some bytes,
    decodeSlice := fun _ _ _ _ => true,
    proven := fun _ _ _ _ _ => some (true, [(0, 2, cv, true), (2, 1, cv, false)]),
    agrees := fun _ _ _ start _ _ => start == 0 }

private def sliceTrace := ["lease:cas_writers", "snapshot:blobs", "snapshot:blobs", "bao:decodeSlice",
  "bao:flush", "begin", "read:blobs", "upsert:blobs", "commit"]

theorem slice_commits_the_window :
    let result := SimulatedHost.run (writeSlice root 49152 [(0, 2), (5, 9)] 0 0 .local) receiving
    (result.1, result.2.trace) == (.ok [(0, 2)], sliceTrace ++ ["release"]) ∧
    rows result.2.db "blobs" == [blob otherRoot 49152, committed root 49152 [⟨0, 2⟩] none 0 .local] ∧
    counter result.2 ("cas_writers", root) == 0 := by decide +kernel

theorem slice_completing_the_object_trims_it :
    let result := SimulatedHost.run (writeSlice root 49152 [(0, 3)] 0 0 .local) receiving
    (result.1, result.2.trace) == (.ok [(0, 3)], sliceTrace ++ ["bao:trim", "release"]) ∧
    rows result.2.db "blobs" == [blob otherRoot 49152, committed root 49152 [⟨0, 3⟩] none 0 .local] := by
  decide +kernel

theorem slice_of_a_small_object_is_inline :
    let result := SimulatedHost.run (writeSlice root 4 [(0, 1)] 0 0 .local) receiving
    result.1 == .ok [(0, 1)] ∧
    rows result.2.db "blobs" == [blob otherRoot 49152, committed root 4 [⟨0, 1⟩] (some bytes) 0 .local] := by
  decide +kernel

theorem slice_for_a_complete_row_decodes_nothing :
    let result := SimulatedHost.run (writeSlice otherRoot 49152 [(0, 3)] 0 0 .local) receiving
    (result.1, result.2.trace) ==
      (.ok [], ["lease:cas_writers", "snapshot:blobs", "snapshot:blobs", "release"]) := by decide +kernel

theorem slice_refused_by_the_claim_decodes_nothing :
    let result := SimulatedHost.run (writeSlice otherRoot 100 [(0, 1)] 0 0 .local) receiving
    (result.1, result.2.trace) ==
      (.error (.sizeMismatch otherRoot 49152 100), ["lease:cas_writers", "snapshot:blobs", "release"]) := by
  decide +kernel

/-- A failure at any effect before the commit leaves no row and no lease. -/
theorem every_failed_slice_effect_leaves_no_row_and_no_lease :
    (List.range sliceTrace.length).all (fun index =>
      let result := SimulatedHost.run (writeSlice root 49152 [(0, 2)] 0 0 .local) (fail receiving index)
      failed result.1 && (rows result.2.db "blobs" == [blob otherRoot 49152]) &&
        (counter result.2 ("cas_writers", root) == 0) && result.2.pending.isNone) = true := by
  decide +kernel

private def proofTrace := ["lease:cas_writers", "snapshot:blobs", "bao:writeProof", "bao:flush",
  "begin", "read:blobs", "upsert:blobs", "commit", "release"]

theorem proof_answers_its_subtrees_and_records_a_held_nothing_row :
    let result := SimulatedHost.run (writeProof root 49152 [(0, 3)] 0 0 0 .local) receiving
    (result.1, result.2.trace) == (.ok [⟨0, 2, cv, true⟩, ⟨2, 1, cv, false⟩], proofTrace) ∧
    rows result.2.db "blobs" == [blob otherRoot 49152, committed root 49152 [] none 0 .local] := by
  decide +kernel

theorem every_failed_proof_effect_leaves_no_row_and_no_lease :
    (List.range 8).all (fun index =>
      let result := SimulatedHost.run (writeProof root 49152 [(0, 3)] 0 0 0 .local) (fail receiving index)
      failed result.1 && (rows result.2.db "blobs" == [blob otherRoot 49152]) &&
        (counter result.2 ("cas_writers", root) == 0)) = true := by decide +kernel

private def proven : List ProvenSubtree := [⟨0, 2, cv, true⟩, ⟨2, 1, cv, false⟩]

theorem promotion_asks_only_eligible_runs_and_commits_what_agreed :
    let result := SimulatedHost.run (promote otherRoot root 49152 proven 0 .local) receiving
    (result.1, result.2.trace) == (.ok [(0, 2)],
      ["lease:cas_writers", "snapshot:blobs", "snapshot:blobs", "snapshot:blobs", "bao:promoteRun",
        "bao:promoteRun", "bao:flush", "begin", "read:blobs", "upsert:blobs", "commit", "release"]) ∧
    rows result.2.db "blobs" == [blob otherRoot 49152, committed root 49152 [⟨0, 2⟩] none 0 .local] := by
  decide +kernel

theorem promotion_never_asks_about_a_held_group :
    let holding := { receiving with db := [("blobs", [blob otherRoot 49152,
      blob root 49152 (complete := 0) (bitmap := .blob (Cas.Codec.encodeRawBitmap [⟨0, 2⟩]))])] }
    let result := SimulatedHost.run (promote otherRoot root 49152 proven 0 .local) holding
    (result.1, result.2.trace) == (.ok [],
      ["lease:cas_writers", "snapshot:blobs", "snapshot:blobs", "snapshot:blobs", "bao:promoteRun", "release"]) := by
  decide +kernel

theorem promotion_without_a_donor_row_copies_nothing :
    let result := SimulatedHost.run (promote otherRoot root 49152 proven 0 .local) { receiving with db := [] }
    (result.1, result.2.trace) == (.ok [],
      ["lease:cas_writers", "snapshot:blobs", "snapshot:blobs", "snapshot:blobs", "release"]) := by
  decide +kernel

theorem promotion_of_an_inline_object_takes_no_lease :
    let result := SimulatedHost.run (promote otherRoot root 100 proven 0 .local) receiving
    (result.1, result.2.trace) == (.ok [], []) := by decide +kernel

end Synchronicity.CasReceiveProofs
