import Synchronicity.CasFixtures
import Synchronicity.CasReadPromises
import VerifiedCore.Cas.Serve

/-! Serving, on the shared simulated host. The window lemmas are about the
executable window computation: every group the program asks the Bao service
to serve was asked for, is held by the row and lies within the object, and a
slice window never exceeds one exchange. The execution theorems show what
the program requests and publishes in each case; the fixtures run it on
concrete rows with a failure injected at each effect. -/
namespace Synchronicity.CasServeProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Cas.Serve SimulatedHost CasFixtures

/-! ## The window -/

theorem overlap_bounds (left right span : GroupSpan) (hit : overlap left right = some span) :
    left.start ≤ span.start ∧ span.stop ≤ left.stop ∧
    right.start ≤ span.start ∧ span.stop ≤ right.stop ∧ span.start < span.stop := by
  unfold overlap at hit
  by_cases proper : max left.start right.start < min left.stop right.stop
  · rw [if_pos proper] at hit
    cases hit
    exact ⟨Nat.le_max_left _ _, Nat.min_le_left _ _, Nat.le_max_right _ _, Nat.min_le_right _ _, proper⟩
  · rw [if_neg proper] at hit
    cases hit

/-- A group of the intersection is a group of both sides. -/
theorem intersect_contains (left right : List GroupSpan) (group : Nat)
    (inside : spansContain (intersect left right) group = true) :
    spansContain left group = true ∧ spansContain right group = true := by
  simp only [spansContain, intersect, List.any_eq_true, List.mem_flatMap, List.mem_filterMap,
    Bool.and_eq_true, decide_eq_true_eq] at inside ⊢
  obtain ⟨span, ⟨a, aMember, b, bMember, hit⟩, low, high⟩ := inside
  have bounds := overlap_bounds a b span hit
  exact ⟨⟨a, aMember, by omega, by omega⟩, ⟨b, bMember, by omega, by omega⟩⟩

/-- Taking a budget of groups never adds a group. -/
theorem takeGroups_contains (budget : Nat) (spans : List GroupSpan) (group : Nat)
    (inside : spansContain (takeGroups budget spans) group = true) :
    spansContain spans group = true := by
  induction spans generalizing budget with
  | nil => simp [takeGroups, spansContain] at inside
  | cons span rest ih =>
    cases budget with
    | zero => simp [takeGroups, spansContain] at inside
    | succ remaining =>
      simp only [takeGroups] at inside
      split at inside
      · simp only [spansContain, List.any_cons, Bool.or_eq_true] at inside ⊢
        rcases inside with head | tail
        · exact Or.inl head
        · exact Or.inr (ih _ tail)
      · simp only [spansContain, List.any_cons, List.any_nil, Bool.or_false, Bool.or_eq_true,
          Bool.and_eq_true, decide_eq_true_eq] at inside ⊢
        left
        omega

/-- How many groups a span list covers, counting each run. -/
def groupsOf (spans : List GroupSpan) : Nat := (spans.map fun span => span.stop - span.start).sum

theorem takeGroups_le (budget : Nat) (spans : List GroupSpan) :
    groupsOf (takeGroups budget spans) ≤ budget := by
  induction spans generalizing budget with
  | nil => simp [takeGroups, groupsOf]
  | cons span rest ih =>
    cases budget with
    | zero => simp [takeGroups, groupsOf]
    | succ remaining =>
      simp only [takeGroups]
      split
      · have tail := ih (remaining + 1 - (span.stop - span.start))
        simp only [groupsOf, List.map_cons, List.sum_cons] at tail ⊢
        omega
      · simp only [groupsOf, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil]
        omega

/-- Every group of what is wanted was requested, is held by the row and lies
within the object. -/
theorem wanted_sound (row : Cas.Read.Metadata) (requested : List GroupSpan) (group : Nat)
    (inside : spansContain (wanted row requested) group = true) :
    spansContain requested group = true ∧ spansContain (held row) group = true ∧
      group < (groupCount row.size).toNat := by
  unfold wanted at inside
  obtain ⟨inner, bound⟩ := (CasPlanProofs.normalize_spans_membership _ _ _).mp inside
  obtain ⟨left, right⟩ := intersect_contains _ _ _ inner
  exact ⟨left, right, bound⟩

/-- A slice window serves only wanted groups, and at most one exchange's worth. -/
theorem window_sound (row : Cas.Read.Metadata) (requested : List GroupSpan) (group : Nat)
    (inside : spansContain (takeGroups maxSliceGroups (wanted row requested)) group = true) :
    spansContain requested group = true ∧ spansContain (held row) group = true ∧
      group < (groupCount row.size).toNat :=
  wanted_sound row requested group (takeGroups_contains _ _ _ inside)

theorem window_bounded (row : Cas.Read.Metadata) (requested : List GroupSpan) :
    groupsOf (takeGroups maxSliceGroups (wanted row requested)) ≤ maxSliceGroups :=
  takeGroups_le _ _

/-- A complete row holds every group of the object and nothing beyond it. -/
theorem held_complete (row : Cas.Read.Metadata) (complete : row.complete = true) (group : Nat) :
    spansContain (held row) group = true ↔ group < (groupCount row.size).toNat := by
  simp [held, complete, spansContain]

/-! ## Execution -/

/-- A refusal is the program's own terminal, not an effect. -/
@[simp] theorem throw_eq {A : Type} (error : Error) :
    (throw error : Action A) = ExceptT.mk (Program.pure (.error error)) := rfl

/-- The serve statement is the read statement: the same raw rows. -/
theorem serve_observes_like_read (state : State) (root : ByteArray) :
    ((rows state.db "blobs").filter (selects ⟨"blobs", [("root", .blob root)], [], []⟩)).map
      (project ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"]) =
    CasReadPromises.observation state root := rfl

/-- No row: refused before the Bao service is asked anything. -/
theorem slice_of_missing_row (state : State) (root : ByteArray) (requested : List (UInt64 × UInt64))
    (quiet : state.faults = []) (clean : state.scanFault = none)
    (absent : CasReadPromises.observation state root = []) :
    let result := SimulatedHost.run (encodeSlice root requested) state
    result.1 = .error .missingBlob ∧ result.2.output = [] ∧
      result.2.trace = state.trace ++ ["snapshot:blobs"] := by
  unfold CasReadPromises.observation at absent
  simp [SimulatedHost.run, encodeSlice, metadata, VerifiedCore.Cas.Serve.access, raise, performOver,
    Inject.inject, execute, Interpreter.handle, SimulatedHost.access, reply, fault, record, quiet,
    absent, clean, scanFailure, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk, Except.mapError]

/-- An empty window is served as nothing, without asking the Bao service. -/
theorem slice_of_empty_window (state : State) (root : ByteArray) (requested : List (UInt64 × UInt64))
    (row : Cas.Read.Metadata) (raw : Row) (rest : List Row) (quiet : state.faults = [])
    (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row)
    (empty : takeGroups maxSliceGroups (wanted row (spansOf requested)) = []) :
    let result := SimulatedHost.run (encodeSlice root requested) state
    result.1 = .ok ⟨0, []⟩ ∧ result.2.output = [] ∧
      result.2.trace = state.trace ++ ["snapshot:blobs"] := by
  unfold CasReadPromises.observation at observed
  simp [SimulatedHost.run, encodeSlice, metadata, VerifiedCore.Cas.Serve.access, raise, performOver,
    Inject.inject, execute, Interpreter.handle, SimulatedHost.access, reply, fault, record, quiet,
    observed, decoded, empty, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk, Except.mapError]

/-- A nonempty window is served by asking the Bao service for exactly that
window; the published bytes are its encoding and the answer names the window. -/
theorem slice_of_window (state : State) (root : ByteArray) (requested : List (UInt64 × UInt64))
    (row : Cas.Read.Metadata) (raw : Row) (rest : List Row) (quiet : state.faults = [])
    (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row)
    (nonempty : takeGroups maxSliceGroups (wanted row (spansOf requested)) ≠ []) :
    let window := takeGroups maxSliceGroups (wanted row (spansOf requested))
    let encoded := state.slice root row.size row.inline (pairsOf window)
    let result := SimulatedHost.run (encodeSlice root requested) state
    result.1 = .ok ⟨encoded.size.toUInt64, pairsOf window⟩ ∧
      result.2.output = encoded.data.toList ∧
      result.2.trace = state.trace ++ ["snapshot:blobs", "bao:slice"] := by
  unfold CasReadPromises.observation at observed
  simp [SimulatedHost.run, encodeSlice, metadata, VerifiedCore.Cas.Serve.access,
    VerifiedCore.Cas.Serve.bao, raise, performOver, Inject.inject, execute, Interpreter.handle,
    SimulatedHost.access, SimulatedHost.bao, reply, fault, record, quiet, observed, decoded, nonempty,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk,
    Except.mapError]

/-- A single-group object has no interior nodes: nothing is asked or served. -/
theorem proof_of_single_group (state : State) (root : ByteArray) (requested : List (UInt64 × UInt64))
    (level budget : UInt64) (row : Cas.Read.Metadata) (raw : Row) (rest : List Row)
    (quiet : state.faults = []) (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row) (single : groupCount row.size ≤ 1) :
    let result := SimulatedHost.run (encodeProof root requested level budget) state
    result.1 = .ok ⟨0, pairsOf (wanted row (spansOf requested))⟩ ∧ result.2.output = [] ∧
      result.2.trace = state.trace ++ ["snapshot:blobs"] := by
  unfold CasReadPromises.observation at observed
  simp [SimulatedHost.run, encodeProof, metadata, VerifiedCore.Cas.Serve.access, raise, performOver,
    Inject.inject, execute, Interpreter.handle, SimulatedHost.access, reply, fault, record, quiet,
    observed, decoded, single, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk, Except.mapError]

/-- A proof that fits is served for exactly the wanted groups. -/
theorem proof_served (state : State) (root : ByteArray) (requested : List (UInt64 × UInt64))
    (level budget : UInt64) (row : Cas.Read.Metadata) (raw : Row) (rest : List Row)
    (encoded : ByteArray) (quiet : state.faults = [])
    (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row)
    (nonempty : wanted row (spansOf requested) ≠ []) (many : ¬ groupCount row.size ≤ 1)
    (fits : state.proof root row.size (pairsOf (wanted row (spansOf requested))) level budget = some encoded) :
    let result := SimulatedHost.run (encodeProof root requested level budget) state
    result.1 = .ok ⟨encoded.size.toUInt64, pairsOf (wanted row (spansOf requested))⟩ ∧
      result.2.output = encoded.data.toList ∧
      result.2.trace = state.trace ++ ["snapshot:blobs", "bao:proof"] := by
  unfold CasReadPromises.observation at observed
  simp [SimulatedHost.run, encodeProof, metadata, VerifiedCore.Cas.Serve.access,
    VerifiedCore.Cas.Serve.bao, raise, performOver, Inject.inject, execute, Interpreter.handle,
    SimulatedHost.access, SimulatedHost.bao, reply, fault, record, quiet, observed, decoded, nonempty,
    many, fits, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run,
    ExceptT.mk, Except.mapError]

/-- A proof past the budget is refused whole: nothing is published. -/
theorem proof_refused_whole (state : State) (root : ByteArray) (requested : List (UInt64 × UInt64))
    (level budget : UInt64) (row : Cas.Read.Metadata) (raw : Row) (rest : List Row)
    (quiet : state.faults = []) (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row)
    (nonempty : wanted row (spansOf requested) ≠ []) (many : ¬ groupCount row.size ≤ 1)
    (over : state.proof root row.size (pairsOf (wanted row (spansOf requested))) level budget = none) :
    let result := SimulatedHost.run (encodeProof root requested level budget) state
    result.1 = .error (.overBudget level budget) ∧ result.2.output = [] := by
  unfold CasReadPromises.observation at observed
  simp [SimulatedHost.run, encodeProof, metadata, VerifiedCore.Cas.Serve.access,
    VerifiedCore.Cas.Serve.bao, raise, performOver, Inject.inject, execute, Interpreter.handle,
    SimulatedHost.access, SimulatedHost.bao, reply, fault, record, quiet, observed, decoded, nonempty,
    many, over, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run,
    ExceptT.mk, Except.mapError]

/-! ## Fixtures -/

private def encodedSlice : ByteArray := ⟨#[9, 9, 9]⟩

/-- A three-group complete object; the proof service fits two nodes or more. -/
private def serving : State :=
  { db := [("blobs", [blob root 40000])],
    slice := fun _ _ _ _ => encodedSlice,
    proof := fun _ _ _ _ budget => if budget < 2 then none else some ⟨#[1]⟩ }

/-- A twenty-group object holding groups 2–5 and 10–19 out of line. -/
private def partialRow : State :=
  { serving with db := [("blobs", [blob root 327680 (complete := 0)
      (bitmap := .blob (Cas.Codec.encodeRawBitmap [⟨2, 6⟩, ⟨10, 30⟩]))])] }

theorem slice_of_a_complete_object :
    let result := SimulatedHost.run (encodeSlice root [(0, 10)]) serving
    (result.1, result.2.output, result.2.trace) ==
      (.ok ⟨3, [(0, 3)]⟩, [9, 9, 9], ["snapshot:blobs", "bao:slice"]) := by decide +kernel

theorem slice_outside_the_object_serves_nothing :
    let result := SimulatedHost.run (encodeSlice root [(5, 9)]) serving
    (result.1, result.2.output, result.2.trace) == (.ok ⟨0, []⟩, [], ["snapshot:blobs"]) := by
  decide +kernel

theorem slice_of_a_partial_row_serves_what_the_bitmap_covers :
    let result := SimulatedHost.run (encodeSlice root [(0, 100)]) partialRow
    result.1 == .ok ⟨3, [(2, 6), (10, 20)]⟩ := by decide +kernel

theorem slice_window_is_one_exchange :
    let large := { serving with db := [("blobs", [blob root 9830400])] }
    let result := SimulatedHost.run (encodeSlice root [(1, 3), (4, 100000)]) large
    result.1 == .ok ⟨3, [(1, 3), (4, 514)]⟩ := by decide +kernel

theorem slice_of_a_missing_row_is_refused_before_any_encoding :
    let result := SimulatedHost.run (encodeSlice otherRoot [(0, 10)]) serving
    (result.1, result.2.output, result.2.trace) == (.error .missingBlob, [], ["snapshot:blobs"]) := by
  decide +kernel

theorem proof_of_a_single_group_object_is_empty :
    let result := SimulatedHost.run (encodeProof root [(0, 5)] 0 8) { serving with db := [("blobs", [blob])] }
    (result.1, result.2.output, result.2.trace) == (.ok ⟨0, [(0, 1)]⟩, [], ["snapshot:blobs"]) := by
  decide +kernel

theorem proof_is_served_for_the_wanted_groups :
    let result := SimulatedHost.run (encodeProof root [(1, 10)] 0 8) serving
    (result.1, result.2.output, result.2.trace) ==
      (.ok ⟨1, [(1, 3)]⟩, [1], ["snapshot:blobs", "bao:proof"]) := by decide +kernel

theorem proof_past_the_budget_is_refused_whole :
    let result := SimulatedHost.run (encodeProof root [(0, 10)] 0 1) serving
    (result.1, result.2.output) == (.error (.overBudget 0 1), []) := by decide +kernel

theorem every_failed_serving_effect_publishes_nothing :
    (List.range 2).all (fun index =>
      let slice := SimulatedHost.run (encodeSlice root [(0, 10)]) (fail serving index)
      let proof := SimulatedHost.run (encodeProof root [(0, 10)] 0 8) (fail serving index)
      failed slice.1 && slice.2.output.isEmpty && failed proof.1 && proof.2.output.isEmpty) = true := by
  decide +kernel

end Synchronicity.CasServeProofs
