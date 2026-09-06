import Synchronicity.CasFixtures
import VerifiedCore.Cas.Project

/-! The projections of the content store, executed on the shared simulated
host: what a row decodes to and how a bad one is refused, that the joined
pin state is merged onto exactly the rows it belongs to, what a holder
spelling means, and the ordered listings on concrete rows with a failure
injected at every effect. -/
namespace Synchronicity.CasProjectProofs
open VerifiedCore.Host VerifiedCore.Cas VerifiedCore.Cas.Project SimulatedHost CasFixtures

/-! ## Row decoding -/

/-- A well-typed row decodes to its cells, unpinned until the join says otherwise. -/
theorem decodeBlob_of_typed (root : ByteArray) (size complete lastAccess durable : Int64)
    (bitmap inline : Option ByteArray) (width : root.size = 32) :
    decodeBlob [.blob root, .integer size, .integer complete, bitmap.elim .null .blob,
      inline.elim .null .blob, .integer lastAccess, .integer durable] =
      .ok ⟨root, size.toUInt64, complete != 0, durable != 0, bitmap, inline, false, lastAccess⟩ := by
  cases bitmap <;> cases inline <;>
    simp [decodeBlob, blobField, integerField, optionalBlobField, VerifiedCore.Cas.Codec.blobField,
      VerifiedCore.Cas.Codec.integerField, VerifiedCore.Cas.Codec.optionalBlobField, width, bind, pure,
      Except.bind, Except.pure]

/-- A column of the wrong class is refused by its position and name, before
the root's width is looked at. -/
theorem decodeBlob_refuses_a_text_size (root : ByteArray) (size : String) (a b c d e : Cell) :
    decodeBlob [.blob root, .text size, a, b, c, d, e] = .error (.columnType 1 "size" .text) := by
  simp [decodeBlob, blobField, integerField, VerifiedCore.Cas.Codec.blobField,
    VerifiedCore.Cas.Codec.integerField, VerifiedCore.Cas.Codec.cellType, bind, Except.bind]

/-- A root of the wrong width is refused by name, once every field is typed. -/
theorem decodeBlob_refuses_a_short_root (root : ByteArray) (size complete lastAccess durable : Int64)
    (narrow : root.size ≠ 32) :
    decodeBlob [.blob root, .integer size, .integer complete, .null, .null, .integer lastAccess,
      .integer durable] = .error (.column "blobs.root" (toString root.size ++ " bytes, not 32")) := by
  simp [decodeBlob, blobField, integerField, optionalBlobField, VerifiedCore.Cas.Codec.blobField,
    VerifiedCore.Cas.Codec.integerField, VerifiedCore.Cas.Codec.optionalBlobField, narrow, bind, pure,
    Except.bind, Except.pure]
  rfl

/-- A row of the wrong width is malformed metadata. -/
theorem decodeBlob_refuses_a_narrow_row (root : ByteArray) :
    decodeBlob [.blob root] = .error .malformed := by simp [decodeBlob]

/-! ## The pin merge -/

/-- The loop behind `span`: a run of the key is consumed whole, and stops at
the first foreign element. -/
theorem span_loop_replicate (a : ByteArray) (n : Nat) (rest acc : List ByteArray)
    (foreign : ∀ x ∈ rest, (x == a) = false) :
    List.span.loop (· == a) (List.replicate n a ++ rest) acc = (acc.reverse ++ List.replicate n a, rest) := by
  induction n generalizing acc with
  | zero =>
    cases rest with
    | nil => simp [List.span.loop]
    | cons head tail => simp [List.span.loop, foreign head (List.mem_cons_self ..)]
  | succ n ih =>
    simp only [List.replicate_succ, List.cons_append, List.span.loop, beq_self_eq_true]
    rw [ih (a :: acc)]
    simp

theorem span_replicate (a : ByteArray) (n : Nat) (rest : List ByteArray)
    (foreign : ∀ x ∈ rest, (x == a) = false) :
    (List.replicate n a ++ rest).span (· == a) = (List.replicate n a, rest) := by
  simpa [List.span] using span_loop_replicate a n rest [] foreign

theorem not_isEmpty_replicate (a : ByteArray) (n : Nat) :
    (!(List.replicate n a).isEmpty) = (n != 0) := by
  cases n <;> simp [List.replicate_succ]

/-- The join lists each row's root once per claim, in the rows' order. Merged
in one pass, every row is marked pinned exactly when it has a claim, given
that roots are distinct, as a primary key's are. -/
theorem markPinned_marks_exactly {A : Type} (mark : A → Bool → A) (root : A → ByteArray)
    (count : A → Nat) (rows : List A) (distinct : (rows.map root).Nodup) :
    markPinned mark root rows (rows.flatMap fun row => List.replicate (count row) (root row)) =
      rows.map fun row => mark row (count row != 0) := by
  induction rows with
  | nil => rfl
  | cons row rest ih =>
    simp only [List.map_cons, List.nodup_cons] at distinct
    have foreign : ∀ x ∈ rest.flatMap (fun row => List.replicate (count row) (root row)), (x == root row) = false := by
      intro x member
      obtain ⟨other, present, hit⟩ := List.mem_flatMap.mp member
      rw [List.eq_of_mem_replicate hit]
      exact beq_eq_false_iff_ne.mpr fun same => distinct.1 (same ▸ List.mem_map_of_mem present)
    simp only [List.flatMap_cons, markPinned, span_replicate _ _ _ foreign, not_isEmpty_replicate,
      List.map_cons, ih distinct.2]

/-! ## Distinct roots -/

/-- Dropping adjacent duplicates keeps exactly the roots that were there. -/
theorem mem_distinctSorted (roots : List ByteArray) (root : ByteArray) :
    root ∈ distinctSorted roots ↔ root ∈ roots := by
  induction roots with
  | nil => simp [distinctSorted]
  | cons head tail ih =>
    simp only [distinctSorted]
    split
    · rename_i next others sorted
      rw [sorted] at ih
      split
      · rename_i same
        have eq : next = head := eq_of_beq same
        subst eq
        rw [ih, List.mem_cons]
        constructor
        · exact Or.inr
        · rintro (rfl | member)
          · exact ih.mp (List.mem_cons_self ..)
          · exact member
      · rw [List.mem_cons, ih, List.mem_cons]
    · rename_i sorted
      rw [sorted] at ih
      rw [List.mem_singleton, List.mem_cons, ← ih]
      simp

/-! ## Holder spellings -/

theorem parse_operator : PinHolder.parse "operator" = .operator := by decide
theorem parse_source : PinHolder.parse "source:media" = .source "media" := by decide
theorem parse_replica_keeps_colons : PinHolder.parse "replica:a:b" = .replica "a:b" := by decide
theorem parse_empty_space_is_unknown : PinHolder.parse "source:" = .other "source:" := by decide
theorem parse_unknown_spelling_is_kept : PinHolder.parse "future:x" = .other "future:x" := by decide
theorem parse_bare_word_is_kept : PinHolder.parse "operators" = .other "operators" := by decide

/-! ## One object's row on the simulated host -/

/-- No row: nothing is asked of the pins, and the answer is `none`. -/
theorem blob_absent (state : State) (root : ByteArray)
    (quiet : state.faults = []) (idle : state.pending = none)
    (absent : query state.db "blobs" blobColumns [("root", .blob root)] [] [] = []) :
    let result := SimulatedHost.run (VerifiedCore.Cas.Project.blob root) state
    result.1 = .ok none ∧ result.2.db = state.db ∧
      result.2.trace = state.trace ++ ["begin", "read:blobs", "commit"] := by
  simp [SimulatedHost.run, VerifiedCore.Cas.Project.blob, VerifiedCore.Cas.Project.read,
    VerifiedCore.Cas.Project.transaction, transactionWith, transactionOver,
    VerifiedCore.Cas.Project.storage, performWith, execute, Interpreter.handle, SimulatedHost.storage,
    reply, fault, record, SimulatedHost.transaction, quiet, idle, absent,
    Except.mapError, Except.pure, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]

/-- One row: it is decoded as the read path decodes it, and its pin state is
whatever claim stands on the root in the same transaction. -/
theorem blob_present (state : State) (root : ByteArray) (row : Row) (decoded : Blob)
    (quiet : state.faults = []) (idle : state.pending = none)
    (observed : query state.db "blobs" blobColumns [("root", .blob root)] [] [] = [row])
    (typed : decodeBlob row = .ok decoded) :
    let result := SimulatedHost.run (VerifiedCore.Cas.Project.blob root) state
    result.1 = .ok (some { decoded with
      pinned := (rows state.db "pins").any (fun pin => equals pin [("root", .blob root)]) }) ∧
      result.2.db = state.db := by
  simp [SimulatedHost.run, VerifiedCore.Cas.Project.blob, VerifiedCore.Cas.Project.read,
    VerifiedCore.Cas.Project.transaction, transactionWith, transactionOver,
    VerifiedCore.Cas.Project.storage, performWith, execute, Interpreter.handle, SimulatedHost.storage,
    reply, fault, record, SimulatedHost.transaction, quiet, idle, observed, typed,
    Except.mapError, Except.pure, Except.bind, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]

/-! ## Fixtures -/

private def thirdRoot : ByteArray := ⟨Array.replicate 32 2⟩

private def row (key : ByteArray) (accessed : Int64) (inline : Cell := .null) : Fields :=
  [("root", .blob key), ("size", .integer 4), ("complete", .integer 1), ("bitmap", .null),
   ("inline", inline), ("last_access", .integer accessed), ("durable", .integer 0)]

private def projected (key : ByteArray) (accessed : Int64) (pinned : Bool) (inline : Option ByteArray := none) : Blob :=
  ⟨key, 4, true, false, none, inline, pinned, accessed⟩

/-- Three objects, the middle one pinned twice, the last inline. -/
private def stocked : State :=
  { db := [("blobs", [row root 10, row otherRoot 30, row thirdRoot 20 (inline := .blob bytes)]),
      ("pins", [pin otherRoot "source:media", pin otherRoot "operator", pin thirdRoot "future:x"])] }

theorem rows_are_listed_most_recent_first_with_their_pin_state :
    let result := SimulatedHost.run blobs stocked
    (result.1, result.2.trace) == (.ok [projected otherRoot 30 true, projected thirdRoot 20 true (some bytes),
      projected root 10 false], ["begin", "read:blobs", "read:blobs", "commit"]) := by decide +kernel

theorem summaries_carry_the_same_order_and_pin_state :
    let result := SimulatedHost.run candidates stocked
    result.1 == .ok [⟨otherRoot, 4, true, false, true, 30⟩, ⟨thirdRoot, 4, true, false, true, 20⟩,
      ⟨root, 4, true, false, false, 10⟩] := by decide +kernel

theorem one_row_reads_its_pin_state :
    let result := SimulatedHost.run (VerifiedCore.Cas.Project.blob otherRoot) stocked
    (result.1, result.2.trace) == (.ok (some (projected otherRoot 30 true)),
      ["begin", "read:blobs", "exists:pins", "commit"]) := by decide +kernel

theorem an_absent_row_is_none :
    let result := SimulatedHost.run (VerifiedCore.Cas.Project.blob ⟨Array.replicate 32 9⟩) stocked
    (result.1, result.2.trace) == (.ok none, ["begin", "read:blobs", "commit"]) := by decide +kernel

theorem claims_are_listed_by_object_then_holder_and_unknown_spellings_are_kept :
    let result := SimulatedHost.run (pins none) stocked
    result.1 == .ok [⟨otherRoot, .operator, 7, none⟩, ⟨otherRoot, .source "media", 7, none⟩,
      ⟨thirdRoot, .other "future:x", 7, none⟩] := by decide +kernel

theorem claims_on_one_object_are_only_its_own :
    let result := SimulatedHost.run (pins (some thirdRoot)) stocked
    result.1 == .ok [⟨thirdRoot, .other "future:x", 7, none⟩] := by decide +kernel

theorem pinned_roots_are_distinct_and_ordered :
    let result := SimulatedHost.run pinnedBlobs stocked
    result.1 == .ok [otherRoot, thirdRoot] := by decide +kernel

theorem a_mistyped_row_is_refused_by_its_column :
    let broken := { stocked with db := [("blobs", [[("root", .blob root), ("size", .text "nine"),
      ("complete", .integer 1), ("bitmap", .null), ("inline", .null), ("last_access", .integer 0),
      ("durable", .integer 0)]])] }
    let result := SimulatedHost.run blobs broken
    (result.1, result.2.trace) == (.error (.columnType 1 "size" .text), ["begin", "read:blobs", "rollback"]) := by
  decide +kernel

/-- A failure at any effect ends the read with no transaction left open. -/
theorem every_failed_projection_effect_rolls_back :
    (List.range 4).all (fun index =>
      let result := SimulatedHost.run blobs (fail stocked index)
      failed result.1 && result.2.pending.isNone && (result.2.db == stocked.db)) = true := by decide +kernel

end Synchronicity.CasProjectProofs
