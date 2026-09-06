import VerifiedCore.Cas.Read
import Synchronicity.CasPlanProofs

/-! Extensional read guarantees under exact raw file/output effects. -/
namespace Synchronicity.CasReadPromises
open VerifiedCore VerifiedCore.Host VerifiedCore.Cas.Read
noncomputable section
local instance (p : Prop) : Decidable p := Classical.propDecidable p

/-- One stable object's raw observation and physical bytes. Decoding and range
selection are performed by the production program, never by this host. -/
structure Host where
  row : Row
  payload : ByteArray

private def unavailable : Failure := ⟨3, 0⟩

def answer (host : Host) (root : ByteArray) : {A : Type} → Effects A → A
  | _, .left .begin => .error unavailable
  | _, .left (.commit _) => .error unavailable
  | _, .left (.rollback _) => .error unavailable
  | _, .left (.readRows ..) => .error unavailable
  | _, .left (.scanRows ..) => .error unavailable
  | _, .left (.upsert ..) => .error unavailable
  | _, .left (.deleteRows ..) => .error unavailable
  | _, .left (.readBytes ..) => .error unavailable
  | _, .left (.readInput ..) => .error unavailable
  | _, .left (.readCounter ..) => .error unavailable
  | _, .left (.removeFile ..) => .error unavailable
  | _, .left (.existsRows ..) => .error unavailable
  | _, .right (.left (.snapshot selection columns)) =>
      if selection.relation = "blobs" ∧ selection.equals = [("root", .blob root)] ∧
          selection.likeAny = [] ∧
          columns = ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"] then
        .ok ⟨[host.row], none⟩ else .error unavailable
  | _, .right (.left (.update ..)) => .error unavailable
  | _, .right (.left (.copyRows ..)) => .error unavailable
  | _, .right (.left (.delete ..)) => .error unavailable
  | _, .right (.right (.left (.open space key))) =>
      if space = "cas_payload" ∧ key = root then .ok 0 else .error ⟨unavailable, .other⟩
  | _, .right (.right (.left (.readAt _ offset count))) =>
      .ok (host.payload.extract offset.toNat (offset.toNat + count.toNat))
  | _, .right (.right (.left (.transfer ..))) => .ok ()
  | _, .right (.right (.left (.close _))) => .ok ()
  | _, .right (.right (.right (.left .nowNs))) => .error unavailable
  | _, .right (.right (.right (.right (.append _)))) => .ok ()

/-- Output is tracked independently of the terminal count. The file host
copies the physical slice requested by the program, not a predicted result. -/
def emitted (host : Host) : {A : Type} → Effects A → List UInt8
  | _, .right (.right (.left (.transfer _ offset count))) =>
      (host.payload.extract offset.toNat (offset.toNat + count.toNat)).data.toList
  | _, .right (.right (.right (.right (.append bytes)))) => bytes.data.toList
  | _, _ => []

def execute (host : Host) (root : ByteArray) : Program Effects A → A × List UInt8
  | .pure value => (value, [])
  | .request effect resume =>
      let (result, tail) := execute host root (resume (answer host root effect))
      (result, emitted host effect ++ tail)

/-- Only successful completion with the exact count publishes a buffer. This
is the explicit native-output contract, not a claim about the Rust allocator. -/
def publish : Except Error UInt64 × List UInt8 → Except Error (List UInt8)
  | (.error error, _) => .error error
  | (.ok count, bytes) =>
      if count.toNat = bytes.length then .ok bytes else .error .protocol

def run (host : Host) (root : ByteArray) (request : Request) :=
  publish (execute host root (read root request).run)

/-- A failed read never returns a partial answer as success, for any prefix. -/
theorem failed_read_never_returns_partial_success (error : Error) (partialBytes : List UInt8) :
    publish (.error error, partialBytes) = .error error := rfl

/-- Successful command publication is the whole buffer with the stated count. -/
theorem published_result_is_whole (result : Except Error UInt64) (buffer bytes : List UInt8)
    (success : publish (result, buffer) = .ok bytes) :
    buffer = bytes ∧ ∃ count, result = .ok count ∧ count.toNat = bytes.length := by
  cases result with
  | error e => simp [publish] at success
  | ok count =>
    simp only [publish] at success
    split at success
    · cases success
      exact ⟨rfl, count, rfl, by assumption⟩
    · contradiction

/-- Execute any nonempty covered inline range, with no fixture bytes or size. -/
theorem inline_range_execution (host : Host) (root : ByteArray) (row : Metadata)
    (offset length : UInt64) (bytes : ByteArray)
    (decoded : decodeRow host.row = .ok row)
    (inline : row.inline = some bytes)
    (valid : offset.toNat ≤ row.size.toNat)
    (nonempty : offset.toNat ≠ min (offset.toNat + length.toNat) row.size.toNat)
    (available : covered row offset (min (offset.toNat + length.toNat) row.size.toNat).toUInt64 = true)
    (intact : min (offset.toNat + length.toNat) row.size.toNat ≤ bytes.size) :
    execute host root (read root (.range offset length)).run =
      (.ok (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat).toUInt64,
       (bytes.extract offset.toNat (min (offset.toNat + length.toNat) row.size.toNat)).data.toList) := by
  simp [Cas.Read.read, metadata, requestAccess, requestOutput, raise, performOver, Inject.inject,
    execute, answer, emitted, decoded, inline, Nat.not_lt.mpr valid, nonempty, available, Nat.not_lt.mpr intact,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk, Except.mapError]

/-- The file transfer path returns the physical range selected by Lean. -/
theorem file_range_execution (host : Host) (root : ByteArray) (row : Metadata)
    (offset length : UInt64)
    (decoded : decodeRow host.row = .ok row)
    (inline : row.inline = none)
    (valid : offset.toNat ≤ row.size.toNat)
    (nonempty : offset.toNat ≠ min (offset.toNat + length.toNat) row.size.toNat)
    (available : covered row offset (min (offset.toNat + length.toNat) row.size.toNat).toUInt64 = true) :
    execute host root (read root (.range offset length)).run =
      (.ok (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat).toUInt64,
       (host.payload.extract offset.toNat (min (offset.toNat + length.toNat) row.size.toNat)).data.toList) := by
  have bound : min (offset.toNat + length.toNat) row.size.toNat - offset.toNat < UInt64.size :=
    Nat.lt_of_le_of_lt (Nat.le_trans (Nat.sub_le ..) (Nat.min_le_right ..)) row.size.toNat_lt
  have stop : offset.toNat + (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat) =
      min (offset.toNat + length.toNat) row.size.toNat := by omega
  simp [Cas.Read.read, metadata, requestAccess, readPayload, requestFile, observe,
    raise, performOver, Inject.inject, execute, answer, emitted, decoded, inline,
    Nat.not_lt.mpr valid, nonempty, available, bind, pure, Program.bind,
    ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk, Except.mapError,
    UInt64.toNat_ofNat_of_lt' bound, stop]

/-- Empty valid ranges succeed without requiring local availability. -/
theorem empty_range_execution (host : Host) (root : ByteArray) (row : Metadata)
    (offset length : UInt64) (decoded : decodeRow host.row = .ok row)
    (valid : offset.toNat ≤ row.size.toNat)
    (empty : offset.toNat = min (offset.toNat + length.toNat) row.size.toNat) :
    execute host root (read root (.range offset length)).run = (.ok 0, []) := by
  simp only [Cas.Read.read, metadata, requestAccess, raise, performOver, Inject.inject,
    execute, answer, emitted, decoded, Nat.not_lt.mpr valid,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk, Except.mapError, UInt64.ofNat_toNat,
    beq_iff_eq, and_self, if_true, if_false, if_pos empty, List.nil_append]

/-- One representation of intact content; no root/hash correctness is inferred
from metadata alone. Physical storage and inline storage denote the same bytes. -/
def Represents (host : Host) (row : Metadata) (bytes : ByteArray) : Prop :=
  decodeRow host.row = .ok row ∧ row.size.toNat = bytes.size ∧
    (match row.inline with | some inline => inline = bytes | none => host.payload = bytes)

/-- Reading a part returns exactly that part of the represented content. This
includes empty requests, EOF clamping, inline storage and physical transfers. -/
theorem reading_a_part_returns_that_part (host : Host) (root : ByteArray)
    (row : Metadata) (bytes : ByteArray) (offset length : UInt64)
    (represents : Represents host row bytes)
    (valid : offset.toNat ≤ row.size.toNat)
    (available : covered row offset (min (offset.toNat + length.toNat) row.size.toNat).toUInt64 = true) :
    run host root (.range offset length) = .ok
      (bytes.extract offset.toNat (min (offset.toNat + length.toNat) bytes.size)).data.toList := by
  obtain ⟨decoded, size, representation⟩ := represents
  have bound : min (offset.toNat + length.toNat) row.size.toNat - offset.toNat < UInt64.size :=
    Nat.lt_of_le_of_lt (Nat.le_trans (Nat.sub_le ..) (Nat.min_le_right ..)) row.size.toNat_lt
  by_cases empty : offset.toNat = min (offset.toNat + length.toNat) row.size.toNat
  · unfold run
    rw [empty_range_execution host root row offset length decoded valid empty]
    simp [publish, ← size, ← empty]
  · have executed : execute host root (read root (.range offset length)).run =
        (.ok (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat).toUInt64,
         (bytes.extract offset.toNat (min (offset.toNat + length.toNat) row.size.toNat)).data.toList) := by
      cases inline : row.inline with
      | none =>
        simp only [inline] at representation
        simpa [representation] using
          file_range_execution host root row offset length decoded inline valid empty available
      | some value =>
        simp only [inline] at representation
        subst value
        exact inline_range_execution host root row offset length bytes decoded inline valid empty available
          (by omega)
    unfold run
    rw [executed]
    have count : (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat).toUInt64.toNat =
        (bytes.extract offset.toNat (min (offset.toNat + length.toNat) row.size.toNat)).data.toList.length := by
      change (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat).toUInt64.toNat =
        (bytes.extract offset.toNat (min (offset.toNat + length.toNat) row.size.toNat)).size
      rw [UInt64.toNat_ofNat_of_lt' bound, ByteArray.size_extract]
      omega
    simp only [publish]
    rw [if_pos count, size]

/-- A complete local claim covers every byte range inside the recorded size. -/
theorem complete_covers (row : Metadata) (start stop : UInt64)
    (complete : row.complete = true) (inside : stop.toNat ≤ row.size.toNat) :
    covered row start stop = true := by
  unfold covered
  split
  · rfl
  · simp only [List.any_cons, List.any_nil, Bool.or_false,
      Bool.and_eq_true, decide_eq_true_eq]
    constructor
    · omega
    · rw [CasPlanProofs.groupCount_spec]
      split
      · rename_i zero
        simp [zero] at inside
        omega
      · omega

/-- Full and ranged reads share the same executable operation after observation. -/
theorem full_read_is_range (host : Host) (root : ByteArray) (row : Metadata)
    (decoded : decodeRow host.row = .ok row) :
    execute host root (read root .all).run = execute host root (read root (.range 0 row.size)).run := by
  simp [Cas.Read.read, metadata, requestAccess, raise, performOver, Inject.inject,
    execute, answer, emitted, decoded, bind, pure, Program.bind, ExceptT.bind,
    ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk, Except.mapError]

/-- A full read of intact complete content returns that content. -/
theorem full_read_returns_content (host : Host) (root : ByteArray)
    (row : Metadata) (bytes : ByteArray) (represents : Represents host row bytes)
    (complete : row.complete = true) :
    run host root .all = .ok bytes.data.toList := by
  unfold run
  rw [full_read_is_range host root row represents.1]
  change run host root (.range 0 row.size) = _
  have available : covered row 0 (min ((0 : UInt64).toNat + row.size.toNat) row.size.toNat).toUInt64 = true := by
    simpa using complete_covers row 0 row.size complete (Nat.le_refl _)
  have result := reading_a_part_returns_that_part host root row bytes 0 row.size represents
    (by simp) available
  simpa [represents.2.1] using result

/-- Reading a part agrees with reading the whole, in either representation. -/
theorem reading_a_part_agrees_with_reading_the_whole (host : Host) (root : ByteArray)
    (row : Metadata) (bytes : ByteArray) (offset length : UInt64)
    (represents : Represents host row bytes) (complete : row.complete = true)
    (valid : offset.toNat ≤ row.size.toNat) :
    run host root (.range offset length) =
      (run host root .all).map (fun whole =>
        (whole.drop offset.toNat).take (min (offset.toNat + length.toNat) whole.length - offset.toNat)) := by
  rw [full_read_returns_content host root row bytes represents complete,
    reading_a_part_returns_that_part host root row bytes offset length represents valid]
  · simp only [Except.map, ByteArray.data_extract, Array.toList_extract]
    rfl
  · apply complete_covers row _ _ complete
    rw [UInt64.toNat_ofNat_of_lt' (Nat.lt_of_le_of_lt (Nat.min_le_right ..) row.size.toNat_lt)]
    exact Nat.min_le_right ..

end
end Synchronicity.CasReadPromises
