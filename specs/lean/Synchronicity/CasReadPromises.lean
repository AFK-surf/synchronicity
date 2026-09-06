import Synchronicity.SimulatedHost
import Synchronicity.CasPlanProofs
import VerifiedCore.Cas.Read

/-! Read laws over the common simulated host's raw database and file store. -/
namespace Synchronicity.CasReadPromises
open VerifiedCore VerifiedCore.Host VerifiedCore.Cas.Read SimulatedHost

/-- Raw rows selected by the read operation's actual snapshot statement. -/
def observation (state : State) (root : ByteArray) : List Row :=
  ((rows state.db "blobs").filter (selects ⟨"blobs", [("root", .blob root)], []⟩)).map
    (project ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"])

/-- The database decodes to this metadata and the selected backing storage
contains the represented bytes. No separate read-host state is constructed. -/
def Represents (state : State) (root : ByteArray) (row : Metadata) (bytes : ByteArray) : Prop :=
  (∃ raw rest, observation state root = raw :: rest ∧ decodeRow raw = .ok row) ∧
  row.size.toNat = bytes.size ∧
  (match row.inline with
    | some inline => inline = bytes
    | none => lookupFile state.files ("cas_payload", root) = some bytes)

def readResult (state : State) (root : ByteArray) (request : Request) : Except Error (List UInt8) :=
  let result := SimulatedHost.run (read root request) state
  publish Error.protocol result.1 result.2

/-- Publication uses the shared host's private buffer, for any failure/prefix. -/
theorem failed_read_never_returns_partial_success (error : Error) (state : State) :
    publish Error.protocol (.error error) state = .error error := rfl

theorem published_result_is_whole (result : Except Error UInt64) (state : State) (bytes : List UInt8)
    (success : publish Error.protocol result state = .ok bytes) :
    state.output = bytes ∧ ∃ count, result = .ok count ∧ count.toNat = bytes.length := by
  cases result with
  | error e => simp [publish] at success
  | ok count =>
    simp only [publish] at success
    split at success
    · cases success; exact ⟨rfl, count, rfl, by assumption⟩
    · contradiction

/-- Empty requests are answered using metadata alone. -/
theorem empty_range_execution (state : State) (root : ByteArray) (row : Metadata)
    (raw : Row) (rest : List Row) (offset length : UInt64)
    (quiet : state.faults = []) (observed : observation state root = raw :: rest)
    (decoded : decodeRow raw = .ok row) (valid : offset.toNat ≤ row.size.toNat)
    (empty : offset.toNat = min (offset.toNat + length.toNat) row.size.toNat) :
    let result := execute (read root (.range offset length)).run state
    (result.1, result.2.output) = (.ok 0, state.output) := by
  unfold observation at observed
  simp only [Cas.Read.read, metadata, requestAccess, raise, performOver, Inject.inject,
    execute, Interpreter.handle, access, reply, fault, record, quiet, List.find?_nil,
    Option.map_none, observed, decoded, Nat.not_lt.mpr valid,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk, Except.mapError, UInt64.ofNat_toNat,
    beq_iff_eq, if_false, if_pos empty]

/-- A nonempty available range appends exactly the selected stored bytes. -/
theorem range_execution (state : State) (root : ByteArray) (row : Metadata)
    (bytes : ByteArray) (offset length : UInt64)
    (quiet : state.faults = []) (represents : Represents state root row bytes)
    (valid : offset.toNat ≤ row.size.toNat)
    (nonempty : offset.toNat ≠ min (offset.toNat + length.toNat) row.size.toNat)
    (available : covered row offset (min (offset.toNat + length.toNat) row.size.toNat).toUInt64 = true) :
    let result := execute (read root (.range offset length)).run state
    (result.1, result.2.output) =
      (.ok (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat).toUInt64,
       state.output ++ (bytes.extract offset.toNat (min (offset.toNat + length.toNat) row.size.toNat)).data.toList) := by
  obtain ⟨⟨raw, rest, observed, decoded⟩, size, representation⟩ := represents
  unfold observation at observed
  have intact : min (offset.toNat + length.toNat) row.size.toNat ≤ bytes.size := by omega
  have bound : min (offset.toNat + length.toNat) row.size.toNat - offset.toNat < UInt64.size :=
    Nat.lt_of_le_of_lt (Nat.le_trans (Nat.sub_le ..) (Nat.min_le_right ..)) row.size.toNat_lt
  have stop : offset.toNat + (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat) =
      min (offset.toNat + length.toNat) row.size.toNat := by omega
  cases inline : row.inline with
  | some value =>
    simp only [inline] at representation
    subst value
    simp [Cas.Read.read, metadata, requestAccess, requestOutput, raise, performOver, Inject.inject,
      execute, Interpreter.handle, access, SimulatedHost.output, reply, fault, record, quiet,
      observed, decoded, inline, Nat.not_lt.mpr valid, nonempty, available, Nat.not_lt.mpr intact,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
      ExceptT.run, ExceptT.mk, Except.mapError]
  | none =>
    simp only [inline] at representation
    simp [Cas.Read.read, metadata, requestAccess, readPayload, requestFile, observe, raise,
      performOver, Inject.inject, execute, Interpreter.handle, access, file, fileReply, opened,
      reply, fault, record, quiet, observed, decoded, inline, representation,
      Nat.not_lt.mpr valid, nonempty, available, UInt64.toNat_ofNat_of_lt' bound, stop, intact,
      bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
      ExceptT.run, ExceptT.mk, Except.mapError]

/-- Reading a part returns exactly that part, with no host/state conversion. -/
theorem reading_a_part_returns_that_part (state : State) (root : ByteArray)
    (row : Metadata) (bytes : ByteArray) (offset length : UInt64)
    (quiet : state.faults = []) (represents : Represents state root row bytes)
    (valid : offset.toNat ≤ row.size.toNat)
    (available : covered row offset (min (offset.toNat + length.toNat) row.size.toNat).toUInt64 = true) :
    readResult state root (.range offset length) = .ok
      (bytes.extract offset.toNat (min (offset.toNat + length.toNat) bytes.size)).data.toList := by
  have rep : Represents { state with output := [] } root row bytes := represents
  have size := represents.2.1
  have bound : min (offset.toNat + length.toNat) row.size.toNat - offset.toNat < UInt64.size :=
    Nat.lt_of_le_of_lt (Nat.le_trans (Nat.sub_le ..) (Nat.min_le_right ..)) row.size.toNat_lt
  by_cases empty : offset.toNat = min (offset.toNat + length.toNat) row.size.toNat
  · obtain ⟨raw, rest, observed, decoded⟩ := represents.1
    have result := empty_range_execution { state with output := [] } root row raw rest offset length
      quiet observed decoded valid empty
    have value := congrArg Prod.fst result
    have output := congrArg Prod.snd result
    simp only [readResult, SimulatedHost.run] at value output ⊢
    rw [value]
    simp [publish, output, ← size, ← empty]
  · have result := range_execution { state with output := [] } root row bytes offset length
      quiet rep valid empty available
    have value := congrArg Prod.fst result
    have output := congrArg Prod.snd result
    simp only [List.nil_append] at value output
    simp only [readResult, SimulatedHost.run, value, publish, output]
    have count : (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat).toUInt64.toNat =
        (bytes.extract offset.toNat (min (offset.toNat + length.toNat) row.size.toNat)).data.toList.length := by
      change (min (offset.toNat + length.toNat) row.size.toNat - offset.toNat).toUInt64.toNat =
        (bytes.extract offset.toNat (min (offset.toNat + length.toNat) row.size.toNat)).size
      rw [UInt64.toNat_ofNat_of_lt' bound, ByteArray.size_extract]
      omega
    rw [if_pos count, size]

/-- A complete local claim covers all ranges inside the object. -/
theorem complete_covers (row : Metadata) (start stop : UInt64)
    (complete : row.complete = true) (inside : stop.toNat ≤ row.size.toNat) :
    covered row start stop = true := by
  unfold covered
  split
  · rfl
  · simp only [List.any_cons, List.any_nil, Bool.or_false, Bool.and_eq_true, decide_eq_true_eq]
    constructor
    · omega
    · rw [CasPlanProofs.groupCount_spec]
      split
      · rename_i zero; simp [zero] at inside; omega
      · omega

theorem full_read_is_range (state : State) (root : ByteArray) (row : Metadata)
    (raw : Row) (rest : List Row) (quiet : state.faults = [])
    (observed : observation state root = raw :: rest) (decoded : decodeRow raw = .ok row) :
    execute (read root .all).run state = execute (read root (.range 0 row.size)).run state := by
  unfold observation at observed
  simp [Cas.Read.read, metadata, requestAccess, raise, performOver, Inject.inject,
    execute, Interpreter.handle, access, reply, fault, record, quiet, observed, decoded,
    bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure, ExceptT.run, ExceptT.mk, Except.mapError]

theorem full_read_returns_content (state : State) (root : ByteArray) (row : Metadata)
    (bytes : ByteArray) (quiet : state.faults = []) (represents : Represents state root row bytes)
    (complete : row.complete = true) :
    readResult state root .all = .ok bytes.data.toList := by
  obtain ⟨raw, rest, observed, decoded⟩ := represents.1
  unfold readResult SimulatedHost.run
  rw [full_read_is_range { state with output := [] } root row raw rest quiet observed decoded]
  change readResult state root (.range 0 row.size) = _
  have available : covered row 0 (min ((0 : UInt64).toNat + row.size.toNat) row.size.toNat).toUInt64 = true := by
    simpa using complete_covers row 0 row.size complete (Nat.le_refl _)
  have result := reading_a_part_returns_that_part state root row bytes 0 row.size quiet represents (by simp) available
  simpa [represents.2.1] using result

theorem reading_a_part_agrees_with_reading_the_whole (state : State) (root : ByteArray)
    (row : Metadata) (bytes : ByteArray) (offset length : UInt64)
    (quiet : state.faults = []) (represents : Represents state root row bytes)
    (complete : row.complete = true) (valid : offset.toNat ≤ row.size.toNat) :
    readResult state root (.range offset length) = (readResult state root .all).map
      (fun whole => (whole.drop offset.toNat).take
        (min (offset.toNat + length.toNat) whole.length - offset.toNat)) := by
  rw [full_read_returns_content state root row bytes quiet represents complete,
    reading_a_part_returns_that_part state root row bytes offset length quiet represents valid]
  · simp only [Except.map, ByteArray.data_extract, Array.toList_extract]; rfl
  · apply complete_covers row _ _ complete
    rw [UInt64.toNat_ofNat_of_lt' (Nat.lt_of_le_of_lt (Nat.min_le_right ..) row.size.toNat_lt)]
    exact Nat.min_le_right ..

end Synchronicity.CasReadPromises
