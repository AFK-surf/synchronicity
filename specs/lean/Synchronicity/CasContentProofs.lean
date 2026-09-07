import Synchronicity.CasRangeProofs
import Synchronicity.CasReadPromises

/-! Partial content has meaning independently of the index flags: each byte
of a verified group agrees with the named content. Nothing is required of
bytes in groups that have not arrived yet. -/
namespace Synchronicity.CasContentProofs
open VerifiedCore VerifiedCore.Host SimulatedHost

/-- The physical contract a trusted verified decoder must establish for the
groups it writes, and preserve for groups verified by earlier receives. -/
def AgreesOn (payload content : ByteArray) (groups : List GroupSpan) : Prop :=
  ∀ i (inside : i < content.size), spansContain groups (i / 16384) = true →
    ∃ backed : i < payload.size, payload[i]'backed = content[i]'inside

/-- A range assembled from verified groups has its complete physical backing
and the exact requested content, even if all other groups are missing. -/
theorem verified_range_backed (payload content : ByteArray) (groups : List GroupSpan)
    (first stop : Nat) (positive : first < stop) (inside : stop ≤ content.size)
    (agrees : AgreesOn payload content groups)
    (held : ∀ g, first / 16384 ≤ g → g < (stop + 16383) / 16384 →
      spansContain groups g = true) :
    stop ≤ payload.size ∧ payload.extract first stop = content.extract first stop := by
  have each (i : Nat) (lower : first ≤ i) (upper : i < stop) :
      ∃ backed : i < payload.size, payload[i]'backed = content[i]'(by omega) := by
    apply agrees i (by omega)
    apply held (i / 16384) <;> omega
  obtain ⟨last, _⟩ := each (stop - 1) (by omega) (by omega)
  have backed : stop ≤ payload.size := by omega
  refine ⟨backed, ByteArray.ext (Array.ext ?_ ?_)⟩
  · change (payload.extract first stop).size = (content.extract first stop).size
    simp [ByteArray.size_extract, Nat.min_eq_left backed, Nat.min_eq_left inside]
  · intro i left right
    change (payload.extract first stop)[i]'left = (content.extract first stop)[i]'right
    rw [ByteArray.getElem_extract, ByteArray.getElem_extract]
    have extent : i < stop - first := by
      simpa [ByteArray.size_extract, Nat.min_eq_left backed] using left
    obtain ⟨_, equal⟩ := each (first + i) (by omega) (by omega)
    exact equal

/-- Reading any available part returns that part of the verified content.
The database and payload may still lack the rest of the object. This runs
the actual Read command against the same raw rows and file bytes. -/
theorem verified_parts_read_as_content (state : State) (root : ByteArray)
    (row : Cas.Read.Metadata) (payload content : ByteArray) (offset length : UInt64)
    (raw : Row) (rest : List Row)
    (quiet : state.faults = []) (observed : CasReadPromises.observation state root = raw :: rest)
    (decoded : Cas.Read.decodeRow raw = .ok row)
    (sameSize : row.size.toNat = content.size)
    (physical : match row.inline with
      | some inline => inline = payload
      | none => lookupFile state.files ("cas_payload", root) = some payload)
    (agrees : AgreesOn payload content (Cas.Serve.held row))
    (valid : offset.toNat ≤ row.size.toNat)
    (nonempty : offset.toNat ≠ min (offset.toNat + length.toNat) row.size.toNat)
    (available : Cas.Read.covered row offset
      (min (offset.toNat + length.toNat) row.size.toNat).toUInt64 = true) :
    CasReadPromises.readResult state root (.range offset length) = .ok
      (content.extract offset.toNat (min (offset.toNat + length.toNat) content.size)).data.toList := by
  let stop := min (offset.toNat + length.toNat) row.size.toNat
  have bound : stop < UInt64.size := Nat.lt_of_le_of_lt (Nat.min_le_right ..) row.size.toNat_lt
  have endpoint : stop.toUInt64.toNat = stop := UInt64.toNat_ofNat_of_lt' bound
  have positive : offset < stop.toUInt64 := by
    change offset.toNat < stop.toUInt64.toNat
    rw [endpoint]
    dsimp [stop]
    omega
  have held := (CasRangeProofs.read_range_iff_groups row offset stop.toUInt64 positive).1 available
  rw [endpoint] at held
  have backed := verified_range_backed payload content (Cas.Serve.held row) offset.toNat stop
    (by change offset.toNat < min (offset.toNat + length.toNat) row.size.toNat; omega)
    (by dsimp [stop]; omega) agrees held
  rw [CasReadPromises.reading_received_part state root row payload offset length raw rest
    quiet observed decoded physical backed.1 valid nonempty available]
  simpa [stop, sameSize] using congrArg (fun bytes : ByteArray => (Except.ok bytes.data.toList : Except Cas.Read.Error (List UInt8))) backed.2

end Synchronicity.CasContentProofs
