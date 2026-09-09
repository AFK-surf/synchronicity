import Synchronicity.MaterializationProviderSql
import Synchronicity.TransactionSuccess

namespace Synchronicity.MaterializationProviderApply
open VerifiedCore VerifiedCore.Host Replication SimulatedHost
open MaterializationProviderSql MaterializationRecords TransactionSuccess

def body (tx : Transaction) (origin : String) (root : ByteArray) : Option ByteArray → Materialize.Action Unit
  | none => Materialize.erase tx "blob_providers" (key origin root)
  | some bytes => do
    let fields ← Materialize.decode "b: record" Records.blob bytes
    Materialize.write tx "blob_providers" (key origin root) fields

theorem apply_provider_unfold (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (rawKey : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (tag : rawKey[0]? = some 98) (width : rawKey.size = 34) (separator : rawKey[1]? = some 58) :
    Materialize.apply tx origin now releaseNow replicas rawKey kind value = body tx origin (rawKey.extract 2 34) value := by
  have nonfile : (some (98 : UInt8) == some 102) = false := by decide
  simp only [Materialize.apply, tag, width, separator, nonfile, beq_self_eq_true, Bool.and_self,
    Bool.false_eq_true, ↓reduceIte]
  rfl

theorem body_refines (tx : Transaction) (origin : String) (root : ByteArray) (value : Option ByteArray)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (ran : execute (body tx origin root value) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧
      MaterializedView.ReplacesRecord db after origin (.provider root) value := by
  cases value with
  | none =>
    have finalState := MaterializationSql.erase_state tx "blob_providers" (key origin root) state final db opened ran
    refine ⟨MaterializationSql.erased db "blob_providers" (key origin root), by rw [finalState]; rfl, ?_, ?_⟩
    · intro values
      constructor
      · rintro ⟨row, member, selected, _⟩
        change row ∈ rows (MaterializationSql.erased db "blob_providers" (key origin root)) "blob_providers" at member
        simp only [MaterializationSql.erased, rows_setRows, List.mem_filter] at member
        simp only [key, selected, Bool.not_true, Bool.false_eq_true, and_false] at member
      · rintro ⟨bytes, impossible, _⟩
        cases impossible
    · intro row outside
      simp [MaterializationSql.erased, MaterializedView.Address.table, key, outside]
  | some bytes =>
    obtain ⟨fields, decoded, parseRun, writeRun⟩ := bind_success _ _ _ _ _ ran
    obtain ⟨rest, parsed, unchanged⟩ := decode_state "b: record" Records.blob bytes state decoded fields parseRun
    subst decoded
    have finalState := MaterializationSql.write_state tx "blob_providers" (key origin root) fields false state final db opened writeRun
    have schema := blob_schema
    unfold Ensures at schema
    specialize schema (bytes, 0) fields rest parsed
    refine ⟨MaterializationSql.written db "blob_providers" (key origin root) fields false,
      by rw [finalState]; rfl, ?_, ?_⟩
    · intro values
      have correct := write_replaces db origin root fields schema true values
      simp only [true_and, ne_eq, not_true_eq_false, false_and, or_false, Option.some.injEq] at correct
      change MaterializedView.Observed _ origin (.provider root) values ↔ _ at correct
      rw [correct]
      constructor
      · intro same
        exact ⟨bytes, rfl, fields, rest, parsed, same⟩
      · rintro ⟨other, equal, decoded, decodedRest, decodedRun, data⟩
        cases equal
        have same : fields = decoded := congrArg (fun r => r.toOption.map (·.1)) (parsed.symm.trans decodedRun) |> Option.some.inj
        subst decoded
        exact data
    · exact write_keeps_other_row db origin root fields schema

/-- Actual provider-key execution installs exactly the decoded provider
record or its deletion; no other provider row changes. -/
theorem apply_provider_refines (tx : Transaction) (origin : String) (now releaseNow : Int64)
    (replicas : List Materialize.Target) (rawKey : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (state final : State) (db : Database) (opened : state.pending = some (tx, db))
    (tag : rawKey[0]? = some 98) (width : rawKey.size = 34) (separator : rawKey[1]? = some 58)
    (ran : execute (Materialize.apply tx origin now releaseNow replicas rawKey kind value) state = (.ok (), final)) :
    ∃ after, final.pending = some (tx, after) ∧
      MaterializedView.ReplacesRecord db after origin (.provider (rawKey.extract 2 34)) value := by
  rw [apply_provider_unfold tx origin now releaseNow replicas rawKey kind value tag width separator] at ran
  exact body_refines tx origin _ value state final db opened ran

end Synchronicity.MaterializationProviderApply
