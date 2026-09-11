import Synchronicity.MaterializedView

/-! Schema facts derived from the actual published-record decoders. In
particular, a decoded file's content field agrees with its retention root,
and published record fields cannot overwrite receiver-owned primary keys. -/
namespace Synchronicity.MaterializationRecords
open VerifiedCore VerifiedCore.Host Replication SimulatedHost MaterializedView

@[irreducible] def Ensures (decoder : Records.Decoder A) (P : A → Prop) : Prop :=
  ∀ input value rest, decoder input = .ok (value, rest) → P value

theorem bind_ensures (first : Records.Decoder A) (next : A → Records.Decoder B) (P : B → Prop)
    (kept : ∀ value, Ensures (next value) P) : Ensures (first >>= next) P := by
  unfold Ensures at *
  intro input value rest ran
  change (do let (a, state) ← first input; next a state) = .ok (value, rest) at ran
  cases firstRun : first input with
  | error error => simp [firstRun, bind, Except.bind] at ran
  | ok result =>
    rcases result with ⟨a, state⟩
    exact kept a state value rest (by simpa only [firstRun, bind, Except.bind] using ran)

theorem pure_ensures (value : A) (P : A → Prop) (holds : P value) : Ensures (pure value) P := by
  unfold Ensures
  intro input result rest ran
  cases ran
  exact holds

theorem throw_ensures (error : String) (P : A → Prop) : Ensures (throw error) P := by
  unfold Ensures
  intro input result rest ran
  cases ran

def FileSchema (file : Records.File) : Prop :=
  file.fields.map Prod.fst = (Address.file "" "").columns ∧
    cell file.fields "content" = Records.nullable Cell.blob file.content

theorem file_schema : Ensures Records.file FileSchema := by
  unfold Records.file
  repeat' first
    | (apply pure_ensures; solve | simp [FileSchema, Address.columns, cell])
    | apply throw_ensures
    | (apply bind_ensures; intro value)
    | split

theorem blob_schema : Ensures Records.blob (fun fields => fields.map Prod.fst = (Address.provider ByteArray.empty).columns) := by
  unfold Records.blob
  repeat' first
    | (apply pure_ensures; solve | simp [Address.columns])
    | apply throw_ensures
    | (apply bind_ensures; intro value)
    | split

theorem delegation_schema : Ensures Records.delegation
    (fun fields => fields.map Prod.fst = (Address.delegation ByteArray.empty).columns) := by
  unfold Records.delegation
  -- The version branch binds the read-only list, so the continuation
  -- arrives as an applied lambda over local `have`s; reducing it exposes the
  -- same `if`/`throw`/`pure` shape the other decoders present directly.
  repeat' first
    | (apply pure_ensures; solve | simp [Address.columns])
    | apply throw_ensures
    | (apply bind_ensures; intro value)
    | split
    | dsimp only

/-- Successful production decoding returns the actual parser output and has
no database or primitive-state effect. -/
theorem decode_state (label : String) (parser : Records.Decoder A) (bytes : ByteArray)
    (state final : State) (value : A)
    (ran : execute (Materialize.decode label parser bytes) state = (.ok value, final)) :
    ∃ rest, parser (bytes, 0) = .ok (value, rest) ∧ final = state := by
  unfold Materialize.decode Materialize.checked at ran
  cases parsed : parser (bytes, 0) with
  | error error => simp [parsed, Except.map, Except.mapError, ExceptT.mk, pure, execute] at ran
  | ok result =>
    rcases result with ⟨result, rest⟩
    simp only [parsed, Except.map, Except.mapError, ExceptT.mk, pure, execute,
      Prod.mk.injEq, Except.ok.injEq] at ran
    exact ⟨rest, by rw [ran.1], ran.2.symm⟩

end Synchronicity.MaterializationRecords
