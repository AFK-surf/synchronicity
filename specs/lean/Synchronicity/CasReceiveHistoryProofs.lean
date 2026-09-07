import Synchronicity.CasPersistenceProofs

/-! Receiving more data preserves the content you can already read. Raw
records and physical bytes define the stored-content invariant independently
of the receive or read command's return value. -/
namespace Synchronicity.CasReceiveHistoryProofs
open VerifiedCore VerifiedCore.Host SimulatedHost
open CasContentProofs

/-- A well-typed file-backed record, allowing arbitrary physical field order
and arbitrary unrelated columns. Durability retains its stored integer. -/
structure Record (row : Fields) (root : ByteArray) (size : UInt64) (complete : Bool)
    (bitmap : Option ByteArray) (durable accessed : Int64) : Prop where
  named : cell row "root" = .blob root
  sized : cell row "size" = .integer size.toInt64
  completion : cell row "complete" = .integer (if complete then 1 else 0)
  coverage : cell row "bitmap" = (match bitmap with | none => .null | some bytes => .blob bytes)
  fileBacked : cell row "inline" = .null
  durability : cell row "durable" = .integer durable
  clock : cell row "last_access" = .integer accessed

private theorem Record.updated (record : Record row root oldSize oldComplete oldBitmap durable oldAccess)
    (size : UInt64) (complete : Bool) (bitmap : Option ByteArray) (now : Int64)
    (tier : Cas.IngestCommit.Tier) :
    let incoming := Cas.IngestCommit.values root size complete bitmap none now tier
    let updated := assign row (Cas.IngestCommit.assignments.map fun (column, value) =>
      (column, conflictValue row incoming value))
    Record updated root size complete bitmap
      (max durable (if complete && tier == .local then 1 else 0)) now := by
  let incoming := Cas.IngestCommit.values root size complete bitmap none now tier
  have rootUnchanged : cell (assign row (Cas.IngestCommit.assignments.map fun (column, value) =>
      (column, conflictValue row incoming value))) "root" = .blob root := by
    rw [CasDurableProofs.cell_assign_other]
    · exact record.named
    · simp [Cas.IngestCommit.assignments]
  have fileBacked := record.fileBacked
  have durability := record.durability
  simp only [cell] at fileBacked durability
  constructor
  · exact rootUnchanged
  all_goals cases complete <;> cases bitmap <;> cases tier <;>
    simp [Cas.IngestCommit.values, Cas.IngestCommit.assignments, conflictValue,
      assign, cell, fileBacked, durability]

def payload (state : State) (root : ByteArray) : ByteArray :=
  (lookupFile state.files ("cas_payload", root)).getD ByteArray.empty

def held (size : UInt64) (complete : Bool) (bitmap : Option ByteArray) : List GroupSpan :=
  if complete then [⟨0, (groupCount size).toNat⟩]
  else match bitmap with | none => [] | some bytes => Cas.Codec.decodeRawBitmap bytes

/-- The physical and relational meaning of a saved file version. Missing
unverified groups impose no byte requirement, nor require a whole payload file. -/
structure StoredFile (state : State) (root content : ByteArray) where
  size : UInt64
  complete : Bool
  bitmap : Option ByteArray
  durable : Int64
  accessed : Int64
  row : Fields
  recorded : Record row root size complete bitmap durable accessed
  selected : (rows state.db "blobs").filter
    (fun row => equals row [("root", .blob root)]) = [row]
  width : root.size = 32
  identity : state.hash content = root
  sameSize : size.toNat = content.size
  large : ¬ size ≤ Cas.Receive.inlineMax
  sound : AgreesOn (payload state root) content (held size complete bitmap)

def StoredFile.metadata (saved : StoredFile state root content) : Cas.Read.Metadata :=
  ⟨saved.size, saved.complete, saved.bitmap, none⟩

def StoredFile.claim (saved : StoredFile state root content) : Cas.IngestCommit.Claim :=
  ⟨saved.size, saved.complete, saved.durable != 0, saved.bitmap⟩

private theorem unordered_query (db : Database) (table : String) (columns : List String)
    (fields : Fields) :
    query db table columns fields [] [] =
      ((rows db table).filter (fun row => equals row fields)).map (project columns) := by
  have sorted (rs : List Fields) : sortRows (ordered []) rs = rs := by
    induction rs with
    | nil => rfl
    | cons row rest ih =>
      rw [sortRows, ih]
      cases rest <;> rfl
  simp [query, sorted]

private theorem record_read (row : Fields) (root : ByteArray) (size : UInt64)
    (complete : Bool) (bitmap : Option ByteArray) (durable accessed : Int64)
    (record : Record row root size complete bitmap durable accessed) (width : root.size = 32) :
    Cas.Read.decodeRow (project ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"] row) =
      .ok ⟨size, complete, bitmap, none⟩ := by
  simp only [project, List.map_cons, List.map_nil, record.named, record.sized,
    record.completion, record.coverage, record.fileBacked, record.durability, record.clock]
  cases complete <;> cases bitmap <;>
    simp [Cas.Read.decodeRow, Cas.Read.blobField, Cas.Read.integerField, Cas.Read.optionalBlobField,
      Cas.Codec.blobField, Cas.Codec.integerField, Cas.Codec.optionalBlobField,
      width, bind, pure, Except.bind, Except.pure]

private theorem record_claim (row : Fields) (root : ByteArray) (size : UInt64)
    (complete : Bool) (bitmap : Option ByteArray) (durable accessed : Int64)
    (record : Record row root size complete bitmap durable accessed) :
    Cas.IngestCommit.decodeClaim [project Cas.IngestCommit.claimColumns row] =
      .ok (some ⟨size, complete, durable != 0, bitmap⟩) := by
  simp only [Cas.IngestCommit.claimColumns, project, List.map_cons, List.map_nil,
    record.sized, record.completion, record.coverage, record.durability]
  cases complete <;> cases bitmap <;>
    simp [Cas.IngestCommit.decodeClaim, Cas.Codec.integerField, Cas.Codec.optionalBlobField,
      bind, pure, Except.bind, Except.pure]

theorem StoredFile.observed (saved : StoredFile state root content) :
    ∃ raw, CasReadPromises.observation state root = [raw] ∧
      Cas.Read.decodeRow raw = .ok saved.metadata := by
  refine ⟨project ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"] saved.row, ?_, ?_⟩
  · have predicate : selects ⟨"blobs", [("root", .blob root)], [], []⟩ =
        fun row => equals row [("root", .blob root)] := by
      funext row
      simp [selects]
    simp only [CasReadPromises.observation, predicate, saved.selected, List.map_cons, List.map_nil]
  · exact record_read _ _ _ _ _ _ _ saved.recorded saved.width

theorem StoredFile.claimed (saved : StoredFile state root content) :
    Cas.IngestCommit.decodeClaim
      (query state.db "blobs" Cas.IngestCommit.claimColumns [("root", .blob root)] [] []) =
      .ok (some saved.claim) := by
  rw [unordered_query, saved.selected]
  exact record_claim _ _ _ _ _ _ _ saved.recorded

/-- A normalized read view and the stored raw bitmap describe the same
in-bound groups. Complete rows use every group, regardless of bitmap bytes. -/
private theorem read_groups (size : UInt64) (complete : Bool) (bitmap : Option ByteArray) (group : Nat)
    (inside : group < (groupCount size).toNat) :
    spansContain (Cas.Serve.held ⟨size, complete, bitmap, none⟩) group =
      spansContain (held size complete bitmap) group := by
  by_cases full : complete = true
  · simp [Cas.Serve.held, held, full]
  · have incomplete : complete = false := Bool.eq_false_iff.mpr full
    cases bitmap with
    | none => simp [Cas.Serve.held, held, incomplete]
    | some bytes =>
      simp only [Cas.Serve.held, held, incomplete,
        Bool.false_eq_true, if_false, Cas.Read.decodeBitmap, Cas.Read.decodeRawBitmap]
      apply Bool.eq_iff_iff.mpr
      rw [CasPlanProofs.normalize_spans_membership]
      simp [inside]

private theorem byte_group_inside (size : UInt64) (i : Nat) (inside : i < size.toNat) :
    i / 16384 < (groupCount size).toNat := by
  rw [CasPlanProofs.groupCount_spec]
  split
  · rename_i zero
    subst size
    simp at inside
  · omega

theorem StoredFile.read_sound (saved : StoredFile state root content) :
    AgreesOn (payload state root) content (Cas.Serve.held saved.metadata) := by
  have size := saved.sameSize
  intro i inside available
  apply saved.sound i inside
  rw [← read_groups saved.size saved.complete saved.bitmap (i / 16384) (byte_group_inside saved.size i (by omega))]
  exact available

/-- Every readable range of the persisted version returns its exact content,
including unaligned and empty requests and files whose other groups are absent. -/
theorem StoredFile.reads (saved : StoredFile state root content) (offset length : UInt64)
    (quiet : state.faults = []) (valid : offset.toNat ≤ saved.size.toNat)
    (available : Cas.Read.covered saved.metadata offset
      (min (offset.toNat + length.toNat) saved.size.toNat).toUInt64 = true) :
    CasReadPromises.readResult state root (.range offset length) = .ok
      (content.extract offset.toNat (min (offset.toNat + length.toNat) content.size)).data.toList := by
  have size := saved.sameSize
  obtain ⟨raw, observed, decoded⟩ := saved.observed
  by_cases empty : offset.toNat = min (offset.toNat + length.toNat) saved.size.toNat
  · have result := CasReadPromises.empty_range_execution { state with output := [] } root
      saved.metadata raw [] offset length quiet observed decoded valid empty
    have value := congrArg Prod.fst result
    have output := congrArg Prod.snd result
    simp only [CasReadPromises.readResult, SimulatedHost.run] at value output ⊢
    rw [value]
    simp [publish, output, ← saved.sameSize, ← empty]
  · let stop := min (offset.toNat + length.toNat) saved.size.toNat
    have bound : stop < UInt64.size := Nat.lt_of_le_of_lt (Nat.min_le_right ..) saved.size.toNat_lt
    have endpoint : stop.toUInt64.toNat = stop := UInt64.toNat_ofNat_of_lt' bound
    have positive : offset < stop.toUInt64 := by
      change offset.toNat < stop.toUInt64.toNat
      rw [endpoint]
      dsimp [stop]
      omega
    have held := (CasRangeProofs.read_range_iff_groups saved.metadata offset stop.toUInt64 positive).1 available
    rw [endpoint] at held
    have backed := verified_range_backed (payload state root) content (Cas.Serve.held saved.metadata)
      offset.toNat stop (by dsimp [stop]; omega) (by dsimp [stop]; omega) saved.read_sound held
    have physical : lookupFile state.files ("cas_payload", root) = some (payload state root) := by
      cases found : lookupFile state.files ("cas_payload", root) with
      | none =>
        have impossible := backed.1
        simp [payload, found] at impossible
        dsimp [stop] at impossible
        omega
      | some bytes => simp [payload, found]
    exact CasContentProofs.verified_parts_read_as_content state root saved.metadata
      (payload state root) content offset length raw [] quiet observed decoded saved.sameSize
      physical saved.read_sound valid empty available

/-- The decoder contract is about its byte writes, including errors. It does
not assume anything about a future Read result or a future database flag. -/
def DecoderCorrect (state : State) (root content : ByteArray) (size : UInt64) : Prop :=
  ∀ (spans : List GroupSpan) (input : UInt64) (previous : ByteArray),
    (∀ span ∈ spans, span.start < span.stop ∧ span.stop ≤ (groupCount size).toNat) →
    let decoded := state.decodedPayload root size (Cas.Serve.pairsOf spans) input previous
    (∀ heldGroups, AgreesOn previous content heldGroups → AgreesOn decoded content heldGroups) ∧
    (state.decodeSlice root size (Cas.Serve.pairsOf spans) input = true →
      AgreesOn decoded content spans)

/-- A failed transfer can write a verified prefix, but content already saved
remains readable byte for byte. This runs the real receive and then the real
read against its resulting files and database. -/
theorem interrupted_transfer_preserves_readable_content
    (saved : StoredFile state root content)
    (decoder : DecoderCorrect state root content saved.size)
    (served : List (UInt64 × UInt64)) (input : UInt64) (now : Int64)
    (tier : Cas.IngestCommit.Tier) (offset length : UInt64)
    (quiet : state.faults = []) (idle : state.pending = none) (clean : state.scanFault = none)
    (incomplete : saved.complete = false)
    (nonempty : Cas.Receive.window saved.size served ≠ [])
    (interrupted : state.decodeSlice root saved.size
      (Cas.Serve.pairsOf (Cas.Receive.window saved.size served)) input = false)
    (valid : offset.toNat ≤ saved.size.toNat)
    (available : Cas.Read.covered saved.metadata offset
      (min (offset.toNat + length.toNat) saved.size.toNat).toUInt64 = true) :
    let received := SimulatedHost.run
      (Cas.Receive.writeSlice root saved.size served input now tier) state
    received.1 = .error (.host state.decodeSliceFailure) ∧
    CasReadPromises.readResult received.2 root (.range offset length) = .ok
      (content.extract offset.toNat (min (offset.toNat + length.toNat) content.size)).data.toList := by
  obtain ⟨raw, observed, decoded⟩ := saved.observed
  have admitted : (Cas.IngestCommit.plan (some saved.claim) saved.size []).accepted = true := by
    simp [Cas.IngestCommit.plan, StoredFile.claim, planCasCommit, settleSize]
  have execution := CasReceiveStateProofs.interrupted_decoder_keeps_committed_metadata
    state root saved.size served input now tier saved.claim saved.metadata raw []
    quiet idle clean saved.claimed observed decoded incomplete admitted saved.large nonempty interrupted
  dsimp only at execution ⊢
  obtain ⟨failed, db, physical, quietAfter, idleAfter, hashAfter, decodeAfter, payloadAfter, failureAfter⟩ := execution
  refine ⟨failed, ?_⟩
  let received := SimulatedHost.run
    (Cas.Receive.writeSlice root saved.size served input now tier) state
  have preserved := (decoder (Cas.Receive.window saved.size served) input (payload state root)
    (CasPlanProofs.normalize_spans_bounds _ _)).1
      (held saved.size saved.complete saved.bitmap) saved.sound
  let next : StoredFile received.2 root content :=
    { saved with
      selected := by rw [db]; exact saved.selected
      identity := by rw [hashAfter]; exact saved.identity
      sound := by
        change AgreesOn ((lookupFile received.2.files ("cas_payload", root)).getD ByteArray.empty) _ _
        change lookupFile received.2.files ("cas_payload", root) = _ at physical
        rw [physical]
        exact preserved }
  exact next.reads offset length quietAfter valid available

end Synchronicity.CasReceiveHistoryProofs
