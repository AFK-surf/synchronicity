import VerifiedCore.Replication.History
import Std.Data.TreeMap.Lemmas
import Std.Data.TreeSet.Lemmas
import Synchronicity.Handlers

/-! These properties concern the executable retention program, not a parallel model. -/
namespace Synchronicity.HistoryProgramProofs
-- The pinned compiler's asynchronous elaborator emits internal Option.get!
-- diagnostics for these expanded scripted traces. Keep elaboration serial;
-- kernel checks and warnings-as-errors are unchanged.
set_option Elab.async false
open VerifiedCore.Host VerifiedCore.Replication.History

theorem summary_count_fold (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (initial : Std.TreeMap UInt64 SequenceSummary) (seq : UInt64) :
    ((receipts.foldl (addReceipt pointers before) initial).getD seq {}).count =
      (initial.getD seq {}).count + (receipts.filter (fun r => r.pointer.seq == seq)).length := by
  induction receipts generalizing initial with
  | nil => simp
  | cons head rest ih =>
    simp only [List.foldl_cons, ih]
    by_cases same : head.pointer.seq = seq
    · simp [addReceipt, same, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]
    · simp [addReceipt, Std.TreeMap.getD_insert, same]

theorem summary_count (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (seq : UInt64) :
    ((summarize pointers before receipts).getD seq {}).count =
      (receipts.filter (fun r => r.pointer.seq == seq)).length := by
  simp [summarize, summary_count_fold]

theorem summary_keys_fold (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (initial : Std.TreeMap UInt64 SequenceSummary) (seq : UInt64) :
    seq ∈ receipts.foldl (addReceipt pointers before) initial ↔
      seq ∈ initial ∨ ∃ r ∈ receipts, r.pointer.seq = seq := by
  induction receipts generalizing initial with
  | nil => simp
  | cons head rest ih =>
    simp only [List.foldl_cons, ih, addReceipt, Std.TreeMap.mem_insert]
    simp only [List.mem_cons]
    grind

theorem summary_keys (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (seq : UInt64) :
    seq ∈ (summarize pointers before receipts).toList.map Prod.fst ↔
      ∃ r ∈ receipts, r.pointer.seq = seq := by
  have keys : seq ∈ summarize pointers before receipts ↔ ∃ r ∈ receipts, r.pointer.seq = seq := by
    simp [summarize, summary_keys_fold]
  rw [← keys]
  constructor
  · intro h
    obtain ⟨⟨key, value⟩, member, same⟩ := List.mem_map.mp h
    change key = seq at same
    subst key
    have found := Std.TreeMap.mem_toList_iff_getElem?_eq_some.mp member
    change (summarize pointers before receipts).contains seq = true
    rw [Std.TreeMap.contains_eq_isSome_getElem?, found]
    rfl
  · intro member
    exact List.mem_map.mpr ⟨(seq, (summarize pointers before receipts).getD seq {}),
      Std.TreeMap.mem_toList_iff_getElem?_eq_some.mpr
        (Std.TreeMap.getElem?_eq_some_getD member), rfl⟩

private theorem maximum_fold_ceiling (seqs : List UInt64) (initial : Option UInt64)
    (ceiling : UInt64) (bounded : ∀ seq ∈ seqs, seq ≤ ceiling)
    (initialBound : ∀ seq ∈ initial, seq ≤ ceiling)
    (present : ceiling ∈ seqs ∨ initial = some ceiling) :
    seqs.foldl retainMaximum initial =
      some ceiling := by
  induction seqs generalizing initial with
  | nil => simpa using present
  | cons head rest ih =>
    simp only [List.foldl_cons]
    have hb := bounded head (by simp)
    have tailBound : ∀ seq ∈ rest, seq ≤ ceiling := fun seq member => bounded seq (by simp [member])
    apply ih _ tailBound
    · cases initial with
      | none => simpa [retainMaximum] using hb
      | some old =>
        have ho := initialBound old (by simp)
        simp only [retainMaximum, Option.mem_def, Option.some.injEq]
        split
        · simpa using ho
        · simpa using hb
    · rcases present with member | initialEq
      · rcases List.mem_cons.mp member with same | tail
        · right
          cases initial with
          | none => simp [retainMaximum, same]
          | some old =>
            have ho := initialBound old (by simp)
            simp only [retainMaximum, ← same, Option.some.injEq]
            split
            · rename_i h
              exact UInt64.toNat_inj.mp (Nat.le_antisymm ho h)
            · rfl
        · exact Or.inl tail
      · right
        simp [retainMaximum, initialEq, hb]

theorem maximum_of_greatest (seqs : List UInt64) (ceiling : UInt64)
    (member : ceiling ∈ seqs) (bounded : ∀ seq ∈ seqs, seq ≤ ceiling) :
    maximum seqs = some ceiling :=
  maximum_fold_ceiling seqs none ceiling bounded (by simp) (Or.inl member)

/-- Every input receipt at a greatest sequence survives the actual policy,
including orphaned history above both current slots and unsigned high seqs. -/
theorem greatest_sequence_preserved (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (receipt : Receipt) (held : receipt ∈ receipts)
    (greatest : ∀ r ∈ receipts, r.pointer.seq ≤ receipt.pointer.seq) :
    receipt ∉ selected pointers before receipts := by
  have member : receipt.pointer.seq ∈ (summarize pointers before receipts).toList.map Prod.fst :=
    (summary_keys _ _ _ _).mpr ⟨receipt, held, rfl⟩
  have bounded : ∀ seq ∈ (summarize pointers before receipts).toList.map Prod.fst,
      seq ≤ receipt.pointer.seq := by
    intro seq member
    obtain ⟨r, hr, same⟩ := (summary_keys _ _ _ _).mp member
    simpa [← same] using greatest r hr
  have ceiling : (retention pointers before receipts).ceiling = some receipt.pointer.seq :=
    maximum_of_greatest _ _ member bounded
  simp [selected, deletable, ceiling]

theorem witness_step_preserves (movedPast : Option UInt64)
    (state : Option UInt64 × Std.TreeSet UInt64) (entry : UInt64 × SequenceSummary)
    (witness : UInt64) (present : witness ∈ state.2) :
    witness ∈ (witnessStep movedPast state entry).2 := by
  rcases state with ⟨nextOld, witnesses⟩
  rcases entry with ⟨seq, summary⟩
  simp only [witnessStep]
  split
  · cases nextOld <;> simp_all
  · exact present

theorem witness_fold_preserves (movedPast : Option UInt64)
    (entries : List (UInt64 × SequenceSummary)) (state : Option UInt64 × Std.TreeSet UInt64)
    (witness : UInt64) (present : witness ∈ state.2) :
    witness ∈ (entries.foldl (witnessStep movedPast) state).2 := by
  induction entries generalizing state with
  | nil => exact present
  | cons head rest ih => exact ih _ (witness_step_preserves _ _ _ _ present)

theorem scan_keeps_last_old (movedPast : Option UInt64)
    (entries : List (UInt64 × SequenceSummary)) (state : Option UInt64 × Std.TreeSet UInt64)
    (noneOld : ∀ entry ∈ entries, entry.2.old = false) :
    (entries.foldl (witnessStep movedPast) state).1 = state.1 := by
  induction entries generalizing state with
  | nil => rfl
  | cons head rest ih =>
    rw [List.foldl_cons, ih _ (fun entry member => noneOld entry (by simp [member]))]
    simp [witnessStep, noneOld head (by simp)]

theorem scan_remembers_last_old (movedPast : Option UInt64)
    (earlier later : List (UInt64 × SequenceSummary)) (seq : UInt64)
    (summary : SequenceSummary) (old : summary.old = true)
    (noneLater : ∀ entry ∈ later, entry.2.old = false) :
    ((earlier ++ (seq, summary) :: later).foldl (witnessStep movedPast) (none, {})).1 = some seq := by
  rw [List.foldl_append, List.foldl_cons, scan_keeps_last_old _ _ _ noneLater]
  simp [witnessStep, old]

/-- A protected fork adds the last old sequence encountered before it in the
actual descending scan; no later scan step can discard that witness. -/
theorem required_scan_witness (movedPast : Option UInt64)
    (earlier later : List (UInt64 × SequenceSummary)) (seq witness : UInt64)
    (summary : SequenceSummary)
    (previous : (earlier.foldl (witnessStep movedPast) (none, {})).1 = some witness)
    (fork : 1 < summary.count) (exempt : expired movedPast seq summary = false) :
    witness ∈ ((earlier ++ (seq, summary) :: later).foldl
      (witnessStep movedPast) (none, {})).2 := by
  rw [List.foldl_append, List.foldl_cons]
  apply witness_fold_preserves
  simp [witnessStep, previous, fork, exempt]

/-- Every receipt at a needed witness sequence survives. The hypotheses refer
only to the scan of the actual input-derived summaries and its last old row,
not to host-provided witness classifications. TreeMap's descending key order
makes this last old sequence the least higher old sequence at that fork. -/
theorem required_witness_preserved (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (earlier later : List (UInt64 × SequenceSummary))
    (seq : UInt64) (summary : SequenceSummary) (receipt : Receipt)
    (scan : (summarize pointers before receipts).toList.reverse = earlier ++ (seq, summary) :: later)
    (previous : (earlier.foldl (witnessStep (retention pointers before receipts).movedPast)
      (none, {})).1 = some receipt.pointer.seq)
    (fork : 1 < summary.count)
    (exempt : expired (retention pointers before receipts).movedPast seq summary = false) :
    receipt ∉ selected pointers before receipts := by
  have present : receipt.pointer.seq ∈ (retention pointers before receipts).witnesses := by
    change receipt.pointer.seq ∈ (((summarize pointers before receipts).toList.reverse).foldl
      (witnessStep (retention pointers before receipts).movedPast) (none, {})).2
    rw [scan]
    exact required_scan_witness _ _ _ _ _ _ previous fork exempt
  have contains : (retention pointers before receipts).witnesses.contains receipt.pointer.seq = true :=
    present
  simp only [selected, List.mem_filter, deletable, contains, Bool.not_true, Bool.and_false,
    Bool.false_and, Bool.false_eq_true, and_false, not_false_eq_true]

/-- A receipt at the nearest earlier old sequence in the actual descending
summary list cannot be pruned while the later fork remains exempt. No
continuation-state/witness-membership premise is needed. -/
theorem nearest_old_witness_preserved (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (earlier between later : List (UInt64 × SequenceSummary))
    (witness seq : UInt64) (witnessSummary forkSummary : SequenceSummary) (receipt : Receipt)
    (scan : (summarize pointers before receipts).toList.reverse =
      earlier ++ (witness, witnessSummary) :: (between ++ (seq, forkSummary) :: later))
    (old : witnessSummary.old = true) (noneBetween : ∀ entry ∈ between, entry.2.old = false)
    (fork : 1 < forkSummary.count)
    (exempt : expired (retention pointers before receipts).movedPast seq forkSummary = false)
    (same : receipt.pointer.seq = witness) : receipt ∉ selected pointers before receipts := by
  apply required_witness_preserved pointers before receipts
    (earlier ++ (witness, witnessSummary) :: between) later seq forkSummary receipt
  · simpa only [List.append_assoc, List.cons_append] using scan
  · simpa [same] using scan_remembers_last_old (retention pointers before receipts).movedPast
      earlier between witness witnessSummary old noneBetween
  · exact fork
  · exact exempt

theorem summary_pinned_fold (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (initial : Std.TreeMap UInt64 SequenceSummary) (seq : UInt64) :
    ((receipts.foldl (addReceipt pointers before) initial).getD seq {}).pinned =
      ((initial.getD seq {}).pinned || receipts.any (fun r => r.pointer.seq == seq &&
        (before ≤ r.recordedAt || current pointers r))) := by
  induction receipts generalizing initial with
  | nil => simp
  | cons head rest ih =>
    simp only [List.foldl_cons, ih]
    by_cases same : head.pointer.seq = seq
    · simp [addReceipt, same, Bool.or_assoc]
    · have different : (head.pointer.seq == seq) = false := by simp [same]
      simp [addReceipt, Std.TreeMap.getD_insert, same, different]

theorem summary_pinned (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (seq : UInt64) :
    ((summarize pointers before receipts).getD seq {}).pinned =
      receipts.any (fun r => r.pointer.seq == seq && (before ≤ r.recordedAt || current pointers r)) := by
  simp [summarize, summary_pinned_fold]

private theorem distinct_members_length {A : Type} (values : List A) (left right : A)
    (hl : left ∈ values) (hr : right ∈ values) (different : left ≠ right) :
    1 < values.length := by
  cases values with
  | nil => simp at hl
  | cons head rest =>
    cases rest with
    | nil => simp_all
    | cons next tail => simp

/-- A current or young retained fork side protects every other retained root
at its sequence. All fork and pinned facts are derived from the actual input
receipts, not supplied as policy flags by the caller or host. -/
theorem protected_fork_side (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (protectedSide other : Receipt)
    (held : protectedSide ∈ receipts) (otherHeld : other ∈ receipts)
    (same : protectedSide.pointer.seq = other.pointer.seq)
    (different : protectedSide.pointer.root ≠ other.pointer.root)
    (protect : before ≤ protectedSide.recordedAt ∨ current pointers protectedSide = true) :
    other ∉ selected pointers before receipts := by
  have differentRows : protectedSide ≠ other := by
    intro eq
    exact different (congrArg (fun r : Receipt => r.pointer.root) eq)
  have leftMem : protectedSide ∈ receipts.filter (fun r => r.pointer.seq == other.pointer.seq) := by
    simp [held, same]
  have rightMem : other ∈ receipts.filter (fun r => r.pointer.seq == other.pointer.seq) := by
    simp [otherHeld]
  have count : 1 < ((summarize pointers before receipts).getD other.pointer.seq {}).count := by
    rw [summary_count]
    exact distinct_members_length _ _ _ leftMem rightMem differentRows
  have pinned : ((summarize pointers before receipts).getD other.pointer.seq {}).pinned = true := by
    rw [summary_pinned, List.any_eq_true]
    refine ⟨protectedSide, held, ?_⟩
    rcases protect with young | current
    · simp [same, young]
    · simp [same, current]
  have large : ¬ ((retention pointers before receipts).summaries.getD other.pointer.seq {}).count ≤ 1 :=
    Nat.not_le.mpr count
  have policyPinned : ((retention pointers before receipts).summaries.getD other.pointer.seq {}).pinned = true :=
    pinned
  simp [selected, deletable, large, expired, policyPinned]

theorem current_not_deletable (policy : Retention) (pointers : List Pointer)
    (before : Int64) (receipt : Receipt) (held : current pointers receipt = true) :
    deletable policy pointers before receipt = false := by
  simp [deletable, held]

theorem young_not_deletable (policy : Retention) (pointers : List Pointer)
    (before : Int64) (receipt : Receipt) (young : ¬ receipt.recordedAt < before) :
    deletable policy pointers before receipt = false := by
  simp [deletable, young]

theorem ceiling_not_deletable (policy : Retention) (pointers : List Pointer)
    (before : Int64) (receipt : Receipt) (ceiling : policy.ceiling = some receipt.pointer.seq) :
    deletable policy pointers before receipt = false := by
  simp [deletable, ceiling]

theorem witness_not_deletable (policy : Retention) (pointers : List Pointer)
    (before : Int64) (receipt : Receipt)
    (witness : policy.witnesses.contains receipt.pointer.seq = true) :
    deletable policy pointers before receipt = false := by
  simp only [deletable, witness, Bool.not_true, Bool.and_false, Bool.false_and]

theorem selected_from_input (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (receipt : Receipt) (chosen : receipt ∈ selected pointers before receipts) :
    receipt ∈ receipts := (List.mem_filter.mp chosen).1

theorem selected_not_current (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (receipt : Receipt) (chosen : receipt ∈ selected pointers before receipts) :
    current pointers receipt = false := by
  have allowed := (List.mem_filter.mp chosen).2
  cases h : current pointers receipt
  · rfl
  · rw [current_not_deletable _ _ _ _ h] at allowed
    contradiction

theorem selected_before_horizon (pointers : List Pointer) (before : Int64)
    (receipts : List Receipt) (receipt : Receipt) (chosen : receipt ∈ selected pointers before receipts) :
    receipt.recordedAt < before := by
  have allowed := (List.mem_filter.mp chosen).2
  apply Classical.byContradiction
  intro h
  rw [young_not_deletable _ _ _ _ h] at allowed
  contradiction

/-- Once row-local age/current guards agree, retirement is a sequence-level
decision: eligible sides cannot be split by their different roots. -/
theorem eligible_sides_agree (policy : Retention) (pointers : List Pointer)
    (before : Int64) (left right : Receipt)
    (same : left.pointer.seq = right.pointer.seq)
    (leftOld : left.recordedAt < before) (rightOld : right.recordedAt < before)
    (leftFree : current pointers left = false) (rightFree : current pointers right = false) :
    deletable policy pointers before left = deletable policy pointers before right := by
  simp [deletable, same, leftOld, rightOld, leftFree, rightFree]

theorem remove_empty (tx : Transaction) (origin : String) :
    (remove tx origin []).run = .pure (.ok 0) := rfl

/-- Deletion effects contain the exact retained-record key and a mutation-time
exclusion for matching head pointers. A failed delete has no continuation that
can attempt another deletion or return success. -/
theorem remove_next (tx : Transaction) (origin : String) (total : Nat)
    (receipt : Receipt) (rest : List Receipt) :
    (removeLoop tx origin total (receipt :: rest)).run =
      .request (.left (.deleteRows tx "head_history"
        (receiptKey origin receipt) [⟨"heads", receiptKey origin receipt, []⟩]))
        (fun reply => match reply with
          | .error failure => .pure (.error (.host failure))
          | .ok count => (removeLoop tx origin (total + count) rest).run) := by
  change Program.request _ _ = Program.request _ _
  congr 1
  funext reply
  cases reply <;> rfl

/-- Retention obtains raw pointers itself, within the caller's transaction. -/
theorem prune_reads_pointers (tx : Transaction) (origin : String) (before : Int64) :
    ∃ resume, (pruneIn tx origin before).run = .request
      (.left (.scanRows tx "heads" headColumns
        [("origin_id", .text origin), ("slot", .text "complete")] [] headJoin)) resume := by
  exact ⟨_, rfl⟩

/-- The public operation itself requests its snapshot lock, before any read. -/
theorem prune_begins_transaction (origin : String) (before : Int64) :
    ∃ resume, (prune origin before).run = .request (.left .begin) resume := by
  exact ⟨_, rfl⟩

/-- An absent raw join is an absent slot, with no decoding or additional reads. -/
theorem absent_joined_slot (tx : Transaction) (origin slot : String) :
    ∃ resume, (readSlot tx origin slot).run = .request
      (.left (.scanRows tx "heads" headColumns
        [("origin_id", .text origin), ("slot", .text slot)] [] headJoin)) resume ∧
      resume (.ok ⟨[], none⟩) = .pure (.ok []) := by
  exact ⟨_, rfl, rfl⟩

/-- Field conversion and signature width precede origin and key validation. -/
theorem joined_fields_admitted (origin : String) (seq created received verified : Int64)
    (hash key sig : ByteArray) (sigSize : sig.size = 64) :
    decodeJoinedFields [.text origin, .integer seq, .blob hash, .integer created,
      .blob key, .blob sig, .integer received, .integer verified] =
      .ok ⟨origin, ⟨seq.toUInt64, hash⟩, key⟩ := by
  simp [decodeJoinedFields, textField, integerField, blobField,
    bind, Except.bind, pure, Except.pure, sigSize]

/-- Syntax errors precede root/key widths without requesting crypto. -/
theorem joined_origin_before_hash (origin : String) (seq created received verified : Int64)
    (hash key sig : ByteArray) (failure : VerifiedCore.Origin.Error)
    (sigSize : sig.size = 64)
    (invalid : VerifiedCore.Origin.parseSyntax origin = .error failure) :
    (decodeJoinedHead [.text origin, .integer seq, .blob hash, .integer created,
      .blob key, .blob sig, .integer received, .integer verified]).run =
        .pure (.error (.origin failure)) := by
  simp [decodeJoinedHead, joined_fields_admitted origin seq created received verified hash key sig sigSize,
    VerifiedCore.Origin.parse, invalid, ExceptT.run, ExceptT.mk,
    bind, ExceptT.bind, ExceptT.bindCont, pure, ExceptT.pure, Program.bind, Except.mapError]

/-- A malformed signature is rejected before any primitive or storage effect. -/
theorem joined_signature_width_required (origin : String) (seq created received verified : Int64)
    (hash key sig : ByteArray) (bad : sig.size ≠ 64) :
    (decodeJoinedHead [.text origin, .integer seq, .blob hash, .integer created,
      .blob key, .blob sig, .integer received, .integer verified]).run =
        .pure (.error (.column "heads.sig" "not 64 bytes")) := by
  simp [decodeJoinedHead, decodeJoinedFields, textField, integerField, blobField,
    bind, Except.bind, bad, ExceptT.run, ExceptT.mk, ExceptT.bind, ExceptT.bindCont, Program.bind, pure]
  rfl

/-- Later raw anomalies cannot replace the first field error or invoke crypto. -/
theorem joined_first_field_error (seq root created key sig received verified : Cell) :
    (decodeJoinedHead [.null, seq, root, created, key, sig, received, verified]).run =
      .pure (.error (.columnType 0 "origin_id" .null)) := by
  rfl

/-- Typed conversion of recorded_at precedes checking the root's byte width. -/
theorem receipt_type_before_width (seq : Int64) (root : ByteArray) :
    decodeReceipt [.integer seq, .blob root, .real 0] =
      .error (.columnType 2 "recorded_at" .real) := by
  rfl

/-! Scripted host fixtures run the actual free-monadic program. They deliberately
return raw cells; no fork, age, current or ceiling decisions enter from the host. -/
private def root (byte : UInt8) : ByteArray := ⟨Array.replicate 32 byte⟩
private def pointerRow (seq : Int64) (byte : UInt8) : Row := [.integer seq, .blob (root byte)]
private def receiptRow (seq : Int64) (byte : UInt8) (received : Int64) : Row :=
  pointerRow seq byte ++ [.integer received]

private def headRow (seq : Int64) (byte : UInt8) : Row :=
  [.text "node@example", .integer seq, .blob (root byte), .integer 0, .blob (root 0),
   .blob ⟨Array.replicate 64 0⟩, .integer 0, .integer 0]

private structure Script where
  pointers : List Row := []
  receipts : List Row := []
  failAt : Option Nat := none
  invalidKey : Bool := false
  scanFailure : Option Failure := none

private def failure : Failure := ⟨1, 99⟩

private def scriptReply (script : Script) (index : Nat) (value : A) : Reply A :=
  if script.failAt == some index then .error failure else .ok value

private structure State where
  script : Script
  index : Nat

private def step (state : State) (label : String) (value : A) : Option (String × Reply A × State) :=
  some (label, scriptReply state.script state.index value, { state with index := state.index + 1 })

private def refused (state : State) (label : String) : Option (String × Reply A × State) :=
  some (label, .error failure, { state with index := state.index + 1 })

private instance : Handlers.Handler Crypto State String where
  handle
    | .validateEd25519 _, s => step s "crypto" (!s.script.invalidKey)

private instance : Handlers.Handler Storage State String where
  handle
    | .begin, s => step s "begin" 7
    | .commit _, s => step s "commit" ()
    | .rollback _, s => step s "rollback" ()
    | .scanRows _ relation columns equals order joined, s =>
      if relation == "heads" && columns == headColumns && joined == headJoin && order.isEmpty then
        step s relation ⟨(if equals.contains ("slot", .text "complete") then s.script.pointers else []), none⟩
      else if relation == "head_history" && order == [⟨"seq", true⟩, ⟨"root", true⟩] then
        step s relation ⟨s.script.receipts, s.script.scanFailure⟩
      else refused s relation
    | .deleteRows _ relation equals blockers atMost, s =>
      if relation == "head_history" && blockers == [⟨"heads", equals, []⟩] && atMost.isEmpty then
        step s "delete" 1 else refused s "delete"
    | .readRows .., s => refused s "unexpected eager read"
    | .upsert _ _ _ _ _, s => refused s "unexpected upsert"
    | .readBytes _ _, s => refused s "unexpected byte read"
    | .readInput .., s => refused s "unexpected input read"
    | .readCounter .., s => refused s "unexpected counter read"
    | .removeFile .., s => refused s "unexpected file removal"
    | .existsRows .., s => refused s "unexpected existence query"

/-- Scripted execution of the actual free-monadic program from a given effect
index, so every failure position of the successful trace can be scripted. -/
private def runScript (script : Script) (fuel index : Nat) (program : Program Effects (Result Nat)) :
    Option (Result Nat × List String) :=
  Handlers.run fuel program (⟨script, index⟩ : State)

private def forkScript : Script :=
  { receipts := [receiptRow 1 1 10, receiptRow 1 2 10, receiptRow 2 3 10] }

/-- Earlier domain validation wins over a later scan failure. -/
example : runScript { receipts := [[.integer 1, .blob ByteArray.empty, .integer 0]], scanFailure := some failure }
    12 0 (prune "origin" 20).run =
    some (.error (.column "head_history.root" "0 bytes, not 32"),
      ["begin", "heads", "heads", "head_history", "rollback"]) := by decide

/-- A valid prefix does not hide the trailing failure or permit mutation. -/
example : runScript { forkScript with scanFailure := some failure }
    12 0 (prune "origin" 20).run =
    some (.error (.host failure), ["begin", "heads", "heads", "head_history", "rollback"]) := by decide

/-- Both expired fork roots are deleted, the ceiling survives, and success is
returned only after the commit acknowledgement. -/
example : runScript forkScript 12 0 (prune "origin" 20).run =
    some (.ok 2, ["begin", "heads", "heads", "head_history", "delete", "delete", "commit"]) := by
  decide

/-- The current pointer preserves its whole fork and the next old witness. -/
example : runScript { forkScript with pointers := [headRow 1 1] }
    12 0 (prune "origin" 20).run =
    some (.ok 0, ["begin", "heads", "crypto", "heads", "head_history", "commit"]) := by
  decide

/-- Invalid signing-key bytes stop the operation and roll back its transaction. -/
example : runScript { forkScript with pointers := [headRow 1 1], invalidKey := true }
    12 0 (prune "origin" 20).run =
    some (.error (.column "heads.signed_by" "data is not a valid public key"),
      ["begin", "heads", "crypto", "rollback"]) := by decide

/-- A primitive host failure retains its token and prevents any further reads. -/
example : runScript { forkScript with pointers := [headRow 1 1], failAt := some 2 }
    12 0 (prune "origin" 20).run =
    some (.error (.host failure), ["begin", "heads", "crypto", "rollback"]) := by decide

/-- A young side preserves the complete fork, never just one proof. -/
example : runScript { forkScript with
      receipts := [receiptRow 1 1 10, receiptRow 1 2 30, receiptRow 2 3 10] }
    12 0 (prune "origin" 20).run =
    some (.ok 0, ["begin", "heads", "heads", "head_history", "commit"]) := by
  decide

/-- Commit failure is not success, even after both delete acknowledgements. -/
example : runScript { forkScript with failAt := some 6 } 12 0 (prune "origin" 20).run =
    some (.error (.host failure), ["begin", "heads", "heads", "head_history", "delete", "delete", "commit", "rollback"]) := by
  decide

/-- A partial deletion failure stops immediately and rolls back the prefix. -/
example : runScript { forkScript with failAt := some 5 } 12 0 (prune "origin" 20).run =
    some (.error (.host failure), ["begin", "heads", "heads", "head_history", "delete", "delete", "rollback"]) := by
  decide

/-- Raw malformed pointers cause rollback before history reads or deletions. -/
example : runScript { forkScript with pointers := [[.integer 1, .blob ByteArray.empty]] }
    12 0 (prune "origin" 20).run =
    some (.error malformed, ["begin", "heads", "rollback"]) := by
  decide

/-- Every fallible position of the successful trace reports the original
failure, including begin, all three reads, both deletes, and commit. -/
example : (List.range 7).all (fun index =>
    ((runScript { forkScript with failAt := some index } 12 0 (prune "origin" 20).run).map
      (fun result => result.1)) == some (.error (.host failure))) = true := by
  decide

/-- An exempt fork retains its least higher old witness even when that witness
is not itself the sequence ceiling. -/
example : runScript { forkScript with receipts :=
      [receiptRow 1 1 10, receiptRow 1 2 30, receiptRow 2 3 10, receiptRow 3 4 10] }
    12 0 (prune "origin" 20).run =
    some (.ok 0, ["begin", "heads", "heads", "head_history", "commit"]) := by
  decide

/-- Negative SQL sequence cells are unsigned high sequences, not zero. The
maximum bit-pattern remains the ceiling, protecting recovery monotonicity. -/
example : runScript { forkScript with receipts := [receiptRow 2 1 10, receiptRow (-1) 2 10] }
    12 0 (prune "origin" 20).run =
    some (.ok 1, ["begin", "heads", "heads", "head_history", "delete", "commit"]) := by
  decide

end Synchronicity.HistoryProgramProofs
