import VerifiedCore.Replication.History
import Std.Data.TreeMap.Lemmas
import Std.Data.TreeSet.Lemmas
import Synchronicity.Prelude

/-! These properties concern the executable retention program, not a parallel model. -/
namespace Synchronicity.HistoryProgramProofs
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
  by_contra h
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
      .request (.deleteRows tx "head_history"
        (receiptKey origin receipt) [⟨"heads", receiptKey origin receipt⟩])
        (fun reply => match reply with
          | .error failure => .pure (.error failure)
          | .ok count => (removeLoop tx origin (total + count) rest).run) := by
  change Program.request _ _ = Program.request _ _
  congr 1
  funext reply
  cases reply <;> rfl

/-- Retention obtains raw pointers itself, within the caller's transaction. -/
theorem prune_reads_pointers (tx : Transaction) (origin : String) (before : Int64) :
    ∃ resume, (pruneIn tx origin before).run = .request
      (.readRows tx "heads" ["seq", "root"] [("origin_id", .text origin)]) resume := by
  exact ⟨_, rfl⟩

/-- The public operation itself requests its snapshot lock, before any read. -/
theorem prune_begins_transaction (origin : String) (before : Int64) :
    ∃ resume, (prune origin before).run = .request .begin resume := by
  exact ⟨_, rfl⟩

/-! Scripted host fixtures run the actual free-monadic program. They deliberately
return raw cells; no fork, age, current or ceiling decisions enter from the host. -/
private def root (byte : UInt8) : ByteArray := ⟨Array.replicate 32 byte⟩
private def pointerRow (seq : Int64) (byte : UInt8) : Row := [.integer seq, .blob (root byte)]
private def receiptRow (seq : Int64) (byte : UInt8) (received : Int64) : Row :=
  pointerRow seq byte ++ [.integer received]

private structure Script where
  pointers : List Row := []
  receipts : List Row := []
  failAt : Option Nat := none

private def failure : Failure := ⟨1, 99⟩

private def scriptReply (script : Script) (index : Nat) (value : A) : Reply A :=
  if script.failAt == some index then .error failure else .ok value

private def runScript (script : Script) : Nat → Nat →
    Program Storage (Reply Nat) → Option (Reply Nat × List String)
  | 0, _, _ => none
  | _ + 1, _, .pure value => some (value, [])
  | fuel + 1, index, .request effect resume =>
    let step (label : String) (next : Program Storage (Reply Nat)) :=
      (runScript script fuel (index + 1) next).map fun (result, trace) => (result, label :: trace)
    match effect with
    | .begin => step "begin" (resume (scriptReply script index 7))
    | .commit _ => step "commit" (resume (scriptReply script index ()))
    | .rollback _ => step "rollback" (resume (scriptReply script index ()))
    | .readRows _ relation _ _ order => step relation (resume
      (if relation == "heads" && order.isEmpty then scriptReply script index script.pointers
       else if relation == "head_history" && order == [⟨"seq", true⟩, ⟨"root", true⟩] then
         scriptReply script index script.receipts
       else .error failure))
    | .deleteRows _ relation equals blockers => step "delete" (resume
      (if relation == "head_history" && blockers == [⟨"heads", equals⟩] then
        scriptReply script index 1 else .error failure))
    | .upsert _ _ _ _ _ => step "unexpected upsert" (resume (.error failure))
    | .readBytes _ _ => step "unexpected byte read" (resume (.error failure))
    | .readInput .. => step "unexpected input read" (resume (.error failure))
    | .readCounter .. => step "unexpected counter read" (resume (.error failure))
    | .removeFile .. => step "unexpected file removal" (resume (.error failure))
    | .existsRows .. => step "unexpected existence query" (resume (.error failure))

private def forkScript : Script :=
  ⟨[], [receiptRow 1 1 10, receiptRow 1 2 10, receiptRow 2 3 10], none⟩

/-- Both expired fork roots are deleted, the ceiling survives, and success is
returned only after the commit acknowledgement. -/
example : runScript forkScript 12 0 (prune "origin" 20).run =
    some (.ok 2, ["begin", "heads", "head_history", "delete", "delete", "commit"]) := by
  decide

/-- The current pointer preserves its whole fork and the next old witness. -/
example : runScript { forkScript with pointers := [pointerRow 1 1] }
    12 0 (prune "origin" 20).run =
    some (.ok 0, ["begin", "heads", "head_history", "commit"]) := by
  decide

/-- A young side preserves the complete fork, never just one proof. -/
example : runScript { forkScript with
      receipts := [receiptRow 1 1 10, receiptRow 1 2 30, receiptRow 2 3 10] }
    12 0 (prune "origin" 20).run =
    some (.ok 0, ["begin", "heads", "head_history", "commit"]) := by
  decide

/-- Commit failure is not success, even after both delete acknowledgements. -/
example : runScript { forkScript with failAt := some 5 } 12 0 (prune "origin" 20).run =
    some (.error failure, ["begin", "heads", "head_history", "delete", "delete", "commit", "rollback"]) := by
  decide

/-- A partial deletion failure stops immediately and rolls back the prefix. -/
example : runScript { forkScript with failAt := some 4 } 12 0 (prune "origin" 20).run =
    some (.error failure, ["begin", "heads", "head_history", "delete", "delete", "rollback"]) := by
  decide

/-- Raw malformed pointers cause rollback before history reads or deletions. -/
example : runScript { forkScript with pointers := [[.integer 1, .blob ByteArray.empty]] }
    12 0 (prune "origin" 20).run =
    some (.error malformed, ["begin", "heads", "rollback"]) := by
  decide

/-- Every fallible position of the successful trace reports the original
failure, including begin, both reads, both deletes, and commit. -/
example : (List.range 6).all (fun index =>
    ((runScript { forkScript with failAt := some index } 12 0 (prune "origin" 20).run).map
      (fun result => result.1)) == some (.error failure)) = true := by
  decide

/-- An exempt fork retains its least higher old witness even when that witness
is not itself the sequence ceiling. -/
example : runScript { forkScript with receipts :=
      [receiptRow 1 1 10, receiptRow 1 2 30, receiptRow 2 3 10, receiptRow 3 4 10] }
    12 0 (prune "origin" 20).run =
    some (.ok 0, ["begin", "heads", "head_history", "commit"]) := by
  decide

/-- Negative SQL sequence cells are unsigned high sequences, not zero. The
maximum bit-pattern remains the ceiling, protecting recovery monotonicity. -/
example : runScript { forkScript with receipts := [receiptRow 2 1 10, receiptRow (-1) 2 10] }
    12 0 (prune "origin" 20).run =
    some (.ok 1, ["begin", "heads", "head_history", "delete", "commit"]) := by
  decide

end Synchronicity.HistoryProgramProofs

#lint
