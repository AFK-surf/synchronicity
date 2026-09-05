import VerifiedCore.Replication.History
import Synchronicity.Prelude

/-! These properties concern the executable retention program, not a parallel model. -/
namespace Synchronicity.HistoryProgramProofs
open VerifiedCore.Host VerifiedCore.Replication.History

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

/-- Deletion effects contain the exact retained-record key. A failed delete
has no continuation that can attempt another deletion or return success. -/
theorem remove_next (tx : Transaction) (origin : String) (total : Nat)
    (receipt : Receipt) (rest : List Receipt) :
    (removeLoop tx origin total (receipt :: rest)).run =
      .request (.deleteRows tx "head_history"
        [("origin_id", .text origin), ("seq", .integer receipt.pointer.seq.toInt64),
         ("root", .blob receipt.pointer.root)])
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
    | .readRows _ relation _ _ => step relation (resume
      (scriptReply script index (if relation == "heads" then script.pointers else script.receipts)))
    | .deleteRows _ _ _ => step "delete" (resume (scriptReply script index 1))
    | .upsert _ _ _ _ _ => step "unexpected upsert" (resume (.error failure))
    | .readBytes _ _ => step "unexpected byte read" (resume (.error failure))

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
