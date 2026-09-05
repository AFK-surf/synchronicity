import Synchronicity.CasProgramProofs

/-! Executions of the production explicit pin-release operation. These proofs
check its actual storage requests, not a separate abstract CAS transition. -/
namespace Synchronicity.CasReleaseProofs
open VerifiedCore.Host VerifiedCore.Cas
open CasProgramProofs (Event Script execute)

/-- Execute the actual command with independently scripted raw host replies. -/
def run (script : Script) (root : ByteArray) (holder : PinHolder) :
    Reply Bool × List Event :=
  execute script (unpin root holder).run

/-- The sole mutation's exact key and atomic live-entry exclusion. -/
def mutation (tx : Transaction) (root : ByteArray) (holder : PinHolder) : Event :=
  .deleteRows tx "pins" [("root", .blob root), ("holder", .text holder.render)]
    (match holder.space with
      | none => []
      | some space => [⟨"entries", [("space", .text space), ("content", .blob root)]⟩])

/-- There are no metadata reads or secondary mutations: the single DELETE
carries the guard, and its affected-row count is returned only after commit. -/
@[rust_impl "cas-release-operation"]
theorem successful_execution (tx : Transaction) (root : ByteArray)
    (holder : PinHolder) (count : Nat) :
    run { begin := .ok tx, delete := .ok count } root holder =
      (.ok (count != 0), [.begin, mutation tx root holder, .commit tx]) := rfl

/-- Operator claims do not acquire a live-entry exclusion. -/
theorem operator_mutation (tx : Transaction) (root : ByteArray) :
    mutation tx root .operator =
      .deleteRows tx "pins" [("root", .blob root), ("holder", .text "operator")] [] := rfl

/-- Unknown typed holders are preserved verbatim and do not become roles. -/
theorem other_mutation (tx : Transaction) (root : ByteArray) (text : String) :
    mutation tx root (.other text) =
      .deleteRows tx "pins" [("root", .blob root), ("holder", .text text)] [] := rfl

/-- A source's current entry protects exactly the root in exactly its space. -/
theorem source_mutation (tx : Transaction) (root : ByteArray) (space : String) :
    mutation tx root (.source space) =
      .deleteRows tx "pins"
        [("root", .blob root), ("holder", .text ("source:" ++ space))]
        [{ relation := "entries", equals := [("space", .text space), ("content", .blob root)] }] := rfl

/-- Replica protection uses the same live-entry relation, not source policy. -/
theorem replica_mutation (tx : Transaction) (root : ByteArray) (space : String) :
    mutation tx root (.replica space) =
      .deleteRows tx "pins"
        [("root", .blob root), ("holder", .text ("replica:" ++ space))]
        [{ relation := "entries", equals := [("space", .text space), ("content", .blob root)] }] := rfl

/-- The public typed role survives even when its space is empty. -/
theorem empty_source_is_role : PinHolder.space (.source "") = some "" := rfl

theorem empty_replica_is_role : PinHolder.space (.replica "") = some "" := rfl

/-- Equal database spellings do not collapse distinct command meanings. -/
theorem role_like_other_is_not_role (space : String) :
    PinHolder.render (.other ("source:" ++ space)) = PinHolder.render (.source space) ∧
      PinHolder.space (.other ("source:" ++ space)) = none ∧
      PinHolder.space (.source space) = some space := ⟨rfl, rfl, rfl⟩

/-- A protected or absent claim reports false, without any fallback deletion. -/
theorem no_rows_released (tx : Transaction) (root : ByteArray) (holder : PinHolder) :
    run { begin := .ok tx, delete := .ok 0 } root holder =
      (.ok false, [.begin, mutation tx root holder, .commit tx]) := rfl

/-- A failed begin cannot issue a delete or a spurious rollback. -/
theorem begin_failure (failure : Failure) (root : ByteArray) (holder : PinHolder) :
    run { begin := .error failure } root holder = (.error failure, [.begin]) := rfl

/-- Deletion failure prevents commit. Any rollback failure remains secondary. -/
theorem delete_failure (tx : Transaction) (failure : Failure) (rollback : Reply Unit)
    (root : ByteArray) (holder : PinHolder) :
    run { begin := .ok tx, delete := .error failure, rollback := rollback } root holder =
      (.error failure, [.begin, mutation tx root holder, .rollback tx]) := rfl

/-- Even a successful mutation cannot report release before commit succeeds.
This also covers count zero and an independently failing rollback. -/
theorem commit_failure (tx : Transaction) (failure : Failure) (rollback : Reply Unit)
    (root : ByteArray) (holder : PinHolder) (count : Nat) :
    run { begin := .ok tx, delete := .ok count, commit := .error failure, rollback := rollback } root holder =
      (.error failure, [.begin, mutation tx root holder, .commit tx, .rollback tx]) := rfl

end Synchronicity.CasReleaseProofs

#lint
