import Synchronicity.CasProgramProofs

/-! Executions of the production scheduled pin-expiry command. These proofs
retain the complete raw mutation, its correlation and inclusive deadline, not
a second implementation of the expiry policy. -/
namespace Synchronicity.CasExpiryProofs
open VerifiedCore.Host VerifiedCore.Cas
open CasProgramProofs (Event Script execute)

/-- Execute the actual command against independently scripted host replies. -/
def run (script : Script) (holder : Option PinHolder) (now : Int64) :
    Reply Nat × List Event :=
  execute script (expire holder now).run

/-- The exact bulk request, including the atomic per-row content correlation. -/
def mutation (tx : Transaction) (holder : Option PinHolder) (now : Int64) : Event :=
  .deleteRows tx "pins"
    (match holder with
      | none => []
      | some holder => [("holder", .text holder.render)])
    [{ relation := "entries", equals := [], keys := [("root", "content")] }]
    [("release_after", .integer now)]

/-- No rows are pre-read, interpreted in Rust, or individually deleted. The
exact affected-row count is returned after successful commit, including zero. -/
@[rust_impl "cas-expiry-operation"]
theorem successful_execution (tx : Transaction) (holder : Option PinHolder)
    (now : Int64) (count : Nat) :
    run { begin := .ok tx, delete := .ok count } holder now =
      (.ok count, [.begin, mutation tx holder now, .commit tx]) := rfl

/-- Global expiry does not restrict the holder or the protecting entry's space. -/
theorem global_mutation (tx : Transaction) (now : Int64) :
    mutation tx none now =
      .deleteRows tx "pins" []
        [{ relation := "entries", equals := [], keys := [("root", "content")] }]
        [("release_after", .integer now)] := rfl

/-- Holder-specific expiry uses its exact rendered key, with the same global
live-content protection as global expiry. -/
theorem holder_mutation (tx : Transaction) (holder : PinHolder) (now : Int64) :
    mutation tx (some holder) now =
      .deleteRows tx "pins" [("holder", .text holder.render)]
        [{ relation := "entries", equals := [], keys := [("root", "content")] }]
        [("release_after", .integer now)] := rfl

/-- Unlike explicit unpin, scheduled expiry treats identical persisted holder
spellings identically: no typed role changes the live-content exclusion. -/
theorem equal_spelling_equal_mutation (tx : Transaction) (left right : PinHolder)
    (now : Int64) (same : left.render = right.render) :
    mutation tx (some left) now = mutation tx (some right) now := by
  simp only [mutation, same]

/-- An empty deletion is still committed, with no fallback mutation. -/
theorem no_rows_expired (tx : Transaction) (holder : Option PinHolder) (now : Int64) :
    run { begin := .ok tx, delete := .ok 0 } holder now =
      (.ok 0, [.begin, mutation tx holder now, .commit tx]) := rfl

/-- A failed begin issues neither a mutation nor a rollback. -/
theorem begin_failure (failure : Failure) (holder : Option PinHolder) (now : Int64) :
    run { begin := .error failure } holder now = (.error failure, [.begin]) := rfl

/-- A failed bulk mutation cannot commit; rollback failure is secondary. -/
theorem delete_failure (tx : Transaction) (failure : Failure) (rollback : Reply Unit)
    (holder : Option PinHolder) (now : Int64) :
    run { begin := .ok tx, delete := .error failure, rollback := rollback } holder now =
      (.error failure, [.begin, mutation tx holder now, .rollback tx]) := rfl

/-- No affected-row count escapes when commit fails, even after a successful
bulk mutation and even when rollback independently fails. -/
theorem commit_failure (tx : Transaction) (failure : Failure) (rollback : Reply Unit)
    (holder : Option PinHolder) (now : Int64) (count : Nat) :
    run { begin := .ok tx, delete := .ok count, commit := .error failure, rollback := rollback }
        holder now =
      (.error failure, [.begin, mutation tx holder now, .commit tx, .rollback tx]) := rfl

end Synchronicity.CasExpiryProofs

#lint
