import Synchronicity.CasFixtures

namespace Synchronicity.CasExpiryProofs
open VerifiedCore.Host VerifiedCore.Cas SimulatedHost CasFixtures

/-- The exact bulk request, including the atomic per-row content correlation. -/
def mutation (tx : Transaction) (holder : Option PinHolder) (now : Int64) : Storage (Reply Nat) :=
  .deleteRows tx "pins"
    (match holder with
      | none => []
      | some holder => [("holder", .text holder.render)])
    [{ relation := "entries", equals := [], keys := [("root", "content")] }]
    [("release_after", .integer now)]

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


private def scheduled : State :=
  { db := [("pins", [pin root "operator" (.integer 10), pin otherRoot "operator" (.integer 11), pin root "source:media"])] }

theorem expiry_is_inclusive_and_ignores_unscheduled :
    let result := SimulatedHost.run (expire none 10) scheduled
    result.1 == .ok 1 ∧ rows result.2.db "pins" ==
      [pin otherRoot "operator" (.integer 11), pin root "source:media"] := by decide +kernel

theorem live_entry_protects_every_holder :
    let initial := { scheduled with db := scheduled.db ++ [("entries", [entry])] }
    let result := SimulatedHost.run (expire none 10) initial
    result.1 == .ok 0 ∧ rows result.2.db "pins" == rows initial.db "pins" := by decide +kernel

theorem every_failure_restores_pins :
    (List.range 3).all (fun index =>
      let result := SimulatedHost.run (expire none 10) (fail scheduled index)
      failed result.1 && (result.2.db == scheduled.db)) = true := by decide +kernel

end Synchronicity.CasExpiryProofs
