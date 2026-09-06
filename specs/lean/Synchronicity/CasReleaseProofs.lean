import Synchronicity.CasFixtures

namespace Synchronicity.CasReleaseProofs
open VerifiedCore.Host VerifiedCore.Cas SimulatedHost CasFixtures

/-- The sole mutation's exact key and atomic live-entry exclusion. -/
def mutation (tx : Transaction) (root : ByteArray) (holder : PinHolder) : Storage (Reply Nat) :=
  .deleteRows tx "pins" [("root", .blob root), ("holder", .text holder.render)]
    (match holder.space with
      | none => []
      | some space => [⟨"entries", [("space", .text space), ("content", .blob root)], []⟩])

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


private def pinned : State := { stored with db := [("blobs", [blob]), ("pins", [pin, pin root "operator"])] }

theorem release_removes_only_requested_holder :
    let result := SimulatedHost.run (unpin root .operator) pinned
    result.1 == .ok true ∧ rows result.2.db "pins" == [pin] := by decide +kernel

theorem live_entry_protects_standing_role :
    let initial := { pinned with db := pinned.db ++ [("entries", [entry])] }
    let result := SimulatedHost.run (unpin root (.source "media")) initial
    result.1 == .ok false ∧ rows result.2.db "pins" == rows initial.db "pins" := by decide +kernel

theorem every_failure_restores_pins :
    (List.range 3).all (fun index =>
      let result := SimulatedHost.run (unpin root .operator) (fail pinned index)
      failed result.1 && (result.2.db == pinned.db)) = true := by decide +kernel

end Synchronicity.CasReleaseProofs
