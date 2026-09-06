import Synchronicity.SimulatedHost

/-! Checks of the shared raw semantics independently of any CAS policy. -/
deriving instance DecidableEq for VerifiedCore.Host.Cell

namespace Synchronicity.SimulatedHostProofs
open VerifiedCore.Host SimulatedHost
private def failure : Failure := ⟨1, 99⟩
private def base : State := { db := [("table", [[("id", .integer 1), ("value", .text "old")]])] }
private def started := storage .begin base
private def changed := access (.update 1 ⟨"table", [("id", .integer 1)], []⟩ [("value", .text "new")]) started.2

theorem transactions_hide_uncommitted_writes :
    (access (.snapshot ⟨"table", [], []⟩ ["value"]) changed.2).1.map Scan.rows == .ok [[.text "old"]] := by decide +kernel

theorem transactions_read_their_own_writes :
    (storage (.readRows 1 "table" ["value"] []) changed.2).1 == .ok [[.text "new"]] := by decide +kernel

theorem commit_publishes_writes :
    (access (.snapshot ⟨"table", [], []⟩ ["value"]) (storage (.commit 1) changed.2).2).1.map Scan.rows ==
      .ok [[.text "new"]] := by decide +kernel

theorem rollback_restores_committed_state : (storage (.rollback 1) changed.2).2.db == base.db := by decide +kernel

theorem failed_commit_does_not_publish :
    (storage (.commit 1) { changed.2 with faults := [(2, failure)] }).2.db == base.db := by decide +kernel

theorem invalid_transaction_token_cannot_mutate :
    let result := access (.delete 2 ⟨"table", [], []⟩) changed.2
    result.1 == .error invalid ∧ result.2.pending.map Prod.snd == changed.2.pending.map Prod.snd := by decide +kernel

theorem actual_delete_count_and_correlation :
    let state : State := { pending := some (1, [("a", [[("id", .integer 1)], [("id", .integer 2)]]),
      ("b", [[("ref", .integer 1)]])]) }
    let result := storage (.deleteRows 1 "a" [] [⟨"b", [], [("id", "ref")]⟩]) state
    result.1 == .ok 1 ∧ (result.2.pending.map fun (_, db) => rows db "a") == some [[("id", .integer 1)]] := by decide +kernel

theorem conflict_do_nothing_preserves_every_field :
    upsertRows [[("id", .integer 1), ("value", .text "old")]]
      [("id", .integer 1), ("value", .text "new")] ["id"] [] ==
        [[("id", .integer 1), ("value", .text "old")]] := by decide +kernel

theorem like_uses_wildcards_and_case_folding :
    like (.text "SOURCE:media") "source:%" && like (.text "ab") "a_" &&
    !like (.text "operator") "source:%" := by decide +kernel

theorem short_transfer_does_not_append_a_prefix :
    let state : State := { handles := [(1, ⟨#[1, 2]⟩)], output := [9] }
    let result := file (.transfer 1 0 3) state
    result.1 == .error ⟨truncated, .shortRead⟩ ∧ result.2.output == [9] := by decide +kernel

theorem opened_handle_keeps_its_file_after_replacement :
    let state : State := { files := [(("space", ByteArray.empty), ⟨#[1, 2]⟩)] }
    let opened := file (.open "space" ByteArray.empty) state
    let replaced := { opened.2 with files := writeFile opened.2.files ("space", ByteArray.empty) ⟨#[3, 4]⟩ }
    (file (.readAt 1 0 2) replaced).1 == .ok ⟨#[1, 2]⟩ := by decide +kernel

theorem failed_close_consumes_the_handle :
    let state : State := { handles := [(1, ⟨#[1]⟩)], faults := [(0, failure)] }
    (file (.close 1) state).2.handles.isEmpty := by decide +kernel

theorem abandonment_aborts_and_releases_private_resources :
    let state := { changed.2 with
      handles := [(1, ⟨#[1]⟩)], output := [1]
      leases := [(2, ("writers", ByteArray.empty))], counters := [(("writers", ByteArray.empty), 2)] }
    let result := abandon state
    result.db == base.db ∧ result.pending.isNone ∧ result.output.isEmpty ∧ result.handles.isEmpty ∧
      counter result ("writers", ByteArray.empty) == 1 := by decide +kernel

end Synchronicity.SimulatedHostProofs
