import Synchronicity.CasFixtures

/-! Acquisition runs against the common database, never scripted read replies. -/
namespace Synchronicity.CasProgramProofs
open VerifiedCore.Host VerifiedCore.Cas SimulatedHost CasFixtures

theorem durability_nonzero (value : Int64) :
    decodeDurability [[.integer value]] = .ok (value != 0) := rfl

/-- Missing rows are not durable; malformed columns are errors, not absence. -/
theorem missing_not_durable : decodeDurability [] = .ok false := rfl

theorem null_not_durable : decodeDurability [[.null]] = .error (.columnType 0 "durable" .null) := rfl

/-- Text, including numeric-looking text, retains its column-type error. -/
theorem text_not_durable (value : String) :
    decodeDurability [[.text value]] = .error (.columnType 0 "durable" .text) := rfl

/-- Opaque bytes cannot be coerced into a durable integer. -/
theorem blob_not_durable (value : ByteArray) :
    decodeDurability [[.blob value]] = .error (.columnType 0 "durable" .blob) := rfl

/-- Raw malformed text is still a text-type error for an integer projection;
attempting UTF-8 conversion first would change the original field error. -/
theorem raw_text_not_durable (value : ByteArray) :
    decodeDurability [[.rawText value]] = .error (.columnType 0 "durable" .text) := rfl

/-- REAL cells remain distinguishable until the domain selects its type error. -/
theorem real_not_durable (bits : UInt64) :
    decodeDurability [[.real bits]] = .error (.columnType 0 "durable" .real) := rfl

/-- A projection of any other shape is malformed metadata, not absence. -/
theorem wide_row_malformed (cell extra : Cell) :
    decodeDurability [[cell, extra]] = .error .malformed := rfl


private def wanting : State := { stored with db := [("blobs", [blob]), ("content_want", [want])] }
private def check (state : State := wanting) (possession : Bool := true) :=
  traceResult (acquire root "source:media" 123 possession) state

theorem successful_execution : check =
    (.ok true, ["begin", "read:blobs", "read:content_want", "delete:content_want", "upsert:pins", "commit"]) := by decide +kernel

theorem missing_row_refused : check { wanting with db := [("content_want", [want])] } =
    (.ok false, ["begin", "read:blobs", "commit"]) := by decide +kernel

theorem staged_row_refused : check { wanting with db := [("blobs", [blob root 4 1 .null .null 0]), ("content_want", [want])] } =
    (.ok false, ["begin", "read:blobs", "commit"]) := by decide +kernel

theorem cancelled_want_does_not_create_pin : check stored =
    (.ok false, ["begin", "read:blobs", "read:content_want", "commit"]) := by decide +kernel

theorem plain_pin_ignores_want : check stored false =
    (.ok true, ["begin", "read:blobs", "upsert:pins", "commit"]) := by decide +kernel

theorem acquisition_consumes_want_and_creates_pin :
    let result := SimulatedHost.run (acquire root "source:media" 123 true) wanting
    rows result.2.db "content_want" == [] ∧
      rows result.2.db "pins" == [[("root", .blob root), ("holder", .text "source:media"),
        ("created_at", .integer 123), ("release_after", .null)]] := by decide +kernel

theorem reacquisition_preserves_creation_time_and_clears_expiry :
    let initial := { stored with db := [("blobs", [blob]), ("pins", [pin root "operator" (.integer 10)])] }
    let result := SimulatedHost.run (acquire root "operator" 123 false) initial
    (rows result.2.db "pins").map (fun row => [cell row "created_at", cell row "release_after"]) ==
      [[.integer 7, .null]] := by decide +kernel

theorem every_failed_stage_restores_database :
    (List.range 6).all (fun index =>
      let result := SimulatedHost.run (acquire root "source:media" 123 true) (fail wanting index)
      failed result.1 && (result.2.db == wanting.db) && result.2.pending.isNone) = true := by decide +kernel

theorem rollback_failure_preserves_primary : check (fail (fail wanting 4) 5 secondary) =
    (.error (.host primary), ["begin", "read:blobs", "read:content_want", "delete:content_want", "upsert:pins", "rollback"]) := by decide +kernel

end Synchronicity.CasProgramProofs
