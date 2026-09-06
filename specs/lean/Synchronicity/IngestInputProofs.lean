import VerifiedCore.Cas.Input
import Synchronicity.HostResourceProofs
import Init.Data.ByteArray.Lemmas

/-! Input-policy proofs of the executable orchestration. Large captures are
handled compositionally, without allocating giant kernel-evaluated fixtures. -/
namespace Synchronicity.IngestInputProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Cas
open VerifiedCore.Cas.Input
set_option Elab.async false

/-- Capacity affects allocation only, never the captured byte sequence. -/
theorem flatten_capacity_irrelevant (first second : Nat) (chunks : List ByteArray) :
    flattenCapture first chunks = flattenCapture second chunks := rfl

/-- Retaining a new chunk at the head of the reversed list appends exactly
that chunk after the earlier capture, for arbitrary allocation capacities. -/
theorem flatten_capture_cons (nextCapacity previousCapacity : Nat)
    (bytes : ByteArray) (chunks : List ByteArray) :
    flattenCapture nextCapacity (bytes :: chunks) =
      flattenCapture previousCapacity chunks ++ bytes := by
  unfold flattenCapture
  rw [List.reverse_cons, List.foldl_append]
  rfl

/-- Every captured byte occurs once in the final allocation, independently
of the capacity hint. This is a universal length law, not a fixture. -/
theorem flatten_capture_size (capacity : Nat) (chunks : List ByteArray) :
    (flattenCapture capacity chunks).size = (chunks.map ByteArray.size).sum := by
  induction chunks with
  | nil => rfl
  | cons bytes chunks ih =>
    rw [flatten_capture_cons capacity capacity bytes chunks, ByteArray.size_append, ih]
    change (chunks.map ByteArray.size).sum + bytes.size =
      bytes.size + (chunks.map ByteArray.size).sum
    exact Nat.add_comm _ _

theorem collecting_chunk_preserves_ordered_capture (total : Nat)
    (bytes : ByteArray) (chunks : List ByteArray) :
    flattenCapture (total + bytes.size) (bytes :: chunks) =
      flattenCapture total chunks ++ bytes :=
  flatten_capture_cons _ _ _ _

theorem bytes_open_without_stat (size : UInt64) (now : Int64) (tier : IngestCommit.Tier)
    (policy : Ingest.DirectoryPolicy) :
    ∃ resume, (run (.bytes size) now tier policy).run =
      .request (.left (.left (.left (.open "input" ByteArray.empty)))) resume := ⟨_, rfl⟩

theorem file_stat_precedes_open (now : Int64) (tier : IngestCommit.Tier)
    (policy : Ingest.DirectoryPolicy) :
    ∃ resume, (run .file now tier policy).run =
      .request (.right (.stat "input" ByteArray.empty)) resume := ⟨_, rfl⟩

theorem file_stat_failure_cannot_open (now : Int64) (tier : IngestCommit.Tier)
    (policy : Ingest.DirectoryPolicy) (failure : Failure) :
    ∃ resume, (run .file now tier policy).run =
      .request (.right (.stat "input" ByteArray.empty)) resume ∧
      resume (.error failure) = .pure (.error (.host failure)) := ⟨_, rfl, rfl⟩

theorem file_stat_success_then_open (now : Int64) (tier : IngestCommit.Tier)
    (policy : Ingest.DirectoryPolicy) (size : UInt64) :
    ∃ resume next, (run .file now tier policy).run =
      .request (.right (.stat "input" ByteArray.empty)) resume ∧
      resume (.ok size) =
        .request (.left (.left (.left (.open "input" ByteArray.empty)))) next := ⟨_, _, rfl, rfl⟩

/-- Exact immutable bytes do not use EOF collection or filesystem metadata. -/
theorem three_bytes_input_requests_exact_read (now : Int64) (tier : IngestCommit.Tier)
    (policy : Ingest.DirectoryPolicy) (handle : UInt64) :
    ∃ opened next, (run (.bytes 3) now tier policy).run =
      .request (.left (.left (.left (.open "input" ByteArray.empty)))) opened ∧
      opened (.ok handle) =
        .request (.left (.left (.left (.readAt handle 0 3)))) next := ⟨_, _, rfl, rfl⟩

/-- An initially small file requests up-to reads, not an exact read of stat's
size. That distinction preserves a shrinking or growing file's captured bytes. -/
theorem initially_small_file_collects_to_eof (now : Int64) (tier : IngestCommit.Tier)
    (policy : Ingest.DirectoryPolicy) (handle : UInt64) :
    ∃ stated opened next, (run .file now tier policy).run =
      .request (.right (.stat "input" ByteArray.empty)) stated ∧
      stated (.ok 3) =
        .request (.left (.left (.left (.open "input" ByteArray.empty)))) opened ∧
      opened (.ok handle) = .request (.right (.readSome handle 0 65536)) next :=
  ⟨_, _, _, rfl, rfl, rfl⟩

theorem initially_large_file_delegates_captured_stat_size (now : Int64)
    (tier : IngestCommit.Tier) (policy : Ingest.DirectoryPolicy) (handle : UInt64) :
    ∃ stated opened, (run .file now tier policy).run =
      .request (.right (.stat "input" ByteArray.empty)) stated ∧
      stated (.ok 16385) =
        .request (.left (.left (.left (.open "input" ByteArray.empty)))) opened ∧
      opened (.ok handle) = (captured handle 16385 now tier policy).run :=
  ⟨_, _, rfl, rfl, rfl⟩

theorem collector_fuel_exhaustion_has_no_read (handle : UInt64) (total : Nat) (chunks : List ByteArray) :
    (collectAux 0 handle total chunks).run = .pure (.error .protocol) := rfl

/-- Each observation uses the current byte count as its offset and consumes
one unit of fuel, including the final EOF observation. -/
theorem collector_step (fuel : Nat) (handle : UInt64) (total : Nat) (chunks : List ByteArray) :
    (collectAux (fuel + 1) handle total chunks).run =
      .request (.right (.readSome handle total.toUInt64 65536)) (fun reply =>
        match reply with
        | .error failure => .pure (.error (.host failure))
        | .ok bytes =>
          if bytes.size > 65536 || total + bytes.size > 18446744073709551615 then
            .pure (.error .protocol)
          else if bytes.isEmpty then .pure (.ok (flattenCapture total chunks))
          else (collectAux fuel handle (total + bytes.size) (bytes :: chunks)).run) := by
  rw [collectAux]
  change Program.request (E := Effects) (A := Except Error ByteArray)
    (.right (.readSome handle total.toUInt64 65536)) _ = _
  apply congrArg (Program.request (E := Effects) (A := Except Error ByteArray)
    (.right (.readSome handle total.toUInt64 65536)))
  funext reply
  cases reply with
  | error failure => rfl
  | ok bytes => rfl

theorem collector_host_failure_preserved (fuel : Nat) (handle : UInt64) (total : Nat) (chunks : List ByteArray)
    (failure : Failure) :
    ∃ resume, (collectAux (fuel + 1) handle total chunks).run =
      .request (.right (.readSome handle total.toUInt64 65536)) resume ∧
      resume (.error failure) = .pure (.error (.host failure)) := ⟨_, rfl, rfl⟩

theorem nonempty_chunk_advances_capture_and_fuel (fuel : Nat) (handle : UInt64)
    (total : Nat) (chunks : List ByteArray) (bytes : ByteArray) (bounded : ¬ bytes.size > 65536)
    (fits : ¬ total + bytes.size > 18446744073709551615) (nonempty : bytes.isEmpty = false) :
    ∃ resume, (collectAux (fuel + 1) handle total chunks).run =
      .request (.right (.readSome handle total.toUInt64 65536)) resume ∧
      resume (.ok bytes) = (collectAux fuel handle (total + bytes.size) (bytes :: chunks)).run := by
  rw [collector_step]
  refine ⟨_, rfl, ?_⟩
  simp [bounded, fits, nonempty]

/-- Oversized successful replies cannot append bytes or request another read. -/
theorem oversized_chunk_rejected_before_append (fuel : Nat) (handle : UInt64)
    (total : Nat) (chunks : List ByteArray) (bytes : ByteArray) (oversized : bytes.size > 65536) :
    ∃ resume, (collectAux (fuel + 1) handle total chunks).run =
      .request (.right (.readSome handle total.toUInt64 65536)) resume ∧
      resume (.ok bytes) = .pure (.error .protocol) := by
  rw [collector_step]
  refine ⟨_, rfl, ?_⟩
  simp [oversized]

theorem oversized_collector_reply_runs_owned_source_close (fuel : Nat) (handle : UInt64)
    (total : Nat) (chunks : List ByteArray) (bytes : ByteArray) (oversized : bytes.size > 65536) :
    ∃ resume, (ensure (collectAux (fuel + 1) handle total chunks) (closeSource handle)).run =
      .request (.right (.readSome handle total.toUInt64 65536)) resume ∧
      resume (.ok bytes) = .request (.left (.left (.left (.close handle))))
        (fun _ => .pure (.error .protocol)) := by
  obtain ⟨resume, equation, rejected⟩ :=
    oversized_chunk_rejected_before_append fuel handle total chunks bytes oversized
  rw [HostResourceProofs.ensure_expansion, equation]
  refine ⟨_, rfl, ?_⟩
  change (resume (.ok bytes)).bind _ = _
  rw [rejected]
  rfl

theorem inline_capture_uses_actual_bytes (bytes : ByteArray) (now : Int64)
    (tier : IngestCommit.Tier) (policy : Ingest.DirectoryPolicy) (small : bytes.size ≤ 16384) :
    capturedBytes bytes now tier policy = inlineBytes bytes now tier := by
  simp [capturedBytes, small]

/-- The growing-file branch freezes the captured stream itself. Neither the
mutable source path nor its earlier stat size is an input to this continuation. -/
theorem grown_capture_freezes_exact_bytes (bytes : ByteArray) (now : Int64)
    (tier : IngestCommit.Tier) (policy : Ingest.DirectoryPolicy) (large : ¬ bytes.size ≤ 16384) :
    (capturedBytes bytes now tier policy).run =
      .request (.right (.freeze bytes)) (fun reply => match reply with
        | .error failure => .pure (.error (.host failure))
        | .ok handle => (captured handle bytes.size.toUInt64 now tier policy).run) := by
  simp only [capturedBytes, large, ↓reduceIte]
  change Program.request (E := Effects) (A := Except Error Input.Result) (.right (.freeze bytes)) _ = _
  apply congrArg (Program.request (E := Effects) (A := Except Error Input.Result) (.right (.freeze bytes)))
  funext reply
  cases reply with
  | error failure => rfl
  | ok handle => rfl

/-- This is the actual large-input continuation, not a separately executed
large-byte fixture. It immediately starts owned staging under Ingest.run. -/
theorem captured_delegates_exact_size (handle size : UInt64) (now : Int64)
    (tier : IngestCommit.Tier) (policy : Ingest.DirectoryPolicy) :
    (captured handle size now tier policy).run =
      ((Ingest.run handle size now tier policy).run.mapEffects EffectSum.left).bind
        (fun reply => .pure ((reply.mapError Error.ingestion).map (fun root => ⟨root, size⟩))) := rfl

private def twoBytes : ByteArray := ⟨#[41, 42]⟩

/-- The explicit counter is a cached sum, not independently supplied metadata. -/
theorem capture_total_preserved (total : Nat) (chunks : List ByteArray) (bytes : ByteArray)
    (consistent : total = (chunks.map ByteArray.size).sum) :
    total + bytes.size = ((bytes :: chunks).map ByteArray.size).sum := by
  simp only [List.map_cons, List.sum_cons]
  omega

theorem flatten_preserves_capture_order :
    flattenCapture 4 [⟨#[43, 44]⟩, twoBytes] = ⟨#[41, 42, 43, 44]⟩ := rfl

theorem eof_flattens_multiple_chunks_in_original_order (handle : UInt64) :
    ∃ resume, (collectAux 1 handle 4 [⟨#[43, 44]⟩, twoBytes]).run =
      .request (.right (.readSome handle 4 65536)) resume ∧
      resume (.ok ByteArray.empty) = .pure (.ok ⟨#[41, 42, 43, 44]⟩) := ⟨_, rfl, rfl⟩

/-- EOF returns the bytes accumulated, not the earlier stat length. -/
theorem eof_returns_actual_capture (handle : UInt64) :
    ∃ resume, (collectAux 1 handle 2 [twoBytes]).run =
      .request (.right (.readSome handle 2 65536)) resume ∧
      resume (.ok ByteArray.empty) = .pure (.ok twoBytes) := ⟨_, rfl, rfl⟩

theorem source_close_failure_prevents_capture_publication (handle : UInt64) (failure : Failure) :
    ∃ resume, (ensure (pure twoBytes : Action ByteArray) (closeSource handle)).run =
      .request (.left (.left (.left (.close handle)))) resume ∧
      resume (.error failure) = .pure (.error (.host failure)) := ⟨_, rfl, rfl⟩

theorem whole_small_input_close_failure_stops_before_hash (now : Int64)
    (tier : IngestCommit.Tier) (policy : Ingest.DirectoryPolicy) (handle : UInt64)
    (failure : Failure) :
    ∃ opened read closed, (run (.bytes 2) now tier policy).run =
      .request (.left (.left (.left (.open "input" ByteArray.empty)))) opened ∧
      opened (.ok handle) = .request (.left (.left (.left (.readAt handle 0 2)))) read ∧
      read (.ok twoBytes) = .request (.left (.left (.left (.close handle)))) closed ∧
      closed (.error failure) = .pure (.error (.host failure)) := ⟨_, _, _, rfl, rfl, rfl, rfl⟩

end Synchronicity.IngestInputProofs
