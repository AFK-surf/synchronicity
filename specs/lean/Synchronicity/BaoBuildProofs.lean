import Synchronicity.BaoHashProofs

/-! Whole-constructor evidence for the executable Bao program. Native reads,
writes and cryptographic primitives remain explicit environmental contracts.
Agreement with the grouped recurrence is not yet a theorem identifying that
recurrence with a standard BLAKE3 root or proving the complete outboard layout. -/
namespace Synchronicity.BaoBuildProofs
open VerifiedCore.Host VerifiedCore.Cas.Bao BaoHashProofs
set_option Elab.async false

/-- A successful bind contains both a successful first action and a successful
continuation, in the order fixed by the actual Program.bind constructor. -/
theorem bind_success_iff {A B : Type} (respond : Responder) (action : Action A)
    (next : A → Action B) (result : B) :
    interpret respond (action >>= next).run = .ok result ↔
      ∃ value, interpret respond action.run = .ok value ∧
        interpret respond (next value).run = .ok result := by
  rw [interpret_action_bind]
  cases interpret respond action.run <;> simp [Except.bind]

/-- Every accepted whole-constructor root has 32 bytes, even with arbitrary
host failures or malformed successful replies. No primitive honesty is needed. -/
theorem buildAux_success_width (respond : Responder) (fuel : Nat)
    (source payload outboard : UInt64) (offset size base : Nat) (root : Bool)
    (digest : ByteArray)
    (accepted : interpret respond (buildAux fuel source payload outboard offset size base root).run =
      .ok digest) : digest.size = 32 := by
  cases fuel with
  | zero =>
    by_cases leaf : size ≤ 16384
    · rw [buildAux] at accepted
      simp only [if_pos leaf] at accepted
      apply bind_success_property respond _ _ (fun digest => digest.size = 32) _ digest accepted
      intro bytes result success
      apply bind_success_property respond _ _ (fun digest => digest.size = 32) _ result success
      intro ignored result success
      exact hashAux_success_width respond _ _ _ _ _ success
    · rw [buildAux] at accepted
      simp [leaf, interpret] at accepted
  | succ fuel =>
    by_cases leaf : size ≤ 16384
    · rw [buildAux] at accepted
      simp only [if_pos leaf] at accepted
      apply bind_success_property respond _ _ (fun digest => digest.size = 32) _ digest accepted
      intro bytes result success
      apply bind_success_property respond _ _ (fun digest => digest.size = 32) _ result success
      intro ignored result success
      exact hashAux_success_width respond _ _ _ _ _ success
    · rw [BaoProgramProofs.build_branch_program fuel source payload outboard offset size base root
        (by omega)] at accepted
      apply bind_success_property respond _ _ (fun digest => digest.size = 32) _ digest accepted
      intro left result success
      apply bind_success_property respond _ _ (fun digest => digest.size = 32) _ result success
      intro right result success
      apply bind_success_property respond _ _ (fun digest => digest.size = 32) _ result success
      intro ignored result success
      exact hash_success_width respond _ _ success

theorem build_success_width (respond : Responder) (source payload outboard size : UInt64)
    (digest : ByteArray) (accepted : interpret respond (build source payload outboard size).run =
      .ok digest) : digest.size = 32 :=
  buildAux_success_width respond 64 source payload outboard 0 size.toNat 0 true digest accepted

/-- Successful branch completion requires both recursively built children,
the exact pair write, then a checked parent hash. Failed writes cannot be
skipped even when both child roots are already known. -/
theorem branch_success_requires_children_and_pair (respond : Responder) (fuel : Nat)
    (source payload outboard : UInt64) (offset size base : Nat) (root : Bool)
    (branch : 16384 < size) (digest : ByteArray)
    (accepted : interpret respond
      (buildAux (fuel + 1) source payload outboard offset size base root).run = .ok digest) :
    let split := splitBytes 16384 size
    ∃ left right,
      interpret respond (buildAux fuel source payload outboard offset split (base + 64) false).run = .ok left ∧
      interpret respond (buildAux fuel source payload outboard (offset + split) (size - split)
        (base + 64 * (split / 16384)) false).run = .ok right ∧
      interpret respond (VerifiedCore.Cas.Bao.writeAt outboard base (left ++ right)).run = .ok () ∧
      interpret respond (VerifiedCore.Cas.Bao.hash (.parent root left right)).run = .ok digest := by
  rw [BaoProgramProofs.build_branch_program fuel source payload outboard offset size base root branch]
    at accepted
  obtain ⟨left, leftDone, accepted⟩ := (bind_success_iff respond _ _ digest).1 accepted
  obtain ⟨right, rightDone, accepted⟩ := (bind_success_iff respond _ _ digest).1 accepted
  obtain ⟨ignored, pairDone, parentDone⟩ := (bind_success_iff respond _ _ digest).1 accepted
  cases ignored
  exact ⟨left, right, leftDone, rightDone, pairDone, parentDone⟩

/-- A bounded, immutable input view. Coherence with a physical file is a raw
read contract; no root, group, span or outboard is supplied by this model. -/
structure SourceModel where
  size : UInt64
  view : Nat → Nat → ByteArray
  exactSize : ∀ offset count, count ≤ 16384 → offset + count ≤ size.toNat →
    (view offset count).size = count

def ReadsSucceed (respond : Responder) (source : UInt64) (input : SourceModel) : Prop :=
  ∀ offset count, count ≤ 16384 → offset + count ≤ input.size.toNat →
    respond (.left (.readAt source offset.toUInt64 count.toUInt64)) = .ok (input.view offset count)

def WritesSucceed (respond : Responder) (handle : UInt64) : Prop :=
  ∀ (offset : Nat) (bytes : ByteArray),
    respond (.right (.left (.writeAt handle offset.toUInt64 bytes))) = .ok ()

def checkedRead (count : Nat) : FileReply ByteArray → Except Error ByteArray
  | .error failure => .error (.host failure.failure)
  | .ok bytes => if bytes.size == count then .ok bytes else .error .protocol

theorem interpret_readAt (respond : Responder) (source : UInt64) (offset count : Nat) :
    interpret respond (VerifiedCore.Cas.Bao.readAt source offset count).run =
      checkedRead count (respond (.left (.readAt source offset.toUInt64 count.toUInt64))) := by
  change interpret respond (.request (.left (.readAt source offset.toUInt64 count.toUInt64)) _) = _
  rw [interpret]
  generalize respond (.left (.readAt source offset.toUInt64 count.toUInt64)) = reply
  cases reply with
  | error failure => rfl
  | ok bytes =>
    simp only [Program.bind, ExceptT.bindCont]
    by_cases width : bytes.size = count <;> simp only [checkedRead, width, beq_iff_eq,
      if_true, if_false, bne_iff_ne, ne_eq, not_true_eq_false, not_false_eq_true] <;> rfl

theorem checkedRead_success_width (count : Nat) (reply : FileReply ByteArray) (bytes : ByteArray)
    (accepted : checkedRead count reply = .ok bytes) : bytes.size = count := by
  cases reply with
  | error failure => cases accepted
  | ok returned =>
    by_cases width : returned.size = count
    · have same : returned = bytes := by simpa [checkedRead, width] using accepted
      exact same ▸ width
    · simp [checkedRead, width] at accepted

theorem read_success_exact (respond : Responder) (source : UInt64) (offset count : Nat)
    (bytes : ByteArray)
    (accepted : interpret respond (VerifiedCore.Cas.Bao.readAt source offset count).run = .ok bytes) :
    bytes.size = count := by
  rw [interpret_readAt] at accepted
  exact checkedRead_success_width count _ bytes accepted

theorem read_under_contract (respond : Responder) (source : UInt64) (input : SourceModel)
    (reads : ReadsSucceed respond source input) (offset count : Nat) (bounded : count ≤ 16384)
    (within : offset + count ≤ input.size.toNat) :
    interpret respond (VerifiedCore.Cas.Bao.readAt source offset count).run =
      .ok (input.view offset count) := by
  calc
    _ = checkedRead count (respond (.left (.readAt source offset.toUInt64 count.toUInt64))) :=
      interpret_readAt respond source offset count
    _ = checkedRead count (.ok (input.view offset count)) :=
      congrArg (checkedRead count) (reads offset count bounded within)
    _ = _ := by simp [checkedRead, input.exactSize offset count bounded within]

theorem write_under_contract (respond : Responder) (handle : UInt64)
    (writes : WritesSucceed respond handle) (offset : Nat) (bytes : ByteArray) :
    interpret respond (VerifiedCore.Cas.Bao.writeAt handle offset bytes).run = .ok () := by
  change (respond (.right (.left (.writeAt handle offset.toUInt64 bytes)))).mapError Error.host = _
  exact congrArg (Except.mapError Error.host) (writes offset bytes)

/-- Pure grouped recurrence over raw input views and the existing inner
reference. It contains no writes, handles or host-prepared Bao information. -/
def groupedReference (model : PrimitiveModel) (input : SourceModel) :
    Nat → Nat → Nat → Bool → Except Error ByteArray
  | fuel, offset, size, root =>
    if size ≤ 16384 then reference model 4 (offset / 1024) root (input.view offset size)
    else match fuel with
      | 0 => .error .protocol
      | fuel + 1 => do
        let split := splitBytes 16384 size
        let left ← groupedReference model input fuel offset split false
        let right ← groupedReference model input fuel (offset + split) (size - split) false
        return model.parent root left right

/-- Conditional agreement for the complete executable constructor, including
every payload and pair write. Failures are excluded by explicit raw contracts,
not silently assumed away in the executable code. -/
theorem buildAux_matches_grouped_reference (model : PrimitiveModel) (respond : Responder)
    (crypto : PrimitiveContract model respond) (input : SourceModel)
    (source payload outboard : UInt64) (reads : ReadsSucceed respond source input)
    (payloadWrites : WritesSucceed respond payload) (pairWrites : WritesSucceed respond outboard)
    (fuel offset size base : Nat) (root : Bool) (within : offset + size ≤ input.size.toNat)
    (rootOffset : root = true → offset = 0) :
    interpret respond (buildAux fuel source payload outboard offset size base root).run =
      groupedReference model input fuel offset size root := by
  induction fuel generalizing offset size base root with
  | zero =>
    by_cases leaf : size ≤ 16384
    · rw [buildAux, groupedReference]
      simp only [if_pos leaf]
      change interpret respond
        ((VerifiedCore.Cas.Bao.readAt source offset size) >>= fun bytes =>
          VerifiedCore.Cas.Bao.writeAt payload offset bytes >>= fun _ =>
            hashAux 4 (offset / 1024) root bytes).run = _
      rw [interpret_action_bind, read_under_contract respond source input reads offset size leaf within]
      change interpret respond
        (VerifiedCore.Cas.Bao.writeAt payload offset (input.view offset size) >>= fun _ =>
          hashAux 4 (offset / 1024) root (input.view offset size)).run = _
      rw [interpret_action_bind, write_under_contract respond payload payloadWrites]
      exact hashAux_matches_reference model respond crypto 4 (offset / 1024) root (input.view offset size) (by
        intro isRoot; rw [rootOffset isRoot]; rfl)
    · rw [buildAux, groupedReference]
      simp [leaf, interpret]
  | succ fuel ih =>
    by_cases leaf : size ≤ 16384
    · rw [buildAux, groupedReference]
      simp only [if_pos leaf]
      change interpret respond
        ((VerifiedCore.Cas.Bao.readAt source offset size) >>= fun bytes =>
          VerifiedCore.Cas.Bao.writeAt payload offset bytes >>= fun _ =>
            hashAux 4 (offset / 1024) root bytes).run = _
      rw [interpret_action_bind, read_under_contract respond source input reads offset size leaf within]
      change interpret respond
        (VerifiedCore.Cas.Bao.writeAt payload offset (input.view offset size) >>= fun _ =>
          hashAux 4 (offset / 1024) root (input.view offset size)).run = _
      rw [interpret_action_bind, write_under_contract respond payload payloadWrites]
      exact hashAux_matches_reference model respond crypto 4 (offset / 1024) root (input.view offset size) (by
        intro isRoot; rw [rootOffset isRoot]; rfl)
    · rw [BaoProgramProofs.build_branch_program fuel source payload outboard offset size base root
        (by omega), groupedReference]
      simp only [if_neg leaf]
      let split := splitBytes 16384 size
      have strict : split < size := BaoProgramProofs.split_strict 16384 size (by decide) (by omega)
      have leftCorrect := ih offset split (base + 64) false (by omega) (by simp)
      have rightCorrect := ih (offset + split) (size - split) (base + 64 * (split / 16384)) false
        (by omega) (by simp)
      simp only [interpret_action_bind]
      rw [← leftCorrect, ← rightCorrect]
      cases leftResult : interpret respond
          (buildAux fuel source payload outboard offset split (base + 64) false).run with
      | error error => simp [bind, Except.bind]
      | ok left =>
        have leftWidth := buildAux_success_width respond fuel source payload outboard offset split
          (base + 64) false left leftResult
        cases rightResult : interpret respond
            (buildAux fuel source payload outboard (offset + split) (size - split)
              (base + 64 * (split / 16384)) false).run with
        | error error => simp [bind, Except.bind]
        | ok right =>
          have rightWidth := buildAux_success_width respond fuel source payload outboard (offset + split)
            (size - split) (base + 64 * (split / 16384)) false right rightResult
          simpa [leftResult, rightResult, write_under_contract respond outboard pairWrites,
            bind, Except.bind, pure, Except.pure] using
            parent_under_contract model respond crypto root left right leftWidth rightWidth

theorem build_matches_grouped_reference (model : PrimitiveModel) (respond : Responder)
    (crypto : PrimitiveContract model respond) (input : SourceModel)
    (source payload outboard : UInt64) (reads : ReadsSucceed respond source input)
    (payloadWrites : WritesSucceed respond payload) (pairWrites : WritesSucceed respond outboard) :
    interpret respond (build source payload outboard input.size).run =
      groupedReference model input 64 0 input.size.toNat true := by
  exact buildAux_matches_grouped_reference model respond crypto input source payload outboard
    reads payloadWrites pairWrites 64 0 input.size.toNat 0 true (by omega) (by simp)

end Synchronicity.BaoBuildProofs
