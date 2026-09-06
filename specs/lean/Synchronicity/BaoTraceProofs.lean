import Synchronicity.BaoLayoutProofs
import Synchronicity.HostResourceProofs

/-! Accumulated outboard-write request traces of the actual Bao program.
Replies come from an arbitrary deterministic raw responder: this proves the
complete observed trace, not a filesystem implementation or a theorem for
history-dependent replies. Failed writes are recorded too; the final theorem
requires successful completion. -/
namespace Synchronicity.BaoTraceProofs
open VerifiedCore.Host VerifiedCore.Cas.Bao BaoHashProofs BaoBuildProofs BaoLayoutProofs
set_option Elab.async false

def writeEvent {A : Type} (outboard : UInt64) : Effects A → List UInt64
  | .left _ => []
  | .right effect => match effect with
    | .right _ => []
    | .left writer => match writer with
      | .writeAt handle offset _ => if handle = outboard then [offset] else []

/-- Observe requests along the actual continuations selected by raw replies.
This retains every matching request, including repeated identical offsets. -/
def writeTrace {A : Type} (respond : Responder) (outboard : UInt64) :
    Program Effects A → List UInt64
  | .pure _ => []
  | .request effect resume =>
      writeEvent outboard effect ++ writeTrace respond outboard (resume (respond effect))

/-- The result and its accumulated request log share the same deterministic
environment and therefore follow the same path through the executable. -/
def observe {A : Type} (respond : Responder) (outboard : UInt64)
    (program : Program Effects A) : A × List UInt64 :=
  (interpret respond program, writeTrace respond outboard program)

/-- A genuinely accumulating host: replies are independent of history, but
the updated log is passed to each subsequent request by the shared interpreter. -/
def accumulatingResponder (respond : Responder) (outboard : UInt64)
    {A : Type} (effect : Effects A) (initial : List UInt64) : A × List UInt64 :=
  (respond effect, initial ++ writeEvent outboard effect)

/-- The shared stateful interpreter produces the same result and complete
write trace, extending rather than replacing an arbitrary initial log. -/
theorem accumulating_interpret {A : Type} (respond : Responder) (outboard : UInt64)
    (program : Program Effects A) (initial : List UInt64) :
    HostResourceProofs.interpret (accumulatingResponder respond outboard) program initial =
      (interpret respond program, initial ++ writeTrace respond outboard program) := by
  induction program generalizing initial with
  | pure value => simp only [HostResourceProofs.interpret, interpret, writeTrace, List.append_nil]
  | request effect resume ih =>
    simp only [HostResourceProofs.interpret, accumulatingResponder, interpret, writeTrace]
    rw [ih]
    simp only [List.append_assoc]

theorem writeTrace_bind {A B : Type} (respond : Responder) (outboard : UInt64)
    (program : Program Effects A) (next : A → Program Effects B) :
    writeTrace respond outboard (Program.bind program next) =
      writeTrace respond outboard program ++
        writeTrace respond outboard (next (interpret respond program)) := by
  induction program with
  | pure value => rfl
  | request effect resume ih =>
    simp only [Program.bind, writeTrace, interpret, ih, List.append_assoc]

theorem writeTrace_action_bind {A B : Type} (respond : Responder) (outboard : UInt64)
    (action : Action A) (next : A → Action B) :
    writeTrace respond outboard (action >>= next).run =
      writeTrace respond outboard action.run ++
        match interpret respond action.run with
        | .error _ => []
        | .ok value => writeTrace respond outboard (next value).run := by
  change writeTrace respond outboard (Program.bind action.run _) = _
  rw [writeTrace_bind]
  cases interpret respond action.run <;> rfl

theorem writeTrace_bind_success {A B : Type} (respond : Responder) (outboard : UInt64)
    (action : Action A) (next : A → Action B) (value : A)
    (accepted : interpret respond action.run = .ok value) :
    writeTrace respond outboard (action >>= next).run =
      writeTrace respond outboard action.run ++ writeTrace respond outboard (next value).run := by
  rw [writeTrace_action_bind, accepted]

theorem writeTrace_bind_empty {A B : Type} (respond : Responder) (outboard : UInt64)
    (action : Action A) (next : A → Action B)
    (first : writeTrace respond outboard action.run = [])
    (rest : ∀ value, writeTrace respond outboard (next value).run = []) :
    writeTrace respond outboard (action >>= next).run = [] := by
  rw [writeTrace_action_bind, first]
  cases interpret respond action.run <;> simp only [rest, List.nil_append]

theorem hash_writeTrace (respond : Responder) (outboard : UInt64)
    (effect : Blake3 (Reply ByteArray)) :
    writeTrace respond outboard (VerifiedCore.Cas.Bao.hash effect).run = [] := by
  change writeTrace respond outboard (.request (.right (.right effect)) _) = []
  rw [writeTrace]
  generalize respond (.right (.right effect)) = reply
  cases reply with
  | error failure => rfl
  | ok bytes =>
    simp only [Program.bind, ExceptT.bindCont, Except.mapError]
    by_cases width : bytes.size = 32 <;> simp only [width,
      if_true, if_false, bne_iff_ne, ne_eq, not_true_eq_false, not_false_eq_true] <;> rfl

theorem read_writeTrace (respond : Responder) (outboard handle : UInt64) (offset size : Nat) :
    writeTrace respond outboard (VerifiedCore.Cas.Bao.readAt handle offset size).run = [] := by
  change writeTrace respond outboard
    (.request (.left (.readAt handle offset.toUInt64 size.toUInt64)) _) = []
  rw [writeTrace]
  generalize respond (.left (.readAt handle offset.toUInt64 size.toUInt64)) = reply
  cases reply with
  | error failure => rfl
  | ok bytes =>
    simp only [Program.bind, ExceptT.bindCont]
    by_cases width : bytes.size = size <;> simp only [width,
      if_true, if_false, bne_iff_ne, ne_eq, not_true_eq_false, not_false_eq_true] <;> rfl

theorem write_writeTrace (respond : Responder) (outboard handle : UInt64)
    (offset : Nat) (bytes : ByteArray) :
    writeTrace respond outboard (VerifiedCore.Cas.Bao.writeAt handle offset bytes).run =
      if handle = outboard then [offset.toUInt64] else [] := by
  change (if handle = outboard then [offset.toUInt64] else []) ++ [] = _
  exact List.append_nil _

theorem hashAux_writeTrace (respond : Responder) (outboard : UInt64)
    (fuel counter : Nat) (root : Bool) (bytes : ByteArray) :
    writeTrace respond outboard (hashAux fuel counter root bytes).run = [] := by
  induction fuel generalizing counter root bytes with
  | zero =>
    by_cases leaf : bytes.size ≤ 1024
    · rw [hashAux]
      simp only [if_pos leaf]
      exact hash_writeTrace respond outboard _
    · rw [hashAux]
      simp only [if_neg leaf]
      rfl
  | succ fuel ih =>
    by_cases leaf : bytes.size ≤ 1024
    · rw [hashAux]
      simp only [if_pos leaf]
      exact hash_writeTrace respond outboard _
    · rw [BaoProgramProofs.hash_branch_program fuel counter root bytes (by omega)]
      apply writeTrace_bind_empty respond outboard _ _ (ih _ _ _)
      intro left
      apply writeTrace_bind_empty respond outboard _ _ (ih _ _ _)
      intro right
      exact hash_writeTrace respond outboard _

theorem leaf_writeTrace (respond : Responder) (source payload outboard : UInt64)
    (separate : payload ≠ outboard) (fuel offset size base : Nat) (root : Bool)
    (leaf : size ≤ 16384) :
    writeTrace respond outboard
      (buildAux fuel source payload outboard offset size base root).run = [] := by
  rw [buildAux.eq_def]
  simp only [if_pos leaf]
  change writeTrace respond outboard
    (VerifiedCore.Cas.Bao.readAt source offset size >>= fun bytes =>
      VerifiedCore.Cas.Bao.writeAt payload offset bytes >>= fun _ =>
        hashAux 4 (offset / 1024) root bytes).run = []
  apply writeTrace_bind_empty respond outboard _ _ (read_writeTrace respond outboard _ _ _)
  intro bytes
  apply writeTrace_bind_empty respond outboard _ _
    (by rw [write_writeTrace, if_neg separate])
  intro ignored
  exact hashAux_writeTrace respond outboard _ _ _ _

/-- Complete accumulated write-offset sequence, not merely pointwise
membership: successful execution writes precisely the postorder enumeration.
Only payload/outboard separation is needed; read requests never add writes. -/
theorem buildAux_writeTrace (respond : Responder) (source payload outboard : UInt64)
    (separate : payload ≠ outboard) (fuel offset size first : Nat) (root : Bool)
    (digest : ByteArray)
    (accepted : interpret respond
      (buildAux fuel source payload outboard offset size (64 * first) root).run = .ok digest) :
    writeTrace respond outboard
      (buildAux fuel source payload outboard offset size (64 * first) root).run =
      (pairSlots fuel size first).map (fun slot => (64 * slot).toUInt64) := by
  induction fuel generalizing offset size first root digest with
  | zero =>
    by_cases leaf : size ≤ 16384
    · rw [leaf_writeTrace respond source payload outboard separate _ _ _ _ _ leaf]
      rfl
    · rw [buildAux] at accepted
      simp [leaf, interpret] at accepted
  | succ fuel ih =>
    by_cases leaf : size ≤ 16384
    · rw [leaf_writeTrace respond source payload outboard separate _ _ _ _ _ leaf]
      simp [pairSlots, leaf]
    · obtain ⟨left, right, leftDone, rightDone, pairDone, _⟩ :=
        branch_success_requires_children_and_pair respond fuel source payload outboard
          offset size (64 * first) root (by omega) digest accepted
      have leftBase : 64 * first + 64 = 64 * (first + 1) := by omega
      have rightBase : 64 * first + 64 * (splitBytes 16384 size / 16384) =
          64 * (first + splitBytes 16384 size / 16384) := by omega
      have leftTrace := ih offset (splitBytes 16384 size) (first + 1) false left
        (by simpa only [leftBase] using leftDone)
      have rightTrace := ih (offset + splitBytes 16384 size) (size - splitBytes 16384 size)
        (first + splitBytes 16384 size / 16384) false right
        (by simpa only [rightBase] using rightDone)
      rw [BaoProgramProofs.build_branch_program fuel source payload outboard offset size
        (64 * first) root (by omega)]
      rw [writeTrace_bind_success respond outboard _ _ left leftDone,
        writeTrace_bind_success respond outboard _ _ right rightDone,
        writeTrace_bind_success respond outboard _ _ () pairDone]
      simp only [leftBase, rightBase]
      rw [leftTrace, rightTrace, write_writeTrace, if_pos rfl, hash_writeTrace]
      simp only [pairSlots, if_neg leaf, List.map_append, List.map_cons, List.map_nil,
        List.append_nil, List.append_assoc]

theorem build_observed_writeTrace (respond : Responder) (source payload outboard size : UInt64)
    (separate : payload ≠ outboard) (digest : ByteArray)
    (accepted : interpret respond (build source payload outboard size).run = .ok digest) :
    observe respond outboard (build source payload outboard size).run =
      (.ok digest, (pairSlots 64 size.toNat 0).map (fun slot => (64 * slot).toUInt64)) := by
  apply Prod.ext
  · exact accepted
  · exact buildAux_writeTrace respond source payload outboard separate 64 0 size.toNat 0 true
      digest accepted

/-- Whole-build equality in the actual accumulating state interpreter. The
reply function remains explicitly deterministic and independent of its log. -/
theorem build_accumulated_writeTrace (respond : Responder) (source payload outboard size : UInt64)
    (separate : payload ≠ outboard) (digest : ByteArray) (initial : List UInt64)
    (accepted : interpret respond (build source payload outboard size).run = .ok digest) :
    HostResourceProofs.interpret (accumulatingResponder respond outboard)
      (build source payload outboard size).run initial =
      (.ok digest, initial ++
        (pairSlots 64 size.toNat 0).map (fun slot => (64 * slot).toUInt64)) := by
  rw [accumulating_interpret, accepted]
  have trace := buildAux_writeTrace respond source payload outboard separate 64 0 size.toNat 0 true
    digest accepted
  change writeTrace respond outboard (build source payload outboard size).run = _ at trace
  rw [trace]

end Synchronicity.BaoTraceProofs
