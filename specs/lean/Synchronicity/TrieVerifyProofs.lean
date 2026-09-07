import VerifiedCore.Trie.Verify
import Synchronicity.TrieCodecProofs

/-! The canonical ingress boundary, as executed: what `admit` accepts is
exactly an encoder image within the shared key bound and the structural
invariants, and the fault decision of `verify` follows from the digests the
host answers, nothing else. -/
namespace Synchronicity.TrieVerifyProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie Synchronicity.TrieCodecProofs

/-! ## Except, as the do-notation spells it -/

@[simp] theorem bind_error (e : ε) (f : α → Except ε β) : (Except.error e >>= f) = .error e := rfl
@[simp] theorem map_error (f : α → β) (e : ε) : Except.map f (.error e : Except ε α) = .error e := rfl
@[simp] theorem fmap_eq (f : α → β) (x : Except ε α) : f <$> x = Except.map f x := rfl
@[simp] theorem throw_eq (e : ε) : (throw e : Except ε α) = .error e := rfl
@[simp] theorem pure_eq (a : α) : (pure a : Except ε α) = .ok a := rfl
@[simp] theorem mapError_id (r : Except ε α) : r.mapError id = r := by cases r <;> rfl

/-! ## Byte-array equality on the wire -/

theorem byteArray_beq_iff (a b : ByteArray) : (a == b) = true ↔ a = b := by
  show (a.data == b.data) = true ↔ a = b
  rw [beq_iff_eq, ByteArray.ext_iff]

theorem byteArray_beq_self (a : ByteArray) : (a == a) = true :=
  (byteArray_beq_iff a a).mpr rfl

/-! ## Admission -/

/-- Only an encoder image is canonical, and it decodes to the node admitted. -/
theorem canonical_sound {bytes : ByteArray} {n : Node} (h : canonical bytes = .ok n) :
    encode n = bytes ∧ decode bytes = .ok n := by
  unfold canonical at h
  cases decoded : decode bytes with
  | error message => simp [decoded] at h
  | ok m =>
    simp only [decoded] at h
    split at h
    · cases h
      exact ⟨(byteArray_beq_iff _ _).mp (by assumption), rfl⟩
    · cases h

theorem canonical_encode {n : Node} (wf : n.wf) : canonical (encode n) = .ok n := by
  simp [canonical, decode_encode wf, byteArray_beq_self]

/-- What admission establishes about the node it returns: canonical image,
the key bound `get` and the walks share, and every structural invariant. -/
theorem admit_sound {bytes : ByteArray} {n : Node} (h : admit bytes = .ok n) :
    encode n = bytes ∧ nibbleRun n ≤ maxKeyBytes * 2 ∧ checkInvariants n = .ok () := by
  unfold admit at h
  cases canon : canonical bytes with
  | error refusal => simp [canon] at h
  | ok m =>
    simp only [canon, bind_ok] at h
    split at h
    · simp at h
    · rename_i within
      cases inv : checkInvariants m with
      | error refusal => simp [inv] at h
      | ok _ =>
        simp only [inv] at h
        cases h
        exact ⟨(canonical_sound canon).1, Nat.not_lt.mp within, inv⟩

theorem admit_encode {n : Node} (wf : n.wf) (within : nibbleRun n ≤ maxKeyBytes * 2)
    (invariants : checkInvariants n = .ok ()) : admit (encode n) = .ok n := by
  simp [admit, canonical_encode wf, Nat.not_lt.mpr within, invariants]

/-- The per-node half of the depth bound is the same `maxKeyBytes` lookup
enforces on whole keys. -/
theorem admitted_within_key_bound {bytes : ByteArray} {n : Node} (h : admit bytes = .ok n) :
    nibbleRun n ≤ maxKeyBytes * 2 := (admit_sound h).2.1

theorem admitted_extension_nonempty {bytes segment child : ByteArray}
    (h : admit bytes = .ok (.extension segment child)) : segment.size ≠ 0 := by
  have inv := (admit_sound h).2.2
  simp only [checkInvariants] at inv
  intro zero
  simp [zero] at inv

theorem admitted_branch_occupied {bytes : ByteArray} {cs : List (Option ByteArray)}
    {v : Option Value} (h : admit bytes = .ok (.branch cs v)) : 2 ≤ occupants cs v := by
  have inv := (admit_sound h).2.2
  simp only [checkInvariants] at inv
  refine Nat.le_of_not_lt fun lt => ?_
  cases v with
  | none => simp [lt] at inv
  | some v =>
    cases cv : checkValue v with
    | error _ => simp [cv] at inv
    | ok _ => simp [cv, lt] at inv

theorem admitted_inline_bounded {bytes suffix payload : ByteArray}
    (h : admit bytes = .ok (.leaf suffix (.inline payload))) : payload.size ≤ inlineValueMax := by
  have inv := (admit_sound h).2.2
  simp only [checkInvariants, checkValue] at inv
  refine Nat.le_of_not_lt fun lt => ?_
  simp [lt] at inv

/-! ## Execution against a digest host

The verify programs request digests and nothing else once the bytes are in
hand: a host contract for hashing is one function of the bytes, and every
storage effect is refused by this interpreter. -/

def executeDigest (d : ByteArray → ByteArray) : Nat → Program Effects A → Option A
  | _, .pure result => some result
  | 0, .request _ _ => none
  | fuel + 1, .request (.right (.blake3 bytes)) next => executeDigest d fuel (next (.ok (d bytes)))
  | _ + 1, .request (.left _) _ => none

@[simp] theorem executeDigest_pure (d : ByteArray → ByteArray) (fuel : Nat) (result : A) :
    executeDigest d fuel (.pure result) = some result := by
  cases fuel <;> rfl

@[simp] theorem executeDigest_blake3 (d : ByteArray → ByteArray) (fuel : Nat) (bytes : ByteArray)
    (next : Reply ByteArray → Program Effects A) :
    executeDigest d (fuel + 1) (.request (.right (.blake3 bytes)) next) =
      executeDigest d fuel (next (.ok (d bytes))) := rfl

/-! The executable shape of the effect monad, one definitional step each. -/

@[simp] theorem run_bind (m : Action A) (k : A → Action B) :
    (m >>= k).run = m.run >>= ExceptT.bindCont k := rfl
@[simp] theorem program_bind_request (e : Effects R) (next : R → Program Effects A)
    (f : A → Program Effects B) :
    (Program.request e next >>= f) = .request e (fun r => next r >>= f) := rfl
@[simp] theorem program_bind_pure (a : A) (f : A → Program Effects B) :
    (Program.pure a >>= f) = f a := rfl
@[simp] theorem program_pure_eq (a : A) : (pure a : Program Effects A) = .pure a := rfl
@[simp] theorem bindCont_ok (k : A → Action B) (a : A) :
    ExceptT.bindCont k (.ok a) = (k a).run := rfl
@[simp] theorem bindCont_error (k : A → Action B) (e : Failure) :
    ExceptT.bindCont k (.error e) = .pure (.error e) := rfl
@[simp] theorem run_pure' (a : A) : (pure a : Action A).run = .pure (.ok a) := rfl
@[simp] theorem run_throw' (e : Failure) : (throw e : Action A).run = .pure (.error e) := rfl
@[simp] theorem run_ite (c : Prop) [Decidable c] (t e : Action A) :
    (if c then t else e).run = if c then t.run else e.run := by split <;> rfl
@[simp] theorem digest_run (bytes : ByteArray) :
    (digest bytes).run = .request (.right (.blake3 bytes)) (fun r => .pure (r.mapError id)) := rfl
@[simp] theorem readInput_raw (handle offset size : UInt64) :
    (raise id (Storage.readInput handle offset size) : Action ByteArray).run =
      .request (.left (.readInput handle offset size)) (fun r => .pure (r.mapError id)) := rfl

/-- A refused node never reaches the host: no digest is requested. -/
theorem hashAdmitted_refused {bytes : ByteArray} {refusal : Refusal}
    (h : admit bytes = .error refusal) :
    (hashAdmitted bytes).run = .pure (.ok (.error refusal)) := by
  simp [hashAdmitted, h]

/-- An admitted node is hashed under its own kind's tag, once, and the reply
is the answer: a host failure is the operation's failure. -/
theorem hashAdmitted_admitted {bytes : ByteArray} {n : Node} (h : admit bytes = .ok n) :
    (hashAdmitted bytes).run = .request (.right (.blake3 (tagOf n ++ bytes)))
      (fun | .ok hash => .pure (.ok (.ok hash)) | .error failure => .pure (.error failure)) := by
  simp only [hashAdmitted, h, run_bind, digest_run, program_bind_request, mapError_id,
    program_bind_pure]
  congr 1
  funext reply
  cases reply <;> simp

theorem hashAdmitted_semantics (d : ByteArray → ByteArray) (fuel : Nat) {bytes : ByteArray}
    {n : Node} (h : admit bytes = .ok n) :
    executeDigest d (fuel + 1) (hashAdmitted bytes).run = some (.ok (.ok (d (tagOf n ++ bytes)))) := by
  simp [hashAdmitted, h]

/-- Admitted bytes are accepted exactly when their tagged digest is the
requested hash; otherwise the bytes are the peer's. -/
theorem verify_admitted (d : ByteArray → ByteArray) (fuel : Nat) {expected bytes : ByteArray}
    {n : Node} (h : admit bytes = .ok n) :
    executeDigest d (fuel + 1) (verify expected bytes).run =
      some (.ok (if d (tagOf n ++ bytes) == expected then .accepted else .peerFault)) := by
  simp [verify, h]

/-- Refused bytes are the origin's fault exactly when they hash to the
requested hash under some kind's tag, and the peer's otherwise. -/
theorem verify_refused (d : ByteArray → ByteArray) (fuel : Nat) {expected bytes : ByteArray}
    {refusal : Refusal} (h : admit bytes = .error refusal) :
    executeDigest d (fuel + 4) (verify expected bytes).run =
      some (.ok (if tags.any (fun tag => d (tag ++ bytes) == expected)
        then .originFault refusal else .peerFault)) := by
  simp only [verify, h, tags, List.any_cons, List.any_nil, Bool.or_false]
  cases leaf : (d (leafTag ++ bytes) == expected) <;>
    cases ext : (d (extensionTag ++ bytes) == expected) <;>
    cases branch : (d (branchTag ++ bytes) == expected) <;>
    cases route : (d (routeTag ++ bytes) == expected) <;>
    simp [hashesToAny, leaf, ext, branch, route]

/-- Acceptance names a digest equality: the host said the tagged bytes hash
to the requested address. -/
theorem accepted_hashes (d : ByteArray → ByteArray) {expected bytes : ByteArray}
    (h : executeDigest d 4 (verify expected bytes).run = some (.ok .accepted)) :
    ∃ n, admit bytes = .ok n ∧ d (tagOf n ++ bytes) = expected := by
  cases admitted : admit bytes with
  | error refusal =>
    rw [verify_refused d 0 admitted] at h
    split at h <;> cases h
  | ok n =>
    refine ⟨n, rfl, ?_⟩
    rw [verify_admitted d 3 admitted] at h
    split at h
    · exact (byteArray_beq_iff _ _).mp (by assumption)
    · cases h

/-- An origin fault is never pronounced on bytes that hash to nothing wanted. -/
theorem origin_fault_hashes (d : ByteArray → ByteArray) {expected bytes : ByteArray}
    {refusal : Refusal}
    (h : executeDigest d 4 (verify expected bytes).run = some (.ok (.originFault refusal))) :
    admit bytes = .error refusal ∧ ∃ tag ∈ tags, d (tag ++ bytes) = expected := by
  cases admitted : admit bytes with
  | ok n =>
    rw [verify_admitted d 3 admitted] at h
    split at h <;> cases h
  | error r =>
    rw [verify_refused d 0 admitted] at h
    split at h
    · cases h
      refine ⟨rfl, ?_⟩
      rename_i any
      obtain ⟨tag, mem, hit⟩ := List.any_eq_true.mp any
      exact ⟨tag, mem, (byteArray_beq_iff _ _).mp hit⟩
    · cases h

/-! ## The borrowed input -/

/-- The served bytes are read, in full, before anything is decided: a short
read is a protocol failure, a host failure is the operation's, and exact
bytes continue as `verify`. -/
theorem verifyInput_reads_first (expected : ByteArray) (handle size : UInt64) :
    (verifyInput expected handle size).run = .request (.left (.readInput handle 0 size))
      (fun
        | .error failure => .pure (.error failure)
        | .ok bytes =>
          if bytes.size != size.toNat then .pure (.error ⟨3, 0⟩) else (verify expected bytes).run) := by
  simp only [verifyInput, readInput, run_bind, readInput_raw, program_bind_request, mapError_id,
    program_bind_pure]
  congr 1
  funext reply
  cases reply with
  | error failure => simp
  | ok bytes =>
    simp only [bindCont_ok, run_bind, run_ite, run_throw', run_pure', program_bind_pure]
    split <;> simp [*]

theorem admitInput_reads_first (handle size : UInt64) :
    (admitInput handle size).run = .request (.left (.readInput handle 0 size))
      (fun
        | .error failure => .pure (.error failure)
        | .ok bytes =>
          if bytes.size != size.toNat then .pure (.error ⟨3, 0⟩) else (hashAdmitted bytes).run) := by
  simp only [admitInput, readInput, run_bind, readInput_raw, program_bind_request, mapError_id,
    program_bind_pure]
  congr 1
  funext reply
  cases reply with
  | error failure => simp
  | ok bytes =>
    simp only [bindCont_ok, run_bind, run_ite, run_throw', run_pure', program_bind_pure]
    split <;> simp [*]

end Synchronicity.TrieVerifyProofs
