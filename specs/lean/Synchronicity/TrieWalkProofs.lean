import Synchronicity.CasFixtures
import Synchronicity.TrieServeProofs
import VerifiedCore.Trie.Diff

/-! Structural walks, as executed: the nibble packing a key goes through and
back, how a value is compared as a value, what every descent maintains (no
walk charges past the ceiling, every frame sits under the walk's base), what
every entry a range scan lists satisfies (the prefix, the resume cursor, the
limit), and on a concrete trie the scan's listing under prefix, cursor and
limit, a refusal never concealing missing data, the diff of two roots with
structural sharing pruned and representations reconciled, the streamed
materialization in walk order, and a failure injected at every effect. -/
namespace Synchronicity.TrieWalkProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Trie.Walk VerifiedCore.Trie.Diff
  SimulatedHost CasFixtures

/-! ## Keys

A key becomes nibbles and comes back the same; an odd run of nibbles is no
key at all; a path that starts with a prefix's nibbles packs to a key that
starts with the prefix. -/

theorem toList_loop (bs : ByteArray) (i : Nat) (r : List UInt8) :
    ByteArray.toList.loop bs i r = r.reverse ++ bs.data.toList.drop i := by
  induction i, r using ByteArray.toList.loop.induct bs with
  | case1 i r lt ih =>
    rw [ByteArray.toList.loop, if_pos lt, ih]
    have : bs.data.toList.drop i = bs.data[i] :: bs.data.toList.drop (i + 1) := by
      rw [List.drop_eq_getElem_cons (by simpa using lt)]
      rfl
    rw [this]
    simp [ByteArray.get!, lt]
  | case2 i r ge =>
    rw [ByteArray.toList.loop, if_neg ge]
    have : bs.data.toList.drop i = [] := List.drop_of_length_le (by simpa using ge)
    simp [this]

theorem toList_eq (bs : ByteArray) : bs.toList = bs.data.toList := by
  rw [ByteArray.toList, toList_loop]; rfl

theorem nibble_pack (b : UInt8) : b / 16 * 16 + b % 16 = b := by
  apply UInt8.toNat_inj.mp
  simp only [UInt8.toNat_add, UInt8.toNat_mul, UInt8.toNat_div, UInt8.toNat_mod, UInt8.toNat_ofNat,
    Nat.reducePow, Nat.reduceMod]
  have := Nat.div_add_mod b.toNat 16
  have bound := b.toNat_lt
  omega

theorem bytesOfNibbles_flatMap (list : List UInt8) :
    bytesOfNibbles (list.flatMap fun b => [b / 16, b % 16]) = some ⟨list.toArray⟩ := by
  induction list with
  | nil => rfl
  | cons b rest ih =>
    simp only [List.flatMap_cons, List.cons_append, List.nil_append, bytesOfNibbles, ih, Option.map_some,
      nibble_pack, Option.some.injEq]
    apply ByteArray.ext
    simp

theorem bytesOfNibbles_keyNibbles (key : ByteArray) : bytesOfNibbles (keyNibbles key) = some key := by
  have := bytesOfNibbles_flatMap key.toList
  rw [toList_eq, Array.toArray_toList] at this
  unfold keyNibbles
  rw [toList_eq]
  exact this

theorem bytesOfNibbles_odd (nibbles : List UInt8) (odd : nibbles.length % 2 = 1) :
    bytesOfNibbles nibbles = none := by
  induction nibbles using bytesOfNibbles.induct with
  | case1 => simp at odd
  | case2 hi lo rest ih =>
    simp only [List.length_cons] at odd
    simp only [bytesOfNibbles, ih (by omega), Option.map_none]
  | case3 => rfl

/-- Packing a prefix's nibbles followed by anything packs the prefix first. -/
theorem prefix_of_nibbles (prefixBytes : List UInt8) : ∀ (nibbles : List UInt8) (key : ByteArray),
    bytesOfNibbles ((prefixBytes.flatMap fun b => [b / 16, b % 16]) ++ nibbles) = some key →
    ∃ tail, key = ⟨prefixBytes.toArray⟩ ++ tail := by
  induction prefixBytes with
  | nil =>
    intro nibbles key _
    refine ⟨key, ?_⟩
    apply ByteArray.ext
    simp
  | cons b rest ih =>
    intro nibbles key packed
    simp only [List.flatMap_cons, List.cons_append, List.nil_append, bytesOfNibbles, nibble_pack] at packed
    cases inner : bytesOfNibbles ((rest.flatMap fun b => [b / 16, b % 16]) ++ nibbles) with
    | none => simp [inner] at packed
    | some key' =>
      simp only [inner, Option.map_some, Option.some.injEq] at packed
      obtain ⟨tail, shape⟩ := ih nibbles key' inner
      refine ⟨tail, ?_⟩
      rw [← packed, shape]
      apply ByteArray.ext
      apply Array.toList_inj.mp
      simp

theorem prefix_of_keyNibbles (keyPrefix key : ByteArray) (nibbles : List UInt8)
    (packed : bytesOfNibbles (keyNibbles keyPrefix ++ nibbles) = some key) :
    ∃ tail, key = keyPrefix ++ tail := by
  obtain ⟨tail, shape⟩ := prefix_of_nibbles keyPrefix.toList nibbles key packed
  rw [toList_eq, Array.toArray_toList] at shape
  exact ⟨tail, shape⟩

/-! ## Values

Two references denote one value exactly when they agree as values: inline
bytes against inline bytes, address against address, and inline bytes
against the address that is their digest. -/

@[simp] theorem throw_run (e : Walk.Error) :
    (throw e : OperationOver E Walk.Error A) = (Program.pure (Except.error e) : Program E (Except Walk.Error A)) :=
  rfl

@[simp] theorem execute_pure [Interpreter E] (value : A) (state : State) :
    execute (pure value : Program E A) state = (value, state) := rfl

theorem sameValue_inline (p q : ByteArray) (state : State) :
    (SimulatedHost.run (sameValue (E := Diff.Effects) (some (.inline p)) (some (.inline q))) state).1 =
      .ok (p == q) := by
  simp [SimulatedHost.run, sameValue, execute, pure, ExceptT.pure, ExceptT.run, ExceptT.mk]

theorem sameValue_mixed (p q : ByteArray) (state : State) (quiet : state.faults = []) :
    (SimulatedHost.run (sameValue (E := Diff.Effects) (some (.inline p)) (some (.hash q))) state).1 =
      .ok (state.hash p == q) ∧
    (SimulatedHost.run (sameValue (E := Diff.Effects) (some (.hash q)) (some (.inline p))) state).1 =
      .ok (state.hash p == q) := by
  constructor <;>
    simp [SimulatedHost.run, sameValue, Diff.digest, raise, performOver, Inject.inject, bind, ExceptT.bind,
      ExceptT.bindCont, ExceptT.mk, ExceptT.run, Program.bind, execute, pure, ExceptT.pure, Interpreter.handle,
      SimulatedHost.digest, reply, fault, quiet, record, Except.mapError]

theorem sameValue_absent (value : Value) (state : State) :
    (SimulatedHost.run (sameValue (E := Diff.Effects) none (some value)) state).1 = .ok false ∧
    (SimulatedHost.run (sameValue (E := Diff.Effects) (some value) none) state).1 = .ok false := by
  cases value <;> simp [SimulatedHost.run, sameValue, execute, pure, ExceptT.pure, ExceptT.run, ExceptT.mk]

/-! ## The descent

What one iteration of any walk maintains: every frame's path extends the
walk's base, the positions charged never pass the ceiling, and whatever
`P` the step keeps of the accumulator. -/

/-- What a descent maintains: every frame's path extends `base`, the
positions charged are within the ceiling, and `P` holds of the accumulator. -/
def DescentOk (base : Path) (P : A → Prop) (d : Descent T A) : Prop :=
  (∀ frame ∈ d.stack, ∃ tail, frame.2.2 = base ++ tail) ∧ d.positions ≤ walkPositionCeiling ∧ P d.acc

theorem descend_step [Interpreter E] [Inject Storage E] [Inject Redaction E]
    (next : T → UInt8 → Option UInt8)
    (step : A → T → UInt8 → Path → OperationOver E Walk.Error (Step T × A)) (base : Path) (P : A → Prop)
    (stepOk : ∀ acc frame nibble tail state answer acc', P acc →
      (execute (step acc frame nibble (base ++ tail)).run state).1 = .ok (answer, acc') → P acc')
    (d : Descent T A) (state : State) (ok : DescentOk base P d) :
    (∀ d', (execute (descend next step d).run state).1 = .ok (.inl d') → DescentOk base P d') ∧
    (∀ a, (execute (descend next step d).run state).1 = .ok (.inr a) → P a) := by
  obtain ⟨frames, within, holds⟩ := ok
  match d with
  | ⟨[], positions, acc⟩ =>
    simp only [descend, pure, ExceptT.pure, ExceptT.mk, ExceptT.run, execute, Except.ok.injEq, reduceCtorEq,
      Sum.inr.injEq, false_implies, implies_true, true_and]
    intro a h; exact h ▸ holds
  | ⟨(frame, nibble, path) :: stack, positions, acc⟩ =>
    obtain ⟨tail, shape⟩ := frames (frame, nibble, path) (List.mem_cons_self ..)
    simp only [descend]
    split
    · simp only [pure, ExceptT.pure, ExceptT.mk, ExceptT.run, execute, Except.ok.injEq, reduceCtorEq,
        Sum.inl.injEq, false_implies, implies_true, and_true]
      intro d' h
      subst h
      exact ⟨fun f mem => frames f (List.mem_cons_of_mem _ mem), within, holds⟩
    · rename_i nibble' _
      simp only at shape
      subst shape
      simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run]
      rw [execute_bind]
      have ok := stepOk acc frame nibble' (tail ++ [nibble']) state
      simp only [ExceptT.run, ← List.append_assoc] at ok
      generalize execute (step acc frame nibble' (base ++ tail ++ [nibble'])) state = stepRun at ok ⊢
      obtain ⟨result, state'⟩ := stepRun
      match result with
      | .error e => simp [ExceptT.bindCont]
      | .ok (answer, acc') =>
        have holds' := ok answer acc' holds rfl
        have frames' : ∀ f ∈ (frame, nibble' + 1, base ++ tail) :: stack, ∃ tail, f.2.2 = base ++ tail :=
          fun f mem => by
            rcases List.mem_cons.mp mem with here | there
            · exact ⟨tail, by rw [here]⟩
            · exact frames f (List.mem_cons_of_mem _ there)
        cases answer with
        | descend child =>
          simp only [ExceptT.bindCont]
          split
          · simp [Program.bind, ExceptT.bindCont]
          · rename_i room
            simp only [pure, ExceptT.pure, ExceptT.mk, execute, Except.ok.injEq, reduceCtorEq, Sum.inl.injEq,
              false_implies, implies_true, and_true]
            intro d' h
            subst h
            refine ⟨fun f mem => ?_, by simp only; omega, holds'⟩
            rcases List.mem_cons.mp mem with here | there
            · exact ⟨tail ++ [nibble'], by rw [here, List.append_assoc]⟩
            · exact frames' f there
        | visited =>
          simp only [ExceptT.bindCont]
          split
          · simp [Program.bind, ExceptT.bindCont]
          · rename_i room
            simp only [pure, ExceptT.pure, ExceptT.mk, execute, Except.ok.injEq, reduceCtorEq, Sum.inl.injEq,
              false_implies, implies_true, and_true]
            intro d' h
            subst h
            exact ⟨frames', by simp only; omega, holds'⟩
        | skip =>
          simp only [ExceptT.bindCont, pure, ExceptT.pure, ExceptT.mk, execute, Except.ok.injEq, reduceCtorEq,
            Sum.inl.injEq, false_implies, implies_true, and_true]
          intro d' h
          subst h
          exact ⟨frames', within, holds'⟩
        | stop =>
          simp only [ExceptT.bindCont, pure, ExceptT.pure, ExceptT.mk, execute, Except.ok.injEq, reduceCtorEq,
            Sum.inr.injEq, false_implies, implies_true, true_and]
          intro a h
          exact h ▸ holds'

/-- What a walk answers satisfies whatever its step keeps of the accumulator. -/
theorem walk_sound [Interpreter E] [Inject Storage E] [Inject Redaction E]
    (next : T → UInt8 → Option UInt8)
    (step : A → T → UInt8 → Path → OperationOver E Walk.Error (Step T × A)) (start : T) (base : Path)
    (acc : A) (P : A → Prop)
    (stepOk : ∀ acc frame nibble tail state answer acc', P acc →
      (execute (step acc frame nibble (base ++ tail)).run state).1 = .ok (answer, acc') → P acc')
    (holds : P acc) (state : State) (result : A)
    (ran : (execute (walk next step start base acc).run state).1 = .ok result) : P result := by
  unfold walk OperationOver.iterate at ran
  generalize walkFuel = fuel at ran
  have first : DescentOk base P ⟨[(start, 0, base)], 0, acc⟩ :=
    ⟨fun f mem => by
      rw [List.mem_singleton] at mem
      exact ⟨[], by rw [mem, List.append_nil]⟩, Nat.zero_le _, holds⟩
  have ran' : (execute (Program.iterate (fun d => (descend next step d).run) .ceiling fuel
      (descend next step ⟨[(start, 0, base)], 0, acc⟩).run) state).1 = .ok result := ran
  exact iterate_sound _ .ceiling (DescentOk base P) P
    (fun d state d' ok ran => (descend_step next step base P stepOk d state ok).1 d' ran)
    (fun d state a ok ran => (descend_step next step base P stepOk d state ok).2 a ran)
    fuel _ state
    (descend_step next step base P stepOk _ state first).1
    (descend_step next step base P stepOk _ state first).2 result ran'

/-- At the ceiling, a step that found a real position is refused: the walk
answers `ceiling` rather than charging one more. -/
theorem descend_refuses_past_the_ceiling [Interpreter E] [Inject Storage E] [Inject Redaction E]
    (next : T → UInt8 → Option UInt8)
    (step : A → T → UInt8 → Path → OperationOver E Walk.Error (Step T × A))
    (frame : T) (nibble : UInt8) (path : Path) (stack : List (Frame T)) (acc : A) (state : State)
    (shallow : nibble.toNat < 16 ∧ path.length < maxDepthNibbles) (child : UInt8)
    (worth : (next frame nibble).filter (·.toNat < 16) = some child) (answer : Step T) (acc' : A)
    (real : answer ≠ .skip ∧ answer ≠ .stop)
    (stepped : (execute (step acc frame child (path ++ [child])).run state).1 = .ok (answer, acc')) :
    (execute (descend next step ⟨(frame, nibble, path) :: stack, walkPositionCeiling, acc⟩).run state).1 =
      .error .ceiling := by
  simp only [descend, ge_iff_le, Nat.not_le.mpr shallow.1, Nat.not_le.mpr shallow.2,
    decide_false, Bool.or_self, Bool.false_eq_true, if_false, worth]
  simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run]
  rw [execute_bind]
  simp only [ExceptT.run] at stepped
  generalize execute (step acc frame child (path ++ [child])) state = stepRun at stepped ⊢
  obtain ⟨result, state'⟩ := stepRun
  simp only at stepped
  subst stepped
  cases answer with
  | descend child => simp [ExceptT.bindCont, Program.bind]
  | visited => simp [ExceptT.bindCont, Program.bind]
  | skip => exact (real.1 rfl).elim
  | stop => exact (real.2 rfl).elim

/-! ## What a scan lists

Every entry `takeValue` adds sits exactly at the path it was taken at, has
passed the resume cursor, and was added while the limit had room; so every
entry the collection under a cursor lists sits under the cursor's path,
and a scan's listing has the prefix, is strictly past the cursor and is no
longer than the limit. -/

/-- An entry taken at `path`, past `after`. -/
def EntryOk (path : Path) (after : Option ByteArray) (entry : Entry) : Prop :=
  bytesOfNibbles path = some entry.1 ∧
    ∀ bound, after = some bound → Serve.before bound.toList entry.1.toList = true

/-- An entry taken somewhere under `base`, past `after`. -/
def Under (base : Path) (after : Option ByteArray) (entry : Entry) : Prop :=
  ∃ tail, EntryOk (base ++ tail) after entry

/-- What a collection keeps of its listing: every entry is under the base,
and the listing is within the limit. -/
def Listing (base : Path) (after : Option ByteArray) (limit : Option Nat) (out : List Entry) : Prop :=
  (∀ entry ∈ out, Under base after entry) ∧ ∀ bound, limit = some bound → out.length ≤ bound

theorem takeValue_sound [Interpreter E] [Inject Storage E] (cursor : Cursor) (path : Path)
    (after : Option ByteArray) (limit : Option Nat) (out : List Entry) (state : State) (out' : List Entry)
    (ran : (execute (takeValue (E := E) cursor path after limit out).run state).1 = .ok out') :
    out' = out ∨ ∃ entry, out' = entry :: out ∧ EntryOk path after entry ∧
      ∀ bound, limit = some bound → out.length < bound := by
  unfold takeValue at ran
  split at ran
  · left
    simp only [pure, ExceptT.pure, ExceptT.mk, ExceptT.run, execute, Except.ok.injEq] at ran
    exact ran.symm
  · rename_i room
    split at ran
    · left
      simp only [pure, ExceptT.pure, ExceptT.mk, ExceptT.run, execute, Except.ok.injEq] at ran
      exact ran.symm
    · rename_i value _
      split at ran
      · simp only [ExceptT.run, throw_run, execute, reduceCtorEq] at ran
      · rename_i key packed
        have room' : ∀ bound, limit = some bound → out.length < bound := fun bound found => by
          subst found
          simp only [Option.any_some, decide_eq_true_eq, Nat.not_le] at room
          exact room
        have taken : ∀ passed : Bool,
            (execute (if passed then (do return (key, ← resolve (E := E) value) :: out) else return out).run
              state).1 = .ok out' →
            out' = out ∨ ∃ bytes, out' = (key, bytes) :: out ∧ passed = true := by
          intro passed ran
          cases passed with
          | false =>
            left
            simp only [Bool.false_eq_true, if_false, pure, ExceptT.pure, ExceptT.mk, ExceptT.run, execute,
              Except.ok.injEq] at ran
            exact ran.symm
          | true =>
            simp only [if_true, bind, ExceptT.bind, ExceptT.mk, ExceptT.run] at ran
            rw [execute_bind] at ran
            generalize execute (resolve (E := E) value) state = resolved at ran
            obtain ⟨result, state'⟩ := resolved
            match result with
            | .error e => simp [ExceptT.bindCont] at ran
            | .ok bytes =>
              simp only [ExceptT.bindCont, pure, ExceptT.pure, ExceptT.mk, execute, Except.ok.injEq] at ran
              exact .inr ⟨bytes, ran.symm, rfl⟩
        cases after with
        | none =>
          rcases taken true ran with same | ⟨bytes, added, _⟩
          · exact .inl same
          · exact .inr ⟨(key, bytes), added, ⟨packed, fun _ found => by cases found⟩, room'⟩
        | some bound =>
          rcases taken _ ran with same | ⟨bytes, added, passed⟩
          · exact .inl same
          · exact .inr ⟨(key, bytes), added, ⟨packed, fun _ found => by cases found; exact passed⟩, room'⟩

theorem listing_take (base tail : Path) (after : Option ByteArray) (limit : Option Nat)
    (out out' : List Entry) (kept : Listing base after limit out)
    (taken : out' = out ∨ ∃ entry, out' = entry :: out ∧ EntryOk (base ++ tail) after entry ∧
      ∀ bound, limit = some bound → out.length < bound) : Listing base after limit out' := by
  rcases taken with same | ⟨entry, added, ok, room⟩
  · exact same ▸ kept
  · subst added
    refine ⟨fun e mem => ?_, fun bound found => ?_⟩
    · rcases List.mem_cons.mp mem with here | there
      · exact ⟨tail, here ▸ ok⟩
      · exact kept.1 e there
    · simp only [List.length_cons]
      exact room bound found

/-- One step of the collection keeps the listing. -/
theorem collect_step [Interpreter E] [Inject Storage E] [Inject Redaction E] (base : Path)
    (after : Option ByteArray) (limit : Option Nat) (out : List Entry) (parent : Cursor) (nibble : UInt8)
    (tail : Path) (state : State) (answer : Step Cursor) (out' : List Entry)
    (kept : Listing base after limit out)
    (ran : (execute (collectStep (E := E) after limit out parent nibble (base ++ tail)).run state).1 =
      .ok (answer, out')) :
    Listing base after limit out' := by
  unfold collectStep at ran
  split at ran
  · simp only [pure, ExceptT.pure, ExceptT.mk, ExceptT.run, execute, Except.ok.injEq, Prod.mk.injEq] at ran
    exact ran.2 ▸ kept
  · split at ran
    · simp only [pure, ExceptT.pure, ExceptT.mk, ExceptT.run, execute, Except.ok.injEq, Prod.mk.injEq] at ran
      exact ran.2 ▸ kept
    · simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run] at ran
      rw [execute_bind] at ran
      generalize execute (cursorChild (E := E) parent nibble) state = found at ran
      obtain ⟨result, state'⟩ := found
      match result with
      | .error e => simp [ExceptT.bindCont] at ran
      | .ok child =>
        simp only [ExceptT.bindCont] at ran
        split at ran
        · simp only [pure, ExceptT.pure, ExceptT.mk, execute, Except.ok.injEq, Prod.mk.injEq] at ran
          exact ran.2 ▸ kept
        · rw [execute_bind] at ran
          generalize taking : execute (takeValue (E := E) child (base ++ tail) after limit out) state' = taken at ran
          obtain ⟨result, state''⟩ := taken
          match result with
          | .error e => simp [ExceptT.bindCont] at ran
          | .ok out'' =>
            simp only [ExceptT.bindCont, pure, ExceptT.pure, ExceptT.mk, execute, Except.ok.injEq,
              Prod.mk.injEq] at ran
            have taken := takeValue_sound (E := E) child (base ++ tail) after limit out state' out''
              (by rw [ExceptT.run, taking])
            exact ran.2 ▸ listing_take base tail after limit out out'' kept taken

/-- Everything a collection lists sits under its cursor's path, past the
resume cursor, within the limit. -/
theorem collect_sound [Interpreter E] [Inject Storage E] [Inject Redaction E] (cursor : Cursor)
    (path : Path) (after : Option ByteArray) (limit : Option Nat) (state : State) (entries : List Entry)
    (ran : (execute (collect (E := E) cursor path after limit).run state).1 = .ok entries) :
    Listing path after limit entries := by
  unfold collect at ran
  simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run] at ran
  rw [execute_bind] at ran
  generalize taking : execute (takeValue (E := E) cursor path after limit []) state = taken at ran
  obtain ⟨result, state'⟩ := taken
  match result with
  | .error e => simp [ExceptT.bindCont] at ran
  | .ok out =>
    have first : Listing path after limit out :=
      listing_take path [] after limit [] out ⟨fun _ mem => (List.not_mem_nil mem).elim, fun _ _ => Nat.zero_le _⟩
        (by
          simpa only [List.append_nil] using
            takeValue_sound (E := E) cursor path after limit [] state out (by rw [ExceptT.run, taking]))
    simp only [ExceptT.bindCont] at ran
    rw [execute_bind] at ran
    generalize walking : execute (walk (E := E) Cursor.nextChild (collectStep after limit) cursor path out) state' =
      walked at ran
    obtain ⟨result, state''⟩ := walked
    match result with
    | .error e => simp [ExceptT.bindCont] at ran
    | .ok listed =>
      simp only [ExceptT.bindCont, pure, ExceptT.pure, ExceptT.mk, execute, Except.ok.injEq] at ran
      have kept := walk_sound Cursor.nextChild (collectStep after limit) cursor path out
        (Listing path after limit)
        (fun out parent nibble tail state answer out' kept ran =>
          collect_step path after limit out parent nibble tail state answer out' kept ran)
        first state' listed (by rw [ExceptT.run, walking])
      subst ran
      exact ⟨fun entry mem => kept.1 entry (List.mem_reverse.mp mem),
        fun bound found => by rw [List.length_reverse]; exact kept.2 bound found⟩

/-- Every entry a scan lists starts with the prefix and sorts strictly
after the resume cursor, and the listing is within the limit. -/
theorem scan_sound [Interpreter E] [Inject Storage E] [Inject Redaction E] (root keyPrefix : ByteArray)
    (startAfter : Option ByteArray) (limit : Option UInt64) (state : State) (entries : List Entry)
    (ran : (SimulatedHost.run (scan (E := E) root keyPrefix startAfter limit) state).1 = .ok entries) :
    (∀ entry ∈ entries, (∃ tail, entry.1 = keyPrefix ++ tail) ∧
      ∀ bound, startAfter = some bound → Serve.before bound.toList entry.1.toList = true) ∧
    ∀ bound, limit = some bound → entries.length ≤ bound.toNat := by
  unfold SimulatedHost.run scan at ran
  simp only [bind, ExceptT.bind, ExceptT.mk, ExceptT.run] at ran
  rw [execute_bind] at ran
  generalize execute (cursorAt (E := E) (rootOf root)) { state with output := [] } = rooted at ran
  obtain ⟨result, state'⟩ := rooted
  match result with
  | .error e => simp [ExceptT.bindCont] at ran
  | .ok start =>
    simp only [ExceptT.bindCont] at ran
    rw [execute_bind] at ran
    generalize execute (follow (E := E) start (keyNibbles keyPrefix)) state' = followed at ran
    obtain ⟨result, state''⟩ := followed
    match result with
    | .error e => simp [ExceptT.bindCont] at ran
    | .ok cursor =>
      simp only [ExceptT.bindCont] at ran
      split at ran
      · simp only [pure, ExceptT.pure, ExceptT.mk, execute, Except.ok.injEq] at ran
        subst ran
        exact ⟨fun _ mem => (List.not_mem_nil mem).elim, fun _ _ => Nat.zero_le _⟩
      · have ran' : (execute (collect (E := E) cursor (keyNibbles keyPrefix) startAfter
            (limit.map fun bound : UInt64 => bound.toNat)).run state'').1 = .ok entries := ran
        have listed := collect_sound (E := E) cursor (keyNibbles keyPrefix) startAfter
          (limit.map fun bound : UInt64 => bound.toNat) state'' entries ran'
        refine ⟨fun entry mem => ?_, fun bound found => ?_⟩
        · obtain ⟨tail, packed, past⟩ := listed.1 entry mem
          exact ⟨prefix_of_keyNibbles keyPrefix entry.1 tail packed, past⟩
        · exact listed.2 bound.toNat (by rw [found, Option.map_some])

/-! ## A concrete trie

The five-node trie of `TrieServeProofs`, holding the keys `67 01 11` (inline
`97`) and `67 02 22` (`payload`, out of line), and beside it a second
version of the same entries with the out-of-line value inlined, and a third
root adding the key `50` next to the untouched extension. -/

open TrieServeProofs (bytes address rootHash extHash lowerHash leafAHash leafBHash valueHash slots
  rootNode extNode lowerNode leafANode leafBNode payload graph atLeafB reads)

private def keyA : ByteArray := bytes [0x67, 0x01, 0x11]
private def keyB : ByteArray := bytes [0x67, 0x02, 0x22]
private def keyC : ByteArray := bytes [0x50]
private def valueA : ByteArray := bytes [97]
private def valueC : ByteArray := bytes [42]

private def leafB2Hash := address 10
private def lower2Hash := address 11
private def ext2Hash := address 12
private def root2Hash := address 13
private def leafCHash := address 14
private def root3Hash := address 15
private def leafB2Node : Node := .leaf (bytes [2, 2]) (.inline payload)
private def lower2Node : Node := .branch (slots [(1, leafAHash), (2, leafB2Hash)]) none
private def ext2Node : Node := .extension (bytes [7, 0]) lower2Hash
private def root2Node : Node := .branch (slots [(6, ext2Hash)]) none
private def leafCNode : Node := .leaf (bytes [0]) (.inline valueC)
private def root3Node : Node := .branch (slots [(5, leafCHash), (6, extHash)]) none

/-- All three roots, under a digest that names `payload`'s address. -/
private def three : State :=
  { graph with
    hash := fun _ => valueHash,
    files := graph.files ++ [((nodeSpace, leafB2Hash), encode leafB2Node),
      ((nodeSpace, lower2Hash), encode lower2Node), ((nodeSpace, ext2Hash), encode ext2Node),
      ((nodeSpace, root2Hash), encode root2Node), ((nodeSpace, leafCHash), encode leafCNode),
      ((nodeSpace, root3Hash), encode root3Node)] }

/-- Leaf B is not held, and its position was refused by the peer. -/
private def refused : State :=
  { graph with
    files := graph.files.filter fun entry => entry.1 != (nodeSpace, leafBHash),
    redacted := [(leafBHash, bytes atLeafB)] }

/-- Leaf B is not held, and nothing says why. -/
private def missing : State :=
  { graph with files := graph.files.filter fun entry => entry.1 != (nodeSpace, leafBHash) }

private def empty : ByteArray := address 0
private def whole : Serve.Scope := ⟨none, []⟩
private def valueRead : List String := ["bytes:" ++ valueSpace]

/-- A scan of the whole trie lists both entries in key order, reading each
node once and only the out-of-line value. -/
theorem a_scan_lists_the_trie_in_key_order :
    let result := SimulatedHost.run (scan (E := Walk.Effects) rootHash (bytes []) none none) graph
    (result.1, result.2.trace) == (.ok [(keyA, valueA), (keyB, payload)], reads 5 ++ valueRead) := by
  decide +kernel

/-- A prefix confines the listing to the keys that start with it, walking
only the spine down to the prefix and what hangs below it; a prefix nothing
starts with lists nothing. -/
theorem a_prefix_confines_the_listing :
    (let result := SimulatedHost.run (scan (E := Walk.Effects) rootHash (bytes [0x67, 0x02]) none none) graph
     (result.1, result.2.trace) == (.ok [(keyB, payload)], reads 4 ++ valueRead)) ∧
    (let result := SimulatedHost.run (scan (E := Walk.Effects) rootHash (bytes [0x67, 0x03]) none none) graph
     (result.1, result.2.trace) == (.ok [], reads 3)) := by
  decide +kernel

/-- Resuming after a key lists what sorts strictly after it, and a limit
stops the walk as soon as it is full: leaf B is never read. -/
theorem a_cursor_and_a_limit_bound_the_listing :
    (let result := SimulatedHost.run (scan (E := Walk.Effects) rootHash (bytes []) (some keyA) none) graph
     (result.1, result.2.trace) == (.ok [(keyB, payload)], reads 5 ++ valueRead)) ∧
    (let result := SimulatedHost.run (scan (E := Walk.Effects) rootHash (bytes []) none (some 1)) graph
     (result.1, result.2.trace) == (.ok [(keyA, valueA)], reads 4)) := by
  decide +kernel

/-- The zero root is the empty trie: nothing is listed and nothing is read. -/
theorem nothing_is_listed_under_the_empty_root :
    let result := SimulatedHost.run (scan (E := Walk.Effects) empty (bytes []) none none) graph
    (result.1, result.2.trace) == (.ok [], []) := by
  decide +kernel

/-- A refusal cannot turn a partial file list into successful output. Both
refused and unexplained missing nodes leave the scan incomplete. -/
theorem a_refusal_cannot_hide_a_missing_part_of_the_snapshot :
    (let result := SimulatedHost.run (scan (E := Walk.Effects) rootHash (bytes []) none none) refused
     (result.1, result.2.trace) == (.error (.missingNode leafBHash), reads 5)) ∧
    (let result := SimulatedHost.run (scan (E := Walk.Effects) rootHash (bytes []) none none) missing
     (result.1, result.2.trace) == (.error (.missingNode leafBHash), reads 5)) := by
  decide +kernel

/-- A root against itself reads nothing; against the empty root, every
entry is an addition. -/
theorem a_diff_against_the_empty_root_adds_everything :
    (let result := SimulatedHost.run (diff (E := Diff.Effects) rootHash rootHash) three
     (result.1, result.2.trace) == (.ok [], [])) ∧
    (let result := SimulatedHost.run (diff (E := Diff.Effects) empty rootHash) three
     (result.1, result.2.trace) ==
       (.ok [⟨keyA, none, some (.inline valueA)⟩, ⟨keyB, none, some (.hash valueHash)⟩], reads 5)) := by
  decide +kernel

/-- The same entries with one value inlined are no change: both spines are
walked, leaf A is shared by address and never read, and the two
representations of leaf B's value are reconciled by one digest. -/
theorem representations_of_one_value_are_no_change :
    let result := SimulatedHost.run (diff (E := Diff.Effects) rootHash root2Hash) three
    (result.1, result.2.trace) == (.ok [], reads 8 ++ ["digest"]) := by
  decide +kernel

/-- Structural sharing is pruned before it is read: adding one key beside
the extension reads the two roots and the new leaf, nothing below the
shared address. -/
theorem a_shared_subtree_is_pruned_unread :
    let result := SimulatedHost.run (diff (E := Diff.Effects) rootHash root3Hash) three
    (result.1, result.2.trace) == (.ok [⟨keyC, none, some (.inline valueC)⟩], reads 3) := by
  decide +kernel

/-- Materializing streams each change as it is found, only the new side
resolved, and answers how many were handed over. -/
theorem materializing_streams_changes_in_walk_order :
    let result := SimulatedHost.run (materialize (E := Diff.Effects) whole empty rootHash) three
    (result.1, result.2.trace, result.2.applied) ==
      (.ok 2, reads 4 ++ ["apply"] ++ reads 1 ++ valueRead ++ ["apply"],
        [(keyA, 0, some valueA), (keyB, 0, some payload)]) := by
  decide +kernel

/-- A scoped materialization stays inside the grant: leaf B's position is
skipped before it is read. -/
theorem a_scoped_materialization_stays_inside_the_grant :
    let result := SimulatedHost.run (materialize (E := Diff.Effects) ⟨some [bytes [6, 7, 0, 1]], []⟩ empty rootHash)
      three
    (result.1, result.2.trace, result.2.applied) == (.ok 1, reads 4 ++ ["apply"], [(keyA, 0, some valueA)]) := by
  decide +kernel

/-- A walk writes nothing: a failure at any effect is the answer, and the
store is exactly as it was. -/
theorem every_failed_walk_effect_changes_nothing :
    ((List.range 6).all fun index =>
      let result := SimulatedHost.run (scan (E := Walk.Effects) rootHash (bytes []) none none) (fail graph index)
      failed result.1 && result.2.files == graph.files && result.2.db == graph.db) = true ∧
    ((List.range 9).all fun index =>
      let result := SimulatedHost.run (diff (E := Diff.Effects) rootHash root2Hash) (fail three index)
      failed result.1 && result.2.files == three.files && result.2.db == three.db) = true ∧
    ((List.range 8).all fun index =>
      let result := SimulatedHost.run (materialize (E := Diff.Effects) whole empty rootHash) (fail three index)
      failed result.1 && result.2.files == three.files && result.2.db == three.db) = true := by
  decide +kernel

end Synchronicity.TrieWalkProofs
