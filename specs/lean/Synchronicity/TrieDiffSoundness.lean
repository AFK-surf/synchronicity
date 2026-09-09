import Synchronicity.TrieDiffCoverage
import Synchronicity.SnapshotDelta

/-! Soundness complements coverage: every emitted change is tied to the
independent old/new snapshots at its actual path. SQL consumers can use this
local fact without assuming that a completed traversal is an exact view. -/
namespace Synchronicity.TrieDiffSoundness
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie Walk SimulatedHost PrivateDatabase
open TrieProgramProofs TrieSnapshotProofs TrieSnapshotClosure TrieCursorSemantics TrieDiffSemantics
open TrieDiffCoverage

def KeyPath (path : Path) : Prop :=
  (∀ nibble ∈ path, nibble.toNat < 16) ∧ path.length ≤ maxDepthNibbles

theorem packed_path (path : Path) (key : ByteArray)
    (digits : ∀ nibble ∈ path, nibble.toNat < 16)
    (packed : bytesOfNibbles path = some key) : keyNibbles key = path := by
  induction path using bytesOfNibbles.induct generalizing key with
  | case1 => cases packed; simp [keyNibbles, TrieWalkProofs.toList_eq]
  | case3 => cases packed
  | case2 hi lo rest ih =>
    have hiBound := digits hi (by simp)
    have loBound := digits lo (by simp)
    have high : (hi * 16 + lo) / 16 = hi := by
      apply UInt8.toNat_inj.mp
      simp only [UInt8.toNat_div, UInt8.toNat_add, UInt8.toNat_mul, UInt8.toNat_ofNat,
        Nat.reducePow, Nat.reduceMod]
      omega
    have low : (hi * 16 + lo) % 16 = lo := by
      apply UInt8.toNat_inj.mp
      simp only [UInt8.toNat_mod, UInt8.toNat_add, UInt8.toNat_mul, UInt8.toNat_ofNat,
        Nat.reducePow, Nat.reduceMod]
      omega
    cases inner : bytesOfNibbles rest with
    | none => simp [bytesOfNibbles, inner] at packed
    | some tail =>
      have exactTail := ih tail (fun nibble member => digits nibble (by simp [member])) inner
      simp only [bytesOfNibbles, inner, Option.map_some, Option.some.injEq] at packed
      rw [← packed]
      simpa [keyNibbles, TrieWalkProofs.toList_eq, high, low] using congrArg (hi :: lo :: ·) exactTail

theorem packed_bound (path : Path) (key : ByteArray) (valid : KeyPath path)
    (packed : bytesOfNibbles path = some key) : key.size ≤ maxKeyBytes := by
  have length := congrArg List.length (packed_path path key valid.1 packed)
  rw [TrieMutateProofs.keyNibbles_length] at length
  have bound := valid.2
  unfold maxDepthNibbles at bound
  omega

def AtRoot (world : World) (root : ByteArray) (cursor : Cursor) (path : Path) : Prop :=
  ∀ tail bytes, CursorEntry world.snapshot cursor tail bytes ↔
    ReferenceEntry world.snapshot (rootOf root) (path ++ tail) bytes

def Position (world : World) (oldRoot newRoot : ByteArray) (pair : Cursor × Cursor) (path : Path) : Prop :=
  Ready world.snapshot world.images pair.1 ∧ Ready world.snapshot world.images pair.2 ∧
  AtRoot world oldRoot pair.1 path ∧ AtRoot world newRoot pair.2 path ∧ KeyPath path

/-- Optional payload meaning, including authenticated absence, at a root. -/
def RootValue (world : World) (root : ByteArray) (path : Path) (value : Option ByteArray) : Prop :=
  ∀ bytes, ReferenceEntry world.snapshot (rootOf root) path bytes ↔ value = some bytes

/-- A real payload change at the packed position in the two snapshots. The
path is retained explicitly until the walk's nibble-bound theorem is applied. -/
def ValidChange (world : World) (oldRoot newRoot : ByteArray) (change : Diff.Change) : Prop :=
  ∃ path oldValue newValue, bytesOfNibbles path = some change.key ∧ KeyPath path ∧
    OptionalValue world.snapshot change.old oldValue ∧ OptionalValue world.snapshot change.new newValue ∧
    RootValue world oldRoot path oldValue ∧ RootValue world newRoot path newValue ∧ oldValue ≠ newValue

/-- The packed key denotes the real byte-key difference, not merely the
position from which a walker happened to produce a value. -/
theorem valid_change_meaning (valid : ValidChange world oldRoot newRoot change) :
    ∃ oldValue newValue, SnapshotDelta.Changes world.snapshot oldRoot newRoot change.key oldValue newValue ∧
      OptionalValue world.snapshot change.old oldValue ∧ OptionalValue world.snapshot change.new newValue := by
  obtain ⟨path, oldValue, newValue, packed, validPath, old, new, oldRootValue, newRootValue, different⟩ := valid
  have pathEq := packed_path path change.key validPath.1 packed
  have bound := packed_bound path change.key validPath packed
  refine ⟨oldValue, newValue, ⟨?_, ?_, different⟩, old, new⟩
  · intro bytes
    rw [← reference_meaning world.snapshot oldRoot change.key bytes bound, pathEq]
    exact oldRootValue bytes
  · intro bytes
    rw [← reference_meaning world.snapshot newRoot change.key bytes bound, pathEq]
    exact newRootValue bytes

section Interpreted
variable [handler : Interpreter Diff.Effects] [ReadsAgree handler]

theorem resolve_exact (world : World) (state final : State) (value : Value) (bytes : ByteArray)
    (faithful : Faithful world state)
    (ran : execute (resolve (E := Diff.Effects) value) state = (.ok bytes, final)) :
    ValueDenotes world.snapshot value bytes := by
  have ran := (read_execute_same (handler := handler) _ (resolve_readonly value) state).symm.trans ran
  letI : Interpreter Diff.Effects := standard
  cases value with
  | inline payload => cases ran; exact .inline _
  | hash hash =>
    unfold resolve at ran
    obtain ⟨value, middle, read, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
    have rawRead := read_result state valueSpace hash value middle read
    cases value with
    | none => cases rest
    | some payload =>
      cases rest
      exact .stored _ _ (faithful.1 _ _ _ (.inr rfl) (by simp [readableBytes, rawRead]))

theorem resolve_optional_exact (world : World) (state final : State)
    (value : Option Value) (bytes : Option ByteArray) (faithful : Faithful world state)
    (ran : execute ((match value with
      | none => pure none | some value => some <$> resolve value) : TrieDiffCoverage.Action (Option ByteArray))
      state = (.ok bytes, final)) : OptionalValue world.snapshot value bytes := by
  cases value with
  | none => cases ran; exact .absent
  | some value =>
    simp only [Functor.map, ExceptT.map, ExceptT.mk, bind, execute_bind] at ran
    cases resolved : execute (resolve (E := Diff.Effects) value) state with
    | mk result middle =>
      cases result with
      | error error => simp [resolved] at ran
      | ok bytes =>
        simp only [resolved] at ran
        cases ran
        exact .present (resolve_exact world state final value bytes faithful resolved)

theorem enter_valid (world : World) (oldRoot newRoot : ByteArray) (state : State)
    (pair : Cursor × Cursor) (path : Path) (change : Diff.Change) (worth : Bool)
    (faithful : Faithful world state) (position : Position world oldRoot newRoot pair path)
    (ran : (execute (Diff.enter (E := Diff.Effects) pair.1 pair.2 path) state).1 = .ok (some change, worth)) :
    ValidChange world oldRoot newRoot change := by
  obtain ⟨a, left, aImages⟩ := ready_value position.1
  obtain ⟨b, right, bImages⟩ := ready_value position.2.1
  have distinct : Distinguishes state.hash a b := by
    intro x y hx hy hashes
    rw [faithful.2] at hashes
    exact world.collisionFree x (aImages x hx) y (bImages y hy) hashes
  have rawRun := (congrArg Prod.fst (read_execute_same (handler := handler)
    _ (enter_readonly pair.1 pair.2 path) state)).symm.trans ran
  have facts := enter_exact pair.1 pair.2 path world.snapshot state a b left right
    (by simpa only [faithful.2] using world.addressed) distinct (some change) worth rawRun
  obtain ⟨packed, old, new⟩ := facts.2 change rfl
  refine ⟨path, a, b, packed, position.2.2.2.2, old ▸ left, new ▸ right, ?_, ?_, facts.1.mp rfl⟩
  · intro bytes
    simpa only [List.append_nil] using (position.2.2.1 [] bytes).symm.trans (optional_meaning left)
  · intro bytes
    simpa only [List.append_nil] using (position.2.2.2.1 [] bytes).symm.trans (optional_meaning right)

theorem child_position (world : World) (oldRoot newRoot : ByteArray) (state loadedA loadedB : State)
    (pair child : Cursor × Cursor) (path : Path) (nibble : UInt8)
    (nibbleBound : nibble.toNat < 16) (depth : path.length < maxDepthNibbles)
    (faithful : Faithful world state) (position : Position world oldRoot newRoot pair path)
    (readA : execute (cursorChild (E := Diff.Effects) pair.1 nibble) state = (.ok child.1, loadedA))
    (readB : execute (cursorChild (E := Diff.Effects) pair.2 nibble) loadedA = (.ok child.2, loadedB)) :
    Faithful world loadedB ∧ Position world oldRoot newRoot child (path ++ [nibble]) := by
  have faithfulA : Faithful world loadedA := by
    have facts := read_preserves (handler := handler) _ (child_readonly pair.1 nibble) world state faithful
    exact (congrArg (Faithful world) (congrArg Prod.snd readA)).mp facts
  have faithfulB : Faithful world loadedB := by
    have facts := read_preserves (handler := handler) _ (child_readonly pair.2 nibble) world loadedA faithfulA
    exact (congrArg (Faithful world) (congrArg Prod.snd readB)).mp facts
  have meaningA := cursor_child_exact state world.snapshot pair.1 child.1 nibble faithful.1
    (congrArg Prod.fst ((read_execute_same _ (child_readonly pair.1 nibble) state).symm.trans readA))
  have meaningB := cursor_child_exact loadedA world.snapshot pair.2 child.2 nibble faithfulA.1
    (congrArg Prod.fst ((read_execute_same _ (child_readonly pair.2 nibble) loadedA).symm.trans readB))
  refine ⟨faithfulB, child_ready world state _ _ nibble faithful position.1 (congrArg Prod.fst readA),
    child_ready world loadedA _ _ nibble faithfulA position.2.1 (congrArg Prod.fst readB), ?_, ?_, ?_⟩
  · intro tail bytes
    simpa only [List.append_assoc, List.singleton_append] using
      (meaningA tail bytes).trans (position.2.2.1 (nibble :: tail) bytes)
  · intro tail bytes
    simpa only [List.append_assoc, List.singleton_append] using
      (meaningB tail bytes).trans (position.2.2.2.1 (nibble :: tail) bytes)
  · refine ⟨?_, by simp only [List.length_append, List.length_singleton]; omega⟩
    intro digit member
    rcases List.mem_append.mp member with member | member
    · exact position.2.2.2.2.1 digit member
    · exact List.mem_singleton.mp member ▸ nibbleBound

/-- Consumers must maintain their invariant only for changes proved to
come from the two roots, not arbitrary invented callback arguments. -/
def ConsumerLaw (world : World) (oldRoot newRoot : ByteArray) (scope : Serve.Scope) (P : State → A → Prop)
    (emit : A → Diff.Change → TrieDiffCoverage.Action A) : Prop :=
  ∀ state acc change answer final, Faithful world state → P state acc →
    ValidChange world oldRoot newRoot change → scope.admitsKeyPath (keyNibbles change.key) = true →
    execute (emit acc change) state = (.ok answer, final) → Faithful world final ∧ P final answer

theorem inspect_preserves (world : World) (oldRoot newRoot : ByteArray) (P : State → A → Prop)
    (stable : ReadStable P) (emit : A → Diff.Change → TrieDiffCoverage.Action A)
    (scope : Serve.Scope) (law : ConsumerLaw world oldRoot newRoot scope P emit)
    (state final : State) (acc answer : A) (pair : Cursor × Cursor) (path : Path)
    (decision : Step (Cursor × Cursor)) (faithful : Faithful world state) (holds : P state acc)
    (position : Position world oldRoot newRoot pair path)
    (ran : execute (inspect scope emit acc pair path) state = (.ok (decision, answer), final)) :
    Faithful world final ∧ P final answer ∧
      (∀ child, decision = .descend child → child = pair) := by
  unfold inspect at ran
  obtain ⟨⟨change, worth⟩, checked, checkRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  have facts := readonly_result world P stable _ (enter_readonly pair.1 pair.2 path)
    state checked _ acc faithful checkRun
  have sequence : execute ((match change with
      | some change => admitted scope emit acc change | none => pure acc) >>=
      fun out => pure (if worth then .descend pair else .visited, out)
      : TrieDiffCoverage.Action (Step (Cursor × Cursor) × A)) checked = (.ok (decision, answer), final) := by
    cases change <;> exact rest
  obtain ⟨out, applied, applyRun, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ sequence
  have appliedFacts : Faithful world applied ∧ P applied out := by
    cases change with
    | none => cases applyRun; exact ⟨facts.1, facts.2 holds⟩
    | some change =>
      dsimp only at applyRun
      have valid := enter_valid world oldRoot newRoot state pair path change worth faithful position
        (congrArg Prod.fst checkRun)
      unfold admitted at applyRun
      split at applyRun
      · rename_i granted
        exact law checked acc change out applied facts.1 (facts.2 holds) valid granted applyRun
      · cases applyRun; exact ⟨facts.1, facts.2 holds⟩
  cases worth <;> cases returned
  · exact ⟨appliedFacts.1, appliedFacts.2, by intro child impossible; cases impossible⟩
  · exact ⟨appliedFacts.1, appliedFacts.2, by intro child same; cases same; rfl⟩

theorem step_preserves (world : World) (oldRoot newRoot : ByteArray) (P : State → A → Prop)
    (stable : ReadStable P) (emit : A → Diff.Change → TrieDiffCoverage.Action A)
    (scope : Serve.Scope) (law : ConsumerLaw world oldRoot newRoot scope P emit)
    (state final : State) (acc answer : A) (pair : Cursor × Cursor) (path : Path) (nibble : UInt8)
    (nibbleBound : nibble.toNat < 16) (depth : path.length < maxDepthNibbles)
    (decision : Step (Cursor × Cursor)) (faithful : Faithful world state) (holds : P state acc)
    (position : Position world oldRoot newRoot pair path)
    (ran : execute (step scope emit acc pair nibble (path ++ [nibble])) state = (.ok (decision, answer), final)) :
    Faithful world final ∧ P final answer ∧
      (∀ child, decision = .descend child → Position world oldRoot newRoot child (path ++ [nibble])) := by
  unfold step at ran
  split at ran
  · cases ran; exact ⟨faithful, holds, by intro child impossible; cases impossible⟩
  · split at ran
    · cases ran; exact ⟨faithful, holds, by intro child impossible; cases impossible⟩
    · obtain ⟨ca, loadedA, readA, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
      obtain ⟨cb, loadedB, readB, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
      have positioned := child_position world oldRoot newRoot state loadedA loadedB pair (ca, cb)
        path nibble nibbleBound depth faithful position readA readB
      have keptA := readonly_result world P stable _ (child_readonly pair.1 nibble)
        state loadedA _ acc faithful readA
      have keptB := readonly_result world P stable _ (child_readonly pair.2 nibble)
        loadedA loadedB _ acc keptA.1 readB
      split at rest
      · cases rest; exact ⟨positioned.1, keptB.2 (keptA.2 holds), by intro child impossible; cases impossible⟩
      · have facts := inspect_preserves world oldRoot newRoot P stable emit scope law loadedB final acc answer
          (ca, cb) (path ++ [nibble]) decision positioned.1 (keptB.2 (keptA.2 holds)) positioned.2 rest
        exact ⟨facts.1, facts.2.1, fun child same => facts.2.2 child same ▸ positioned.2⟩

def SoundState (world : World) (oldRoot newRoot : ByteArray) (P : State → A → Prop)
    (state : State) (d : Descent (Cursor × Cursor) A) : Prop :=
  Faithful world state ∧ P state d.acc ∧
    ∀ frame ∈ d.stack, Position world oldRoot newRoot frame.1 frame.2.2

theorem descend_preserves (world : World) (oldRoot newRoot : ByteArray) (P : State → A → Prop)
    (stable : ReadStable P) (emit : A → Diff.Change → TrieDiffCoverage.Action A)
    (scope : Serve.Scope) (law : ConsumerLaw world oldRoot newRoot scope P emit)
    (state : State) (d : Descent (Cursor × Cursor) A)
    (holds : SoundState world oldRoot newRoot P state d) :
    (∀ next final, execute (Walk.descend Diff.nextChild (step scope emit) d) state = (.ok (.inl next), final) →
      SoundState world oldRoot newRoot P final next) ∧
    (∀ answer final, execute (Walk.descend Diff.nextChild (step scope emit) d) state = (.ok (.inr answer), final) →
      Faithful world final ∧ P final answer) := by
  obtain ⟨faithful, holds, frames⟩ := holds
  match d with
  | ⟨[], positions, acc⟩ =>
    constructor
    · intro next final ran; cases ran
    · intro answer final ran; cases ran; exact ⟨faithful, holds⟩
  | ⟨(pair, start, path) :: stack, positions, acc⟩ =>
    have positioned := frames (pair, start, path) (List.mem_cons_self ..)
    simp only [Walk.descend]
    split
    · constructor
      · intro next final ran; cases ran
        exact ⟨faithful, holds, fun frame member => frames frame (List.mem_cons_of_mem _ member)⟩
      · intro answer final ran; cases ran
    · rename_i chosen selected
      have bounds : chosen.toNat < 16 ∧ path.length < maxDepthNibbles := by
        split at selected
        · cases selected
        · rename_i room
          have chosenBound := (Option.filter_eq_some_iff.mp selected).2
          simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at room
          exact ⟨by simpa using chosenBound, by omega⟩
      have result : ∀ decision answer final,
          execute (step scope emit acc pair chosen (path ++ [chosen])) state = (.ok (decision, answer), final) →
          Faithful world final ∧ P final answer ∧
            ∀ frame ∈ nextStack decision pair chosen path stack,
              Position world oldRoot newRoot frame.1 frame.2.2 := by
        intro decision answer final ran
        have facts := step_preserves world oldRoot newRoot P stable emit scope law state final acc answer
          pair path chosen bounds.1 bounds.2 decision faithful holds positioned ran
        refine ⟨facts.1, facts.2.1, ?_⟩
        intro frame member
        cases decision with
        | descend child =>
          rcases List.mem_cons.mp member with same | member
          · subst frame; exact facts.2.2 child rfl
          · rcases List.mem_cons.mp member with same | member
            · subst frame; exact positioned
            · exact frames frame (List.mem_cons_of_mem _ member)
        | visited | skip =>
          rcases List.mem_cons.mp member with same | member
          · subst frame; exact positioned
          · exact frames frame (List.mem_cons_of_mem _ member)
        | stop => cases member
      constructor
      · intro next final ran
        obtain ⟨⟨decision, answer⟩, middle, stepRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
        have facts := result decision answer middle stepRun
        cases decision with
        | descend child | visited =>
          dsimp only at rest
          split at rest
          · cases rest
          · cases rest; exact facts
        | skip => cases rest; exact facts
        | stop => cases rest
      · intro answer final ran
        obtain ⟨⟨decision, out⟩, middle, stepRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
        have facts := result decision out middle stepRun
        cases decision with
        | descend child | visited =>
          dsimp only at rest
          split at rest <;> cases rest
        | skip => cases rest
        | stop => cases rest; exact ⟨facts.1, facts.2.1⟩

theorem loop_preserves (fuel : Nat) (world : World) (oldRoot newRoot : ByteArray) (P : State → A → Prop)
    (stable : ReadStable P) (emit : A → Diff.Change → TrieDiffCoverage.Action A)
    (scope : Serve.Scope) (law : ConsumerLaw world oldRoot newRoot scope P emit)
    (state final : State) (d : Descent (Cursor × Cursor) A) (answer : A)
    (holds : SoundState world oldRoot newRoot P state d)
    (ran : execute (OperationOver.iterate (Walk.descend Diff.nextChild (step scope emit))
      Walk.Error.ceiling fuel d) state = (.ok answer, final)) : Faithful world final ∧ P final answer := by
  exact iterate_invariant (fun d => (Walk.descend Diff.nextChild (step scope emit) d).run) .ceiling
    (SoundState world oldRoot newRoot P) (fun state answer => Faithful world state ∧ P state answer)
    (fun state d next final holds ran =>
      (descend_preserves world oldRoot newRoot P stable emit scope law state d holds).1 next final ran)
    (fun state d answer final holds ran =>
      (descend_preserves world oldRoot newRoot P stable emit scope law state d holds).2 answer final ran)
    fuel _ state
    (descend_preserves world oldRoot newRoot P stable emit scope law state d holds).1
    (descend_preserves world oldRoot newRoot P stable emit scope law state d holds).2 answer final ran

theorem walk_preserves (world : World) (oldRoot newRoot : ByteArray) (P : State → A → Prop)
    (stable : ReadStable P) (emit : A → Diff.Change → TrieDiffCoverage.Action A)
    (scope : Serve.Scope) (law : ConsumerLaw world oldRoot newRoot scope P emit)
    (state final : State) (pair : Cursor × Cursor) (path : Path) (acc answer : A)
    (faithful : Faithful world state) (holds : P state acc)
    (position : Position world oldRoot newRoot pair path)
    (ran : execute (walk Diff.nextChild (step scope emit) pair path acc) state = (.ok answer, final)) :
    Faithful world final ∧ P final answer := by
  apply loop_preserves walkFuel world oldRoot newRoot P stable emit scope law state final _ answer _ ran
  refine ⟨faithful, holds, ?_⟩
  intro frame member
  have same := List.mem_singleton.mp member
  subst frame
  exact position

/-- The real scoped stream maintains any consumer invariant whose local
refinement has been proved for genuine changes in the two snapshots. -/
theorem diff_each_preserves (world : World) (oldRoot newRoot : ByteArray) (P : State → A → Prop)
    (stable : ReadStable P) (emit : A → Diff.Change → TrieDiffCoverage.Action A)
    (scope : Serve.Scope) (law : ConsumerLaw world oldRoot newRoot scope P emit)
    (state final : State) (acc answer : A) (faithful : Faithful world state) (holds : P state acc)
    (ran : execute (Diff.diffEach scope emit oldRoot newRoot acc) state = (.ok answer, final)) :
    Faithful world final ∧ P final answer := by
  rw [diff_each_unfold] at ran
  split at ran
  · cases ran; exact ⟨faithful, holds⟩
  · obtain ⟨a, loadedA, readA, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
    have factsA := readonly_result world P stable _ (cursor_readonly (rootOf oldRoot))
      state loadedA _ acc faithful readA
    have readyA := cursor_ready world state _ a faithful (congrArg Prod.fst readA)
    have meaningA := cursor_at_exact state world.snapshot (rootOf oldRoot) a faithful.1
      (congrArg Prod.fst ((read_execute_same _ (cursor_readonly (rootOf oldRoot)) state).symm.trans readA))
    obtain ⟨b, loadedB, readB, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
    have factsB := readonly_result world P stable _ (cursor_readonly (rootOf newRoot))
      loadedA loadedB _ acc factsA.1 readB
    have readyB := cursor_ready world loadedA _ b factsA.1 (congrArg Prod.fst readB)
    have meaningB := cursor_at_exact loadedA world.snapshot (rootOf newRoot) b factsA.1.1
      (congrArg Prod.fst ((read_execute_same _ (cursor_readonly (rootOf newRoot)) loadedA).symm.trans readB))
    have position : Position world oldRoot newRoot (a, b) [] :=
      ⟨readyA, readyB, meaningA, meaningB, by simp [KeyPath]⟩
    obtain ⟨⟨change, worth⟩, checked, checkRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
    have sequence : execute ((match change with
        | some change => admitted scope emit acc change | none => pure acc) >>= fun out =>
        if !worth then pure out else walk Diff.nextChild (step scope emit) (a, b) [] out
        : TrieDiffCoverage.Action A) checked = (.ok answer, final) := by
      cases change <;> exact rest
    obtain ⟨out, applied, applyRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ sequence
    have inspected := inspect_run scope emit (a, b) [] loadedB checked applied acc out change worth
      checkRun (by cases change <;> exact applyRun)
    have facts := inspect_preserves world oldRoot newRoot P stable emit scope law loadedB applied acc out
      (a, b) [] _ factsB.1 (factsB.2 (factsA.2 holds)) position inspected
    cases worth with
    | false => cases rest; exact ⟨facts.1, facts.2.1⟩
    | true =>
      exact walk_preserves world oldRoot newRoot P stable emit scope law applied final (a, b) [] out answer
        facts.1 facts.2.1 position rest

theorem diff_lists_only_changes (world : World) (oldRoot newRoot : ByteArray)
    (state final : State) (changes : List Diff.Change) (faithful : Faithful world state)
    (ran : execute (Diff.diff (E := Diff.Effects) oldRoot newRoot) state = (.ok changes, final)) :
    ∀ change ∈ changes, ValidChange world oldRoot newRoot change := by
  unfold Diff.diff at ran
  obtain ⟨output, finished, walked, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  cases returned
  let P := fun (_ : State) (changes : List Diff.Change) =>
    ∀ change ∈ changes, ValidChange world oldRoot newRoot change
  have stable : ReadStable P := fun _ _ _ _ h => h
  have law : ConsumerLaw world oldRoot newRoot ⟨none, []⟩ P (fun acc c => pure (c :: acc)) := by
    intro state acc change answer final faithful holds valid _ ran
    cases ran
    refine ⟨faithful, ?_⟩
    intro c member
    rcases List.mem_cons.mp member with same | member
    · exact same ▸ valid
    · exact holds c member
  have facts := diff_each_preserves world oldRoot newRoot P stable (fun acc c => pure (c :: acc))
    ⟨none, []⟩ law state final [] output faithful (by intro c member; cases member) walked
  intro change member
  exact facts.2 change (List.mem_reverse.mp member)

/-- The actual returned list contains a key exactly when that key's
independent snapshot entry meaning changed. Payload meaning is supplied
separately by `valid_change_meaning`; duplicates/order are not assumed. -/
theorem diff_keys_exact (world : World) (oldRoot newRoot key : ByteArray)
    (bound : key.size ≤ maxKeyBytes) (state final : State) (changes : List Diff.Change)
    (faithful : Faithful world state)
    (ran : execute (Diff.diff (E := Diff.Effects) oldRoot newRoot) state = (.ok changes, final)) :
    (∃ change ∈ changes, change.key = key) ↔ SnapshotDelta.ChangedKey world.snapshot oldRoot newRoot key := by
  constructor
  · rintro ⟨change, member, same⟩
    obtain ⟨oldValue, newValue, delta, _⟩ := valid_change_meaning
      (diff_lists_only_changes world oldRoot newRoot state final changes faithful ran change member)
    exact same ▸ SnapshotDelta.changes_key delta
  · intro different
    exact diff_lists_changed_key world oldRoot newRoot key bound state final changes faithful different ran

end Interpreted
end Synchronicity.TrieDiffSoundness
