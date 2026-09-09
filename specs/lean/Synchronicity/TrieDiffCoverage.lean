import Synchronicity.TrieCursorSemantics
import Synchronicity.PrivateDatabase
import Synchronicity.TransactionSuccess

/-! Coverage of the executable lockstep diff. The reference snapshot is
independent of local availability: local raw records must agree with it, but
missing local records are allowed. A successful walk must account for changes
in that reference, not merely exhaust its own stack. -/
namespace Synchronicity.TrieDiffCoverage
set_option maxRecDepth 16384
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie Walk SimulatedHost PrivateDatabase
open TrieProgramProofs TrieSnapshotProofs TrieSnapshotClosure TrieCursorSemantics TrieDiffSemantics

/-- Immediate payloads, including a compressed leaf's not-yet-visited value. -/
def PayloadReady (store : RawSnapshot) (images : List ByteArray) (value : Value) : Prop :=
  ∃ bytes ∈ images, ValueDenotes store value bytes

def NodeReady (store : RawSnapshot) (images : List ByteArray) : Node → Prop
  | .leaf _ value => PayloadReady store images value
  | .extension _ _ => True
  | .branch _ value => ∀ v, value = some v → PayloadReady store images v
  | .route _ value => ∀ hash, value = some hash → PayloadReady store images (.hash hash)

def Ready (store : RawSnapshot) (images : List ByteArray) : Cursor → Prop
  | .empty => True
  | .at node => NodeReady store images node

/-- A finite reference-payload domain supplies the relevant-image hash
contract. It need not be present locally. No traversal result, completion
flag, view projection or refinement assertion occurs in this structure. -/
structure World where
  snapshot : RawSnapshot
  images : List ByteArray
  digest : ByteArray → ByteArray
  addressed : Addressed snapshot digest
  collisionFree : ∀ a ∈ images, ∀ b ∈ images, digest a = digest b → a = b
  payloads : ∀ hash raw node, snapshot nodeSpace hash = some raw → decode raw = .ok node →
    NodeReady snapshot images node

def Faithful (world : World) (state : State) : Prop :=
  RecordsIncluded (readableBytes state) world.snapshot ∧ state.hash = world.digest

def readAllowed : (A : Type) → Diff.Effects A → Prop
  | _, .left (.readBytes _ _) => True
  | _, .right (.right (.left _)) => True
  | _, _ => False

abbrev standard : Interpreter Diff.Effects := inferInstance

/-- Only raw reads and hashing are fixed here. Apply can be implemented by
the consuming SQL program; it is not required to be a host-side event log. -/
class ReadsAgree (handler : Interpreter Diff.Effects) : Prop where
  reads : ∀ {A} (effect : Diff.Effects A), readAllowed _ effect → ∀ state,
    handler.handle effect state = standard.handle effect state

instance : ReadsAgree standard := ⟨fun _ _ _ => rfl⟩

section Interpreted
variable [handler : Interpreter Diff.Effects] [ReadsAgree handler]

theorem read_execute_same (program : Program Diff.Effects A) (safe : Only readAllowed program)
    (state : State) : execute program state = @execute _ _ standard program state := by
  induction safe generalizing state with
  | done _ => rfl
  | @request B effect next allowed _ ih =>
    simp only [execute, ReadsAgree.reads effect allowed]
    exact ih _ _

def ReadObservation (state : State) := (readableBytes state, state.hash, state.applied)

theorem read_effect_preserves (effect : Diff.Effects A) (safe : readAllowed _ effect)
    (state : State) : ReadObservation (Interpreter.handle effect state).2 = ReadObservation state := by
  rw [ReadsAgree.reads effect safe]
  cases effect with
  | left storage =>
    cases storage <;> try contradiction
    simp only [Interpreter.handle, SimulatedHost.storage, reply]
    split <;> rfl
  | right e =>
    rcases e with e | e
    · cases e; contradiction
    · rcases e with e | e
      · cases e
        simp only [Interpreter.handle, SimulatedHost.digest, reply]
        split <;> rfl
      · cases e; contradiction

theorem read_preserves (program : Program Diff.Effects A) (safe : Only readAllowed program)
    (world : World) (state : State) (faithful : Faithful world state) :
    Faithful world (execute program state).2 := by
  have same := safe.preserves_observation ReadObservation program read_effect_preserves state
  have bytes := congrArg Prod.fst same
  have hash := congrArg (fun observation => observation.2.1) same
  refine ⟨?_, hash.trans faithful.2⟩
  change readableBytes (execute program state).2 = readableBytes state at bytes
  rw [bytes]
  exact faithful.1

omit handler [ReadsAgree handler] in
theorem cursor_readonly (reference : Option ByteArray) :
    Only readAllowed (cursorAt (E := Diff.Effects) reference).run := by
  unfold cursorAt
  repeat' first
    | exact .done _
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | split

omit handler [ReadsAgree handler] in
theorem child_readonly (cursor : Cursor) (nibble : UInt8) :
    Only readAllowed (cursorChild (E := Diff.Effects) cursor nibble).run := by
  unfold cursorChild
  repeat' first | exact .done _ | exact cursor_readonly _ | split

omit handler [ReadsAgree handler] in
theorem enter_readonly (a b : Cursor) (path : Path) :
    Only readAllowed (Diff.enter (E := Diff.Effects) a b path).run := by
  unfold Diff.enter
  repeat' first
    | exact .done _
    | exact Only.raise _ _ trivial
    | (refine Only.seq ?_ fun _ => ?_)
    | (unfold Diff.sameValue; split)
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem cursor_ready (world : World) (state : State) (reference : Option ByteArray) (cursor : Cursor)
    (faithful : Faithful world state)
    (ran : (execute (cursorAt (E := Diff.Effects) reference) state).1 = .ok cursor) :
    Ready world.snapshot world.images cursor := by
  have ran := (congrArg Prod.fst (read_execute_same (handler := handler)
    _ (cursor_readonly reference) state)).symm.trans ran
  letI : Interpreter Diff.Effects := standard
  cases reference with
  | none => cases ran; trivial
  | some hash =>
    unfold cursorAt at ran
    obtain ⟨value, middle, read, rest⟩ := TrieServePrivacyProofs.bind_ok _ _ state cursor ran
    have rawRead := read_result state nodeSpace hash value middle read
    cases value with
    | none => cases rest
    | some raw =>
      have held : world.snapshot nodeSpace hash = some raw :=
        faithful.1 _ _ _ (.inl rfl) (by simp [readableBytes, rawRead])
      cases decoded : decode raw with
      | error message => simp [decoded, execute] at rest
      | ok node =>
        simp only [decoded] at rest
        cases rest
        exact world.payloads hash raw node held decoded

theorem child_ready (world : World) (state : State) (parent child : Cursor) (nibble : UInt8)
    (faithful : Faithful world state) (ready : Ready world.snapshot world.images parent)
    (ran : (execute (cursorChild (E := Diff.Effects) parent nibble) state).1 = .ok child) :
    Ready world.snapshot world.images child := by
  cases parent with
  | empty => cases ran; trivial
  | «at» node =>
    cases node with
    | leaf suffix value =>
      simp only [cursorChild] at ran
      split at ran
      · split at ran <;> cases ran <;> first | exact ready | trivial
      · cases ran; trivial
    | extension segment address =>
      simp only [cursorChild] at ran
      split at ran
      · split at ran
        · cases ran; trivial
        · split at ran
          · exact cursor_ready world state _ child faithful ran
          · cases ran; trivial
      · cases ran; trivial
    | branch children value => exact cursor_ready world state _ child faithful ran
    | route children value => exact cursor_ready world state _ child faithful ran

omit handler [ReadsAgree handler] in
theorem ready_value (ready : Ready store images cursor) :
    ∃ value, OptionalValue store cursor.value value ∧ ∀ bytes, value = some bytes → bytes ∈ images := by
  cases cursor with
  | empty => exact ⟨none, .absent, by simp⟩
  | «at» node =>
    cases node with
    | leaf suffix value =>
      obtain ⟨bytes, member, denotes⟩ := ready
      simp only [Cursor.value]
      split
      · exact ⟨some bytes, .present denotes, by simpa⟩
      · exact ⟨none, .absent, by simp⟩
    | extension segment address => exact ⟨none, .absent, by simp⟩
    | branch children value =>
      cases value with
      | none => exact ⟨none, .absent, by simp⟩
      | some v =>
        obtain ⟨bytes, member, denotes⟩ := ready v rfl
        exact ⟨some bytes, .present denotes, by simpa⟩
    | route children value =>
      cases value with
      | none => exact ⟨none, .absent, by simp⟩
      | some v =>
        obtain ⟨bytes, member, denotes⟩ := ready v rfl
        exact ⟨some bytes, .present denotes, by simpa⟩

omit handler [ReadsAgree handler] in
theorem terminal_meaning (store : RawSnapshot) (cursor : Cursor) (bytes : ByteArray) :
    CursorEntry store cursor [] bytes ↔
      ∃ v, cursor.value = some v ∧ ValueDenotes store v bytes := by
  cases cursor with
  | empty => simp [CursorEntry, Cursor.value]
  | «at» node =>
    cases node with
    | leaf suffix value =>
      have zero : suffix.size = 0 ↔ suffix.toList = [] := by
        rw [← byte_array_list_length, List.length_eq_zero_iff]
      by_cases empty : suffix.size = 0
      · simp [CursorEntry, NodeEntries, Cursor.value, empty, zero.mp empty]
      · have notEmpty : suffix.toList ≠ [] := fun h => empty (zero.mpr h)
        simp [CursorEntry, NodeEntries, Cursor.value, empty, Ne.symm notEmpty]
    | extension segment address =>
      simp [CursorEntry, NodeEntries, Cursor.value]
      intro nonempty empty
      exact False.elim (nonempty empty)
    | branch children value => rfl
    | route children value =>
      cases value <;> simp [CursorEntry, NodeEntries, Cursor.value]

omit handler [ReadsAgree handler] in
theorem optional_meaning (denotes : OptionalValue store cursor.value value) :
    CursorEntry store cursor [] bytes ↔ value = some bytes := by
  rw [terminal_meaning]
  generalize ref : cursor.value = reference at denotes ⊢
  cases denotes with
  | absent => simp
  | @present v payload denotes =>
    simp only [Option.some.injEq, exists_eq_left']
    constructor
    · intro found
      have equal := optional_value_unique (.present denotes) (.present found)
      exact Option.some.inj equal
    · intro equal; subst payload; exact denotes

def Different (store : RawSnapshot) (pair : Cursor × Cursor) (tail : Path) : Prop :=
  ∃ bytes, ¬(CursorEntry store pair.1 tail bytes ↔ CursorEntry store pair.2 tail bytes)

omit handler [ReadsAgree handler] in
theorem different_has_entry (different : Different store pair tail) :
    ∃ bytes, CursorEntry store pair.1 tail bytes ∨ CursorEntry store pair.2 tail bytes := by
  obtain ⟨bytes, different⟩ := different
  by_cases left : CursorEntry store pair.1 tail bytes
  · exact ⟨bytes, .inl left⟩
  · by_cases right : CursorEntry store pair.2 tail bytes
    · exact ⟨bytes, .inr right⟩
    · exact False.elim (different (by simp [left, right]))

omit [ReadsAgree handler] in
theorem enter_pruned_equal (state : State) (a b : Cursor) (path : Path) (change : Option Diff.Change)
    (ran : (execute (Diff.enter (E := Diff.Effects) a b path) state).1 = .ok (change, false)) : a = b := by
  have active (ran : (execute (do
      let answer ← Diff.sameValue (E := Diff.Effects) a.value b.value
      if answer then pure (none, true) else
        match bytesOfNibbles path with
        | none => throw Walk.Error.oddDepthValue
        | some key => pure (some (Diff.Change.mk key a.value b.value), true)
      : OperationOver Diff.Effects Walk.Error (Option Diff.Change × Bool)) state).1 =
        .ok (change, false)) : False := by
    obtain ⟨_, _, _, rest⟩ := TrieServePrivacyProofs.bind_ok _ _ state _ ran
    split at rest
    · cases rest
    · split at rest <;> cases rest
  unfold Diff.enter at ran
  split at ran
  · cases a <;> cases b <;> simp_all [Cursor.node]
  · rename_i x y left right
    by_cases same : x = y
    · cases a <;> cases b <;> simp_all [Cursor.node]
    · have unequal : (x != y) = true := by simp [same]
      simp only [unequal, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at ran
      exact False.elim (active ran)
  · exact False.elim (active ran)

theorem enter_terminal_change (world : World) (state : State) (pair : Cursor × Cursor) (path : Path)
    (faithful : Faithful world state) (leftReady : Ready world.snapshot world.images pair.1)
    (rightReady : Ready world.snapshot world.images pair.2)
    (different : Different world.snapshot pair []) (change : Option Diff.Change) (worth : Bool)
    (ran : (execute (Diff.enter (E := Diff.Effects) pair.1 pair.2 path) state).1 = .ok (change, worth)) :
    ∃ emitted, change = some emitted ∧ bytesOfNibbles path = some emitted.key := by
  have ran := (congrArg Prod.fst (read_execute_same (handler := handler)
    _ (enter_readonly pair.1 pair.2 path) state)).symm.trans ran
  obtain ⟨a, left, aImages⟩ := ready_value leftReady
  obtain ⟨b, right, bImages⟩ := ready_value rightReady
  have unequal : a ≠ b := by
    intro same
    obtain ⟨bytes, different⟩ := different
    apply different
    rw [optional_meaning left, optional_meaning right, same]
  have distinct : Distinguishes state.hash a b := by
    intro x y hx hy hashes
    rw [faithful.2] at hashes
    exact world.collisionFree x (aImages x hx) y (bImages y hy) hashes
  have exactChange := enter_exact pair.1 pair.2 path world.snapshot state a b left right
    (by simpa only [faithful.2] using world.addressed) distinct change worth ran
  cases change with
  | none => exact False.elim (Bool.noConfusion (exactChange.1.mpr unequal))
  | some emitted => exact ⟨emitted, rfl, (exactChange.2 emitted rfl).1⟩

abbrev Action := OperationOver Diff.Effects Walk.Error

/-- Definitional names for the production callbacks, not a second walk. -/
def admitted (scope : Serve.Scope) (emit : A → Diff.Change → Action A) (acc : A) (change : Diff.Change) : Action A :=
  if scope.admitsKeyPath (keyNibbles change.key) then emit acc change else pure acc

def inspect (scope : Serve.Scope) (emit : A → Diff.Change → Action A)
    (acc : A) (pair : Cursor × Cursor) (path : Path) : Action (Step (Cursor × Cursor) × A) := do
  let (change, worth) ← Diff.enter pair.1 pair.2 path
  let acc ← match change with
    | some change => admitted scope emit acc change
    | none => pure acc
  return (if worth then .descend pair else .visited, acc)

def step (scope : Serve.Scope) (emit : A → Diff.Change → Action A)
    (acc : A) (pair : Cursor × Cursor) (nibble : UInt8) (below : Path) : Action (Step (Cursor × Cursor) × A) := do
  if !scope.admitsPath below then return (.skip, acc)
  if Diff.sameChild pair.1 pair.2 nibble then return (.skip, acc)
  let ca ← cursorChild pair.1 nibble
  let cb ← cursorChild pair.2 nibble
  if ca.isEmpty && cb.isEmpty then return (.skip, acc)
  inspect scope emit acc (ca, cb) below

omit handler [ReadsAgree handler] in
theorem diff_each_unfold (scope : Serve.Scope) (emit : A → Diff.Change → Action A)
    (oldRoot newRoot : ByteArray) (acc : A) :
    Diff.diffEach scope emit oldRoot newRoot acc = (do
      if oldRoot == newRoot then return acc
      let a ← cursorAt (rootOf oldRoot)
      let b ← cursorAt (rootOf newRoot)
      let (change, worth) ← Diff.enter a b []
      let acc ← match change with
        | some change => admitted scope emit acc change
        | none => pure acc
      if !worth then return acc
      walk Diff.nextChild (step scope emit) (a, b) [] acc) := rfl

def ReadStable (seen : State → A → Prop) : Prop :=
  ∀ {B} (effect : Diff.Effects B), readAllowed _ effect → ∀ state acc,
    seen state acc → seen (Interpreter.handle effect state).2 acc

def EmitContract (world : World) (key : ByteArray) (seen : State → A → Prop)
    (emit : A → Diff.Change → Action A) : Prop :=
  ∀ state acc change answer final, Faithful world state →
    execute (emit acc change) state = (.ok answer, final) →
    Faithful world final ∧ (seen state acc ∨ change.key = key → seen final answer)

theorem readonly_result (world : World) (seen : State → A → Prop) (stable : ReadStable seen)
    (program : Program Diff.Effects B) (safe : Only readAllowed program)
    (state final : State) (result : B) (acc : A) (faithful : Faithful world state)
    (ran : execute program state = (result, final)) :
    Faithful world final ∧ (seen state acc → seen final acc) := by
  have good := read_preserves program safe world state faithful
  have kept : seen state acc → seen (execute program state).2 acc :=
    fun holds => safe.invariant (fun state => seen state acc)
      (fun effect allowed state holds => stable effect allowed state acc holds) state holds
  rw [ran] at good kept
  exact ⟨good, kept⟩

omit [ReadsAgree handler] in
theorem admitted_result (world : World) (key : ByteArray) (seen : State → A → Prop)
    (emit : A → Diff.Change → Action A) (contract : EmitContract world key seen emit)
    (scope : Serve.Scope) (granted : scope.admitsKeyPath (keyNibbles key) = true)
    (state final : State) (acc answer : A) (change : Diff.Change) (faithful : Faithful world state)
    (ran : execute (admitted scope emit acc change) state = (.ok answer, final)) :
    Faithful world final ∧ (seen state acc ∨ change.key = key → seen final answer) := by
  unfold admitted at ran
  split at ran
  · exact contract state acc change answer final faithful ran
  · rename_i denied
    cases ran
    refine ⟨faithful, ?_⟩
    rintro (already | target)
    · exact already
    · exact False.elim (denied (by simpa [target] using granted))

theorem inspect_result (world : World) (key : ByteArray) (seen : State → A → Prop)
    (stable : ReadStable seen) (emit : A → Diff.Change → Action A)
    (contract : EmitContract world key seen emit) (scope : Serve.Scope)
    (granted : scope.admitsKeyPath (keyNibbles key) = true)
    (state final : State) (acc answer : A) (pair : Cursor × Cursor) (path : Path)
    (decision : Step (Cursor × Cursor)) (faithful : Faithful world state)
    (leftReady : Ready world.snapshot world.images pair.1)
    (rightReady : Ready world.snapshot world.images pair.2)
    (ran : execute (inspect scope emit acc pair path) state = (.ok (decision, answer), final)) :
    Faithful world final ∧ (seen state acc → seen final answer) ∧ decision ≠ .stop ∧
    (∀ child, decision = .descend child → child = pair) ∧
    (∀ tail, keyNibbles key = path ++ tail → Different world.snapshot pair tail →
      ¬seen final answer → decision = .descend pair ∧ tail ≠ []) := by
  unfold inspect at ran
  obtain ⟨⟨change, worth⟩, checked, checkRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  have checkedFacts := readonly_result world seen stable _ (enter_readonly pair.1 pair.2 path)
    state checked _ acc faithful checkRun
  have sequence : execute ((match change with
      | some change => admitted scope emit acc change | none => pure acc) >>=
      fun out => pure (if worth then .descend pair else .visited, out)
      : Action (Step (Cursor × Cursor) × A)) checked = (.ok (decision, answer), final) := by
    cases change <;> exact rest
  obtain ⟨out, applied, applyRun, finished⟩ := TransactionSuccess.bind_success _ _ _ _ _ sequence
  have appliedFacts : Faithful world applied ∧
      (seen checked acc ∨ (∃ c, change = some c ∧ c.key = key) → seen applied out) := by
    cases change with
    | none => cases applyRun; exact ⟨checkedFacts.1, by simp⟩
    | some change =>
      have facts := admitted_result world key seen emit contract scope granted checked applied acc out
        change checkedFacts.1 applyRun
      exact ⟨facts.1, fun h => facts.2 (by simpa using h)⟩
  have shape : decision = (if worth then .descend pair else .visited) ∧ answer = out ∧ final = applied := by
    cases worth <;> cases finished <;> exact ⟨rfl, rfl, rfl⟩
  obtain ⟨rfl, rfl, rfl⟩ := shape
  refine ⟨appliedFacts.1, fun h => appliedFacts.2 (.inl (checkedFacts.2 h)), ?_, ?_, ?_⟩
  · cases worth <;> intro impossible <;> cases impossible
  · intro child same; cases worth <;> cases same; rfl
  · intro tail atTarget different unseen
    have worthTrue : worth = true := by
      cases h : worth with
      | true => rfl
      | false =>
        have equal := enter_pruned_equal state pair.1 pair.2 path change (by simpa [h] using congrArg Prod.fst checkRun)
        obtain ⟨bytes, different⟩ := different
        exact False.elim (different (by simp [equal]))
    refine ⟨by simp [worthTrue], ?_⟩
    intro terminal
    subst tail
    obtain ⟨emitted, selected, packed⟩ := enter_terminal_change world state pair path faithful
      leftReady rightReady different change worth (congrArg Prod.fst checkRun)
    have sameKey : emitted.key = key := by
      simp only [List.append_nil] at atTarget
      rw [← atTarget, TrieWalkProofs.bytesOfNibbles_keyNibbles] at packed
      exact (Option.some.inj packed).symm
    exact unseen (appliedFacts.2 (.inr ⟨emitted, selected, sameKey⟩))

theorem step_result (world : World) (key : ByteArray) (seen : State → A → Prop)
    (stable : ReadStable seen) (emit : A → Diff.Change → Action A)
    (contract : EmitContract world key seen emit) (scope : Serve.Scope)
    (granted : scope.admitsKeyPath (keyNibbles key) = true)
    (state final : State) (acc answer : A) (pair : Cursor × Cursor) (nibble : UInt8) (path : Path)
    (decision : Step (Cursor × Cursor)) (faithful : Faithful world state)
    (leftReady : Ready world.snapshot world.images pair.1)
    (rightReady : Ready world.snapshot world.images pair.2)
    (ran : execute (step scope emit acc pair nibble path) state = (.ok (decision, answer), final)) :
    Faithful world final ∧ (seen state acc → seen final answer) ∧ decision ≠ .stop ∧
    (∀ child, decision = .descend child → Ready world.snapshot world.images child.1 ∧
      Ready world.snapshot world.images child.2) ∧
    (∀ tail, keyNibbles key = path ++ tail → Different world.snapshot pair (nibble :: tail) →
      ¬seen final answer → ∃ child, decision = .descend child ∧ tail ≠ [] ∧
        Different world.snapshot child tail) := by
  unfold step at ran
  split at ran
  · rename_i denied
    cases ran
    refine ⟨faithful, id, (by intro h; cases h), (by intro c h; cases h), ?_⟩
    intro tail atTarget _ _
    have admitted := TrieServeProofs.admitsPath_of_admitsKeyPath scope (keyNibbles key) granted
    rw [atTarget] at admitted
    have allowed := TrieServeProofs.admitsPath_of_append scope path tail admitted
    simp [allowed] at denied
  · split at ran
    · rename_i shared
      cases ran
      refine ⟨faithful, id, (by intro h; cases h), (by intro c h; cases h), ?_⟩
      intro tail _ different _
      obtain ⟨bytes, different⟩ := different
      exact False.elim (different (same_child_exact world.snapshot pair.1 pair.2 nibble shared tail bytes))
    · obtain ⟨ca, loadedA, readA, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
      have factsA := readonly_result world seen stable _ (child_readonly pair.1 nibble)
        state loadedA _ acc faithful readA
      have readyA := child_ready world state pair.1 ca nibble faithful leftReady (congrArg Prod.fst readA)
      have meaningA := cursor_child_exact state world.snapshot pair.1 ca nibble faithful.1
        (congrArg Prod.fst ((read_execute_same _ (child_readonly pair.1 nibble) state).symm.trans readA))
      obtain ⟨cb, loadedB, readB, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
      have factsB := readonly_result world seen stable _ (child_readonly pair.2 nibble)
        loadedA loadedB _ acc factsA.1 readB
      have readyB := child_ready world loadedA pair.2 cb nibble factsA.1 rightReady (congrArg Prod.fst readB)
      have meaningB := cursor_child_exact loadedA world.snapshot pair.2 cb nibble factsA.1.1
        (congrArg Prod.fst ((read_execute_same _ (child_readonly pair.2 nibble) loadedA).symm.trans readB))
      have differentChild : ∀ tail, Different world.snapshot pair (nibble :: tail) →
          Different world.snapshot (ca, cb) tail := by
        rintro tail ⟨bytes, different⟩
        exact ⟨bytes, fun equal => different ((meaningA tail bytes).symm.trans (equal.trans (meaningB tail bytes)))⟩
      split at rest
      · rename_i empty
        have empties : ca = .empty ∧ cb = .empty := by
          cases ca <;> cases cb <;> simp_all [Cursor.isEmpty]
        cases rest
        refine ⟨factsB.1, fun h => factsB.2 (factsA.2 h), (by intro h; cases h),
          (by intro c h; cases h), ?_⟩
        intro tail _ different _
        obtain ⟨bytes, different⟩ := differentChild tail different
        exact False.elim (different (by simp [empties.1, empties.2]))
      · have facts := inspect_result world key seen stable emit contract scope granted loadedB final acc answer
          (ca, cb) path decision factsB.1 readyA readyB rest
        refine ⟨facts.1, fun h => facts.2.1 (factsB.2 (factsA.2 h)), facts.2.2.1, ?_, ?_⟩
        · intro child selected
          have same := facts.2.2.2.1 child selected
          subst child
          exact ⟨readyA, readyB⟩
        · intro tail atTarget different unseen
          have diff := differentChild tail different
          obtain ⟨descended, nonempty⟩ := facts.2.2.2.2 tail atTarget diff unseen
          exact ⟨(ca, cb), descended, nonempty, diff⟩

def Pending (world : World) (key : ByteArray) (stack : List (Frame (Cursor × Cursor))) : Prop :=
  ∃ frame ∈ stack, ∃ nibble tail,
    keyNibbles key = frame.2.2 ++ (nibble :: tail) ∧
    frame.2.1.toNat ≤ nibble.toNat ∧ Different world.snapshot frame.1 (nibble :: tail)

def StackReady (world : World) (stack : List (Frame (Cursor × Cursor))) : Prop :=
  ∀ frame ∈ stack, Ready world.snapshot world.images frame.1.1 ∧
    Ready world.snapshot world.images frame.1.2

omit handler [ReadsAgree handler] in
private theorem pending_cons (pending : Pending world key stack) (frame : Frame (Cursor × Cursor)) :
    Pending world key (frame :: stack) := by
  obtain ⟨queued, member, rest⟩ := pending
  exact ⟨queued, List.mem_cons_of_mem frame member, rest⟩

omit handler [ReadsAgree handler] in
private theorem pending_candidate (world : World) (key : ByteArray) (bound : key.size ≤ maxKeyBytes)
    (pair : Cursor × Cursor) (start nibble : UInt8) (path tail : Path)
    (same : keyNibbles key = path ++ (nibble :: tail)) (lower : start.toNat ≤ nibble.toNat)
    (different : Different world.snapshot pair (nibble :: tail)) :
    ∃ found, (if start.toNat ≥ 16 || path.length ≥ maxDepthNibbles then none
      else (Diff.nextChild pair start).filter (·.toNat < 16)) = some found ∧ found.toNat ≤ nibble.toNat := by
  have member : nibble ∈ keyNibbles key := by simp [same]
  have bounded : nibble.toNat < 16 := by
    have := TrieMutateProofs.nibbles_keyNibbles key nibble member
    omega
  have length : (keyNibbles key).length ≤ maxDepthNibbles := by
    rw [key_nibbles_length]
    exact Nat.mul_le_mul_right 2 bound
  have depth : path.length < maxDepthNibbles := by
    simp only [same, List.length_append, List.length_cons] at length
    omega
  obtain ⟨bytes, entry⟩ := different_has_entry different
  obtain ⟨found, upper, selected⟩ := next_before_either pair.1 pair.2 world.snapshot nibble tail bytes
    start entry lower bounded
  refine ⟨found, ?_, upper⟩
  have low : ¬start.toNat ≥ 16 := by omega
  have high : found.toNat < 16 := by omega
  simp [low, Nat.not_le_of_lt depth, selected, high]

def nextStack (decision : Step (Cursor × Cursor)) (pair : Cursor × Cursor) (chosen : UInt8)
    (path : Path) (stack : List (Frame (Cursor × Cursor))) : List (Frame (Cursor × Cursor)) :=
  match decision with
  | .descend child => (child, 0, path ++ [chosen]) :: (pair, chosen + 1, path) :: stack
  | .visited | .skip => (pair, chosen + 1, path) :: stack
  | .stop => []

omit handler [ReadsAgree handler] in
private theorem queue_after (world : World) (key : ByteArray) (bound : key.size ≤ maxKeyBytes)
    (pair : Cursor × Cursor) (start chosen : UInt8) (path : Path) (stack : List (Frame (Cursor × Cursor)))
    (decision : Step (Cursor × Cursor)) (noStop : decision ≠ .stop)
    (pending : Pending world key ((pair, start, path) :: stack))
    (selected : (if start.toNat ≥ 16 || path.length ≥ maxDepthNibbles then none
      else (Diff.nextChild pair start).filter (·.toNat < 16)) = some chosen)
    (target : ∀ tail, keyNibbles key = (path ++ [chosen]) ++ tail →
      Different world.snapshot pair (chosen :: tail) →
      ∃ child, decision = .descend child ∧ tail ≠ [] ∧ Different world.snapshot child tail) :
    Pending world key (nextStack decision pair chosen path stack) := by
  have retain (pending : Pending world key ((pair, chosen + 1, path) :: stack)) :
      Pending world key (nextStack decision pair chosen path stack) := by
    cases decision with
    | descend child => exact pending_cons pending _
    | visited | skip => exact pending
    | stop => exact False.elim (noStop rfl)
  obtain ⟨queued, member, nibble, tail, same, lower, different⟩ := pending
  rcases List.mem_cons.mp member with head | later
  · subst queued
    obtain ⟨found, selectedFound, upper⟩ := pending_candidate world key bound pair start nibble path tail
      same lower different
    have equal : found = chosen := Option.some.inj (selectedFound.symm.trans selected)
    subst found
    by_cases hit : chosen = nibble
    · subst chosen
      obtain ⟨child, rfl, nonempty, meaning⟩ := target tail
        (by simpa only [List.append_assoc, List.singleton_append] using same) different
      cases tail with
      | nil => exact False.elim (nonempty rfl)
      | cons next rest =>
        refine ⟨(child, 0, path ++ [nibble]), List.mem_cons_self .., next, rest, ?_, Nat.zero_le _, meaning⟩
        simpa only [List.append_assoc, List.singleton_append] using same
    · have earlier : chosen.toNat < nibble.toNat := by
        have unequal : chosen.toNat ≠ nibble.toNat := fun equal => hit (UInt8.toNat_inj.mp equal)
        omega
      have bounded : nibble.toNat < 16 := by
        have := TrieMutateProofs.nibbles_keyNibbles key nibble (by simp [same])
        omega
      apply retain
      refine ⟨(pair, chosen + 1, path), List.mem_cons_self .., nibble, tail, same, ?_, different⟩
      simp only [UInt8.toNat_add, UInt8.toNat_ofNat]
      omega
  · exact retain (pending_cons ⟨queued, later, nibble, tail, same, lower, different⟩ _)

def Invariant (world : World) (key : ByteArray) (seen : State → A → Prop)
    (state : State) (d : Descent (Cursor × Cursor) A) : Prop :=
  Faithful world state ∧ StackReady world d.stack ∧ (¬seen state d.acc → Pending world key d.stack)

theorem descend_invariant (world : World) (key : ByteArray) (bound : key.size ≤ maxKeyBytes)
    (seen : State → A → Prop) (stable : ReadStable seen) (emit : A → Diff.Change → Action A)
    (contract : EmitContract world key seen emit) (scope : Serve.Scope)
    (granted : scope.admitsKeyPath (keyNibbles key) = true)
    (state : State) (d : Descent (Cursor × Cursor) A) (holds : Invariant world key seen state d) :
    (∀ next final, execute (descend Diff.nextChild (step scope emit) d) state = (.ok (.inl next), final) →
      Invariant world key seen final next) ∧
    (∀ answer final, execute (descend Diff.nextChild (step scope emit) d) state = (.ok (.inr answer), final) →
      seen final answer) := by
  obtain ⟨faithful, ready, pending⟩ := holds
  match d with
  | ⟨[], positions, acc⟩ =>
    constructor
    · intro next final ran; cases ran
    · intro answer final ran; cases ran
      apply Classical.byContradiction
      intro unseen
      obtain ⟨frame, member, _⟩ := pending unseen
      cases member
  | ⟨(pair, start, path) :: stack, positions, acc⟩ =>
    have pairReady := ready (pair, start, path) (List.mem_cons_self ..)
    simp only [Walk.descend]
    split
    · rename_i absent
      constructor
      · intro next final ran; cases ran
        refine ⟨faithful, fun f member => ready f (List.mem_cons_of_mem _ member), ?_⟩
        intro unseen
        obtain ⟨queued, member, nibble, tail, same, lower, different⟩ := pending unseen
        rcases List.mem_cons.mp member with head | later
        · subst queued
          obtain ⟨found, selected, _⟩ := pending_candidate world key bound pair start nibble path tail
            same lower different
          simp only [absent] at selected
          cases selected
        · exact ⟨queued, later, nibble, tail, same, lower, different⟩
      · intro answer final ran; cases ran
    · rename_i chosen selected
      have result : ∀ decision answer final,
          execute (step scope emit acc pair chosen (path ++ [chosen])) state = (.ok (decision, answer), final) →
          Invariant world key seen final ⟨nextStack decision pair chosen path stack, positions, answer⟩ ∧
          decision ≠ .stop := by
        intro decision answer final ran
        have facts := step_result world key seen stable emit contract scope granted state final acc answer
          pair chosen (path ++ [chosen]) decision faithful pairReady.1 pairReady.2 ran
        refine ⟨⟨facts.1, ?_, ?_⟩, facts.2.2.1⟩
        · intro frame member
          cases decision with
          | descend child =>
            rcases List.mem_cons.mp member with childFrame | parentFrame
            · subst frame; exact facts.2.2.2.1 child rfl
            · rcases List.mem_cons.mp parentFrame with same | rest
              · subst frame; exact pairReady
              · exact ready frame (List.mem_cons_of_mem _ rest)
          | visited | skip =>
            rcases List.mem_cons.mp member with same | rest
            · subst frame; exact pairReady
            · exact ready frame (List.mem_cons_of_mem _ rest)
          | stop => exact False.elim (facts.2.2.1 rfl)
        · intro unseen
          have unseenBefore : ¬seen state acc := fun h => unseen (facts.2.1 h)
          exact queue_after world key bound pair start chosen path stack decision facts.2.2.1
            (pending unseenBefore) selected (fun tail atTarget diff => facts.2.2.2.2 tail atTarget diff unseen)
      constructor
      · intro next final ran
        obtain ⟨⟨decision, answer⟩, middle, stepRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
        obtain ⟨holds, noStop⟩ := result decision answer middle stepRun
        cases decision with
        | descend child =>
          dsimp only at rest
          split at rest
          · cases rest
          · cases rest; exact holds
        | visited =>
          dsimp only at rest
          split at rest
          · cases rest
          · cases rest; exact holds
        | skip => cases rest; exact holds
        | stop => exact False.elim (noStop rfl)
      · intro answer final ran
        obtain ⟨⟨decision, out⟩, middle, stepRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
        have noStop := (result decision out middle stepRun).2
        cases decision with
        | descend child | visited => dsimp only at rest; split at rest <;> cases rest
        | skip => cases rest
        | stop => exact False.elim (noStop rfl)

omit handler [ReadsAgree handler] in
theorem iterate_invariant [Interpreter E] (body : S → Program E (Except ε (S ⊕ R))) (exhausted : ε)
    (P : State → S → Prop) (Q : State → R → Prop)
    (kept : ∀ state start next final, P state start → execute (body start) state = (.ok (.inl next), final) → P final next)
    (stopped : ∀ state start answer final, P state start → execute (body start) state = (.ok (.inr answer), final) → Q final answer)
    (fuel : Nat) : ∀ (program : Program E (Except ε (S ⊕ R))) state,
    (∀ next final, execute program state = (.ok (.inl next), final) → P final next) →
    (∀ answer final, execute program state = (.ok (.inr answer), final) → Q final answer) →
    ∀ answer final, execute (Program.iterate body exhausted fuel program) state = (.ok answer, final) → Q final answer := by
  induction fuel with
  | zero => intro program state _ _ answer final ran; cases ran
  | succ fuel ih =>
    intro program state keeps stops answer final ran
    match program with
    | .pure (.error error) => cases ran
    | .pure (.ok (.inr result)) => cases ran; exact stops _ state rfl
    | .pure (.ok (.inl next)) =>
      exact ih (body next) state (fun next' final => kept state next next' final (keeps next state rfl))
        (fun result final => stopped state next result final (keeps next state rfl)) answer final ran
    | .request effect resume =>
      rw [execute_iterate_request] at ran
      cases effectState : Interpreter.handle effect state with
      | mk reply after =>
        simp only [execute, effectState] at keeps stops
        simp only [effectState] at ran
        exact ih (resume reply) after keeps stops answer final ran

/-- Any successful production walk accounts for a pending semantic
difference. Host failures and budget exhaustion are not successful exits. -/
theorem loop_covers (fuel : Nat) (world : World) (key : ByteArray) (bound : key.size ≤ maxKeyBytes)
    (seen : State → A → Prop) (stable : ReadStable seen) (emit : A → Diff.Change → Action A)
    (contract : EmitContract world key seen emit) (scope : Serve.Scope)
    (granted : scope.admitsKeyPath (keyNibbles key) = true)
    (state final : State) (pair : Cursor × Cursor) (path : Path) (acc answer : A)
    (holds : Invariant world key seen state ⟨[(pair, 0, path)], 0, acc⟩)
    (ran : execute (OperationOver.iterate (Walk.descend Diff.nextChild (step scope emit))
      Walk.Error.ceiling fuel ⟨[(pair, 0, path)], 0, acc⟩) state = (.ok answer, final)) :
    seen final answer := by
  let P := Invariant world key seen
  have round := fun state d (holds : P state d) =>
    descend_invariant world key bound seen stable emit contract scope granted state d holds
  have kept := fun state d next final holds ran => (round state d holds).1 next final ran
  have stopped := fun state d answer final holds ran => (round state d holds).2 answer final ran
  unfold OperationOver.iterate at ran
  exact iterate_invariant _ Walk.Error.ceiling P seen kept stopped fuel _ state
    (kept state _ · · holds) (stopped state _ · · holds) answer final ran

theorem walk_covers (world : World) (key : ByteArray) (bound : key.size ≤ maxKeyBytes)
    (seen : State → A → Prop) (stable : ReadStable seen) (emit : A → Diff.Change → Action A)
    (contract : EmitContract world key seen emit) (scope : Serve.Scope)
    (granted : scope.admitsKeyPath (keyNibbles key) = true)
    (state final : State) (pair : Cursor × Cursor) (path : Path) (acc answer : A)
    (holds : Invariant world key seen state ⟨[(pair, 0, path)], 0, acc⟩)
    (ran : execute (walk Diff.nextChild (step scope emit) pair path acc) state = (.ok answer, final)) :
    seen final answer :=
  loop_covers walkFuel world key bound seen stable emit contract scope granted state final pair path acc answer holds ran

omit [ReadsAgree handler] in
theorem inspect_run (scope : Serve.Scope) (emit : A → Diff.Change → Action A)
    (pair : Cursor × Cursor) (path : Path) (state checked applied : State) (acc out : A)
    (change : Option Diff.Change) (worth : Bool)
    (checkRun : execute (Diff.enter (E := Diff.Effects) pair.1 pair.2 path) state = (.ok (change, worth), checked))
    (applyRun : execute (match change with
      | none => pure acc | some c => admitted scope emit acc c : Action A) checked = (.ok out, applied)) :
    execute (inspect scope emit acc pair path) state =
      (.ok (if worth then .descend pair else .visited, out), applied) := by
  simp only [inspect, bind, ExceptT.bind, ExceptT.mk, execute_bind, checkRun, ExceptT.bindCont]
  cases change <;>
    simp only [execute_bind, ExceptT.bindCont, applyRun]
  all_goals rfl

/-- The actual entire diff, from its two root reads to its successful
return, delivers every permitted semantic difference to its callback. The
callback's local contract is separate from (and does not assume) coverage. -/
theorem diff_each_covers (world : World) (key : ByteArray) (bound : key.size ≤ maxKeyBytes)
    (seen : State → A → Prop) (stable : ReadStable seen) (emit : A → Diff.Change → Action A)
    (contract : EmitContract world key seen emit) (scope : Serve.Scope)
    (granted : scope.admitsKeyPath (keyNibbles key) = true)
    (oldRoot newRoot : ByteArray) (state final : State) (acc answer : A)
    (faithful : Faithful world state)
    (different : ∃ bytes, ¬(ReferenceEntry world.snapshot (rootOf oldRoot) (keyNibbles key) bytes ↔
      ReferenceEntry world.snapshot (rootOf newRoot) (keyNibbles key) bytes))
    (ran : execute (Diff.diffEach scope emit oldRoot newRoot acc) state = (.ok answer, final)) :
    seen final answer := by
  rw [diff_each_unfold] at ran
  split at ran
  · rename_i equal
    have same : oldRoot = newRoot := eq_of_beq equal
    obtain ⟨bytes, different⟩ := different
    exact False.elim (different (by simp [same]))
  · obtain ⟨a, loadedA, readA, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
    have factsA := readonly_result world seen stable _ (cursor_readonly (rootOf oldRoot))
      state loadedA _ acc faithful readA
    have readyA := cursor_ready world state _ a faithful (congrArg Prod.fst readA)
    have meaningA := cursor_at_exact state world.snapshot (rootOf oldRoot) a faithful.1
      (congrArg Prod.fst ((read_execute_same _ (cursor_readonly (rootOf oldRoot)) state).symm.trans readA))
    obtain ⟨b, loadedB, readB, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
    have factsB := readonly_result world seen stable _ (cursor_readonly (rootOf newRoot))
      loadedA loadedB _ acc factsA.1 readB
    have readyB := cursor_ready world loadedA _ b factsA.1 (congrArg Prod.fst readB)
    have meaningB := cursor_at_exact loadedA world.snapshot (rootOf newRoot) b factsA.1.1
      (congrArg Prod.fst ((read_execute_same _ (cursor_readonly (rootOf newRoot)) loadedA).symm.trans readB))
    have diff : Different world.snapshot (a, b) (keyNibbles key) := by
      obtain ⟨bytes, different⟩ := different
      exact ⟨bytes, fun equal => different ((meaningA _ _).symm.trans (equal.trans (meaningB _ _)))⟩
    obtain ⟨⟨change, worth⟩, checked, checkRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
    have sequence : execute ((match change with
        | some c => admitted scope emit acc c | none => pure acc) >>= fun out =>
        if !worth then pure out else walk Diff.nextChild (step scope emit) (a, b) [] out
        : Action A) checked = (.ok answer, final) := by
      cases change <;> exact rest
    obtain ⟨out, applied, applyRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ sequence
    have inspected := inspect_run scope emit (a, b) [] loadedB checked applied acc out change worth checkRun
      (by cases change <;> exact applyRun)
    have facts := inspect_result world key seen stable emit contract scope granted loadedB applied acc out
      (a, b) [] _ factsB.1 readyA readyB inspected
    cases h : worth with
    | false =>
      have same := enter_pruned_equal loadedB a b [] change (by simpa [h] using congrArg Prod.fst checkRun)
      obtain ⟨bytes, different⟩ := diff
      exact False.elim (different (by simp [same]))
    | true =>
      simp only [h, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at rest
      apply walk_covers world key bound seen stable emit contract scope granted applied final (a, b) [] out answer _ rest
      refine ⟨facts.1, ?_, ?_⟩
      · intro frame member
        have same := List.mem_singleton.mp member
        subst frame
        exact ⟨readyA, readyB⟩
      · intro unseen
        have nonempty := (facts.2.2.2.2 (keyNibbles key) rfl diff unseen).2
        cases keyPath : keyNibbles key with
        | nil => exact False.elim (nonempty keyPath)
        | cons nibble tail =>
          refine ⟨((a, b), 0, []), List.mem_singleton_self _, nibble, tail, keyPath, Nat.zero_le _, ?_⟩
          simpa only [keyPath] using diff

omit handler [ReadsAgree handler] in
theorem reference_meaning (snapshot : RawSnapshot) (root key bytes : ByteArray)
    (bound : key.size ≤ maxKeyBytes) :
    ReferenceEntry snapshot (rootOf root) (keyNibbles key) bytes ↔ Entry snapshot root key bytes := by
  unfold rootOf
  split <;> simp_all [ReferenceEntry, TrieSnapshotProofs.Entry]

/-- No changed key can be missing from the list returned by the actual
production diff. This instantiates the callback contract with real cons. -/
theorem diff_lists_changed_key (world : World) (oldRoot newRoot key : ByteArray)
    (bound : key.size ≤ maxKeyBytes) (state final : State) (changes : List Diff.Change)
    (faithful : Faithful world state)
    (different : ∃ bytes, ¬(Entry world.snapshot oldRoot key bytes ↔ Entry world.snapshot newRoot key bytes))
    (ran : execute (Diff.diff (E := Diff.Effects) oldRoot newRoot) state = (.ok changes, final)) :
    ∃ change ∈ changes, change.key = key := by
  unfold Diff.diff at ran
  obtain ⟨output, finished, walked, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ ran
  cases returned
  let seen := fun (_ : State) (changes : List Diff.Change) => ∃ c ∈ changes, c.key = key
  have stable : ReadStable seen := fun _ _ _ _ h => h
  have emits : EmitContract world key seen (fun acc c => pure (c :: acc)) := by
    intro state acc c answer final faithful ran
    cases ran
    refine ⟨faithful, ?_⟩
    rintro (⟨prior, member, target⟩ | target)
    · exact ⟨prior, List.mem_cons_of_mem _ member, target⟩
    · exact ⟨c, List.mem_cons_self .., target⟩
  have difference : ∃ bytes, ¬(ReferenceEntry world.snapshot (rootOf oldRoot) (keyNibbles key) bytes ↔
      ReferenceEntry world.snapshot (rootOf newRoot) (keyNibbles key) bytes) := by
    simpa only [reference_meaning world.snapshot oldRoot key _ bound,
      reference_meaning world.snapshot newRoot key _ bound] using different
  have covered := diff_each_covers world key bound seen stable (fun acc c => pure (c :: acc)) emits
    ⟨none, []⟩ (by rfl) oldRoot newRoot state final [] output faithful difference walked
  obtain ⟨change, member, target⟩ := covered
  exact ⟨change, List.mem_reverse.mpr member, target⟩

def AppliedKey (key : ByteArray) (state : State) (_ : UInt64) : Prop :=
  ∃ event ∈ state.applied, event.1 = key

theorem applied_stable (key : ByteArray) : ReadStable (AppliedKey key) := by
  intro B effect allowed state acc seen
  have same := congrArg (fun observation => observation.2.2) (read_effect_preserves effect allowed state)
  change (Interpreter.handle effect state).2.applied = state.applied at same
  simpa only [AppliedKey, same] using seen

def materializeEmit (count : UInt64) (change : Diff.Change) : Action UInt64 := do
  let new ← match change.new with
    | none => pure none
    | some value => some <$> resolve value
  Diff.apply (.applyChange change.key change.kind new)
  return count + 1

omit handler [ReadsAgree handler] in
theorem resolve_readonly (value : Value) : Only readAllowed (resolve (E := Diff.Effects) value).run := by
  unfold resolve
  repeat' first
    | exact .done _
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | split

end Interpreted

theorem apply_delivers (world : World) (key : ByteArray) (state final : State)
    (changed : ByteArray) (kind : UInt64) (value : Option ByteArray)
    (faithful : Faithful world state)
    (ran : execute (Diff.apply (E := Diff.Effects) (.applyChange changed kind value)) state = (.ok (), final)) :
    Faithful world final ∧ (AppliedKey key state count ∨ changed = key → AppliedKey key final count') := by
  simp only [Diff.apply, raise, performOver, Inject.inject, ExceptT.mk, execute,
    Interpreter.handle, SimulatedHost.apply, reply] at ran
  cases failed : fault state with
  | some failure => simp [failed, Except.mapError] at ran
  | none =>
    simp only [failed, Except.mapError, Prod.mk.injEq, true_and] at ran
    rw [← ran]
    refine ⟨faithful, ?_⟩
    rintro (⟨event, member, target⟩ | target)
    · exact ⟨event, List.mem_append_left _ member, target⟩
    · exact ⟨(changed, kind, value), List.mem_append_right _ (List.mem_singleton_self _), target⟩

theorem materialize_emit_contract (world : World) (key : ByteArray) :
    EmitContract world key (AppliedKey key) materializeEmit := by
  intro state count change answer final faithful ran
  unfold materializeEmit at ran
  have sequence : execute ((match change.new with
      | none => pure none | some value => some <$> resolve value) >>= fun new => do
        Diff.apply (.applyChange change.key change.kind new)
        pure (count + 1) : Action UInt64) state = (.ok answer, final) := by
    cases h : change.new <;> simpa only [h] using ran
  obtain ⟨new, resolved, resolveRun, rest⟩ := TransactionSuccess.bind_success _ _ _ _ _ sequence
  have safe : Only readAllowed ((match change.new with
      | none => pure none | some value => some <$> resolve value) : Action (Option ByteArray)).run := by
    cases change.new with
    | none => exact .done _
    | some value => exact Only.map _ _ (resolve_readonly value)
  have resolvedFacts := readonly_result world (AppliedKey key) (applied_stable key) _ safe
    state resolved _ count faithful resolveRun
  obtain ⟨result, applied, applyRun, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ rest
  cases result
  cases returned
  have facts := apply_delivers (count := count) (count' := count + 1)
    world key resolved final change.key change.kind new resolvedFacts.1 applyRun
  refine ⟨facts.1, ?_⟩
  rintro (already | target)
  · exact facts.2 (.inl (resolvedFacts.2 already))
  · exact facts.2 (.inr target)

/-- Every permitted changed key reaches the actual streamed Apply effect
before materialization reports success. Missing local metadata and arbitrary
host failures are allowed, but cannot produce an incomplete successful stream.
This is stream coverage, not yet correctness of the consuming SQL projection. -/
theorem materialize_delivers_changed_key (world : World) (scope : Serve.Scope)
    (oldRoot newRoot key : ByteArray) (bound : key.size ≤ maxKeyBytes)
    (granted : scope.admitsKeyPath (keyNibbles key) = true)
    (state final : State) (count : UInt64) (faithful : Faithful world state)
    (freshLog : state.applied = [])
    (different : ∃ bytes, ¬(Entry world.snapshot oldRoot key bytes ↔ Entry world.snapshot newRoot key bytes))
    (ran : execute (Diff.materialize (E := Diff.Effects) scope oldRoot newRoot) state = (.ok count, final)) :
    ∃ event ∈ final.applied.drop state.applied.length, event.1 = key := by
  have difference : ∃ bytes, ¬(ReferenceEntry world.snapshot (rootOf oldRoot) (keyNibbles key) bytes ↔
      ReferenceEntry world.snapshot (rootOf newRoot) (keyNibbles key) bytes) := by
    simpa only [reference_meaning world.snapshot oldRoot key _ bound,
      reference_meaning world.snapshot newRoot key _ bound] using different
  have covered := diff_each_covers world key bound (AppliedKey key) (applied_stable key) materializeEmit
    (materialize_emit_contract world key) scope granted oldRoot newRoot state final 0 count faithful difference ran
  simpa only [freshLog, List.length_nil, List.drop_zero, AppliedKey] using covered

end Synchronicity.TrieDiffCoverage
