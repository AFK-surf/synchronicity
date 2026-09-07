import Synchronicity.CasFixtures
import Synchronicity.TrieVerifyProofs
import VerifiedCore.Trie.Serve

/-! Serving a trie to a peer, as executed: the scope predicates a scoped view
is cut along, that a descent answers only a hash the stored graph really
places at the position asked about, how an unscoped peer and an unvouched
root are answered before any position is looked at, the bound one answer
keeps, and the served, missing and redacted lists on a concrete trie with a
failure injected at every effect. -/
namespace Synchronicity.TrieServeProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Trie.Serve SimulatedHost CasFixtures
open Synchronicity.TrieVerifyProofs (byteArray_beq_self)

/-! ## Scope

Scope is a statement about where a node sits. The spine property is what lets
a scoped peer recompute the signed root: every ancestor of an admitted
position is admitted. The stop-at-the-boundary property is what lets a check
stop once inside a grant: nothing below leaves it. And inside a grant no node
is ever redacted, whatever it spells. -/

/-- An unscoped view admits every position. -/
theorem admitsPath_full (scope : Scope) (full : scope.prefixes = none) (path : Path) :
    scope.admitsPath path = true := by
  simp [Scope.admitsPath, full]

/-- The spine: a position above an admitted one is admitted. -/
theorem admitsPath_of_append (scope : Scope) (path rest : Path)
    (below : scope.admitsPath (path ++ rest) = true) : scope.admitsPath path = true := by
  unfold Scope.admitsPath at below ⊢
  cases granted : scope.prefixes with
  | none => rfl
  | some prefixes =>
    rw [granted] at below
    simp only [Bool.or_eq_true, List.any_eq_true] at below ⊢
    rcases below with ⟨g, mem, h⟩ | ⟨k, mem, h⟩
    · refine .inl ⟨g, mem, ?_⟩
      simp only [List.isPrefixOf_iff_prefix] at h ⊢
      rcases h with h | h
      · exact .inl ((List.prefix_append path rest).trans h)
      · rcases List.prefix_or_prefix_of_prefix h (List.prefix_append path rest) with h' | h'
        · exact .inr h'
        · exact .inl h'
    · refine .inr ⟨k, mem, ?_⟩
      rw [List.isPrefixOf_iff_prefix] at h ⊢
      exact (List.prefix_append path rest).trans h

/-- The boundary: below a position inside a grant, everything is inside it. -/
theorem containsSubtree_append (scope : Scope) (path rest : Path)
    (inside : scope.containsSubtree path = true) : scope.containsSubtree (path ++ rest) = true := by
  unfold Scope.containsSubtree at inside ⊢
  cases granted : scope.prefixes with
  | none => rfl
  | some prefixes =>
    rw [granted] at inside
    simp only [List.any_eq_true, List.isPrefixOf_iff_prefix] at inside ⊢
    obtain ⟨g, mem, h⟩ := inside
    exact ⟨g, mem, h.trans (List.prefix_append path rest)⟩

theorem admitsPath_of_containsSubtree (scope : Scope) (path : Path)
    (inside : scope.containsSubtree path = true) : scope.admitsPath path = true := by
  unfold Scope.containsSubtree at inside
  unfold Scope.admitsPath
  cases granted : scope.prefixes with
  | none => rfl
  | some prefixes =>
    rw [granted] at inside
    simp only [List.any_eq_true, Bool.or_eq_true] at inside ⊢
    obtain ⟨g, mem, h⟩ := inside
    exact .inl ⟨g, mem, .inr h⟩

/-- Granting a value also grants the route needed to authenticate its position. -/
theorem admitsPath_of_admitsKeyPath (scope : Scope) (path : Path)
    (allowed : scope.admitsKeyPath path = true) : scope.admitsPath path = true := by
  simp only [Scope.admitsKeyPath, Bool.or_eq_true, List.any_eq_true] at allowed
  rcases allowed with inside | ⟨key, member, same⟩
  · exact admitsPath_of_containsSubtree scope path inside
  · have same' : key.toList = path := by simpa using same
    subst path
    unfold Scope.admitsPath
    cases scope.prefixes with
    | none => rfl
    | some prefixes =>
      simp only [Bool.or_eq_true]
      exact .inr (List.any_eq_true.mpr ⟨key, member, by simp⟩)

/-- Inside a grant no node is redacted: whatever a node spells below a
position the grant contains, it spells inside the grant. -/
theorem no_redaction_inside_grant (scope : Scope) (path : Path) (node : Node)
    (inside : scope.containsSubtree path = true) : scope.admitsNode path node = true := by
  cases node with
  | route _ _ => exact admitsPath_of_containsSubtree scope path inside
  | branch children value =>
    cases value with
    | none => simp [Scope.admitsNode]
    | some v =>
      cases v with
      | hash _ => simp [Scope.admitsNode]
      | inline _ => simp [Scope.admitsNode, Scope.admitsKeyPath, inside]
  | extension segment child =>
    simp [Scope.admitsNode,
      admitsPath_of_containsSubtree _ _ (containsSubtree_append scope path _ inside)]
  | leaf suffix value =>
    simp [Scope.admitsNode, Scope.admitsKeyPath, containsSubtree_append scope path _ inside]

/-- A value goes out only from a node that could itself travel whole: the
two handlers draw one boundary. -/
theorem admitsNode_of_admitsValue (scope : Scope) (path : Path) (node : Node)
    (value : scope.admitsValue path node = true) : scope.admitsNode path node = true := by
  cases node with
  | route _ _ => exact admitsPath_of_admitsKeyPath scope path value
  | branch children v =>
    cases v with
    | none => simp [Scope.admitsNode]
    | some v =>
      cases v with
      | hash _ => simp [Scope.admitsNode]
      | inline _ =>
        simp only [Scope.admitsValue] at value
        simp [Scope.admitsNode, value]
  | extension _ _ => simp [Scope.admitsValue] at value
  | leaf _ _ =>
    simp only [Scope.admitsValue] at value
    simp [Scope.admitsNode, value]

/-- An exact key admits its spine and itself, never a position below it. -/
theorem exact_key_admits_itself (scope : Scope) (key : ByteArray) (granted : key ∈ scope.exact) :
    scope.admitsKeyPath key.toList = true := by
  simp only [Scope.admitsKeyPath, Bool.or_eq_true, List.any_eq_true]
  exact .inr ⟨key, granted, beq_self_eq_true _⟩

/-- A granted descendant remains authenticatable even when a shorter key is
private: its routing ancestor can travel, while that ancestor's payload cannot. -/
theorem granted_descendant_keeps_private_ancestor_private (scope : Scope) (path rest : Path)
    (children : List (Option ByteArray)) (payload : Option ByteArray)
    (granted : scope.admitsKeyPath (path ++ rest) = true)
    (privateKey : scope.admitsKeyPath path = false) :
    scope.admitsNode path (.route children payload) = true ∧
      scope.admitsValue path (.route children payload) = false := by
  exact ⟨admitsPath_of_append scope path rest
    (admitsPath_of_admitsKeyPath scope (path ++ rest) granted), privateKey⟩

/-! ## The descent

What a descent answers is a hash the stored graph really places at the
position: a claimed hash is never consulted, and a position holding nothing
answers nothing. The relation below has no fuel, trail or interpreter: an
extension's label concatenates, a branch contributes one nibble. -/

/-- The nodes a host state holds, by address. -/
def nodesOf (state : State) (hash : ByteArray) : Option ByteArray :=
  readableBytes state nodeSpace hash

/-- The stored graph places `found` at `path` below `hash`. -/
inductive Reaches (lookup : ByteArray → Option ByteArray) : ByteArray → Path → ByteArray → Prop where
  | here (hash : ByteArray) : Reaches lookup hash [] hash
  | extension (hash raw segment child found : ByteArray) (rest : Path)
      (held : lookup hash = some raw) (decoded : decode raw = .ok (.extension segment child))
      (nonempty : segment.toList ≠ [])
      (below : Reaches lookup child rest found) :
      Reaches lookup hash (segment.toList ++ rest) found
  | branch (hash raw child found : ByteArray) (children : List (Option ByteArray))
      (value : Option Value) (nibble : UInt8) (rest : Path)
      (held : lookup hash = some raw) (decoded : decode raw = .ok (.branch children value))
      (edge : children[nibble.toNat]? = some (some child))
      (below : Reaches lookup child rest found) :
      Reaches lookup hash (nibble :: rest) found
  | route (hash raw child found : ByteArray) (children : List (Option ByteArray))
      (value : Option ByteArray) (nibble : UInt8) (rest : Path)
      (held : lookup hash = some raw) (decoded : decode raw = .ok (.route children value))
      (edge : children[nibble.toNat]? = some (some child))
      (below : Reaches lookup child rest found) :
      Reaches lookup hash (nibble :: rest) found

theorem Reaches.trans {lookup : ByteArray → Option ByteArray} {hash middle found : ByteArray}
    {path rest : Path} (above : Reaches lookup hash path middle)
    (below : Reaches lookup middle rest found) : Reaches lookup hash (path ++ rest) found := by
  induction above with
  | here _ => simpa using below
  | extension hash raw segment child middle tail held decoded nonempty _ ih =>
    rw [List.append_assoc]
    exact .extension hash raw segment child found (tail ++ rest) held decoded nonempty (ih below)
  | branch hash raw child middle children value nibble tail held decoded edge _ ih =>
    exact .branch hash raw child found children value nibble (tail ++ rest) held decoded edge (ih below)
  | route hash raw child middle children value nibble tail held decoded edge _ ih =>
    exact .route hash raw child found children value nibble (tail ++ rest) held decoded edge (ih below)

@[simp] theorem nodesOf_record (state : State) (event : String) :
    nodesOf (record state event) = nodesOf state := rfl

/-- A thrown domain error is the program's answer, whatever the state. -/
@[simp] theorem throw_eq (e : Error) :
    (@MonadExceptOf.throw Error (ExceptT Error (Program Serve.Effects)) _ A e) =
      (Program.pure (Except.error e) : Program Serve.Effects (Except Error A)) := rfl

@[simp] theorem execute_throw (e : Error) (state : State) :
    execute (@MonadExceptOf.throw Error (ExceptT Error (Program Serve.Effects)) _ A e) state =
      (Except.error e, state) := rfl

@[simp] theorem faults_record (state : State) (event : String) :
    (record state event).faults = state.faults := rfl

theorem getD_none_eq_some {child : ByteArray} {slot : Option (Option ByteArray)}
    (h : slot.getD none = some child) : slot = some (some child) := by
  cases slot with
  | none => simp at h
  | some inner => cases inner <;> simp_all

theorem drop_of_isPrefixOf {segment rest : Path} (h : segment.isPrefixOf rest = true) :
    segment ++ rest.drop segment.length = rest := by
  rw [List.isPrefixOf_iff_prefix] at h
  obtain ⟨tail, rfl⟩ := h
  simp

/-- Whatever a descent answers, the stored graph places it at the position
descended to, below the node the descent started from. -/
theorem descend_sound (fuel : Nat) : ∀ (consumed : Nat) (current : Option ByteArray) (rest : Path)
    (trail : List (Nat × ByteArray)) (state : State) (found : ByteArray)
    (trail' : List (Nat × ByteArray)), state.faults = [] →
    (execute (descend fuel consumed current rest trail) state).1 = .ok (some found, trail') →
    ∃ start, current = some start ∧ Reaches (nodesOf state) start rest found := by
  induction fuel with
  | zero =>
    intro consumed current rest trail state found trail' _ ran
    simp [descend, execute, ExceptT.mk, pure, ExceptT.pure] at ran
  | succ fuel ih =>
    intro consumed current rest trail state found trail' quiet ran
    cases current with
    | none => simp [descend, execute, ExceptT.mk, pure, ExceptT.pure] at ran
    | some hash =>
      refine ⟨hash, rfl, ?_⟩
      cases rest with
      | nil =>
        obtain ⟨same, _⟩ : hash = found ∧ trail = trail' := by
          simpa [descend, execute, ExceptT.mk, pure, ExceptT.pure] using ran
        subst same
        exact .here _
      | cons nibble below =>
        simp only [descend, List.isEmpty_cons, Bool.false_eq_true, ↓reduceIte,
          VerifiedCore.Trie.Serve.storage, raise, performOver, Inject.inject, bind, ExceptT.bind,
          ExceptT.bindCont, ExceptT.mk, Program.bind, execute, Interpreter.handle,
          SimulatedHost.storage, reply, fault, quiet, List.find?_nil, Option.map_none, record,
          Except.mapError] at ran
        cases read : readByteObject state nodeSpace hash with
        | error failure =>
          simp [read, execute, pure] at ran
        | ok bytes =>
          cases bytes with
          | none => simp [read, execute, ExceptT.mk, pure, ExceptT.pure] at ran
          | some raw =>
            have held : nodesOf state hash = some raw := by simp [nodesOf, readableBytes, read]
            simp only [read] at ran
            cases decoded : decode raw with
            | error message => simp [decoded, throw, throwThe, MonadExcept.throw, execute] at ran
            | ok node =>
              simp only [decoded] at ran
              cases node with
              | leaf _ _ => simp [execute, ExceptT.mk, pure, ExceptT.pure] at ran
              | extension segment child =>
                simp only at ran
                split at ran
                · simp [execute, ExceptT.mk, pure, ExceptT.pure] at ran
                · rename_i spelled
                  simp only [Bool.or_eq_true, Bool.not_eq_true', not_or] at spelled
                  obtain ⟨nonempty, prefixed⟩ := spelled
                  obtain ⟨start, same, reached⟩ :=
                    ih _ _ _ _ { record state ("bytes:" ++ nodeSpace) with faults := [] } _ _ rfl ran
                  cases same
                  have shape := drop_of_isPrefixOf (segment := segment.toList) (rest := nibble :: below)
                    (by simpa using prefixed)
                  rw [← shape]
                  exact .extension hash raw segment child found _ held decoded
                    (by simpa using nonempty) reached
              | branch children value =>
                simp only at ran
                split at ran
                · simp [execute, ExceptT.mk, pure, ExceptT.pure] at ran
                · rename_i inRange
                  cases edge : (children[nibble.toNat]?).getD none with
                  | none => simp [edge, execute, ExceptT.mk, pure, ExceptT.pure] at ran
                  | some child =>
                    simp only [edge] at ran
                    obtain ⟨start, same, reached⟩ :=
                      ih _ _ _ _ { record state ("bytes:" ++ nodeSpace) with faults := [] } _ _ rfl ran
                    cases same
                    exact .branch hash raw child found children value nibble below held decoded
                      (getD_none_eq_some edge) reached
              | route children value =>
                simp only at ran
                split at ran
                · simp [execute, ExceptT.mk, pure, ExceptT.pure] at ran
                · rename_i inRange
                  cases edge : (children[nibble.toNat]?).getD none with
                  | none => simp [edge, execute, ExceptT.mk, pure, ExceptT.pure] at ran
                  | some child =>
                    simp only [edge] at ran
                    obtain ⟨start, same, reached⟩ :=
                      ih _ _ _ _ { record state ("bytes:" ++ nodeSpace) with faults := [] } _ _ rfl ran
                    cases same
                    exact .route hash raw child found children value nibble below held decoded
                      (getD_none_eq_some edge) reached

/-! ## The trail

A batch is one merged descent: each path resumes from the deepest node of
the previous descent it still agrees with. What makes that an optimization
and never an answer is that every step on the trail is a position of the
path walked that the graph really places its hash at, so resuming from a
step is descending from the root. -/

theorem prefix_shape {segment rest : Path} (h : segment.isPrefixOf rest = true) :
    ∃ tail, rest = segment ++ tail := by
  rw [List.isPrefixOf_iff_prefix] at h
  obtain ⟨tail, shape⟩ := h
  exact ⟨tail, shape.symm⟩

/-- What a descent leaves behind: the store untouched, no fault, and on the
trail only what it was handed and positions it reached from its start. -/
theorem descend_trail (fuel : Nat) : ∀ (consumed : Nat) (current : Option ByteArray) (rest : Path)
    (trail : List (Nat × ByteArray)) (state : State), state.faults = [] →
    nodesOf (execute (descend fuel consumed current rest trail) state).2 = nodesOf state ∧
    (execute (descend fuel consumed current rest trail) state).2.faults = [] ∧
    ∀ found trail', (execute (descend fuel consumed current rest trail) state).1 = .ok (found, trail') →
      ∀ step ∈ trail', step ∈ trail ∨ ∃ start, current = some start ∧ consumed ≤ step.1 ∧
        step.1 - consumed ≤ rest.length ∧
        Reaches (nodesOf state) start (rest.take (step.1 - consumed)) step.2 := by
  induction fuel with
  | zero =>
    intro consumed current rest trail state quiet
    simp only [descend, execute, ExceptT.mk, pure, ExceptT.pure]
    refine ⟨by trivial, by first | exact quiet | trivial, ?_⟩
    intro found trail' same step mem
    cases same
    exact .inl mem
  | succ fuel ih =>
    intro consumed current rest trail state quiet
    cases current with
    | none =>
      simp only [descend, execute, ExceptT.mk, pure, ExceptT.pure]
      refine ⟨by trivial, by first | exact quiet | trivial, ?_⟩
      intro found trail' same step mem
      cases same
      exact .inl mem
    | some hash =>
      cases rest with
      | nil =>
        simp only [descend, List.isEmpty_nil, ↓reduceIte, execute, ExceptT.mk, pure, ExceptT.pure]
        refine ⟨by trivial, by first | exact quiet | trivial, ?_⟩
        intro found trail' same step mem
        cases same
        exact .inl mem
      | cons nibble below =>
        simp only [descend, List.isEmpty_cons, Bool.false_eq_true, ↓reduceIte,
          VerifiedCore.Trie.Serve.storage, raise, performOver, Inject.inject, bind, ExceptT.bind,
          ExceptT.bindCont, ExceptT.mk, Program.bind, execute, Interpreter.handle,
          SimulatedHost.storage, reply, fault, quiet, List.find?_nil, Option.map_none, record,
          Except.mapError]
        cases read : readByteObject state nodeSpace hash with
        | error failure =>
          simp only [execute, pure]
          exact ⟨rfl, by trivial, by intros; contradiction⟩
        | ok bytes =>
          cases bytes with
          | none =>
            simp only [execute, ExceptT.mk, pure, ExceptT.pure]
            refine ⟨by trivial, by trivial, ?_⟩
            intro found trail' same step mem
            cases same
            exact .inl mem
          | some raw =>
            have held : nodesOf state hash = some raw := by simp [nodesOf, readableBytes, read]
            cases decoded : decode raw with
            | error message =>
              simp only [decoded, throw, throwThe, MonadExcept.throw, execute_throw]
              refine ⟨by trivial, by trivial, ?_⟩
              intro found trail' same
              cases same
            | ok node =>
              simp only [decoded]
              cases node with
              | leaf _ _ =>
                simp only [execute, ExceptT.mk, pure, ExceptT.pure]
                refine ⟨by trivial, by trivial, ?_⟩
                intro found trail' same step mem
                cases same
                exact .inl mem
              | extension segment child =>
                simp only
                split
                · simp only [execute, ExceptT.mk, pure, ExceptT.pure]
                  refine ⟨by trivial, by trivial, ?_⟩
                  intro found trail' same step mem
                  cases same
                  exact .inl mem
                · rename_i spelled
                  simp only [Bool.or_eq_true, Bool.not_eq_true', not_or] at spelled
                  obtain ⟨nonempty, prefixed⟩ := spelled
                  obtain ⟨tail, shape⟩ := prefix_shape (segment := segment.toList) (rest := nibble :: below)
                    (by simpa using prefixed)
                  obtain ⟨files, faults, steps⟩ := ih (consumed + segment.toList.length) (some child)
                    (List.drop segment.toList.length (nibble :: below))
                    (trail ++ [(consumed + segment.toList.length, child)])
                    { record state ("bytes:" ++ nodeSpace) with faults := [] } rfl
                  refine ⟨files, faults, ?_⟩
                  intro found trail' ran step mem
                  rcases steps found trail' ran step mem with old | ⟨start, same, lower, upper, reached⟩
                  · rcases List.mem_append.mp old with old | new
                    · exact .inl old
                    · simp only [List.mem_singleton] at new
                      subst new
                      refine .inr ⟨hash, rfl, by omega, ?_, ?_⟩
                      · simp only [Nat.add_sub_cancel_left, shape, List.length_append]
                        omega
                      · simp only [Nat.add_sub_cancel_left, shape, List.take_left]
                        simpa using Reaches.extension hash raw segment child child [] held decoded
                          (by simpa using nonempty) (.here child)
                  · cases same
                    have bound : segment.toList.length ≤ (nibble :: below).length := by
                      rw [shape, List.length_append]
                      omega
                    refine .inr ⟨hash, rfl, by omega, ?_, ?_⟩
                    · simp only [List.length_drop] at upper
                      omega
                    · have split : step.1 - consumed =
                        segment.toList.length + (step.1 - (consumed + segment.toList.length)) := by omega
                      rw [split, List.take_add, shape, List.take_left]
                      refine Reaches.extension hash raw segment child step.2 _ held decoded
                        (by simpa using nonempty) ?_
                      have reached' : Reaches (nodesOf state) child
                          (List.take (step.1 - (consumed + segment.toList.length))
                            (List.drop segment.toList.length (nibble :: below))) step.2 := reached
                      simpa [shape] using reached'
              | branch children value =>
                simp only
                split
                · simp only [execute, ExceptT.mk, pure, ExceptT.pure]
                  refine ⟨by trivial, by trivial, ?_⟩
                  intro found trail' same step mem
                  cases same
                  exact .inl mem
                · cases edge : (children[nibble.toNat]?).getD none with
                  | none =>
                    simp only [execute, ExceptT.mk, pure, ExceptT.pure]
                    refine ⟨by trivial, by trivial, ?_⟩
                    intro found trail' same step mem
                    cases same
                    exact .inl mem
                  | some child =>
                    obtain ⟨files, faults, steps⟩ := ih (consumed + 1) (some child) below
                      (trail ++ [(consumed + 1, child)]) { record state ("bytes:" ++ nodeSpace) with faults := [] } rfl
                    refine ⟨files, faults, ?_⟩
                    intro found trail' ran step mem
                    rcases steps found trail' ran step mem with old | ⟨start, same, lower, upper, reached⟩
                    · rcases List.mem_append.mp old with old | new
                      · exact .inl old
                      · simp only [List.mem_singleton] at new
                        subst new
                        refine .inr ⟨hash, rfl, by omega, by simp, ?_⟩
                        simp only [Nat.add_sub_cancel_left, List.take_succ_cons, List.take_zero]
                        exact Reaches.branch hash raw child child children value nibble [] held decoded
                          (getD_none_eq_some edge) (.here child)
                    · cases same
                      refine .inr ⟨hash, rfl, by omega, by simp; omega, ?_⟩
                      have split : step.1 - consumed = (step.1 - (consumed + 1)) + 1 := by omega
                      rw [split, List.take_succ_cons]
                      exact Reaches.branch hash raw child step.2 children value nibble _ held decoded
                        (getD_none_eq_some edge) reached
              | route children value =>
                simp only
                split
                · simp only [execute, ExceptT.mk, pure, ExceptT.pure]
                  refine ⟨by trivial, by trivial, ?_⟩
                  intro found trail' same step mem
                  cases same
                  exact .inl mem
                · cases edge : (children[nibble.toNat]?).getD none with
                  | none =>
                    simp only [execute, ExceptT.mk, pure, ExceptT.pure]
                    refine ⟨by trivial, by trivial, ?_⟩
                    intro found trail' same step mem
                    cases same
                    exact .inl mem
                  | some child =>
                    obtain ⟨files, faults, steps⟩ := ih (consumed + 1) (some child) below
                      (trail ++ [(consumed + 1, child)]) { record state ("bytes:" ++ nodeSpace) with faults := [] } rfl
                    refine ⟨files, faults, ?_⟩
                    intro found trail' ran step mem
                    rcases steps found trail' ran step mem with old | ⟨start, same, lower, upper, reached⟩
                    · rcases List.mem_append.mp old with old | new
                      · exact .inl old
                      · simp only [List.mem_singleton] at new
                        subst new
                        refine .inr ⟨hash, rfl, by omega, by simp, ?_⟩
                        simp only [Nat.add_sub_cancel_left, List.take_succ_cons, List.take_zero]
                        exact Reaches.route hash raw child child children value nibble [] held decoded
                          (getD_none_eq_some edge) (.here child)
                    · cases same
                      refine .inr ⟨hash, rfl, by omega, by simp; omega, ?_⟩
                      have split : step.1 - consumed = (step.1 - (consumed + 1)) + 1 := by omega
                      rw [split, List.take_succ_cons]
                      exact Reaches.route hash raw child step.2 children value nibble _ held decoded
                        (getD_none_eq_some edge) reached

/-- Executing a bound program runs the first, then the continuation on the
state it leaves. -/
theorem execute_bind (m : Program Serve.Effects A) (k : A → Program Serve.Effects B) (state : State) :
    execute (m.bind k) state = execute (k (execute m state).1) (execute m state).2 := by
  induction m generalizing state with
  | pure a => rfl
  | request effect resume ih =>
    show execute (.request effect fun reply => (resume reply).bind k) state = _
    simp only [execute]
    generalize Interpreter.handle effect state = handled
    obtain ⟨reply, next⟩ := handled
    exact ih reply next

theorem commonPrefix_le_right (a b : Path) : commonPrefix a b ≤ b.length := by
  induction a generalizing b with
  | nil => cases b <;> simp [commonPrefix]
  | cons x xs ih =>
    cases b with
    | nil => simp [commonPrefix]
    | cons y ys =>
      simp only [commonPrefix, List.length_cons]
      split
      · exact Nat.succ_le_succ (ih ys)
      · exact Nat.zero_le _

theorem commonPrefix_take (a b : Path) : ∀ n, n ≤ commonPrefix a b → a.take n = b.take n := by
  induction a generalizing b with
  | nil =>
    intro n h
    cases b <;> simp [commonPrefix] at h <;> subst h <;> rfl
  | cons x xs ih =>
    intro n h
    cases b with
    | nil =>
      simp [commonPrefix] at h
      subst h
      rfl
    | cons y ys =>
      simp only [commonPrefix] at h
      split at h
      · rename_i same
        cases n with
        | zero => rfl
        | succ n =>
          rw [beq_iff_eq] at same
          subst same
          simp [List.take_succ_cons, ih ys n (by omega)]
      · have : n = 0 := by omega
        subst this
        rfl

/-- Every step on a trail is a position of the path walked that the graph
places its hash at, below the root. -/
def TrailOk (lookup : ByteArray → Option ByteArray) (root : Option ByteArray) (walked : Path)
    (trail : List (Nat × ByteArray)) : Prop :=
  ∀ step ∈ trail, step.1 ≤ walked.length ∧
    ∃ start, root = some start ∧ Reaches lookup start (walked.take step.1) step.2

/-- One path of a merged descent, from a chosen depth and node. -/
def body (root : Option ByteArray) (index : Nat) (path : Path) (rest : List (Nat × Path))
    (consumed : Nat) (current : Option ByteArray) (trail : List (Nat × ByteArray)) :
    Serve.Action (List (Nat × Option ByteArray)) := do
  let (found, trail) ← descend descentFuel consumed current (path.drop consumed) trail
  let others ← resolveSorted root rest path trail
  return (index, found) :: others

theorem resolveSorted_cons (root : Option ByteArray) (index : Nat) (path : Path)
    (rest : List (Nat × Path)) (walked : Path) (trail : List (Nat × ByteArray)) :
    resolveSorted root ((index, path) :: rest) walked trail =
      match (trail.filter fun step => step.1 ≤ commonPrefix walked path).getLast? with
      | some (depth, hash) =>
        body root index path rest depth (some hash) (trail.filter fun step => step.1 ≤ commonPrefix walked path)
      | none => body root index path rest 0 root (trail.filter fun step => step.1 ≤ commonPrefix walked path) := by
  unfold resolveSorted
  split <;> rename_i heq <;> simp only [heq] <;> rfl

/-- Whatever a merged descent answers for a position, the graph places it
there below the root: resuming from the trail never answers for a position
the descent did not reach. -/
theorem resolveSorted_sound (sorted : List (Nat × Path)) :
    ∀ (root : Option ByteArray) (walked : Path) (trail : List (Nat × ByteArray)) (state : State),
    state.faults = [] → TrailOk (nodesOf state) root walked trail →
    ∀ answers, (execute (resolveSorted root sorted walked trail) state).1 = .ok answers →
    ∀ index found, (index, some found) ∈ answers →
      ∃ path, (index, path) ∈ sorted ∧ ∃ start, root = some start ∧
        Reaches (nodesOf state) start path found := by
  induction sorted with
  | nil =>
    intro root walked trail state _ _ answers ran index found mem
    simp only [resolveSorted, execute, ExceptT.mk, pure, ExceptT.pure, Except.ok.injEq] at ran
    subst ran
    simp at mem
  | cons want rest ih =>
    obtain ⟨index, path⟩ := want
    intro root walked trail state quiet ok answers ran index' found mem
    rw [resolveSorted_cons] at ran
    generalize kept : (trail.filter fun step => step.1 ≤ commonPrefix walked path) = trailF at ran
    have keptOk : ∀ step ∈ trailF, step.1 ≤ commonPrefix walked path ∧ step.1 ≤ walked.length ∧
        ∃ start, root = some start ∧ Reaches (nodesOf state) start (walked.take step.1) step.2 := by
      intro step mem
      rw [← kept, List.mem_filter, decide_eq_true_eq] at mem
      exact ⟨mem.2, ok step mem.1⟩
    -- One path, from wherever the descent starts, given that the start is a
    -- position of the path the graph places its node at.
    have step : ∀ consumed current, consumed ≤ path.length →
        (∀ start, current = some start → ∃ origin, root = some origin ∧
          Reaches (nodesOf state) origin (path.take consumed) start) →
        (execute (body root index path rest consumed current trailF) state).1 = Except.ok answers →
        ∃ path', (index', path') ∈ (index, path) :: rest ∧ ∃ start, root = some start ∧
          Reaches (nodesOf state) start path' found := by
      intro consumed current within origins ran
      simp only [body, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind,
        pure, ExceptT.pure] at ran
      obtain ⟨files, faults, steps⟩ :=
        descend_trail descentFuel consumed current (path.drop consumed) trailF state quiet
      have sound := descend_sound descentFuel consumed current (path.drop consumed) trailF state
      generalize descended : execute (descend descentFuel consumed current (path.drop consumed) trailF) state
        = first at ran files faults steps sound
      obtain ⟨answer, next⟩ := first
      cases answer with
      | error _ => simp [execute] at ran
      | ok pair =>
        obtain ⟨found', trail'⟩ := pair
        simp only [execute_bind] at ran
        simp only at files faults steps sound
        generalize resolved : execute (resolveSorted root rest path trail') next = second at ran
        obtain ⟨others, final⟩ := second
        cases others with
        | error _ => simp [execute, ExceptT.bindCont, pure] at ran
        | ok others =>
          simp only [ExceptT.bindCont, execute, Except.ok.injEq] at ran
          subst ran
          rcases List.mem_cons.mp mem with here | later
          · simp only [Prod.mk.injEq] at here
            obtain ⟨rfl, rfl⟩ := here
            refine ⟨path, List.mem_cons_self .., ?_⟩
            obtain ⟨start, same, reached⟩ := sound found trail' quiet rfl
            obtain ⟨origin, same', above⟩ := origins start same
            exact ⟨origin, same', by simpa [List.take_append_drop] using above.trans reached⟩
          · have nodes : nodesOf next = nodesOf state := files
            have trailOk : TrailOk (nodesOf next) root path trail' := by
              intro step mem
              rw [nodes]
              rcases steps found' trail' rfl step mem with old | ⟨start, same, lower, upper, reached⟩
              · obtain ⟨agree, _, origin, same, reached⟩ := keptOk step old
                refine ⟨Nat.le_trans agree (commonPrefix_le_right walked path), origin, same, ?_⟩
                rwa [commonPrefix_take walked path step.1 agree] at reached
              · obtain ⟨origin, same', above⟩ := origins start same
                refine ⟨?_, origin, same', ?_⟩
                · simp only [List.length_drop] at upper
                  omega
                · have shape : step.1 = consumed + (step.1 - consumed) := by omega
                  rw [shape, List.take_add]
                  exact above.trans reached
            obtain ⟨path', mem', origin, same, reached⟩ :=
              ih root path trail' next faults trailOk others (by rw [resolved]) index' found later
            exact ⟨path', List.mem_cons_of_mem _ mem', origin, same, by rwa [nodes] at reached⟩
    cases last : trailF.getLast? with
    | none =>
      simp only [last] at ran
      refine step 0 root (Nat.zero_le _) (fun start same => ⟨start, same, ?_⟩) ran
      simpa using Reaches.here start
    | some entry =>
      obtain ⟨depth, hash⟩ := entry
      simp only [last] at ran
      have mem : (depth, hash) ∈ trailF := by
        rw [List.getLast?_eq_some_iff] at last
        obtain ⟨front, shape⟩ := last
        rw [shape]
        exact List.mem_append_right _ (List.mem_singleton.mpr rfl)
      obtain ⟨agree, _, origin, same, reached⟩ := keptOk _ mem
      refine step depth (some hash) (Nat.le_trans agree (commonPrefix_le_right walked path))
        (fun start eq => ?_) ran
      cases eq
      refine ⟨origin, same, ?_⟩
      rwa [commonPrefix_take walked path depth agree] at reached

theorem mem_insertByPath (want entry : Nat × Path) (list : List (Nat × Path)) :
    entry ∈ insertByPath want list ↔ entry = want ∨ entry ∈ list := by
  induction list with
  | nil => simp [insertByPath]
  | cons head rest ih =>
    simp only [insertByPath]
    split
    · simp
    · simp only [List.mem_cons, ih]
      constructor
      · rintro (h | h | h) <;> simp [h]
      · rintro (h | h | h) <;> simp [h]

theorem mem_sortByPath (entry : Nat × Path) (list : List (Nat × Path)) :
    entry ∈ sortByPath list ↔ entry ∈ list := by
  induction list with
  | nil => simp [sortByPath]
  | cons head rest ih => simp [sortByPath, mem_insertByPath, ih]

/-- A position cannot be claimed into existence: whatever `resolvePaths`
answers for a path, the stored graph places it at exactly that path below
the root, and the claimed hash is never consulted. -/
theorem resolvePaths_sound (root : ByteArray) (paths : List Path) (state : State) (quiet : state.faults = [])
    (answers : List (Option ByteArray))
    (ran : (SimulatedHost.run (resolvePaths root paths) state).1 = .ok answers)
    (index : Nat) (found : ByteArray) (answered : answers[index]? = some (some found)) :
    ∃ path start, paths[index]? = some path ∧ rootOf root = some start ∧
      Reaches (nodesOf state) start path found := by
  simp only [SimulatedHost.run, resolvePaths, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, ExceptT.run,
    execute_bind, pure, ExceptT.pure] at ran
  generalize resolved : execute (resolveSorted (rootOf root)
    (sortByPath (paths.zipIdx.map fun (path, index) => (index, path))) [] []) { state with output := [] }
    = result at ran
  obtain ⟨answer, final⟩ := result
  cases answer with
  | error _ => simp [execute] at ran
  | ok resolvedList =>
    simp only [execute, Except.ok.injEq] at ran
    subst ran
    rw [List.getElem?_map] at answered
    cases range : (List.range paths.length)[index]? with
    | none => simp [range] at answered
    | some index' =>
      simp only [range, Option.map_some, Option.some.injEq] at answered
      have bound : index < paths.length := by
        rcases Nat.lt_or_ge index paths.length with lt | ge
        · exact lt
        · rw [List.getElem?_eq_none (by simpa [List.length_range] using ge)] at range
          cases range
      rw [List.getElem?_range bound, Option.some.injEq] at range
      subst range
      cases hit : resolvedList.find? (fun entry => entry.1 == index) with
      | none => simp [hit] at answered
      | some entry =>
        simp only [hit, Option.map_some, Option.getD_some] at answered
        have same := List.find?_some hit
        simp only [beq_iff_eq] at same
        have mem := List.mem_of_find?_eq_some hit
        obtain ⟨entryIndex, entryFound⟩ := entry
        simp only at same answered
        subst same answered
        obtain ⟨path, sorted, start, rooted, reached⟩ := resolveSorted_sound _ (rootOf root) [] []
          { state with output := [] } quiet (fun _ mem => nomatch mem) resolvedList (by rw [resolved])
          entryIndex found mem
        rw [mem_sortByPath, List.mem_map] at sorted
        obtain ⟨⟨path', index'⟩, zipped, shape⟩ := sorted
        simp only [Prod.mk.injEq] at shape
        obtain ⟨sameIndex, samePath⟩ := shape
        obtain ⟨_, within, at_index⟩ := List.mem_zipIdx zipped
        refine ⟨path, start, ?_, rooted, reached⟩
        rw [← samePath, at_index, ← sameIndex]
        simp [List.getElem?_eq_getElem (by simpa using within)]

/-! ## Admission

Before any position is looked at: an unscoped peer is answered by the hashes
it named, and a scoped peer asking about a root no origin other than its own
signed is refused whole. -/

theorem admit_full (scope : Scope) (root : ByteArray) (origins peerOrigins : List String)
    (wants : List (ByteArray × ByteArray)) (state : State) (full : scope.isFull = true) :
    SimulatedHost.run (Serve.admit scope root origins peerOrigins wants) state =
      (.ok (wants.map fun (_, claimed) => some claimed), { state with output := [] }) := by
  simp [SimulatedHost.run, Serve.admit, full, execute, pure, ExceptT.pure, ExceptT.run, ExceptT.mk]

theorem admit_unvouched (scope : Scope) (root : ByteArray) (origins peerOrigins : List String)
    (wants : List (ByteArray × ByteArray)) (state : State) (bounded : scope.isFull = false)
    (own : origins.any (fun origin => !peerOrigins.contains origin) = false) :
    SimulatedHost.run (Serve.admit scope root origins peerOrigins wants) state =
      (.error .unvouchedRoot, { state with output := [] }) := by
  simp only [SimulatedHost.run, Serve.admit, bounded, own, Bool.false_eq_true, Bool.not_false, ↓reduceIte,
    bind, ExceptT.bind, ExceptT.bindCont, ExceptT.run, ExceptT.mk, Program.bind, execute, throw, throwThe,
    MonadExcept.throw, throw_eq, pure, ExceptT.pure]

/-! ## The answer

One answer carries payloads under the budget, or exactly one payload larger
than the whole budget, and a hash pushed is a hash served. -/

/-- The payload bytes an answer carries. -/
def carriedBytes (answer : Answer) : Nat := (answer.payloads.map fun (_, data) => data.size).sum

theorem push_within (answer : Answer) (hash data : ByteArray)
    (bounded : carriedBytes answer + answer.budget ≤ answerBudget) :
    carriedBytes (answer.push hash data) + (answer.push hash data).budget ≤ answerBudget ∨
    ((answer.push hash data).payloads = [(hash, data)] ∧ (answer.push hash data).full = true) := by
  unfold Answer.push
  split
  · rename_i fits
    left
    simp only [carriedBytes, List.map_append, List.sum_append, List.map_cons, List.map_nil,
      List.sum_cons, List.sum_nil] at bounded ⊢
    omega
  · split
    · right
      simp
    · left
      simpa [carriedBytes] using bounded

theorem push_served (answer : Answer) (hash data : ByteArray) :
    (answer.push hash data).served hash = true := by
  unfold Answer.push Answer.served
  split <;> (try split) <;> simp

/-- The empty answer is within the budget, so every answer built from it is. -/
theorem empty_within : carriedBytes {} + Answer.budget {} ≤ answerBudget := by
  simp [carriedBytes]

/-! ## A concrete trie

Five nodes: a branch at the root with one child at nibble 6, an extension
spelling `7 0`, a branch with leaves at nibbles 1 and 2, one leaf inline and
one holding its value out of line. Positions: the root at `[]`, the
extension at `[6]`, the lower branch at `[6 7 0]`, the leaves at `[6 7 0 1]`
and `[6 7 0 2]`. The root is a recorded head of `nas`. -/

def bytes (list : List UInt8) : ByteArray := ⟨list.toArray⟩
def address (value : UInt8) : ByteArray := bytes (List.replicate 32 value)
def rootHash := address 1
def extHash := address 2
def lowerHash := address 3
def leafAHash := address 4
def leafBHash := address 5
def valueHash := address 6
def strange := address 9

def slots (children : List (Nat × ByteArray)) : List (Option ByteArray) :=
  (List.range 16).map fun slot => (children.find? fun entry => entry.1 == slot).map Prod.snd

def rootNode : Node := .branch (slots [(6, extHash)]) none
def extNode : Node := .extension (bytes [7, 0]) lowerHash
def lowerNode : Node := .branch (slots [(1, leafAHash), (2, leafBHash)]) none
def leafANode : Node := .leaf (bytes [1, 1]) (.inline (bytes [97]))
def leafBNode : Node := .leaf (bytes [2, 2]) (.hash valueHash)
def payload : ByteArray := bytes [1, 2, 3]

def graph : State :=
  { files := [((nodeSpace, rootHash), encode rootNode), ((nodeSpace, extHash), encode extNode),
      ((nodeSpace, lowerHash), encode lowerNode), ((nodeSpace, leafAHash), encode leafANode),
      ((nodeSpace, leafBHash), encode leafBNode), ((valueSpace, valueHash), payload)],
    db := [("head_history", [[("root", .blob rootHash), ("origin_id", .text "nas")]]),
      ("trie_node_origins", [[("origin_id", .text "nas"), ("hash", .blob rootHash)],
        [("origin_id", .text "nas"), ("hash", .blob extHash)]])] }

def atRoot : Path := []
def atExt : Path := [6]
def atLower : Path := [6, 7, 0]
def atLeafA : Path := [6, 7, 0, 1]
def atLeafB : Path := [6, 7, 0, 2]

def wantAll : List (ByteArray × ByteArray) :=
  [(bytes atRoot, rootHash), (bytes atExt, extHash), (bytes atLower, lowerHash),
    (bytes atLeafA, leafAHash), (bytes atLeafB, leafBHash)]

/-- A grant below leaf A's position: the spine down to it is admitted, the
leaf itself spells a key outside the grant, and leaf B's position is not
admitted at all. -/
def narrow : Scope := ⟨some [bytes [6, 7, 0, 1, 1, 5]], []⟩
def onLeafB : Scope := ⟨some [bytes atLeafB], []⟩
def onLeafA : Scope := ⟨some [bytes atLeafA], []⟩

def reads (count : Nat) : List String := List.replicate count ("bytes:" ++ nodeSpace)

/-- Every position resolves to what stands there, in the caller's order, by
one merged descent: the root costs no read, the deepest path walks three
nodes, and each later path resumes from the deepest node it still agrees
with. -/
theorem positions_resolve_to_what_stands_there :
    let result := SimulatedHost.run (resolvePaths rootHash
      [atLeafA, atRoot, atLeafB, [6, 7, 0, 3], [9], atLeafA ++ [1]]) graph
    (result.1, result.2.trace) ==
      (.ok [some leafAHash, some rootHash, some leafBHash, none, none, none], reads 7) := by
  decide +kernel

/-- The zero root is the empty trie: nothing stands anywhere, and nothing is read. -/
theorem nothing_stands_under_the_empty_root :
    let result := SimulatedHost.run (resolvePaths (address 0) [atRoot, atLeafA]) graph
    (result.1, result.2.trace) == (.ok [none, none], []) := by
  decide +kernel

/-- A scoped peer gets the spine and nothing that spells past its grant: the
root, the extension and the lower branch travel; leaf A sits at an admitted
position but spells a key outside the grant, so it is redacted; leaf B's
position is not admitted, so the hash claimed there is reported missing. -/
theorem a_scoped_peer_sees_the_spine_and_not_past_its_grant :
    let result := SimulatedHost.run (serveNodes rootHash wantAll narrow ["delegate"] []) graph
    (result.1, result.2.trace) == (.ok ⟨[(rootHash, encode rootNode), (extHash, encode extNode),
        (lowerHash, encode lowerNode)], [leafBHash], [leafAHash]⟩,
      ["snapshot:head_history"] ++ reads 3 ++ reads 5) := by
  decide +kernel

/-- Inside the grant nothing is redacted, and a position holding nothing
cannot be talked into holding the hash claimed there. -/
theorem a_position_holding_nothing_answers_nothing :
    let result := SimulatedHost.run (serveNodes rootHash
      [(bytes atLeafB, leafBHash), (bytes [6, 7, 0, 2, 2, 2], strange), (bytes [6, 7, 0, 3], leafAHash)]
      onLeafB ["delegate"] []) graph
    (result.1, result.2.trace) == (.ok ⟨[(leafBHash, encode leafBNode)], [strange, leafAHash], []⟩,
      ["snapshot:head_history"] ++ reads 3 ++ reads 2 ++ reads 1) := by
  decide +kernel

/-- A root this node holds no head for, or only the asking peer's own,
vouches for no position: refused before any node is read. -/
theorem an_unvouched_root_is_refused_whole :
    (let result := SimulatedHost.run (serveNodes rootHash wantAll narrow ["nas"] []) graph
     (result.1, result.2.trace) == (.error .unvouchedRoot, ["snapshot:head_history"])) ∧
    (let result := SimulatedHost.run (serveNodes strange wantAll narrow ["delegate"] []) graph
     (result.1, result.2.trace) == (.error .unvouchedRoot, ["snapshot:head_history"])) := by
  decide +kernel

/-- An unscoped peer is answered by hash: positions are not consulted, a
hash named twice is read twice and goes once, and a hash this node does not
hold is missing. -/
theorem an_unscoped_peer_is_answered_by_hash :
    let result := SimulatedHost.run (serveNodes rootHash
      [(bytes [9, 9], rootHash), (bytes atRoot, rootHash), (bytes atRoot, leafBHash), (bytes atRoot, strange)]
      ⟨none, []⟩ [] []) graph
    (result.1, result.2.trace) == (.ok ⟨[(rootHash, encode rootNode), (leafBHash, encode leafBNode)],
        [strange], []⟩, ["snapshot:head_history"] ++ reads 4) := by
  decide +kernel

/-- Under a confined origin's root only a node this store was served as that
origin's goes out, to any peer: the lower branch is held but not vouched for. -/
theorem a_confined_root_serves_only_vouched_nodes :
    let result := SimulatedHost.run (serveNodes rootHash wantAll ⟨none, []⟩ [] ["nas"]) graph
    (result.1, result.2.trace) == (.ok ⟨[(rootHash, encode rootNode), (extHash, encode extNode)],
        [lowerHash, leafAHash, leafBHash], []⟩,
      ["snapshot:head_history"] ++ (List.replicate 5 (reads 1 ++ ["snapshot:trie_node_origins"])).flatten) := by
  decide +kernel

/-- A value is served by the coverage of the node that holds it: from leaf
B's position inside a grant on it, not from a position the grant does not
admit, and not from a node that does not carry it. -/
theorem a_value_is_served_by_the_coverage_of_its_holder :
    (let result := SimulatedHost.run (serveValues rootHash [(bytes atLeafB, valueHash)] onLeafB ["delegate"] []) graph
     (result.1, result.2.trace) == (.ok ⟨[(valueHash, payload)], []⟩,
       ["snapshot:head_history"] ++ reads 3 ++ reads 1 ++ ["bytes:" ++ valueSpace])) ∧
    (let result := SimulatedHost.run (serveValues rootHash [(bytes atLeafB, valueHash)] onLeafA ["delegate"] []) graph
     (result.1, result.2.trace) == (.ok ⟨[], [valueHash]⟩, ["snapshot:head_history"] ++ reads 3)) ∧
    (let result := SimulatedHost.run (serveValues rootHash [(bytes atLeafA, valueHash)] onLeafA ["delegate"] []) graph
     (result.1, result.2.trace) == (.ok ⟨[], [valueHash]⟩, ["snapshot:head_history"] ++ reads 3 ++ reads 1)) ∧
    (let result := SimulatedHost.run (serveValues rootHash [(bytes [9], valueHash), (bytes [9], strange)]
        ⟨none, []⟩ [] []) graph
     (result.1, result.2.trace) == (.ok ⟨[(valueHash, payload)], [strange]⟩,
       ["snapshot:head_history", "bytes:" ++ valueSpace, "bytes:" ++ valueSpace])) := by
  decide +kernel

/-- Serving writes nothing: a failure at any effect is the answer, and the
store is exactly as it was. -/
theorem every_failed_serving_effect_changes_nothing :
    (List.range 9).all (fun index =>
      let result := SimulatedHost.run (serveNodes rootHash wantAll narrow ["delegate"] []) (fail graph index)
      failed result.1 && result.2.files == graph.files && result.2.db == graph.db) = true := by
  decide +kernel

end Synchronicity.TrieServeProofs
