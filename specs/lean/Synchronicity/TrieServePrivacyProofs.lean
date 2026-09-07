import Synchronicity.TrieServeProofs

/-! Privacy of whole trie-serving answers. The invariant follows the actual
answer loop, including deduplication and both budget exits. It does not
assume successful host effects, canonical stored bytes, or distinct wants. -/
namespace Synchronicity.TrieServePrivacyProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Trie.Serve
  SimulatedHost

/-- A successful sequential operation reached its continuation with a
successful intermediate result, in the state the first operation left. -/
theorem bind_ok [Interpreter E] (first : OperationOver E ε A)
    (next : A → OperationOver E ε B) (state : State) (result : B)
    (ran : (execute (first >>= next : OperationOver E ε B) state).1 = .ok result) :
    ∃ value middle, execute first state = (.ok value, middle) ∧
      (execute (next value) middle).1 = .ok result := by
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind] at ran
  generalize step : execute first state = pair at ran
  obtain ⟨reply, middle⟩ := pair
  cases reply with
  | error error => simp [execute, pure] at ran
  | ok value => exact ⟨value, middle, rfl, ran⟩

/-- Adding a payload preserves any property shared by the old payloads and
the candidate, even when the budget refuses that candidate. -/
theorem push_preserves (P : ByteArray × ByteArray → Prop) (answer : Answer)
    (hash data : ByteArray) (old : ∀ pair ∈ answer.payloads, P pair)
    (new : P (hash, data)) : ∀ pair ∈ (answer.push hash data).payloads, P pair := by
  unfold Answer.push
  split
  · intro pair mem
    rcases List.mem_append.mp mem with mem | mem
    · exact old pair mem
    · have eq := List.mem_singleton.mp mem
      exact eq ▸ new
  · split
    · intro pair mem
      have eq := List.mem_singleton.mp mem
      exact eq ▸ new
    · exact old

/-- Every payload the loop adds has passed the node-content check at one
of the supplied positions. A duplicate hash never bypasses that check. -/
theorem answerNodes_preserves (scope : Scope) (origins confined : List String)
    (P : ByteArray × ByteArray → Prop)
    (bounded : scope.isFull = false)
    (entries : List (Option ByteArray × (ByteArray × ByteArray))) :
    ∀ (answer : Answer) (missing redacted : List ByteArray) (state : State) (result : NodeAnswer),
    (∀ pair ∈ answer.payloads, P pair) →
    (∀ hash path claimed, (some hash, (path, claimed)) ∈ entries →
      ∀ data node, decode data = .ok node → scope.admitsNode path.toList node = true →
        P (hash, data)) →
    (execute (answerNodes scope origins confined entries answer missing redacted) state).1 =
      .ok result → ∀ pair ∈ result.nodes, P pair := by
  induction entries with
  | nil =>
    intro answer missing redacted state result old _ ran
    have eq : (⟨answer.payloads, missing, redacted⟩ : NodeAnswer) = result := Except.ok.inj ran
    subst result
    exact old
  | cons entry rest ih =>
    obtain ⟨found, path, claimed⟩ := entry
    intro answer missing redacted state result old allowed ran
    have tail := fun hash path claimed mem =>
      allowed hash path claimed (List.mem_cons_of_mem _ mem)
    cases found with
    | none => exact ih answer _ _ state result old tail ran
    | some hash =>
      unfold answerNodes at ran
      obtain ⟨held, readState, _, ran⟩ := bind_ok _ _ state result ran
      cases held with
      | none => exact ih answer _ _ readState result old tail ran
      | some data =>
        obtain ⟨covered, coveredState, _, ran⟩ := bind_ok _ _ readState result ran
        cases covered with
        | false => exact ih answer _ _ coveredState result old tail ran
        | true =>
          simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte, bounded, Bool.false_or] at ran
          cases decoded : decode data with
          | error message =>
            simp only [decoded, Bool.not_false, ↓reduceIte] at ran
            exact ih answer _ _ coveredState result old tail ran
          | ok node =>
            simp only [decoded] at ran
            cases revealed : scope.admitsNode path.toList node with
            | false =>
              simp only [revealed, Bool.not_false, ↓reduceIte] at ran
              exact ih answer _ _ coveredState result old tail ran
            | true =>
              simp only [revealed, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at ran
              split at ran
              · exact ih answer _ _ coveredState result old tail ran
              · have added := allowed hash path claimed (List.mem_cons_self ..) data node decoded revealed
                have kept := push_preserves P answer hash data old added
                split at ran
                · have eq : (⟨(answer.push hash data).payloads, missing, redacted⟩ : NodeAnswer) =
                      result := Except.ok.inj ran
                  subst result
                  exact kept
                · exact ih _ _ _ coveredState result kept tail ran

/-- Filtering resolved positions by the scope never admits a position the
scope refused, even if the resolver returns a list of a different length. -/
theorem masked_positions (scope : Scope) (wants : List (ByteArray × ByteArray)) :
    ∀ (resolved : List (Option ByteArray)) (hash path claimed : ByteArray),
    (some hash, (path, claimed)) ∈
      ((resolved.zip (wants.map fun (path, _) => scope.admitsPath path.toList)).map
        fun (found, ok) => if ok then found else none).zip wants →
    scope.admitsPath path.toList = true := by
  induction wants with
  | nil => simp
  | cons want rest ih =>
    intro resolved hash path claimed mem
    cases resolved with
    | nil => simp at mem
    | cons found resolved =>
      simp only [List.map_cons, List.zip_cons_cons, List.mem_cons] at mem
      rcases mem with here | later
      · cases allowed : scope.admitsPath want.1.toList with
        | false => simp [allowed] at here
        | true =>
          have shape := (Prod.mk.inj here).2
          cases shape
          exact allowed
      · exact ih resolved hash path claimed later

/-- Successful scoped admission supplies only scope-admitted positions. -/
theorem admit_positions (scope : Scope) (root : ByteArray) (origins peerOrigins : List String)
    (wants : List (ByteArray × ByteArray)) (state : State) (admitted : List (Option ByteArray))
    (bounded : scope.isFull = false)
    (ran : (execute (Serve.admit scope root origins peerOrigins wants) state).1 = .ok admitted) :
    ∀ hash path claimed, (some hash, (path, claimed)) ∈ admitted.zip wants →
      scope.admitsPath path.toList = true := by
  unfold Serve.admit at ran
  simp only [bounded, Bool.false_eq_true, ↓reduceIte] at ran
  split at ran
  · cases ran
  · obtain ⟨resolved, _, _, ran⟩ := bind_ok _ _ state admitted ran
    have eq := Except.ok.inj ran
    subst admitted
    exact masked_positions scope wants resolved

/-- Every node payload in a successful scoped answer decodes to a node
that the scope may reveal at a requested position admitted by that scope.
This is a theorem about the whole serving operation for arbitrary batches,
stored bytes and injected failures; no distinct-hash premise is needed. -/
theorem serveNodes_private (root : ByteArray) (wants : List (ByteArray × ByteArray))
    (scope : Scope) (peerOrigins confined : List String) (state : State) (result : NodeAnswer)
    (bounded : scope.isFull = false)
    (ran : (SimulatedHost.run (serveNodes root wants scope peerOrigins confined) state).1 = .ok result) :
    ∀ hash data, (hash, data) ∈ result.nodes →
      ∃ path claimed node, (path, claimed) ∈ wants ∧ scope.admitsPath path.toList = true ∧
        decode data = .ok node ∧ scope.admitsNode path.toList node = true := by
  unfold SimulatedHost.run serveNodes at ran
  obtain ⟨origins, originState, _, ran⟩ := bind_ok _ _ _ result ran
  obtain ⟨admitted, admittedState, admission, ran⟩ := bind_ok _ _ originState result ran
  have positions := admit_positions scope root origins peerOrigins wants originState admitted bounded
    (congrArg Prod.fst admission)
  intro hash data mem
  apply answerNodes_preserves scope origins confined
    (fun pair => ∃ path claimed node, (path, claimed) ∈ wants ∧ scope.admitsPath path.toList = true ∧
      decode pair.2 = .ok node ∧ scope.admitsNode path.toList node = true)
    bounded (admitted.zip wants) {} [] [] admittedState result
    (by simp) ?_ ran (hash, data) mem
  intro hash path claimed mem data node decoded revealed
  exact ⟨path, claimed, node, (List.of_mem_zip mem).2, positions hash path claimed mem, decoded, revealed⟩

/-- A successful holder check found a decoded node that both names the
out-of-line value and may reveal that value at this position. -/
theorem carried_private (scope : Scope) (origins confined : List String)
    (holder : Option ByteArray) (path : Path) (wanted : ByteArray) (state : State)
    (ran : (execute (carried scope origins confined holder path wanted) state).1 = .ok true) :
    ∃ hash raw node, holder = some hash ∧ decode raw = .ok node ∧
      node.valueHashes.contains wanted = true ∧ scope.admitsValue path node = true := by
  cases holder with
  | none => cases ran
  | some hash =>
    unfold carried at ran
    obtain ⟨covered, coveredState, _, ran⟩ := bind_ok _ _ state true ran
    cases covered with
    | false => cases ran
    | true =>
      obtain ⟨held, _, _, ran⟩ := bind_ok _ _ coveredState true ran
      cases held with
      | none => cases ran
      | some raw =>
        cases decoded : decode raw with
        | error _ => simp only [decoded] at ran; cases ran
        | ok node =>
          simp only [decoded] at ran
          have allowed := Except.ok.inj ran
          simp only [Bool.and_eq_true] at allowed
          exact ⟨hash, raw, node, rfl, decoded, allowed⟩

/-- Value payloads preserve the authorization supplied by a successful
holder check. The outer `none` (the unscoped bypass) must be excluded. -/
theorem answerValues_preserves (scope : Scope) (origins confined : List String)
    (P : ByteArray × ByteArray → Prop)
    (entries : List (Option (Option ByteArray) × (ByteArray × ByteArray))) :
    ∀ (answer : Answer) (missing : List ByteArray) (state : State) (result : ValueAnswer),
    (∀ pair ∈ answer.payloads, P pair) →
    (∀ path wanted, (none, (path, wanted)) ∉ entries) →
    (∀ holder path wanted, (some holder, (path, wanted)) ∈ entries →
      ∀ hash raw node, holder = some hash → decode raw = .ok node →
        node.valueHashes.contains wanted = true → scope.admitsValue path.toList node = true →
        ∀ data, P (wanted, data)) →
    (execute (answerValues scope origins confined entries answer missing) state).1 = .ok result →
    ∀ pair ∈ result.values, P pair := by
  induction entries with
  | nil =>
    intro answer missing state result old _ _ ran
    have eq : (⟨answer.payloads, missing⟩ : ValueAnswer) = result := Except.ok.inj ran
    subst result
    exact old
  | cons entry rest ih =>
    obtain ⟨holder, path, wanted⟩ := entry
    intro answer missing state result old restricted allowed ran
    have scopedTail := fun path wanted mem => restricted path wanted (List.mem_cons_of_mem _ mem)
    have tail := fun holder path wanted mem =>
      allowed holder path wanted (List.mem_cons_of_mem _ mem)
    unfold answerValues at ran
    split at ran
    · exact ih answer _ state result old scopedTail tail ran
    · cases holder with
      | none => exact False.elim (restricted path wanted (List.mem_cons_self ..))
      | some holder =>
        obtain ⟨authorized, checkedState, checked, ran⟩ := bind_ok _ _ state result ran
        cases authorized with
        | false => exact ih answer _ checkedState result old scopedTail tail ran
        | true =>
          obtain ⟨hash, raw, node, found, decoded, carries, reveals⟩ :=
            carried_private scope origins confined holder path.toList wanted state
              (congrArg Prod.fst checked)
          have new := allowed holder path wanted (List.mem_cons_self ..)
            hash raw node found decoded carries reveals
          obtain ⟨held, readState, _, ran⟩ := bind_ok _ _ checkedState result ran
          cases held with
          | none => exact ih answer _ readState result old scopedTail tail ran
          | some data =>
            have kept := push_preserves P answer wanted data old (new data)
            dsimp only at ran
            split at ran
            · have eq : (⟨(answer.push wanted data).payloads, missing⟩ : ValueAnswer) = result :=
                Except.ok.inj ran
              subst result
              exact kept
            · exact ih _ _ readState result kept scopedTail tail ran

theorem mem_some_holders (admitted : List (Option ByteArray)) :
    ∀ (wants : List (ByteArray × ByteArray)) holder want,
    (holder, want) ∈ (admitted.map some).zip wants →
      ∃ found, holder = some found ∧ (found, want) ∈ admitted.zip wants := by
  induction admitted with
  | nil => simp
  | cons found rest ih =>
    intro wants holder want mem
    cases wants with
    | nil => simp at mem
    | cons first wants =>
      simp only [List.map_cons, List.zip_cons_cons, List.mem_cons] at mem
      rcases mem with here | later
      · cases here
        exact ⟨found, rfl, List.mem_cons_self ..⟩
      · obtain ⟨found, same, mem⟩ := ih wants holder want later
        exact ⟨found, same, List.mem_cons_of_mem _ mem⟩

/-- Every value payload in a successful scoped answer was requested at an
admitted position whose decoded holder names that value and grants its
key. A holder that could expose only child hashes cannot authorize a value. -/
theorem serveValues_private (root : ByteArray) (wants : List (ByteArray × ByteArray))
    (scope : Scope) (peerOrigins confined : List String) (state : State) (result : ValueAnswer)
    (bounded : scope.isFull = false)
    (ran : (SimulatedHost.run (serveValues root wants scope peerOrigins confined) state).1 = .ok result) :
    ∀ wanted data, (wanted, data) ∈ result.values →
      ∃ path raw node, (path, wanted) ∈ wants ∧ scope.admitsPath path.toList = true ∧
        decode raw = .ok node ∧ node.valueHashes.contains wanted = true ∧
        scope.admitsValue path.toList node = true := by
  unfold SimulatedHost.run serveValues at ran
  obtain ⟨origins, originState, _, ran⟩ := bind_ok _ _ _ result ran
  simp only [bounded, Bool.false_eq_true, ↓reduceIte] at ran
  obtain ⟨holders, holderState, mapped, ran⟩ := bind_ok _ _ originState result ran
  have mappedBind :
      ((Serve.admit scope root origins peerOrigins wants).map (·.map some)) =
        (do let admitted ← Serve.admit scope root origins peerOrigins wants
            pure (admitted.map some) : Serve.Action (List (Option (Option ByteArray)))) := rfl
  rw [mappedBind] at mapped
  obtain ⟨admitted, _, admission, mapped⟩ := bind_ok _ _ originState holders (congrArg Prod.fst mapped)
  have same : admitted.map some = holders := Except.ok.inj mapped
  subst holders
  have positions := admit_positions scope root origins peerOrigins wants originState admitted bounded
    (congrArg Prod.fst admission)
  intro wanted data mem
  apply answerValues_preserves scope origins confined
    (fun pair => ∃ path raw node, (path, pair.1) ∈ wants ∧ scope.admitsPath path.toList = true ∧
      decode raw = .ok node ∧ node.valueHashes.contains pair.1 = true ∧
      scope.admitsValue path.toList node = true)
    ((admitted.map some).zip wants) {} [] holderState result (by simp) ?_ ?_ ran (wanted, data) mem
  · intro path wanted mem
    obtain ⟨found, same, _⟩ := mem_some_holders admitted wants none (path, wanted) mem
    cases same
  · intro holder path wanted mem hash raw node found decoded carries reveals data
    obtain ⟨found', same, entry⟩ := mem_some_holders admitted wants (some holder) (path, wanted) mem
    cases same
    subst holder
    exact ⟨path, raw, node, (List.of_mem_zip entry).2,
      positions hash path wanted entry, decoded, carries, reveals⟩

/-! A shared leaf at two positions: the first key is granted, the second
position is on a granted spine but its leaf's key is outside the grant.
The same payload may therefore be authorized at one position and refused
at the other. Privacy needs an authorized witness, not distinct hashes. -/
open TrieServeProofs

def sharedLeaf : Node := .leaf (bytes [0]) (.hash valueHash)

def sharedGraph : State :=
  { files := [((nodeSpace, rootHash), encode (.branch (slots [(1, leafAHash), (2, leafAHash)]) none)),
      ((nodeSpace, leafAHash), encode sharedLeaf), ((valueSpace, valueHash), payload)],
    db := [("head_history", [[("root", .blob rootHash), ("origin_id", .text "nas")]])] }

def sharedScope : Scope := ⟨some [bytes [2, 0, 1]], [bytes [1, 0]]⟩

/-- Node deduplication does not suppress the refusal at the second position,
whichever position comes first; an entirely refused batch sends no payload. -/
theorem shared_node_is_checked_at_each_position :
    (let wants := [(bytes [1], leafAHash), (bytes [2], leafAHash)]
     (SimulatedHost.run (serveNodes rootHash wants sharedScope ["delegate"] []) sharedGraph).1 ==
       .ok ⟨[(leafAHash, encode sharedLeaf)], [], [leafAHash]⟩) ∧
    (let wants := [(bytes [2], leafAHash), (bytes [1], leafAHash)]
     (SimulatedHost.run (serveNodes rootHash wants sharedScope ["delegate"] []) sharedGraph).1 ==
       .ok ⟨[(leafAHash, encode sharedLeaf)], [], [leafAHash]⟩) ∧
    ((SimulatedHost.run (serveNodes rootHash [(bytes [2], leafAHash), (bytes [2], leafAHash)]
      sharedScope ["delegate"] []) sharedGraph).1 == .ok ⟨[], [], [leafAHash]⟩) := by
  decide +kernel

/-- A shared value travels once if one holder position authorizes it. A
prior refusal stays in the missing list, while an already authorized value
is deduplicated; no payload travels when both positions are refused. -/
theorem shared_value_needs_an_authorized_holder :
    (let wants := [(bytes [1], valueHash), (bytes [2], valueHash)]
     (SimulatedHost.run (serveValues rootHash wants sharedScope ["delegate"] []) sharedGraph).1 ==
       .ok ⟨[(valueHash, payload)], []⟩) ∧
    (let wants := [(bytes [2], valueHash), (bytes [1], valueHash)]
     (SimulatedHost.run (serveValues rootHash wants sharedScope ["delegate"] []) sharedGraph).1 ==
       .ok ⟨[(valueHash, payload)], [valueHash]⟩) ∧
    ((SimulatedHost.run (serveValues rootHash [(bytes [2], valueHash), (bytes [2], valueHash)]
      sharedScope ["delegate"] []) sharedGraph).1 == .ok ⟨[], [valueHash]⟩) := by
  decide +kernel

end Synchronicity.TrieServePrivacyProofs
