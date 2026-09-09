import Synchronicity.TrieFetchAdmissionProgress
import Synchronicity.TrieCompleteProofs
import Synchronicity.TrieReadEffects
import Synchronicity.TrieMissingTransfer
import Synchronicity.TransactionSuccess

/-! Semantic accounting for the production missing walk and completeness
memo.  A frontier is useful evidence only when every still-unverified
requirement is represented by a pending or deferred position.  Consequently,
an exhausted accounted frontier establishes completion; an empty queue alone
does not.

The memo contract below assigns meaning to a cached key.  It is deliberately
stronger than the host's returned Boolean: `isKnown = true` is sound only when
the certificate was retained under this contract. -/
namespace Synchronicity.TrieMissingCompletion
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open VerifiedCore.Trie.Missing SimulatedHost
open TrieFetchCompletion TrieFetchAdmissionProgress

/-- The narrower effect language actually used by `Missing.inspect`. -/
def evidenceRead (A : Type) : Missing.Effects A → Prop
  | .left effect => match effect with
    | .readBytes _ _ => True
    | _ => False
  | .right (.left effect) => match effect with
    | .snapshot _ _ => True
    | _ => False
  | .right (.right _) => False

private theorem rowPresent_evidence_read (relation : String) (fields : Fields) :
    PrivateDatabase.Only evidenceRead (rowPresent relation fields).run := by
  unfold rowPresent
  refine PrivateDatabase.Only.seq (PrivateDatabase.Only.raise _ _ trivial) fun scan => ?_
  repeat' first | exact .done _ | split

private theorem loadOwned_evidence_read (owner : Option String) (address : ByteArray) :
    PrivateDatabase.Only evidenceRead (loadOwned owner address).run := by
  unfold loadOwned
  cases owner with
  | none => exact PrivateDatabase.Only.raise _ _ trivial
  | some origin =>
    refine (rowPresent_evidence_read _ _).seq fun owned => ?_
    split
    · exact .done _
    · exact PrivateDatabase.Only.raise _ _ trivial

private theorem valueAbsent_evidence_read (node : Node) (address : ByteArray) :
    PrivateDatabase.Only evidenceRead (valueAbsent node address).run := by
  unfold valueAbsent
  refine PrivateDatabase.Only.seq (PrivateDatabase.Only.raise _ _ trivial) fun answer => ?_
  repeat' first | exact .done _ | split

theorem inspectValuesAux_evidence_read (node : Node) (addresses : List ByteArray) :
    PrivateDatabase.Only evidenceRead (inspectValuesAux node addresses).run := by
  induction addresses with
  | nil => exact .done _
  | cons address rest ih =>
    simp only [inspectValuesAux]
    refine PrivateDatabase.Only.seq (valueAbsent_evidence_read node address) fun _ => ?_
    refine PrivateDatabase.Only.seq ih fun _ => .done _

private theorem inspectValues_evidence_read
    (context : Context) (position : Position) (node : Node) :
    PrivateDatabase.Only evidenceRead (inspectValues context position node).run := by
  unfold inspectValues
  split
  · exact inspectValuesAux_evidence_read node node.valueHashes
  · exact .done _

set_option maxHeartbeats 2000000 in
private theorem inspectPendingBranch_evidence_read (node : Node) :
    PrivateDatabase.Only evidenceRead (inspectPendingBranch node).run := by
  unfold inspectPendingBranch
  repeat' first
    | exact .done _
    | (refine PrivateDatabase.Only.seq (PrivateDatabase.Only.raise _ _ trivial) fun _ => ?_)
    | (refine PrivateDatabase.Only.seq (.done _) fun _ => ?_)
    | contradiction
    | (dsimp only; split)
    | split

private theorem inspectReference_evidence_read (reference : Option ByteArray) :
    PrivateDatabase.Only evidenceRead (inspectReference reference).run := by
  unfold inspectReference
  repeat' first
    | exact .done _
    | (refine PrivateDatabase.Only.seq (PrivateDatabase.Only.raise _ _ trivial) fun _ => ?_)
    | (refine PrivateDatabase.Only.seq (.done _) fun _ => ?_)
    | (dsimp only; split)
    | split

private theorem validateNodeDepth_evidence_read (position : Position) (node : Node) :
    PrivateDatabase.Only evidenceRead (validateNodeDepth position node).run := by
  cases node with
  | leaf suffix value => simp only [validateNodeDepth]; split <;> exact .done _
  | extension | branch | route => exact .done _

private theorem prepareDecoded_evidence_read [WorkSet Visit V] [WorkSet ByteArray H]
    (frontier : Frontier V H) (position : Position) (node : Node) :
    PrivateDatabase.Only evidenceRead (prepareDecoded frontier position node).run := by
  unfold prepareDecoded
  repeat' first
    | exact .done _
    | (refine PrivateDatabase.Only.seq (inspectPendingBranch_evidence_read _) fun _ => ?_)
    | (refine PrivateDatabase.Only.seq (inspectReference_evidence_read _) fun _ => ?_)
    | (refine PrivateDatabase.Only.seq (validateNodeDepth_evidence_read _ _) fun _ => ?_)
    | contradiction
    | (dsimp only; split)
    | split

private theorem prepareLoaded_evidence_read [WorkSet Visit V] [WorkSet ByteArray H]
    (frontier : Frontier V H) (position : Position) (raw : ByteArray) :
    PrivateDatabase.Only evidenceRead (prepareLoaded frontier position raw).run := by
  unfold prepareLoaded
  refine PrivateDatabase.Only.seq (.done _) fun node =>
    prepareDecoded_evidence_read _ _ node

private theorem inspectLoaded_evidence_read [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (frontier : Frontier V H) (position : Position) (raw : ByteArray) :
    PrivateDatabase.Only evidenceRead (inspectLoaded context frontier position raw).run := by
  unfold inspectLoaded
  refine PrivateDatabase.Only.seq (prepareLoaded_evidence_read _ _ _) fun prepared => ?_
  refine PrivateDatabase.Only.seq (inspectValues_evidence_read _ _ _) fun _ => .done _

set_option maxHeartbeats 2000000 in
theorem inspect_evidence_read [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (frontier : Frontier V H) (position : Position) :
    PrivateDatabase.Only evidenceRead (inspect context frontier position).run := by
  unfold inspect
  repeat' first
    | exact .done _
    | (refine PrivateDatabase.Only.seq (loadOwned_evidence_read _ _) fun _ => ?_)
    | (refine PrivateDatabase.Only.seq (inspectLoaded_evidence_read _ _ _ _) fun _ => ?_)
    | contradiction
    | (dsimp only; split)
    | split

/-- Inspecting changes tracing only; bytes and provenance evidence are stable. -/
theorem evidence_read_effect_preserves_replica {A : Type}
    (effect : Missing.Effects A) (safe : evidenceRead A effect)
    (state : SimulatedHost.State) :
    replicaOfState (Interpreter.handle effect state).2 = replicaOfState state := by
  cases effect with
  | left storageEffect =>
    cases storageEffect <;> try contradiction
    change replicaOfState (SimulatedHost.storage (.readBytes _ _) state).2 = replicaOfState state
    simp only [SimulatedHost.storage, SimulatedHost.reply]
    split <;> rfl
  | right other =>
    cases other with
    | left accessEffect =>
      cases accessEffect <;> try contradiction
      change replicaOfState (SimulatedHost.access (.snapshot _ _) state).2 = replicaOfState state
      simp only [SimulatedHost.access, SimulatedHost.reply]
      split <;> rfl
    | right redactionEffect => contradiction

theorem inspect_preserves_replica [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (frontier : Frontier V H) (position : Position)
    (state : SimulatedHost.State) :
    replicaOfState (execute (inspect context frontier position) state).2 = replicaOfState state :=
  (inspect_evidence_read context frontier position).preserves_observation
    replicaOfState _ evidence_read_effect_preserves_replica state

/-- A successful production raw read is exactly a readable replica fact. -/
theorem storage_read_some_verified (space : String) (address bytes : ByteArray)
    (state final : SimulatedHost.State)
    (ran : execute (Missing.storage (.readBytes space address)) state =
      (.ok (some bytes), final)) :
    readableBytes final space address = some bytes := by
  unfold Missing.storage at ran
  simp only [raise, performOver, ExceptT.mk, Inject.inject, execute,
    Interpreter.handle, SimulatedHost.storage] at ran
  unfold SimulatedHost.reply at ran
  split at ran
  · cases ran
  · have answer := congrArg Prod.fst ran
    have finalEq := congrArg Prod.snd ran
    dsimp at answer finalEq
    rw [← finalEq]
    change readableBytes state space address = some bytes
    unfold readableBytes
    cases readEq : readByteObject state space address <;> simp [readEq] at answer ⊢
    assumption

theorem loadOwned_some_has_node (owner : Option String) (address raw : ByteArray)
    (state final : SimulatedHost.State)
    (ran : execute (loadOwned owner address) state = (.ok (some raw), final)) :
    Verified (replicaOfState final) (.node address raw) := by
  change readableBytes final nodeSpace address = some raw
  cases owner with
  | none =>
    exact storage_read_some_verified nodeSpace address raw state final (by
      simpa [loadOwned] using ran)
  | some origin =>
    obtain ⟨owned, checked, ownedRun, tailRun⟩ := TrieServePrivacyProofs.bind_ok
      (rowPresent "trie_node_origins"
        [("origin_id", .text origin), ("hash", .blob address)])
      (fun owned => if !owned then pure none else Missing.storage (.readBytes nodeSpace address))
      state (some raw) (by simpa [loadOwned] using congrArg Prod.fst ran)
    have present : owned = true := by
      cases owned with
      | false =>
        change (Except.ok none : Except Missing.Error (Option ByteArray)) =
          Except.ok (some raw) at tailRun
        have impossible : (none : Option ByteArray) = some raw :=
          Except.ok.inj tailRun
        contradiction
      | true => rfl
    have decomposed : execute (loadOwned (some origin) address) state =
        execute (Missing.storage (.readBytes nodeSpace address)) checked := by
      unfold loadOwned
      simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
      rw [ownedRun]
      simp [present]
    exact storage_read_some_verified nodeSpace address raw checked final
      (decomposed.symm.trans ran)

theorem origin_rowPresent_true (origin : String) (address : ByteArray)
    (state final : SimulatedHost.State)
    (ran : execute (rowPresent "trie_node_origins"
      [("origin_id", .text origin), ("hash", .blob address)]) state = (.ok true, final)) :
    Verified (replicaOfState final) (.provenance origin address) := by
  have preserved := (rowPresent_evidence_read "trie_node_origins"
    [("origin_id", .text origin), ("hash", .blob address)]).preserves_observation
      replicaOfState _ evidence_read_effect_preserves_replica state
  rw [show final = (execute (rowPresent "trie_node_origins"
    [("origin_id", .text origin), ("hash", .blob address)]) state).2 by
      exact (congrArg Prod.snd ran).symm]
  change replicaOfState (execute (rowPresent "trie_node_origins"
    [("origin_id", .text origin), ("hash", .blob address)]) state).2 =
      replicaOfState state at preserved
  rw [preserved]
  change (rows state.db "trie_node_origins").any (fun row =>
    equals row [("origin_id", .text origin), ("hash", .blob address)]) = true
  obtain ⟨scan, checked, scanRun, tailRun⟩ := TrieServePrivacyProofs.bind_ok
    (raise Missing.Error.host (Access.snapshot
      ⟨"trie_node_origins", [("origin_id", .text origin), ("hash", .blob address)], [], []⟩
      ["hash"]) : Missing.Action Scan)
    (fun scan => if !scan.rows.isEmpty then pure true else
      match scan.failure with
      | some failure => throw (.host failure)
      | none => pure false) state true (by
        have ranFirst := congrArg Prod.fst ran
        unfold rowPresent at ranFirst
        exact ranFirst)
  have nonempty : scan.rows.isEmpty = false := by
    cases empty : scan.rows.isEmpty with
    | false => rfl
    | true =>
      simp only [empty, Bool.not_true, Bool.false_eq_true, ↓reduceIte] at tailRun
      cases failureEq : scan.failure with
      | none =>
        rw [failureEq] at tailRun
        change (Except.ok false : Except Missing.Error Bool) = Except.ok true at tailRun
        contradiction
      | some failure =>
        rw [failureEq] at tailRun
        change (Except.error (.host failure) : Except Missing.Error Bool) = Except.ok true at tailRun
        contradiction
  have actualRows : scan.rows = ((rows state.db "trie_node_origins").filter
      (selects ⟨"trie_node_origins",
        [("origin_id", .text origin), ("hash", .blob address)], [], []⟩)).map
        (project ["hash"]) := by
    simp only [raise, performOver, ExceptT.mk, Inject.inject, execute,
      Interpreter.handle, SimulatedHost.access] at scanRun
    unfold SimulatedHost.reply at scanRun
    split at scanRun
    · cases scanRun
    · let expected : Scan := ⟨((rows state.db "trie_node_origins").filter
          (selects ⟨"trie_node_origins",
            [("origin_id", .text origin), ("hash", .blob address)], [], []⟩)).map
              (project ["hash"]), scanFailure state⟩
      have same : Except.ok expected = (Except.ok scan : Except Missing.Error Scan) := by
        simpa using congrArg Prod.fst scanRun
      simpa [expected] using congrArg Scan.rows (Except.ok.inj same).symm
  apply List.any_eq_true.mpr
  have filteredNonempty : (rows state.db "trie_node_origins").filter
      (selects ⟨"trie_node_origins",
        [("origin_id", .text origin), ("hash", .blob address)], [], []⟩) ≠ [] := by
    intro empty
    rw [empty] at actualRows
    simp at actualRows
    rw [actualRows] at nonempty
    contradiction
  obtain ⟨row, member⟩ := List.exists_mem_of_ne_nil _ filteredNonempty
  have selected := List.mem_filter.mp member
  exact ⟨row, selected.1, by simpa [selects] using selected.2⟩

theorem loadOwned_some_verified (origin : String) (address raw : ByteArray)
    (state final : SimulatedHost.State)
    (ran : execute (loadOwned (some origin) address) state = (.ok (some raw), final)) :
    Verified (replicaOfState final) (.node address raw) ∧
      Verified (replicaOfState final) (.provenance origin address) := by
  refine ⟨loadOwned_some_has_node _ _ _ _ _ ran, ?_⟩
  obtain ⟨owned, checked, ownedRun, tailRun⟩ := TrieServePrivacyProofs.bind_ok
    (rowPresent "trie_node_origins"
      [("origin_id", .text origin), ("hash", .blob address)])
    (fun owned => if !owned then pure none else Missing.storage (.readBytes nodeSpace address))
    state (some raw) (by simpa [loadOwned] using congrArg Prod.fst ran)
  have present : owned = true := by
    cases owned with
    | false =>
      change (Except.ok (none : Option ByteArray) : Except Missing.Error (Option ByteArray)) =
        Except.ok (some raw) at tailRun
      have impossible : (none : Option ByteArray) = some raw := Except.ok.inj tailRun
      contradiction
    | true => rfl
  have atChecked := origin_rowPresent_true origin address state checked (by simpa [present] using ownedRun)
  have wholePreserved := (loadOwned_evidence_read (some origin) address).preserves_observation
    replicaOfState _ evidence_read_effect_preserves_replica state
  change replicaOfState (execute (loadOwned (some origin) address) state).2 =
    replicaOfState state at wholePreserved
  rw [congrArg Prod.snd ran] at wholePreserved
  have rowPreserved := (rowPresent_evidence_read "trie_node_origins"
    [("origin_id", .text origin), ("hash", .blob address)]).preserves_observation
      replicaOfState _ evidence_read_effect_preserves_replica state
  change replicaOfState (execute (rowPresent "trie_node_origins"
    [("origin_id", .text origin), ("hash", .blob address)]) state).2 =
      replicaOfState state at rowPreserved
  rw [congrArg Prod.snd ownedRun] at rowPreserved
  simpa [wholePreserved.trans rowPreserved.symm] using atChecked

/-- An actual successful no-reference expansion necessarily found the holder
and completed the factored loaded inspection. -/
theorem inspect_expand_decompose [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (frontier : Frontier V H) (position : Position)
    (state final : SimulatedHost.State) (children : List Position)
    (pending : Option ByteArray) (absent : List ByteArray) (routing : Bool)
    (noRef : position.reference = none)
    (ran : execute (inspect context frontier position) state =
      (.ok (.expand children pending absent routing), final)) :
    ∃ raw middle, execute (loadOwned context.owner position.hash) state = (.ok (some raw), middle) ∧
      execute (inspectLoaded context frontier position raw) middle =
        (.ok ⟨children, pending, absent, routing⟩, final) := by
  have first := congrArg Prod.fst ran
  have depth : ¬ position.path.size > Walk.maxDepthNibbles := by
    intro tooDeep
    unfold inspect at first
    simp only [tooDeep, ↓reduceIte, throw] at first
    contradiction
  have refBeq : (position.reference == some position.hash) = false := by simp [noRef]
  have unseen : ¬ WorkSet.contains frontier.seen
      (visit context.scope position.hash position.path) = true := by
    intro seen
    unfold inspect at first
    simp only [depth, refBeq, seen, Bool.false_eq_true, ↓reduceIte, pure,
      ExceptT.pure, ExceptT.mk, execute] at first
    cases first
  let tail : Option ByteArray → Missing.Action Checked := fun loaded => match loaded with
    | none => pure Checked.absent
    | some raw => do
      let expansion ← inspectLoaded context frontier position raw
      return .expand expansion.children expansion.pendingBranch expansion.absentValues expansion.routing
  have wholeEq : execute (inspect context frontier position) state =
      execute ((loadOwned context.owner position.hash >>= tail) : Missing.Action Checked) state := by
    unfold inspect
    simp only [depth, refBeq, unseen, Bool.false_eq_true, ↓reduceIte]
    rfl
  have sequenceRun : execute ((loadOwned context.owner position.hash >>= tail) :
      Missing.Action Checked) state = (.ok (.expand children pending absent routing), final) :=
    wholeEq.symm.trans ran
  obtain ⟨loaded, middle, loadRun, tailRun⟩ := TransactionSuccess.bind_success
    (loadOwned context.owner position.hash) tail state final
    (.expand children pending absent routing) sequenceRun
  cases loaded with
  | none => simp [tail, pure, ExceptT.pure, ExceptT.mk, execute] at tailRun
  | some raw =>
    let finish : Expansion → Missing.Action Checked := fun expansion =>
      pure (.expand expansion.children expansion.pendingBranch
        expansion.absentValues expansion.routing)
    have expansionTail : execute ((inspectLoaded context frontier position raw >>= finish) :
        Missing.Action Checked) middle = (.ok (.expand children pending absent routing), final) := by
      simpa [tail, finish] using tailRun
    obtain ⟨expansion, expanded, expansionRun, finishRun⟩ := TransactionSuccess.bind_success
      (inspectLoaded context frontier position raw) finish middle final
      (.expand children pending absent routing) expansionTail
    simp [finish, pure, ExceptT.pure, ExceptT.mk, execute] at finishRun
    rcases finishRun with ⟨fields, stateEq⟩
    have expansionEq : expansion = ⟨children, pending, absent, routing⟩ := by
      cases expansion
      simp_all
    subst expanded
    rw [expansionEq] at expansionRun
    exact ⟨raw, middle, loadRun, expansionRun⟩

theorem inspectLoaded_decompose [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (frontier : Frontier V H) (position : Position) (raw : ByteArray)
    (state final : SimulatedHost.State) (children : List Position)
    (pending : Option ByteArray) (absent : List ByteArray) (routing : Bool)
    (ran : execute (inspectLoaded context frontier position raw) state =
      (.ok ⟨children, pending, absent, routing⟩, final)) :
    ∃ prepared valuesStarted,
      execute (prepareLoaded frontier position raw) state = (.ok prepared, valuesStarted) ∧
      execute (inspectValues context position prepared.node) valuesStarted = (.ok absent, final) ∧
      prepared.children = children ∧ prepared.pendingBranch = pending ∧
      isRoute prepared.node = routing := by
  unfold inspectLoaded at ran
  obtain ⟨prepared, valuesStarted, preparedRun, tailRun⟩ :=
    TransactionSuccess.bind_success (prepareLoaded frontier position raw)
      (fun prepared => do
        let absent ← inspectValues context position prepared.node
        return (⟨prepared.children, prepared.pendingBranch, absent,
          isRoute prepared.node⟩ : Expansion))
      state final (⟨children, pending, absent, routing⟩ : Expansion) ran
  obtain ⟨foundAbsent, assembled, valuesRun, returned⟩ :=
    TransactionSuccess.bind_success (inspectValues context position prepared.node)
      (fun absent => pure (⟨prepared.children, prepared.pendingBranch, absent,
        isRoute prepared.node⟩ : Expansion))
      valuesStarted final (⟨children, pending, absent, routing⟩ : Expansion) tailRun
  simp [pure, ExceptT.pure, ExceptT.mk, execute] at returned
  rcases returned with ⟨fields, stateEq⟩
  subst assembled
  rcases fields with ⟨childrenEq, pendingEq, absentEq, routingEq⟩
  subst foundAbsent
  exact ⟨prepared, valuesStarted, preparedRun, valuesRun, childrenEq, pendingEq, routingEq⟩

theorem prepareDecoded_no_reference_shape [WorkSet Visit V] [WorkSet ByteArray H]
    (frontier : Frontier V H) (position : Position) (node : Node)
    (state final : SimulatedHost.State) (prepared : Prepared)
    (noRef : position.reference = none)
    (ran : execute (prepareDecoded frontier position node) state = (.ok prepared, final)) :
    prepared.node = node ∧ prepared.children = pairedChildren none node := by
  cases guard : (WorkSet.contains frontier.mustBeBranch position.hash && !isBranch node) with
  | true =>
    unfold prepareDecoded at ran
    simp [guard, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk,
      throw, throwThe, MonadExcept.throw, MonadExceptOf.throw, execute,
      Program.bind, pure, ExceptT.pure] at ran
  | false =>
    unfold prepareDecoded at ran
    simp only [guard, Bool.false_eq_true, ↓reduceIte] at ran
    let tail : Option ByteArray → Missing.Action Prepared := fun pendingBranch => do
      let reference ← inspectReference position.reference
      validateNodeDepth position node
      return ⟨node, pairedChildren reference node, pendingBranch⟩
    have sequenceRun : execute ((inspectPendingBranch node >>= tail) :
        Missing.Action Prepared) state = (.ok prepared, final) := by
      simpa [tail] using ran
    obtain ⟨pending, referenced, pendingRun, tailRun⟩ := TransactionSuccess.bind_success
      (inspectPendingBranch node) tail state final prepared sequenceRun
    have noReference : execute (inspectReference position.reference) referenced =
        (.ok none, referenced) := by
      simp [noRef, inspectReference, pure, ExceptT.pure, ExceptT.mk, execute]
    let finish : Option Node → Missing.Action Prepared := fun reference => do
      validateNodeDepth position node
      return ⟨node, pairedChildren reference node, pending⟩
    have finishRun : execute ((inspectReference position.reference >>= finish) :
        Missing.Action Prepared) referenced = (.ok prepared, final) := by
      simpa [tail, finish] using tailRun
    obtain ⟨reference, validated, referenceRun, validateRun⟩ :=
      TransactionSuccess.bind_success (inspectReference position.reference) finish
        referenced final prepared finishRun
    rw [noReference] at referenceRun
    cases referenceRun
    let returned : Unit → Missing.Action Prepared := fun _ =>
      pure ⟨node, pairedChildren none node, pending⟩
    have validationRun : execute ((validateNodeDepth position node >>= returned) :
        Missing.Action Prepared) referenced = (.ok prepared, final) := by
      simpa [finish, returned] using validateRun
    obtain ⟨ignored, assembled, _, returnedRun⟩ := TransactionSuccess.bind_success
      (validateNodeDepth position node) returned referenced final prepared validationRun
    simp [returned, pure, ExceptT.pure, ExceptT.mk, execute] at returnedRun
    rcases returnedRun with ⟨fields, _⟩
    exact ⟨(congrArg Prepared.node fields).symm,
      (congrArg Prepared.children fields).symm⟩

theorem prepareLoaded_decompose [WorkSet Visit V] [WorkSet ByteArray H]
    (frontier : Frontier V H) (position : Position) (raw : ByteArray)
    (state final : SimulatedHost.State) (prepared : Prepared)
    (ran : execute (prepareLoaded frontier position raw) state = (.ok prepared, final)) :
    ∃ node decodedState, decode raw = .ok node ∧
      execute (prepareDecoded frontier position node) decodedState = (.ok prepared, final) := by
  unfold prepareLoaded at ran
  obtain ⟨node, decodedState, decodeRun, preparedRun⟩ := TransactionSuccess.bind_success
    (decodeNode raw) (prepareDecoded frontier position) state final prepared ran
  refine ⟨node, decodedState, ?_, preparedRun⟩
  unfold decodeNode at decodeRun
  simp only [ExceptT.mk, execute] at decodeRun
  cases decoded : decode raw with
  | error message => simp [decoded] at decodeRun
  | ok decodedNode =>
    simp only [decoded, Except.mapError, Except.ok.injEq, Prod.mk.injEq] at decodeRun
    rw [decodeRun.1]

theorem valueAbsent_false_verified (node : Node) (address : ByteArray)
    (state final : SimulatedHost.State)
    (ran : execute (valueAbsent node address) state = (.ok false, final)) :
    ∃ bytes, Verified (replicaOfState final) (.value address bytes) := by
  unfold valueAbsent at ran
  obtain ⟨answer, read, readRun, tailRun⟩ := TransactionSuccess.bind_success
    (Missing.storage (.readBytes valueSpace address)) _ state final false ran
  cases answer with
  | none => simp [pure, ExceptT.pure, ExceptT.mk, execute] at tailRun
  | some bytes =>
    refine ⟨bytes, ?_⟩
    have verified := storage_read_some_verified valueSpace address bytes state read readRun
    dsimp only at tailRun
    split at tailRun
    · simp only [bind, ExceptT.bind, ExceptT.mk] at tailRun
      cases tailRun
    · simp only [pure, ExceptT.pure, ExceptT.mk, execute] at tailRun
      have stateEq := congrArg Prod.snd tailRun
      simp only at stateEq
      subst final
      exact verified

theorem inspectValuesAux_none_verified (node : Node) (addresses : List ByteArray)
    (state final : SimulatedHost.State)
    (ran : execute (inspectValuesAux node addresses) state = (.ok [], final)) :
    ∀ address ∈ addresses, ∃ bytes,
      Verified (replicaOfState final) (.value address bytes) := by
  induction addresses generalizing state final with
  | nil => simp
  | cons head rest ih =>
    simp only [inspectValuesAux] at ran
    obtain ⟨absent, checked, headRun, tailRun⟩ := TransactionSuccess.bind_success
      (valueAbsent node head)
      (fun absent => do
        let more ← inspectValuesAux node rest
        return if absent then head :: more else more)
      state final [] ran
    obtain ⟨more, assembled, restRun, returnRun⟩ := TransactionSuccess.bind_success
      (inspectValuesAux node rest)
      (fun more => pure (if absent then head :: more else more))
      checked final [] tailRun
    simp only [pure, ExceptT.pure, ExceptT.mk, execute, Prod.mk.injEq,
      Except.ok.injEq] at returnRun
    have stateEq := returnRun.2
    subst assembled
    cases absent with
    | true => simp at returnRun
    | false =>
      simp only [Bool.false_eq] at returnRun
      have empty : more = [] := returnRun.1
      subst more
      intro address member
      rcases List.mem_cons.mp member with rfl | later
      · obtain ⟨bytes, held⟩ := valueAbsent_false_verified node address state checked headRun
        refine ⟨bytes, ?_⟩
        have preserved := (inspectValuesAux_evidence_read node rest).preserves_observation
          replicaOfState _ evidence_read_effect_preserves_replica checked
        change replicaOfState (execute (inspectValuesAux node rest) checked).2 =
          replicaOfState checked at preserved
        rw [congrArg Prod.snd restRun] at preserved
        simpa [preserved] using held
      · exact ih checked final restRun address later

theorem inspectValues_none_verified (context : Context) (position : Position) (node : Node)
    (state final : SimulatedHost.State)
    (admitted : context.scope.admitsValue position.path.toList node = true)
    (ran : execute (inspectValues context position node) state = (.ok [], final)) :
    ∀ address ∈ node.valueHashes, ∃ bytes,
      Verified (replicaOfState final) (.value address bytes) := by
  unfold inspectValues at ran
  simp only [admitted, ↓reduceIte] at ran
  exact inspectValuesAux_none_verified node node.valueHashes state final ran

def PositionRequires (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (position : Position) (evidence : Evidence) : Prop :=
  Needs publisher context.scope context.owner position.hash position.path.toList evidence

theorem needs_current_node_held
    {hash : ByteArray} (needed : Needs publisher scope owner hash path evidence) :
    ∃ raw, publisher nodeSpace hash = some raw := by
  cases needed with
  | node admitted held => exact ⟨_, held⟩
  | provenance admitted held => exact ⟨_, held⟩
  | value heldNode decoded admitted named heldValue => exact ⟨_, heldNode⟩
  | extension held decoded nonempty below => exact ⟨_, held⟩
  | branch held decoded edge below => exact ⟨_, held⟩
  | route held decoded edge below => exact ⟨_, held⟩

/-- Every root requirement is either already durable or remains represented
by an actual pending/deferred walk position. -/
def FrontierAccountsFor (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) (replica : Replica)
    (frontier : Frontier V H) : Prop :=
  ∀ evidence, Needs publisher context.scope context.owner root [] evidence →
    Verified replica evidence ∨
      ∃ position, (position ∈ frontier.positions ∨ position ∈ frontier.deferred) ∧
        PositionRequires publisher context position evidence

def FrontierInvariant (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) (replica : Replica)
    (frontier : Frontier V H) : Prop :=
  TrieMissingProofs.FrontierAdmitted context.scope frontier ∧
    FrontierAccountsFor publisher context root replica frontier

theorem needs_admitted_at
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {hash : ByteArray} {path : List UInt8}
    {evidence : Evidence}
    (needed : Needs publisher scope owner hash path evidence) :
    scope.admitsPath path = true := by
  induction needed with
  | node admitted held => exact admitted
  | provenance admitted held => exact admitted
  | @value owner hash raw address bytes path node held decoded admitted named valueHeld =>
    cases node with
    | leaf suffix value =>
      exact TrieServeProofs.admitsPath_of_append scope path suffix.toList
        (TrieServeProofs.admitsPath_of_admitsKeyPath scope _ admitted)
    | extension segment child => simp [Serve.Scope.admitsValue] at admitted
    | branch children value =>
      exact TrieServeProofs.admitsPath_of_admitsKeyPath scope path admitted
    | route children value =>
      exact TrieServeProofs.admitsPath_of_admitsKeyPath scope path admitted
  | @extension owner hash raw segment child path evidence held decoded nonempty below ih =>
    exact TrieServeProofs.admitsPath_of_append scope path segment.toList ih
  | @branch owner hash raw child path evidence children branchValue nibble held decoded edge below ih =>
    exact TrieServeProofs.admitsPath_of_append scope path [nibble] ih
  | @route owner hash raw child path evidence children routeValue nibble held decoded edge below ih =>
    exact TrieServeProofs.admitsPath_of_append scope path [nibble] ih

private theorem admitsValue_inside (scope : Serve.Scope) (path : List UInt8)
    (node : Node) (admitted : scope.admitsValue path node = true)
    (inside : scope.containsSubtree tail = true) :
    scope.admitsValue tail node = true := by
  cases node with
  | leaf suffix value =>
    simp [Serve.Scope.admitsValue, Serve.Scope.admitsKeyPath,
      TrieServeProofs.containsSubtree_append scope tail suffix.toList inside]
  | extension segment child => simp [Serve.Scope.admitsValue] at admitted
  | branch children value =>
    simp [Serve.Scope.admitsValue, Serve.Scope.admitsKeyPath, inside]
  | route children value =>
    simp [Serve.Scope.admitsValue, Serve.Scope.admitsKeyPath, inside]

/-- Below a wholly admitted prefix, the semantic evidence set depends on
the addressed graph, not on the absolute path used to reach that DAG node. -/
theorem needs_rebase_inside {publisher : TrieProgramProofs.RawSnapshot}
    {scope : Serve.Scope} {owner : Option String} {address : ByteArray}
    {path tail : List UInt8} {evidence : Evidence}
    (needed : Needs publisher scope owner address path evidence)
    (inside : scope.containsSubtree path = true)
    (there : scope.containsSubtree tail = true) :
    Needs publisher scope owner address tail evidence := by
  induction needed generalizing tail with
  | node admitted held =>
    exact .node (TrieServeProofs.admitsPath_of_containsSubtree scope tail there) held
  | provenance admitted held =>
    exact .provenance (TrieServeProofs.admitsPath_of_containsSubtree scope tail there) held
  | @value owner hash raw address bytes path node held decoded admitted named valueHeld =>
    exact .value held decoded (admitsValue_inside scope path node admitted there) named valueHeld
  | @extension owner hash raw segment child path evidence held decoded nonempty below ih =>
    exact .extension held decoded nonempty (ih
      (TrieServeProofs.containsSubtree_append scope path segment.toList inside)
      (TrieServeProofs.containsSubtree_append scope tail segment.toList there))
  | @branch owner hash raw child path evidence children branchValue nibble held decoded edge below ih =>
    exact .branch held decoded edge (ih
      (TrieServeProofs.containsSubtree_append scope path [nibble] inside)
      (TrieServeProofs.containsSubtree_append scope tail [nibble] there))
  | @route owner hash raw child path evidence children routeValue nibble held decoded edge below ih =>
    exact .route held decoded edge (ih
      (TrieServeProofs.containsSubtree_append scope path [nibble] inside)
      (TrieServeProofs.containsSubtree_append scope tail [nibble] there))

/-- Equal production visit keys have equal evidence obligations.  Outside a
complete grant the key retains the full path; inside one, `needs_rebase_inside`
justifies the intentional path elision used by fan-out deduplication. -/
theorem positionRequires_of_same_visit (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (left right : Position) (evidence : Evidence)
    (same : visit context.scope left.hash left.path =
      visit context.scope right.hash right.path)
    (required : PositionRequires publisher context left evidence) :
    PositionRequires publisher context right evidence := by
  unfold PositionRequires at required ⊢
  unfold visit at same
  cases leftInside : context.scope.containsSubtree left.path.toList <;>
    cases rightInside : context.scope.containsSubtree right.path.toList <;>
    simp [leftInside, rightInside] at same
  · obtain ⟨_, hashes, paths⟩ := same
    simpa [hashes, paths] using required
  · obtain ⟨_, hashes⟩ := same
    rw [hashes] at required
    exact needs_rebase_inside required leftInside rightInside

theorem initial_accounts [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (reference : Option ByteArray) (root : ByteArray) (replica : Replica)
    (rooted : rootOf root = some root)
    (admitted : context.scope.admitsPath [] = true) :
    FrontierAccountsFor publisher context root replica
      (initial (V := V) (H := H) context reference root) := by
  intro evidence needed
  right
  refine ⟨⟨reference.bind rootOf, root, ByteArray.empty, false⟩, ?_, ?_⟩
  · left
    simp [initial, rooted, admitted]
  · simpa [PositionRequires] using needed

theorem initial_invariant [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (reference : Option ByteArray) (root : ByteArray) (replica : Replica)
    (rooted : rootOf root = some root)
    (admitted : context.scope.admitsPath [] = true) :
    FrontierInvariant publisher context root replica
      (initial (V := V) (H := H) context reference root) :=
  ⟨TrieMissingProofs.initial_admitted context reference root,
    initial_accounts publisher context reference root replica rooted admitted⟩

theorem resume_accounts [WorkSet Visit V] (context : Context)
    (frontier : Frontier V H)
    (accounted : FrontierAccountsFor publisher context root replica frontier) :
    FrontierAccountsFor publisher context root replica (resume context frontier) := by
  intro evidence needed
  rcases accounted evidence needed with verified | ⟨position, pending, requires⟩
  · exact .inl verified
  · right
    refine ⟨position, .inl ?_, requires⟩
    rcases pending with inPositions | inDeferred
    · exact List.mem_append.mpr (.inr inPositions)
    · exact List.mem_append.mpr (.inl inDeferred)

theorem resume_invariant [WorkSet Visit V] (context : Context)
    (frontier : Frontier V H)
    (invariant : FrontierInvariant publisher context root replica frontier) :
    FrontierInvariant publisher context root replica (resume context frontier) :=
  ⟨TrieMissingProofs.resume_admitted context frontier invariant.1,
    resume_accounts context frontier invariant.2⟩

/-- Exhaustion eliminates the outstanding side of the invariant, so every
semantic requirement is verified. -/
theorem exhausted_accounts_complete
    (accounted : FrontierAccountsFor publisher context root replica frontier)
    (exhausted : frontier.isExhausted = true) :
    PermittedComplete publisher context.scope context.owner root replica := by
  intro evidence needed
  rcases accounted evidence needed with verified | ⟨position, pending, requires⟩
  · exact verified
  · simp [Frontier.isExhausted] at exhausted
    rcases pending with inPositions | inDeferred <;> simp_all

theorem exhausted_invariant_complete
    (invariant : FrontierInvariant publisher context root replica frontier)
    (exhausted : frontier.isExhausted = true) :
    PermittedComplete publisher context.scope context.owner root replica :=
  exhausted_accounts_complete invariant.2 exhausted

/-- Moving an absent node to `deferred` retains its obligation.  In
particular a refusal does not become authenticated absence. -/
theorem absent_commit_accounts [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (work : Work V H) (position : Position)
    (rest : List Position) (pending : work.frontier.positions = position :: rest)
    (accounted : FrontierAccountsFor publisher context root replica work.frontier) :
    FrontierAccountsFor publisher context root replica
      (commit context work position rest .absent).frontier := by
  intro evidence needed
  rcases accounted evidence needed with verified | ⟨owed, location, requires⟩
  · exact .inl verified
  · right
    refine ⟨owed, ?_, requires⟩
    rcases location with inPositions | inDeferred
    · rw [pending] at inPositions
      rcases List.mem_cons.mp inPositions with rfl | inRest
      · exact .inr (by simp [commit])
      · exact .inl (by simpa [commit] using inRest)
    · exact .inr (by simp [commit, inDeferred])

theorem absent_commit_not_exhausted [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (work : Work V H) (position : Position)
    (rest : List Position) :
    (commit context work position rest .absent).frontier.isExhausted = false :=
  (TrieMissingProofs.absent_defers context work position rest).2

def PositionSettled (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (replica : Replica) (position : Position) : Prop :=
  ∀ evidence, PositionRequires publisher context position evidence →
    Verified replica evidence

def PositionTransferred (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (replica : Replica) (position : Position)
    (frontier : Frontier V H) : Prop :=
  ∀ evidence, PositionRequires publisher context position evidence →
    Verified replica evidence ∨
      ∃ child, (child ∈ frontier.positions ∨ child ∈ frontier.deferred) ∧
        PositionRequires publisher context child evidence

/-- Every visit admitted to the production deduplication set denotes a
semantically completed position.  Equal visits may arise at distinct paths
inside a wholly granted DAG; `positionRequires_of_same_visit` is the exact
reason this remains sound. -/
def SeenSettled [WorkSet Visit V] (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (replica : Replica) (frontier : Frontier V H) : Prop :=
  ∀ position, WorkSet.contains frontier.seen
      (visit context.scope position.hash position.path) = true →
    PositionSettled publisher context replica position

/-- A finish marker's outstanding obligations are carried only by work before
that marker (its DFS descendants) or by retryable work.  This is the ordered
fact which turns postorder arrival at the head into semantic settlement. -/
def MarkersAccounted (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (replica : Replica) (frontier : Frontier V H) : Prop :=
  ∀ before marker suffix, frontier.positions = before ++ marker :: suffix →
    marker.finish = true →
    ∀ evidence, PositionRequires publisher context marker evidence →
      Verified replica evidence ∨
        ∃ position, (position ∈ before ∨ position ∈ frontier.deferred) ∧
          PositionRequires publisher context position evidence

theorem marker_head_settled
    (accounted : MarkersAccounted publisher context replica frontier)
    (pending : frontier.positions = marker :: rest)
    (finish : marker.finish = true) (ready : frontier.deferred = []) :
    PositionSettled publisher context replica marker := by
  intro evidence required
  rcases accounted [] marker rest (by simpa using pending) finish evidence required with
    verified | ⟨position, location, requires⟩
  · exact verified
  · rcases location with before | deferred
    · simp at before
    · rw [ready] at deferred
      simp at deferred

theorem initial_markers_accounted [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (root : ByteArray) (replica : Replica) :
    MarkersAccounted publisher context replica
      (initial (V := V) (H := H) context none root) := by
  intro before marker suffix positions finish
  simp only [initial] at positions
  split at positions
  · simp at positions
  · split at positions
    · have member : marker ∈ before ++ marker :: suffix := by simp
      rw [← positions] at member
      simp only [List.mem_singleton] at member
      subst marker
      contradiction
    · simp at positions

theorem initial_seen_settled [WorkSet Visit V] [WorkSet ByteArray H]
    [TrieMissingProofs.LawfulWorkSet Visit V]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (root : ByteArray) (replica : Replica) :
    SeenSettled publisher context replica
      (initial (V := V) (H := H) context none root) := by
  intro position seen
  simp only [initial, TrieMissingProofs.LawfulWorkSet.empty] at seen
  contradiction

theorem settle_seen_settled [WorkSet Visit V] [WorkSet ByteArray H]
    [TrieMissingProofs.LawfulWorkSet Visit V]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (replica : Replica) (work : Work V H) (position : Position)
    (rest : List Position)
    (prior : SeenSettled publisher context replica work.frontier)
    (ready : work.frontier.deferred = [] →
      PositionSettled publisher context replica position) :
    SeenSettled publisher context replica (settle context work position rest).frontier := by
  intro probe contained evidence required
  unfold settle at contained
  split at contained
  · rw [TrieMissingProofs.LawfulWorkSet.insert] at contained
    simp only [Bool.or_eq_true] at contained
    rcases contained with same | old
    · have visits : visit context.scope position.hash position.path =
          visit context.scope probe.hash probe.path := eq_of_beq same
      exact ready (by simpa using ‹work.frontier.deferred.isEmpty = true›) evidence
        (positionRequires_of_same_visit publisher context probe position evidence visits.symm required)
    · exact prior probe old evidence required
  · exact prior probe contained evidence required

/-- Removing a finish marker is sound in both concrete branches of
`settle`: with outstanding deferred work it moves to their tail; with none,
its postorder obligation must already be settled. -/
theorem settle_accounts [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (root : ByteArray) (replica : Replica) (work : Work V H)
    (position : Position) (rest : List Position)
    (pending : work.frontier.positions = position :: rest)
    (accounted : FrontierAccountsFor publisher context root replica work.frontier)
    (ready : work.frontier.deferred = [] →
      PositionSettled publisher context replica position) :
    FrontierAccountsFor publisher context root replica
      (settle context work position rest).frontier := by
  intro evidence needed
  rcases accounted evidence needed with verified | ⟨owed, location, requires⟩
  · exact .inl verified
  · rcases location with inPositions | inDeferred
    · rw [pending] at inPositions
      rcases List.mem_cons.mp inPositions with same | inRest
      · have owedEq : owed = position := same
        subst owed
        unfold settle
        split
        · left
          apply ready
          simpa using ‹work.frontier.deferred.isEmpty = true›
          exact requires
        · right
          refine ⟨position, .inr ?_, requires⟩
          exact List.mem_append.mpr (.inr (by simp))
      · right
        refine ⟨owed, .inl ?_, requires⟩
        unfold settle
        split <;> simpa using inRest
    · right
      refine ⟨owed, .inr ?_, requires⟩
      unfold settle
      split
      · exact inDeferred
      · exact List.mem_append.mpr (.inl inDeferred)

theorem settle_accounts_of_markers [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (root : ByteArray) (replica : Replica) (work : Work V H)
    (position : Position) (rest : List Position)
    (pending : work.frontier.positions = position :: rest)
    (finish : position.finish = true)
    (accounted : FrontierAccountsFor publisher context root replica work.frontier)
    (markers : MarkersAccounted publisher context replica work.frontier) :
    FrontierAccountsFor publisher context root replica
      (settle context work position rest).frontier :=
  settle_accounts publisher context root replica work position rest pending accounted
    (fun empty => marker_head_settled markers pending finish empty)

theorem settle_seen_settled_of_markers [WorkSet Visit V] [WorkSet ByteArray H]
    [TrieMissingProofs.LawfulWorkSet Visit V]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (replica : Replica) (work : Work V H) (position : Position)
    (rest : List Position) (pending : work.frontier.positions = position :: rest)
    (finish : position.finish = true)
    (prior : SeenSettled publisher context replica work.frontier)
    (markers : MarkersAccounted publisher context replica work.frontier) :
    SeenSettled publisher context replica (settle context work position rest).frontier := by
  apply settle_seen_settled publisher context replica work position rest prior
  exact fun empty => marker_head_settled markers pending finish empty

theorem settle_markers_accounted [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (replica : Replica) (work : Work V H) (position : Position)
    (rest : List Position) (pending : work.frontier.positions = position :: rest)
    (finish : position.finish = true)
    (markers : MarkersAccounted publisher context replica work.frontier) :
    MarkersAccounted publisher context replica (settle context work position rest).frontier := by
  unfold settle
  split
  · rename_i empty
    have headSettled := marker_head_settled markers pending finish (by simpa using empty)
    intro before marker suffix positions markerFinish evidence required
    change rest = before ++ marker :: suffix at positions
    have oldPositions : work.frontier.positions =
        (position :: before) ++ marker :: suffix := by
      rw [pending, positions]
      rfl
    rcases markers (position :: before) marker suffix oldPositions markerFinish evidence required with
      verified | ⟨witness, location, witnessRequires⟩
    · exact .inl verified
    · rcases location with inPrefix | inDeferred
      · rcases List.mem_cons.mp inPrefix with same | earlier
        · subst witness
          exact .inl (headSettled evidence witnessRequires)
        · exact .inr ⟨witness, .inl earlier, witnessRequires⟩
      · rw [show work.frontier.deferred = [] by simpa using empty] at inDeferred
        simp at inDeferred
  · intro before marker suffix positions markerFinish evidence required
    change rest = before ++ marker :: suffix at positions
    have oldPositions : work.frontier.positions =
        (position :: before) ++ marker :: suffix := by
      rw [pending, positions]
      rfl
    rcases markers (position :: before) marker suffix oldPositions markerFinish evidence required with
      verified | ⟨witness, location, witnessRequires⟩
    · exact .inl verified
    · right
      rcases location with inPrefix | inDeferred
      · rcases List.mem_cons.mp inPrefix with same | earlier
        · subst witness
          exact ⟨position, .inr (List.mem_append.mpr (.inr (by simp))), witnessRequires⟩
        · exact ⟨witness, .inl earlier, witnessRequires⟩
      · exact ⟨witness, .inr (List.mem_append.mpr (.inl inDeferred)), witnessRequires⟩

private theorem pushChildren_keeps_stack (scope : Serve.Scope) (path : ByteArray)
    (children stack : List Position) (position : Position) (member : position ∈ stack) :
    position ∈ pushChildren scope path children stack := by
  induction children generalizing stack with
  | nil => exact member
  | cons child rest ih =>
    simp only [pushChildren, List.foldl_cons]
    split
    · exact ih _ (List.mem_cons_of_mem _ member)
    · exact ih _ member

private theorem byteArray_toList_append (left right : ByteArray) :
    (left ++ right).toList = left.toList ++ right.toList := by
  simp only [ByteArrayProofs.toList_eq_data, ByteArray.data_append, Array.toList_append]

private theorem pushChildren_adds_child (scope : Serve.Scope) (path : ByteArray)
    (children stack : List Position) (child : Position) (member : child ∈ children)
    (admitted : scope.admitsPath (path ++ child.path).toList = true) :
    { child with path := path ++ child.path } ∈ pushChildren scope path children stack := by
  induction children generalizing stack with
  | nil => cases member
  | cons head rest ih =>
    simp only [pushChildren, List.foldl_cons]
    rcases List.mem_cons.mp member with rfl | later
    · rw [admitted]
      exact pushChildren_keeps_stack scope path rest _ _ (List.mem_cons_self ..)
    · split
      · exact ih _ later
      · exact ih _ later

/-- The successful production expansion discharges direct evidence with its
actual reads and transfers recursive evidence to the exact pushed child.  If
a payload is absent, the holder itself remains deferred. -/
theorem inspect_expand_transferred [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (work : Work V H) (position : Position) (rest children : List Position)
    (pendingBranch : Option ByteArray) (absentValues : List ByteArray) (routing : Bool)
    (state final : SimulatedHost.State)
    (authentic : TrieSnapshotProofs.RecordsIncluded
      (replicaOfState state).records publisher)
    (noRef : position.reference = none)
    (ran : execute (inspect context work.frontier position) state =
      (.ok (.expand children pendingBranch absentValues routing), final)) :
    PositionTransferred publisher context (replicaOfState final) position
      (commit context work position rest
        (.expand children pendingBranch absentValues routing)).frontier := by
  obtain ⟨raw, loaded, loadRun, loadedRun⟩ := inspect_expand_decompose
    context work.frontier position state final children pendingBranch absentValues routing noRef ran
  obtain ⟨prepared, valuesStarted, preparedRun, valuesRun,
      preparedChildren, preparedPending, preparedRouting⟩ :=
    inspectLoaded_decompose context work.frontier position raw loaded final
      children pendingBranch absentValues routing loadedRun
  obtain ⟨node, decodedState, decoded, decodedRun⟩ :=
    prepareLoaded_decompose work.frontier position raw loaded valuesStarted prepared preparedRun
  have preparedShape := prepareDecoded_no_reference_shape work.frontier position node
    decodedState valuesStarted prepared noRef decodedRun
  have childrenShape : children = pairedChildren none node :=
    preparedChildren.symm.trans preparedShape.2
  have replicaFinal : replicaOfState final = replicaOfState state := by
    have preserved := inspect_preserves_replica context work.frontier position state
    rw [congrArg Prod.snd ran] at preserved
    exact preserved
  have authenticFinal : TrieSnapshotProofs.RecordsIncluded
      (replicaOfState final).records publisher := by
    simpa [replicaFinal] using authentic
  have loadedPreserved := inspectLoaded_evidence_read context work.frontier position raw
    |>.preserves_observation replicaOfState _ evidence_read_effect_preserves_replica loaded
  change replicaOfState (execute (inspectLoaded context work.frontier position raw) loaded).2 =
    replicaOfState loaded at loadedPreserved
  rw [congrArg Prod.snd loadedRun] at loadedPreserved
  have nodeVerified : Verified (replicaOfState final) (.node position.hash raw) := by
    have atLoaded := loadOwned_some_has_node context.owner position.hash raw state loaded loadRun
    simpa [loadedPreserved] using atLoaded
  have publisherHeld : publisher nodeSpace position.hash = some raw :=
    authenticFinal nodeSpace position.hash raw (.inl rfl) nodeVerified
  intro evidence required
  cases absentValues with
  | cons first more =>
    right
    refine ⟨position, .inr ?_, required⟩
    simp [commit]
  | nil =>
    have valuesRun' : execute (inspectValues context position node) valuesStarted =
        (.ok [], final) := by simpa [preparedShape.1] using valuesRun
    rcases TrieMissingTransfer.needs_direct_or_child publisherHeld decoded required with
      nodeEvidence | provenanceEvidence | valueEvidence | childEvidence
    · subst evidence
      exact .inl nodeVerified
    · obtain ⟨origin, ownerEq, evidenceEq⟩ := provenanceEvidence
      subst evidence
      have ownedRun := loadRun
      rw [ownerEq] at ownedRun
      have provenanceAtLoaded := (loadOwned_some_verified origin position.hash raw state loaded
        ownedRun).2
      exact .inl (by simpa [loadedPreserved] using provenanceAtLoaded)
    · obtain ⟨address, bytes, evidenceEq, member, heldValue, admitted⟩ := valueEvidence
      subst evidence
      obtain ⟨localBytes, localVerified⟩ :=
        inspectValues_none_verified context position node valuesStarted final admitted valuesRun'
          address member
      have publisherLocal := authenticFinal valueSpace address localBytes (.inr rfl) localVerified
      have sameBytes : localBytes = bytes := Option.some.inj (publisherLocal.symm.trans heldValue)
      subst localBytes
      exact .inl localVerified
    · obtain ⟨child, childMember, below⟩ := childEvidence
      let pushed : Position := { child with path := position.path ++ child.path }
      have pushedRequires : PositionRequires publisher context pushed evidence := by
        unfold PositionRequires
        simpa [pushed, byteArray_toList_append] using below
      have childAdmitted : context.scope.admitsPath
          (position.path ++ child.path).toList = true := by
        simpa [pushed] using needs_admitted_at pushedRequires
      right
      refine ⟨pushed, .inl ?_, pushedRequires⟩
      simp only [commit]
      apply pushChildren_adds_child context.scope position.path children
        ({ position with finish := true } :: rest) child
      · simpa [childrenShape] using childMember
      · exact childAdmitted

/-- A skip is safe exactly when the skipped position has already been
settled (by a sound reference or a semantically accounted prior visit).
All unrelated pending and deferred positions survive the concrete commit. -/
theorem skip_commit_accounts [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (work : Work V H) (position : Position)
    (rest : List Position) (pending : work.frontier.positions = position :: rest)
    (accounted : FrontierAccountsFor publisher context root replica work.frontier)
    (settled : PositionSettled publisher context replica position) :
    FrontierAccountsFor publisher context root replica
      (commit context work position rest .skip).frontier := by
  intro evidence needed
  rcases accounted evidence needed with verified | ⟨owed, location, requires⟩
  · exact .inl verified
  · rcases location with inPositions | inDeferred
    · rw [pending] at inPositions
      rcases List.mem_cons.mp inPositions with rfl | inRest
      · exact .inl (settled evidence requires)
      · exact .inr ⟨owed, .inl (by simpa [commit] using inRest), requires⟩
    · exact .inr ⟨owed, .inr (by simpa [commit] using inDeferred), requires⟩

theorem skip_commit_accounts_of_seen [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (work : Work V H) (position : Position)
    (rest : List Position) (pending : work.frontier.positions = position :: rest)
    (accounted : FrontierAccountsFor publisher context root replica work.frontier)
    (settledSeen : SeenSettled publisher context replica work.frontier)
    (seen : WorkSet.contains work.frontier.seen
      (visit context.scope position.hash position.path) = true) :
    FrontierAccountsFor publisher context root replica
      (commit context work position rest .skip).frontier :=
  skip_commit_accounts context work position rest pending accounted
    (settledSeen position seen)

private theorem accounts_congr_lists (left right : Frontier V H)
    (positions : left.positions = right.positions)
    (deferred : left.deferred = right.deferred)
    (accounted : FrontierAccountsFor publisher context root replica left) :
    FrontierAccountsFor publisher context root replica right := by
  intro evidence needed
  rcases accounted evidence needed with verified | ⟨position, location, requires⟩
  · exact .inl verified
  · right
    refine ⟨position, ?_, requires⟩
    rcases location with pending | delayed
    · exact .inl (by simpa [positions] using pending)
    · exact .inr (by simpa [deferred] using delayed)

/-- `boundary` has the same frontier effect as `skip`; callers must supply
the independent boundary-completion fact. -/
theorem boundary_commit_accounts [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (work : Work V H) (position : Position)
    (rest : List Position) (pending : work.frontier.positions = position :: rest)
    (accounted : FrontierAccountsFor publisher context root replica work.frontier)
    (settled : PositionSettled publisher context replica position) :
    FrontierAccountsFor publisher context root replica
      (commit context work position rest .boundary).frontier := by
  apply accounts_congr_lists
    (commit context work position rest .skip).frontier
    (commit context work position rest .boundary).frontier
  · rfl
  · rfl
  · exact skip_commit_accounts context work position rest pending accounted settled

/-- Expansion preserves global accounting once the successfully inspected
position's requirements have either become verified or moved to one of the
concrete child/deferred positions produced by `commit`. -/
theorem expand_commit_accounts [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (work : Work V H) (position : Position)
    (rest children : List Position) (pendingBranch : Option ByteArray)
    (absentValues : List ByteArray) (routing : Bool)
    (pending : work.frontier.positions = position :: rest)
    (accounted : FrontierAccountsFor publisher context root before work.frontier)
    (included : EvidenceIncluded before after)
    (transferred : PositionTransferred publisher context after position
      (commit context work position rest
        (.expand children pendingBranch absentValues routing)).frontier) :
    FrontierAccountsFor publisher context root after
      (commit context work position rest
        (.expand children pendingBranch absentValues routing)).frontier := by
  intro evidence needed
  rcases accounted evidence needed with verified | ⟨owed, location, requires⟩
  · exact .inl (included evidence verified)
  · rcases location with inPositions | inDeferred
    · rw [pending] at inPositions
      rcases List.mem_cons.mp inPositions with rfl | inRest
      · exact transferred evidence requires
      · exact .inr ⟨owed, .inl (by
          simp only [commit]
          apply pushChildren_keeps_stack
          split
          · exact List.mem_cons_of_mem _ inRest
          · exact inRest), requires⟩
    · right
      refine ⟨owed, .inr ?_, requires⟩
      simp only [commit]
      split
      · exact inDeferred
      · exact List.mem_cons_of_mem _ inDeferred

theorem failed_accounts (frontier : Frontier V H) (error : Missing.Error)
    (accounted : FrontierAccountsFor publisher context root replica frontier) :
    FrontierAccountsFor publisher context root replica (failed frontier error) := by
  cases error <;> exact accounted

/-- Host/decode interruption commits no negative fact: the exact actual
`batchStep` result retains the accounting invariant. -/
theorem interrupted_batchStep_accounts [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (maximum : Nat) (work : Work V H)
    (position : Position) (rest : List Position) (state after : SimulatedHost.State)
    (error : Missing.Error) (healthy : work.frontier.fault = none)
    (pending : work.frontier.positions = position :: rest)
    (entering : position.finish = false)
    (room : work.batch.size < maximum)
    (accounted : FrontierAccountsFor publisher context root replica work.frontier)
    (interrupted : execute (inspect context work.frontier position) state = (.error error, after)) :
    execute (batchStep context maximum work) state =
        (.ok (.inr (failed work.frontier error, .error error)), after) ∧
      FrontierAccountsFor publisher context root replica (failed work.frontier error) ∧
      (failed work.frontier error).isExhausted = false :=
  ⟨TrieMissingProofs.batchStep_interrupted context maximum work position rest state after error
      healthy pending entering room interrupted,
    failed_accounts work.frontier error accounted,
    by cases error <;> simp [failed, Frontier.isExhausted, pending]⟩

/-! `Complete.inspectRoot` always starts without a reference.  The following
facts isolate that production specialization before reasoning about visited
DAG nodes.  In particular, `.boundary` is not returned by today's `inspect`
implementation and reference pruning cannot arise from a no-reference
frontier. -/

def NoReferences (frontier : Frontier V H) : Prop :=
  (∀ position ∈ frontier.positions, position.reference = none) ∧
    ∀ position ∈ frontier.deferred, position.reference = none

theorem initial_no_references [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) :
    NoReferences (initial (V := V) (H := H) context none root) := by
  constructor <;> intro position member
  · simp only [initial] at member
    split at member
    · simp at member
    · split at member
      · simp only [List.mem_cons, List.not_mem_nil, or_false] at member
        subst position
        rfl
      · simp at member
  · simp [initial] at member

theorem pairedChildren_none_have_no_references (node : Node) :
    ∀ child ∈ pairedChildren none node, child.reference = none := by
  intro child member
  cases node with
  | leaf suffix value => simp [pairedChildren] at member
  | extension segment hash =>
    simp only [pairedChildren, List.mem_cons, List.not_mem_nil, or_false] at member
    subst child
    rfl
  | branch children value =>
    simp only [pairedChildren] at member
    rcases List.mem_filterMap.mp member with ⟨entry, inEntries, made⟩
    rcases entry with ⟨candidate, index⟩
    cases candidate <;> simp_all
    subst child
    rfl
  | route children value =>
    simp only [pairedChildren] at member
    rcases List.mem_filterMap.mp member with ⟨entry, inEntries, made⟩
    rcases entry with ⟨candidate, index⟩
    cases candidate <;> simp_all
    subst child
    rfl

/-- The remaining positive-walk obligation: successful `inspect`/`commit`
steps must preserve semantic accounting.  This contract names that precise
frontier proof boundary without assuming completion. -/
def InspectRootAccounts (V H : Type) [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) : Prop :=
  ∀ (started walked : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch),
    execute (Complete.inspectRoot V H context root) started =
      (.ok (frontier, .ok batch), walked) →
    FrontierAccountsFor publisher context root (replicaOfState walked) frontier

theorem inspectRoot_exhausted_complete
    [WorkSet Visit V] [WorkSet ByteArray H]
    (sound : InspectRootAccounts V H publisher context root)
    (ran : execute (Complete.inspectRoot V H context root) started =
      (.ok (frontier, .ok batch), walked))
    (exhausted : frontier.isExhausted = true) :
    PermittedComplete publisher context.scope context.owner root (replicaOfState walked) :=
  exhausted_accounts_complete (sound started walked frontier batch ran) exhausted

/-- Meaning assigned by the host to retained memo certificates.  The key is
the one actually computed by production `Memo.keyFor`; digest collisions and
scope/owner mismatches therefore cannot be silently ignored by the proof. -/
def MemoSound (publisher : TrieProgramProofs.RawSnapshot)
    (state : SimulatedHost.State) : Prop :=
  ∀ (context : Context) (root key : ByteArray) (keyed : SimulatedHost.State),
    execute (Memo.keyFor (E := Complete.Effects) Missing.Error.host
      context.scope root context.owner) state = (.ok key, keyed) →
    keyed.certified.contains key = true →
    PermittedComplete publisher context.scope context.owner root (replicaOfState keyed)

theorem memo_known_true_is_retained (key : ByteArray) (state checked : SimulatedHost.State)
    (ran : execute (Complete.memo (.isKnown key)) state = (.ok true, checked)) :
    state.certified.contains key = true ∧ replicaOfState checked = replicaOfState state := by
  unfold Complete.memo at ran
  simp only [raise, performOver, ExceptT.mk, Inject.inject, execute,
    Interpreter.handle, SimulatedHost.memo] at ran
  unfold reply at ran
  split at ran
  · cases ran
  · have answer : (!state.memoBlocked && state.certified.contains key) = true :=
      Except.ok.inj (congrArg Prod.fst ran)
    have checkedEq := congrArg Prod.snd ran
    dsimp at checkedEq
    have retained : state.certified.contains key = true :=
      ((Bool.and_eq_true _ _).mp answer).2
    refine ⟨retained, ?_⟩
    rw [← checkedEq]
    rfl

theorem memo_certify_preserves_replica (key : ByteArray) (generation : UInt64)
    (state checked : SimulatedHost.State)
    (ran : execute (Complete.memo (.certify key generation)) state = (.ok true, checked)) :
    replicaOfState checked = replicaOfState state := by
  unfold Complete.memo at ran
  simp only [raise, performOver, ExceptT.mk, Inject.inject, execute,
    Interpreter.handle, SimulatedHost.memo] at ran
  unfold reply at ran
  split at ran
  · cases ran
  · have checkedEq := congrArg Prod.snd ran
    dsimp at checkedEq
    rw [← checkedEq]
    rfl

theorem recheck_true_is_complete [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (root key : ByteArray) (state final : SimulatedHost.State)
    (walkSound : InspectRootAccounts V H publisher context root)
    (ran : execute (Complete.recheck V H context root key) state = (.ok true, final)) :
    PermittedComplete publisher context.scope context.owner root (replicaOfState final) := by
  obtain ⟨generation, started, walked, frontier, batch, ticket, walk, exhausted, certified⟩ :=
    TrieCompleteProofs.recheck_true_has_original_ticket (V := V) (H := H)
      context root key state (congrArg Prod.fst ran)
  have completeAtWalk :
      PermittedComplete publisher context.scope context.owner root (replicaOfState walked) :=
    inspectRoot_exhausted_complete walkSound walk exhausted
  have execution := TrieCompleteProofs.recheck_after_walk context root key state started walked
    generation frontier batch ticket walk
  rw [exhausted] at execution
  rw [execution] at ran
  have sameReplica := memo_certify_preserves_replica key generation walked final ran
  simpa [sameReplica] using completeAtWalk

/-- The production cached branch is independently closed: a retained key
whose host contract is sound needs no frontier premise. -/
theorem isComplete_known_path_is_complete [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (root key : ByteArray) (state keyed checked final : SimulatedHost.State)
    (memoSound : MemoSound publisher state)
    (keyRun : execute (Memo.keyFor (E := Complete.Effects) Missing.Error.host
      context.scope root context.owner) state = (.ok key, keyed))
    (knownRun : execute (Complete.memo (.isKnown key)) keyed = (.ok true, checked))
    (ran : execute (Complete.isComplete V H context root) state = (.ok true, final)) :
    PermittedComplete publisher context.scope context.owner root (replicaOfState final) := by
  have retained := memo_known_true_is_retained key keyed checked knownRun
  have completeAtKeyed := memoSound context root key keyed keyRun retained.1
  have decomposed : execute (Complete.isComplete V H context root) state = (.ok true, checked) := by
    unfold Complete.isComplete
    simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
    rw [keyRun]
    simp only
    rw [execute_bind, knownRun]
    rfl
  have sameFinal : checked = final := congrArg Prod.snd (decomposed.symm.trans ran)
  subst final
  simpa [retained.2] using completeAtKeyed

/-- Soundness of the actual `isComplete` result.  The fresh-walk branch is
justified by frontier accounting; the cached branch is justified by
`MemoSound`, never by the Boolean cache answer alone. -/
theorem isComplete_true_is_complete [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context)
    (root : ByteArray) (state final : SimulatedHost.State)
    (memoSound : MemoSound publisher state)
    (walkSound : InspectRootAccounts V H publisher context root)
    (ran : execute (Complete.isComplete V H context root) state = (.ok true, final)) :
    PermittedComplete publisher context.scope context.owner root (replicaOfState final) := by
  have success : (execute (Complete.isComplete V H context root) state).1 = .ok true :=
    congrArg Prod.fst ran
  unfold Complete.isComplete at success
  obtain ⟨key, keyed, keyRun, ranFirst⟩ := TrieServePrivacyProofs.bind_ok
    (Memo.keyFor (E := Complete.Effects) Missing.Error.host
      context.scope root context.owner)
    (fun key => do
      if ← Complete.memo (.isKnown key) then return true
      Complete.recheck V H context root key)
    state true success
  obtain ⟨known, checked, knownRun, resultFirst⟩ := TrieServePrivacyProofs.bind_ok
    (Complete.memo (.isKnown key))
    (fun known => if known then pure true else Complete.recheck V H context root key)
    keyed true ranFirst
  let tail : Complete.Action Bool :=
    if known then pure true else Complete.recheck V H context root key
  have decomposed : execute (Complete.isComplete V H context root) state = execute tail checked := by
    unfold Complete.isComplete
    simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
    rw [keyRun]
    simp only
    rw [execute_bind, knownRun]
    rfl
  have tailRun : execute tail checked = (.ok true, final) := decomposed.symm.trans ran
  cases known with
  | true =>
    have retained := memo_known_true_is_retained key keyed checked knownRun
    have completeAtKeyed := memoSound context root key keyed keyRun retained.1
    simp only [tail, ↓reduceIte, pure, ExceptT.pure, ExceptT.mk, execute] at tailRun
    cases tailRun
    simpa [retained.2] using completeAtKeyed
  | false =>
    simp only [tail, Bool.false_eq] at tailRun
    exact recheck_true_is_complete publisher context root key checked final walkSound tailRun

end Synchronicity.TrieMissingCompletion
