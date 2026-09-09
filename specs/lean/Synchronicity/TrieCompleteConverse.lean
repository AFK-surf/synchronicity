import Synchronicity.TrieMissingCompletion
import Synchronicity.PromotionProgress

/-! A positive execution certificate for the production completeness walk.
Unlike a premise that merely assumes `isComplete = true`, `WalkOpportunity`
records the finite sequence of actual host replies consumed by
`Program.iterate`.  Its terminal condition is the concrete empty production
work queues, and its step index must fit the production fuel bound. -/
namespace Synchronicity.TrieCompleteConverse
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open VerifiedCore.Trie.Missing SimulatedHost
open TrieFetchCompletion TrieFetchAdmissionProgress TrieMissingCompletion

/-- A finite, host-specific opportunity for an effect-counted trampoline to
reach an ordinary batch result with no pending or retryable positions.  It
does not contain an execution of `nextBatch`, `inspectRoot`, or `isComplete`.
Requests are justified one primitive host reply at a time. -/
inductive WalkOpportunity [Interpreter E]
    (body : Work V H → Program E (Except Missing.Error (Work V H ⊕ BatchResult V H))) :
    Nat → Program E (Except Missing.Error (Work V H ⊕ BatchResult V H)) →
      SimulatedHost.State → Frontier V H → Batch → SimulatedHost.State → Prop where
  | stopped (state : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch) :
      WalkOpportunity body 1 (.pure (.ok (.inr (frontier, .ok batch))))
        state frontier batch state
  | continued (next : Work V H) (state : SimulatedHost.State)
      (plan : WalkOpportunity body steps (body next) state frontier batch final) :
      WalkOpportunity body (steps + 1) (.pure (.ok (.inl next)))
        state frontier batch final
  | requested (effect : E A) (resume : A →
      Program E (Except Missing.Error (Work V H ⊕ BatchResult V H)))
      (state after : SimulatedHost.State) (reply : A)
      (handled : Interpreter.handle effect state = (reply, after))
      (plan : WalkOpportunity body steps (resume reply) after frontier batch final) :
      WalkOpportunity body (steps + 1) (.request effect resume)
        state frontier batch final

theorem WalkOpportunity.execute {body : Work V H →
    Program E (Except Missing.Error (Work V H ⊕ BatchResult V H))}
    [Interpreter E]
    (plan : WalkOpportunity body steps program state frontier batch final)
    (fits : steps ≤ fuel) :
    execute (Program.iterate body Missing.Error.exhausted fuel program) state =
      (.ok (frontier, .ok batch), final) := by
  induction plan generalizing fuel with
  | stopped state frontier batch =>
    cases fuel with
    | zero => omega
    | succ fuel => rfl
  | continued next state plan ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      simp only [Program.iterate]
      exact ih (Nat.le_of_succ_le_succ fits)
  | requested effect resume state after reply handled plan ih =>
    cases fuel with
    | zero => omega
    | succ fuel =>
      rw [SimulatedHost.execute_iterate_request, handled]
      exact ih (Nat.le_of_succ_le_succ fits)

abbrev MissingWalkOpportunity [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) (steps : Nat)
    (state : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (final : SimulatedHost.State) : Prop :=
  let initialWork : Work V H :=
    ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩
  WalkOpportunity (fun work => (batchStep context 1 work).run) steps
    (batchStep context 1 initialWork).run state frontier batch final

theorem nextBatch_exec_of_opportunity [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) (steps : Nat)
    (state final : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (plan : MissingWalkOpportunity context root steps state frontier batch final)
    (fits : steps ≤ batchFuel) :
    execute (nextBatch context (initial (V := V) (H := H) context none root) 1) state =
      (.ok (frontier, .ok batch), final) := by
  unfold MissingWalkOpportunity at plan
  unfold nextBatch OperationOver.iterate
  exact plan.execute fits

theorem inspectRoot_exec_of_opportunity [WorkSet Visit V] [WorkSet ByteArray H]
    (context : Context) (root : ByteArray) (steps : Nat)
    (state final : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (plan : MissingWalkOpportunity context root steps state frontier batch final)
    (fits : steps ≤ batchFuel) :
    execute (Complete.inspectRoot V H context root) state =
      (.ok (frontier, .ok batch), final) := by
  have missingRun := nextBatch_exec_of_opportunity context root steps state final
    frontier batch plan fits
  unfold Complete.inspectRoot
  calc
    execute ((nextBatch context (initial (V := V) (H := H) context none root) 1).run.mapEffects
      (fun {A} (effect : Missing.Effects A) =>
        (Inject.inject effect : Complete.Effects A))) state =
        execute (nextBatch context (initial (V := V) (H := H) context none root) 1).run state :=
      SimulatedHost.execute_mapEffects (E := Missing.Effects) (F := Complete.Effects)
        Inject.inject (fun effect state => by
          cases effect with
          | left storageEffect => rfl
          | right other => cases other <;> rfl) _ _
    _ = (.ok (frontier, .ok batch), final) := missingRun

private theorem mapEffects_iterate
    {E F : Type → Type}
    (body : S → Program E (Except ε (S ⊕ R))) (exhausted : ε)
    (inject : {A : Type} → E A → F A) : ∀ fuel program,
    (Program.iterate body exhausted fuel program).mapEffects inject =
      Program.iterate (fun next => (body next).mapEffects inject) exhausted fuel
        (program.mapEffects inject) := by
  intro fuel
  induction fuel with
  | zero => intro program; rfl
  | succ fuel ih =>
    intro program
    cases program with
    | pure result =>
      rcases result with error | result
      · rfl
      · rcases result with next | answer
        · exact ih _
        · rfl
    | request effect resume =>
      simp only [Program.iterate, Program.mapEffects]
      congr 1
      funext reply
      exact ih _

private theorem mapEffects_compose {E F G : Type → Type}
    (first : {A : Type} → E A → F A)
    (second : {A : Type} → F A → G A) : ∀ (program : Program E A),
    (program.mapEffects first).mapEffects second =
      program.mapEffects (fun effect => second (first effect)) := by
  intro program
  induction program with
  | pure value => rfl
  | request effect resume ih =>
    simp only [Program.mapEffects]
    congr 1
    funext reply
    exact ih reply

private theorem mapEffects_bind {E F : Type → Type}
    (inject : {A : Type} → E A → F A) :
    ∀ (program : Program E A) (next : A → Program E B),
      (program.bind next).mapEffects inject =
        (program.mapEffects inject).bind (fun answer => (next answer).mapEffects inject) := by
  intro program next
  induction program with
  | pure value => rfl
  | request effect resume ih =>
    simp only [Program.bind, Program.mapEffects]
    congr 1
    funext reply
    exact ih reply

private theorem execute_mapped_bind_ok {E F : Type → Type} [Interpreter F]
    (inject : {A : Type} → E A → F A)
    (operation : OperationOver E ε A) (next : A → OperationOver E ε B)
    (state middle : SimulatedHost.State) (answer : A)
    (ran : execute (operation.run.mapEffects inject) state = (.ok answer, middle)) :
    execute ((operation >>= next).run.mapEffects inject) state =
      execute ((next answer).run.mapEffects inject) middle := by
  change execute ((operation.run.bind (ExceptT.bindCont next)).mapEffects inject) state = _
  rw [mapEffects_bind, SimulatedHost.execute_bind, ran]
  rfl

private def promoteMissing (tx : Transaction) :
    {A : Type} → Missing.Effects A → Replication.Promote.Effects A :=
  fun effect => Replication.Promote.inTransaction tx
    (Inject.inject effect : Complete.Effects _)

private theorem promotion_readBytes_of_verified
    (tx : Transaction) (space : String) (address bytes : ByteArray)
    (state : SimulatedHost.State) (quiet : state.faults = [])
    (verified : readableBytes state space address = some bytes) :
    ∃ final,
      execute ((Missing.storage (.readBytes space address)).run.mapEffects
        (promoteMissing tx)) state = (.ok (some bytes), final) ∧
      replicaOfState final = replicaOfState state ∧ final.faults = [] := by
  refine ⟨SimulatedHost.record state ("bytes:" ++ space), ?_, ?_, ?_⟩
  · have readOk : readByteObject state space address = .ok (some bytes) := by
      unfold readableBytes at verified
      cases found : readByteObject state space address <;> simp [found] at verified ⊢
      exact verified
    rw [show ((Missing.storage (.readBytes space address)).run.mapEffects
        (promoteMissing tx)) = Program.request
          (promoteMissing tx (.left (.readBytes space address)))
          (fun result => .pure (Except.mapError Missing.Error.host result)) by rfl]
    simp [promoteMissing, Replication.Promote.inTransaction, Inject.inject,
      execute, Interpreter.handle, SimulatedHost.storage, SimulatedHost.reply,
      SimulatedHost.fault, quiet, readOk]
  · rfl
  · simpa [SimulatedHost.record] using quiet

private theorem promotion_valueAbsent_false
    (tx : Transaction) (node : Node) (address bytes : ByteArray)
    (state : SimulatedHost.State) (quiet : state.faults = [])
    (verified : Verified (replicaOfState state) (.value address bytes))
    (bounded : bytes.size ≤ maxValueBytes)
    (sized : isRoute node = true ∨ inlineValueMax < bytes.size) :
    ∃ final,
      execute ((valueAbsent node address).run.mapEffects (promoteMissing tx)) state =
        (.ok false, final) ∧
      replicaOfState final = replicaOfState state ∧ final.faults = [] := by
  obtain ⟨read, readRun, replicaEq, quietRead⟩ :=
    promotion_readBytes_of_verified tx valueSpace address bytes state quiet verified
  let tail : Option ByteArray → Missing.Action Bool := fun answer =>
    match answer with
    | none => pure true
    | some bytes =>
        if bytes.size > maxValueBytes || (!isRoute node && bytes.size ≤ inlineValueMax) then
          throw (.canonical (.valueLength address bytes.size (isRoute node)))
        else pure false
  have sequence := execute_mapped_bind_ok (promoteMissing tx)
    (Missing.storage (.readBytes valueSpace address)) tail state read (some bytes) readRun
  have validProp : ¬ (maxValueBytes < bytes.size ∨
      (isRoute node = false ∧ bytes.size ≤ inlineValueMax)) := by
    intro bad
    rcases bad with tooLarge | ⟨notRoute, small⟩
    · omega
    · rcases sized with routed | large
      · rw [routed] at notRoute
        contradiction
      · omega
  refine ⟨read, ?_, replicaEq, quietRead⟩
  rw [show valueAbsent node address =
      Missing.storage (.readBytes valueSpace address) >>= tail by rfl]
  rw [sequence]
  simp [tail, validProp]
  rfl

private theorem promotion_inspectValuesAux_nil
    (tx : Transaction) (node : Node) (addresses : List ByteArray)
    (state : SimulatedHost.State) (quiet : state.faults = [])
    (available : ∀ address ∈ addresses, ∃ bytes,
      Verified (replicaOfState state) (.value address bytes) ∧
      bytes.size ≤ maxValueBytes ∧
      (isRoute node = true ∨ inlineValueMax < bytes.size)) :
    ∃ final,
      execute ((inspectValuesAux node addresses).run.mapEffects (promoteMissing tx)) state =
        (.ok [], final) ∧
      replicaOfState final = replicaOfState state ∧ final.faults = [] := by
  induction addresses generalizing state with
  | nil => exact ⟨state, rfl, rfl, quiet⟩
  | cons head rest ih =>
      obtain ⟨bytes, verified, bounded, sized⟩ := available head (by simp)
      obtain ⟨checked, headRun, replicaHead, quietHead⟩ :=
        promotion_valueAbsent_false tx node head bytes state quiet verified bounded sized
      have availableRest : ∀ address ∈ rest, ∃ bytes,
          Verified (replicaOfState checked) (.value address bytes) ∧
          bytes.size ≤ maxValueBytes ∧
          (isRoute node = true ∨ inlineValueMax < bytes.size) := by
        intro address member
        obtain ⟨payload, held, bounded, sized⟩ :=
          available address (List.mem_cons_of_mem head member)
        exact ⟨payload, by simpa [replicaHead] using held, bounded, sized⟩
      obtain ⟨final, restRun, replicaRest, quietFinal⟩ :=
        ih checked quietHead availableRest
      let afterHead : Bool → Missing.Action (List ByteArray) := fun absent => do
        let more ← inspectValuesAux node rest
        return if absent then head :: more else more
      have headTail := execute_mapped_bind_ok (promoteMissing tx)
        (valueAbsent node head) afterHead state checked false headRun
      let finish : List ByteArray → Missing.Action (List ByteArray) := fun more =>
        pure more
      have restTail := execute_mapped_bind_ok (promoteMissing tx)
        (inspectValuesAux node rest) finish checked final [] restRun
      refine ⟨final, ?_, replicaRest.trans replicaHead, quietFinal⟩
      rw [show inspectValuesAux node (head :: rest) =
          valueAbsent node head >>= afterHead by rfl]
      rw [headTail]
      change execute (((inspectValuesAux node rest >>= finish).run.mapEffects
        (promoteMissing tx))) checked = _
      rw [restTail]
      rfl

private theorem promotion_inspectValues_nil
    (tx : Transaction) (context : Context) (position : Position) (node : Node)
    (state : SimulatedHost.State) (quiet : state.faults = [])
    (available : context.scope.admitsValue position.path.toList node = true →
      ∀ address ∈ node.valueHashes, ∃ bytes,
        Verified (replicaOfState state) (.value address bytes) ∧
        bytes.size ≤ maxValueBytes ∧
        (isRoute node = true ∨ inlineValueMax < bytes.size)) :
    ∃ final,
      execute ((inspectValues context position node).run.mapEffects
        (promoteMissing tx)) state = (.ok [], final) ∧
      replicaOfState final = replicaOfState state ∧ final.faults = [] := by
  unfold inspectValues
  cases admitted : context.scope.admitsValue position.path.toList node with
  | false => exact ⟨state, by simp; rfl, rfl, quiet⟩
  | true =>
      simpa [admitted] using
        promotion_inspectValuesAux_nil tx node node.valueHashes state quiet (available admitted)

abbrev PromotionWalkOpportunity [WorkSet Visit V] [WorkSet ByteArray H]
    (tx : Transaction) (context : Context) (root : ByteArray) (steps : Nat)
    (state : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (final : SimulatedHost.State) : Prop :=
  let initialWork : Work V H :=
    ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩
  WalkOpportunity
    (fun work => (batchStep context 1 work).run.mapEffects (promoteMissing tx)) steps
    ((batchStep context 1 initialWork).run.mapEffects (promoteMissing tx))
    state frontier batch final

theorem promotion_inspectRoot_exec_of_opportunity
    [WorkSet Visit V] [WorkSet ByteArray H]
    (tx : Transaction) (context : Context) (root : ByteArray) (steps : Nat)
    (state final : SimulatedHost.State) (frontier : Frontier V H) (batch : Batch)
    (plan : PromotionWalkOpportunity tx context root steps state frontier batch final)
    (fits : steps ≤ batchFuel) :
    execute ((Complete.inspectRoot V H context root).run.mapEffects
      (Replication.Promote.inTransaction tx)) state =
        (.ok (frontier, .ok batch), final) := by
  unfold PromotionWalkOpportunity at plan
  have ran := plan.execute fits
  have lifted : (Complete.inspectRoot V H context root).run.mapEffects
      (Replication.Promote.inTransaction tx) =
      Program.iterate
        (fun work => (batchStep context 1 work).run.mapEffects (promoteMissing tx))
        Missing.Error.exhausted batchFuel
        ((batchStep context 1
          ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩).run.mapEffects
            (promoteMissing tx)) := by
    unfold Complete.inspectRoot nextBatch OperationOver.iterate
    change
      ((Program.iterate (fun work => (batchStep context 1 work).run)
        Missing.Error.exhausted batchFuel
        (batchStep context 1
          ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩).run).mapEffects
          (fun {A} (effect : Missing.Effects A) =>
            (Inject.inject effect : Complete.Effects A))).mapEffects
          (Replication.Promote.inTransaction tx) = _
    rw [mapEffects_compose, mapEffects_iterate]
    rfl
  rw [lifted]
  exact ran

/-- Every local obligation represented by a production position is also an
obligation of the selected root.  This is the forward structural invariant
needed by the positive walk; unlike frontier accounting it rules out a
spurious missing request once the root is semantically complete. -/
def PositionInherited (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) (position : Position) : Prop :=
  ∀ evidence, TrieMissingCompletion.PositionRequires publisher context position evidence →
    Needs publisher context.scope context.owner root [] evidence

def FrontierInherited (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) (frontier : Frontier V H) : Prop :=
  (∀ position ∈ frontier.positions, PositionInherited publisher context root position) ∧
    ∀ position ∈ frontier.deferred, PositionInherited publisher context root position

/-- Operational state maintained while semantic completion rules out every
missing-node/value branch.  Empty batch/deferred fields are consequences to
preserve, not a terminal result supplied by an opportunity. -/
def CompleteWork (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) (work : Work V H) : Prop :=
  work.frontier.fault = none ∧ work.frontier.deferred = [] ∧
  work.batch = {} ∧ FrontierInherited publisher context root work.frontier

def FrontierClosed (publisher : TrieProgramProofs.RawSnapshot)
    (frontier : Frontier V H) : Prop :=
  (∀ position ∈ frontier.positions,
      TrieSnapshotClosure.Closed publisher position.hash) ∧
    ∀ position ∈ frontier.deferred,
      TrieSnapshotClosure.Closed publisher position.hash

def CanonicalWork (publisher : TrieProgramProofs.RawSnapshot)
    (context : Context) (root : ByteArray) (work : Work V H) : Prop :=
  CompleteWork publisher context root work ∧
    TrieMissingProofs.WorkAdmitted context.scope work ∧
    NoReferences work.frontier ∧ FrontierClosed publisher work.frontier

theorem initial_completeWork [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context) (root : ByteArray) :
    CompleteWork publisher context root
      ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩ := by
  refine ⟨rfl, rfl, rfl, ?_⟩
  constructor
  · intro position member evidence required
    unfold initial at member
    cases rooted : rootOf root with
    | none => simp [rooted] at member
    | some hash =>
      have hashEq : hash = root := by
        unfold rootOf at rooted
        split at rooted <;> simp_all
      subst hash
      cases admitted : context.scope.admitsPath [] with
      | false => simp [rooted, admitted] at member
      | true =>
        simp only [rooted, admitted, ↓reduceIte, List.mem_cons,
          List.not_mem_nil, or_false] at member
        subst position
        simpa [TrieMissingCompletion.PositionRequires] using required
  · intro position member
    simp [initial] at member

private theorem initial_closed [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context) (root : ByteArray)
    (stored : TrieSnapshotClosure.StoredSnapshot publisher root) :
    FrontierClosed publisher (initial (V := V) (H := H) context none root) := by
  constructor
  · intro position member
    unfold initial at member
    cases rooted : rootOf root with
    | none => simp [rooted] at member
    | some hash =>
      have hashEq : hash = root := by
        unfold rootOf at rooted
        split at rooted <;> simp_all
      have closedHash : TrieSnapshotClosure.Closed publisher hash := by
        rcases stored with empty | closed
        · change root.data.all (fun x => x == 0) 0 root.size = true at empty
          have emptyRoot : rootOf root = none := by simp [rootOf, empty]
          rw [emptyRoot] at rooted
          contradiction
        · simpa [hashEq] using closed
      simp only [rooted] at member
      split at member
      · rcases List.mem_singleton.mp member with rfl
        exact closedHash
      · simp at member
  · intro position member
    simp [initial] at member

private theorem initial_canonicalWork [WorkSet Visit V] [WorkSet ByteArray H]
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context) (root : ByteArray)
    (stored : TrieSnapshotClosure.StoredSnapshot publisher root) :
    CanonicalWork publisher context root
      ⟨initial (V := V) (H := H) context none root, {}, WorkSet.empty ByteArray⟩ := by
  refine ⟨initial_completeWork publisher context root, ?_,
    initial_no_references context root, initial_closed publisher context root stored⟩
  exact ⟨TrieMissingProofs.initial_admitted context none root, by simp [TrieMissingProofs.BatchAdmitted,
    TrieMissingProofs.WantsAdmitted]⟩

private theorem closed_paired_child
    {publisher : TrieProgramProofs.RawSnapshot} {hash raw : ByteArray} {node : Node}
    (closed : TrieSnapshotClosure.Closed publisher hash)
    (held : publisher nodeSpace hash = some raw) (decoded : decode raw = .ok node)
    (child : Position) (member : child ∈ pairedChildren none node) :
    TrieSnapshotClosure.Closed publisher child.hash := by
  cases closed with
  | leaf stored decodedClosed payload =>
      have sameRaw := Option.some.inj (stored.symm.trans held)
      subst raw
      have sameNode := Except.ok.inj (decodedClosed.symm.trans decoded)
      subst node
      simp [pairedChildren] at member
  | extension stored decodedClosed nonempty below =>
      have sameRaw := Option.some.inj (stored.symm.trans held)
      subst raw
      have sameNode := Except.ok.inj (decodedClosed.symm.trans decoded)
      subst node
      simp only [pairedChildren, List.mem_cons, List.not_mem_nil, or_false] at member
      subst child
      exact below
  | branch stored decodedClosed payload below =>
      have sameRaw := Option.some.inj (stored.symm.trans held)
      subst raw
      have sameNode := Except.ok.inj (decodedClosed.symm.trans decoded)
      subst node
      simp only [pairedChildren] at member
      rcases List.mem_filterMap.mp member with ⟨entry, inEntries, made⟩
      rcases entry with ⟨candidate, index⟩
      cases candidate with
      | none => simp at made
      | some address =>
          simp only [Option.map_some] at made
          have childEq := Option.some.inj made
          subst child
          exact below index address (List.mk_mem_zipIdx_iff_getElem?.mp inEntries)
  | route stored decodedClosed payload below =>
      have sameRaw := Option.some.inj (stored.symm.trans held)
      subst raw
      have sameNode := Except.ok.inj (decodedClosed.symm.trans decoded)
      subst node
      simp only [pairedChildren] at member
      rcases List.mem_filterMap.mp member with ⟨entry, inEntries, made⟩
      rcases entry with ⟨candidate, index⟩
      cases candidate with
      | none => simp at made
      | some address =>
          simp only [Option.map_some] at made
          have childEq := Option.some.inj made
          subst child
          exact below index address (List.mk_mem_zipIdx_iff_getElem?.mp inEntries)

private theorem inherited_paired_child
    {publisher : TrieProgramProofs.RawSnapshot} {context : Context} {root raw : ByteArray}
    {node : Node} (position child : Position)
    (closed : TrieSnapshotClosure.Closed publisher position.hash)
    (held : publisher nodeSpace position.hash = some raw)
    (decoded : decode raw = .ok node) (wellFormed : node.wf)
    (member : child ∈ pairedChildren none node)
    (inherited : PositionInherited publisher context root position) :
    PositionInherited publisher context root
      { child with path := position.path ++ child.path } := by
  intro evidence required
  apply inherited evidence
  unfold TrieMissingCompletion.PositionRequires at required ⊢
  rw [show (position.path ++ child.path).toList =
      position.path.toList ++ child.path.toList by
    simp [ByteArrayProofs.toList_eq_data]] at required
  cases closed with
  | leaf stored decodedClosed payload =>
      have sameRaw := Option.some.inj (stored.symm.trans held)
      subst raw
      have sameNode := Except.ok.inj (decodedClosed.symm.trans decoded)
      subst node
      simp [pairedChildren] at member
  | extension stored decodedClosed nonempty below =>
      have sameRaw := Option.some.inj (stored.symm.trans held)
      subst raw
      have sameNode := Except.ok.inj (decodedClosed.symm.trans decoded)
      subst node
      simp only [pairedChildren, List.mem_cons, List.not_mem_nil, or_false] at member
      subst child
      exact .extension stored decodedClosed nonempty required
  | branch stored decodedClosed payload below =>
      have sameRaw := Option.some.inj (stored.symm.trans held)
      subst raw
      have sameNode := Except.ok.inj (decodedClosed.symm.trans decoded)
      subst node
      obtain ⟨width, _, _⟩ := wellFormed
      simp only [pairedChildren] at member
      rcases List.mem_filterMap.mp member with ⟨entry, inEntries, made⟩
      rcases entry with ⟨candidate, index⟩
      cases candidate with
      | none => simp at made
      | some address =>
          simp only [Option.map_some] at made
          have childEq := Option.some.inj made
          subst child
          have edge := List.mk_mem_zipIdx_iff_getElem?.mp inEntries
          have indexBound : index < _ := (List.getElem?_eq_some_iff.mp edge).1
          have bound : index < 16 := by
            omega
          have indexEq : index.toUInt8.toNat = index := by
            simpa [Nat.toUInt8_eq] using
              (UInt8.toNat_ofNat_of_lt' (n := index)
                (by simpa [UInt8.size] using (show index < 256 by omega)))
          apply Needs.branch (nibble := index.toUInt8) stored decodedClosed
          · simpa [indexEq] using edge
          · simpa [ByteArrayProofs.toList_eq_data] using required
  | route stored decodedClosed payload below =>
      have sameRaw := Option.some.inj (stored.symm.trans held)
      subst raw
      have sameNode := Except.ok.inj (decodedClosed.symm.trans decoded)
      subst node
      obtain ⟨width, _, _⟩ := wellFormed
      simp only [pairedChildren] at member
      rcases List.mem_filterMap.mp member with ⟨entry, inEntries, made⟩
      rcases entry with ⟨candidate, index⟩
      cases candidate with
      | none => simp at made
      | some address =>
          simp only [Option.map_some] at made
          have childEq := Option.some.inj made
          subst child
          have edge := List.mk_mem_zipIdx_iff_getElem?.mp inEntries
          have indexBound : index < _ := (List.getElem?_eq_some_iff.mp edge).1
          have bound : index < 16 := by
            omega
          have indexEq : index.toUInt8.toNat = index := by
            simpa [Nat.toUInt8_eq] using
              (UInt8.toNat_ofNat_of_lt' (n := index)
                (by simpa [UInt8.size] using (show index < 256 by omega)))
          apply Needs.route (nibble := index.toUInt8) stored decodedClosed
          · simpa [indexEq] using edge
          · simpa [ByteArrayProofs.toList_eq_data] using required

private theorem closed_has_decoded
    {publisher : TrieProgramProofs.RawSnapshot} {addressHash : ByteArray}
    (closed : TrieSnapshotClosure.Closed publisher addressHash) :
    ∃ raw node, publisher nodeSpace addressHash = some raw ∧ decode raw = .ok node := by
  cases closed with
  | leaf held decoded payload => exact ⟨_, _, held, decoded⟩
  | extension held decoded nonempty below => exact ⟨_, _, held, decoded⟩
  | branch held decoded payload below => exact ⟨_, _, held, decoded⟩
  | route held decoded payload below => exact ⟨_, _, held, decoded⟩

private theorem closed_value_hashes
    {publisher : TrieProgramProofs.RawSnapshot} {addressHash raw : ByteArray} {node : Node}
    (closed : TrieSnapshotClosure.Closed publisher addressHash)
    (held : publisher nodeSpace addressHash = some raw) (decoded : decode raw = .ok node) :
    ∀ address ∈ node.valueHashes, ∃ bytes,
      publisher valueSpace address = some bytes := by
  have nodeClosed := TrieSnapshotClosure.loaded_node_closed closed held decoded
  cases node with
  | extension segment child => simp [Node.valueHashes]
  | leaf suffix value =>
      intro address member
      cases value with
      | inline inlineBytes => simp [Node.valueHashes] at member
      | hash valueHash =>
          simp only [Node.valueHashes, List.mem_cons, List.not_mem_nil, or_false] at member
          subst address
          obtain ⟨bytes, denotes⟩ := nodeClosed
          cases denotes with
          | stored storedHash bytes heldValue => exact ⟨bytes, heldValue⟩
  | branch children value =>
      intro address member
      rcases nodeClosed with ⟨payload, below⟩
      cases value with
      | none => simp [Node.valueHashes] at member
      | some valueNode =>
          obtain ⟨bytes, denotes⟩ := payload valueNode rfl
          cases valueNode with
          | inline inlineBytes => simp [Node.valueHashes] at member
          | hash valueHash =>
              simp only [Node.valueHashes, List.mem_cons, List.not_mem_nil, or_false] at member
              subst address
              cases denotes with
              | stored storedHash bytes heldValue => exact ⟨bytes, heldValue⟩
  | route children value =>
      intro address member
      rcases nodeClosed with ⟨payload, below⟩
      cases value with
      | none => simp [Node.valueHashes] at member
      | some valueHash =>
          have same : address = valueHash := by simpa [Node.valueHashes] using member
          subst address
          obtain ⟨bytes, denotes⟩ := payload valueHash rfl
          cases denotes with
          | stored storedHash bytes heldValue => exact ⟨bytes, heldValue⟩
def FitsPositionDepth (position : Position) : Node → Prop
  | .leaf suffix _ => position.path.size + suffix.size ≤ Walk.maxDepthNibbles
  | _ => True

def PublisherExtensionChild (publisher : TrieProgramProofs.RawSnapshot)
    (address : ByteArray) : Prop :=
  ∃ parent raw segment, publisher nodeSpace parent = some raw ∧
    decode raw = .ok (.extension segment address)

/-- Publisher and host facts needed to turn semantic evidence into raw
production reads.  The only execution premises are the ownership projection
and the auxiliary child byte read used by extensions.  In particular this
does not contain an execution of `inspect`, `prepareLoaded` or `inspectLoaded`,
an empty absence list, paired children, a successor work item, exhaustion, or
a completeness Boolean. -/
structure PromotionReadOpportunity (publisher : TrieProgramProofs.RawSnapshot)
    (tx : Transaction) (context : Context) (root : ByteArray) : Prop where
  stored : TrieSnapshotClosure.StoredSnapshot publisher root
  quiet : ∀ (state : SimulatedHost.State)
      (work : Work (Std.HashSet Visit) (Std.HashSet ByteArray))
      (position : Position) (rest : List Position),
    work.frontier.positions = position :: rest →
    position.finish = false →
    CanonicalWork publisher context root work →
    state.faults = []
  canonical : ∀ (work : Work (Std.HashSet Visit) (Std.HashSet ByteArray))
      (position : Position) (rest : List Position) (raw : ByteArray) (node : Node),
    work.frontier.positions = position :: rest →
    position.finish = false →
    CanonicalWork publisher context root work →
    publisher nodeSpace position.hash = some raw → decode raw = .ok node →
    position.path.size ≤ Walk.maxDepthNibbles ∧ node.wf ∧
      (WorkSet.contains work.frontier.mustBeBranch position.hash = true →
        isBranch node = true) ∧
      FitsPositionDepth position node ∧
      ∀ address bytes, address ∈ node.valueHashes →
        publisher valueSpace address = some bytes →
        bytes.size ≤ maxValueBytes ∧
          (isRoute node = true ∨ inlineValueMax < bytes.size)
  ownershipRead : ∀ (state : SimulatedHost.State) (origin : String)
      (address : ByteArray),
    Verified (replicaOfState state) (.provenance origin address) →
    ∃ after,
      execute ((rowPresent "trie_node_origins"
        [("origin_id", .text origin), ("hash", .blob address)]).run.mapEffects
          (promoteMissing tx)) state = (.ok true, after) ∧
      replicaOfState after = replicaOfState state ∧ after.faults = []
  supportingNodeRead : ∀ (state : SimulatedHost.State) (address : ByteArray),
    PublisherExtensionChild publisher address →
    state.faults = [] →
    ∃ answer after,
      execute ((Missing.storage (.readBytes nodeSpace address)).run.mapEffects
        (promoteMissing tx)) state = (.ok answer, after) ∧
      replicaOfState after = replicaOfState state ∧ after.faults = [] ∧
      match answer with
      | none => True
      | some raw => ∃ node, decode raw = .ok node ∧ isBranch node = true

private theorem promotion_loadOwned_of_settled
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (context : Context) (root : ByteArray)
    (reads : PromotionReadOpportunity publisher tx context root)
    (state : SimulatedHost.State) (position : Position) (raw : ByteArray)
    (quiet : state.faults = [])
    (admitted : context.scope.admitsPath position.path.toList = true)
    (held : publisher nodeSpace position.hash = some raw)
    (settled : TrieMissingCompletion.PositionSettled publisher context
      (replicaOfState state) position) :
    ∃ final,
      execute ((loadOwned context.owner position.hash).run.mapEffects
        (promoteMissing tx)) state = (.ok (some raw), final) ∧
      replicaOfState final = replicaOfState state ∧ final.faults = [] := by
  have nodeVerified : Verified (replicaOfState state) (.node position.hash raw) :=
    settled _ (.node admitted held)
  cases owner : context.owner with
  | none =>
      obtain ⟨final, ran, replicaEq, quietFinal⟩ :=
        promotion_readBytes_of_verified tx nodeSpace position.hash raw state quiet nodeVerified
      exact ⟨final, by simpa [loadOwned, owner] using ran, replicaEq, quietFinal⟩
  | some origin =>
      have provenanceVerified : Verified (replicaOfState state)
          (.provenance origin position.hash) :=
        settled _ (by
          unfold TrieMissingCompletion.PositionRequires
          simpa [owner] using (Needs.provenance admitted held :
            Needs publisher context.scope (some origin) position.hash position.path.toList
              (.provenance origin position.hash)))
      obtain ⟨owned, ownedRun, replicaOwned, quietOwned⟩ :=
        reads.ownershipRead state origin position.hash provenanceVerified
      have nodeAtOwned : Verified (replicaOfState owned) (.node position.hash raw) := by
        simpa [replicaOwned] using nodeVerified
      obtain ⟨final, bytesRun, replicaFinal, quietFinal⟩ :=
        promotion_readBytes_of_verified tx nodeSpace position.hash raw owned quietOwned nodeAtOwned
      let tail : Bool → Missing.Action (Option ByteArray) := fun present =>
        if !present then pure none else Missing.storage (.readBytes nodeSpace position.hash)
      have ownedTail := execute_mapped_bind_ok (promoteMissing tx)
        (rowPresent "trie_node_origins"
          [("origin_id", .text origin), ("hash", .blob position.hash)]) tail
        state owned true ownedRun
      refine ⟨final, ?_, replicaFinal.trans replicaOwned, quietFinal⟩
      rw [show loadOwned (some origin) position.hash =
          rowPresent "trie_node_origins"
            [("origin_id", .text origin), ("hash", .blob position.hash)] >>= tail by
        simp [loadOwned, tail]]
      rw [ownedTail]
      simpa [tail] using bytesRun

private theorem promotion_inspectPendingBranch
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (context : Context) (root : ByteArray)
    (reads : PromotionReadOpportunity publisher tx context root)
    (state : SimulatedHost.State) (node : Node) (quiet : state.faults = [])
    (extensionChild : ∀ segment child, node = .extension segment child →
      PublisherExtensionChild publisher child) :
    ∃ pending final,
      execute ((inspectPendingBranch node).run.mapEffects (promoteMissing tx)) state =
        (.ok pending, final) ∧
      replicaOfState final = replicaOfState state ∧ final.faults = [] := by
  cases node with
  | leaf suffix value => exact ⟨none, state, rfl, rfl, quiet⟩
  | branch children value => exact ⟨none, state, rfl, rfl, quiet⟩
  | route children value => exact ⟨none, state, rfl, rfl, quiet⟩
  | extension segment child =>
      obtain ⟨answer, final, readRun, replicaEq, quietFinal, safe⟩ :=
        reads.supportingNodeRead state child (extensionChild segment child rfl) quiet
      let tail : Option ByteArray → Missing.Action (Option ByteArray) := fun answer =>
        match answer with
        | none => pure (some child)
        | some raw => do
            if !isBranch (← decodeNode raw) then
              throw (.canonical (.expectedBranch child))
            pure none
      have sequence := execute_mapped_bind_ok (promoteMissing tx)
        (Missing.storage (.readBytes nodeSpace child)) tail state final answer readRun
      cases answer with
      | none =>
          refine ⟨some child, final, ?_, replicaEq, quietFinal⟩
          rw [show inspectPendingBranch (.extension segment child) =
              Missing.storage (.readBytes nodeSpace child) >>= tail by rfl]
          rw [sequence]
          rfl
      | some childRaw =>
          obtain ⟨childNode, decoded, branch⟩ := safe
          refine ⟨none, final, ?_, replicaEq, quietFinal⟩
          rw [show inspectPendingBranch (.extension segment child) =
              Missing.storage (.readBytes nodeSpace child) >>= tail by rfl]
          rw [sequence]
          simp [tail, decodeNode, decoded, branch, bind, ExceptT.bind,
            ExceptT.bindCont, ExceptT.mk, pure, ExceptT.pure, Program.bind]
          rfl

private theorem promotion_prepareDecoded
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (context : Context) (root : ByteArray)
    (reads : PromotionReadOpportunity publisher tx context root)
    (state : SimulatedHost.State)
    (work : Work (Std.HashSet Visit) (Std.HashSet ByteArray))
    (position : Position) (node : Node)
    (quiet : state.faults = []) (noRef : position.reference = none)
    (branchShape : WorkSet.contains work.frontier.mustBeBranch position.hash = true →
      isBranch node = true)
    (depth : FitsPositionDepth position node)
    (extensionChild : ∀ segment child, node = .extension segment child →
      PublisherExtensionChild publisher child) :
    ∃ prepared final,
      execute ((prepareDecoded work.frontier position node).run.mapEffects
        (promoteMissing tx)) state = (.ok prepared, final) ∧
      prepared.node = node ∧ prepared.children = pairedChildren none node ∧
      replicaOfState final = replicaOfState state ∧ final.faults = [] := by
  have guardFalse : (WorkSet.contains work.frontier.mustBeBranch position.hash &&
      !isBranch node) = false := by
    cases present : WorkSet.contains work.frontier.mustBeBranch position.hash with
    | false => rfl
    | true => simp [branchShape present]
  obtain ⟨pending, checked, pendingRun, replicaEq, quietChecked⟩ :=
    promotion_inspectPendingBranch publisher tx context root reads state node quiet extensionChild
  let tail : Option ByteArray → Missing.Action Prepared := fun pendingBranch => do
    let reference ← inspectReference position.reference
    validateNodeDepth position node
    return ⟨node, pairedChildren reference node, pendingBranch⟩
  have sequence := execute_mapped_bind_ok (promoteMissing tx)
    (inspectPendingBranch node) tail state checked pending pendingRun
  refine ⟨⟨node, pairedChildren none node, pending⟩, checked, ?_, rfl, rfl,
    replicaEq, quietChecked⟩
  rw [show prepareDecoded work.frontier position node =
      inspectPendingBranch node >>= tail by
    unfold prepareDecoded
    simp [guardFalse, tail]]
  rw [sequence]
  cases node with
  | leaf suffix value =>
      have shallow : ¬ Walk.maxDepthNibbles < position.path.size + suffix.size := by
        simpa [FitsPositionDepth] using Nat.not_lt.mpr depth
      simp [tail, noRef, inspectReference, validateNodeDepth, shallow, bind,
        ExceptT.bind, ExceptT.bindCont, ExceptT.mk, pure, ExceptT.pure, Program.bind]
      rfl
  | extension segment child =>
      simp [tail, noRef, inspectReference, validateNodeDepth, bind,
        ExceptT.bind, ExceptT.bindCont, ExceptT.mk, pure, ExceptT.pure, Program.bind]
      rfl
  | branch children value =>
      simp [tail, noRef, inspectReference, validateNodeDepth, bind,
        ExceptT.bind, ExceptT.bindCont, ExceptT.mk, pure, ExceptT.pure, Program.bind]
      rfl
  | route children value =>
      simp [tail, noRef, inspectReference, validateNodeDepth, bind,
        ExceptT.bind, ExceptT.bindCont, ExceptT.mk, pure, ExceptT.pure, Program.bind]
      rfl

private theorem promotion_prepareLoaded
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (context : Context) (root : ByteArray)
    (reads : PromotionReadOpportunity publisher tx context root)
    (state : SimulatedHost.State)
    (work : Work (Std.HashSet Visit) (Std.HashSet ByteArray))
    (position : Position) (raw : ByteArray) (node : Node)
    (quiet : state.faults = [])
    (held : publisher nodeSpace position.hash = some raw)
    (decoded : decode raw = .ok node)
    (noRef : position.reference = none)
    (branchShape : WorkSet.contains work.frontier.mustBeBranch position.hash = true →
      isBranch node = true)
    (depth : FitsPositionDepth position node) :
    ∃ prepared final,
      execute ((prepareLoaded work.frontier position raw).run.mapEffects
        (promoteMissing tx)) state = (.ok prepared, final) ∧
      prepared.node = node ∧ prepared.children = pairedChildren none node ∧
      replicaOfState final = replicaOfState state ∧ final.faults = [] := by
  obtain ⟨prepared, final, preparedRun, preparedNode, children, replicaEq, quietFinal⟩ :=
    promotion_prepareDecoded publisher tx context root reads state work position node quiet
      noRef branchShape depth (fun segment child same => by
        subst node
        exact ⟨position.hash, raw, segment, held, decoded⟩)
  let tail : Node → Missing.Action Prepared := prepareDecoded work.frontier position
  have decodedRun : execute ((decodeNode raw).run.mapEffects (promoteMissing tx)) state =
      (.ok node, state) := by
    simp [decodeNode, decoded]
    rfl
  have sequence := execute_mapped_bind_ok (promoteMissing tx)
    (decodeNode raw) tail state state node decodedRun
  refine ⟨prepared, final, ?_, preparedNode, children, replicaEq, quietFinal⟩
  rw [show prepareLoaded work.frontier position raw = decodeNode raw >>= tail by rfl]
  rw [sequence]
  exact preparedRun

private theorem inspect_of_settled_reads
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (context : Context) (root : ByteArray)
    (reads : PromotionReadOpportunity publisher tx context root)
    (state : SimulatedHost.State)
    (work : Work (Std.HashSet Visit) (Std.HashSet ByteArray))
    (position : Position) (rest : List Position)
    (pending : work.frontier.positions = position :: rest)
    (entering : position.finish = false)
    (good : CanonicalWork publisher context root work)
    (settled : TrieMissingCompletion.PositionSettled publisher context
      (replicaOfState state) position) :
    ∃ checked after,
      execute ((Missing.inspect context work.frontier position).run.mapEffects
        (promoteMissing tx)) state = (.ok checked, after) ∧
      replicaOfState after = replicaOfState state ∧
      (checked = .skip ∨ ∃ raw node pendingBranch,
        node.wf ∧ publisher nodeSpace position.hash = some raw ∧
        decode raw = .ok node ∧
        checked = .expand (pairedChildren none node) pendingBranch [] (isRoute node)) := by
  have noRef := good.2.2.1.1 position (by rw [pending]; simp)
  have closed := good.2.2.2.1 position (by rw [pending]; simp)
  obtain ⟨raw, node, held, decoded⟩ := closed_has_decoded closed
  obtain ⟨depth, wellFormed, branchShape, validDepth, valueShape⟩ :=
    reads.canonical work position rest raw node pending entering good held decoded
  have shallow : ¬ position.path.size > Walk.maxDepthNibbles := by omega
  have refBeq : (position.reference == some position.hash) = false := by simp [noRef]
  by_cases seen : WorkSet.contains work.frontier.seen
      (visit context.scope position.hash position.path) = true
  · refine ⟨.skip, state, ?_, rfl, .inl rfl⟩
    unfold Missing.inspect
    simp [shallow, refBeq, seen]
    rfl
  ·
    have quiet := reads.quiet state work position rest pending entering good
    have admitted : context.scope.admitsPath position.path.toList = true :=
      good.2.1.1.1 position (by rw [pending]; simp)
    obtain ⟨loaded, loadRun, replicaLoaded, quietLoaded⟩ :=
      promotion_loadOwned_of_settled publisher tx context root reads state position raw
        quiet admitted held settled
    obtain ⟨prepared, valuesStarted, preparedRun, preparedNode, preparedChildren,
        replicaPrepared, quietPrepared⟩ :=
      promotion_prepareLoaded publisher tx context root reads loaded work position raw node
        quietLoaded held decoded noRef branchShape validDepth
    have available : context.scope.admitsValue position.path.toList node = true →
        ∀ address ∈ node.valueHashes, ∃ bytes,
          Verified (replicaOfState valuesStarted) (.value address bytes) ∧
          bytes.size ≤ maxValueBytes ∧
          (isRoute node = true ∨ inlineValueMax < bytes.size) := by
      intro valueAdmitted address member
      obtain ⟨bytes, heldValue⟩ := closed_value_hashes closed held decoded address member
      have verified : Verified (replicaOfState state) (.value address bytes) :=
        settled _ (.value held decoded valueAdmitted member heldValue)
      obtain ⟨bounded, sized⟩ := valueShape address bytes member heldValue
      exact ⟨bytes, by simpa [replicaPrepared, replicaLoaded] using verified, bounded, sized⟩
    obtain ⟨after, valuesRun, replicaValues, quietAfter⟩ :=
      promotion_inspectValues_nil tx context position node valuesStarted quietPrepared available
    have replicaEq : replicaOfState after = replicaOfState state :=
      replicaValues.trans (replicaPrepared.trans replicaLoaded)
    let finishValues : List ByteArray → Missing.Action Expansion := fun absent =>
      pure ⟨prepared.children, prepared.pendingBranch, absent, isRoute prepared.node⟩
    have valuesTail := execute_mapped_bind_ok (promoteMissing tx)
      (inspectValues context position prepared.node) finishValues valuesStarted after []
      (by simpa [preparedNode] using valuesRun)
    let finishPrepared : Prepared → Missing.Action Expansion := fun prepared => do
      let absent ← inspectValues context position prepared.node
      return ⟨prepared.children, prepared.pendingBranch, absent, isRoute prepared.node⟩
    have preparedTail := execute_mapped_bind_ok (promoteMissing tx)
      (prepareLoaded work.frontier position raw) finishPrepared loaded valuesStarted prepared
      preparedRun
    have loadedRun : execute ((inspectLoaded context work.frontier position raw).run.mapEffects
        (promoteMissing tx)) loaded =
        (.ok ⟨pairedChildren none node, prepared.pendingBranch, [], isRoute node⟩, after) := by
      rw [show inspectLoaded context work.frontier position raw =
          prepareLoaded work.frontier position raw >>= finishPrepared by rfl]
      rw [preparedTail]
      change execute (((inspectValues context position prepared.node >>= finishValues).run.mapEffects
        (promoteMissing tx))) valuesStarted = _
      rw [valuesTail]
      simp [finishValues, preparedNode, preparedChildren]
      rfl
    refine ⟨.expand (pairedChildren none node) prepared.pendingBranch [] (isRoute node), after,
      ?_, replicaEq,
      .inr ⟨raw, node, prepared.pendingBranch, wellFormed, held, decoded, rfl⟩⟩
    let tail : Option ByteArray → Missing.Action Checked := fun loaded =>
      match loaded with
      | none => pure Checked.absent
      | some raw => do
          let expansion ← inspectLoaded context work.frontier position raw
          return .expand expansion.children expansion.pendingBranch
            expansion.absentValues expansion.routing
    have whole : Missing.inspect context work.frontier position =
        loadOwned context.owner position.hash >>= tail := by
      unfold Missing.inspect
      simp [shallow, refBeq, seen, tail]
      rfl
    rw [whole]
    have loadTail := execute_mapped_bind_ok (promoteMissing tx)
      (loadOwned context.owner position.hash) tail state loaded (some raw) loadRun
    rw [loadTail]
    let finish : Expansion → Missing.Action Checked := fun expansion =>
      pure (.expand expansion.children expansion.pendingBranch
        expansion.absentValues expansion.routing)
    have loadedTail := execute_mapped_bind_ok (promoteMissing tx)
      (inspectLoaded context work.frontier position raw) finish loaded after
      (⟨pairedChildren none node, prepared.pendingBranch, [], isRoute node⟩ : Expansion) loadedRun
    change execute (((inspectLoaded context work.frontier position raw >>= finish).run.mapEffects
      (promoteMissing tx))) loaded = _
    rw [loadedTail]
    rfl

private theorem pushChildren_cases (scope : Serve.Scope) (path : ByteArray)
    (children stack : List Position) (probe : Position)
    (member : probe ∈ pushChildren scope path children stack) :
    probe ∈ stack ∨ ∃ child, child ∈ children ∧
      scope.admitsPath (path ++ child.path).toList = true ∧
      probe = { child with path := path ++ child.path } := by
  induction children generalizing stack with
  | nil => exact .inl member
  | cons head rest ih =>
      simp only [pushChildren, List.foldl_cons] at member
      split at member
      · rename_i admitted
        rcases ih ({ head with path := path ++ head.path } :: stack) member with
          old | ⟨child, inRest, childAdmitted, rfl⟩
        · rcases List.mem_cons.mp old with same | inStack
          · exact .inr ⟨head, List.mem_cons_self, admitted, same⟩
          · exact .inl inStack
        · exact .inr ⟨child, List.mem_cons_of_mem _ inRest, childAdmitted, rfl⟩
      · rcases ih stack member with old | ⟨child, inRest, childAdmitted, rfl⟩
        · exact .inl old
        · exact .inr ⟨child, List.mem_cons_of_mem _ inRest, childAdmitted, rfl⟩

private theorem expand_canonical
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context) (root : ByteArray)
    (work : Work (Std.HashSet Visit) (Std.HashSet ByteArray))
    (position : Position) (rest : List Position) (raw : ByteArray) (node : Node)
    (pendingBranch : Option ByteArray)
    (pending : work.frontier.positions = position :: rest)
    (good : CanonicalWork publisher context root work)
    (held : publisher nodeSpace position.hash = some raw)
    (decoded : decode raw = .ok node) (wellFormed : node.wf)
    (closed : TrieSnapshotClosure.Closed publisher position.hash) :
    CanonicalWork publisher context root
      (commit context work position rest
        (.expand (pairedChildren none node) pendingBranch [] (isRoute node))) := by
  have parentInherited := good.1.2.2.2.1 position (by rw [pending]; simp)
  have restInherited : ∀ probe ∈ rest, PositionInherited publisher context root probe :=
    fun probe member => good.1.2.2.2.1 probe (by rw [pending]; exact List.mem_cons_of_mem _ member)
  have restClosed : ∀ probe ∈ rest, TrieSnapshotClosure.Closed publisher probe.hash :=
    fun probe member => good.2.2.2.1 probe (by rw [pending]; exact List.mem_cons_of_mem _ member)
  refine ⟨?_, TrieMissingProofs.commit_admitted context work position rest
      (.expand (pairedChildren none node) pendingBranch [] (isRoute node)) good.2.1 pending,
    commit_no_references context work position rest
      (.expand (pairedChildren none node) pendingBranch [] (isRoute node)) pending good.2.2.1 ?_, ?_⟩
  · unfold CompleteWork
    simp only [commit, List.isEmpty_nil, ↓reduceIte]
    refine ⟨good.1.1, good.1.2.1, ?_, ?_⟩
    · simp [askValues, good.1.2.2.1]
    · constructor
      · intro probe member
        rcases pushChildren_cases context.scope position.path (pairedChildren none node)
            ({ position with finish := true } :: rest) probe member with
          inStack | ⟨child, childMember, admitted, rfl⟩
        · rcases List.mem_cons.mp inStack with rfl | inRest
          · exact parentInherited
          · exact restInherited probe inRest
        · exact inherited_paired_child position child closed held decoded wellFormed
            childMember parentInherited
      · exact good.1.2.2.2.2
  · intro children pending absent routing same
    injection same with childrenEq
    subst children
    exact pairedChildren_none_have_no_references node
  · unfold FrontierClosed
    simp only [commit, List.isEmpty_nil, ↓reduceIte]
    constructor
    · intro probe member
      rcases pushChildren_cases context.scope position.path (pairedChildren none node)
          ({ position with finish := true } :: rest) probe member with
        inStack | ⟨child, childMember, admitted, rfl⟩
      · rcases List.mem_cons.mp inStack with rfl | inRest
        · exact closed
        · exact restClosed probe inRest
      · exact closed_paired_child closed held decoded child childMember
    · exact good.2.2.2.2

private theorem skip_canonical
    (publisher : TrieProgramProofs.RawSnapshot) (context : Context) (root : ByteArray)
    (work : Work (Std.HashSet Visit) (Std.HashSet ByteArray))
    (position : Position) (rest : List Position)
    (pending : work.frontier.positions = position :: rest)
    (good : CanonicalWork publisher context root work) :
    CanonicalWork publisher context root (commit context work position rest .skip) := by
  refine ⟨?_, TrieMissingProofs.commit_admitted context work position rest .skip good.2.1 pending,
    commit_no_references context work position rest .skip pending good.2.2.1
      (by intro children pending absent routing impossible; cases impossible), ?_⟩
  · unfold CompleteWork
    simp only [commit]
    refine ⟨good.1.1, good.1.2.1, good.1.2.2.1, ?_⟩
    exact ⟨fun probe member => good.1.2.2.2.1 probe (by
      rw [pending]; exact List.mem_cons_of_mem _ member), good.1.2.2.2.2⟩
  · unfold FrontierClosed
    simp only [commit]
    exact ⟨fun probe member => good.2.2.2.1 probe (by
      rw [pending]; exact List.mem_cons_of_mem _ member), good.2.2.2.2⟩

private theorem promotion_batchStep_complete
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (context : Context) (root : ByteArray)
    (reads : PromotionReadOpportunity publisher tx context root)
    {state final : SimulatedHost.State}
    {work : Work (Std.HashSet Visit) (Std.HashSet ByteArray)}
    {result : Work (Std.HashSet Visit) (Std.HashSet ByteArray) ⊕
      BatchResult (Std.HashSet Visit) (Std.HashSet ByteArray)}
    (complete : PermittedComplete publisher context.scope context.owner root
      (replicaOfState state))
    (good : CanonicalWork publisher context root work)
    (ran : execute ((batchStep context 1 work).run.mapEffects (promoteMissing tx)) state =
      (.ok result, final)) :
    match result with
    | .inl next => CanonicalWork publisher context root next ∧
        PermittedComplete publisher context.scope context.owner root
          (replicaOfState final)
    | .inr (frontier, .ok _batch) => frontier.isExhausted = true
    | .inr (_, .error _) => False := by
  unfold batchStep at ran
  simp only [good.1.1] at ran
  cases pending : work.frontier.positions with
  | nil =>
    simp only [pending, pure, ExceptT.pure, ExceptT.mk, ExceptT.run,
      Program.mapEffects, execute, Except.ok.injEq, Prod.mk.injEq] at ran
    rcases ran with ⟨rfl, rfl⟩
    simp [finished, Frontier.isExhausted, pending, good.1.2.1, good.1.1]
  | cons position rest =>
    simp only [pending] at ran
    cases finish : position.finish with
    | true =>
      simp only [finish, ↓reduceIte, pure, ExceptT.pure, ExceptT.mk,
        ExceptT.run, Program.mapEffects, execute, Except.ok.injEq,
        Prod.mk.injEq] at ran
      rcases ran with ⟨rfl, rfl⟩
      refine ⟨?_, complete⟩
      have completeWork : CompleteWork publisher context root
          (settle context work position rest) := by
        unfold CompleteWork
        rw [settle, good.1.2.1]
        simp only [List.isEmpty_nil, ↓reduceIte]
        refine ⟨good.1.1, good.1.2.1, good.1.2.2.1, ?_⟩
        exact ⟨fun probe member => good.1.2.2.2.1 probe (by
          rw [pending]; exact List.mem_cons_of_mem _ member), good.1.2.2.2.2⟩
      refine ⟨completeWork,
        TrieMissingProofs.settle_admitted context work position rest good.2.1 pending,
        settle_no_references context work position rest pending good.2.2.1, ?_⟩
      unfold FrontierClosed
      rw [settle, good.1.2.1]
      simp only [List.isEmpty_nil, ↓reduceIte]
      exact ⟨fun probe member => good.2.2.2.1 probe (by
        rw [pending]; exact List.mem_cons_of_mem _ member), good.2.2.2.2⟩
    | false =>
      have noBatch : (work.batch.size ≥ 1) = false := by
        rw [good.1.2.2.1]
        decide
      simp only [finish, Bool.false_eq_true, noBatch, ↓reduceIte] at ran
      have inherited := good.1.2.2.2.1 position (by rw [pending]; simp)
      have settled : TrieMissingCompletion.PositionSettled publisher context
          (replicaOfState state) position := fun evidence required =>
        complete evidence (inherited evidence required)
      obtain ⟨checked, after, inspected, replicaEq, shape⟩ :=
        inspect_of_settled_reads publisher tx context root reads state work position rest
          pending finish good settled
      simp only [ExceptT.run] at inspected
      simp only [ExceptT.mk, ExceptT.run, bind] at ran
      rw [mapEffects_bind, SimulatedHost.execute_bind, inspected] at ran
      have completeAfter : PermittedComplete publisher context.scope context.owner root
          (replicaOfState after) := by simpa [replicaEq] using complete
      cases ran
      rcases shape with rfl | ⟨raw, node, pendingBranch, wellFormed, held, decoded, rfl⟩
      · exact ⟨skip_canonical publisher context root work position rest pending good,
          completeAfter⟩
      · exact ⟨expand_canonical publisher context root work position rest raw node pendingBranch
          pending good held decoded wellFormed
          (good.2.2.2.1 position (by rw [pending]; simp)), completeAfter⟩

private theorem iterate_complete [Interpreter E]
    (body : S → Program E (Except ε (S ⊕ R))) (exhausted : ε)
    (P : SimulatedHost.State → S → Prop)
    (Q : SimulatedHost.State → R → Prop)
    (kept : ∀ state start next final, P state start →
      execute (body start) state = (.ok (.inl next), final) → P final next)
    (stopped : ∀ state start answer final, P state start →
      execute (body start) state = (.ok (.inr answer), final) → Q final answer)
    (fuel : Nat) : ∀ (program : Program E (Except ε (S ⊕ R))) state,
    (∀ next final, execute program state = (.ok (.inl next), final) → P final next) →
    (∀ answer final, execute program state = (.ok (.inr answer), final) → Q final answer) →
    ∀ answer final,
      execute (Program.iterate body exhausted fuel program) state = (.ok answer, final) →
      Q final answer := by
  induction fuel with
  | zero => intro program state _ _ answer final ran; cases ran
  | succ fuel ih =>
    intro program state keeps stops answer final ran
    match program with
    | .pure (.error error) => cases ran
    | .pure (.ok (.inr result)) => cases ran; exact stops _ state rfl
    | .pure (.ok (.inl next)) =>
      exact ih (body next) state
        (fun next' final => kept state next next' final (keeps next state rfl))
        (fun result final => stopped state next result final (keeps next state rfl))
        answer final ran
    | .request effect resume =>
      rw [execute_iterate_request] at ran
      cases effectState : Interpreter.handle effect state with
      | mk reply after =>
        simp only [execute, effectState] at keeps stops
        simp only [effectState] at ran
        exact ih (resume reply) after keeps stops answer final ran

/-- Semantic completion turns a finite sequence of primitive production read
replies into an exhausted frontier.  Exhaustion is proved here; it is not a
field of the opportunity. -/
theorem promotion_walk_exhausted_of_complete
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (context : Context) (root : ByteArray) (steps : Nat)
    (state final : SimulatedHost.State)
    (frontier : Frontier (Std.HashSet Visit) (Std.HashSet ByteArray))
    (batch : Batch)
    (reads : PromotionReadOpportunity publisher tx context root)
    (complete : PermittedComplete publisher context.scope context.owner root
      (replicaOfState state))
    (plan : PromotionWalkOpportunity tx context root steps state frontier batch final)
    (fits : steps ≤ batchFuel) :
    frontier.isExhausted = true := by
  let initialWork : Work (Std.HashSet Visit) (Std.HashSet ByteArray) :=
    ⟨initial context none root, {}, WorkSet.empty ByteArray⟩
  let P : SimulatedHost.State → Work (Std.HashSet Visit) (Std.HashSet ByteArray) → Prop :=
    fun observed work => CanonicalWork publisher context root work ∧
      PermittedComplete publisher context.scope context.owner root
        (replicaOfState observed)
  let Q : SimulatedHost.State →
      BatchResult (Std.HashSet Visit) (Std.HashSet ByteArray) → Prop :=
    fun _ answer => match answer with
      | (frontier, .ok _) => frontier.isExhausted = true
      | (_, .error _) => False
  have initialHeld : P state initialWork :=
    ⟨initial_canonicalWork publisher context root reads.stored, complete⟩
  have keeps : ∀ observed work next after, P observed work →
      execute ((batchStep context 1 work).run.mapEffects (promoteMissing tx)) observed =
        (.ok (.inl next), after) → P after next := by
    intro observed work next after held ran
    exact promotion_batchStep_complete publisher tx context root reads held.2 held.1 ran
  have stops : ∀ observed work answer after, P observed work →
      execute ((batchStep context 1 work).run.mapEffects (promoteMissing tx)) observed =
        (.ok (.inr answer), after) → Q after answer := by
    intro observed work answer after held ran
    rcases answer with ⟨answerFrontier, answerBatch⟩
    cases answerBatch with
    | error error =>
        exact promotion_batchStep_complete publisher tx context root reads held.2 held.1 ran
    | ok answerBatch =>
        exact promotion_batchStep_complete publisher tx context root reads held.2 held.1 ran
  unfold PromotionWalkOpportunity at plan
  have ran := plan.execute fits
  exact iterate_complete
    (fun work => (batchStep context 1 work).run.mapEffects (promoteMissing tx))
    Missing.Error.exhausted P Q keeps stops
    batchFuel _ state
    (fun next after ran => keeps state initialWork next after initialHeld ran)
    (fun answer after ran => stops state initialWork answer after initialHeld ran)
    (frontier, .ok batch) final ran

/-- Transaction-lifted counterpart of `FreshOpportunity`, matching the exact
effect map in `PromotionReads.complete`.  Every field is a primitive phase or
finite walk reply, never the result of the enclosing completeness call. -/
structure PromotionFreshOpportunity
    (tx : Transaction) (context : Context) (root : ByteArray)
    (state : SimulatedHost.State) where
  quiet : state.faults = []
  key : ByteArray
  keyed : SimulatedHost.State
  checked : SimulatedHost.State
  generation : UInt64
  started : SimulatedHost.State
  walked : SimulatedHost.State
  final : SimulatedHost.State
  steps : Nat
  frontier : Frontier (Std.HashSet Visit) (Std.HashSet ByteArray)
  batch : Batch
  startedReplica : replicaOfState started = replicaOfState state
  keyRun : execute ((Memo.keyFor (E := Complete.Effects) Missing.Error.host
    context.scope root context.owner).run.mapEffects
      (Replication.Promote.inTransaction tx)) state = (.ok key, keyed)
  unknownRun : execute ((Complete.memo (.isKnown key)).run.mapEffects
    (Replication.Promote.inTransaction tx)) keyed = (.ok false, checked)
  generationRun : execute ((Complete.memo .generation).run.mapEffects
    (Replication.Promote.inTransaction tx)) checked = (.ok generation, started)
  walk : PromotionWalkOpportunity tx context root steps started frontier batch walked
  withinFuel : steps ≤ batchFuel
  certifyRun : execute ((Complete.memo (.certify key generation)).run.mapEffects
    (Replication.Promote.inTransaction tx)) walked = (.ok true, final)

theorem promotion_isComplete_mapped_exec
    (publisher : TrieProgramProofs.RawSnapshot)
    (tx : Transaction) (context : Context) (root : ByteArray)
    (state : SimulatedHost.State)
    (reads : PromotionReadOpportunity publisher tx context root)
    (complete : PermittedComplete publisher context.scope context.owner root
      (replicaOfState state))
    (ready : PromotionFreshOpportunity tx context root state) :
    execute ((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
      context root).run.mapEffects (Replication.Promote.inTransaction tx)) state =
        (.ok true, ready.final) := by
  have walkRun := promotion_inspectRoot_exec_of_opportunity tx context root ready.steps
    ready.started ready.walked ready.frontier ready.batch ready.walk ready.withinFuel
  have completeStarted : PermittedComplete publisher context.scope context.owner root
      (replicaOfState ready.started) := by
    simpa only [ready.startedReplica] using complete
  have exhausted := promotion_walk_exhausted_of_complete publisher tx context root
    ready.steps ready.started ready.walked ready.frontier ready.batch
      reads completeStarted ready.walk ready.withinFuel
  let afterWalk : Frontier (Std.HashSet Visit) (Std.HashSet ByteArray) ×
      Except Missing.Error Batch → Complete.Action Bool := fun answer =>
    match answer.2 with
    | .error error => throw error
    | .ok _ => if answer.1.isExhausted then
        Complete.memo (.certify ready.key ready.generation) else pure false
  let afterGeneration : UInt64 → Complete.Action Bool := fun generation =>
    Complete.inspectRoot (Std.HashSet Visit) (Std.HashSet ByteArray) context root >>=
      fun answer =>
        match answer.2 with
        | .error error => throw error
        | .ok _ => if answer.1.isExhausted then
            Complete.memo (.certify ready.key generation) else pure false
  have generationTail := execute_mapped_bind_ok (Replication.Promote.inTransaction tx)
    (Complete.memo .generation) afterGeneration ready.checked ready.started
      ready.generation ready.generationRun
  have walkTail := execute_mapped_bind_ok (Replication.Promote.inTransaction tx)
    (Complete.inspectRoot (Std.HashSet Visit) (Std.HashSet ByteArray) context root)
      afterWalk ready.started ready.walked (ready.frontier, .ok ready.batch) walkRun
  have recheckRun : execute ((Complete.recheck (Std.HashSet Visit) (Std.HashSet ByteArray)
      context root ready.key).run.mapEffects (Replication.Promote.inTransaction tx)) ready.checked =
      (.ok true, ready.final) := by
    rw [show Complete.recheck (Std.HashSet Visit) (Std.HashSet ByteArray)
        context root ready.key = Complete.memo .generation >>= afterGeneration by
      rfl]
    rw [generationTail]
    rw [show afterGeneration ready.generation =
        Complete.inspectRoot (Std.HashSet Visit) (Std.HashSet ByteArray) context root >>=
          afterWalk by rfl]
    rw [walkTail]
    simp only [afterWalk, exhausted, ↓reduceIte]
    exact ready.certifyRun
  let afterKnown : Bool → Complete.Action Bool := fun known =>
    if known then pure true else Complete.recheck (Std.HashSet Visit)
      (Std.HashSet ByteArray) context root ready.key
  let afterKey : ByteArray → Complete.Action Bool := fun key =>
    Complete.memo (.isKnown key) >>= fun known =>
      if known then pure true else Complete.recheck (Std.HashSet Visit)
        (Std.HashSet ByteArray) context root key
  have keyTail := execute_mapped_bind_ok (Replication.Promote.inTransaction tx)
    (Memo.keyFor (E := Complete.Effects) Missing.Error.host
      context.scope root context.owner) afterKey
      state ready.keyed ready.key ready.keyRun
  have knownTail := execute_mapped_bind_ok (Replication.Promote.inTransaction tx)
    (Complete.memo (.isKnown ready.key)) afterKnown ready.keyed ready.checked false
      ready.unknownRun
  rw [show Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray) context root =
      Memo.keyFor (E := Complete.Effects) Missing.Error.host
        context.scope root context.owner >>= afterKey by rfl]
  rw [keyTail]
  rw [show afterKey ready.key = Complete.memo (.isKnown ready.key) >>= afterKnown by rfl]
  rw [knownTail]
  exact recheckRun

/-- Exact positive execution required by `PromotionProgress.BodyReady`'s
`completeExecution` field, constructed from primitive transaction-lifted host
replies and finite walk fuel. -/
theorem promotion_complete_exec_of_opportunity
    (publisher : TrieProgramProofs.RawSnapshot)
    (tx : Transaction) (context : Context) (root : ByteArray)
    (state : SimulatedHost.State)
    (reads : PromotionReadOpportunity publisher tx context root)
    (complete : PermittedComplete publisher context.scope context.owner root
      (replicaOfState state))
    (ready : PromotionFreshOpportunity tx context root state) :
    execute (PromotionReads.complete tx context root) state = (.ok true, ready.final) := by
  have completed := promotion_isComplete_mapped_exec publisher tx context root state
    reads complete ready
  unfold PromotionReads.complete
  change execute (Program.bind
    ((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
      context root).run.mapEffects (Replication.Promote.inTransaction tx))
    (fun answer => pure (Except.mapError Replication.Promote.missingError answer))) state = _
  rw [SimulatedHost.execute_bind, completed]
  rfl

theorem bodyReady_completeExecution_of_opportunity
    (publisher : TrieProgramProofs.RawSnapshot)
    (tx : Transaction) (scope : Serve.Scope)
    (authority : Authorization.OriginAuthority)
    (pending : Replication.Promote.Pending) (state : SimulatedHost.State)
    (reads : PromotionReadOpportunity publisher tx
      ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root)
    (complete : PermittedComplete publisher scope
      (authority.provenance.map Origin.canonical) pending.head.root
      (replicaOfState state))
    (ready : PromotionFreshOpportunity tx
      ⟨scope, authority.provenance.map Origin.canonical⟩
      pending.head.root state) :
    execute (((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
      ⟨scope, authority.provenance.map Origin.canonical⟩
      pending.head.root).run.mapEffects (Replication.Promote.inTransaction tx)
      |> fun program => Except.mapError Replication.Promote.missingError <$> program)) state =
        (.ok true, ready.final) := by
  have completed := promotion_isComplete_mapped_exec publisher tx
    ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root state
      reads complete ready
  change execute (Program.bind
    ((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
      ⟨scope, authority.provenance.map Origin.canonical⟩
      pending.head.root).run.mapEffects (Replication.Promote.inTransaction tx))
    (fun answer => pure (Except.mapError Replication.Promote.missingError answer))) state = _
  rw [SimulatedHost.execute_bind, completed]
  rfl

/-- Direct M1 input: zero finite semantic deficit plus a bounded sequence of
actual transaction-lifted host replies supplies both semantic completion and
the exact `BodyReady.completeExecution` value. -/
theorem finite_promotion_complete_execution
    (publisher : TrieProgramProofs.RawSnapshot) (tx : Transaction)
    (scope : Serve.Scope) (authority : Authorization.OriginAuthority)
    (pending : Replication.Promote.Pending) (state : SimulatedHost.State)
    (requirements : FiniteRequirements publisher scope
      (authority.provenance.map Origin.canonical) pending.head.root)
    (complete : missingEvidence requirements.items (replicaOfState state) = 0)
    (reads : PromotionReadOpportunity publisher tx
      ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root)
    (ready : PromotionFreshOpportunity tx
      ⟨scope, authority.provenance.map Origin.canonical⟩
      pending.head.root state) :
    PermittedComplete publisher scope
        (authority.provenance.map Origin.canonical)
        pending.head.root (replicaOfState state) ∧
      execute (((Complete.isComplete (Std.HashSet Visit) (Std.HashSet ByteArray)
        ⟨scope, authority.provenance.map Origin.canonical⟩
        pending.head.root).run.mapEffects (Replication.Promote.inTransaction tx)
        |> fun program => Except.mapError Replication.Promote.missingError <$> program)) state =
          (.ok true, ready.final) :=
  ⟨(TrieFetchCompletion.finite_measure_eq_zero_iff_complete requirements).mp complete,
    bodyReady_completeExecution_of_opportunity publisher tx scope authority pending state
      reads ((TrieFetchCompletion.finite_measure_eq_zero_iff_complete requirements).mp complete)
      ready⟩

/-- All independent positive promotion phases, replacing only the old opaque
`BodyReady.completeExecution` field with primitive memo replies and a finite
transaction-lifted trie walk. -/
structure PromotionOpportunity (origin : Origin.Parsed) (now : Int64)
    (refused : List (UInt64 × ByteArray × ByteArray)) (state : SimulatedHost.State) where
  tx : Transaction
  opened : SimulatedHost.State
  prepared : SimulatedHost.State
  scope : Serve.Scope
  replicas : List Replication.Materialize.Target
  authority : Authorization.OriginAuthority
  pending : Replication.Promote.Pending
  old : Option Replication.Promote.Pending
  began : execute (Replication.Promote.raw .begin) state = (.ok tx, opened)
  preparation : execute (PromotionCommand.prepare tx origin now) opened =
    (.ok (scope, authority, some pending, old), prepared)
  policy : MaterializationInputs.ReadPolicy state.db origin scope replicas
  policyUnique : ∀ actualScope actualReplicas,
    MaterializationInputs.ReadPolicy state.db origin actualScope actualReplicas →
      actualScope = scope ∧ actualReplicas = replicas
  notRefused : (pending.head.seq, pending.head.root,
    old.map (·.head.root) |>.getD Trie.emptyRoot) ∉ refused
  newer : old.any (fun old => !Replication.Reconcile.newer
    pending.head.seq pending.head.root ⟨old.head.seq, old.head.root⟩) = false
  completion : PromotionFreshOpportunity tx
    ⟨scope, authority.provenance.map Origin.canonical⟩ pending.head.root prepared
  authorized : SimulatedHost.State
  written : SimulatedHost.State
  cleared : SimulatedHost.State
  staged : SimulatedHost.State
  count : UInt64
  permittedExecution :
    execute (PromotionPublication.permitted tx pending authority) completion.final =
      (.ok true, authorized)
  writeExecution : execute (Replication.Promote.history
    (Replication.Reconcile.putSlot tx "complete" pending.head pending.received now)) authorized =
      (.ok (), written)
  clearExecution : execute (Replication.Promote.clear tx origin) written = (.ok (), cleared)
  materializeExecution : execute (Replication.Materialize.materialize tx origin
    (old.map (·.head.root) |>.getD Trie.emptyRoot) pending.head.root) cleared =
      (.ok count, staged)
  final : SimulatedHost.State
  committed : execute (Replication.Promote.raw (.commit tx)) staged = (.ok (), final)

def PromotionOpportunity.bodyReady
    (ready : PromotionOpportunity origin now refused state)
    (publisher : TrieProgramProofs.RawSnapshot)
    (reads : PromotionReadOpportunity publisher ready.tx
      ⟨ready.scope, ready.authority.provenance.map Origin.canonical⟩
      ready.pending.head.root)
    (complete : PermittedComplete publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root
      (replicaOfState ready.prepared)) :
    PromotionProgress.BodyReady ready.tx origin now ready.pending ready.old
      ready.scope ready.authority ready.prepared where
  newer := ready.newer
  checked := ready.completion.final
  authorized := ready.authorized
  written := ready.written
  cleared := ready.cleared
  staged := ready.staged
  count := ready.count
  completeExecution := bodyReady_completeExecution_of_opportunity publisher ready.tx ready.scope
    ready.authority ready.pending ready.prepared reads complete ready.completion
  permittedExecution := ready.permittedExecution
  writeExecution := ready.writeExecution
  clearExecution := ready.clearExecution
  materializeExecution := ready.materializeExecution

/-- Constructor consumed directly by M1: actual begin/prepare, finite
completeness host opportunity, publication/materialization phases and commit
produce the existing positive `PromotionProgress.Ready` witness. -/
def ready_of_opportunity
    (ready : PromotionOpportunity origin now refused state)
    (publisher : TrieProgramProofs.RawSnapshot)
    (reads : PromotionReadOpportunity publisher ready.tx
      ⟨ready.scope, ready.authority.provenance.map Origin.canonical⟩
      ready.pending.head.root)
    (complete : PermittedComplete publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root
      (replicaOfState ready.prepared)) :
    PromotionProgress.Ready origin now refused state where
  tx := ready.tx
  opened := ready.opened
  prepared := ready.prepared
  scope := ready.scope
  replicas := ready.replicas
  authority := ready.authority
  pending := ready.pending
  old := ready.old
  began := ready.began
  preparation := ready.preparation
  policy := ready.policy
  policyUnique := ready.policyUnique
  notRefused := ready.notRefused
  body := ready.bodyReady publisher reads complete
  final := ready.final
  committed := ready.committed

/-- Fetch convergence and the later promotion attempt are joined by durable
evidence inclusion.  Semantic completion at an earlier committed observation
therefore supplies the zero deficit used to build the exact production
completeness execution inside `PromotionProgress.Ready`. -/
def ready_of_semantic_completion
    (ready : PromotionOpportunity origin now refused state)
    (publisher : TrieProgramProofs.RawSnapshot)
    (requirements : FiniteRequirements publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root)
    (complete : PermittedComplete publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root before)
    (carried : EvidenceIncluded before (replicaOfState ready.prepared))
    (reads : PromotionReadOpportunity publisher ready.tx
      ⟨ready.scope, ready.authority.provenance.map Origin.canonical⟩
      ready.pending.head.root) :
    PromotionProgress.Ready origin now refused state := by
  have preparedComplete : PermittedComplete publisher ready.scope
      (ready.authority.provenance.map Origin.canonical) ready.pending.head.root
      (replicaOfState ready.prepared) :=
    TrieFetchCompletion.completion_mono complete carried
  have zero : missingEvidence requirements.items (replicaOfState ready.prepared) = 0 :=
    (TrieFetchCompletion.finite_measure_eq_zero_iff_complete requirements).mpr preparedComplete
  have completed := (finite_promotion_complete_execution publisher ready.tx ready.scope
    ready.authority ready.pending ready.prepared requirements zero reads ready.completion).2
  let body : PromotionProgress.BodyReady ready.tx origin now ready.pending ready.old
      ready.scope ready.authority ready.prepared :=
    { newer := ready.newer
      checked := ready.completion.final
      authorized := ready.authorized
      written := ready.written
      cleared := ready.cleared
      staged := ready.staged
      count := ready.count
      completeExecution := completed
      permittedExecution := ready.permittedExecution
      writeExecution := ready.writeExecution
      clearExecution := ready.clearExecution
      materializeExecution := ready.materializeExecution }
  exact
    { tx := ready.tx
      opened := ready.opened
      prepared := ready.prepared
      scope := ready.scope
      replicas := ready.replicas
      authority := ready.authority
      pending := ready.pending
      old := ready.old
      began := ready.began
      preparation := ready.preparation
      policy := ready.policy
      policyUnique := ready.policyUnique
      notRefused := ready.notRefused
      body := body
      final := ready.final
      committed := ready.committed }

end Synchronicity.TrieCompleteConverse
