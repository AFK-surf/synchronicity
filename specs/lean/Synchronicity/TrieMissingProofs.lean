import VerifiedCore.Trie.Missing
import Synchronicity.TrieCollectProofs
import Synchronicity.TrieServePrivacyProofs

/-! The requesting walk's state transitions and histories, over the code
used by completeness and to be composed into the suspending fetch. This module does not yet
claim exhaustion implies coverage; that needs the reference and visited
set invariant across the whole walk and across store generations. -/
namespace Synchronicity.TrieMissingProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Trie.Missing
  SimulatedHost

/-- The membership laws used by the walk, including resumption's erasure. -/
class LawfulWorkSet (K S : Type) [BEq K] [WorkSet K S] : Prop where
  empty : ∀ (key : K), WorkSet.contains (WorkSet.empty K : S) key = false
  insert : ∀ (set : S) (key probe : K),
    WorkSet.contains (WorkSet.insert set key) probe = (key == probe || WorkSet.contains set probe)
  erase : ∀ (set : S) (key probe : K),
    WorkSet.contains (WorkSet.erase set key) probe = (!(key == probe) && WorkSet.contains set probe)

instance [BEq K] [Hashable K] [LawfulBEq K] [LawfulHashable K] :
    LawfulWorkSet K (Std.HashSet K) where
  empty _ := Std.HashSet.contains_empty
  insert _ _ _ := Std.HashSet.contains_insert
  erase _ _ _ := Std.HashSet.contains_erase

instance [BEq K] [LawfulBEq K] : LawfulWorkSet K (List K) where
  empty _ := rfl
  insert set key probe := by
    show (if set.contains key then set else key :: set).contains probe = (key == probe || set.contains probe)
    split
    · rename_i held
      cases same : key == probe
      · simp
      · simp only [Bool.true_or]
        rw [eq_of_beq same] at held
        exact held
    · rw [List.contains_cons, BEq.comm]
  erase set key probe := by
    show (set.filter fun entry => !(entry == key)).contains probe = (!(key == probe) && set.contains probe)
    apply Bool.eq_iff_iff.mpr
    simp [List.mem_filter, BEq.comm, and_comm]

/-- Both the native representation and the kernel fixtures satisfy the
laws for visit keys as well as plain content addresses. -/
theorem both_set_implementations_are_lawful :
    LawfulWorkSet Visit (Std.HashSet Visit) ∧ LawfulWorkSet ByteArray (Std.HashSet ByteArray) ∧
    LawfulWorkSet Visit (List Visit) ∧ LawfulWorkSet ByteArray (List ByteArray) :=
  ⟨inferInstance, inferInstance, inferInstance, inferInstance⟩

theorem erase_fold_absent [BEq K] [WorkSet K S] [LawfulWorkSet K S]
    (keys : List K) (set : S) (probe : K) (absent : WorkSet.contains set probe = false) :
    WorkSet.contains (keys.foldl WorkSet.erase set) probe = false := by
  induction keys generalizing set with
  | nil => exact absent
  | cons key rest ih =>
    apply ih
    rw [LawfulWorkSet.erase, absent, Bool.and_false]

theorem erase_fold_member [BEq K] [LawfulBEq K] [WorkSet K S] [LawfulWorkSet K S]
    (keys : List K) (set : S) (probe : K) (mem : probe ∈ keys) :
    WorkSet.contains (keys.foldl WorkSet.erase set) probe = false := by
  induction keys generalizing set with
  | nil => cases mem
  | cons key rest ih =>
    simp only [List.foldl_cons]
    rcases List.mem_cons.mp mem with rfl | later
    · apply erase_fold_absent
      simp [LawfulWorkSet.erase]
    · exact ih _ later

/-- A deferred position is never suppressed by an earlier visit after
resumption, for either lawful set implementation. -/
theorem resume_revisits [WorkSet Visit V] [LawfulWorkSet Visit V]
    (context : Context) (frontier : Frontier V H) (position : Position)
    (pending : position ∈ frontier.deferred) :
    WorkSet.contains (resume context frontier).seen
      (visit context.scope position.hash position.path) = false := by
  unfold resume
  simp only
  have folded : frontier.deferred.foldl (fun seen position =>
      WorkSet.erase seen (visit context.scope position.hash position.path)) frontier.seen =
      (frontier.deferred.map fun position => visit context.scope position.hash position.path).foldl
        WorkSet.erase frontier.seen := by rw [List.foldl_map]
  rw [folded]
  exact erase_fold_member _ _ _ (List.mem_map.mpr ⟨position, pending, rfl⟩)

/-- Even a value deduplicated from the request keeps this holder deferred;
neither it nor an absent node can make the walk exhausted. -/
theorem absent_defers [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (work : Work V H) (position : Position) (rest : List Position) :
    (commit context work position rest .absent).frontier.deferred = position :: work.frontier.deferred ∧
    (commit context work position rest .absent).frontier.isExhausted = false := by
  simp [commit, Frontier.isExhausted]

theorem missing_value_defers [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (work : Work V H) (position : Position) (rest children : List Position)
    (pending : Option ByteArray) (values : List ByteArray) (nonempty : values.isEmpty = false) :
    (commit context work position rest (.expand children pending values)).frontier.deferred =
      position :: work.frontier.deferred ∧
    (commit context work position rest (.expand children pending values)).frontier.isExhausted = false := by
  simp [commit, nonempty, Frontier.isExhausted]

/-- A failed position returns exactly the frontier it interrupted, except
for remembering a canonicality fault. It commits none of that inspection's
deduplication, child-expansion or pending-branch changes. -/
theorem batchStep_interrupted [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (maximum : Nat) (work : Work V H) (position : Position) (rest : List Position)
    (state after : State) (error : Missing.Error)
    (healthy : work.frontier.fault = none) (pending : work.frontier.positions = position :: rest)
    (entering : position.finish = false)
    (room : work.batch.size < maximum)
    (interrupted : execute (inspect context work.frontier position) state = (.error error, after)) :
    execute (batchStep context maximum work) state =
      (.ok (.inr (failed work.frontier error, .error error)), after) := by
  simp only [batchStep, healthy, pending, entering, Bool.false_eq_true, Nat.not_le.mpr room,
    ↓reduceIte, ExceptT.mk,
    ExceptT.run, bind, execute_bind, interrupted, pure, execute]

/-- A terminal fault is returned before any host effect, regardless of
batch size, remaining frontier or resumption. -/
theorem fault_stays_terminal [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (maximum : Nat) (work : Work V H) (fault : Fault) (state : State)
    (poisoned : work.frontier.fault = some fault) :
    execute (batchStep context maximum work) state =
      (.ok (.inr (work.frontier, .error (.canonical fault))), state) := by
  simp [batchStep, poisoned, execute, pure, ExceptT.pure, ExceptT.mk]

/-! ## Scope throughout the frontier and batches -/

def PositionsAdmitted (scope : Serve.Scope) (positions : List Position) : Prop :=
  ∀ position ∈ positions, scope.admitsPath position.path.toList = true

def WantsAdmitted (scope : Serve.Scope) (wants : List (ByteArray × ByteArray)) : Prop :=
  ∀ want ∈ wants, scope.admitsPath want.1.toList = true

def FrontierAdmitted (scope : Serve.Scope) (frontier : Frontier V H) : Prop :=
  PositionsAdmitted scope frontier.positions ∧ PositionsAdmitted scope frontier.deferred

def BatchAdmitted (scope : Serve.Scope) (batch : Batch) : Prop :=
  WantsAdmitted scope batch.nodes ∧ WantsAdmitted scope batch.values

def WorkAdmitted (scope : Serve.Scope) (work : Work V H) : Prop :=
  FrontierAdmitted scope work.frontier ∧ BatchAdmitted scope work.batch

def ResultAdmitted (scope : Serve.Scope) (result : BatchResult V H) : Prop :=
  FrontierAdmitted scope result.1 ∧ ∀ batch, result.2 = .ok batch → BatchAdmitted scope batch

theorem initial_admitted [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (reference : Option ByteArray) (root : ByteArray) :
    FrontierAdmitted context.scope (initial (V := V) (H := H) context reference root) := by
  unfold initial FrontierAdmitted PositionsAdmitted
  cases rooted : rootOf root with
  | none => simp
  | some hash =>
    cases allowed : context.scope.admitsPath [] <;> simp [allowed]

theorem resume_admitted [WorkSet Visit V] (context : Context) (frontier : Frontier V H)
    (held : FrontierAdmitted context.scope frontier) :
    FrontierAdmitted context.scope (resume context frontier) := by
  constructor
  · intro position mem
    rcases List.mem_append.mp mem with deferred | pending
    · exact held.2 position deferred
    · exact held.1 position pending
  · intro position mem
    cases mem

theorem pushChildren_admitted (scope : Serve.Scope) (path : ByteArray) (children stack : List Position)
    (held : PositionsAdmitted scope stack) : PositionsAdmitted scope (pushChildren scope path children stack) := by
  induction children generalizing stack with
  | nil => exact held
  | cons child rest ih =>
    unfold pushChildren
    simp only [List.foldl_cons]
    split
    · rename_i allowed
      apply ih
      intro position mem
      rcases List.mem_cons.mp mem with rfl | pending
      · exact allowed
      · exact held position pending
    · exact ih stack held

theorem askValues_admitted [WorkSet ByteArray H] (scope : Serve.Scope) (path : ByteArray)
    (absent : List ByteArray) (asked : H) (values : List (ByteArray × ByteArray))
    (atPath : scope.admitsPath path.toList = true) (held : WantsAdmitted scope values) :
    WantsAdmitted scope (askValues path absent asked values).2 := by
  induction absent generalizing asked values with
  | nil => exact held
  | cons hash rest ih =>
    unfold askValues
    simp only [List.foldl_cons]
    split
    · exact ih asked values held
    · apply ih
      intro want mem
      rcases List.mem_cons.mp mem with rfl | pending
      · exact atPath
      · exact held want pending

theorem commit_admitted [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (work : Work V H) (position : Position) (rest : List Position) (checked : Checked)
    (held : WorkAdmitted context.scope work)
    (pending : work.frontier.positions = position :: rest) :
    WorkAdmitted context.scope (commit context work position rest checked) := by
  have atPath := held.1.1 position (by rw [pending]; exact List.mem_cons_self ..)
  have tail : PositionsAdmitted context.scope rest := fun child mem =>
    held.1.1 child (by rw [pending]; exact List.mem_cons_of_mem _ mem)
  have deferred : PositionsAdmitted context.scope (position :: work.frontier.deferred) := by
    intro child mem
    rcases List.mem_cons.mp mem with rfl | old
    · exact atPath
    · exact held.1.2 child old
  cases checked with
  | skip => exact ⟨⟨tail, held.1.2⟩, held.2⟩
  | boundary => exact ⟨⟨tail, held.1.2⟩, held.2⟩
  | absent =>
    refine ⟨⟨tail, deferred⟩, ?_, held.2.2⟩
    intro want mem
    rcases List.mem_cons.mp mem with rfl | old
    · exact atPath
    · exact held.2.1 want old
  | expand children pendingBranch values routing =>
    have finishTail : PositionsAdmitted context.scope
        (if values.isEmpty then { position with finish := true } :: rest else rest) := by
      split
      · intro child mem
        rcases List.mem_cons.mp mem with rfl | old
        · exact atPath
        · exact tail child old
      · exact tail
    refine ⟨⟨pushChildren_admitted _ _ _ _ finishTail, ?_⟩, held.2.1,
      askValues_admitted _ _ _ _ _ atPath held.2.2⟩
    change PositionsAdmitted context.scope (if values.isEmpty then work.frontier.deferred
      else position :: work.frontier.deferred)
    split
    · exact held.1.2
    · exact deferred

theorem finished_admitted (scope : Serve.Scope) (work : Work V H)
    (held : WorkAdmitted scope work) : ResultAdmitted scope (finished work) := by
  refine ⟨held.1, ?_⟩
  intro batch result
  have same := Except.ok.inj result
  subst batch
  exact ⟨fun want mem => held.2.1 want (List.mem_reverse.mp mem),
    fun want mem => held.2.2 want (List.mem_reverse.mp mem)⟩

theorem settle_admitted [WorkSet Visit V] (context : Context) (work : Work V H)
    (position : Position) (rest : List Position)
    (held : WorkAdmitted context.scope work)
    (pending : work.frontier.positions = position :: rest) :
    WorkAdmitted context.scope (settle context work position rest) := by
  have atPath := held.1.1 position (by rw [pending]; exact List.mem_cons_self ..)
  have tail : PositionsAdmitted context.scope rest := fun child member =>
    held.1.1 child (by rw [pending]; exact List.mem_cons_of_mem _ member)
  unfold settle
  split
  · exact ⟨⟨tail, held.1.2⟩, held.2⟩
  · refine ⟨⟨tail, ?_⟩, held.2⟩
    intro child member
    rcases List.mem_append.mp member with old | last
    · exact held.1.2 child old
    · have same : child = position := by simpa using last
      rw [same]
      exact atPath

/-- Every successful step keeps its frontier and accumulated wants within
scope, or returns an answer with the same property. This needs no assumptions
about the host's bytes or failures. -/
theorem batchStep_admitted [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (maximum : Nat) (work : Work V H) (state : State)
    (held : WorkAdmitted context.scope work) (result : Work V H ⊕ BatchResult V H)
    (ran : (execute (batchStep context maximum work) state).1 = .ok result) :
    match result with
    | .inl next => WorkAdmitted context.scope next
    | .inr answer => ResultAdmitted context.scope answer := by
  unfold batchStep at ran
  cases poisoned : work.frontier.fault with
  | some fault =>
    simp only [poisoned] at ran
    have same := Except.ok.inj ran
    subst result
    exact ⟨held.1, fun _ impossible => nomatch impossible⟩
  | none =>
    simp only [poisoned] at ran
    cases pending : work.frontier.positions with
    | nil =>
      simp only [pending] at ran
      have same := Except.ok.inj ran
      subst result
      exact finished_admitted _ _ held
    | cons position rest =>
      simp only [pending] at ran
      split at ran
      · have same := Except.ok.inj ran
        subst result
        exact settle_admitted context work position rest held pending
      · simp only [ExceptT.mk, ExceptT.run, bind] at ran
        split at ran
        · have same := Except.ok.inj ran
          subst result
          exact finished_admitted _ _ held
        · rw [execute_bind] at ran
          generalize execution : execute (inspect context work.frontier position) state = inspected at ran
          obtain ⟨reply, after⟩ := inspected
          cases reply with
          | error error =>
            have same := Except.ok.inj ran
            subst result
            refine ⟨?_, fun _ impossible => nomatch impossible⟩
            cases error <;> exact held.1
          | ok checked =>
            have same := Except.ok.inj ran
            subst result
            exact commit_admitted context work position rest checked held pending

/-- Every reported want is at a scope-admitted position, for any batch
size and any host state. The returned frontier preserves that fact for
later rounds and resumption. -/
theorem nextBatch_admitted [WorkSet Visit V] [WorkSet ByteArray H] (context : Context)
    (frontier : Frontier V H) (maximum : Nat) (state : State)
    (held : FrontierAdmitted context.scope frontier) (result : BatchResult V H)
    (ran : (execute (nextBatch context frontier maximum) state).1 = .ok result) :
    ResultAdmitted context.scope result := by
  have initialOk : WorkAdmitted context.scope (⟨frontier, {}, WorkSet.empty ByteArray⟩ : Work V H) :=
    ⟨held, (by simp [BatchAdmitted, WantsAdmitted])⟩
  have keeps := fun (work : Work V H) state next held ran =>
    batchStep_admitted context maximum work state held (.inl next) ran
  have stops := fun (work : Work V H) state answer held ran =>
    batchStep_admitted context maximum work state held (.inr answer) ran
  exact iterate_sound (fun work => (batchStep context maximum work).run) Missing.Error.exhausted
    (WorkAdmitted context.scope) (ResultAdmitted context.scope) keeps stops batchFuel _ state
    (keeps _ state · initialOk) (stops _ state · initialOk) result ran

/-! ## Shared-state histories

The fixtures start inside the transaction the caller owns. Byte reads use
the raw files and existence queries the raw rows in that same snapshot. -/
open TrieServeProofs

abbrev ListFrontier := Frontier (List Visit) (List ByteArray)

def full : Context := ⟨⟨none, []⟩, none⟩

def snapshot (state : State) : State := { state with pending := some (1, state.db) }

def withoutValue : State :=
  { graph with files := graph.files.filter fun entry => entry.1.1 != valueSpace }

def withValue : State :=
  { graph with
    files := ((valueSpace, valueHash), ⟨Array.replicate 129 1⟩) ::
      (graph.files.filter fun entry => entry.1.1 != valueSpace)
    db := (valueSpace, [[("hash", .blob valueHash), ("value", .blob payload)]]) :: graph.db }

/-- The same immutable frontier is passed to the next command; only the
host state changes when the caller stores a fetched payload. -/
def batchRun (context : Context) (frontier : ListFrontier) (maximum : Nat) (state : State) :=
  SimulatedHost.run (nextBatch context frontier maximum) (snapshot state)

def initialFull : ListFrontier := initial full none rootHash

def summary (result : Except Missing.Error (BatchResult (List Visit) (List ByteArray))) :=
  result.map fun (frontier, batch) => (batch, frontier.isExhausted,
    frontier.positions.map Position.hash, frontier.deferred.map Position.hash)

/-- A missing out-of-line value keeps its holder outstanding. It is asked
again on a resumed round, then exhaustion follows only after it arrives. -/
theorem missing_value_repeats_until_it_arrives :
    let first := batchRun full initialFull 64 withoutValue
    (summary first.1 == .ok (.ok ⟨[], [(bytes atLeafB, valueHash)], []⟩, false, [],
      [leafBHash, leafAHash, lowerHash, extHash, rootHash])) ∧
    (match first.1 with
      | .error _ => false
      | .ok (frontier, _) =>
        let retry := batchRun full (resume full frontier) 64 withoutValue
        let complete := batchRun full (resume full frontier) 64 withValue
        summary retry.1 == .ok (.ok ⟨[], [(bytes atLeafB, valueHash)], []⟩, false, [],
          [leafBHash, leafAHash, lowerHash, extHash, rootHash]) &&
        summary complete.1 == .ok (.ok {}, true, [], []) &&
        complete.2.trace == ["bytes:" ++ nodeSpace, "bytes:" ++ valueSpace]) = true := by
  decide +kernel

/-- One missing hash may be held by two nodes: ask once per batch but defer
both holders, so deduplication cannot manufacture completeness. -/
theorem shared_value_defers_every_holder :
    let state : State :=
      { files := [((nodeSpace, rootHash), encode (.branch (slots [(1, leafAHash), (2, leafBHash)]) none)),
          ((nodeSpace, leafAHash), encode (.leaf (bytes [0]) (.hash valueHash))),
          ((nodeSpace, leafBHash), encode (.leaf (bytes [1]) (.hash valueHash)))] }
    let first := batchRun full initialFull 64 state
    summary first.1 == .ok (.ok ⟨[], [(bytes [2], valueHash)], []⟩, false, [],
      [leafAHash, leafBHash, rootHash]) := by
  decide +kernel

/-- A shared DAG node reached at two distinct paths cannot enter `seen` after
the first path discovers an unfinished payload.  Both holders remain
retryable; the old preorder insertion skipped the second occurrence. -/
theorem unfinished_shared_dag_visit_is_not_seen :
    let state : State :=
      { files := [
          ((nodeSpace, rootHash),
            encode (.branch (slots [(1, leafAHash), (2, leafAHash)]) none)),
          ((nodeSpace, leafAHash), encode (.leaf (bytes [0]) (.hash valueHash)))] }
    let first := batchRun full initialFull 64 state
    (match first.1 with
      | .error _ => false
      | .ok (frontier, result) =>
        result == .ok ⟨[], [(bytes [2], valueHash)], []⟩ &&
        frontier.seen == [] &&
        frontier.deferred.map Position.hash == [leafAHash, leafAHash, rootHash]) = true := by
  decide +kernel

/-- A refused node remains missing on a grant's spine as well as inside it.
An unsupported refusal never makes the requesting walk complete. -/
theorem refusals_cannot_satisfy_missing_positions :
    (let context : Context := ⟨onLeafA, none⟩
     let state : State := { redacted := [(rootHash, bytes [])] }
     let result := batchRun context (initial context none rootHash) 64 state
     summary result.1 == .ok (.ok ⟨[(bytes [], rootHash)], [], []⟩, false, [], [rootHash]) &&
       result.2.trace == ["bytes:" ++ nodeSpace]) ∧
    (let state : State := { redacted := [(rootHash, bytes [])] }
     let result := batchRun full initialFull 64 state
     summary result.1 == .ok (.ok ⟨[(bytes [], rootHash)], [], []⟩, false, [], [rootHash]) &&
       result.2.trace == ["bytes:" ++ nodeSpace]) := by
  decide +kernel

/-- Holding a boundary's bytes overrides a remembered refusal: descend it
and still ask for the in-grant value beneath it. -/
theorem a_held_boundary_is_expanded :
    let context : Context := ⟨onLeafB, none⟩
    let state := { withoutValue with redacted := [(rootHash, bytes [])] }
    summary (batchRun context (initial context none rootHash) 64 state).1 ==
      .ok (.ok ⟨[], [(bytes atLeafB, valueHash)], []⟩, false, [],
        [leafBHash, lowerHash, extHash, rootHash]) := by
  decide +kernel

/-- A confined root needs provenance even when another origin supplied all
its bytes. A reference known complete for the same owner prunes before reads. -/
theorem provenance_and_reference_are_distinct_inputs :
    (let context : Context := ⟨⟨none, []⟩, some "stranger"⟩
     let result := batchRun context (initial context none rootHash) 64 withValue
     summary result.1 == .ok (.ok ⟨[(bytes [], rootHash)], [], []⟩, false, [], [rootHash]) &&
       result.2.trace == ["snapshot:trie_node_origins"]) ∧
    (let result := batchRun full (initial full (some rootHash) rootHash) 64 withValue
     summary result.1 == .ok (.ok {}, true, [], []) && result.2.trace == []) := by
  decide +kernel

/-- An extension above a leaf is a terminal origin fault. Resumption cannot
clear the fault, and the second call asks the host for nothing. -/
theorem an_extension_requires_a_branch :
    let state : State := { files := [((nodeSpace, rootHash), encode (.extension (bytes [1]) leafAHash)),
      ((nodeSpace, leafAHash), encode leafANode)] }
    let first := batchRun full initialFull 64 state
    (match first.1 with
      | .error _ => false
      | .ok (frontier, result) =>
        result == .error (.canonical (.expectedBranch leafAHash)) &&
        frontier.positions == initialFull.positions &&
        (batchRun full (resume full frontier) 64 state).2.trace == []) = true := by
  decide +kernel

/-- An absent extension child is remembered as requiring a branch. When
the bytes arrive as a leaf, the resumed walk refuses the same origin. -/
theorem a_late_extension_child_is_still_checked :
    let state : State := { files := [((nodeSpace, rootHash), encode (.extension (bytes [1]) leafAHash))] }
    let first := batchRun full initialFull 64 state
    (match first.1 with
      | .error _ => false
      | .ok (frontier, result) =>
        result == .ok ⟨[(bytes [1], leafAHash)], [], []⟩ && frontier.mustBeBranch.contains leafAHash &&
        (let supplied := { state with files := ((nodeSpace, leafAHash), encode leafANode) :: state.files }
         match (batchRun full (resume full frontier) 64 supplied).1 with
         | .error _ => false
         | .ok (_, result) => result == .error (.canonical (.expectedBranch leafAHash)))) = true := by
  decide +kernel

/-- The batch limit is checked before the next read. Zero asks nothing and
leaves the root pending; one absent node is sufficient to stop the batch. -/
theorem the_batch_limit_keeps_unfinished_positions :
    (let result := batchRun full initialFull 0 {}
     summary result.1 == .ok (.ok {}, false, [rootHash], []) && result.2.trace == []) ∧
    (let result := batchRun full initialFull 1 {}
     summary result.1 == .ok (.ok ⟨[(bytes [], rootHash)], [], []⟩, false, [], [rootHash]) &&
       result.2.trace == ["bytes:" ++ nodeSpace]) := by
  decide +kernel

/-- Reference pairing follows equal branch slots and equal extension
labels; a different extension label deliberately supplies no reference. -/
theorem children_pair_only_at_the_same_position :
    (pairedChildren (some (.branch (slots [(1, leafAHash), (2, leafBHash)]) none))
      (.branch (slots [(1, extHash), (3, lowerHash)]) none) ==
        [⟨some leafAHash, extHash, bytes [1], false⟩, ⟨none, lowerHash, bytes [3], false⟩]) ∧
    (pairedChildren (some (.extension (bytes [1, 2]) leafAHash))
      (.extension (bytes [1, 2]) leafBHash) == [⟨some leafAHash, leafBHash, bytes [1, 2], false⟩]) ∧
    (pairedChildren (some (.extension (bytes [1, 3]) leafAHash))
      (.extension (bytes [1, 2]) leafBHash) == [⟨none, leafBHash, bytes [1, 2], false⟩]) := by
  decide +kernel

/-- A failed empty scan cannot stand for absence. A row already returned
establishes presence, regardless of a failure stepping beyond it. -/
theorem presence_keeps_the_scan_failure_boundary :
    ((SimulatedHost.run (rowPresent valueSpace [("hash", .blob valueHash)])
      { scanFault := some (0, invalid) }).1 == .error (.host invalid)) ∧
    ((SimulatedHost.run (rowPresent valueSpace [("hash", .blob valueHash)])
      { withValue with scanFault := some (0, invalid) }).1 == .ok true) := by
  decide +kernel

/-- Failure at every read of the complete fixture retains the interrupted
position. Retrying that returned state, without even calling `resume`,
still reaches exhaustion once the host stops failing. -/
theorem every_interrupted_read_can_retry :
    (List.range 7).all (fun index =>
      let first := batchRun full initialFull 64 (CasFixtures.fail withValue index)
      match first.1 with
      | .error _ => false
      | .ok (frontier, result) =>
        CasFixtures.failed result && !frontier.positions.isEmpty &&
        frontier.fault.isNone && first.2.files == withValue.files && first.2.db == withValue.db &&
        summary (batchRun full frontier 64 withValue).1 == .ok (.ok {}, true, [], [])) = true := by
  decide +kernel

end Synchronicity.TrieMissingProofs

namespace Synchronicity.TrieMissingProofs
open VerifiedCore VerifiedCore.Host SimulatedHost
open VerifiedCore.Trie VerifiedCore.Trie.Missing TrieServeProofs

/-- A locally present small payload cannot establish completeness through a
legacy addressed holder, even if another snapshot legitimately stored it. -/
theorem small_legacy_payload_is_rejected :
    ((batchRun full initialFull 64 graph).1.map Prod.snd) ==
      .ok (.error (.canonical (.valueLength valueHash payload.size false))) := by
  decide +kernel

/-- Routing holders may address small payloads without forcing their bytes
into the routing node disclosed to a reader. -/
theorem small_route_payload_is_complete :
    let state : State := { files :=
      [((nodeSpace, rootHash), encode (.route (slots []) (some valueHash))),
       ((valueSpace, valueHash), payload)] }
    summary (batchRun full initialFull 64 state).1 == .ok (.ok {}, true, [], []) := by
  decide +kernel

/-- Presence alone never certifies an oversized routing payload. -/
theorem oversized_route_payload_is_rejected :
    let state : State := { files :=
      [((nodeSpace, rootHash), encode (.route (slots []) (some valueHash))),
       ((valueSpace, valueHash), ⟨Array.replicate 32769 0⟩)] }
    ((batchRun full initialFull 64 state).1.map Prod.snd) ==
      .ok (.error (.canonical (.valueLength valueHash 32769 true))) := by
  decide +kernel

end Synchronicity.TrieMissingProofs
