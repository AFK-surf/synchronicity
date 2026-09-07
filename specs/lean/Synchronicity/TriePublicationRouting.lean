import Synchronicity.TrieNormalizeProofs
import Synchronicity.TrieServeProofs

/-! Publication routing separates the commitments needed to locate shared
entries from the payloads a peer is allowed to read. The target is the form
produced by the actual normalization operation, followed by its effect on the
actual serving decision. Compression remains valid inside complete grants. -/
namespace Synchronicity.TriePublicationRouting
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open TrieProgramProofs TrieSnapshotProofs TrieSnapshotClosure TrieNormalizeProofs
open TrieServeProofs TrieMutateProofs TrieWriteSemantics

/-- Every position outside a complete compression boundary is an addressed
routing node. This describes stored bytes, not a traversal completion flag. -/
inductive RoutedAt (store : RawSnapshot) : List UInt8 → ByteArray → Prop where
  | inside (boundary : Normalize.belowBoundary path = true) (closed : Closed store root) :
      RoutedAt store path root
  | route (held : store nodeSpace root = some raw)
      (decoded : decode raw = .ok (.route children value)) (closed : Closed store root)
      (below : ∀ (nibble : UInt8) child, children[nibble.toNat]? = some (some child) →
        RoutedAt store (path ++ [nibble]) child) : RoutedAt store path root

/-- Schema grants contain a whole deliberately compressed subtree whenever
they intersect it. Exact metadata keys outside those boundaries remain valid
and need not be prefix-free. The authorization layer must establish this for
its actual grants; arbitrary `Scope` values need not satisfy it. -/
def BoundaryCompatible (scope : Serve.Scope) : Prop :=
  ∀ path, Normalize.belowBoundary path = true → scope.admitsPath path = true →
    scope.containsSubtree path = true

/-- Adding compatible records cannot turn an already routed version into an
unrouted one, including when other completed siblings are written later. -/
theorem routed_preserved (routed : RoutedAt before path root)
    (included : RecordsIncluded before after) : RoutedAt after path root := by
  induction routed with
  | inside boundary closed => exact .inside boundary (closed_preserved closed included)
  | route held decoded closed below ih =>
    exact .route (included _ _ _ (.inl rfl) held) decoded (closed_preserved closed included)
      (fun nibble child edge => ih nibble child edge)

/-- A routed snapshot can reveal every node needed on an authorized path,
without requiring permission to read a private ancestor's payload. -/
theorem routed_nodes_are_admitted (compatible : BoundaryCompatible scope)
    (routed : RoutedAt store pathPrefix root)
    (reaches : Reaches (store nodeSpace) root suffix found)
    (admitted : scope.admitsPath (pathPrefix ++ suffix) = true)
    (held : store nodeSpace found = some raw) (decoded : decode raw = .ok node) :
    scope.admitsNode (pathPrefix ++ suffix) node = true := by
  induction routed generalizing suffix found raw node with
  | @inside pathPrefix root boundary closed =>
    exact no_redaction_inside_grant scope _ node
      (containsSubtree_append scope pathPrefix suffix
        (compatible pathPrefix boundary (admitsPath_of_append scope pathPrefix suffix admitted)))
  | @route root ownRaw children value pathPrefix stored ownDecoded closed below ih =>
    cases reaches with
    | here =>
      rw [stored] at held
      cases held
      rw [ownDecoded] at decoded
      cases decoded
      exact admitted
    | extension hash bytes segment child found rest loaded shape nonempty reaches =>
      rw [stored] at loaded
      cases loaded
      rw [ownDecoded] at shape
      cases shape
    | branch hash bytes child found children value nibble rest loaded shape edge reaches =>
      rw [stored] at loaded
      cases loaded
      rw [ownDecoded] at shape
      cases shape
    | route hash bytes child found children value nibble rest loaded shape edge reaches =>
      rw [stored] at loaded
      cases loaded
      rw [ownDecoded] at shape
      cases shape
      have pathSame : pathPrefix ++ nibble :: rest = (pathPrefix ++ [nibble]) ++ rest := by simp
      rw [pathSame] at admitted ⊢
      exact ih nibble child edge reaches admitted held decoded

/-- Paths of results waiting for their parent. Assembly records its parent
path in the proof invariant even though the executable stack need not store
that redundant information. -/
inductive PendingPaths : List Normalize.Work → List (List UInt8) → List UInt8 → Prop where
  | done (path : List UInt8) : PendingPaths [] [path] path
  | visit (below : PendingPaths work (path :: results) target) :
      PendingPaths (.visit path cursor :: work) results target
  | assemble (positions : List UInt8)
      (below : PendingPaths work (path :: results) target) :
      PendingPaths (.assemble positions value :: work)
        ((positions.map (fun nibble => path ++ [nibble])).reverse ++ results) target

inductive RoutedResults (store : RawSnapshot) : List ByteArray → List (List UInt8) → Prop where
  | nil : RoutedResults store [] []
  | cons (head : RoutedAt store path root) (tail : RoutedResults store roots paths) :
      RoutedResults store (root :: roots) (path :: paths)

/-- Each completed root has the publication form required at its original
path, and the pending work will assemble those paths into the selected root. -/
def RoutingState (store : RawSnapshot) (state : Normalize.State) (path : List UInt8) : Prop :=
  ∃ paths, PendingPaths state.work paths path ∧ RoutedResults store state.results paths

private theorem routed_results_preserved (ready : RoutedResults before roots paths)
    (included : RecordsIncluded before after) : RoutedResults after roots paths := by
  induction ready with
  | nil => exact .nil
  | cons head tail ih => exact .cons (routed_preserved head included) ih

private theorem routing_state_preserved (state : RoutingState before machine path)
    (included : RecordsIncluded before after) : RoutingState after machine path := by
  obtain ⟨paths, pending, ready⟩ := state
  exact ⟨paths, pending, routed_results_preserved ready included⟩

private theorem prepend_visit_paths (selected : List (UInt8 × ByteArray))
    (below : PendingPaths work
      ((selected.map (fun edge => path ++ [edge.1])).reverse ++ results) target) :
    PendingPaths
      ((selected.map fun edge => Normalize.Work.visit (path ++ [edge.1]) (.stored edge.2)) ++ work)
      results target := by
  induction selected generalizing results with
  | nil => simpa using below
  | cons edge rest ih =>
    simp only [List.map_cons, List.cons_append]
    apply PendingPaths.visit
    apply ih
    simpa only [List.map_cons, List.reverse_cons, List.append_assoc,
      List.singleton_append] using below

private theorem schedule_paths
    (below : PendingPaths state.work (path :: paths) target) :
    PendingPaths (Normalize.schedule path children value state).work paths target := by
  let selected := (List.range 16).filterMap fun index =>
    ((children[index]?).getD none).map fun address => (index.toUInt8, address)
  have assembled := PendingPaths.assemble (value := value) (selected.map Prod.fst) below
  simp only [List.map_map, Function.comp_def] at assembled
  exact prepend_visit_paths selected assembled

/-- Every occupied edge of a constructed routing node points to a subtree
with the publication form required at that child path. -/
def RoutedChildren (store : RawSnapshot) (path : List UInt8)
    (children : List (Option ByteArray)) : Prop :=
  ∀ (nibble : UInt8) child, children[nibble.toNat]? = some (some child) →
    RoutedAt store (path ++ [nibble]) child

private theorem set_child_routed {position : UInt8} (childrenRouted : RoutedChildren store path children)
    (bound : position.toNat < children.length)
    (rootRouted : RoutedAt store (path ++ [position]) root) :
    RoutedChildren store path (setChild children position (some root)) := by
  intro nibble child edge
  by_cases same : nibble = position
  · subst nibble
    rw [setChild, List.getElem?_set_self bound] at edge
    cases edge
    exact rootRouted
  · rw [TrieMutateProofs.setChild_getElem_ne children (Ne.symm same)] at edge
    exact childrenRouted nibble child edge

/-- The real child assembler retains the routed meaning of each consumed
result and leaves surrounding completed results untouched. -/
theorem assemble_children_routed (positions : List UInt8)
    (width : children.length = 16)
    (bounds : ∀ position ∈ positions, position.toNat < 16)
    (childrenRouted : RoutedChildren store path children)
    (ready : RoutedResults store roots
      ((positions.map (fun nibble => path ++ [nibble])) ++ remainingPaths))
    (ran : Normalize.assembleChildren positions roots children = some (built, rest)) :
    RoutedChildren store path built ∧ RoutedResults store rest remainingPaths := by
  induction positions generalizing roots children with
  | nil =>
    simp only [Normalize.assembleChildren, Option.some.injEq, Prod.mk.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨childrenRouted, ready⟩
  | cons position positions ih =>
    cases ready with
    | cons head tail =>
      exact ih (by simpa [setChild] using width)
        (fun nibble member => bounds nibble (by simp [member]))
        (set_child_routed childrenRouted (by rw [width]; exact bounds position (by simp)) head)
        tail ran

private theorem head_closed
    (meaning : StateMeaning store ⟨work, root :: roots⟩ target) : Closed store root := by
  obtain ⟨views, pending, completed⟩ := meaning
  cases completed with
  | cons head tail => exact head.2.1

private theorem push_routed_result
    (routing : RoutingState before ⟨.visit path cursor :: work, roots⟩ target)
    (included : RecordsIncluded before after) (routed : RoutedAt after path root) :
    RoutingState after ⟨work, root :: roots⟩ target := by
  obtain ⟨paths, pending, ready⟩ := routing
  cases pending with
  | visit below => exact ⟨_, below, .cons routed (routed_results_preserved ready included)⟩

private theorem unary_routing_state
    (routing : RoutingState store ⟨.visit path cursor :: work, roots⟩ target) :
    RoutingState store
      ⟨.visit (path ++ [nibble]) child :: .assemble [nibble] none :: work, roots⟩ target := by
  obtain ⟨paths, pending, ready⟩ := routing
  cases pending with
  | visit below =>
    refine ⟨paths, .visit ?_, ready⟩
    simpa using PendingPaths.assemble (value := none) [nibble] below

private theorem scheduled_routing_state
    (routing : RoutingState before ⟨.visit path cursor :: work, roots⟩ target)
    (included : RecordsIncluded before after) :
    RoutingState after (Normalize.schedule path children value ⟨work, roots⟩) target := by
  obtain ⟨paths, pending, ready⟩ := routing
  cases pending with
  | visit below => exact ⟨paths, schedule_paths below, routed_results_preserved ready included⟩

/-- Keeping a whole compressed subtree is permitted exactly at a schema
boundary; its stored form is carried into the actual result stack. -/
theorem boundary_step_routed
    (routing : RoutingState before.read ⟨.visit path cursor :: work, roots⟩ target)
    (meaningAfter : StateMeaning after.read next entries)
    (within : path.length ≤ maxKeyBytes * 2) (boundary : Normalize.belowBoundary path = true)
    (safe : SafeWrites d before (Normalize.step ⟨.visit path cursor :: work, roots⟩).run)
    (ran : execute d before (Normalize.step ⟨.visit path cursor :: work, roots⟩).run =
      some (.ok (.inl next), after)) : RoutingState after.read next target := by
  have included := execution_preserves_records _ safe ran
  cases cursor with
  | stored root =>
    simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, boundary, run_bind,
      run_pure, program_bind_pure, bindCont_ok, TrieMutateProofs.execute_pure,
      Option.some.injEq, Prod.mk.injEq, Except.ok.injEq, Sum.inl.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact push_routed_result routing included (.inside boundary (head_closed meaningAfter))
  | node node =>
    simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, boundary] at ran
    rw [execute_run_bind, execute_put] at ran
    simp only [run_pure, TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq,
      Except.ok.injEq, Sum.inl.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact push_routed_result routing included (.inside boundary (head_closed meaningAfter))

/-- Splitting an exact leaf into routing edges retains the original path at
which its eventual addressed payload must be assembled. -/
theorem leaf_edge_step_routed
    (routing : RoutingState before.read ⟨.visit path (.node (.leaf suffix value)) :: work, roots⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (spelling : suffix.toList = nibble :: rest)
    (ran : execute d before
      (Normalize.step ⟨.visit path (.node (.leaf suffix value)) :: work, roots⟩).run =
      some (.ok (.inl next), after)) : RoutingState after.read next target := by
  simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, spine, Bool.false_eq_true,
    spelling, run_bind, run_pure, program_bind_pure, bindCont_ok,
    TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq,
    Except.ok.injEq, Sum.inl.injEq] at ran
  obtain ⟨rfl, rfl⟩ := ran
  exact unary_routing_state routing

/-- An extension is split at the same path positions as a leaf, whether its
last edge leads to another stored node or to a remaining constructed run. -/
theorem extension_edge_step_routed
    (routing : RoutingState before.read
      ⟨.visit path (.node (.extension segment child)) :: work, roots⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (spelling : segment.toList = nibble :: rest)
    (ran : execute d before
      (Normalize.step ⟨.visit path (.node (.extension segment child)) :: work, roots⟩).run =
      some (.ok (.inl next), after)) : RoutingState after.read next target := by
  simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, spine, Bool.false_eq_true,
    spelling, run_bind, run_pure, program_bind_pure, bindCont_ok,
    TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq,
    Except.ok.injEq, Sum.inl.injEq] at ran
  obtain ⟨rfl, rfl⟩ := ran
  exact unary_routing_state routing

/-- Existing route nodes schedule all children at their original paths. -/
theorem route_step_routed
    (routing : RoutingState before.read ⟨.visit path (.node (.route children value)) :: work, roots⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (ran : execute d before
      (Normalize.step ⟨.visit path (.node (.route children value)) :: work, roots⟩).run =
      some (.ok (.inl next), after)) : RoutingState after.read next target := by
  simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, spine, Bool.false_eq_true,
    run_bind, run_pure, program_bind_pure, bindCont_ok,
    TrieMutateProofs.execute_pure, Option.some.injEq, Prod.mk.injEq,
    Except.ok.injEq, Sum.inl.injEq] at ran
  obtain ⟨rfl, rfl⟩ := ran
  exact scheduled_routing_state routing (fun _ _ _ _ held => held)

/-- Addressing a branch payload preserves completed siblings and queues its
children at the same paths used by the actual routing assembler. -/
theorem branch_step_routed
    (routing : RoutingState before.read ⟨.visit path (.node (.branch children value)) :: work, roots⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (safe : SafeWrites d before
      (Normalize.step ⟨.visit path (.node (.branch children value)) :: work, roots⟩).run)
    (ran : execute d before
      (Normalize.step ⟨.visit path (.node (.branch children value)) :: work, roots⟩).run =
      some (.ok (.inl next), after)) : RoutingState after.read next target := by
  have included := execution_preserves_records _ safe ran
  simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, spine, Bool.false_eq_true,
    run_bind, run_pure, program_bind_pure, bindCont_ok] at ran
  rw [TrieMutateProofs.execute_bind] at ran
  cases first : execute d before (Normalize.addressOptional value).run with
  | none => simp [first] at ran
  | some reply =>
    obtain ⟨reply, middle⟩ := reply
    cases reply with
    | error error => simp [first] at ran
    | ok addressed =>
      simp only [first, bindCont_ok, run_pure, TrieMutateProofs.execute_pure,
        Option.some.injEq, Prod.mk.injEq, Except.ok.injEq, Sum.inl.injEq] at ran
      obtain ⟨rfl, rfl⟩ := ran
      exact scheduled_routing_state routing included

private theorem empty_children_routed : RoutedChildren store path emptyChildren := by
  intro nibble child edge
  simp only [emptyChildren, List.getElem?_replicate] at edge
  split at edge <;> cases edge

/-- A terminal key receives its own addressed routing node, so admitting its
spine does not require revealing the key's payload. -/
theorem terminal_leaf_step_routed (digestWidth : Width d) (shaped : Shaped before)
    (meaningBefore : StateMeaning before.read
      ⟨.visit path (.node (.leaf suffix value)) :: work, roots⟩ entries)
    (meaningAfter : StateMeaning after.read next entries)
    (routing : RoutingState before.read
      ⟨.visit path (.node (.leaf suffix value)) :: work, roots⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (spelling : suffix.toList = [])
    (safe : SafeWrites d before
      (Normalize.step ⟨.visit path (.node (.leaf suffix value)) :: work, roots⟩).run)
    (ran : execute d before
      (Normalize.step ⟨.visit path (.node (.leaf suffix value)) :: work, roots⟩).run =
      some (.ok (.inl next), after)) : RoutingState after.read next target := by
  have included := execution_preserves_records _ safe ran
  have valid : CursorValid before.read (.node (.leaf suffix value)) := by
    obtain ⟨views, pending, ready⟩ := meaningBefore
    cases pending with
    | visit valid _ _ => exact valid
  simp only [Normalize.step, Nat.not_lt.mpr within, ↓reduceIte, spine,
    Bool.false_eq_true, run_bind, run_pure, program_bind_pure, bindCont_ok, spelling] at ran
  rw [TrieMutateProofs.execute_bind] at ran
  cases first : execute d before (addressValue value).run with
  | none => simp [first] at ran
  | some reply =>
    obtain ⟨reply, middle⟩ := reply
    cases reply with
    | error error => simp [first] at ran
    | ok addressed =>
      have addressWidth := (addressValue_shape digestWidth shaped valid.2.1.2 first).2
      simp only [first, bindCont_ok] at ran
      rw [execute_run_bind, execute_put] at ran
      simp only [run_pure, TrieMutateProofs.execute_pure, Option.some.injEq,
        Prod.mk.injEq, Except.ok.injEq, Sum.inl.injEq] at ran
      obtain ⟨rfl, rfl⟩ := ran
      have routeWf : (Node.route emptyChildren (some addressed)).wf :=
        ⟨rfl, branchOk_empty.2.1, fun hash same => by cases same; exact addressWidth⟩
      refine push_routed_result routing included
        (.route (by simp [read_write_node]) (TrieCodecProofs.decode_encode routeWf)
          (head_closed meaningAfter) ?_)
      exact empty_children_routed

/-- Assembling normalized children stores an actual routing parent at their
original path, preserving the form of completed siblings. -/
theorem assembly_step_routed {address : Option ByteArray}
    (meaningBefore : StateMeaning before.read ⟨.assemble positions address :: work, roots⟩ entries)
    (meaningAfter : StateMeaning after.read next entries)
    (routing : RoutingState before.read ⟨.assemble positions address :: work, roots⟩ target)
    (safe : SafeWrites d before (Normalize.step ⟨.assemble positions address :: work, roots⟩).run)
    (ran : execute d before (Normalize.step ⟨.assemble positions address :: work, roots⟩).run =
      some (.ok (.inl next), after)) : RoutingState after.read next target := by
  have included := execution_preserves_records _ safe ran
  obtain ⟨views, pending, completed⟩ := meaningBefore
  cases pending with
  | assemble children distinct nibbles occupied payload below =>
    obtain ⟨left, right, rfl, leftMeaning, rightMeaning⟩ := completed_split _ completed
    have ready : Completed before.read left ((children.reverse).map Prod.snd) := by
      simpa only [List.map_reverse] using leftMeaning
    obtain ⟨built, assembled, childMeaning⟩ := assemble_children_exact children.reverse ready
      empty_children_meaning (by simpa using distinct.perm (List.reverse_perm _).symm)
      (fun position member => nibbles position (by simpa using member)) right
    simp only [List.map_reverse, List.reverse_reverse, List.append_nil] at assembled childMeaning
    have routeWf := (assembled_node_meaning childMeaning payload occupied).1
    obtain ⟨paths, pendingPaths, routedResults⟩ := routing
    cases pendingPaths with
    | assemble positions belowPaths =>
      have readyPaths := routedResults
      rw [← List.map_reverse] at readyPaths
      obtain ⟨childrenRouted, remainingRouted⟩ := assemble_children_routed
        (children.map Prod.fst).reverse rfl
        (fun position member => nibbles position (by simpa using member))
        empty_children_routed readyPaths assembled
      simp only [Normalize.step, assembled] at ran
      rw [execute_run_bind, execute_put] at ran
      simp only [run_pure, TrieMutateProofs.execute_pure, Option.some.injEq,
        Prod.mk.injEq, Except.ok.injEq, Sum.inl.injEq] at ran
      obtain ⟨rfl, rfl⟩ := ran
      refine ⟨_, belowPaths, .cons
        (.route (by simp [read_write_node]) (TrieCodecProofs.decode_encode routeWf)
          (head_closed meaningAfter) ?_) (routed_results_preserved remainingRouted included)⟩
      intro nibble child edge
      exact routed_preserved (childrenRouted nibble child edge) included

private theorem replace_cursor_routing
    (routing : RoutingState store ⟨.visit path cursor :: work, roots⟩ target) :
    RoutingState store ⟨.visit path replacement :: work, roots⟩ target := by
  obtain ⟨paths, pending, ready⟩ := routing
  cases pending with
  | visit below => exact ⟨paths, .visit below, ready⟩

private theorem node_step_routed (digestWidth : Width d) (shaped : Shaped before)
    (meaningBefore : StateMeaning before.read ⟨.visit path (.node node) :: work, roots⟩ entries)
    (meaningAfter : StateMeaning after.read next entries)
    (routing : RoutingState before.read ⟨.visit path (.node node) :: work, roots⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (safe : SafeWrites d before (Normalize.step ⟨.visit path (.node node) :: work, roots⟩).run)
    (ran : execute d before (Normalize.step ⟨.visit path (.node node) :: work, roots⟩).run =
      some (.ok (.inl next), after)) : RoutingState after.read next target := by
  cases node with
  | leaf suffix value =>
    cases spelling : suffix.toList with
    | nil =>
      exact terminal_leaf_step_routed digestWidth shaped meaningBefore meaningAfter
        routing within spine spelling safe ran
    | cons nibble rest => exact leaf_edge_step_routed routing within spine spelling ran
  | extension segment child =>
    cases spelling : segment.toList with
    | nil => simp [Normalize.step, Nat.not_lt.mpr within, spine, spelling] at ran
    | cons nibble rest => exact extension_edge_step_routed routing within spine spelling ran
  | branch children value => exact branch_step_routed routing within spine safe ran
  | route children value => exact route_step_routed routing within spine ran

private theorem stored_step_routed (digestWidth : Width d) (shaped : Shaped before)
    (meaningBefore : StateMeaning before.read ⟨.visit path (.stored root) :: work, roots⟩ entries)
    (meaningAfter : StateMeaning after.read next entries)
    (routing : RoutingState before.read ⟨.visit path (.stored root) :: work, roots⟩ target)
    (within : path.length ≤ maxKeyBytes * 2) (spine : Normalize.belowBoundary path = false)
    (safe : SafeWrites d before (Normalize.step ⟨.visit path (.stored root) :: work, roots⟩).run)
    (ran : execute d before (Normalize.step ⟨.visit path (.stored root) :: work, roots⟩).run =
      some (.ok (.inl next), after)) : RoutingState after.read next target := by
  have valid : CursorValid before.read (.stored root) := by
    obtain ⟨_, pending, _⟩ := meaningBefore
    cases pending with
    | visit valid _ _ => exact valid
  rw [stored_step_as_node within spine] at safe ran
  simp only [run_bind] at safe
  rw [execute_run_bind] at ran
  cases first : execute d before (load root).run with
  | none => simp [first] at ran
  | some reply =>
    obtain ⟨reply, middle⟩ := reply
    cases reply with
    | error error => simp [first] at ran
    | ok node =>
      have restSafe := safe_bind_right _ safe first
      simp only [bindCont_ok] at restSafe
      simp only [first] at ran
      obtain ⟨rfl, nodeValid, exactEntries⟩ := load_cursor_meaning shaped valid first
      exact node_step_routed digestWidth shaped
        (replace_cursor_meaning meaningBefore nodeValid exactEntries) meaningAfter
        (replace_cursor_routing routing) within spine restSafe ran

/-- Every successful normalization continuation preserves the routing form
of completed results and their positions in the actual work stack. -/
theorem step_routed (digestWidth : Width d) (shaped : Shaped before)
    (meaning : StateMeaning before.read state entries)
    (routing : RoutingState before.read state target)
    (safe : SafeWrites d before (Normalize.step state).run)
    (ran : execute d before (Normalize.step state).run = some (.ok (.inl next), after)) :
    RoutingState after.read next target := by
  have meaningAfter := (step_preserves_entries digestWidth shaped meaning safe ran).2
  obtain ⟨work, roots⟩ := state
  cases work with
  | nil =>
    cases roots with
    | nil => simp [Normalize.step] at ran
    | cons root rest => cases rest <;> simp [Normalize.step] at ran
  | cons task work =>
    cases task with
    | assemble positions address => exact assembly_step_routed meaning meaningAfter routing safe ran
    | visit path cursor =>
      by_cases over : path.length > maxKeyBytes * 2
      · simp [Normalize.step, over] at ran
      · have within : path.length ≤ maxKeyBytes * 2 := Nat.le_of_not_gt over
        cases spine : Normalize.belowBoundary path with
        | true => exact boundary_step_routed routing meaningAfter within spine safe ran
        | false =>
          cases cursor with
          | stored root => exact stored_step_routed digestWidth shaped meaning meaningAfter routing within spine safe ran
          | node node => exact node_step_routed digestWidth shaped meaning meaningAfter routing within spine safe ran

private theorem initial_routing :
    RoutingState store ⟨[.visit [] (.stored root)], []⟩ [] :=
  ⟨[], .visit (.done []), .nil⟩

private theorem finish_routing
    (routing : RoutingState before.read ⟨[], roots⟩ target)
    (ran : execute d before (Normalize.step ⟨[], roots⟩).run = some (.ok (.inr root), after)) :
    RoutedAt after.read target root := by
  cases roots with
  | nil => simp [Normalize.step] at ran
  | cons result rest =>
    cases rest with
    | cons next rest => simp [Normalize.step] at ran
    | nil =>
      simp only [Normalize.step, run_pure, TrieMutateProofs.execute_pure,
        Option.some.injEq, Prod.mk.injEq, Except.ok.injEq, Sum.inr.injEq] at ran
      obtain ⟨rfl, rfl⟩ := ran
      obtain ⟨paths, pending, ready⟩ := routing
      cases pending with
      | done path =>
        cases ready with
        | cons head tail => exact head

/-- Successful normalization produces the stored routing form needed to
share metadata paths without exposing private ancestor payloads. The input
may use any valid stored representation; it need not already be routed. -/
theorem publication_routed (digestWidth : Width d) (shaped : Shaped before)
    (width : root.size = 32) (closed : Closed before.read root)
    (nonempty : isEmptyRoot root = false)
    (safe : SafeWrites d before (Normalize.publication root).run)
    (ran : execute d before (Normalize.publication root).run = some (.ok normalized, after)) :
    RoutedAt after.read [] normalized := by
  let invariant := fun (store : Store) state => Shaped store ∧
    StateMeaning store.read state (GraphValue before.read root) ∧ RoutingState store.read state []
  let finished := fun (store : Store) result => RoutedAt store.read [] result
  have preservation : ∀ state store reply finalStore, invariant store state →
      SafeWrites d store (Normalize.step state).run →
      execute d store (Normalize.step state).run = some (.ok reply, finalStore) →
      match reply with | .inl next => invariant finalStore next | .inr result => finished finalStore result := by
    intro state store reply finalStore current safeStep ranStep
    cases reply with
    | inl next =>
      have semantic := step_preserves_entries digestWidth current.1 current.2.1 safeStep ranStep
      exact ⟨semantic.1, semantic.2,
        step_routed digestWidth current.1 current.2.1 current.2.2 safeStep ranStep⟩
    | inr result =>
      have empty := finished_step_has_no_work ranStep
      obtain ⟨work, roots⟩ := state
      simp only at empty
      subst work
      exact finish_routing current.2.2 ranStep
  have initial : invariant before ⟨[.visit [] (.stored root)], []⟩ :=
    ⟨shaped, initial_state_meaning width closed, initial_routing⟩
  simp only [Normalize.publication, nonempty, Bool.false_eq_true, ↓reduceIte,
    OperationOver.iterate] at safe ran
  exact iterate_store_invariant (d := d) (S := Normalize.State) (R := ByteArray)
    (fun state => (Normalize.step state).run) (.domain .depthExceeded) invariant finished
    (fun state store reply finalStore current safeStep ranStep => by
      cases reply with
      | inl next => exact preservation state store (.inl next) finalStore current safeStep ranStep
      | inr result => exact preservation state store (.inr result) finalStore current safeStep ranStep)
    Normalize.workFuel (Normalize.step ⟨[.visit [] (.stored root)], []⟩).run before
    (fun reply finalStore initialSafe initialRan => by
      cases reply with
      | inl next => exact preservation _ before (.inl next) finalStore initial initialSafe initialRan
      | inr result => exact preservation _ before (.inr result) finalStore initial initialSafe initialRan)
    normalized after safe ran

/-- A successfully normalized version permits every stored node needed on
a granted path. The grant may select a private exact key or a complete shared
subtree; it need not grant any private ancestor's payload. -/
theorem normalized_nodes_are_admitted (digestWidth : Width d) (shaped : Shaped before)
    (width : root.size = 32) (closed : Closed before.read root)
    (nonempty : isEmptyRoot root = false)
    (safe : SafeWrites d before (Normalize.publication root).run)
    (ran : execute d before (Normalize.publication root).run = some (.ok normalized, after))
    (compatible : BoundaryCompatible scope)
    (reaches : Reaches (after.read nodeSpace) normalized path found)
    (admitted : scope.admitsPath path = true)
    (held : after.read nodeSpace found = some raw) (decoded : decode raw = .ok node) :
    scope.admitsNode path node = true := by
  exact routed_nodes_are_admitted compatible
    (publication_routed digestWidth shaped width closed nonempty safe ran) reaches admitted held decoded

end Synchronicity.TriePublicationRouting
