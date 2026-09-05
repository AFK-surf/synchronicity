import VerifiedCore
import Std.Data.TreeSet.Lemmas
import Synchronicity.ScopedSync
import Synchronicity.Cas

/-! Proofs about the executable source statically linked by synch-verified.
The native package has no dependency on this proof package or on Mathlib. -/
namespace Synchronicity.VerifiedCoreProofs

/-- Interpret the finite runtime scope in the abstract positional model. -/
def scopeModel (s : VerifiedCore.Scope) : Scope :=
  ⟨if s.full then none else some s.prefixes, s.exact⟩

theorem containsSubtree_correct (s : VerifiedCore.Scope) (path : Path) :
    VerifiedCore.containsSubtree s path = true ↔ (scopeModel s).ContainsSubtree path := by
  cases s with
  | mk full prefixes exact => cases full <;>
    simp [VerifiedCore.containsSubtree, scopeModel, Scope.ContainsSubtree]

theorem admitsKey_correct (s : VerifiedCore.Scope) (path : Path) :
    VerifiedCore.admitsKey s path = true ↔ (scopeModel s).AdmitsKey path := by
  simp [VerifiedCore.admitsKey, containsSubtree_correct, Scope.AdmitsKey, scopeModel]

theorem admitsPath_correct (s : VerifiedCore.Scope) (path : Path) :
    VerifiedCore.admitsPath s path = true ↔ (scopeModel s).AdmitsPath path := by
  cases s with
  | mk full prefixes exact => cases full <;>
    simp [VerifiedCore.admitsPath, scopeModel, Scope.AdmitsPath]

/-- The part of a trie node relevant to authorization; content hashes are not
used to decide whether a node or its own value is inside a grant. -/
def shapeModel : ScopedSync.Node → VerifiedCore.Shape
  | .branch _ (some (.inline _)) => .branch true
  | .branch _ _ => .branch false
  | .ext suffix _ => .extension suffix
  | .leaf suffix _ => .leaf suffix

theorem admitsNode_correct (s : VerifiedCore.Scope) (path : Path) (n : ScopedSync.Node) :
    VerifiedCore.admitsNode s path (shapeModel n) = true ↔
      ScopedSync.AdmitsNode (scopeModel s) path n := by
  cases n with
  | leaf suffix value =>
    cases s with
    | mk full prefixes exact => cases full <;>
      simp [VerifiedCore.admitsNode, shapeModel, VerifiedCore.admitsKey,
        VerifiedCore.containsSubtree, ScopedSync.AdmitsNode, Scope.AdmitsKey,
        Scope.ContainsSubtree, scopeModel]
  | ext suffix child =>
    cases s with
    | mk full prefixes exact => cases full <;>
      simp [VerifiedCore.admitsNode, shapeModel, VerifiedCore.admitsPath,
        ScopedSync.AdmitsNode, Scope.AdmitsPath, scopeModel]
  | branch children value =>
    cases value with
    | none => simp [VerifiedCore.admitsNode, shapeModel, ScopedSync.AdmitsNode]
    | some v =>
      cases v with
      | outOfLine hash => simp [VerifiedCore.admitsNode, shapeModel, ScopedSync.AdmitsNode]
      | inline bytes =>
        cases s with
        | mk full prefixes exact => cases full <;>
          simp [VerifiedCore.admitsNode, shapeModel, VerifiedCore.admitsKey,
            VerifiedCore.containsSubtree, ScopedSync.AdmitsNode, Scope.AdmitsKey,
            Scope.ContainsSubtree, scopeModel]

theorem admitsValue_correct (s : VerifiedCore.Scope) (path : Path) (n : ScopedSync.Node) :
    VerifiedCore.admitsValue s path (shapeModel n) = true ↔
      ScopedSync.AdmitsValue (scopeModel s) path n := by
  cases n with
  | leaf suffix value => exact admitsKey_correct s _
  | ext suffix child => simp [shapeModel, VerifiedCore.admitsValue, ScopedSync.AdmitsValue]
  | branch children value =>
    cases value with
    | none => exact admitsKey_correct s _
    | some v => cases v <;> exact admitsKey_correct s _

/-- The exported ByteArray predicate invokes the proved implementation. -/
@[rust_justifies "verified-native-path"]
theorem exported_path_correct (s : VerifiedCore.Scope) (path : ByteArray) :
    VerifiedCore.scopePath s path = true ↔
      (scopeModel s).AdmitsPath (VerifiedCore.pathOf path) := admitsPath_correct s _

/-- The exported node decision is the model predicate for its decoded shape. -/
@[rust_justifies "verified-native-node"]
theorem exported_node_correct (s : VerifiedCore.Scope) (path suffix : ByteArray)
    (tag : UInt8) (inlineValue : Bool) (n : ScopedSync.Node)
    (shape : VerifiedCore.shapeOf tag inlineValue suffix = some (shapeModel n)) :
    VerifiedCore.scopeNode s path tag inlineValue suffix = true ↔
      ScopedSync.AdmitsNode (scopeModel s) (VerifiedCore.pathOf path) n := by
  simpa [VerifiedCore.scopeNode, shape] using admitsNode_correct s (VerifiedCore.pathOf path) n

/-- The exported payload decision does not conflate node and value admission. -/
@[rust_justifies "verified-native-value"]
theorem exported_value_correct (s : VerifiedCore.Scope) (path suffix : ByteArray)
    (tag : UInt8) (n : ScopedSync.Node)
    (shape : VerifiedCore.shapeOf tag false suffix = some (shapeModel n)) :
    VerifiedCore.scopeValue s path tag suffix = true ↔
      ScopedSync.AdmitsValue (scopeModel s) (VerifiedCore.pathOf path) n := by
  simpa [VerifiedCore.scopeValue, shape] using admitsValue_correct s (VerifiedCore.pathOf path) n

/-- Branch payload authorization depends only on the key grant, regardless of
whether the original Rust node stores its value inline or out of line. -/
theorem exported_branch_value_correct (s : VerifiedCore.Scope) (path suffix : ByteArray) :
    VerifiedCore.scopeValue s path 0 suffix = true ↔
      (scopeModel s).AdmitsKey (VerifiedCore.pathOf path) := by
  simpa [VerifiedCore.scopeValue, VerifiedCore.shapeOf, VerifiedCore.admitsValue] using
    admitsKey_correct s (VerifiedCore.pathOf path)

/-- No out-of-scope spine branch's payload is granted by the executable core. -/
theorem spine_payload_refused (s : VerifiedCore.Scope) (path : Path)
    (notGranted : ¬ (scopeModel s).AdmitsKey path) (inlineValue : Bool) :
    VerifiedCore.admitsValue s path (.branch inlineValue) = false := by
  have h := admitsKey_correct s path
  simp only [VerifiedCore.admitsValue]
  cases eq : VerifiedCore.admitsKey s path
  · rfl
  · exact False.elim (notGranted (h.mp eq))

/-- UInt64 arithmetic in the linked implementation agrees with the unbounded
CAS group count even at zero and the maximum representable object size. -/
theorem groupCount_correct (size : UInt64) :
    (VerifiedCore.groupCount size).toNat = Cas.groupCount size.toNat := by
  have bound := size.toNat_lt
  by_cases zero : size = 0
  · subst size
    simp [VerifiedCore.groupCount, Cas.groupCount]
  · have positive : 0 < size.toNat := Nat.pos_of_ne_zero (fun h => zero (UInt64.toNat_inj.mp h))
    simp only [VerifiedCore.groupCount, beq_iff_eq, zero, ↓reduceIte]
    simp [UInt64.toNat_add, UInt64.toNat_div, UInt64.toNat_sub, Cas.groupCount,
      Cas.groupBytes, Nat.ne_of_gt positive]
    omega

/-- Acceptance is exactly the CAS settlement rule, with complete/final-group
evidence supplied by the row adapter, not guessed by the core. -/
theorem settlement_accepts_iff (row durable complete finalHeld : Bool) (recorded claimed : UInt64) :
    VerifiedCore.settleSize row durable complete finalHeld recorded claimed ≠ 0 ↔
      row = false ∨ recorded = claimed ∨ (durable = false ∧ complete = false ∧ finalHeld = false) := by
  unfold VerifiedCore.settleSize
  split_ifs <;> simp_all <;> grind

/-- Reset is requested exactly for an accepted size correction with a changed
group count. -/
theorem settlement_reset_iff (row durable complete finalHeld : Bool) (recorded claimed : UInt64) :
    VerifiedCore.settleSize row durable complete finalHeld recorded claimed = 2 ↔
      row = true ∧ recorded ≠ claimed ∧ durable = false ∧ complete = false ∧ finalHeld = false ∧
        Cas.groupCount recorded.toNat ≠ Cas.groupCount claimed.toNat := by
  have groups : VerifiedCore.groupCount recorded = VerifiedCore.groupCount claimed ↔
      Cas.groupCount recorded.toNat = Cas.groupCount claimed.toNat := by
    rw [← groupCount_correct, ← groupCount_correct]
    exact UInt64.toNat_inj.symm
  unfold VerifiedCore.settleSize
  split_ifs <;> simp_all <;> grind

/-- Connect the exported settlement decision to the existing CAS transition
guard. Row decoding/bitmap membership must supply these representation facts;
the proof does not assume acceptance or the desired postcondition. -/
@[rust_justifies "verified-size-settlement"]
theorem settlement_refines_model {c : Cas.Cell H}
    (row durable complete finalHeld : Bool) (recorded claimed : UInt64)
    (hrow : row = true ↔ c.row) (hdurable : durable = true ↔ c.durable)
    (hcomplete : complete = true ↔ Cas.Complete c)
    (hfinal : finalHeld = true ↔ Cas.groupCount c.size - 1 ∈ c.held)
    (hsize : c.size = recorded.toNat) :
    VerifiedCore.settleSizeExport row durable complete finalHeld recorded claimed ≠ 0 ↔
      Cas.Settles c claimed.toNat := by
  change VerifiedCore.settleSize row durable complete finalHeld recorded claimed ≠ 0 ↔ _
  rw [settlement_accepts_iff]
  have sizes : claimed.toNat = c.size ↔ recorded = claimed := by
    rw [hsize, UInt64.toNat_inj]
    exact eq_comm
  unfold Cas.Settles Cas.Settled Cas.Attested
  rw [sizes]
  cases row <;> cases durable <;> cases complete <;> cases finalHeld <;> simp_all

/-- Exact guard of the production cache, including terminal-epoch refusal. -/
theorem cache_can_certify (s : VerifiedCore.CertificateCache) (epoch : UInt64) :
    VerifiedCore.canCertify s epoch = true ↔
      s.mutating = 0 ∧ s.epoch = epoch ∧ epoch ≠ 18446744073709551615 := by
  simp [VerifiedCore.canCertify, and_assoc]

/-- A usable exported certificate is present and no mutation is outstanding. -/
@[rust_justifies "verified-memo-known"]
theorem cache_known (s : VerifiedCore.CertificateCache) (key : ByteArray) :
    VerifiedCore.cacheKnown s key = true ↔
      s.mutating = 0 ∧ VerifiedCore.pathOf key ∈ s.roots := by
  simp [VerifiedCore.cacheKnown, VerifiedCore.knownComplete]

/-- Invalid tickets leave the entire executable cache unchanged. -/
theorem cache_rejected_unchanged (s : VerifiedCore.CertificateCache) (epoch : UInt64)
    (key : ByteArray) (rejected : VerifiedCore.canCertify s epoch = false) :
    VerifiedCore.cacheCertify s epoch key = s := by
  simp [VerifiedCore.cacheCertify, VerifiedCore.certify, rejected]

/-- Invalidation masks retained certificates even with nested transactions. -/
theorem cache_begin_hides (s : VerifiedCore.CertificateCache) (keep : Array ByteArray)
    (key : ByteArray) : VerifiedCore.cacheKnown (VerifiedCore.cacheBegin s keep) key = false := by
  simp [VerifiedCore.cacheKnown, VerifiedCore.knownComplete, VerifiedCore.cacheBegin,
    VerifiedCore.beginMutation]

/-- Beginning a transaction cannot invent a certificate. -/
@[rust_justifies "verified-memo-begin"]
theorem cache_begin_retains (s : VerifiedCore.CertificateCache) (keep : Array ByteArray)
    (key : List Nat) : key ∈ (VerifiedCore.cacheBegin s keep).roots ↔
      key ∈ s.roots ∧ key ∈ keep.toList.map VerifiedCore.pathOf := by
  simp [VerifiedCore.cacheBegin, VerifiedCore.beginMutation]

/-- Certification only retains prior roots or inserts the supplied key. -/
theorem cache_certify_roots (s : VerifiedCore.CertificateCache) (epoch : UInt64)
    (key q : List Nat) (h : q ∈ (VerifiedCore.certify s epoch key).roots) :
    q = key ∨ q ∈ s.roots := by
  unfold VerifiedCore.certify at h
  split_ifs at h <;> simp_all
  all_goals grind

/-- Soundness is proved about the executable update, not a Rust lookalike.
The completed walk must supply validity of the newly certified query. -/
@[rust_justifies "verified-memo-certify"]
theorem cache_certify_sound (valid : List Nat → Prop) (s : VerifiedCore.CertificateCache)
    (epoch : UInt64) (key : List Nat) (prior : ∀ q ∈ s.roots, valid q)
    (completed : valid key) : ∀ q ∈ (VerifiedCore.certify s epoch key).roots, valid q := by
  intro q h
  rcases cache_certify_roots s epoch key q h with rfl | old
  · exact completed
  · exact prior q old

/-- An accepted exported certification makes its requested key usable. -/
theorem cache_certify_inserts (s : VerifiedCore.CertificateCache) (epoch : UInt64)
    (key : ByteArray) (accepted : VerifiedCore.canCertify s epoch = true) :
    VerifiedCore.cacheKnown (VerifiedCore.cacheCertify s epoch key) key = true := by
  have idle := (cache_can_certify s epoch).mp accepted |>.1
  simp only [VerifiedCore.cacheKnown, VerifiedCore.cacheCertify, VerifiedCore.certify,
    accepted, ↓reduceIte, VerifiedCore.knownComplete]
  split_ifs <;> simp_all

/-- Certification stays bounded; capacity zero retains only the latest key. -/
theorem cache_capacity_preserved (s : VerifiedCore.CertificateCache) (epoch : UInt64)
    (key : List Nat) (bounded : s.roots.length ≤ max s.capacity 1) :
    (VerifiedCore.certify s epoch key).roots.length ≤ max s.capacity 1 := by
  unfold VerifiedCore.certify
  split_ifs <;> simp_all
  all_goals split_ifs <;> simp_all
  omega

/-- The cache remains a finite set even though its executable representation
is currently a list. -/
theorem cache_unique (s : VerifiedCore.CertificateCache) (epoch : UInt64)
    (key : List Nat) (unique : s.roots.Nodup) :
    (VerifiedCore.certify s epoch key).roots.Nodup := by
  unfold VerifiedCore.certify
  split_ifs <;> simp_all
  all_goals split_ifs <;> simp_all

/-- A stale snapshot cannot add any root through the actual exported update. -/
theorem cache_stale_rejected (s : VerifiedCore.CertificateCache) (epoch : UInt64)
    (key : ByteArray) (stale : s.epoch ≠ epoch) :
    VerifiedCore.cacheCertify s epoch key = s := by
  apply cache_rejected_unchanged
  simp [VerifiedCore.canCertify, stale]

/-- Saturation cannot enable an ABA certification, even at quiescence. -/
theorem cache_terminal_rejected (s : VerifiedCore.CertificateCache) (key : ByteArray) :
    VerifiedCore.cacheCertify s 18446744073709551615 key = s := by
  apply cache_rejected_unchanged
  simp [VerifiedCore.canCertify]

/-- Every nonterminal epoch advances strictly, so prior tickets cannot recur. -/
theorem cache_epoch_advances (epoch : UInt64) (h : epoch ≠ 18446744073709551615) :
    epoch.toNat < (VerifiedCore.advanceEpoch epoch).toNat := by
  have bound := epoch.toNat_lt
  have notMax : epoch.toNat ≠ 18446744073709551615 := by
    intro eq
    apply h
    exact UInt64.toNat_inj.mp eq
  simp [VerifiedCore.advanceEpoch, h, UInt64.toNat_add]
  omega

/-- Finishing a real mutation decrements exactly one nesting level and
advances the epoch; the cache cannot manufacture or drop a retained query. -/
@[rust_justifies "verified-memo-finish"]
theorem cache_finish (s : VerifiedCore.CertificateCache) (active : s.mutating ≠ 0) :
    (VerifiedCore.cacheFinish s).roots = s.roots ∧
    (VerifiedCore.cacheFinish s).mutating = s.mutating - 1 ∧
    (VerifiedCore.cacheFinish s).epoch = VerifiedCore.advanceEpoch s.epoch := by
  simp [VerifiedCore.cacheFinish, VerifiedCore.finishMutation, active]

/-- The paired transaction edges restore the prior nesting level. -/
theorem cache_transaction_depth (s : VerifiedCore.CertificateCache) (keep : Array ByteArray) :
    (VerifiedCore.cacheFinish (VerifiedCore.cacheBegin s keep)).mutating = s.mutating := by
  simp [VerifiedCore.cacheFinish, VerifiedCore.cacheBegin, VerifiedCore.finishMutation,
    VerifiedCore.beginMutation]

/-- Exhaustion rules out deferred work and a canonicality fault. -/
theorem walk_exhaustion (s : VerifiedCore.MissingWalk)
    (done : VerifiedCore.walkExhausted s = true) :
    s.frontier = [] ∧ s.deferred = [] ∧ s.fault = none ∧ s.awaiting = false := by
  simpa [VerifiedCore.walkExhausted, Bool.and_eq_true, and_assoc] using done

/-- A recorded payload cannot be requested a second time in the same batch. -/
theorem walk_payload_once (s : VerifiedCore.MissingWalk) (hash : ByteArray) :
    VerifiedCore.walkUnasked (VerifiedCore.walkAsk s hash) hash = false := by
  simp [VerifiedCore.walkUnasked, VerifiedCore.walkAsk]

/-- Batch reset permits a still-missing payload to be reported again. -/
theorem walk_payload_retry (s : VerifiedCore.MissingWalk) (hash : ByteArray) :
    VerifiedCore.walkUnasked (VerifiedCore.walkBatch s) hash = true := by
  simp [VerifiedCore.walkUnasked, VerifiedCore.walkBatch]

/-- Every selected read came from the frontier, is depth-bounded, and has
neither a complete-reference shortcut nor an already-expanded visit key. -/
@[rust_justifies "verified-walk-poll"]
theorem walk_poll_selected (scope : VerifiedCore.Scope) (limit : Nat)
    (seen : Std.TreeSet VerifiedCore.WalkVisit)
    (frontier : List VerifiedCore.WalkPosition) (p : VerifiedCore.WalkPosition)
    (selected : (VerifiedCore.pollFrontier scope limit seen frontier).current = some p) :
    p ∈ frontier ∧ p.path.length ≤ limit ∧
      (p.reference == some p.hash) = false ∧
      seen.contains (VerifiedCore.walkVisit scope p) = false := by
  induction frontier with
  | nil => simp [VerifiedCore.pollFrontier] at selected
  | cons q rest ih =>
    simp only [VerifiedCore.pollFrontier] at selected
    split at selected
    · simp at selected
    · rename_i bounded
      split at selected
      · exact ⟨List.mem_cons_of_mem q (ih selected).1, (ih selected).2⟩
      · rename_i fresh
        simp only [Option.some.injEq] at selected
        subst p
        simp only [Bool.or_eq_true, not_or, Bool.not_eq_true] at fresh
        exact ⟨List.mem_cons_self, Nat.le_of_not_gt bounded, fresh⟩

/-- Over-depth positions fail before reference pruning or deduplication. -/
theorem walk_depth_before_shortcuts (scope : VerifiedCore.Scope) (limit : Nat)
    (seen : Std.TreeSet VerifiedCore.WalkVisit)
    (p : VerifiedCore.WalkPosition) (rest : List VerifiedCore.WalkPosition)
    (deep : limit < p.path.length) :
    (VerifiedCore.pollFrontier scope limit seen (p :: rest)).fault = some p.path.length := by
  simp [VerifiedCore.pollFrontier, deep]

/-- A canonicality fault cannot be cleared by polling or retrying. -/
theorem walk_fault_sticky (s : VerifiedCore.MissingWalk) (fault : s.fault.isSome = true) :
    VerifiedCore.pollWalk s = s ∧ (VerifiedCore.resumeWalk s).fault = s.fault := by
  simp [VerifiedCore.pollWalk, VerifiedCore.resumeWalk, fault]

/-- Retrying preserves all pending work in its stack order. -/
theorem walk_resume_work (s : VerifiedCore.MissingWalk) :
    (VerifiedCore.walkResume s).frontier = s.deferred ++ s.frontier ∧
    (VerifiedCore.walkResume s).deferred = [] := by
  simp [VerifiedCore.walkResume, VerifiedCore.resumeWalk]

/-- A deferred current read prevents exhaustion, even with an empty frontier. -/
theorem walk_deferred_not_exhausted (s : VerifiedCore.MissingWalk)
    (p : VerifiedCore.WalkPosition) (current : s.current = some p) :
    VerifiedCore.walkExhausted (VerifiedCore.walkDefer s) = false := by
  simp [VerifiedCore.walkExhausted, VerifiedCore.walkDefer, VerifiedCore.deferWalk, current]

/-- Child scheduling constructs the absolute path and refuses unadmitted work. -/
theorem walk_enqueue_boundary (s : VerifiedCore.MissingWalk)
    (p : VerifiedCore.WalkPosition) (reference : Option (List Nat)) (hash step : List Nat)
    (current : s.current = some p)
    (denied : VerifiedCore.admitsPath s.scope (p.path ++ step) = false) :
    VerifiedCore.enqueueWalk s reference hash step = s := by
  simp [VerifiedCore.enqueueWalk, current, denied]

/-- Pairing preserves every target edge and invents no target edges. -/
theorem paired_edges_exact (reference node : VerifiedCore.WalkNode)
    (r : Option (List Nat)) (hash step : List Nat) :
    (r, hash, step) ∈ VerifiedCore.pairedEdges reference node ↔
      (step, hash) ∈ VerifiedCore.childEdges node ∧
      r = (if VerifiedCore.compatibleNodes reference node then
        (VerifiedCore.childEdges reference).lookup step else none) := by
  simp only [VerifiedCore.pairedEdges, List.mem_map, Prod.exists, Prod.mk.injEq]
  constructor
  · rintro ⟨a, b, edge, pair⟩
    obtain ⟨rfl, rfl⟩ := pair.2
    exact ⟨edge, pair.1.symm⟩
  · rintro ⟨edge, rfl⟩
    exact ⟨step, hash, edge, rfl, rfl, rfl⟩

/-- Any retained reference hash is reached by exactly the target edge's step. -/
@[rust_justifies "verified-walk-pairing"]
theorem paired_reference_same_step (reference node : VerifiedCore.WalkNode)
    (r hash step : List Nat)
    (paired : (some r, hash, step) ∈ VerifiedCore.pairedEdges reference node) :
    (step, hash) ∈ VerifiedCore.childEdges node ∧
    (step, r) ∈ VerifiedCore.childEdges reference := by
  obtain ⟨target, paired⟩ := (paired_edges_exact reference node (some r) hash step).mp paired
  refine ⟨target, ?_⟩
  split at paired
  · obtain ⟨before, after, edges, _⟩ := List.lookup_eq_some_iff.mp paired.symm
    simp [edges]
  · simp at paired

/-- Incompatible structures cannot supply a pruning reference. -/
theorem paired_incompatible (reference node : VerifiedCore.WalkNode)
    (r : Option (List Nat)) (hash step : List Nat)
    (incompatible : VerifiedCore.compatibleNodes reference node = false)
    (paired : (r, hash, step) ∈ VerifiedCore.pairedEdges reference node) : r = none := by
  simpa [incompatible] using
    ((paired_edges_exact reference node r hash step).mp paired).2

/-- Scheduling children never changes the parent used to construct their paths. -/
theorem enqueue_preserves_current (s : VerifiedCore.MissingWalk)
    (r : Option (List Nat)) (hash step : List Nat) :
    (VerifiedCore.enqueueWalk s r hash step).current = s.current := by
  unfold VerifiedCore.enqueueWalk
  split
  · rfl
  · dsimp only
    split <;> rfl

/-- Expansion retains the current parent across every sibling, not just the first. -/
theorem expand_preserves_current (s : VerifiedCore.MissingWalk)
    (reference node : VerifiedCore.WalkNode) :
    (VerifiedCore.walkExpand s reference node).current = s.current := by
  unfold VerifiedCore.walkExpand VerifiedCore.expandWalk
  generalize VerifiedCore.pairedEdges reference node = edges
  induction edges generalizing s with
  | nil => rfl
  | cons edge rest ih =>
    simp only [List.foldl_cons]
    rw [ih, enqueue_preserves_current]

/-- Refusals cannot hide an absent node inside a granted subtree. -/
@[rust_justifies "verified-walk-absence"]
theorem absent_inside_grant (s : VerifiedCore.MissingWalk) (p : VerifiedCore.WalkPosition)
    (current : s.current = some p) (healthy : s.fault = none)
    (pending : s.awaiting = true)
    (granted : VerifiedCore.containsSubtree s.scope p.path = true) (redacted : Bool) :
    (VerifiedCore.walkAbsent s redacted).requestKind = 1 ∧
    (VerifiedCore.walkAbsent s redacted).deferred = p :: s.deferred := by
  simp [VerifiedCore.walkAbsent, VerifiedCore.finishObservation, VerifiedCore.observeAbsent, VerifiedCore.deferWalk,
    current, healthy, granted, pending]

/-- An absent refused spine position is satisfied without requesting or deferring it. -/
theorem absent_refused_spine (s : VerifiedCore.MissingWalk) (p : VerifiedCore.WalkPosition)
    (current : s.current = some p) (healthy : s.fault = none)
    (pending : s.awaiting = true)
    (spine : VerifiedCore.containsSubtree s.scope p.path = false) :
    (VerifiedCore.walkAbsent s true).requestKind = 0 ∧
    (VerifiedCore.walkAbsent s true).deferred = s.deferred := by
  simp [VerifiedCore.walkAbsent, VerifiedCore.finishObservation, VerifiedCore.observeAbsent, current, healthy, spine, pending]

/-- Every dependent node is deferred, independently of batch request deduplication. -/
theorem payload_missing_defers (s : VerifiedCore.MissingWalk) (p : VerifiedCore.WalkPosition)
    (node : VerifiedCore.WalkNode) (hash : List Nat) (current : s.current = some p)
    (authorized : VerifiedCore.admitsValue s.scope p.path (VerifiedCore.walkShape node) = true) :
    (VerifiedCore.observePayload s node (some hash) false).deferred = p :: s.deferred ∧
    (VerifiedCore.observePayload s node (some hash) false).asked.contains hash = true := by
  simp [VerifiedCore.observePayload, VerifiedCore.deferWalk, current, authorized]

/-- Shared payloads are requested once without losing any dependent node's retry. -/
theorem payload_deduplicated_retry (s : VerifiedCore.MissingWalk) (p : VerifiedCore.WalkPosition)
    (node : VerifiedCore.WalkNode) (hash : List Nat) (current : s.current = some p)
    (authorized : VerifiedCore.admitsValue s.scope p.path (VerifiedCore.walkShape node) = true)
    (asked : s.asked.contains hash = true) :
    (VerifiedCore.observePayload s node (some hash) false).requestKind = 0 ∧
    (VerifiedCore.observePayload s node (some hash) false).deferred = p :: s.deferred := by
  simp [VerifiedCore.observePayload, VerifiedCore.deferWalk, current, authorized, asked]

/-- An already held payload introduces no outstanding work. -/
theorem payload_present_unchanged (s : VerifiedCore.MissingWalk)
    (node : VerifiedCore.WalkNode) (hash : Option (List Nat)) :
    VerifiedCore.observePayload s node hash true = s := by
  cases current : s.current <;> cases hash <;> simp [VerifiedCore.observePayload, current]

/-- Payloads outside the granted keyspace introduce no request or retry. -/
theorem payload_denied_unchanged (s : VerifiedCore.MissingWalk) (p : VerifiedCore.WalkPosition)
    (node : VerifiedCore.WalkNode) (hash : List Nat) (current : s.current = some p)
    (denied : VerifiedCore.admitsValue s.scope p.path (VerifiedCore.walkShape node) = false)
    (present : Bool) : VerifiedCore.observePayload s node (some hash) present = s := by
  simp [VerifiedCore.observePayload, current, denied]

/-- Leaf runs are charged to their absolute key depth using unbounded arithmetic. -/
theorem validate_leaf_depth (s : VerifiedCore.MissingWalk) (p : VerifiedCore.WalkPosition)
    (suffix : List Nat) (current : s.current = some p)
    (noObligation : s.branches.contains p.hash = false)
    (deep : s.maxDepth < p.path.length + suffix.length) (childShape : UInt8) :
    (VerifiedCore.validateWalk s (.leaf suffix) childShape).fault =
      some (p.path.length + suffix.length) ∧
    (VerifiedCore.validateWalk s (.leaf suffix) childShape).faultKind = 1 := by
  simp [VerifiedCore.validateWalk, VerifiedCore.failWalk, current, noObligation, deep]

/-- An absent extension child carries its shape obligation into later batches. -/
theorem validate_extension_obligation (s : VerifiedCore.MissingWalk)
    (p : VerifiedCore.WalkPosition) (segment child : List Nat)
    (current : s.current = some p) (noObligation : s.branches.contains p.hash = false) :
    (VerifiedCore.validateWalk s (.extension segment child) 0).branches.contains child = true := by
  simp [VerifiedCore.validateWalk, current, noObligation]

/-- A child already held as a non-branch is rejected even if it was visited earlier. -/
theorem validate_bad_extension_child (s : VerifiedCore.MissingWalk)
    (p : VerifiedCore.WalkPosition) (segment child : List Nat)
    (current : s.current = some p) (noObligation : s.branches.contains p.hash = false) :
    (VerifiedCore.validateWalk s (.extension segment child) 2).fault = some 0 ∧
    (VerifiedCore.validateWalk s (.extension segment child) 2).faultHash = child := by
  simp [VerifiedCore.validateWalk, VerifiedCore.failWalk, current, noObligation]

/-- A deferred extension child cannot later arrive as a leaf. -/
theorem validate_required_branch (s : VerifiedCore.MissingWalk)
    (p : VerifiedCore.WalkPosition) (suffix : List Nat) (childShape : UInt8)
    (current : s.current = some p) (required : s.branches.contains p.hash = true) :
    (VerifiedCore.validateWalk s (.leaf suffix) childShape).fault = some 0 ∧
    (VerifiedCore.validateWalk s (.leaf suffix) childShape).faultHash = p.hash := by
  simp [VerifiedCore.validateWalk, VerifiedCore.failWalk, current, required]

/-- A rejected node cannot expand children or request payloads. -/
theorem present_rejected_before_expansion (s : VerifiedCore.MissingWalk)
    (reference node : VerifiedCore.WalkNode) (childShape : UInt8)
    (payload : Option (List Nat)) (present : Bool) (healthy : s.fault = none)
    (rejected : (VerifiedCore.validateWalk { s with requestKind := 0 } node childShape).fault.isSome = true) :
    VerifiedCore.observePresent s reference node childShape payload present =
      VerifiedCore.validateWalk { s with requestKind := 0 } node childShape := by
  unfold VerifiedCore.observePresent
  rw [if_neg (by simp [healthy])]
  dsimp only
  rw [if_pos rejected]

/-- Neither storage observation can resurrect a faulted walk. -/
theorem observation_fault_sticky (s : VerifiedCore.MissingWalk)
    (reference node : VerifiedCore.WalkNode) (childShape : UInt8)
    (payload : Option (List Nat)) (present redacted : Bool) (fault : s.fault.isSome = true) :
    VerifiedCore.observePresent s reference node childShape payload present = s ∧
    VerifiedCore.observeAbsent s redacted = s := by
  simp [VerifiedCore.observePresent, VerifiedCore.observeAbsent, fault]

/-- An interrupted read is retried, never consumed a second time by polling. -/
theorem pending_poll_unchanged (s : VerifiedCore.MissingWalk) (pending : s.awaiting = true) :
    VerifiedCore.walkPoll s = s := by
  simp [VerifiedCore.walkPoll, VerifiedCore.pollWalk, pending]

/-- Outstanding storage reads prevent completion independently of frontier size. -/
theorem pending_not_exhausted (s : VerifiedCore.MissingWalk) (pending : s.awaiting = true) :
    VerifiedCore.walkExhausted s = false := by
  simp [VerifiedCore.walkExhausted, pending]

/-- Neither retry scheduling nor a batch reset can discard an interrupted read. -/
theorem pending_survives_resume (s : VerifiedCore.MissingWalk) :
    (VerifiedCore.walkResume s).awaiting = s.awaiting ∧
    (VerifiedCore.walkResume s).current = s.current ∧
    (VerifiedCore.walkBatch s).awaiting = s.awaiting := by
  simp [VerifiedCore.walkResume, VerifiedCore.resumeWalk, VerifiedCore.walkBatch]

/-- Every accepted response acknowledges its selected read. -/
theorem observation_acknowledged (s next : VerifiedCore.MissingWalk)
    (healthy : s.fault = none) (pending : s.awaiting = true) :
    (VerifiedCore.finishObservation s next).awaiting = false := by
  simp [VerifiedCore.finishObservation, healthy, pending]

/-- An unsolicited or duplicate response fails closed, rather than mutating the frontier. -/
theorem unsolicited_observation_rejected (s next : VerifiedCore.MissingWalk)
    (healthy : s.fault = none) (idle : s.awaiting = false) :
    (VerifiedCore.finishObservation s next).fault = some 0 ∧
    (VerifiedCore.finishObservation s next).faultKind = 3 ∧
    (VerifiedCore.finishObservation s next).frontier = s.frontier := by
  simp [VerifiedCore.finishObservation, VerifiedCore.failWalk, healthy, idle]

/-- Scheduling a child cannot discard any already pending position. -/
theorem enqueue_retains_frontier (s : VerifiedCore.MissingWalk)
    (r : Option (List Nat)) (hash step : List Nat) (p : VerifiedCore.WalkPosition)
    (pending : p ∈ s.frontier) : p ∈ (VerifiedCore.enqueueWalk s r hash step).frontier := by
  unfold VerifiedCore.enqueueWalk
  split
  · exact pending
  · dsimp only
    split
    · exact List.mem_cons_of_mem _ pending
    · exact pending

/-- No suffix of child expansion can discard work scheduled by an earlier child. -/
theorem enqueue_fold_retains (edges : List (Option (List Nat) × List Nat × List Nat))
    (s : VerifiedCore.MissingWalk) (p : VerifiedCore.WalkPosition) (pending : p ∈ s.frontier) :
    p ∈ (edges.foldl (fun s (r, hash, step) => VerifiedCore.enqueueWalk s r hash step) s).frontier := by
  induction edges generalizing s with
  | nil => exact pending
  | cons edge rest ih =>
    exact ih _ (enqueue_retains_frontier s edge.1 edge.2.1 edge.2.2 p pending)

/-- The executable expansion preserves every previously pending position. -/
theorem expansion_retains_frontier (s : VerifiedCore.MissingWalk)
    (reference node : VerifiedCore.WalkNode) (p : VerifiedCore.WalkPosition)
    (pending : p ∈ s.frontier) : p ∈ (VerifiedCore.walkExpand s reference node).frontier :=
  enqueue_fold_retains _ s p pending

/-- Sibling expansion never changes the scope used to authorize later children. -/
theorem enqueue_preserves_scope (s : VerifiedCore.MissingWalk)
    (r : Option (List Nat)) (hash step : List Nat) :
    (VerifiedCore.enqueueWalk s r hash step).scope = s.scope := by
  unfold VerifiedCore.enqueueWalk
  split
  · rfl
  · dsimp only
    split <;> rfl

/-- Every admitted edge in a sibling list is on the resulting frontier. This
does not assume edge uniqueness or a particular sibling ordering. -/
theorem enqueue_fold_schedules (edges : List (Option (List Nat) × List Nat × List Nat))
    (s : VerifiedCore.MissingWalk) (parent : VerifiedCore.WalkPosition)
    (r : Option (List Nat)) (hash step : List Nat)
    (current : s.current = some parent)
    (admitted : VerifiedCore.admitsPath s.scope (parent.path ++ step) = true)
    (edge : (r, hash, step) ∈ edges) :
    (⟨r, hash, parent.path ++ step⟩ : VerifiedCore.WalkPosition) ∈
      (edges.foldl (fun s (r, hash, step) => VerifiedCore.enqueueWalk s r hash step) s).frontier := by
  induction edges generalizing s with
  | nil => simp at edge
  | cons first rest ih =>
    rcases List.mem_cons.mp edge with same | later
    · subst first
      apply enqueue_fold_retains rest (VerifiedCore.enqueueWalk s r hash step)
      simp [VerifiedCore.enqueueWalk, current, admitted]
    · apply ih _ (by rw [enqueue_preserves_current, current])
        (by rw [enqueue_preserves_scope]; exact admitted) later

/-- Actual child expansion schedules every admitted target edge, with exactly
the reference selected by the executable pairing function. -/
theorem expansion_schedules_all (s : VerifiedCore.MissingWalk)
    (parent : VerifiedCore.WalkPosition) (reference node : VerifiedCore.WalkNode)
    (hash step : List Nat) (current : s.current = some parent)
    (admitted : VerifiedCore.admitsPath s.scope (parent.path ++ step) = true)
    (edge : (step, hash) ∈ VerifiedCore.childEdges node) :
    (⟨if VerifiedCore.compatibleNodes reference node then
        (VerifiedCore.childEdges reference).lookup step else none,
      hash, parent.path ++ step⟩ : VerifiedCore.WalkPosition) ∈
      (VerifiedCore.walkExpand s reference node).frontier := by
  apply enqueue_fold_schedules _ s parent _ hash step current admitted
  exact (paired_edges_exact reference node _ hash step).mpr ⟨edge, rfl⟩

/-- Every input position survives a successful poll as pending/selected work,
unless the exact executable reference or seen-set shortcut justifies skipping it. -/
theorem poll_frontier_accounts_for_all (scope : VerifiedCore.Scope) (limit : Nat)
    (seen : Std.TreeSet VerifiedCore.WalkVisit)
    (frontier : List VerifiedCore.WalkPosition) (p : VerifiedCore.WalkPosition)
    (healthy : (VerifiedCore.pollFrontier scope limit seen frontier).fault = none)
    (pending : p ∈ frontier) :
    p ∈ (VerifiedCore.pollFrontier scope limit seen frontier).rest ∨
    (VerifiedCore.pollFrontier scope limit seen frontier).current = some p ∨
    (p.reference == some p.hash || seen.contains (VerifiedCore.walkVisit scope p)) = true := by
  induction frontier with
  | nil => simp at pending
  | cons q rest ih =>
    simp only [VerifiedCore.pollFrontier] at healthy ⊢
    by_cases deep : q.path.length > limit
    · simp [deep] at healthy
    · simp only [if_neg deep] at healthy ⊢
      by_cases skipped : (q.reference == some q.hash || seen.contains (VerifiedCore.walkVisit scope q)) = true
      · simp only [if_pos skipped] at healthy ⊢
        rcases List.mem_cons.mp pending with rfl | later
        · exact Or.inr (Or.inr skipped)
        · exact ih healthy later
      · simp only [if_neg skipped] at healthy ⊢
        rcases List.mem_cons.mp pending with rfl | later
        · exact Or.inr (Or.inl rfl)
        · exact Or.inl later

/-- A drained successful poll skipped every original position by an explicit
reference-equality or seen-set shortcut; none disappeared silently. -/
theorem drained_frontier_shortcuts (scope : VerifiedCore.Scope) (limit : Nat)
    (seen : Std.TreeSet VerifiedCore.WalkVisit)
    (frontier : List VerifiedCore.WalkPosition)
    (healthy : (VerifiedCore.pollFrontier scope limit seen frontier).fault = none)
    (drained : (VerifiedCore.pollFrontier scope limit seen frontier).rest = [])
    (idle : (VerifiedCore.pollFrontier scope limit seen frontier).current = none)
    (p : VerifiedCore.WalkPosition) (pending : p ∈ frontier) :
    (p.reference == some p.hash || seen.contains (VerifiedCore.walkVisit scope p)) = true := by
  have accounted := poll_frontier_accounts_for_all scope limit seen frontier p healthy pending
  simpa [drained, idle] using accounted

/-- Payload request/deferral bookkeeping cannot discard scheduled children. -/
theorem payload_preserves_frontier (s : VerifiedCore.MissingWalk)
    (node : VerifiedCore.WalkNode) (payload : Option (List Nat)) (present : Bool) :
    (VerifiedCore.observePayload s node payload present).frontier = s.frontier := by
  unfold VerifiedCore.observePayload
  split
  · rfl
  · split
    · rfl
    · split
      · simp [VerifiedCore.deferWalk, *]
      · rfl

/-- The successful native observation export has exactly the expanded frontier:
neither payload handling nor acknowledgement can silently remove children. -/
theorem present_export_frontier (s : VerifiedCore.MissingWalk)
    (reference node : VerifiedCore.WalkNode) (childShape : UInt8)
    (payload : ByteArray) (present : Bool) (healthy : s.fault = none)
    (pending : s.awaiting = true)
    (valid : (VerifiedCore.validateWalk { s with requestKind := 0 } node childShape).fault = none) :
    (VerifiedCore.walkPresent s reference node childShape payload present).frontier =
      (VerifiedCore.expandWalk (VerifiedCore.validateWalk { s with requestKind := 0 } node childShape)
        reference node).frontier := by
  unfold VerifiedCore.walkPresent VerifiedCore.finishObservation
  rw [if_neg (by simp [healthy]), if_pos pending]
  change (VerifiedCore.observePresent s reference node childShape _ present).frontier = _
  unfold VerifiedCore.observePresent
  rw [if_neg (by simp [healthy])]
  dsimp only
  rw [if_neg (by simp only [valid, Option.isSome_none, Bool.false_eq_true, not_false_eq_true])]
  exact payload_preserves_frontier _ _ _ _

/-- A protocol state cannot claim a pending read without identifying its position. -/
def ReadIdentified (s : VerifiedCore.MissingWalk) : Prop :=
  s.awaiting = true → s.current.isSome = true

/-- The acknowledgement gate preserves read identification regardless of the
observation's result: it either retains the old state or clears the pending bit. -/
theorem acknowledge_read_identified (s next : VerifiedCore.MissingWalk)
    (identified : ReadIdentified s) : ReadIdentified (VerifiedCore.finishObservation s next) := by
  unfold VerifiedCore.finishObservation
  split
  · exact identified
  · split
    · simp [ReadIdentified]
    · simpa [ReadIdentified, VerifiedCore.failWalk] using identified

/-- Finite executions of the actual native exports, not a separately implemented
state machine. Storage facts remain explicit inputs, including arbitrary errors
that leave the selected read pending by making no observation. -/
inductive WalkExecution : VerifiedCore.MissingWalk → Prop where
  | initial (scope : VerifiedCore.Scope) (reference root : ByteArray) (limit : UInt64) :
      WalkExecution (VerifiedCore.walkNew scope reference root limit)
  | poll {s} : WalkExecution s → WalkExecution (VerifiedCore.walkPoll s)
  | resume {s} : WalkExecution s → WalkExecution (VerifiedCore.walkResume s)
  | batch {s} : WalkExecution s → WalkExecution (VerifiedCore.walkBatch s)
  | absent {s} (redacted : Bool) : WalkExecution s → WalkExecution (VerifiedCore.walkAbsent s redacted)
  | present {s} (reference node : VerifiedCore.WalkNode) (childShape : UInt8)
      (payload : ByteArray) (held : Bool) : WalkExecution s →
      WalkExecution (VerifiedCore.walkPresent s reference node childShape payload held)

/-- Across every finite exported-operation sequence, a pending read always has
a concrete position. No assumption about truthful storage facts is needed. -/
theorem execution_read_identified {s : VerifiedCore.MissingWalk} (run : WalkExecution s) :
    ReadIdentified s := by
  induction run with
  | initial => simp [ReadIdentified, VerifiedCore.walkNew]
  | poll prior ih =>
    unfold VerifiedCore.walkPoll VerifiedCore.pollWalk
    split
    · exact ih
    · exact fun h => h
  | resume prior ih => simpa [ReadIdentified, VerifiedCore.walkResume, VerifiedCore.resumeWalk] using ih
  | batch prior ih => simpa [ReadIdentified, VerifiedCore.walkBatch] using ih
  | absent redacted prior ih => exact acknowledge_read_identified _ _ ih
  | present reference node childShape payload held prior ih => exact acknowledge_read_identified _ _ ih

/-- An unacknowledged read stays the same concrete read after any number of
polls, not merely after a single retry. -/
theorem repeated_pending_poll (s : VerifiedCore.MissingWalk) (pending : s.awaiting = true)
    (count : Nat) : (VerifiedCore.walkPoll^[count]) s = s := by
  induction count with
  | zero => rfl
  | succ count ih =>
    rw [Function.iterate_succ_apply', ih, pending_poll_unchanged s pending]

/-- The concrete visit key retains both content identity and depth. Its only
positional quotient is between positions entirely inside granted subtrees. -/
theorem equal_visit_classification (scope : VerifiedCore.Scope)
    (p q : VerifiedCore.WalkPosition) (same : VerifiedCore.walkVisit scope p = VerifiedCore.walkVisit scope q) :
    p.hash = q.hash ∧ p.path.length = q.path.length ∧
    (p.path = q.path ∨ (VerifiedCore.containsSubtree scope p.path = true ∧
      VerifiedCore.containsSubtree scope q.path = true)) := by
  refine ⟨congrArg (fun k => k.2.1) same, congrArg Prod.fst same, ?_⟩
  have positions := congrArg (fun k => k.2.2) same
  by_cases hp : VerifiedCore.containsSubtree scope p.path = true
  · by_cases hq : VerifiedCore.containsSubtree scope q.path = true
    · exact Or.inr ⟨hp, hq⟩
    · simp [VerifiedCore.walkVisit, hp, hq] at positions
  · by_cases hq : VerifiedCore.containsSubtree scope q.path = true
    · simp [VerifiedCore.walkVisit, hp, hq] at positions
    · exact Or.inl (by simpa [VerifiedCore.walkVisit, hp, hq] using positions)

/-- Runtime subtree grants remain grants after every finite child step. -/
theorem runtime_grant_append (scope : VerifiedCore.Scope) (path step : List Nat)
    (granted : VerifiedCore.containsSubtree scope path = true) :
    VerifiedCore.containsSubtree scope (path ++ step) = true :=
  (containsSubtree_correct scope _).mpr
    (Scope.containsSubtree_append ((containsSubtree_correct scope _).mp granted) step)

/-- Hash/depth deduplication cannot change the authorization of a child step. -/
theorem equal_visit_child_admission (scope : VerifiedCore.Scope)
    (p q : VerifiedCore.WalkPosition) (same : VerifiedCore.walkVisit scope p = VerifiedCore.walkVisit scope q)
    (step : List Nat) : VerifiedCore.admitsPath scope (p.path ++ step) =
      VerifiedCore.admitsPath scope (q.path ++ step) := by
  rcases (equal_visit_classification scope p q same).2.2 with paths | ⟨hp, hq⟩
  · rw [paths]
  · have admitted (path : List Nat) (h : VerifiedCore.containsSubtree scope path = true) :
        VerifiedCore.admitsPath scope (path ++ step) = true :=
      (admitsPath_correct scope _).mpr (Scope.admitsPath_of_containsSubtree
        ((containsSubtree_correct scope _).mp (runtime_grant_append scope path step h)))
    rw [admitted p.path hp, admitted q.path hq]

/-- Two equivalent parent visits yield equivalent child visits for identical
content edges, preserving both their depth budget and positional scope quotient. -/
theorem equal_visit_children (scope : VerifiedCore.Scope)
    (p q : VerifiedCore.WalkPosition) (same : VerifiedCore.walkVisit scope p = VerifiedCore.walkVisit scope q)
    (hash step : List Nat) (rp rq : Option (List Nat)) :
    VerifiedCore.walkVisit scope ⟨rp, hash, p.path ++ step⟩ =
      VerifiedCore.walkVisit scope ⟨rq, hash, q.path ++ step⟩ := by
  obtain ⟨_, depth, paths | ⟨hp, hq⟩⟩ := equal_visit_classification scope p q same
  · simp [VerifiedCore.walkVisit, paths]
  · simp [VerifiedCore.walkVisit, runtime_grant_append scope p.path step hp,
      runtime_grant_append scope q.path step hq, depth]

/-- The payload permission of identical content is invariant under visit-key
equivalence; exact-key grants do not get promoted into subtree grants. -/
theorem equal_visit_payload_admission (scope : VerifiedCore.Scope)
    (p q : VerifiedCore.WalkPosition) (same : VerifiedCore.walkVisit scope p = VerifiedCore.walkVisit scope q)
    (node : VerifiedCore.WalkNode) :
    VerifiedCore.admitsValue scope p.path (VerifiedCore.walkShape node) =
      VerifiedCore.admitsValue scope q.path (VerifiedCore.walkShape node) := by
  rcases (equal_visit_classification scope p q same).2.2 with paths | ⟨hp, hq⟩
  · rw [paths]
  · cases node with
    | branch children => simp [VerifiedCore.walkShape, VerifiedCore.admitsValue, VerifiedCore.admitsKey, hp, hq]
    | extension segment child => rfl
    | leaf suffix =>
      simp [VerifiedCore.walkShape, VerifiedCore.admitsValue, VerifiedCore.admitsKey,
        runtime_grant_append scope p.path suffix hp, runtime_grant_append scope q.path suffix hq]

/-- Equivalent visits cannot disagree on a leaf's absolute-depth validation. -/
theorem equal_visit_leaf_depth (scope : VerifiedCore.Scope)
    (p q : VerifiedCore.WalkPosition) (same : VerifiedCore.walkVisit scope p = VerifiedCore.walkVisit scope q)
    (suffix : List Nat) : p.path.length + suffix.length = q.path.length + suffix.length := by
  rw [(equal_visit_classification scope p q same).2.1]

end Synchronicity.VerifiedCoreProofs

#lint
