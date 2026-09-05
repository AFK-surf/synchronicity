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
    s.frontier = [] ∧ s.deferred = [] ∧ s.fault = none := by
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
    (seen : Std.TreeSet (List Nat × Option (List Nat)))
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
    (seen : Std.TreeSet (List Nat × Option (List Nat)))
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
    (granted : VerifiedCore.containsSubtree s.scope p.path = true) (redacted : Bool) :
    (VerifiedCore.walkAbsent s redacted).requestKind = 1 ∧
    (VerifiedCore.walkAbsent s redacted).deferred = p :: s.deferred := by
  simp [VerifiedCore.walkAbsent, VerifiedCore.observeAbsent, VerifiedCore.deferWalk,
    current, healthy, granted]

/-- An absent refused spine position is satisfied without requesting or deferring it. -/
theorem absent_refused_spine (s : VerifiedCore.MissingWalk) (p : VerifiedCore.WalkPosition)
    (current : s.current = some p) (healthy : s.fault = none)
    (spine : VerifiedCore.containsSubtree s.scope p.path = false) :
    (VerifiedCore.walkAbsent s true).requestKind = 0 ∧
    (VerifiedCore.walkAbsent s true).deferred = s.deferred := by
  simp [VerifiedCore.walkAbsent, VerifiedCore.observeAbsent, current, healthy, spine]

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

end Synchronicity.VerifiedCoreProofs

#lint
