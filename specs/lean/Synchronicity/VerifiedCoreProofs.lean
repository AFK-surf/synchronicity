import VerifiedCore
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

end Synchronicity.VerifiedCoreProofs

#lint
