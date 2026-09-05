import Synchronicity.Convergence
import Synchronicity.Bridge

/-!
Semantic layer above the accounting bridge. Heads are indexed by origin, rows
by origin and key, and content references are decoded from the selected trie.
The diff algorithm below computes the new rows rather than accepting an
arbitrary sequence of CAS microsteps. Decoding and the SQL implementation of
this functional delta remain refinement obligations, not kernel-checked Rust.
-/
namespace Synchronicity.Materialization

open ScopedSync

/-- A decoded file entry, including the content identity and advertised size. -/
structure Entry where
  /-- The CAS object named by the file. -/
  root : Cas.Root
  /-- The file entry's length. -/
  size : Nat
  deriving DecidableEq

/-- An origin's materialized rows. -/
abbrev Rows := Path → Option Entry

/-- The decoded trie view is tied to actual authorized trie leaves. A caller
must additionally establish readability before attempting SQL materialization. -/
def ViewOf (c : Content) (s : Scope) (decode : ValueRef → Option Entry)
    (view : Hash → Rows) : Prop :=
  ∀ root key entry, view root key = some entry ↔
    ∃ v, Convergence.ScopedView c s root key v ∧ decode v = some entry

/-- The structural diff changes only keys whose old and new decoded values differ. -/
@[rust_impl "mpt-materialize-delta"]
def applyDiff (old new rows : Rows) : Rows :=
  fun key => if old key = new key then rows key else new key

/-- Starting from the old view, applying its diff yields exactly the new view. -/
theorem applyDiff_exact (old new : Rows) : applyDiff old new old = new := by
  funext key
  simp only [applyDiff]
  split <;> rename_i h
  · exact h
  · rfl

/-- The actual head identity and rows committed for every origin. -/
structure State (O : Type) where
  /-- Each origin's selected root; no head means no rows. -/
  head : O → Option Hash
  /-- Rows rebuilt by the promotion transaction. -/
  rows : O → Rows
  /-- The store snapshot used to resolve the promotion's values. -/
  store : ScopedSync.Store := {}

/-- The empty head has no decoded rows. -/
def atHead (view : Hash → Rows) : Option Hash → Rows
  | none => fun _ => none
  | some root => view root

/-- Materialized rows correspond to the specific root in each origin's slot. -/
def Consistent (view : Hash → Rows) (st : State O) : Prop :=
  ∀ origin, st.rows origin = atHead view (st.head origin)

/-- Atomic head flip and delta application, including deletion via `none`. -/
noncomputable def commit (view : Hash → Rows) (st : State O) (origin : O)
    (root : Option Hash) : State O := by
  classical
  exact { st with
    head := Function.update st.head origin root
    rows := Function.update st.rows origin
      (applyDiff (atHead view (st.head origin)) (atHead view root) (st.rows origin)) }

/-- The head/row invariant is preserved, including origins untouched by the transaction. -/
theorem commit_consistent (view : Hash → Rows) (st : State O) (origin : O)
    (root : Option Hash) (h : Consistent view st) :
    Consistent view (commit view st origin root) := by
  classical
  intro other
  by_cases eq : other = origin
  · subst other
    simp [commit, h origin, applyDiff_exact]
  · simpa [commit, Function.update_of_ne eq] using h other

/-- Actual committed rows converge, not merely the abstract trie relation. -/
theorem rows_converge {a b : State O} (ha : Consistent view a) (hb : Consistent view b)
    (heads : a.head origin = b.head origin) : a.rows origin = b.rows origin := by
  rw [ha origin, hb origin, heads]

/-- A successful promotion requires actual readable, decodable values in its
store snapshot. The pure delta function alone does not authorize a head flip. -/
noncomputable def Promote (c : Content) (s : Scope) (decode : ValueRef → Option Entry)
    (view : Hash → Rows) (origin : O) (root : Hash) : Transition (State O) where
  guard st := ViewOf c s decode view ∧ ∀ key entry, view root key = some entry →
    ∃ v, Convergence.Readable c st.store s root key v ∧ decode v = some entry
  post st := commit view st origin (some root)

/-- Every row a successful promotion installs has a real readable payload at
that exact root, not a refusal counted as a read or a free materialized bit. -/
theorem promoted_row_was_readable {before after : State O}
    (consistent : Consistent view before)
    (step : (Promote c s decode view origin root).rel before after)
    (row : after.rows origin key = some entry) :
    ∃ v, Convergence.Readable c before.store s root key v ∧ decode v = some entry := by
  obtain ⟨guard, rfl⟩ := step
  change (commit view before origin (some root)).rows origin key = some entry at row
  have hc := commit_consistent view before origin (some root) consistent origin
  rw [hc] at row
  have head : (commit view before origin (some root)).head origin = some root := by
    classical
    simp [commit]
  rw [head] at row
  exact guard.2 key entry row

/-- Which materialized file rows reference one CAS root for a holder. The role
predicate selects source, replica or ordinary rows; no independent live bit is
allowed in this semantic projection. -/
def References (rows : O → Rows) (holder : O → Path → H) (role : O → Path → Prop)
    (root : Cas.Root) (h : H) : Prop :=
  ∃ origin key entry, rows origin key = some entry ∧ entry.root = root ∧
    holder origin key = h ∧ role origin key

/-- Each projected CAS reference has an actual decoded leaf in that origin's
selected head. This rules out standing a leaf against an unrelated head bit. -/
theorem reference_has_selected_leaf {st : State O} (consistent : Consistent view st)
    (decoded : ViewOf c s decode view)
    (ref : References st.rows holder role root h) :
    ∃ origin key entry trieRoot v, st.head origin = some trieRoot ∧
      Convergence.ScopedView c s trieRoot key v ∧ decode v = some entry ∧
      entry.root = root ∧ holder origin key = h ∧ role origin key := by
  obtain ⟨origin, key, entry, row, eroot, held, kind⟩ := ref
  rw [consistent origin] at row
  cases head : st.head origin with
  | none => simp [head, atHead] at row
  | some trieRoot =>
    change atHead view (st.head origin) key = some entry at row
    rw [head] at row
    obtain ⟨v, hv, hd⟩ := (decoded trieRoot key entry).mp row
    exact ⟨origin, key, entry, trieRoot, v, head, hv, hd, eroot, held, kind⟩

/-- The semantic CAS projection computes live sets and source sizes from rows.
The candidate CAS state supplies physical storage and pin/want accounting,
but cannot independently choose which published file leaves stand. -/
def withReferences (rows : O → Rows) (holder : O → Path → H)
    (source replica ordinary : O → Path → Prop) (cas : Cas.State H) : Cas.State H :=
  fun root => { cas root with
    entry := ∃ origin key entry, rows origin key = some entry ∧ entry.root = root
    sourceLive := References rows holder source root
    replicaLive := References rows holder replica root
    ordinaryLive := References rows holder ordinary root
    sourceAdvertised := fun h size => ∃ origin key entry,
      rows origin key = some entry ∧ entry.root = root ∧ holder origin key = h ∧
      source origin key ∧ entry.size = size }

/-- The composed contract requires a legal accounting trace to the state whose
references are computed from the actual committed rows. A freely chosen bridge
microtrace no longer suffices. Source availability then follows for precisely
those row-derived references, using the existing CAS preservation proof. -/
theorem row_derived_source_available [Cas.Roles H]
    {before candidate : Cas.State H} (safe : SystemSafety.SystemInvariant before)
    (trace : Bridge.PublishTxn before (withReferences rows holder source replica ordinary candidate))
    (live : References rows holder source root h) :
    Cas.Available (withReferences rows holder source replica ordinary candidate root) := by
  have inv := Bridge.publishTxn_safe safe trace root
  exact inv.2.pin_available h (inv.2.source_pinned h live)

end Synchronicity.Materialization

#lint
