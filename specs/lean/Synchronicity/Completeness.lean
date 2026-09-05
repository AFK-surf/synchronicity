import Synchronicity.TrieGraph

/-!
Generation-checked completeness certificates. `valid` is instantiated with
`CompleteWithin` over the shared or provenance-filtered store. A walk issues a
ticket against its snapshot; certification is a separate step. Non-monotone
mutations advance the generation at both transaction edges and block cache
reads while uncommitted. Monotone arrivals preserve existing tickets.
-/
namespace Synchronicity.Completeness

/-- One store, its certificates, and tickets held by suspended walks. -/
structure State (D Q : Type) where
  /-- The committed node/provenance store. -/
  data : D
  /-- Shared invalidation generation. -/
  generation : Nat := 0
  /-- Transactions which have invalidated but not yet committed or rolled back. -/
  mutating : Nat := 0
  /-- Completed walks, including stale tickets still held by callers. -/
  tickets : Set (Nat × Q) := ∅
  /-- Cached certificates. -/
  memo : Set Q := ∅

variable {D Q : Type} {valid : D → Q → Prop} {s s' : State D Q}

/-- Every current ticket and usable memo describes the committed data. -/
structure Invariant (valid : D → Q → Prop) (s : State D Q) : Prop where
  /-- Tickets cannot come from a future generation. -/
  ticket_age : ∀ e q, (e, q) ∈ s.tickets → e ≤ s.generation
  /-- A current ticket was not invalidated since its walk. -/
  ticket_sound : ∀ q, (s.generation, q) ∈ s.tickets → valid s.data q
  /-- Cached certificates remain true when transactions are quiescent. -/
  memo_sound : s.mutating = 0 → ∀ q ∈ s.memo, valid s.data q

/-- A drained snapshot walk produces a ticket, not an unconditional memo. -/
@[transition]
def Issue (valid : D → Q → Prop) (q : Q) : Transition (State D Q) where
  guard s := valid s.data q
  post s := { s with tickets := insert (s.generation, q) s.tickets }

/-- `Store::note_complete_at`: epoch comparison and insertion share one lock. -/
@[transition]
def Certify (e : Nat) (q : Q) : Transition (State D Q) where
  guard s := s.mutating = 0 ∧ e = s.generation ∧ (e, q) ∈ s.tickets
  post s := { s with memo := insert q s.memo }

/-- Nodes with no redacted position and values preserve all existing answers. -/
@[transition]
def Monotone (valid : D → Q → Prop) (data : D) : Transition (State D Q) where
  guard s := ∀ q, valid s.data q → valid data q
  post s := { s with data := data }

/-- Invalidate before visibility. GC may keep only its retained-root memos;
node and ownership insertions keep none. -/
@[transition]
def Begin (keep : Set Q) : Transition (State D Q) where
  guard _ := True
  post s := { s with
    generation := s.generation + 1
    mutating := s.mutating + 1
    memo := s.memo ∩ keep }

/-- Commit or rollback, after which a snapshot from inside the transaction
must fail its epoch check. `valid` for retained GC certificates is justified
by `TrieGraph.gcSweep_complete_iff`; other invalidations clear the cache. -/
@[transition]
def Finish (valid : D → Q → Prop) (data : D) : Transition (State D Q) where
  guard s := 0 < s.mutating ∧ ∀ q ∈ s.memo, valid data q
  post s := { s with data := data, generation := s.generation + 1, mutating := s.mutating - 1 }

/-- A mutation, walk result, or certificate operation. -/
inductive Kind (D Q : Type) where
  | issue (q : Q) | certify (e : Nat) (q : Q) | monotone (data : D)
  | beginMutation (keep : Set Q) | finish (data : D)

/-- The transition named by an operation. -/
@[transition]
def Trans (valid : D → Q → Prop) : Kind D Q → Transition (State D Q)
  | .issue q => Issue valid q
  | .certify e q => Certify e q
  | .monotone data => Monotone valid data
  | .beginMutation keep => Begin keep
  | .finish data => Finish valid data

/-- One certificate-system operation. -/
def Step (valid : D → Q → Prop) (s s' : State D Q) : Prop :=
  ∃ k, (Trans valid k).rel s s'

theorem invariant_step (h : Invariant valid s) (step : Step valid s s') :
    Invariant valid s' := by
  obtain ⟨age, tickets, memo⟩ := h
  obtain ⟨k, hg, rfl⟩ := step
  cases k <;> simp only [transition] at hg ⊢ <;> constructor <;> grind

/-- The system starts with no tickets or memos over any initial store. -/
def system (valid : D → Q → Prop) (initial : D) : System (State D Q) :=
  ⟨{ data := initial }, Step valid⟩

theorem invariant (initial : D) : (system valid initial).Invariant (Invariant valid) where
  init := ⟨by simp [system], by simp [system], by simp [system]⟩
  step := invariant_step

/-- The cache may answer true only for a currently valid query. -/
theorem certified_is_complete {initial : D} (h : (system valid initial).Reachable s)
    (idle : s.mutating = 0) (cached : q ∈ s.memo) : valid s.data q :=
  (invariant initial |>.reachable h).memo_sound idle q cached

/-- An old fetch cannot restore a memo after either invalidation edge. -/
theorem stale_ticket_rejected (old : e < s.generation) : ¬ (Certify e q).rel s s' := by
  intro h
  have := h.1.2.1
  omega

/-- A transaction in progress cannot publish a snapshot certificate. -/
theorem uncommitted_ticket_rejected (busy : 0 < s.mutating) : ¬ (Certify e q).rel s s' := by
  intro h
  have := h.1.1
  omega

/-- Concrete certificate queries include scope as well as root identity. -/
abbrev TrieQuery := Scope × ScopedSync.Hash

/-- The cache predicate instantiated by the shared trie store. Provenance
queries use the same predicate over `Provenance.view` before certification. -/
def TrieValid (c : ScopedSync.Content) (st : TrieGraph.State) (q : TrieQuery) : Prop :=
  TrieGraph.Complete c q.1 st q.2

/-- Ordinary arrivals really satisfy the certificate model's monotonicity
guard. A formerly refused node does not meet this lemma's premise and must
instead pass through invalidation. -/
theorem ordinary_arrival_monotone {c : ScopedSync.Content} {st : TrieGraph.State}
    {x : ScopedSync.Hash} (notRefused : ∀ p, (p, x) ∉ st.store.redacted) :
    (Monotone (TrieValid c) ((TrieGraph.LearnNode x).post st)).guard
      ({ data := st } : State TrieGraph.State TrieQuery) :=
  fun _ h => TrieGraph.learnNode_complete notRefused h

/-- Retained-root GC is the concrete justification for preserving a memo at
the finish edge; invalidating arrivals preserve no memos. -/
theorem gc_preserves_certificate {c : ScopedSync.Content} {st : TrieGraph.State}
    {q : TrieQuery} (retained : q.2 ∈ st.retained) (valid : TrieValid c st q) :
    TrieValid c ((TrieGraph.GcSweep c).post st) q :=
  (TrieGraph.gcSweep_complete_iff retained).mpr valid

end Synchronicity.Completeness

#lint
