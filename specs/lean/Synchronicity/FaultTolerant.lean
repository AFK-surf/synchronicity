import Synchronicity.SystemSafety

/-!
The fault-tolerant extension of `SystemSafety`.

`SystemSafety` trusts the durable backend: once a row is `durable`, the bytes
are there.  This file drops that trust.  Two environment steps take the bytes
away with no guard at all, and two heal steps mirror what Rust does when a
read discovers the loss.  The invariant that survives is weaker — a role's pin
stands on a row the backend still *claims* durably, not on bytes — and the
operator's pin is given no guarantee, which is exactly what Rust's heal leaves
in place.  Every `SystemSafety`-reachable state is reachable here, so the
strong theorems remain the fault-free specialization.
-/

namespace Synchronicity.FaultTolerant

open SystemSafety (Cell Holder Root State Initial Replace Available IsRole operator CellStep)

/-- A durable claim: the row exists and the backend has acknowledged the bytes.
Only modelled steps write these two fields, so a loss cannot change it. -/
def Durable (c : Cell) : Prop := c.row ∧ c.durable

/-- A claim with nothing behind it: acknowledged bytes that are gone.  The state
between a loss and its heal. -/
def Lost (c : Cell) : Prop := c.durable ∧ ¬(c.bytes ∨ c.remote)

/- The backend loses an object it acknowledged.  No Rust site: this is the
   environment breaking its contract. -/
def LoseRemote (c c' : Cell) : Prop := c' = { c with remote := False }

/- The local payload or outboard goes missing or is truncated.  No Rust site. -/
def LoseBytes (c c' : Cell) : Prop := c' = { c with bytes := False }

/- RUST-IMPL: cas-heal-missing-durable — `cas.rs::Store::heal_missing_durable_blob`.
   The backend answered `NotFound` for a durable root.  The durable claim is
   withdrawn, a row with nothing cached goes with it, every role's pin becomes
   a repair want, and the operator's pin is left standing.  Unguarded on the
   loss itself: the heal believes the backend, and a spurious answer costs a
   refetch rather than a promise. -/
def HealRemote (c c' : Cell) : Prop :=
  c.durable ∧
  c' = { c with
    durable := False
    row := c.row ∧ c.bytes
    pin := fun holder => c.pin holder ∧ ¬IsRole holder
    want := fun holder => c.want holder ∨ (IsRole holder ∧ c.pin holder) }

/- RUST-IMPL: cas-heal-missing-local — `cas.rs::Store::heal_missing_local_blob`.
   A local read found the payload missing or short.  The complete and durable
   claims are withdrawn, the row stays, and pins convert as above. -/
def HealLocal (c c' : Cell) : Prop :=
  c.row ∧
  c' = { c with
    bytes := False
    durable := False
    pin := fun holder => c.pin holder ∧ ¬IsRole holder
    want := fun holder => c.want holder ∨ (IsRole holder ∧ c.pin holder) }

/-- What survives a loss.  Compared with `SystemSafety.Invariant`: `Available`
becomes `Durable`, the pin clause is restricted to roles, a source leaf may be
wanted rather than pinned, and live holders are recorded as roles. -/
def Invariant (c : Cell) : Prop :=
  (∀ holder, IsRole holder → c.pin holder → Durable c) ∧
  (∀ holder, c.sourceLive holder →
    IsRole holder ∧ c.entry ∧ ((c.pin holder ∧ Durable c) ∨ c.want holder)) ∧
  (∀ holder, c.replicaLive holder →
    IsRole holder ∧ c.entry ∧ ((c.pin holder ∧ Durable c) ∨ c.want holder)) ∧
  (∀ holder, c.ordinaryLive holder → c.entry) ∧
  (c.sweeping → ¬c.entry ∧ (∀ holder, ¬c.pin holder) ∧ ¬c.writing ∧ ¬c.row)

inductive FaultStep : Cell → Cell → Prop where
  | cell : CellStep c c' → FaultStep c c'
  | loseRemote : LoseRemote c c' → FaultStep c c'
  | loseBytes : LoseBytes c c' → FaultStep c c'
  | healRemote : HealRemote c c' → FaultStep c c'
  | healLocal : HealLocal c c' → FaultStep c c'

theorem cell_invariant_step (hinv : Invariant c) (hstep : CellStep c c') :
    Invariant c' := by
  rcases hinv with ⟨pins, sources, replicas, ordinary, sweepInv⟩
  cases hstep with
  | beginWrite h =>
      rcases h with ⟨notSweeping, rfl⟩
      refine ⟨pins, sources, replicas, ordinary, ?_⟩
      intro sweeping
      exact False.elim (notSweeping sweeping)
  | writeAbort h =>
      rcases h with ⟨rfl⟩
      refine ⟨pins, sources, replicas, ordinary, ?_⟩
      intro sweeping
      have old := sweepInv sweeping
      exact ⟨old.1, old.2.1, by simp, old.2.2.2⟩
  | commitAvailable h =>
      rcases h with ⟨notSweeping, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder _ _
        exact ⟨trivial, trivial⟩
      · intro holder live
        have old := sources holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨pinned.1, trivial, trivial⟩⟩
        · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨pinned.1, trivial, trivial⟩⟩
        · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | finalizeRemote h =>
      rcases h with ⟨notSweeping, row, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder _ _
        exact ⟨row, trivial⟩
      · intro holder live
        have old := sources holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨pinned.1, row, trivial⟩⟩
        · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨pinned.1, row, trivial⟩⟩
        · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | age h =>
      rcases h with ⟨rfl⟩
      exact ⟨pins, sources, replicas, ordinary, sweepInv⟩
  | adoptRemote h =>
      rcases h with ⟨notSweeping, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder _ _
        exact ⟨trivial, trivial⟩
      · intro holder live
        have old := sources holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨pinned.1, trivial, trivial⟩⟩
        · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨pinned.1, trivial, trivial⟩⟩
        · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | cacheEvict h =>
      rcases h with ⟨_, _, rfl⟩
      exact ⟨pins, sources, replicas, ordinary, sweepInv⟩
  | dropStaged h =>
      rcases h with ⟨notDurable, _, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder role pinned
        exact False.elim (notDurable (pins holder role pinned).2)
      · intro holder live
        have old := sources holder live
        rcases old.2.2 with pinned | wanted
        · exact False.elim (notDurable pinned.2.2)
        · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2.2 with pinned | wanted
        · exact False.elim (notDurable pinned.2.2)
        · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro sweeping
        have old := sweepInv sweeping
        exact ⟨old.1, old.2.1, old.2.2.1, id⟩
  | sourcePublish h =>
      rename_i target
      rcases h with ⟨role, notSweeping, available, rfl⟩
      have durable : Durable c := ⟨available.1, available.2.1⟩
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · intro holder r pinned
        rcases pinned with rfl | old
        · exact durable
        · exact pins holder r old
      · intro holder live
        rcases live with rfl | old
        · exact ⟨role, trivial, Or.inl ⟨Or.inl rfl, durable⟩⟩
        · have prior := sources holder old
          rcases prior.2.2 with pinned | wanted
          · exact ⟨prior.1, trivial, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
          · by_cases same : holder = target
            · exact ⟨prior.1, trivial, Or.inl ⟨Or.inl same, durable⟩⟩
            · exact ⟨prior.1, trivial, Or.inr ⟨wanted, same⟩⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, trivial, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
        · by_cases same : holder = target
          · exact ⟨old.1, trivial, Or.inl ⟨Or.inl same, durable⟩⟩
          · exact ⟨old.1, trivial, Or.inr ⟨wanted, same⟩⟩
      · intro _ _
        trivial
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | replicaPromote h =>
      rename_i target
      rcases h with ⟨role, notSweeping, held | missing⟩
      · rcases held with ⟨available, rfl⟩
        have durable : Durable c := ⟨available.1, available.2.1⟩
        refine ⟨?_, ?_, ?_, ?_, ?_⟩
        · intro holder r pinned
          rcases pinned with rfl | old
          · exact durable
          · exact pins holder r old
        · intro holder live
          have old := sources holder live
          rcases old.2.2 with pinned | wanted
          · exact ⟨old.1, trivial, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
          · by_cases same : holder = target
            · exact ⟨old.1, trivial, Or.inl ⟨Or.inl same, durable⟩⟩
            · exact ⟨old.1, trivial, Or.inr ⟨wanted, same⟩⟩
        · intro holder live
          rcases live with rfl | old
          · exact ⟨role, trivial, Or.inl ⟨Or.inl rfl, durable⟩⟩
          · have prior := replicas holder old
            rcases prior.2.2 with pinned | wanted
            · exact ⟨prior.1, trivial, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
            · by_cases same : holder = target
              · exact ⟨prior.1, trivial, Or.inl ⟨Or.inl same, durable⟩⟩
              · exact ⟨prior.1, trivial, Or.inr ⟨wanted, same⟩⟩
        · intro _ _
          trivial
        · intro sweeping
          exact False.elim (notSweeping sweeping)
      · rcases missing with ⟨_, rfl⟩
        refine ⟨pins, ?_, ?_, ?_, ?_⟩
        · intro holder live
          have old := sources holder live
          exact ⟨old.1, trivial, old.2.2.imp id (fun wanted => Or.inr wanted)⟩
        · intro holder live
          rcases live with rfl | old
          · exact ⟨role, trivial, Or.inr (Or.inl rfl)⟩
          · have prior := replicas holder old
            exact ⟨prior.1, trivial, prior.2.2.imp id (fun wanted => Or.inr wanted)⟩
        · intro _ _
          trivial
        · intro sweeping
          exact False.elim (notSweeping sweeping)
  | ordinaryPromote h =>
      rcases h with ⟨notSweeping, rfl⟩
      refine ⟨pins, ?_, ?_, ?_, ?_⟩
      · intro holder live
        have old := sources holder live
        exact ⟨old.1, trivial, old.2.2⟩
      · intro holder live
        have old := replicas holder live
        exact ⟨old.1, trivial, old.2.2⟩
      · intro _ _
        trivial
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | removeSource h =>
      rcases h with ⟨rfl⟩
      refine ⟨pins, ?_, replicas, ordinary, sweepInv⟩
      intro holder live
      exact sources holder live.1
  | removeReplica h =>
      rcases h with ⟨rfl⟩
      refine ⟨pins, sources, ?_, ordinary, sweepInv⟩
      intro holder live
      exact replicas holder live.1
  | removeOrdinary h =>
      rcases h with ⟨rfl⟩
      refine ⟨pins, sources, replicas, ?_, sweepInv⟩
      intro holder live
      exact ordinary holder live.1
  | dropEntry h =>
      rcases h with ⟨noLive, rfl⟩
      refine ⟨pins, ?_, ?_, ?_, ?_⟩
      · intro holder live
        exact False.elim ((noLive holder).1 live)
      · intro holder live
        exact False.elim ((noLive holder).2.1 live)
      · intro holder live
        exact False.elim ((noLive holder).2.2 live)
      · intro sweeping
        have old := sweepInv sweeping
        exact ⟨id, old.2⟩
  | pin h =>
      rename_i target
      rcases h with ⟨notSweeping, available, rfl⟩
      have durable : Durable c := ⟨available.1, available.2.1⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder r pinned
        rcases pinned with rfl | old
        · exact durable
        · exact pins holder r old
      · intro holder live
        have old := sources holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
        · by_cases same : holder = target
          · exact ⟨old.1, old.2.1, Or.inl ⟨Or.inl same, durable⟩⟩
          · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
        · by_cases same : holder = target
          · exact ⟨old.1, old.2.1, Or.inl ⟨Or.inl same, durable⟩⟩
          · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | unpin h =>
      rename_i target
      rcases h with ⟨noSource, noReplica, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder r pinned
        exact pins holder r pinned.1
      · intro holder live
        by_cases same : holder = target
        · exact False.elim (noSource (same ▸ live))
        · have old := sources holder live
          rcases old.2.2 with pinned | wanted
          · exact ⟨old.1, old.2.1, Or.inl ⟨⟨pinned.1, same⟩, pinned.2⟩⟩
          · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro holder live
        by_cases same : holder = target
        · exact False.elim (noReplica (same ▸ live))
        · have old := replicas holder live
          rcases old.2.2 with pinned | wanted
          · exact ⟨old.1, old.2.1, Or.inl ⟨⟨pinned.1, same⟩, pinned.2⟩⟩
          · exact ⟨old.1, old.2.1, Or.inr wanted⟩
      · intro sweeping
        have old := sweepInv sweeping
        exact ⟨old.1, fun holder pinned => old.2.1 holder pinned.1, old.2.2⟩
  | dropWant h =>
      rename_i target
      rcases h with ⟨noSource, noReplica, rfl⟩
      refine ⟨pins, ?_, ?_, ordinary, sweepInv⟩
      · intro holder live
        by_cases same : holder = target
        · exact False.elim (noSource (same ▸ live))
        · have old := sources holder live
          rcases old.2.2 with pinned | wanted
          · exact ⟨old.1, old.2.1, Or.inl pinned⟩
          · exact ⟨old.1, old.2.1, Or.inr ⟨wanted, same⟩⟩
      · intro holder live
        by_cases same : holder = target
        · exact False.elim (noReplica (same ▸ live))
        · have old := replicas holder live
          rcases old.2.2 with pinned | wanted
          · exact ⟨old.1, old.2.1, Or.inl pinned⟩
          · exact ⟨old.1, old.2.1, Or.inr ⟨wanted, same⟩⟩
  | takePossession h =>
      rename_i target
      rcases h with ⟨notSweeping, _, available, rfl⟩
      have durable : Durable c := ⟨available.1, available.2.1⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder r pinned
        rcases pinned with rfl | old
        · exact durable
        · exact pins holder r old
      · intro holder live
        have old := sources holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
        · by_cases same : holder = target
          · exact ⟨old.1, old.2.1, Or.inl ⟨Or.inl same, durable⟩⟩
          · exact ⟨old.1, old.2.1, Or.inr ⟨wanted, same⟩⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inl ⟨Or.inr pinned.1, pinned.2⟩⟩
        · by_cases same : holder = target
          · exact ⟨old.1, old.2.1, Or.inl ⟨Or.inl same, durable⟩⟩
          · exact ⟨old.1, old.2.1, Or.inr ⟨wanted, same⟩⟩
      · intro sweeping
        exact False.elim (notSweeping sweeping)
  | gcCommit h =>
      rcases h with ⟨collectable, rfl⟩
      rcases collectable with ⟨_, noEntry, noPin, noWriting, _, _⟩
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · intro holder _ pinned
        exact False.elim (noPin ⟨holder, pinned⟩)
      · intro holder live
        exact False.elim (noEntry (sources holder live).2.1)
      · intro holder live
        exact False.elim (noEntry (replicas holder live).2.1)
      · intro holder live
        exact False.elim (noEntry (ordinary holder live))
      · intro _
        exact ⟨noEntry, fun holder pinned => noPin ⟨holder, pinned⟩, noWriting, id⟩
  | gcUnlink h =>
      rcases h with ⟨sweeping, rfl⟩
      have old := sweepInv sweeping
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder _ pinned
        exact False.elim (old.2.1 holder pinned)
      · intro holder live
        exact False.elim (old.1 (sources holder live).2.1)
      · intro holder live
        exact False.elim (old.1 (replicas holder live).2.1)
      · intro impossible
        exact False.elim impossible
  | protectedDelete h =>
      rcases h with ⟨deletable, rfl⟩
      rcases deletable with ⟨noEntry, noPin, noWriting, _⟩
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · intro holder _ pinned
        exact False.elim (noPin ⟨holder, pinned⟩)
      · intro holder live
        exact False.elim (noEntry (sources holder live).2.1)
      · intro holder live
        exact False.elim (noEntry (replicas holder live).2.1)
      · intro holder live
        exact False.elim (noEntry (ordinary holder live))
      · intro _
        exact ⟨noEntry, fun holder pinned => noPin ⟨holder, pinned⟩, noWriting, id⟩

theorem fault_invariant_step (hinv : Invariant c) (hstep : FaultStep c c') :
    Invariant c' := by
  cases hstep with
  | cell step => exact cell_invariant_step hinv step
  | loseRemote h =>
      rcases hinv with ⟨pins, sources, replicas, ordinary, sweepInv⟩
      rcases h with ⟨rfl⟩
      exact ⟨pins, sources, replicas, ordinary, sweepInv⟩
  | loseBytes h =>
      rcases hinv with ⟨pins, sources, replicas, ordinary, sweepInv⟩
      rcases h with ⟨rfl⟩
      exact ⟨pins, sources, replicas, ordinary, sweepInv⟩
  | healRemote h =>
      rcases hinv with ⟨_, sources, replicas, ordinary, sweepInv⟩
      rcases h with ⟨_, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder role pinned
        exact False.elim (pinned.2 role)
      · intro holder live
        have old := sources holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inr (Or.inr ⟨old.1, pinned.1⟩)⟩
        · exact ⟨old.1, old.2.1, Or.inr (Or.inl wanted)⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inr (Or.inr ⟨old.1, pinned.1⟩)⟩
        · exact ⟨old.1, old.2.1, Or.inr (Or.inl wanted)⟩
      · intro sweeping
        have old := sweepInv sweeping
        exact ⟨old.1, fun holder pinned => old.2.1 holder pinned.1, old.2.2.1,
          fun row => old.2.2.2 row.1⟩
  | healLocal h =>
      rcases hinv with ⟨_, sources, replicas, ordinary, sweepInv⟩
      rcases h with ⟨_, rfl⟩
      refine ⟨?_, ?_, ?_, ordinary, ?_⟩
      · intro holder role pinned
        exact False.elim (pinned.2 role)
      · intro holder live
        have old := sources holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inr (Or.inr ⟨old.1, pinned.1⟩)⟩
        · exact ⟨old.1, old.2.1, Or.inr (Or.inl wanted)⟩
      · intro holder live
        have old := replicas holder live
        rcases old.2.2 with pinned | wanted
        · exact ⟨old.1, old.2.1, Or.inr (Or.inr ⟨old.1, pinned.1⟩)⟩
        · exact ⟨old.1, old.2.1, Or.inr (Or.inl wanted)⟩
      · intro sweeping
        have old := sweepInv sweeping
        exact ⟨old.1, fun holder pinned => old.2.1 holder pinned.1, old.2.2⟩

def SystemInvariant (s : State) : Prop := ∀ root, Invariant (s root)

inductive Step : State → State → Prop where
  | root : FaultStep (s root) cell' → Step s (Replace s root cell')

inductive Reachable : State → Prop where
  | initial : Reachable Initial
  | next : Reachable s → Step s s' → Reachable s'

theorem initial_invariant : SystemInvariant Initial := by
  simp [SystemInvariant, Initial, Invariant]

theorem invariant_step (hinv : SystemInvariant s) (hstep : Step s s') :
    SystemInvariant s' := by
  cases hstep with
  | root step =>
      intro candidate
      simp only [Replace]
      split
      · exact fault_invariant_step (hinv _) step
      · exact hinv candidate

theorem reachable_invariant (h : Reachable s) : SystemInvariant s := by
  induction h with
  | initial => exact initial_invariant
  | next _ step ih => exact invariant_step ih step

/- Every fault-free execution is an execution here, so the `SystemSafety`
   theorems are this model's fault-free specialization. -/
theorem fault_free_step (h : SystemSafety.Step s s') : Step s s' := by
  cases h with
  | root step => exact .root (.cell step)

theorem fault_free_is_reachable (h : SystemSafety.Reachable s) : Reachable s := by
  induction h with
  | initial => exact .initial
  | next _ step ih => exact .next ih (fault_free_step step)

/- What survives a loss. -/

theorem role_pin_stands_on_durable_row
    (reachable : Reachable s) (role : IsRole holder) (pinned : (s root).pin holder) :
    Durable (s root) :=
  (reachable_invariant reachable root).1 holder role pinned

theorem role_pin_is_available_or_lost
    (reachable : Reachable s) (role : IsRole holder) (pinned : (s root).pin holder) :
    Available (s root) ∨ Lost (s root) := by
  have durable := role_pin_stands_on_durable_row reachable role pinned
  by_cases held : (s root).bytes ∨ (s root).remote
  · exact Or.inl ⟨durable.1, durable.2, held⟩
  · exact Or.inr ⟨durable.2, held⟩

theorem no_role_pin_over_withdrawn_claim
    (reachable : Reachable s) (withdrawn : ¬(s root).durable) (role : IsRole holder) :
    ¬(s root).pin holder :=
  fun pinned => withdrawn (role_pin_stands_on_durable_row reachable role pinned).2

theorem source_live_is_held_or_wanted
    (reachable : Reachable s) (live : (s root).sourceLive holder) :
    ((s root).pin holder ∧ Durable (s root)) ∨ (s root).want holder :=
  ((reachable_invariant reachable root).2.1 holder live).2.2

theorem replica_live_is_held_or_wanted
    (reachable : Reachable s) (live : (s root).replicaLive holder) :
    ((s root).pin holder ∧ Durable (s root)) ∨ (s root).want holder :=
  ((reachable_invariant reachable root).2.2.1 holder live).2.2

theorem live_holders_are_roles
    (reachable : Reachable s)
    (live : (s root).sourceLive holder ∨ (s root).replicaLive holder) :
    IsRole holder := by
  rcases live with source | replica
  · exact ((reachable_invariant reachable root).2.1 holder source).1
  · exact ((reachable_invariant reachable root).2.2.1 holder replica).1

/- What the heal promises, and what it deliberately does not. -/

theorem heal_converts_role_pins (heal : HealRemote c c') (role : IsRole holder) :
    ¬c'.pin holder ∧ (c.pin holder → c'.want holder) := by
  rcases heal with ⟨_, rfl⟩
  exact ⟨fun pinned => pinned.2 role, fun pinned => Or.inr ⟨role, pinned⟩⟩

theorem local_heal_converts_role_pins (heal : HealLocal c c') (role : IsRole holder) :
    ¬c'.pin holder ∧ (c.pin holder → c'.want holder) := by
  rcases heal with ⟨_, rfl⟩
  exact ⟨fun pinned => pinned.2 role, fun pinned => Or.inr ⟨role, pinned⟩⟩

/- The operator's pin is a person's promise the node reports rather than
   rewrites: it survives the heal, standing over a claim the node has just
   withdrawn.  Nothing in this model says anything stronger about it. -/
theorem heal_keeps_operator_pin (heal : HealRemote c c') (pinned : c.pin operator) :
    c'.pin operator ∧ ¬c'.durable := by
  rcases heal with ⟨_, rfl⟩
  exact ⟨⟨pinned, fun role => role rfl⟩, id⟩

end Synchronicity.FaultTolerant
