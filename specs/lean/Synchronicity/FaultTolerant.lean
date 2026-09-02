import Synchronicity.SystemSafety

/-!
The fault-tolerant extension of `SystemSafety`.

`SystemSafety` trusts the durable backend: once a row is `durable`, the bytes
are there.  This file drops that trust.  Two environment steps take the bytes
away with no guard at all, and two heal steps mirror what Rust does when a
read discovers the loss.  What survives is `Cas.Invariant` alone — a role's
pin stands on a row the backend still *claims* durably, not on bytes, and the
operator's pin is given no guarantee, which is exactly what Rust's heal leaves
in place.  `Cas.invariant_step` already covers the twenty-three cell
transitions; only the four steps added here need proving.  Every
`SystemSafety`-reachable state is reachable here, so the strong theorems
remain the fault-free specialization.
-/

namespace Synchronicity.FaultTolerant

open Cas

variable {H : Type} [Roles H]

/-- A claim with nothing behind it: acknowledged bytes that are gone.  The state
between a loss and its heal. -/
def Lost (c : Cell H) : Prop := c.durable ∧ ¬(c.bytes ∨ c.remote)

/- The backend loses an object it acknowledged.  No Rust site: this is the
   environment breaking its contract. -/
def LoseRemote (c c' : Cell H) : Prop := c' = { c with remote := False }

/- The local payload or outboard goes missing or is truncated.  No Rust site. -/
def LoseBytes (c c' : Cell H) : Prop := c' = { c with bytes := False }

/- RUST-IMPL: cas-heal-missing-durable — `cas.rs::Store::heal_missing_durable_blob`.
   The backend answered `NotFound` for a durable root.  The durable claim is
   withdrawn, a row with nothing cached goes with it, every role's pin becomes
   a repair want, and the operator's pin is left standing.  Unguarded on the
   loss itself: the heal believes the backend, and a spurious answer costs a
   refetch rather than a promise. -/
def HealRemote (c c' : Cell H) : Prop :=
  c.durable ∧
  c' = { c with
    durable := False
    row := c.row ∧ c.bytes
    pin := fun holder => c.pin holder ∧ ¬IsRole holder
    want := fun holder => c.want holder ∨ (IsRole holder ∧ c.pin holder) }

/- RUST-IMPL: cas-heal-missing-local — `cas.rs::Store::heal_missing_local_blob`.
   A local read found the payload missing or short.  The complete and durable
   claims are withdrawn, the row stays, and pins convert as above. -/
def HealLocal (c c' : Cell H) : Prop :=
  c.row ∧
  c' = { c with
    bytes := False
    durable := False
    pin := fun holder => c.pin holder ∧ ¬IsRole holder
    want := fun holder => c.want holder ∨ (IsRole holder ∧ c.pin holder) }

inductive FaultStep : Cell H → Cell H → Prop where
  | cell : CellStep c c' → FaultStep c c'
  | loseRemote : LoseRemote c c' → FaultStep c c'
  | loseBytes : LoseBytes c c' → FaultStep c c'
  | healRemote : HealRemote c c' → FaultStep c c'
  | healLocal : HealLocal c c' → FaultStep c c'

variable {c c' : Cell H} {holder : H}

/-- A heal turns every role's live claim from a pin into a want. -/
theorem LiveClaim.heal (h : LiveClaim c holder)
    (entry : c.entry → c'.entry)
    (want : c.want holder ∨ (IsRole holder ∧ c.pin holder) → c'.want holder) :
    LiveClaim c' holder :=
  ⟨h.1, entry h.2.1,
    Or.inr (want (h.2.2.elim (fun p => Or.inr ⟨h.1, p.1⟩) Or.inl))⟩

theorem fault_invariant_step (hinv : Cas.Invariant c) (hstep : FaultStep c c') :
    Cas.Invariant c' := by
  obtain ⟨pins, sources, replicas, ordinary, sweepInv⟩ := hinv
  cases hstep with
  | cell step => exact invariant_step ⟨pins, sources, replicas, ordinary, sweepInv⟩ step
  | loseRemote h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sources, replicas, ordinary, sweepInv⟩
  | loseBytes h =>
      obtain ⟨rfl⟩ := h
      exact ⟨pins, sources, replicas, ordinary, sweepInv⟩
  | healRemote h =>
      obtain ⟨_, rfl⟩ := h
      exact ⟨fun _ role pinned => absurd role pinned.2,
        fun h l => LiveClaim.heal (sources h l) id id,
        fun h l => LiveClaim.heal (replicas h l) id id,
        ordinary,
        fun sw => ⟨(sweepInv sw).1, fun h p => (sweepInv sw).2.1 h p.1, (sweepInv sw).2.2.1,
          fun row => (sweepInv sw).2.2.2 row.1⟩⟩
  | healLocal h =>
      obtain ⟨_, rfl⟩ := h
      exact ⟨fun _ role pinned => absurd role pinned.2,
        fun h l => LiveClaim.heal (sources h l) id id,
        fun h l => LiveClaim.heal (replicas h l) id id,
        ordinary,
        fun sw => ⟨(sweepInv sw).1, fun h p => (sweepInv sw).2.1 h p.1, (sweepInv sw).2.2⟩⟩

def SystemInvariant (s : State H) : Prop := ∀ root, Cas.Invariant (s root)

inductive Step : State H → State H → Prop where
  | root {s : State H} {root : Root} {cell' : Cell H} :
      FaultStep (s root) cell' → Step s (Replace s root cell')

inductive Reachable : State H → Prop where
  | initial : Reachable Initial
  | next {s s' : State H} : Reachable s → Step s s' → Reachable s'

theorem initial_invariant : SystemInvariant (Initial : State H) :=
  fun _ => Cas.initial_invariant

theorem invariant_step {s s' : State H} (hinv : SystemInvariant s) (hstep : Step s s') :
    SystemInvariant s' := by
  cases hstep with
  | root step => exact replace_forall hinv (fault_invariant_step (hinv _) step)

theorem reachable_invariant {s : State H} (h : Reachable s) : SystemInvariant s := by
  induction h with
  | initial => exact initial_invariant
  | next _ step ih => exact invariant_step ih step

/- Every fault-free execution is an execution here, so the `SystemSafety`
   theorems are this model's fault-free specialization. -/
theorem fault_free_step {s s' : State H} (h : SystemSafety.Step s s') : Step s s' := by
  cases h with
  | root step => exact .root (.cell step)

theorem fault_free_is_reachable {s : State H} (h : SystemSafety.Reachable s) : Reachable s := by
  induction h with
  | initial => exact .initial
  | next _ step ih => exact .next ih (fault_free_step step)

/-! ## What survives a loss -/

variable {s : State H} {root : Root}

theorem role_pin_stands_on_durable_row
    (reachable : Reachable s) (role : IsRole holder) (pinned : (s root).pin holder) :
    Durable (s root) :=
  (reachable_invariant reachable root).role_pin_durable holder role pinned

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
  ((reachable_invariant reachable root).source_live holder live).2.2

theorem replica_live_is_held_or_wanted
    (reachable : Reachable s) (live : (s root).replicaLive holder) :
    ((s root).pin holder ∧ Durable (s root)) ∨ (s root).want holder :=
  ((reachable_invariant reachable root).replica_live holder live).2.2

theorem live_holders_are_roles
    (reachable : Reachable s)
    (live : (s root).sourceLive holder ∨ (s root).replicaLive holder) :
    IsRole holder := by
  have inv := reachable_invariant reachable root
  rcases live with source | replica
  · exact (inv.source_live holder source).1
  · exact (inv.replica_live holder replica).1

/-! ## What the heal promises, and what it deliberately does not -/

theorem heal_converts_role_pins (heal : HealRemote c c') (role : IsRole holder) :
    ¬c'.pin holder ∧ (c.pin holder → c'.want holder) := by
  obtain ⟨_, rfl⟩ := heal
  exact ⟨fun pinned => pinned.2 role, fun pinned => Or.inr ⟨role, pinned⟩⟩

theorem local_heal_converts_role_pins (heal : HealLocal c c') (role : IsRole holder) :
    ¬c'.pin holder ∧ (c.pin holder → c'.want holder) := by
  obtain ⟨_, rfl⟩ := heal
  exact ⟨fun pinned => pinned.2 role, fun pinned => Or.inr ⟨role, pinned⟩⟩

/- The operator's pin is a person's promise the node reports rather than
   rewrites: it survives the heal, standing over a claim the node has just
   withdrawn.  Nothing in this model says anything stronger about it. -/
theorem heal_keeps_operator_pin (heal : HealRemote c c') (operator : ¬IsRole holder)
    (pinned : c.pin holder) : c'.pin holder ∧ ¬c'.durable := by
  obtain ⟨_, rfl⟩ := heal
  exact ⟨⟨pinned, operator⟩, id⟩

end Synchronicity.FaultTolerant
