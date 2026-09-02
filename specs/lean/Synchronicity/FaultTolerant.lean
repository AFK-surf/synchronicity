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

/-- The backend loses an object it acknowledged.  No Rust site: this is the
environment breaking its contract. -/
def LoseRemote (c c' : Cell H) : Prop := c' = { c with remote := False }

/-- The local payload or outboard goes missing or is truncated.  No Rust
site. -/
def LoseBytes (c c' : Cell H) : Prop := c' = { c with bytes := False }

/-- `cas.rs::Store::heal_missing_durable_blob`.  The backend answered
`NotFound` for a durable root.  The durable claim is withdrawn, a row with
nothing cached goes with it, every role's pin becomes a repair want, and the
operator's pin is left standing.  Unguarded on the loss itself: the heal
believes the backend, and a spurious answer costs a refetch rather than a
promise. -/
@[rust_impl "cas-heal-missing-durable"]
def HealRemote (c c' : Cell H) : Prop :=
  c.durable ∧
  c' = { c with
    durable := False
    row := c.row ∧ c.bytes
    pin := fun holder => c.pin holder ∧ ¬IsRole holder
    want := fun holder => c.want holder ∨ (IsRole holder ∧ c.pin holder) }

/-- `cas.rs::Store::heal_missing_local_blob`.  A local read found the payload
missing or short.  The complete and durable claims are withdrawn, the row
stays, and pins convert as above. -/
@[rust_impl "cas-heal-missing-local"]
def HealLocal (c c' : Cell H) : Prop :=
  c.row ∧
  c' = { c with
    bytes := False
    durable := False
    pin := fun holder => c.pin holder ∧ ¬IsRole holder
    want := fun holder => c.want holder ∨ (IsRole holder ∧ c.pin holder) }

/-- A cell transition, a loss, or a heal. -/
inductive FaultStep : Cell H → Cell H → Prop where
  | cell : CellStep c c' → FaultStep c c'
  | loseRemote : LoseRemote c c' → FaultStep c c'
  | loseBytes : LoseBytes c c' → FaultStep c c'
  | healRemote : HealRemote c c' → FaultStep c c'
  | healLocal : HealLocal c c' → FaultStep c c'

variable {c c' : Cell H} {holder : H}

theorem fault_invariant_step (hinv : Cas.Invariant c) (hstep : FaultStep c c') :
    Cas.Invariant c' := by
  cases hstep with
  | cell step => exact invariant_step hinv step
  | _ h =>
    obtain ⟨pins, sources, replicas, ordinary, sweepInv⟩ := hinv
    simp only [LoseRemote, LoseBytes, HealRemote, HealLocal] at h
    subst_step h <;> constructor <;> grind [LiveClaim, Durable]

def SystemInvariant (s : State H) : Prop := ∀ root, Cas.Invariant (s root)

abbrev Step : State H → State H → Prop := Lift FaultStep

/-- The fault-tolerant system. -/
def system (H : Type) [Roles H] : System (State H) := ⟨Initial, Step⟩

abbrev Reachable (s : State H) : Prop := (system H).Reachable s

theorem initial_invariant : SystemInvariant (Initial : State H) :=
  fun _ => Cas.initial_invariant

theorem invariant_step {s s' : State H} (hinv : SystemInvariant s) (hstep : Step s s') :
    SystemInvariant s' :=
  Lift.forall (fun inv step => fault_invariant_step inv step) hinv hstep

theorem reachable_invariant {s : State H} (h : Reachable s) : SystemInvariant s :=
  h.invariant initial_invariant invariant_step

/-- Every fault-free execution is an execution here, so the `SystemSafety`
theorems are this model's fault-free specialization. -/
theorem fault_free_is_reachable {s : State H} (h : SystemSafety.Reachable s) : Reachable s :=
  System.Reachable.mono (S := SystemSafety.system H) (T := system H) rfl
    (fun step => Lift.mono (fun cell => FaultStep.cell cell) step) h

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

/-- The operator's pin is a person's promise the node reports rather than
rewrites: it survives the heal, standing over a claim the node has just
withdrawn.  Nothing in this model says anything stronger about it. -/
theorem heal_keeps_operator_pin (heal : HealRemote c c') (operator : ¬IsRole holder)
    (pinned : c.pin holder) : c'.pin holder ∧ ¬c'.durable := by
  obtain ⟨_, rfl⟩ := heal
  exact ⟨⟨pinned, operator⟩, id⟩

/-! ## At the system's own holders

`SystemSafety.Holder` is `Nat` with the operator at `0`.  The theorems above
are stated for any `Roles` instance; these are the two the design document
quotes, read at the instance the system runs. -/

section Holder

open SystemSafety (Holder operator)

/-- `synch pin add`'s pin survives a heal over the claim it withdrew. -/
theorem operator_pin_survives_heal {c c' : Cell Holder} (heal : HealRemote c c')
    (pinned : c.pin operator) : c'.pin operator ∧ ¬c'.durable :=
  heal_keeps_operator_pin heal SystemSafety.operator_not_role pinned

/-- Every holder but the operator has its pin converted to a want by a heal. -/
theorem configured_pin_becomes_want {c c' : Cell Holder} (heal : HealRemote c c')
    {holder : Holder} (configured : holder ≠ operator) :
    ¬c'.pin holder ∧ (c.pin holder → c'.want holder) :=
  heal_converts_role_pins heal configured

/-- No live leaf of the system is the operator's. -/
theorem operator_holds_no_leaf {s : State Holder} {root : Root} (reachable : Reachable s) :
    ¬(s root).sourceLive operator ∧ ¬(s root).replicaLive operator :=
  ⟨fun live => live_holders_are_roles reachable (Or.inl live) rfl,
    fun live => live_holders_are_roles reachable (Or.inr live) rfl⟩

end Holder

end Synchronicity.FaultTolerant
