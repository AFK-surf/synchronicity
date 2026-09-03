import Synchronicity.SystemSafety

/-!
The fault-tolerant extension of `SystemSafety`.

`SystemSafety` trusts the durable backend: once a row is `durable`, the bytes
are there.  This file drops that trust.  Two environment steps take the bytes
away with no guard at all, and two heal steps mirror what Rust does when a
read discovers the loss.  What survives is `Cas.Invariant` alone — a role's
pin stands on a row the backend still *claims* durably, not on bytes, and the
operator's pin is given no guarantee, which is exactly what Rust's heal leaves
in place.  `Cas.invariant_step` already covers the cell transitions; only the
four steps added here need proving.  Every `SystemSafety`-reachable state is
reachable here, so the strong theorems remain the fault-free specialization.
-/

namespace Synchronicity.FaultTolerant

open Cas

variable {H : Type} [Roles H]

/-- A claim with nothing behind it: acknowledged bytes that are gone.  The state
between a loss and its heal. -/
def Lost (c : Cell H) : Prop := c.durable ∧ ¬(c.bytes ∨ c.remote)

/-- The backend loses an object it acknowledged.  No Rust site: this is the
environment breaking its contract. -/
@[transition]
def LoseRemote : Transition (Cell H) where
  guard _ := True
  post c := { c with remote := False }

/-- The local payload or outboard goes missing or is truncated.  No Rust
site. -/
@[transition]
def LoseBytes : Transition (Cell H) where
  guard _ := True
  post c := { c with bytes := False }

/-- `cas.rs::Store::heal_missing_durable_blob`.  The backend answered
`NotFound` for a durable root.  The durable claim is withdrawn, a row holding
no group goes with it, a row holding some stays as the partial cache it is,
every role's pin becomes a repair want, and the operator's pin is left
standing.  Unguarded on the loss itself: the heal believes the backend, and a
spurious answer costs a refetch rather than a promise. -/
@[transition, rust_impl "cas-heal-missing-durable"]
def HealRemote : Transition (Cell H) where
  guard c := c.durable
  post c := { c with
    durable := False
    row := c.row ∧ ∃ g, g ∈ c.held
    pin := {holder ∈ c.pin | ¬IsRole holder}
    want := c.want ∪ {holder ∈ c.pin | IsRole holder} }

/-- `cas.rs::Store::heal_missing_local_blob`.  A local read found the payload
missing or short.  The row stays and forgets what it held, the durable claim
is withdrawn, and pins convert as above. -/
@[transition, rust_impl "cas-heal-missing-local"]
def HealLocal : Transition (Cell H) where
  guard c := c.row
  post c := { c with
    held := ∅
    bytes := False
    durable := False
    pin := {holder ∈ c.pin | ¬IsRole holder}
    want := c.want ∪ {holder ∈ c.pin | IsRole holder} }

/-- A cell transition, a loss, or a heal. -/
inductive FaultStep : Cell H → Cell H → Prop where
  | cell : CellStep c c' → FaultStep c c'
  | loseRemote : LoseRemote.rel c c' → FaultStep c c'
  | loseBytes : LoseBytes.rel c c' → FaultStep c c'
  | healRemote : HealRemote.rel c c' → FaultStep c c'
  | healLocal : HealLocal.rel c c' → FaultStep c c'

variable {c c' : Cell H} {holder : H}

theorem fault_invariant_step (hinv : Cas.Invariant c) (hstep : FaultStep c c') :
    Cas.Invariant c' := by
  cases hstep with
  | cell step => exact invariant_step hinv step
  | _ h =>
    obtain ⟨pins, sources, replicas, ordinary, sweepInv, heldRow, heldSize⟩ := hinv
    simp only [transition] at h
    obtain ⟨hg, rfl⟩ := h
    constructor <;> grind [LiveClaim, Durable]

/-- Neither a loss nor a heal moves a row's size, so `Cas.settled_size_is_stable`
holds of every step of this model too. -/
theorem settled_size_survives_faults (h : FaultStep c c') (row : c.row) (settled : Settled c)
    (row' : c'.row) : c'.size = c.size := by
  cases h with
  | cell step =>
    obtain ⟨k, step⟩ := step
    exact settled_size_is_stable step row settled row'
  | _ h =>
    simp only [transition] at h
    obtain ⟨_, rfl⟩ := h
    rfl

/-- Every cell satisfies `Cas.Invariant`. -/
def SystemInvariant (s : State H) : Prop := ∀ root, Cas.Invariant (s root)

/-- One cell takes a `FaultStep`; every other root is left as it was. -/
abbrev Step : State H → State H → Prop := Lift FaultStep

/-- The fault-tolerant system. -/
def system (H : Type) [Roles H] : System (State H) := ⟨Initial, Step⟩

/-- The states the fault-tolerant system reaches. -/
abbrev Reachable (s : State H) : Prop := (system H).Reachable s

theorem invariant : (system H).Invariant SystemInvariant where
  init _ := Cas.initial_invariant
  step hinv hstep := Lift.forall (fun inv step => fault_invariant_step inv step) hinv hstep

theorem reachable_invariant {s : State H} (h : Reachable s) : SystemInvariant s :=
  invariant.reachable h

/-- Every fault-free execution is an execution here, so the `SystemSafety`
theorems are this model's fault-free specialization. -/
theorem fault_free_is_reachable {s : State H} (h : SystemSafety.Reachable s) : Reachable s :=
  System.Reachable.mono (S := SystemSafety.system H) (T := system H) rfl
    (fun step => Lift.mono (fun cell => FaultStep.cell cell) step) h

/-! ## What survives a loss -/

variable {s : State H} {root : Root}

theorem role_pin_stands_on_durable_row
    (reachable : Reachable s) (role : IsRole holder) (pinned : holder ∈ (s root).pin) :
    Durable (s root) :=
  (reachable_invariant reachable root).role_pin_durable holder role pinned

theorem role_pin_is_available_or_lost
    (reachable : Reachable s) (role : IsRole holder) (pinned : holder ∈ (s root).pin) :
    Available (s root) ∨ Lost (s root) := by
  have durable := role_pin_stands_on_durable_row reachable role pinned
  by_cases held : (s root).bytes ∨ (s root).remote
  · exact Or.inl ⟨durable.1, durable.2, held⟩
  · exact Or.inr ⟨durable.2, held⟩

theorem no_role_pin_over_withdrawn_claim
    (reachable : Reachable s) (withdrawn : ¬(s root).durable) (role : IsRole holder) :
    holder ∉ (s root).pin :=
  fun pinned => withdrawn (role_pin_stands_on_durable_row reachable role pinned).2

theorem source_live_is_held_or_wanted
    (reachable : Reachable s) (live : holder ∈ (s root).sourceLive) :
    (holder ∈ (s root).pin ∧ Durable (s root)) ∨ holder ∈ (s root).want :=
  ((reachable_invariant reachable root).source_live holder live).2.2

theorem replica_live_is_held_or_wanted
    (reachable : Reachable s) (live : holder ∈ (s root).replicaLive) :
    (holder ∈ (s root).pin ∧ Durable (s root)) ∨ holder ∈ (s root).want :=
  ((reachable_invariant reachable root).replica_live holder live).2.2

theorem live_holders_are_roles
    (reachable : Reachable s)
    (live : holder ∈ (s root).sourceLive ∨ holder ∈ (s root).replicaLive) :
    IsRole holder := by
  have inv := reachable_invariant reachable root
  rcases live with source | replica
  · exact (inv.source_live holder source).1
  · exact (inv.replica_live holder replica).1

/-! ## What the heal promises, and what it deliberately does not -/

theorem heal_converts_role_pins (heal : HealRemote.rel c c') (role : IsRole holder) :
    holder ∉ c'.pin ∧ (holder ∈ c.pin → holder ∈ c'.want) := by
  simp only [transition] at heal
  obtain ⟨_, rfl⟩ := heal
  exact ⟨fun pinned => pinned.2 role, fun pinned => Or.inr ⟨pinned, role⟩⟩

theorem local_heal_converts_role_pins (heal : HealLocal.rel c c') (role : IsRole holder) :
    holder ∉ c'.pin ∧ (holder ∈ c.pin → holder ∈ c'.want) := by
  simp only [transition] at heal
  obtain ⟨_, rfl⟩ := heal
  exact ⟨fun pinned => pinned.2 role, fun pinned => Or.inr ⟨pinned, role⟩⟩

/-- The operator's pin is a person's promise the node reports rather than
rewrites: it survives the heal, standing over a claim the node has just
withdrawn.  Nothing in this model says anything stronger about it. -/
theorem heal_keeps_operator_pin (heal : HealRemote.rel c c') (operator : ¬IsRole holder)
    (pinned : holder ∈ c.pin) : holder ∈ c'.pin ∧ ¬c'.durable := by
  simp only [transition] at heal
  obtain ⟨_, rfl⟩ := heal
  exact ⟨⟨pinned, operator⟩, id⟩

/-! ## At the system's own holders

`SystemSafety.Holder` has the operator at `⟨0⟩`.  The theorems above are
stated for any `Roles` instance; these are the two the design document
quotes, read at the instance the system runs. -/

section Holder

open SystemSafety (Holder operator)

/-- `synch pin add`'s pin survives a heal over the claim it withdrew. -/
theorem operator_pin_survives_heal {c c' : Cell Holder} (heal : HealRemote.rel c c')
    (pinned : operator ∈ c.pin) : operator ∈ c'.pin ∧ ¬c'.durable :=
  heal_keeps_operator_pin heal SystemSafety.operator_not_role pinned

/-- Every holder but the operator has its pin converted to a want by a heal. -/
theorem configured_pin_becomes_want {c c' : Cell Holder} (heal : HealRemote.rel c c')
    {holder : Holder} (configured : holder ≠ operator) :
    holder ∉ c'.pin ∧ (holder ∈ c.pin → holder ∈ c'.want) :=
  heal_converts_role_pins heal configured

/-- No live leaf of the system is the operator's. -/
theorem operator_holds_no_leaf {s : State Holder} {root : Root} (reachable : Reachable s) :
    operator ∉ (s root).sourceLive ∧ operator ∉ (s root).replicaLive :=
  ⟨fun live => live_holders_are_roles reachable (Or.inl live) rfl,
    fun live => live_holders_are_roles reachable (Or.inr live) rfl⟩

end Holder

end Synchronicity.FaultTolerant

#lint
