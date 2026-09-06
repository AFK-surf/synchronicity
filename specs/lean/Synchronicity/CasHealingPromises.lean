import VerifiedCore.Cas.Read

/-! Healing preserves obligations. The state interpreter checks the actual raw
requests and interprets copy-on-conflict and deletion over arbitrary keyed rows.
The SQL LIKE matcher is an explicit parameter, shared by copy and delete. -/
namespace Synchronicity.CasHealingPromises
open VerifiedCore.Host VerifiedCore.Cas.Read
noncomputable section
local instance (p : Prop) : Decidable p := Classical.propDecidable p

abbrev Key := ByteArray × String

structure State where
  /-- Raw fields of the target blob; unassigned columns survive UPDATE. -/
  blob : String → Cell
  pins : Key → Bool
  wants : Key → Option Fields

structure Host where
  root : ByteArray
  size : Int64
  now : Int64
  /-- The backend's LIKE result for the literal repair selection. No typed
  holder interpretation or case-folding assumption is made. -/
  likeMatch : String → Bool

def selected (host : Host) (key : Key) : Prop :=
  key.1 = host.root ∧ host.likeMatch key.2 = true

/-- Raw source-column projection for the pin row being copied. -/
def sourceCell (key : Key) : String → Cell
  | "root" => .blob key.1
  | "holder" => .text key.2
  | _ => .null

def project (fields : List (String × SourceValue)) (key : Key) : Fields :=
  fields.map fun (column, value) => (column, match value with
    | .column name => sourceCell key name
    | .literal cell => cell)

/-- Raw INSERT SELECT ON CONFLICT DO NOTHING semantics. -/
def copy (host : Host) (state : State) (fields : List (String × SourceValue)) : State :=
  { state with wants := fun key =>
      if selected host key ∧ state.pins key = true then
        (state.wants key).orElse (fun _ => some (project fields key))
      else state.wants key }

/-- Raw DELETE semantics for the same selection. -/
def deletePins (host : Host) (state : State) : State :=
  { state with pins := fun key => if selected host key then false else state.pins key }

def update (state : State) (fields : Fields) : State :=
  { state with blob := fun column =>
      ((fields.find? fun field => field.1 == column).map Prod.snd).getD (state.blob column) }

/-- Only the expected raw transaction capabilities are provided. Guards check
keys, projections, relations, and conflicts, rather than guessing the policy. -/
def step (host : Host) : {A : Type} → Effects A → State → Option (A × State)
  | _, .left .begin, state => some (.ok 7, state)
  | _, .left (.commit tx), state => if tx = 7 then some (.ok (), state) else none
  | _, .left (.readRows tx relation columns equals order joins), state =>
      if tx = 7 ∧ relation = "blobs" ∧ columns = ["size"] ∧
          equals = [("root", .blob host.root)] ∧ order = [] ∧ joins = [] then
        some (.ok [[.integer host.size]], state) else none
  | _, .right (.left (.update tx selection fields)), state =>
      if tx = 7 ∧ selection = ⟨"blobs", [("root", .blob host.root)], []⟩ then
        some (.ok 1, update state fields) else none
  | _, .right (.right (.right (.left .nowNs))), state => some (.ok host.now, state)
  | _, .right (.left (.copyRows tx target source fields conflicts)), state =>
      if tx = 7 ∧ target = "content_want" ∧ source = repairPins host.root ∧
          conflicts = ["root", "holder"] then
        some (.ok 1, copy host state fields) else none
  | _, .right (.left (.delete tx selection)), state =>
      if tx = 7 ∧ selection = repairPins host.root then
        some (.ok 1, deletePins host state) else none
  | _, _, _ => none

def execute (host : Host) : Program Effects A → State → Option (A × State)
  | .pure value, state => some (value, state)
  | .request effect resume, state => do
      let (reply, state) ← step host effect state
      execute host (resume reply) state

/-- The exact new request fields come from the executable program. -/
def repairFields (host : Host) : List (String × SourceValue) :=
  [("root", .column "root"), ("holder", .column "holder"),
   ("size", .literal (.integer host.size)), ("prev", .literal .null),
   ("first_wanted", .literal (.integer host.now))]

def invalidation : Fields :=
  [("complete", .integer 0), ("durable", .integer 0), ("bitmap", .null), ("inline", .null)]

/-- Bridge from the actual whole operation to persistent state, for every
initial pin/want map, root, size, timestamp and SQL matching predicate. -/
theorem healing_state (host : Host) (state : State) :
    execute host (heal host.root).run state =
      some (.ok (), deletePins host (copy host (update state invalidation) (repairFields host))) := by
  simp [heal, healIn, transactionOver, requestStorage, requestAccess, requestClock,
    raise, performOver, Inject.inject, execute, step, decodeSize, integerField,
    VerifiedCore.Cas.Codec.integerField, repairFields, invalidation, Except.mapError,
    Except.map, bind, pure, Program.bind, ExceptT.bind, ExceptT.bindCont, ExceptT.pure,
    ExceptT.run, ExceptT.mk]

/-- Responsibility may be represented by possession or by a repair request. -/
def obligation (state : State) (key : Key) : Prop :=
  state.pins key = true ∨ (state.wants key).isSome = true

/-- Losing a copy does not erase the responsibility to keep it. -/
theorem losing_a_copy_preserves_responsibility (host : Host) (before after : State)
    (healed : execute host (heal host.root).run before = some (.ok (), after)) :
    ∀ key, obligation after key ↔ obligation before key := by
  rw [healing_state] at healed
  cases healed
  intro key
  unfold obligation deletePins copy update
  by_cases likeMatch : selected host key <;> cases pin : before.pins key <;>
    cases want : before.wants key <;> simp [likeMatch, pin, want]

/-- Existing repair requests retain every field, including time and predecessor. -/
theorem existing_requests_survive_unchanged (host : Host) (before after : State)
    (healed : execute host (heal host.root).run before = some (.ok (), after))
    (key : Key) (fields : Fields) (present : before.wants key = some fields) :
    after.wants key = some fields := by
  rw [healing_state] at healed
  cases healed
  simp [deletePins, copy, update, present]

/-- Healing cannot touch another object's pins or requests. -/
theorem other_objects_keep_their_claims (host : Host) (before after : State)
    (healed : execute host (heal host.root).run before = some (.ok (), after))
    (key : Key) (other : key.1 ≠ host.root) :
    after.pins key = before.pins key ∧ after.wants key = before.wants key := by
  rw [healing_state] at healed
  cases healed
  simp [deletePins, copy, update, selected, other]

/-- Healing retracts every local availability claim. -/
theorem losing_a_copy_retracts_availability (host : Host) (before after : State)
    (healed : execute host (heal host.root).run before = some (.ok (), after)) :
    after.blob "complete" = .integer 0 ∧ after.blob "durable" = .integer 0 ∧
    after.blob "bitmap" = .null ∧ after.blob "inline" = .null := by
  rw [healing_state] at healed
  cases healed
  simp [deletePins, copy, update, invalidation]

private theorem state_ext (left right : State) (blob : left.blob = right.blob)
    (pins : left.pins = right.pins) (wants : left.wants = right.wants) : left = right := by
  cases left
  cases right
  simp_all

/-- A second repair has nothing left to transfer. Even a new clock value
cannot replace the repair requests created by the first repair. -/
theorem repeated_healing_changes_nothing (host : Host) (state : State) (later : Int64) :
    let once := deletePins host (copy host (update state invalidation) (repairFields host))
    execute { host with now := later } (heal host.root).run once = some (.ok (), once) := by
  dsimp only
  rw [healing_state]
  apply congrArg (fun state => some (Except.ok (), state))
  apply state_ext
  · funext column
    simp only [deletePins, copy, update]
    cases invalidation.find? (fun field => field.1 == column) <;> simp
  · funext key
    by_cases chosen : selected host key <;> simp [deletePins, copy, update, selected] at chosen ⊢ <;>
      simp_all
  · funext key
    by_cases chosen : selected host key <;>
      simp [deletePins, copy, update, selected] at chosen ⊢ <;> simp_all

end
end Synchronicity.CasHealingPromises
