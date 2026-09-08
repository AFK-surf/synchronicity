import VerifiedCore.Trie.Fetch
import Synchronicity.ProtectedHead
import Synchronicity.TrieReadEffects
import Synchronicity.HeadKeyFrame

/-! Every actual requesting continuation protects all rows outside its
captured pending key. All peer replies, retry counts and frontier states are
quantified over; no success or unchanged-selection snapshot is assumed. -/
namespace Synchronicity.FetchHeadSafety
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie SimulatedHost PrivateDatabase

def storageAllowed (row : Fields) : Storage A → Prop
  | .upsert _ relation _ _ _ => relation ≠ "heads"
  | effect => ProtectedHead.storageAllowed row effect

def accessAllowed (row : Fields) : Access A → Prop
  | .update _ selection values => selection.relation ≠ "heads" ∨
      (selects selection row = false ∧ ∀ field ∈ values, field.1 ∉ HeadKeyFrame.columns)
  | effect => ProtectedHead.accessAllowed row effect

theorem storage_retention (row : Fields) (effect : Storage A) (safe : storageAllowed row effect) :
    ProtectedHead.storageAllowed row effect := by
  cases effect <;> first | exact Or.inl safe | exact safe

theorem access_retention (row : Fields) (effect : Access A) (safe : accessAllowed row effect) :
    ProtectedHead.accessAllowed row effect := by
  cases effect <;> first | exact safe | exact safe.imp id And.left

theorem storage_keys (row : Fields) (effect : Storage A) (safe : storageAllowed row effect) :
    HeadKeyFrame.storageAllowed effect := by
  cases effect <;> first | exact safe | trivial

theorem access_keys (row : Fields) (effect : Access A) (safe : accessAllowed row effect) :
    HeadKeyFrame.accessAllowed effect := by
  cases effect <;> first | exact safe | exact safe.imp id And.right | trivial

def allowed (row : Fields) (A : Type) : Fetch.Effects A → Prop
  | .left (.left effect) => storageAllowed row effect
  | .left (.right (.left effect)) => accessAllowed row effect
  | _ => True

theorem effects_retain (row : Fields) (effect : Fetch.Effects A) (safe : allowed row _ effect)
    (state : SimulatedHost.State) (kept : ProtectedHead.retained row state) :
    ProtectedHead.retained row (Interpreter.handle effect state).2 := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => exact ProtectedHead.storage_retains row effect (storage_retention row effect safe) state kept
    | right effect =>
      cases effect with
      | left effect => exact ProtectedHead.access_retains row effect (access_retention row effect safe) state kept
      | right effect => cases effect; apply ProtectedHead.reply_retains _ _ _ _ _ _ kept; intro s h; exact h
  | right effect =>
    rcases effect with effect | effect
    · cases effect; apply ProtectedHead.reply_retains _ _ _ _ _ _ kept; intro s h; exact h
    · rcases effect with effect | effect
      · cases effect <;> apply ProtectedHead.reply_retains _ _ _ _ _ _ kept <;> intro s h <;> exact h
      · rcases effect with effect | effect
        · cases effect <;> apply ProtectedHead.reply_retains _ _ _ _ _ _ kept <;> intro s h <;> split <;> exact h
        · cases effect; apply ProtectedHead.reply_retains _ _ _ _ _ _ kept; intro s h; exact h

theorem missing_mapped (row : Fields) (tx : Transaction) (effect : Missing.Effects A)
    (safe : TrieReadEffects.missingRead _ effect) : allowed row _ (Fetch.inTransaction tx effect) := by
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right effect =>
    cases effect with
    | left effect =>
      cases effect <;> first | contradiction | trivial | (simp only [Fetch.inTransaction]; split <;> trivial)
    | right effect => cases effect; trivial

theorem complete_mapped (row : Fields) (effect : Complete.Effects A)
    (safe : TrieReadEffects.completeRead _ effect) : allowed row _ (Inject.inject effect) := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => cases effect <;> first | contradiction | trivial
    | right effect =>
      cases effect with
      | left effect => cases effect <;> first | contradiction | trivial
      | right _ => trivial
  | right effect => cases effect <;> trivial

theorem key_only (row : Fields) (scope : Serve.Scope) (root : ByteArray) (owner : Option String) :
    Only (allowed row) (Memo.keyFor (E := Fetch.Effects) Fetch.Error.host scope root owner).run := by
  unfold Memo.keyFor
  refine Only.seq ?_ fun key => ?_
  · unfold Memo.scopedKey
    cases scope.prefixes with
    | none => exact .done _
    | some _ => exact Only.raise _ _ trivial
  · cases owner with
    | none => exact .done _
    | some _ => exact Only.raise _ _ trivial

theorem inspect_only [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (row : Fields) (target : Fetch.Target) (state : Fetch.State V H) (maximum : Nat) :
    Only (allowed row) (Fetch.inspect target state maximum).run := by
  unfold Fetch.inspect
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  refine Only.seq (Only.raise _ _ trivial) fun generation => ?_
  refine Only.seq ?_ fun result => ?_
  · exact ((TrieReadEffects.nextBatch _ _ _).mapEffects _ (Fetch.inTransaction tx)
      (missing_mapped row tx)).bind fun _ => .done _
  · obtain ⟨frontier, result⟩ := result
    cases result with
    | error _ => exact .done _
    | ok batch =>
      refine Only.seq (.done _) fun batch => ?_
      split
      · refine (key_only row _ _ _).seq fun key => ?_
        exact Only.seq (Only.raise Fetch.Error.host (Host.Memo.certify key generation) trivial) fun _ => .done _
      · exact Only.seq (.done _) fun _ => .done _

def verifyRead (A : Type) : Trie.Effects A → Prop
  | .left effect => TrieReadEffects.storageRead effect
  | .right _ => True

theorem verify_only (expected bytes : ByteArray) : Only verifyRead (Trie.verify expected bytes).run := by
  have hashes (tags : List ByteArray) : Only verifyRead (Trie.hashesToAny expected bytes tags).run := by
    induction tags with
    | nil => exact .done _
    | cons tag rest ih =>
      refine Only.seq (Only.raise _ _ trivial) fun hash => ?_
      split
      · exact .done _
      · exact ih
  unfold Trie.verify
  split
  · exact Only.seq (Only.raise _ _ trivial) fun _ => .done _
  · exact (hashes _).seq fun _ => .done _

theorem verify_within (row : Fields) (hash bytes : ByteArray) :
    Only (allowed row) (within Fetch.Error.host (Trie.verify hash bytes) : Fetch.Action _).run := by
  apply Only.within _ _ (verify_only hash bytes)
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem admit_only [Missing.WorkSet ByteArray H] (row : Fields) (target : Fetch.Target) (values : Bool)
    (requested served : List (ByteArray × ByteArray)) (routeValues : List ByteArray) :
    Only (allowed row) (Fetch.admit (H := H) target values requested served routeValues).run := by
  unfold Fetch.admit
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  apply Only.seq
  · apply Only.forIn
    intro item accumulator
    obtain ⟨hash, bytes⟩ := item
    obtain ⟨outstanding, learned⟩ := accumulator
    dsimp only
    split
    · exact .done _
    · split
      · refine Only.seq (Only.raise _ _ trivial) fun observed => ?_
        split
        · exact .done _
        · split
          · exact Only.seq (Only.raise _ _ (by change valueSpace ≠ "heads"; decide)) fun _ => .done _
          · exact .done _
      · refine (verify_within row hash bytes).seq fun verdict => ?_
        cases verdict with
        | peerFault => exact .done _
        | originFault _ => exact .done _
        | accepted =>
          refine Only.seq (Only.raise _ _ (by change nodeSpace ≠ "heads"; decide)) fun _ => ?_
          cases target.context.owner with
          | none => exact .done _
          | some _ => exact Only.seq (Only.raise _ _ (by change "trie_node_origins" ≠ "heads"; decide)) fun _ => .done _
  · intro _; exact .done _

theorem touch_only (row : Fields) (target : Fetch.Target)
    (different : equals row (Fetch.targetRows target) = false) :
    Only (allowed row) (Fetch.touch target).run := by
  unfold Fetch.touch
  refine Only.seq (Only.raise _ _ trivial) fun now => ?_
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  refine Only.seq (Only.raise _ _ ?_) fun _ => .done _
  apply Or.inr
  constructor
  · simp [selects, different]
  · simp [HeadKeyFrame.columns]

theorem abandon_only (row : Fields) (target : Fetch.Target)
    (different : equals row (Fetch.targetRows target) = false) :
    Only (allowed row) (Fetch.abandon target).run := by
  unfold Fetch.abandon
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  exact Only.seq (Only.raise _ _ (Or.inr different)) fun _ => .done _

theorem step_only [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (row : Fields) (target : Fetch.Target) (different : equals row (Fetch.targetRows target) = false)
    (maximum retryLimit : Nat) (state : Fetch.State V H) :
    Only (allowed row) (Fetch.step target maximum retryLimit state).run := by
  unfold Fetch.step
  refine (inspect_only row target state maximum).seq fun inspected => ?_
  obtain ⟨state, missing, certified⟩ := inspected
  dsimp only
  repeat' first
    | exact .done _
    | (refine Only.seq (admit_only row _ _ _ _ _) fun _ => ?_)
    | (refine Only.seq (touch_only row target different) fun _ => ?_)
    | (refine Only.seq (abandon_only row target different) fun _ => ?_)
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | split

theorem fetch_only (V H : Type) [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (row : Fields) (target : Fetch.Target) (different : equals row (Fetch.targetRows target) = false)
    (reference : Option ByteArray) (maximum retryLimit : Nat) :
    Only (allowed row) (Fetch.fetch V H target reference maximum retryLimit).run := by
  unfold Fetch.fetch
  refine Only.seq (Only.raise _ _ trivial) fun generation => ?_
  have loop (reference : Option ByteArray) :
      Only (allowed row) (OperationOver.iterate (Fetch.step (V := V) (H := H) target maximum retryLimit)
        Fetch.Error.exhausted Missing.batchFuel
        ⟨Missing.initial target.context reference target.root, generation, 0, 0⟩).run :=
    Only.iterate _ _ _ (fun state => step_only row target different maximum retryLimit state) _
  cases reference with
  | none => exact Only.seq (.done _) loop
  | some root =>
    refine Only.seq ?_ fun complete => ?_
    · exact Only.within _ _ (TrieReadEffects.isComplete V H target.context root) (complete_mapped row)
    · split <;> exact Only.seq (.done _) loop

/-- At every resumption, every row outside the captured pending key survives
every execution prefix, even when the resumption database differs arbitrarily
from the selection database. This covers replacements at the same sequence,
other origins and complete heads, including metadata/host failures and retries.
The scheduler may apply the theorem again after each wait with the new live row. -/
theorem every_resumption_preserves (V H : Type)
    [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (target : Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat)
    (continuation rest : Program Fetch.Effects (Except Fetch.Error Bool))
    (reachable : Continuation (Fetch.fetch V H target reference maximum retryLimit).run continuation)
    (state final : SimulatedHost.State) (closed : state.pending = none)
    (path : Prefix continuation state rest final)
    (row : Fields) (present : row ∈ rows state.db "heads")
    (different : equals row (Fetch.targetRows target) = false) : row ∈ rows final.db "heads" := by
  have safe := (fetch_only V H row target different reference maximum retryLimit).continuation reachable
  exact (safe.invariant_prefix (ProtectedHead.retained row) path (effects_retain row)
    (ProtectedHead.initial row state closed present)).1

theorem effects_preserve_keys (predicate : List Cell → Prop) (row : Fields) (effect : Fetch.Effects A)
    (safe : allowed row _ effect) : HeadInvariant.effectSafe (HeadKeyFrame.allKeys predicate) _ effect := by
  intro state initial
  cases effect with
  | left effect =>
    cases effect with
    | left effect => exact HeadKeyFrame.storage_safe predicate effect (storage_keys row effect safe) state initial
    | right effect =>
      cases effect with
      | left effect => exact HeadKeyFrame.access_safe predicate effect (access_keys row effect safe) state initial
      | right effect => cases effect; apply HeadInvariant.reply_holds _ _ _ _ _ _ initial; intro s h; exact h
  | right effect =>
    rcases effect with effect | effect
    · cases effect; apply HeadInvariant.reply_holds _ _ _ _ _ _ initial; intro s h; exact h
    · rcases effect with effect | effect
      · cases effect <;> apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;> intro s h <;> exact h
      · rcases effect with effect | effect
        · cases effect <;> apply HeadInvariant.reply_holds _ _ _ _ _ _ initial <;> intro s h <;> split <;> exact h
        · cases effect; apply HeadInvariant.reply_holds _ _ _ _ _ _ initial; intro s h; exact h

/-- Even the captured target can only retain its version or disappear; a
timestamp refresh cannot turn it into an older/different head. -/
theorem every_resumption_no_new_key (V H : Type)
    [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (target : Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat)
    (continuation rest : Program Fetch.Effects (Except Fetch.Error Bool))
    (reachable : Continuation (Fetch.fetch V H target reference maximum retryLimit).run continuation)
    (state final : SimulatedHost.State) (closed : state.pending = none)
    (path : Prefix continuation state rest final) :
    ∀ row ∈ rows final.db "heads", ∃ old ∈ rows state.db "heads", HeadKeyFrame.key row = HeadKeyFrame.key old := by
  have different : equals [] (Fetch.targetRows target) = false := by
    simp [Fetch.targetRows, equals, cell, isCell, equalCell, BEq.beq, instBEqCell.beq]
  have safe := (fetch_only V H [] target different reference maximum retryLimit).continuation reachable
  let predicate := fun key => ∃ old ∈ rows state.db "heads", key = HeadKeyFrame.key old
  have initial : HeadInvariant.holds (HeadKeyFrame.allKeys predicate) state :=
    HeadInvariant.closed _ state closed (fun row member => ⟨row, member, rfl⟩)
  exact (safe.invariant_prefix (HeadInvariant.holds (HeadKeyFrame.allKeys predicate)) path
    (effects_preserve_keys predicate []) initial).1

end Synchronicity.FetchHeadSafety
