import Synchronicity.TableInvariant
import Synchronicity.TrieFetchSuspensionProofs
import Synchronicity.MptsyncStableTail

/-! Actual trie requesting, touching and abandonment do not modify the
materialized payload/retention tables, including at arbitrary resumptions. -/
namespace Synchronicity.FetchPayloadFrame
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie SimulatedHost PrivateDatabase

def Allowed (relation : String) (A : Type) : Fetch.Effects A → Prop
  | .left (.left effect) => TableInvariant.StorageAllowed relation effect
  | .left (.right (.left effect)) => TableInvariant.AccessAllowed relation effect
  | _ => True

theorem effects (relation : String) (baseline : List Fields) (effect : Fetch.Effects A)
    (safe : Allowed relation _ effect) : TableInvariant.EffectSafe relation baseline effect := by
  intro state initial
  cases effect with
  | left effect =>
    cases effect with
    | left effect => exact TableInvariant.storage_safe relation baseline effect safe state initial
    | right effect =>
      cases effect with
      | left effect => exact TableInvariant.access_safe relation baseline effect safe state initial
      | right effect =>
        cases effect <;> exact TableInvariant.reply_holds relation baseline state _ _ _
          (fun _ held => held) initial
  | right effect =>
    rcases effect with effect | effect
    · cases effect <;> exact TableInvariant.reply_holds relation baseline state _ _ _
        (fun _ held => held) initial
    · rcases effect with effect | effect
      · cases effect <;> exact TableInvariant.reply_holds relation baseline state _ _ _
          (fun _ held => held) initial
      · rcases effect with effect | effect
        · cases effect <;> exact TableInvariant.reply_holds relation baseline state _ _ _
            (by intro s held; split <;> simp_all) initial
        · cases effect <;> exact TableInvariant.reply_holds relation baseline state _ _ _
            (fun _ held => held) initial

theorem missing_mapped (relation : String) (tx : Transaction) (effect : Missing.Effects A)
    (safe : TrieReadEffects.missingRead _ effect) :
    Allowed relation _ (Fetch.inTransaction tx effect) := by
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right effect =>
    cases effect with
    | left effect =>
      cases effect <;> first
        | contradiction
        | trivial
        | (simp only [Fetch.inTransaction]; split <;> trivial)
    | right effect => cases effect; trivial

theorem complete_mapped (relation : String) (effect : Complete.Effects A)
    (safe : TrieReadEffects.completeRead _ effect) :
    Allowed relation _ (Inject.inject effect : Fetch.Effects A) := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => cases effect <;> first | contradiction | trivial
    | right effect =>
      cases effect with
      | left effect => cases effect <;> first | contradiction | trivial
      | right _ => trivial
  | right effect => cases effect <;> trivial

theorem key_only (relation : String) (scope : Serve.Scope) (root : ByteArray)
    (owner : Option String) :
    Only (Allowed relation) (Memo.keyFor (E := Fetch.Effects) Fetch.Error.host scope root owner).run := by
  unfold Memo.keyFor
  refine Only.seq ?_ fun key => ?_
  · unfold Memo.scopedKey
    cases scope.prefixes with
    | none => exact .done _
    | some _ => exact Only.raise _ _ trivial
  · cases owner with
    | none => exact .done _
    | some _ => exact Only.raise _ _ trivial

def VerifyRead (A : Type) : Trie.Effects A → Prop
  | .left effect => TrieReadEffects.storageRead effect
  | .right _ => True

theorem verify_only (expected bytes : ByteArray) :
    Only VerifyRead (Trie.verify expected bytes).run := by
  have hashes (tags : List ByteArray) :
      Only VerifyRead (Trie.hashesToAny expected bytes tags).run := by
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

theorem verify_within (relation : String) (hash bytes : ByteArray) :
    Only (Allowed relation)
      (within Fetch.Error.host (Trie.verify hash bytes) : Fetch.Action _).run := by
  apply Only.within _ _ (verify_only hash bytes)
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem inspect_only [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (relation : String) (target : Fetch.Target) (state : Fetch.State V H) (maximum : Nat) :
    Only (Allowed relation) (Fetch.inspect target state maximum).run := by
  unfold Fetch.inspect
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  refine Only.seq (Only.raise _ _ trivial) fun generation => ?_
  refine Only.seq ?_ fun result => ?_
  · exact ((TrieReadEffects.nextBatch _ _ _).mapEffects _ (Fetch.inTransaction tx)
      (missing_mapped relation tx)).bind fun _ => .done _
  · obtain ⟨frontier, result⟩ := result
    cases result with
    | error _ => exact .done _
    | ok batch =>
      refine Only.seq (.done _) fun batch => ?_
      split
      · refine (key_only relation _ _ _).seq fun key => ?_
        exact Only.seq (Only.raise Fetch.Error.host (Host.Memo.certify key generation) trivial)
          fun _ => .done _
      · exact Only.seq (.done _) fun _ => .done _

theorem admit_only [Missing.WorkSet ByteArray H] (relation : String)
    (nodes : Trie.nodeSpace ≠ relation) (valuesRelation : Trie.valueSpace ≠ relation)
    (origins : "trie_node_origins" ≠ relation) (target : Fetch.Target) (values : Bool)
    (requested served : List (ByteArray × ByteArray)) (routeValues : List ByteArray) :
    Only (Allowed relation) (Fetch.admit (H := H) target values requested served routeValues).run := by
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
          · exact Only.seq (Only.raise _ _ valuesRelation) fun _ => .done _
          · exact .done _
      · refine (verify_within relation hash bytes).seq fun verdict => ?_
        cases verdict with
        | peerFault => exact .done _
        | originFault _ => exact .done _
        | accepted =>
          refine Only.seq (Only.raise _ _ nodes) fun _ => ?_
          cases target.context.owner with
          | none => exact .done _
          | some _ => exact Only.seq (Only.raise _ _ origins) fun _ => .done _
  · intro _; exact .done _

theorem touch_only (relation : String) (heads : "heads" ≠ relation)
    (target : Fetch.Target) : Only (Allowed relation) (Fetch.touch target).run := by
  unfold Fetch.touch
  refine Only.seq (Only.raise _ _ trivial) fun now => ?_
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  exact Only.seq (Only.raise _ _ heads) fun _ => .done _

theorem abandon_only (relation : String) (heads : "heads" ≠ relation)
    (target : Fetch.Target) : Only (Allowed relation) (Fetch.abandon target).run := by
  unfold Fetch.abandon
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  exact Only.seq (Only.raise _ _ heads) fun _ => .done _

theorem step_only [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (relation : String) (heads : "heads" ≠ relation) (nodes : Trie.nodeSpace ≠ relation)
    (valuesRelation : Trie.valueSpace ≠ relation) (origins : "trie_node_origins" ≠ relation)
    (target : Fetch.Target) (maximum retryLimit : Nat) (state : Fetch.State V H) :
    Only (Allowed relation) (Fetch.step target maximum retryLimit state).run := by
  unfold Fetch.step
  refine (inspect_only relation target state maximum).seq fun inspected => ?_
  obtain ⟨state, missing, certified⟩ := inspected
  dsimp only
  repeat' first
    | exact .done _
    | (refine Only.seq (admit_only relation nodes valuesRelation origins _ _ _ _ _) fun _ => ?_)
    | (refine Only.seq (touch_only relation heads target) fun _ => ?_)
    | (refine Only.seq (abandon_only relation heads target) fun _ => ?_)
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | split

theorem fetch_only (V H : Type) [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (relation : String) (heads : "heads" ≠ relation) (nodes : Trie.nodeSpace ≠ relation)
    (valuesRelation : Trie.valueSpace ≠ relation) (origins : "trie_node_origins" ≠ relation)
    (target : Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat) :
    Only (Allowed relation) (Fetch.fetch V H target reference maximum retryLimit).run := by
  unfold Fetch.fetch
  refine Only.seq (Only.raise _ _ trivial) fun generation => ?_
  have loop (reference : Option ByteArray) :
      Only (Allowed relation) (OperationOver.iterate
        (Fetch.step (V := V) (H := H) target maximum retryLimit) Fetch.Error.exhausted
        Missing.batchFuel ⟨Missing.initial target.context reference target.root, generation, 0, 0⟩).run :=
    Only.iterate _ _ _
      (fun state => step_only relation heads nodes valuesRelation origins target maximum retryLimit state) _
  cases reference with
  | none => exact Only.seq (.done _) loop
  | some root =>
    refine Only.seq ?_ fun complete => ?_
    · exact Only.within _ _ (TrieReadEffects.isComplete V H target.context root)
        (complete_mapped relation)
    · split <;> exact Only.seq (.done _) loop

theorem request_relation (relation : String) (heads : "heads" ≠ relation)
    (nodes : Trie.nodeSpace ≠ relation) (valuesRelation : Trie.valueSpace ≠ relation)
    (origins : "trie_node_origins" ≠ relation)
    (target : Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat)
    (continuation rest : Program Fetch.Effects (Except Fetch.Error Bool))
    (reachable : Continuation (Fetch.fetch (Std.HashSet Missing.Visit)
      (Std.HashSet ByteArray) target reference maximum retryLimit).run continuation)
    (state final : State) (closed : state.pending = none)
    (path : Prefix continuation state rest final) :
    rows final.db relation = rows state.db relation := by
  exact TableInvariant.prefix_rows relation
    (Fetch.fetch (Std.HashSet Missing.Visit) (Std.HashSet ByteArray)
      target reference maximum retryLimit).run rest
    ((fetch_only _ _ relation heads nodes valuesRelation origins target reference maximum retryLimit).mono
      (fun effect good baseline => effects relation baseline effect good))
    reachable state final closed path

theorem request_payload (target : Fetch.Target) (reference : Option ByteArray)
    (maximum retryLimit : Nat)
    (continuation rest : Program Fetch.Effects (Except Fetch.Error Bool))
    (reachable : Continuation (Fetch.fetch (Std.HashSet Missing.Visit)
      (Std.HashSet ByteArray) target reference maximum retryLimit).run continuation)
    (state final : State) (closed : state.pending = none)
    (path : Prefix continuation state rest final) :
    MptsyncStableTail.PayloadFrame state.db final.db := by
  have framed (relation : String) (heads : "heads" ≠ relation)
      (nodes : Trie.nodeSpace ≠ relation) (valuesRelation : Trie.valueSpace ≠ relation)
      (origins : "trie_node_origins" ≠ relation) :=
    request_relation relation heads nodes valuesRelation origins target reference maximum retryLimit
      continuation rest reachable state final closed path
  exact ⟨framed "entries" (by decide) (by decide) (by decide) (by decide),
    framed "pins" (by decide) (by decide) (by decide) (by decide),
    framed "content_want" (by decide) (by decide) (by decide) (by decide)⟩

end Synchronicity.FetchPayloadFrame
