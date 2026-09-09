import VerifiedCore.Trie.Complete
import VerifiedCore.Trie.ScopeCheck
import Synchronicity.PrivateDatabase

/-! The actual missing/completeness walk reads metadata; it does not mutate
head rows or manage the caller's transaction. Memo operations are separate. -/
namespace Synchronicity.TrieReadEffects
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie PrivateDatabase

def storageRead : Storage A → Prop
  | .readRows .. | .scanRows .. | .existsRows .. | .readCounter .. | .readBytes .. | .readInput .. => True
  | _ => False

def accessRead : Access A → Prop
  | .snapshot .. | .snapshotExcluding .. => True
  | _ => False

def missingRead (A : Type) : Missing.Effects A → Prop
  | .left effect => storageRead effect
  | .right (.left effect) => accessRead effect
  | .right (.right _) => True

theorem row_present (relation : String) (fields : Fields) :
    Only missingRead (Missing.rowPresent relation fields).run := by
  unfold Missing.rowPresent
  refine Only.seq (Only.raise _ _ trivial) fun scan => ?_
  repeat' first | exact .done _ | split

theorem load_owned (owner : Option String) (hash : ByteArray) :
    Only missingRead (Missing.loadOwned owner hash).run := by
  unfold Missing.loadOwned
  cases owner with
  | none => exact Only.raise _ _ trivial
  | some origin =>
    refine (row_present _ _).seq fun owned => ?_
    split
    · exact .done _
    · exact Only.raise _ _ trivial

theorem value_absent (node : Node) (hash : ByteArray) :
    Only missingRead (Missing.valueAbsent node hash).run := by
  unfold Missing.valueAbsent
  refine Only.seq (Only.raise _ _ trivial) fun answer => ?_
  repeat' first | exact .done _ | split

theorem inspect_values_aux (node : Node) (addresses : List ByteArray) :
    Only missingRead (Missing.inspectValuesAux node addresses).run := by
  induction addresses with
  | nil => exact .done _
  | cons address rest ih =>
    simp only [Missing.inspectValuesAux]
    refine Only.seq (value_absent node address) fun _ => ?_
    refine Only.seq ih fun _ => .done _

theorem inspect_values (context : Missing.Context) (position : Missing.Position) (node : Node) :
    Only missingRead (Missing.inspectValues context position node).run := by
  unfold Missing.inspectValues
  split
  · exact inspect_values_aux node node.valueHashes
  · exact .done _

set_option maxHeartbeats 2000000 in
theorem inspect_pending_branch (node : Node) :
    Only missingRead (Missing.inspectPendingBranch node).run := by
  unfold Missing.inspectPendingBranch
  repeat' first
    | exact .done _
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | (refine Only.seq (.done _) fun _ => ?_)
    | contradiction
    | (dsimp only; split)
    | split

theorem inspect_reference (reference : Option ByteArray) :
    Only missingRead (Missing.inspectReference reference).run := by
  unfold Missing.inspectReference
  repeat' first
    | exact .done _
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | (refine Only.seq (.done _) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem validate_node_depth (position : Missing.Position) (node : Node) :
    Only missingRead (Missing.validateNodeDepth position node).run := by
  cases node with
  | leaf suffix value => simp only [Missing.validateNodeDepth]; split <;> exact .done _
  | extension | branch | route => exact .done _

theorem prepare_decoded [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (frontier : Missing.Frontier V H) (position : Missing.Position) (node : Node) :
    Only missingRead (Missing.prepareDecoded frontier position node).run := by
  unfold Missing.prepareDecoded
  repeat' first
    | exact .done _
    | (refine Only.seq (inspect_pending_branch _) fun _ => ?_)
    | (refine Only.seq (inspect_reference _) fun _ => ?_)
    | (refine Only.seq (validate_node_depth _ _) fun _ => ?_)
    | contradiction
    | (dsimp only; split)
    | split

theorem prepare_loaded [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (frontier : Missing.Frontier V H) (position : Missing.Position) (raw : ByteArray) :
    Only missingRead (Missing.prepareLoaded frontier position raw).run := by
  unfold Missing.prepareLoaded
  refine Only.seq (.done _) fun node => prepare_decoded _ _ node

theorem inspect_loaded [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (frontier : Missing.Frontier V H)
    (position : Missing.Position) (raw : ByteArray) :
    Only missingRead (Missing.inspectLoaded context frontier position raw).run := by
  unfold Missing.inspectLoaded
  refine Only.seq (prepare_loaded _ _ _) fun prepared => ?_
  refine Only.seq (inspect_values _ _ _) fun _ => .done _

set_option maxHeartbeats 2000000 in
theorem inspect [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (frontier : Missing.Frontier V H) (position : Missing.Position) :
    Only missingRead (Missing.inspect context frontier position).run := by
  unfold Missing.inspect
  repeat' first
    | exact .done _
    | (refine Only.seq (load_owned _ _) fun _ => ?_)
    | (refine Only.seq (inspect_loaded _ _ _ _) fun _ => ?_)
    | contradiction
    | (dsimp only; split)
    | split

theorem batch_step [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (maximum : Nat) (work : Missing.Work V H) :
    Only missingRead (Missing.batchStep context maximum work).run := by
  unfold Missing.batchStep
  repeat' first
    | exact .done _
    | (refine Only.bind (inspect _ _ _) fun _ => .done _)
    | split

theorem nextBatch [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (frontier : Missing.Frontier V H) (maximum : Nat) :
    Only missingRead (Missing.nextBatch context frontier maximum).run :=
  Only.iterate _ _ _ (fun _ => batch_step _ _ _) _

def completeRead (A : Type) : Complete.Effects A → Prop
  | .left effect => missingRead _ effect
  | .right _ => True

theorem key (scope : Serve.Scope) (root : ByteArray) (owner : Option String) :
    Only completeRead (Memo.keyFor (E := Complete.Effects) Missing.Error.host scope root owner).run := by
  unfold Memo.keyFor
  refine Only.seq ?_ fun key => ?_
  · unfold Memo.scopedKey
    cases scope.prefixes with
    | none => exact .done _
    | some _ => exact Only.raise _ _ trivial
  · cases owner with
    | none => exact .done _
    | some _ => exact Only.raise _ _ trivial

theorem inspectRoot (V H : Type) [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (root : ByteArray) :
    Only completeRead (Complete.inspectRoot V H context root).run := by
  apply (nextBatch _ _ _).mapEffects
  intro B effect good
  cases effect with
  | left _ => exact good
  | right effect => cases effect <;> exact good

theorem recheck (V H : Type) [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (root key : ByteArray) :
    Only completeRead (Complete.recheck V H context root key).run := by
  unfold Complete.recheck
  refine Only.seq (Only.raise _ _ trivial) fun generation => ?_
  refine (inspectRoot _ _ _ _).seq fun inspected => ?_
  obtain ⟨frontier, result⟩ := inspected
  cases result with
  | error _ => exact .done _
  | ok _ =>
    dsimp only
    split
    · exact Only.raise Missing.Error.host (Host.Memo.certify key generation) trivial
    · exact .done _

theorem isComplete (V H : Type) [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (root : ByteArray) :
    Only completeRead (Complete.isComplete V H context root).run := by
  unfold Complete.isComplete
  refine (key _ _ _).seq fun key => ?_
  refine Only.seq (Only.raise _ _ trivial) fun known => ?_
  split
  · exact .done _
  · exact recheck _ _ _ _ _

def walkRead (A : Type) : Walk.Effects A → Prop
  | .left effect => storageRead effect
  | .right _ => True

open Walk in
theorem cursorAt (root : Option ByteArray) :
    Only walkRead (Walk.cursorAt (E := Walk.Effects) root).run := by
  unfold Walk.cursorAt
  repeat' first
    | exact .done _
    | (refine Only.seq (Only.raise _ _ trivial) fun _ => ?_)
    | split

theorem cursorChild (cursor : Walk.Cursor) (nibble : UInt8) :
    Only walkRead (Walk.cursorChild (E := Walk.Effects) cursor nibble).run := by
  unfold Walk.cursorChild
  repeat' first | exact .done _ | exact cursorAt _ | split

theorem scope_inspect (scope : Serve.Scope) (cursor : Walk.Cursor) (path : Walk.Path) :
    Only walkRead (ScopeCheck.inspect scope cursor path).run := by
  unfold ScopeCheck.inspect
  repeat' first | exact .done _ | split

theorem scope_step (scope : Serve.Scope) (acc : Option ByteArray) (cursor : Walk.Cursor)
    (nibble : UInt8) (path : Walk.Path) :
    Only walkRead (ScopeCheck.step scope acc cursor nibble path).run := by
  unfold ScopeCheck.step
  repeat' first
    | exact .done _
    | exact scope_inspect ..
    | (refine Only.seq (cursorChild _ _) fun _ => ?_)
    | split

theorem scope_walk (scope : Serve.Scope) (cursor : Walk.Cursor) (path : Walk.Path) (acc : Option ByteArray) :
    Only walkRead (Walk.walk Walk.Cursor.nextChild (ScopeCheck.step scope) cursor path acc).run := by
  apply Only.iterate
  intro state
  unfold Walk.descend
  repeat' first
    | exact .done _
    | (refine Only.seq (scope_step ..) fun _ => ?_)
    | (dsimp only; split)
    | split

theorem firstOutside (root : ByteArray) (scope : Serve.Scope) :
    Only walkRead (ScopeCheck.firstOutside root scope).run := by
  unfold ScopeCheck.firstOutside
  split
  · exact .done _
  · refine (cursorAt _).seq fun cursor => ?_
    refine (scope_inspect ..).seq fun result => ?_
    obtain ⟨decision, answer⟩ := result
    cases decision with
    | descend cursor => exact scope_walk ..
    | skip => exact .done _
    | stop => exact .done _
    | visited => exact .done _

end Synchronicity.TrieReadEffects
