import VerifiedCore.Trie.Complete
import Synchronicity.SuspensionProofs

/-! The reference check uses the actual missing-data walk. Its reads never
open a transaction, so checking a reference cannot leave one open when the
requesting loop starts. Storage is not assumed read-only as an algebra. -/
namespace Synchronicity.TriePreflightTransactions
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie SuspensionProofs

/-- Every effect and continuation remains outside a transaction. This
also covers fuel exhaustion between effects, rather than only final replies. -/
inductive Closed (g : Guard F) : Program F A → Prop where
  | done (value : A) : Closed g (.pure value)
  | request {B : Type} {effect : F B} {resume : B → Program F A}
      (noOpen : ∀ reply, g.after effect reply false = false)
      (continuations : ∀ reply, Closed g (resume reply)) :
      Closed g (.request effect resume)

theorem Closed.pure (value : A) : Closed g (Program.pure value) := .done value

theorem Closed.bind {program : Program F A} {next : A → Program F B}
    (head : Closed g program) (tail : ∀ value, Closed g (next value)) :
    Closed g (program.bind next) := by
  induction head with
  | done value => exact tail value
  | request noOpen replies ih => exact .request noOpen ih

theorem Closed.balanced (closed : Closed g program) :
    Balanced g false program (fun _ isOpen => isOpen = false) := by
  induction closed with
  | done _ => exact .pure rfl
  | request noOpen replies ih =>
    refine .request (fun _ => rfl) fun reply => ?_
    simpa only [noOpen] using ih reply

theorem Closed.seq {operation : OperationOver F ε A} {next : A → OperationOver F ε B}
    (head : Closed g operation.run) (tail : ∀ value, Closed g (next value).run) :
    Closed g (operation >>= next).run := by
  refine Closed.bind head fun result => ?_
  cases result with
  | error _ => exact Closed.pure _
  | ok value => exact tail value

theorem Closed.raise {F : Type → Type} {g : Guard F} [Inject E F] (error : Failure → ε) (effect : E (Reply A))
    (noBegin : g.opens (Inject.inject effect) = none) : Closed g (raise (F := F) error effect).run := by
  refine .request ?_ fun reply => .done _
  intro reply
  simp only [Guard.after, noBegin]
  cases g.closes (Inject.inject effect) <;> simp

theorem Closed.filterM (items : List A) (predicate : A → OperationOver F ε Bool)
    (closed : ∀ item, Closed g (predicate item).run) : Closed g (items.filterM predicate).run := by
  have aux (items acc : List A) : Closed g (List.filterAuxM predicate items acc).run := by
    induction items generalizing acc with
    | nil => exact Closed.pure _
    | cons item rest ih =>
      exact Closed.seq (closed item) fun keep => ih _
  exact Closed.seq (aux items []) fun kept => Closed.pure _

theorem Closed.mapEffects {E F : Type → Type} {source : Guard E} {target : Guard F} {program : Program E A} (closed : Closed source program)
    (inject : {B : Type} → E B → F B)
    (after : ∀ {B} (effect : E B) reply,
      target.after (inject effect) reply false = source.after effect reply false) :
    Closed target (program.mapEffects inject) := by
  induction closed with
  | done value => exact .done value
  | request noOpen replies ih =>
    exact .request (by intro reply; rw [after]; exact noOpen reply) ih

theorem Closed.iterate (body : S → OperationOver F ε (S ⊕ R)) (exhausted : ε) (fuel : Nat)
    (start : S) (closed : ∀ state, Closed g (body state).run) :
    Closed g (OperationOver.iterate body exhausted fuel start).run := by
  have loop (fuel : Nat) (program : Program F (Except ε (S ⊕ R)))
      (safe : Closed g program) :
      Closed g (Program.iterate (fun state => (body state).run) exhausted fuel program) := by
    induction fuel generalizing program with
    | zero => exact Closed.pure _
    | succ fuel ih =>
      cases program with
      | pure result =>
        cases result with
        | error _ => exact Closed.pure _
        | ok next =>
          cases next with
          | inl state => exact ih _ (closed state)
          | inr _ => exact Closed.pure _
      | request effect resume =>
        cases safe with
        | request noOpen replies =>
          exact .request noOpen fun reply => ih _ (replies reply)
  exact loop fuel (body start).run (closed start)

def missingGuard : Guard Missing.Effects where
  opens := fun effect => match effect with
    | .left storage => opensStorage storage
    | _ => none
  closes := fun effect => match effect with
    | .left storage => closesStorage storage
    | _ => none
  suspends := fun _ => false

private theorem row_presence_closed (relation : String) (fields : Fields) :
    Closed missingGuard (Missing.rowPresent relation fields).run := by
  unfold Missing.rowPresent
  refine Closed.seq (Closed.raise _ _ rfl) fun scan => ?_
  repeat' first | exact Closed.pure _ | split

private theorem load_owned_closed (owner : Option String) (hash : ByteArray) :
    Closed missingGuard (Missing.loadOwned owner hash).run := by
  unfold Missing.loadOwned
  cases owner with
  | none => exact Closed.raise _ _ rfl
  | some origin =>
    refine Closed.seq (row_presence_closed _ _) fun owned => ?_
    split
    · exact Closed.pure _
    · exact Closed.raise _ _ rfl

private theorem value_absent_closed (node : Node) (hash : ByteArray) :
    Closed missingGuard (Missing.valueAbsent node hash).run := by
  unfold Missing.valueAbsent
  refine Closed.seq (Closed.raise _ _ rfl) fun answer => ?_
  repeat' first | exact Closed.pure _ | split

private theorem inspect_values_aux_closed (node : Node) (addresses : List ByteArray) :
    Closed missingGuard (Missing.inspectValuesAux node addresses).run := by
  induction addresses with
  | nil => exact Closed.pure _
  | cons address rest ih =>
    simp only [Missing.inspectValuesAux]
    refine Closed.seq (value_absent_closed node address) fun _ => ?_
    refine Closed.seq ih fun _ => Closed.pure _

private theorem inspect_values_closed
    (context : Missing.Context) (position : Missing.Position) (node : Node) :
    Closed missingGuard (Missing.inspectValues context position node).run := by
  unfold Missing.inspectValues
  split
  · exact inspect_values_aux_closed node node.valueHashes
  · exact Closed.pure _

set_option maxHeartbeats 2000000 in
private theorem inspect_pending_branch_closed (node : Node) :
    Closed missingGuard (Missing.inspectPendingBranch node).run := by
  unfold Missing.inspectPendingBranch
  repeat' first
    | exact Closed.pure _
    | (refine Closed.seq (Closed.raise _ _ rfl) fun _ => ?_)
    | (refine Closed.seq (Closed.pure _) fun _ => ?_)
    | contradiction
    | (dsimp only; split)
    | split

private theorem inspect_reference_closed (reference : Option ByteArray) :
    Closed missingGuard (Missing.inspectReference reference).run := by
  unfold Missing.inspectReference
  repeat' first
    | exact Closed.pure _
    | (refine Closed.seq (Closed.raise _ _ rfl) fun _ => ?_)
    | (refine Closed.seq (Closed.pure _) fun _ => ?_)
    | (dsimp only; split)
    | split

private theorem validate_node_depth_closed (position : Missing.Position) (node : Node) :
    Closed missingGuard (Missing.validateNodeDepth position node).run := by
  cases node with
  | leaf suffix value => simp only [Missing.validateNodeDepth]; split <;> exact Closed.pure _
  | extension | branch | route => exact Closed.pure _

private theorem prepare_decoded_closed
    [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (frontier : Missing.Frontier V H) (position : Missing.Position) (node : Node) :
    Closed missingGuard (Missing.prepareDecoded frontier position node).run := by
  unfold Missing.prepareDecoded
  repeat' first
    | exact Closed.pure _
    | (refine Closed.seq (inspect_pending_branch_closed _) fun _ => ?_)
    | (refine Closed.seq (inspect_reference_closed _) fun _ => ?_)
    | (refine Closed.seq (validate_node_depth_closed _ _) fun _ => ?_)
    | contradiction
    | (dsimp only; split)
    | split

private theorem prepare_loaded_closed
    [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (frontier : Missing.Frontier V H) (position : Missing.Position) (raw : ByteArray) :
    Closed missingGuard (Missing.prepareLoaded frontier position raw).run := by
  unfold Missing.prepareLoaded
  refine Closed.seq (Closed.pure _) fun node => prepare_decoded_closed _ _ node

private theorem inspect_loaded_closed
    [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (frontier : Missing.Frontier V H)
    (position : Missing.Position) (raw : ByteArray) :
    Closed missingGuard (Missing.inspectLoaded context frontier position raw).run := by
  unfold Missing.inspectLoaded
  refine Closed.seq (prepare_loaded_closed _ _ _) fun prepared => ?_
  refine Closed.seq (inspect_values_closed _ _ _) fun _ => Closed.pure _

set_option maxHeartbeats 2000000 in
private theorem inspect_closed [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (frontier : Missing.Frontier V H) (position : Missing.Position) :
    Closed missingGuard (Missing.inspect context frontier position).run := by
  unfold Missing.inspect
  repeat' first
    | exact Closed.pure _
    | (refine Closed.seq (load_owned_closed _ _) fun _ => ?_)
    | (refine Closed.seq (inspect_loaded_closed _ _ _ _) fun _ => ?_)
    | contradiction
    | (dsimp only; split)
    | split

private theorem batch_step_closed [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (context : Missing.Context) (maximum : Nat) (work : Missing.Work V H) :
    Closed missingGuard (Missing.batchStep context maximum work).run := by
  unfold Missing.batchStep
  repeat' first
    | exact Closed.pure _
    | (refine Closed.bind (inspect_closed _ _ _) fun _ => Closed.pure _)
    | split

theorem missing_walk_keeps_transaction_closed [Missing.WorkSet Missing.Visit V]
    [Missing.WorkSet ByteArray H] (context : Missing.Context) (frontier : Missing.Frontier V H)
    (maximum : Nat) : Closed missingGuard (Missing.nextBatch context frontier maximum).run := by
  exact Closed.iterate _ _ _ _ fun _ => batch_step_closed _ _ _

def completeGuard : Guard Complete.Effects where
  opens := fun effect => match effect with
    | .left (.left storage) => opensStorage storage
    | _ => none
  closes := fun effect => match effect with
    | .left (.left storage) => closesStorage storage
    | _ => none
  suspends := fun _ => false

private theorem key_closed (scope : Serve.Scope) (root : ByteArray) (owner : Option String) :
    Closed completeGuard (Memo.keyFor (E := Complete.Effects) Missing.Error.host scope root owner).run := by
  unfold Memo.keyFor
  refine Closed.seq ?_ fun key => ?_
  · unfold Memo.scopedKey
    cases scope.prefixes with
    | none => exact Closed.pure _
    | some _ => exact Closed.raise _ _ rfl
  · cases owner with
    | none => exact Closed.pure _
    | some _ => exact Closed.raise _ _ rfl

private theorem root_inspection_closed (V H : Type) [Missing.WorkSet Missing.Visit V]
    [Missing.WorkSet ByteArray H] (context : Missing.Context) (root : ByteArray) :
    Closed completeGuard (Complete.inspectRoot V H context root).run := by
  apply Closed.mapEffects (missing_walk_keeps_transaction_closed _ _ _) Inject.inject
  intro B effect reply
  cases effect with
  | left _ => rfl
  | right effect => cases effect <;> rfl

private theorem recheck_closed (V H : Type) [Missing.WorkSet Missing.Visit V]
    [Missing.WorkSet ByteArray H] (context : Missing.Context) (root key : ByteArray) :
    Closed completeGuard (Complete.recheck V H context root key).run := by
  unfold Complete.recheck
  refine Closed.seq (Closed.raise _ _ rfl) fun generation => ?_
  refine Closed.seq (root_inspection_closed _ _ _ _) fun inspected => ?_
  obtain ⟨frontier, result⟩ := inspected
  cases result with
  | error _ => exact Closed.pure _
  | ok _ =>
    dsimp only
    split
    · exact Closed.raise (g := completeGuard) Missing.Error.host (Host.Memo.certify key generation) rfl
    · exact Closed.pure _

/-- Checking any reference snapshot, including walking it and attempting
certification, never opens a transaction. The claim follows the real reads
and memo effects, and also holds if its effect budget is exhausted. -/
theorem reference_check_keeps_transaction_closed (V H : Type) [Missing.WorkSet Missing.Visit V]
    [Missing.WorkSet ByteArray H] (context : Missing.Context) (root : ByteArray) :
    Closed completeGuard (Complete.isComplete V H context root).run := by
  unfold Complete.isComplete
  refine Closed.seq (key_closed _ _ _) fun key => ?_
  refine Closed.seq (Closed.raise _ _ rfl) fun known => ?_
  split
  · exact Closed.pure _
  · exact recheck_closed _ _ _ _ _

end Synchronicity.TriePreflightTransactions
