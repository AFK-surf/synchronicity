import Synchronicity.ReconciliationReadOnly
import Synchronicity.TransactionFailure
import VerifiedCore.Replication.ScopeChange

/-! Failure atomicity of the production whole-domain permission change.

All destructive decisions execute in the one transaction opened by
`ScopeChange.change`.  This proof includes malformed joined heads and arbitrary
host, commit and rollback failures; none can expose only part of the changed
scope, cleared derived view and requeued head set. -/
namespace Synchronicity.ScopeChangeAtomicity
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
open SimulatedHost PrivateDatabase

def allowed (A : Type) : History.Effects A → Prop
  | .left effect => storagePrivate effect
  | .right _ => True

theorem effects_db (effect : History.Effects A) (safe : allowed _ effect) (state : State) :
    (Interpreter.handle effect state).2.db = state.db := by
  cases effect with
  | left effect => exact storage_preserves_db effect safe state
  | right effect => cases effect <;> apply reply_preserves_db <;> intro s <;> rfl

theorem request_private (effect : Storage (Reply A)) (safe : storagePrivate effect) :
    Only allowed (History.request effect).run :=
  Only.raise History.Error.host effect safe

theorem read_only_private (operation : OperationOver History.Effects ε A)
    (safe : Only ReconciliationReadOnly.allowed operation.run) : Only allowed operation.run := by
  apply safe.mono
  intro B effect good
  cases effect with
  | left effect => cases effect <;> first | contradiction | trivial
  | right _ => trivial

theorem auth_private (operation : Authorization.Action A)
    (safe : Only ReconciliationReadOnly.allowed operation.run) :
    Only allowed (within Reconcile.authorizationError operation : History.Action A).run := by
  apply Only.within _ _ (read_only_private operation safe)
  intro B effect good
  cases effect <;> exact good

theorem decodeStored_private (row : Row) :
    Only allowed (ScopeChange.decodeStored row).run := by
  unfold ScopeChange.decodeStored
  refine (read_only_private _ (ReconciliationReadOnly.decodeJoinedHead_only row)).seq fun _ => ?_
  split <;> exact .done _

theorem allSlot_private (tx : Transaction) (slot : String) :
    Only allowed (ScopeChange.allSlot tx slot).run := by
  unfold ScopeChange.allSlot
  refine Only.seq (request_private _ trivial) fun scan => ?_
  refine (Only.mapM _ _ decodeStored_private).seq fun _ => ?_
  split <;> exact .done _

theorem writeScope_private (tx : Transaction) (spaces : Option (List String)) :
    Only allowed (ScopeChange.writeScope tx spaces).run := by
  cases spaces with
  | none =>
    simp only [ScopeChange.writeScope]
    exact (request_private (.deleteRows tx "config" [("key", .text "local_scope")]) trivial).seq fun _ => .done _
  | some spaces =>
    simp only [ScopeChange.writeScope]
    exact request_private (.upsert tx "config"
      [("key", .text "local_scope"), ("value", .text (ScopeChange.encodeSpaces spaces))]
      ["key"] ["value"]) trivial

theorem eraseDerived_private (tx : Transaction) (origin : String) :
    Only allowed (ScopeChange.eraseDerived tx origin).run := by
  unfold ScopeChange.eraseDerived
  exact (request_private (.deleteRows tx "entries" [("origin_id", .text origin)]) trivial).seq fun _ =>
    (request_private (.deleteRows tx "blob_providers" [("origin_id", .text origin)]) trivial).seq fun _ =>
    (request_private (.deleteRows tx "bindings"
      [("source", .text "delegated"), ("issuer", .text origin)]) trivial).seq fun _ => .done _

theorem writePending_private (tx : Transaction) (head : ScopeChange.Stored) (now : Int64) :
    Only allowed (ScopeChange.writePending tx head now).run := by
  unfold ScopeChange.writePending
  exact request_private _ trivial

theorem demote_private (tx : Transaction) (decision : ScopeChange.Demotion) (now : Int64) :
    Only allowed (ScopeChange.demote tx decision now).run := by
  unfold ScopeChange.demote
  refine (eraseDerived_private tx decision.complete.origin).seq fun _ => ?_
  refine (request_private (.deleteRows tx "heads"
    [("origin_id", .text decision.complete.origin), ("slot", .text "pending")]) trivial).seq fun _ => ?_
  refine (writePending_private tx decision.selectedStored now).seq fun _ => ?_
  exact (request_private (.deleteRows tx "heads"
    [("origin_id", .text decision.complete.origin), ("slot", .text "complete")]) trivial).seq fun _ => .done _

theorem refreshPending_private (tx : Transaction) (own : Option String)
    (demotions : List ScopeChange.Demotion) (head : ScopeChange.Stored) (now : Int64) :
    Only allowed (ScopeChange.refreshPending tx own demotions head now).run := by
  unfold ScopeChange.refreshPending
  split
  · exact .done _
  · exact (request_private (.deleteRows tx "heads"
      [("origin_id", .text head.origin), ("slot", .text "pending")]) trivial).seq fun _ =>
      writePending_private tx head now

theorem demoteAll_private (tx : Transaction) (now : Int64)
    (demotions : List ScopeChange.Demotion) :
    Only allowed (ScopeChange.demoteAll tx now demotions).run := by
  induction demotions with
  | nil => exact .done _
  | cons decision rest ih =>
    exact (demote_private tx decision now).seq fun _ => ih

theorem refreshAll_private (tx : Transaction) (own : Option String)
    (demotions : List ScopeChange.Demotion) (now : Int64) (pending : List ScopeChange.Stored) :
    Only allowed (ScopeChange.refreshAll tx own demotions now pending).run := by
  induction pending with
  | nil => exact .done _
  | cons head rest ih =>
    exact (refreshPending_private tx own demotions head now).seq fun _ => ih

theorem verifyAbsent_private (tx : Transaction) (relation : String) (fields : Fields) :
    Only allowed (ScopeChange.verifyAbsent tx relation fields).run := by
  unfold ScopeChange.verifyAbsent
  exact (request_private (.existsRows tx relation fields) trivial).seq fun found => by
    split <;> exact .done _

theorem verifyDemotion_private (tx : Transaction)
    (decision : ScopeChange.Demotion) (now : Int64) :
    Only allowed (ScopeChange.verifyDemotion tx decision now).run := by
  unfold ScopeChange.verifyDemotion
  refine (request_private (.readRows tx "heads"
    ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
    [("origin_id", .text decision.complete.origin), ("slot", .text "complete")] [] []) trivial).seq
      fun complete => ?_
  split
  · exact .done _
  · refine (request_private (.readRows tx "heads"
      ["origin_id", "slot", "seq", "root", "received_at", "verified_at"]
      [("origin_id", .text decision.complete.origin), ("slot", .text "pending")] [] []) trivial).seq
        fun pending => ?_
    split
    · exact .done _
    · exact (verifyAbsent_private tx "entries" _).seq fun _ =>
        (verifyAbsent_private tx "blob_providers" _).seq fun _ =>
        verifyAbsent_private tx "bindings" _

theorem verifyDemotions_private (tx : Transaction) (now : Int64)
    (demotions : List ScopeChange.Demotion) :
    Only allowed (ScopeChange.verifyDemotions tx now demotions).run := by
  induction demotions with
  | nil => exact .done _
  | cons decision rest ih =>
    exact (verifyDemotion_private tx decision now).seq fun _ => ih

theorem verifyAll_private (tx : Transaction) (now : Int64)
    (demotions : List ScopeChange.Demotion) :
    Only allowed (ScopeChange.verifyAll tx now demotions).run := by
  unfold ScopeChange.verifyAll
  exact (verifyAbsent_private tx "redacted_nodes" []).seq fun _ =>
    verifyDemotions_private tx now demotions

theorem body_private (tx : Transaction) (next : Option (List String)) (now : Int64) :
    Only allowed (do
      let current ← within Reconcile.authorizationError
        (Authorization.localSpacesIn tx)
      if current == next then return ⟨false, []⟩
      let own ← within Reconcile.authorizationError (Authorization.ownOrigin tx)
      let own := own.map Origin.canonical
      let complete ← ScopeChange.allSlot tx "complete"
      let pending ← ScopeChange.allSlot tx "pending"
      let demotions := complete.filterMap (ScopeChange.decision own pending)
      ScopeChange.writeScope tx next
      let _ ← History.request (.deleteRows tx "redacted_nodes" [])
      ScopeChange.demoteAll tx now demotions
      ScopeChange.refreshAll tx own demotions now pending
      ScopeChange.verifyAll tx now demotions
      return ⟨true, demotions⟩ : History.Action ScopeChange.ChangeReport).run := by
  refine (auth_private _ (ReconciliationReadOnly.localSpaces_only tx)).seq fun current => ?_
  split
  · exact .done _
  · refine (auth_private _ (ReconciliationReadOnly.ownOrigin_only tx)).seq fun own => ?_
    refine (allSlot_private tx "complete").seq fun complete => ?_
    refine (allSlot_private tx "pending").seq fun pending => ?_
    refine (writeScope_private tx next).seq fun _ => ?_
    refine (request_private (.deleteRows tx "redacted_nodes" []) trivial).seq fun _ => ?_
    let demotions := complete.filterMap (ScopeChange.decision (own.map Origin.canonical) pending)
    exact (demoteAll_private tx now demotions).seq fun _ =>
      (refreshAll_private tx (own.map Origin.canonical) demotions now pending).seq fun _ =>
      (verifyAll_private tx now demotions).seq fun _ => .done _

/-- Any failed production scope change leaves the committed database byte-for-
byte unchanged. No successful-result or healthy-rollback premise is required. -/
theorem failure_preserves_committed_database (next : Option (List String)) (now : Int64)
    (state : State) (failure : History.Error)
    (failed : (execute (ScopeChange.change next now) state).1 = .error failure) :
    (execute (ScopeChange.change next now) state).2.db = state.db := by
  unfold ScopeChange.change at failed ⊢
  simp only [Functor.map, ExceptT.map, ExceptT.mk, bind, execute_bind] at failed ⊢
  generalize detailed : execute (ScopeChange.changeDetailed next now) state = result at failed ⊢
  obtain ⟨answer, final⟩ := result
  cases answer with
  | error error =>
    have same : error = failure := Except.error.inj failed
    subst error
    change final.db = state.db
    unfold ScopeChange.changeDetailed at detailed
    have bodyKeeps : ∀ tx initial,
        (execute (do
          let current ← within Reconcile.authorizationError
            (Authorization.localSpacesIn tx)
          if current == next then return ⟨false, []⟩
          let own ← within Reconcile.authorizationError (Authorization.ownOrigin tx)
          let own := own.map Origin.canonical
          let complete ← ScopeChange.allSlot tx "complete"
          let pending ← ScopeChange.allSlot tx "pending"
          let demotions := complete.filterMap (ScopeChange.decision own pending)
          ScopeChange.writeScope tx next
          let _ ← History.request (.deleteRows tx "redacted_nodes" [])
          ScopeChange.demoteAll tx now demotions
          ScopeChange.refreshAll tx own demotions now pending
          ScopeChange.verifyAll tx now demotions
          return ⟨true, demotions⟩ : History.Action ScopeChange.ChangeReport) initial).2.db = initial.db := by
      intro tx initial
      exact Only.preserves_db _ (body_private tx next now) effects_db initial
    have kept := TransactionFailure.transaction_failure Inject.inject (fun _ _ => rfl)
      History.Error.host _ bodyKeeps state failure (congrArg Prod.fst detailed)
    simpa only [detailed] using kept
  | ok report => cases failed

end Synchronicity.ScopeChangeAtomicity
