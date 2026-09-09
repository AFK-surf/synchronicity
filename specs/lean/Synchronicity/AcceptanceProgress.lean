import Synchronicity.ReconciliationAcceptance
import Synchronicity.ReconciliationFloor
import Synchronicity.AcceptanceTransition
import Synchronicity.ExchangeVersionProofs

/-! A positive execution theorem for reconciliation acceptance.  Unlike the
existing consequences of a successful acceptance, this module obtains that
success from independently inspectable host, crypto, authorization, and raw
database facts.

The first theorem deliberately covers a fresh origin: neither complete nor
pending has a stored pointer and no history signature can conflict with the
candidate.  Nonempty floors require the analogous raw joined-head decoding
conditions and are kept out of this statement rather than hidden in an
assumption that `accept` already returned `.pending`. -/
namespace Synchronicity.AcceptanceProgress
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication
open Synchronicity.SimulatedHost

/-- The concrete rooted authorization record audited by `FreshReady`.  It is
the same nine-column raw representation consumed by `Authorization.readBindings`. -/
def staticBindingRow (head : Head) (addedAt : Int64) : Fields :=
  [("origin_id", .text (Origin.canonical head.origin)),
   ("node_id", .blob head.signedBy),
   ("source", .text "static"),
   ("domain", .null),
   ("issuer", .text ""),
   ("spaces", .null),
   ("note", .null),
   ("added_at", .integer addedAt),
   ("expires_at", .null)]

/-- Independently checkable facts and actual suboperation certificates for a
fresh host. `originSyntax` and the raw relation expose the authorization input;
`authorizationExecution` certifies that the production reader decoded that
input and found the binding.  The certificate is deliberately an execution of
`liveForKey`, not a premise about the result of `Reconcile.accept` itself.

The later certificates expose history compatibility, empty complete/pending
floors, the candidate write, trimming, and commit separately.  This makes the
remaining boundary explicit until raw-row positive execution lemmas discharge
those certificates automatically. -/
structure FreshReady (state : State) (head : Head) (addedAt : Int64) where
  noOpenTransaction : state.pending = none
  noFailures : state.faults = []
  noScanFailure : state.scanFault = none
  signatureValid :
    state.verifySignature head.signedBy (Reconcile.signingInput head) head.signature = true
  signingKeyWidth : head.signedBy.size = 32
  signingKeyValid : state.validateKey head.signedBy.data.toList = true
  originSyntax : Origin.parseSyntax (Origin.canonical head.origin) = .ok head.origin
  originKeyValid : ∀ bytes, head.origin = .key bytes → state.validateKey bytes = true
  authorizationRows : rows state.db "bindings" = [staticBindingRow head addedAt]
  noClockFloor : rows state.db "config" = []
  noHeads : rows state.db "heads" = []
  noHistory : rows state.db "head_history" = []
  representableSequence : head.seq ≤ 9223372036854775807
  instant : Int64
  afterClock : State
  live : List Authorization.Binding
  afterAuthorization : State
  afterRecord : State
  afterComplete : State
  afterPending : State
  afterWrite : State
  afterTrim : State
  afterCommit : State
  clockExecution :
    execute (within Reconcile.authorizationError
      (Authorization.trustInstant state.nextTx state.now) : History.Action Int64)
      (SimulatedHost.record
        { SimulatedHost.record state "verifySignature" with
          pending := some (state.nextTx, state.db), nextTx := state.nextTx + 1 }
        "begin") = (.ok instant, afterClock)
  authorizationExecution :
    execute (within Reconcile.authorizationError
      (Authorization.liveForKey state.nextTx head.signedBy instant) :
        History.Action (List Authorization.Binding)) afterClock =
      (.ok live, afterAuthorization)
  originBound : live.any (·.origin == head.origin) = true
  recordExecution :
    execute (Reconcile.record state.nextTx head state.now) afterAuthorization =
      (.ok (), afterRecord)
  completeExecution :
    execute (History.readSlot state.nextTx (Origin.canonical head.origin) "complete") afterRecord =
      (.ok [], afterComplete)
  pendingExecution :
    execute (History.readSlot state.nextTx (Origin.canonical head.origin) "pending") afterComplete =
      (.ok [], afterPending)
  writeExecution :
    execute (Reconcile.putSlot state.nextTx "pending" head state.now state.now) afterPending =
      (.ok (), afterWrite)
  trimExecution :
    execute (Reconcile.trimForks state.nextTx (Origin.canonical head.origin) head.seq 0) afterWrite =
      (.ok (), afterTrim)
  commitExecution :
    (Interpreter.handle
      (Inject.inject (F := History.Effects) (Storage.commit state.nextTx)) afterTrim) =
      (.ok (), afterCommit)

/-- Common, independently auditable prefix of a healthy acceptance execution.
Unlike `FreshReady`, the two slot reads may expose existing backed floors. -/
structure HistoryReady (state : State) (head : Head) (keep : Nat) where
  noOpenTransaction : state.pending = none
  noFailures : state.faults = []
  signatureValid :
    state.verifySignature head.signedBy (Reconcile.signingInput head) head.signature = true
  instant : Int64
  afterClock : State
  live : List Authorization.Binding
  afterAuthorization : State
  afterRecord : State
  complete : List History.JoinedHead
  afterComplete : State
  pending : List History.JoinedHead
  afterPending : State
  clockExecution :
    execute (within Reconcile.authorizationError
      (Authorization.trustInstant state.nextTx state.now) : History.Action Int64)
      (SimulatedHost.record
        { SimulatedHost.record state "verifySignature" with
          pending := some (state.nextTx, state.db), nextTx := state.nextTx + 1 }
        "begin") = (.ok instant, afterClock)
  authorizationExecution :
    execute (within Reconcile.authorizationError
      (Authorization.liveForKey state.nextTx head.signedBy instant) :
        History.Action (List Authorization.Binding)) afterClock =
      (.ok live, afterAuthorization)
  originBound : live.any (·.origin == head.origin) = true
  recordExecution :
    execute (Reconcile.record state.nextTx head state.now) afterAuthorization =
      (.ok (), afterRecord)
  completeExecution :
    execute (History.readSlot state.nextTx (Origin.canonical head.origin) "complete") afterRecord =
      (.ok complete, afterComplete)
  pendingExecution :
    execute (History.readSlot state.nextTx (Origin.canonical head.origin) "pending") afterComplete =
      (.ok pending, afterPending)
  completeBacked : ∀ old ∈ complete,
    ReconciliationRead.StoredFloor state.db (Origin.canonical head.origin) "complete"
      old.pointer.seq.toInt64 old.pointer.root
  pendingBacked : ∀ old ∈ pending,
    ReconciliationRead.StoredFloor state.db (Origin.canonical head.origin) "pending"
      old.pointer.seq.toInt64 old.pointer.root

/-- Healthy tail certificates for a candidate strictly above every complete
and pending floor observed by the actual production reads. -/
structure NewerReady (state : State) (head : Head) (keep : Nat)
    extends HistoryReady state head keep where
  afterWrite : State
  afterTrim : State
  afterCommit : State
  aboveFloors : ∀ old ∈ complete ++ pending,
    Reconcile.newer head.seq head.root old.pointer = true
  writeExecution :
    execute (Reconcile.putSlot state.nextTx "pending" head state.now state.now) afterPending =
      (.ok (), afterWrite)
  trimExecution :
    execute (Reconcile.trimForks state.nextTx (Origin.canonical head.origin) head.seq keep) afterWrite =
      (.ok (), afterTrim)
  commitExecution :
    Interpreter.handle
      (Inject.inject (F := History.Effects) (Storage.commit state.nextTx)) afterTrim =
      (.ok (), afterCommit)

/-- Healthy tail certificates for a candidate blocked by one backed floor.
The blocker is a raw/decoded floor fact, not a premise about the command's
answer.  `accept` still records compatible history and trims the candidate's
fork set, but it cannot replace either slot. -/
structure ObsoleteReady (state : State) (head : Head) (keep : Nat)
    extends HistoryReady state head keep where
  blocker : History.JoinedHead
  blockerMember : blocker ∈ complete ++ pending
  notAbove : Reconcile.newer head.seq head.root blocker.pointer = false
  afterTrim : State
  afterCommit : State
  trimExecution :
    execute (Reconcile.trimForks state.nextTx (Origin.canonical head.origin) head.seq keep) afterPending =
      (.ok (), afterTrim)
  commitExecution :
    Interpreter.handle
      (Inject.inject (F := History.Effects) (Storage.commit state.nextTx)) afterTrim =
      (.ok (), afterCommit)

/-- A valid, rooted advertisement for a fresh origin takes the actual
`Reconcile.accept` execution through commit and returns `.pending`. -/
theorem fresh_accepts (head : Head) (addedAt : Int64) (state : State)
    (ready : FreshReady state head addedAt) :
    (execute (Reconcile.accept head state.now 0) state).1 = .ok .pending := by
  have verified :
      execute (raise History.Error.host
        (Crypto.verifyEd25519 head.signedBy (Reconcile.signingInput head) head.signature) :
          History.Action Bool) state =
        (.ok true, SimulatedHost.record state "verifySignature") := by
    simp [raise, performOver, ExceptT.mk, Except.mapError,
      Inject.inject, Interpreter.handle, execute, SimulatedHost.crypto,
      SimulatedHost.reply, SimulatedHost.fault, ready.noFailures, ready.signatureValid]
  have opened :
      Interpreter.handle (Inject.inject (F := History.Effects) Storage.begin)
        (SimulatedHost.record state "verifySignature") =
      (.ok state.nextTx,
        SimulatedHost.record
          { SimulatedHost.record state "verifySignature" with
            pending := some (state.nextTx, state.db), nextTx := state.nextTx + 1 }
          "begin") := by
    simp [Inject.inject, Interpreter.handle, SimulatedHost.storage, SimulatedHost.reply,
      SimulatedHost.fault, ready.noFailures, ready.noOpenTransaction,
      SimulatedHost.record]
  unfold Reconcile.accept
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
  rw [verified]
  dsimp only
  simp only [Bool.not_true, Bool.false_eq_true, if_false, transactionOver, ExceptT.mk,
    bind, Program.bind, execute]
  rw [opened]
  rw [execute_bind]
  dsimp only [ExceptT.run]
  rw [execute_bind]
  rw [ready.clockExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind]
  rw [ready.authorizationExecution]
  dsimp only [ExceptT.bindCont]
  simp only [ready.originBound, Bool.not_true, Bool.false_eq_true, if_false]
  rw [execute_bind]
  rw [ready.recordExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind]
  rw [ready.completeExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind]
  rw [ready.pendingExecution]
  dsimp only [ExceptT.bindCont]
  simp only [List.nil_append, List.all_nil, ↓reduceIte]
  rw [execute_bind]
  rw [ready.writeExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind]
  rw [ready.trimExecution]
  dsimp only [ExceptT.bindCont]
  have returned : execute (pure Acceptance.pending : History.Action Acceptance)
      ready.afterTrim = (.ok .pending, ready.afterTrim) := rfl
  rw [returned]
  dsimp only
  unfold execute
  rw [ready.commitExecution]
  rfl

/-- The positive execution theorem also establishes the durable observable
effect: after commit, the unique pending row for this origin points at the
candidate. -/
theorem fresh_installs_pending (head : Head) (addedAt : Int64) (state : State)
    (ready : FreshReady state head addedAt) :
    let table := rows (execute (Reconcile.accept head state.now 0) state).2.db "heads"
    (∃ row ∈ table,
      ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = true) ∧
    (∀ row ∈ table,
      ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = true →
      ReconciliationSlots.pointsTo row head) := by
  exact ReconciliationAcceptance.accepted_installs_pending head state.now 0 state
    (fresh_accepts head addedAt state ready)

/-- Existing backed floors do not weaken positive progress: if the independently
observed candidate beats all of them, the actual production command returns
`pending`. -/
theorem newer_executes (head : Head) (keep : Nat) (state : State)
    (ready : NewerReady state head keep) :
    execute (Reconcile.accept head state.now keep) state =
      (.ok .pending, ready.afterCommit) := by
  have verified :
      execute (raise History.Error.host
        (Crypto.verifyEd25519 head.signedBy (Reconcile.signingInput head) head.signature) :
          History.Action Bool) state =
        (.ok true, SimulatedHost.record state "verifySignature") := by
    simp [raise, performOver, ExceptT.mk, Except.mapError,
      Inject.inject, Interpreter.handle, execute, SimulatedHost.crypto,
      SimulatedHost.reply, SimulatedHost.fault, ready.noFailures, ready.signatureValid]
  have opened :
      Interpreter.handle (Inject.inject (F := History.Effects) Storage.begin)
        (SimulatedHost.record state "verifySignature") =
      (.ok state.nextTx,
        SimulatedHost.record
          { SimulatedHost.record state "verifySignature" with
            pending := some (state.nextTx, state.db), nextTx := state.nextTx + 1 }
          "begin") := by
    simp [Inject.inject, Interpreter.handle, SimulatedHost.storage, SimulatedHost.reply,
      SimulatedHost.fault, ready.noFailures, ready.noOpenTransaction,
      SimulatedHost.record]
  have greater : (ready.complete ++ ready.pending).all
      (fun old => Reconcile.newer head.seq head.root old.pointer) = true :=
    List.all_eq_true.mpr ready.aboveFloors
  unfold Reconcile.accept
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
  rw [verified]
  dsimp only
  simp only [Bool.not_true, Bool.false_eq_true, if_false, transactionOver, ExceptT.mk,
    bind, Program.bind, execute]
  rw [opened]
  rw [execute_bind]
  dsimp only [ExceptT.run]
  rw [execute_bind, ready.clockExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind, ready.authorizationExecution]
  dsimp only [ExceptT.bindCont]
  simp only [ready.originBound, Bool.not_true, Bool.false_eq_true, if_false]
  rw [execute_bind, ready.recordExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind, ready.completeExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind, ready.pendingExecution]
  dsimp only [ExceptT.bindCont]
  simp only [greater, ↓reduceIte]
  rw [execute_bind, ready.writeExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind, ready.trimExecution]
  dsimp only [ExceptT.bindCont]
  have returned : execute (pure Acceptance.pending : History.Action Acceptance)
      ready.afterTrim = (.ok .pending, ready.afterTrim) := rfl
  rw [returned]
  dsimp only
  unfold execute
  rw [ready.commitExecution]
  rfl

theorem newer_accepts (head : Head) (keep : Nat) (state : State)
    (ready : NewerReady state head keep) :
    (execute (Reconcile.accept head state.now keep) state).1 = .ok .pending := by
  rw [newer_executes head keep state ready]

/-- The same positive execution installs the candidate in the committed
pending slot, even when complete and pending floors already existed. -/
theorem newer_installs_pending (head : Head) (keep : Nat) (state : State)
    (ready : NewerReady state head keep) :
    let table := rows (execute (Reconcile.accept head state.now keep) state).2.db "heads"
    (∃ row ∈ table,
      ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = true) ∧
    (∀ row ∈ table,
      ReconciliationSlots.names row (Origin.canonical head.origin) "pending" = true →
      ReconciliationSlots.pointsTo row head) := by
  exact ReconciliationAcceptance.accepted_installs_pending head state.now keep state
    (newer_accepts head keep state ready)

/-- If one independently observed backed floor blocks the candidate, the
healthy actual command takes the negative branch and returns `notNewer`. -/
theorem obsolete_executes (head : Head) (keep : Nat) (state : State)
    (ready : ObsoleteReady state head keep) :
    execute (Reconcile.accept head state.now keep) state =
      (.ok .notNewer, ready.afterCommit) := by
  have verified :
      execute (raise History.Error.host
        (Crypto.verifyEd25519 head.signedBy (Reconcile.signingInput head) head.signature) :
          History.Action Bool) state =
        (.ok true, SimulatedHost.record state "verifySignature") := by
    simp [raise, performOver, ExceptT.mk, Except.mapError,
      Inject.inject, Interpreter.handle, execute, SimulatedHost.crypto,
      SimulatedHost.reply, SimulatedHost.fault, ready.noFailures, ready.signatureValid]
  have opened :
      Interpreter.handle (Inject.inject (F := History.Effects) Storage.begin)
        (SimulatedHost.record state "verifySignature") =
      (.ok state.nextTx,
        SimulatedHost.record
          { SimulatedHost.record state "verifySignature" with
            pending := some (state.nextTx, state.db), nextTx := state.nextTx + 1 }
          "begin") := by
    simp [Inject.inject, Interpreter.handle, SimulatedHost.storage, SimulatedHost.reply,
      SimulatedHost.fault, ready.noFailures, ready.noOpenTransaction,
      SimulatedHost.record]
  have notGreater : (ready.complete ++ ready.pending).all
      (fun old => Reconcile.newer head.seq head.root old.pointer) = false := by
    apply Bool.eq_false_iff.mpr
    intro greater
    have blocked := (List.all_eq_true.mp greater) ready.blocker ready.blockerMember
    rw [ready.notAbove] at blocked
    cases blocked
  unfold Reconcile.accept
  simp only [bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, execute_bind]
  rw [verified]
  dsimp only
  simp only [Bool.not_true, Bool.false_eq_true, if_false, transactionOver, ExceptT.mk,
    bind, Program.bind, execute]
  rw [opened]
  rw [execute_bind]
  dsimp only [ExceptT.run]
  rw [execute_bind, ready.clockExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind, ready.authorizationExecution]
  dsimp only [ExceptT.bindCont]
  simp only [ready.originBound, Bool.not_true, Bool.false_eq_true, if_false]
  rw [execute_bind, ready.recordExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind, ready.completeExecution]
  dsimp only [ExceptT.bindCont]
  rw [execute_bind, ready.pendingExecution]
  dsimp only [ExceptT.bindCont]
  simp only [notGreater, Bool.false_eq_true, if_false]
  rw [execute_bind, ready.trimExecution]
  dsimp only [ExceptT.bindCont]
  have returned : execute (pure Acceptance.notNewer : History.Action Acceptance)
      ready.afterTrim = (.ok .notNewer, ready.afterTrim) := rfl
  rw [returned]
  dsimp only
  unfold execute
  rw [ready.commitExecution]
  rfl

theorem obsolete_returns_notNewer (head : Head) (keep : Nat) (state : State)
    (ready : ObsoleteReady state head keep) :
    (execute (Reconcile.accept head state.now keep) state).1 = .ok .notNewer := by
  rw [obsolete_executes head keep state ready]

/-- A rejected stable candidate leaves the committed complete/pending table
unchanged.  The blocker supplied by `ObsoleteReady` is backed in the initial
raw database, so this is a consequence of the existing floor theorem. -/
theorem obsolete_preserves_heads (head : Head) (keep : Nat) (state : State)
    (ready : ObsoleteReady state head keep) :
    rows (execute (Reconcile.accept head state.now keep) state).2.db "heads" =
      rows state.db "heads" := by
  have returned := obsolete_returns_notNewer head keep state ready
  rcases List.mem_append.mp ready.blockerMember with complete | pending
  · exact ReconciliationFloor.obsolete_preserves_heads head state.now keep state
      "complete" (Or.inl rfl) ready.blocker.pointer.seq.toInt64 ready.blocker.pointer.root
      (ready.completeBacked ready.blocker complete) ready.notAbove .notNewer returned
  · exact ReconciliationFloor.obsolete_preserves_heads head state.now keep state
      "pending" (Or.inr rfl) ready.blocker.pointer.seq.toInt64 ready.blocker.pointer.root
      (ready.pendingBacked ready.blocker pending) ready.notAbove .notNewer returned

/-- Public sequence/root rank of a signed head.  This is exactly the rank used
by `Exchange.plan`; authentication fields deliberately do not affect it. -/
def rank (head : Head) : Nat :=
  1 + head.root.data.foldl (fun value byte => value * 256 + byte.toNat) head.seq.toNat

/-- Native fixed-width contract for a signed advertisement presented to
`Reconcile.accept`.  Crypto/authority/history validity remains in the per-step
ready certificate and is not circularly defined by acceptance. -/
def ValidSignedAdvertisement (head : Head) : Prop := head.root.size = 32

structure SameValidSignedAdvertisements (left right : List Head) : Prop where
  leftValid : ∀ head ∈ left, ValidSignedAdvertisement head
  rightValid : ∀ head ∈ right, ValidSignedAdvertisement head
  same : ∀ head, head ∈ left ↔ head ∈ right

/-- The semantic stable-latest fold.  Its two constructors below are justified
by actual healthy `Reconcile.accept` executions, rather than by postulated
acceptance answers. -/
def latestRank (initial : Nat) (heads : List Head) : Nat :=
  heads.foldl (fun current head => max current (rank head)) initial

def versionRank (version : HeadVersion) : Nat :=
  1 + version.root.data.foldl (fun value byte => value * 256 + byte.toNat) version.seq.toNat

/-- Missing slots contribute the exchange protocol's zero sentinel. -/
def optionRank : Option HeadVersion → Nat
  | none => 0
  | some version => versionRank version

/-- Typed/backed raw-host observation of any complete/pending combination,
including fresh, complete-only and pending-only origins. -/
structure StableSlots (state : State) (origin : String) (latest : Nat) (view : HeadView) : Prop where
  represents : HeadView.Represents state.db view
  backed : HeadView.Backed state.db view
  valid : ∀ slot version, view origin slot = some version → version.root.size = 32
  maximum : max (optionRank (view origin .complete)) (optionRank (view origin .pending)) = latest

private def advertisedVersion (version : HeadVersion) :
    VerifiedCore.Replication.Exchange.Advertised :=
  ⟨"", version.seq, version.root⟩

/-- The exchange rank is injective on the native fixed-width root domain. -/
theorem versionRank_injective (left right : HeadVersion)
    (leftValid : left.root.size = 32) (rightValid : right.root.size = 32)
    (same : versionRank left = versionRank right) : left = right := by
  let leftAd := advertisedVersion left
  let rightAd := advertisedVersion right
  have rankSame : VerifiedCore.Replication.Exchange.version leftAd =
      VerifiedCore.Replication.Exchange.version rightAd := by
    dsimp [leftAd, rightAd, advertisedVersion, VerifiedCore.Replication.Exchange.version,
      versionRank]
    exact same
  have seqSame : left.seq = right.seq := by
    by_cases equal : left.seq = right.seq
    · exact equal
    exfalso
    have natDifferent : left.seq.toNat ≠ right.seq.toNat := by
      intro sameNat
      exact equal (UInt64.toNat_inj.mp sameNat)
    rcases Nat.lt_or_lt_of_ne natDifferent with less | greater
    · have ordered := (ExchangeVersionProofs.version_order_is_sequence_then_root
        leftAd rightAd (by simpa [leftAd, advertisedVersion] using leftValid)
        (by simpa [rightAd, advertisedVersion] using rightValid)).mpr
          (Or.inl (by simpa [leftAd, rightAd, advertisedVersion,
            UInt64.lt_iff_toNat_lt] using less))
      exact (Nat.ne_of_lt ordered) rankSame
    · have ordered := (ExchangeVersionProofs.version_order_is_sequence_then_root
        rightAd leftAd (by simpa [rightAd, advertisedVersion] using rightValid)
        (by simpa [leftAd, advertisedVersion] using leftValid)).mpr
          (Or.inl (by simpa [leftAd, rightAd, advertisedVersion,
            UInt64.lt_iff_toNat_lt] using greater))
      exact (Nat.ne_of_lt ordered) rankSame.symm
  have rootLists : left.root.data.toList = right.root.data.toList := by
    apply List.lex_trichotomous (r := fun x y : UInt8 => x < y)
      (fun x y notLess notGreater => by
        apply UInt8.toNat_inj.mp
        have leftNotLess : ¬ x.toNat < y.toNat := by
          simpa only [UInt8.lt_iff_toNat_lt] using notLess
        have rightNotLess : ¬ y.toNat < x.toNat := by
          simpa only [UInt8.lt_iff_toNat_lt] using notGreater
        omega)
    · intro rightLess
      have ordered := (ExchangeVersionProofs.version_order_is_sequence_then_root
        rightAd leftAd (by simpa [rightAd, advertisedVersion] using rightValid)
        (by simpa [leftAd, advertisedVersion] using leftValid)).mpr
          (Or.inr ⟨seqSame.symm, rightLess⟩)
      exact (Nat.ne_of_lt ordered) rankSame.symm
    · intro leftLess
      have ordered := (ExchangeVersionProofs.version_order_is_sequence_then_root
        leftAd rightAd (by simpa [leftAd, advertisedVersion] using leftValid)
        (by simpa [rightAd, advertisedVersion] using rightValid)).mpr
          (Or.inr ⟨seqSame, leftLess⟩)
      exact (Nat.ne_of_lt ordered) rankSame
  have rootSame : left.root = right.root :=
    ByteArray.ext (Array.toList_inj.mp rootLists)
  cases left
  cases right
  simp_all

/-- Production's strict sequence/root order strictly increases the same
fixed-width rank used by actual advertisement selection. -/
theorem versionRank_lt_of_newer (old next : HeadVersion)
    (oldValid : old.root.size = 32) (nextValid : next.root.size = 32)
    (newer : next.Newer old) : versionRank old < versionRank next := by
  have orderSpec : old.seq < next.seq ∨ old.seq = next.seq ∧
      List.Lex (· < ·) old.root.data.toList next.root.data.toList := by
    rcases newer with sequence | ⟨sequence, root⟩
    · exact Or.inl sequence
    · exact Or.inr ⟨sequence.symm, List.lex_lt.mpr root⟩
  have compared := (ExchangeVersionProofs.version_order_is_sequence_then_root
    (advertisedVersion old) (advertisedVersion next)
    (by simpa [advertisedVersion] using oldValid)
    (by simpa [advertisedVersion] using nextValid)).mpr (by
      simpa [advertisedVersion] using orderSpec)
  simpa [versionRank, advertisedVersion,
    VerifiedCore.Replication.Exchange.version] using compared

/-- The operation-independent sequence/root order used by `LatestValid`
agrees with the production acceptance/exchange rank on native-width heads. -/
theorem rank_le_of_version_order (candidate latest : Head)
    (candidateValid : candidate.root.size = 32)
    (latestValid : latest.root.size = 32)
    (ordered : (⟨candidate.seq, candidate.root⟩ : HeadVersion) =
        ⟨latest.seq, latest.root⟩ ∨
      (⟨latest.seq, latest.root⟩ : HeadVersion).Newer
        ⟨candidate.seq, candidate.root⟩) :
    rank candidate ≤ rank latest := by
  rcases ordered with same | newer
  · cases candidate
    cases latest
    simp_all [rank]
  · apply Nat.le_of_lt
    have orderSpec : candidate.seq < latest.seq ∨
        candidate.seq = latest.seq ∧
          List.Lex (· < ·) candidate.root.data.toList latest.root.data.toList := by
      rcases newer with sequence | ⟨sequence, root⟩
      · exact Or.inl sequence
      · refine Or.inr ⟨sequence.symm, ?_⟩
        exact List.lex_lt.mpr root
    have compared := (ExchangeVersionProofs.version_order_is_sequence_then_root
      (advertisedVersion ⟨candidate.seq, candidate.root⟩)
      (advertisedVersion ⟨latest.seq, latest.root⟩)
      (by simpa [advertisedVersion] using candidateValid)
      (by simpa [advertisedVersion] using latestValid)).mpr (by
        simpa [advertisedVersion] using orderSpec)
    simpa [rank, versionRank, advertisedVersion,
      VerifiedCore.Replication.Exchange.version] using compared

/-- The actual selected version of the two slots, with pending winning only
when it is strictly newer. -/
def selectedVersion (view : HeadView) (origin : String) : Option HeadVersion :=
  match view origin .complete, view origin .pending with
  | none, none => none
  | some complete, none => some complete
  | none, some pending => some pending
  | some complete, some pending =>
      if versionRank complete < versionRank pending then some pending else some complete

theorem selectedVersion_rank (view : HeadView) (origin : String) :
    optionRank (selectedVersion view origin) =
      max (optionRank (view origin .complete)) (optionRank (view origin .pending)) := by
  cases complete : view origin .complete with
  | none => cases pending : view origin .pending <;>
      simp [selectedVersion, complete, pending, optionRank]
  | some completeVersion =>
      cases pending : view origin .pending with
      | none => simp [selectedVersion, complete, pending, optionRank]
      | some pendingVersion =>
          simp only [selectedVersion, complete, pending, optionRank]
          by_cases order : versionRank completeVersion < versionRank pendingVersion
          · rw [if_pos order]
            exact (Nat.max_eq_right (Nat.le_of_lt order)).symm
          · rw [if_neg order]
            exact (Nat.max_eq_left (Nat.le_of_not_gt order)).symm

theorem StableSlots.selected_valid (stable : StableSlots state origin latest view)
    (selected : selectedVersion view origin = some version) : version.root.size = 32 := by
  cases complete : view origin .complete <;> cases pending : view origin .pending <;>
    simp only [selectedVersion, complete, pending] at selected
  · cases selected
  · cases selected
    exact stable.valid .pending _ pending
  · cases selected
    exact stable.valid .complete _ complete
  · split at selected
    · cases selected
      exact stable.valid .pending _ pending
    · cases selected
      exact stable.valid .complete _ complete

/-- Equal stable ranks now imply equality of the user-visible typed selected
versions, not merely equality of an encoding proxy. -/
theorem stable_slots_selected_equal
    (left : StableSlots leftState origin latest leftView)
    (right : StableSlots rightState origin latest rightView) :
    selectedVersion leftView origin = selectedVersion rightView origin := by
  have sameRank : optionRank (selectedVersion leftView origin) =
      optionRank (selectedVersion rightView origin) := by
    rw [selectedVersion_rank, selectedVersion_rank, left.maximum, right.maximum]
  cases leftSelected : selectedVersion leftView origin with
  | none =>
      cases rightSelected : selectedVersion rightView origin with
      | none => rfl
      | some version =>
          rw [leftSelected, rightSelected] at sameRank
          simp only [optionRank] at sameRank
          unfold versionRank at sameRank
          omega
  | some leftVersion =>
      cases rightSelected : selectedVersion rightView origin with
      | none =>
          rw [leftSelected, rightSelected] at sameRank
          simp only [optionRank] at sameRank
          unfold versionRank at sameRank
          omega
      | some rightVersion =>
          apply congrArg some
          apply versionRank_injective leftVersion rightVersion
          · exact left.selected_valid leftSelected
          · exact right.selected_valid rightSelected
          · simpa [leftSelected, rightSelected, optionRank] using sameRank

private theorem represented_slot_eq (before : HeadView.Represents db view)
    (after : HeadView.Represents nextDb nextView)
    (sameRows : rows nextDb "heads" = rows db "heads") (origin : String) (slot : HeadSlot) :
    nextView origin slot = view origin slot := by
  cases value : view origin slot with
  | some version =>
      apply HeadView.stays before after value
      intro row selected
      rw [sameRows]
      exact selected.1
  | none =>
      cases nextValue : nextView origin slot with
      | none => rfl
      | some version =>
          obtain ⟨row, selected, _⟩ := HeadView.existing after nextValue
          have priorMember : row ∈ rows db "heads" := by
            rw [← sameRows]
            exact selected.1
          exact False.elim (HeadView.absent before value
            ⟨priorMember, selected.2⟩)

private theorem accepted_stable_slots (head : Head) (keep : Nat) (state : State)
    (origin : String) (current : Nat) (named : Origin.canonical head.origin = origin)
    (strict : current < rank head) (ready : NewerReady state head keep)
    (before : StableSlots state origin current beforeView)
    (candidateValid : ValidSignedAdvertisement head)
    (afterRepresents : HeadView.Represents ready.afterCommit.db afterView)
    (afterBacked : HeadView.Backed ready.afterCommit.db afterView)
    (completeFrame : afterView origin .complete = beforeView origin .complete) :
    StableSlots ready.afterCommit origin (rank head) afterView := by
  obtain ⟨pendingRow, pendingMember, pendingNamed⟩ :=
    (newer_installs_pending head keep state ready).1
  have candidatePoints :=
    (newer_installs_pending head keep state ready).2 pendingRow pendingMember pendingNamed
  rw [newer_executes head keep state ready] at pendingMember
  have pendingNamed' : ReconciliationSlots.names pendingRow origin "pending" = true := by
    rwa [← named]
  obtain ⟨pendingVersion, pendingValue, pendingPoints⟩ :=
    HeadView.selected_version (origin := origin) (slot := .pending)
      afterRepresents ⟨pendingMember, pendingNamed'⟩
  have pendingSame : pendingVersion = (⟨head.seq, head.root⟩ : HeadVersion) :=
    HeadView.version_unique pendingRow pendingVersion _ pendingPoints candidatePoints
  subst pendingVersion
  refine ⟨afterRepresents, afterBacked, ?_, ?_⟩
  · intro slot version value
    cases slot with
    | complete => rw [completeFrame] at value; exact before.valid _ _ value
    | pending => rw [pendingValue] at value; cases value; exact candidateValid
  rw [pendingValue, completeFrame]
  have completeBound : optionRank (beforeView origin .complete) ≤ current := by
    rw [← before.maximum]
    exact Nat.le_max_left ..
  have candidateWins : optionRank (beforeView origin .complete) ≤ rank head :=
    Nat.le_trans completeBound (Nat.le_of_lt strict)
  exact Nat.max_eq_right candidateWins

private theorem obsolete_stable_slots (head : Head) (keep : Nat) (state : State)
    (origin : String) (current : Nat) (ready : ObsoleteReady state head keep)
    (before : StableSlots state origin current beforeView)
    (afterRepresents : HeadView.Represents ready.afterCommit.db afterView)
    (afterBacked : HeadView.Backed ready.afterCommit.db afterView) :
    StableSlots ready.afterCommit origin current afterView := by
  have sameRows : rows ready.afterCommit.db "heads" = rows state.db "heads" := by
    have kept := obsolete_preserves_heads head keep state ready
    rw [obsolete_executes head keep state ready] at kept
    exact kept
  have completeKept := represented_slot_eq before.represents afterRepresents sameRows origin .complete
  have pendingKept := represented_slot_eq before.represents afterRepresents sameRows origin .pending
  refine ⟨afterRepresents, afterBacked, ?_, ?_⟩
  · intro slot version value
    cases slot with
    | complete => rw [completeKept] at value; exact before.valid _ _ value
    | pending => rw [pendingKept] at value; exact before.valid _ _ value
  rw [completeKept, pendingKept]
  exact before.maximum

/-- A finite sequence of actual production acceptance commands.  `advance`
requires the positive floor certificate and links the next host state to its
real committed result; `retain` analogously uses a backed blocker.  The rank
comparison is independent semantic bookkeeping used to state convergence. -/
inductive ActualAcceptanceFold (origin : String) (keep : Nat) :
    Nat → State → List Head → Nat → State → Prop where
  | nil (current : Nat) (state : State) :
      ActualAcceptanceFold origin keep current state [] current state
  | advance (current : Nat) (state : State) (head : Head) (tail : List Head)
      (named : Origin.canonical head.origin = origin)
      (strict : current < rank head)
      (candidateValid : ValidSignedAdvertisement head)
      (ready : NewerReady state head keep)
      (rest : ActualAcceptanceFold origin keep (rank head) ready.afterCommit tail final finalState) :
      ActualAcceptanceFold origin keep current state (head :: tail) final finalState
  | retain (current : Nat) (state : State) (head : Head) (tail : List Head)
      (named : Origin.canonical head.origin = origin)
      (blocked : rank head ≤ current)
      (ready : ObsoleteReady state head keep)
      (rest : ActualAcceptanceFold origin keep current ready.afterCommit tail final finalState) :
      ActualAcceptanceFold origin keep current state (head :: tail) final finalState

/-- The raw-observed fold.  Its starting `StableSlots` proof is threaded into
the next edge by the actual pending installation/table-preservation lemmas.
The only extra positive-edge contract is `completeFrame`: the production host
must not manufacture a complete slot while executing a pending-only write. -/
inductive ObservedAcceptanceFold (origin : String) (keep : Nat) :
    (current : Nat) → (state : State) → (view : HeadView) →
      StableSlots state origin current view →
      List Head → (final : Nat) → (finalState : State) → (finalView : HeadView) → Prop where
  | nil (current : Nat) (state : State) (view : HeadView)
      (stable : StableSlots state origin current view) :
      ObservedAcceptanceFold origin keep current state view stable [] current state view
  | advance (current : Nat) (state : State) (view : HeadView)
      (stable : StableSlots state origin current view)
      (head : Head) (tail : List Head)
      (named : Origin.canonical head.origin = origin)
      (strict : current < rank head)
      (candidateValid : ValidSignedAdvertisement head)
      (ready : NewerReady state head keep)
      (afterView : HeadView)
      (afterRepresents : HeadView.Represents ready.afterCommit.db afterView)
      (afterBacked : HeadView.Backed ready.afterCommit.db afterView)
      (completeFrame : afterView origin .complete = view origin .complete)
      (rest : ObservedAcceptanceFold origin keep (rank head) ready.afterCommit afterView
        (accepted_stable_slots head keep state origin current named strict ready stable candidateValid
          afterRepresents afterBacked completeFrame)
        tail final finalState finalView) :
      ObservedAcceptanceFold origin keep current state view stable (head :: tail)
        final finalState finalView
  | retain (current : Nat) (state : State) (view : HeadView)
      (stable : StableSlots state origin current view)
      (head : Head) (tail : List Head)
      (named : Origin.canonical head.origin = origin)
      (blocked : rank head ≤ current)
      (ready : ObsoleteReady state head keep)
      (afterView : HeadView)
      (afterRepresents : HeadView.Represents ready.afterCommit.db afterView)
      (afterBacked : HeadView.Backed ready.afterCommit.db afterView)
      (rest : ObservedAcceptanceFold origin keep current ready.afterCommit afterView
        (obsolete_stable_slots head keep state origin current ready stable
          afterRepresents afterBacked)
        tail final finalState finalView) :
      ObservedAcceptanceFold origin keep current state view stable (head :: tail)
        final finalState finalView

theorem ObservedAcceptanceFold.actual
    (run : ObservedAcceptanceFold origin keep initial state view stable
      heads final finalState finalView) :
    ActualAcceptanceFold origin keep initial state heads final finalState := by
  induction run with
  | nil => exact .nil _ _
  | advance current state view stable head tail named strict candidateValid ready afterView
      afterRepresents afterBacked completeFrame rest ih =>
      exact .advance current state head tail named strict candidateValid ready ih
  | retain current state view stable head tail named blocked ready afterView
      afterRepresents afterBacked rest ih =>
      exact .retain current state head tail named blocked ready ih

/-- In particular, the final ghost rank is the maximum of the actual typed,
backed complete/pending slots in the final raw database. -/
theorem ObservedAcceptanceFold.final_stable
    (run : ObservedAcceptanceFold origin keep initial state view stable
      heads final finalState finalView) :
    StableSlots finalState origin final finalView := by
  induction run with
  | nil current state view initialStable => exact initialStable
  | advance current state view stable head tail named strict candidateValid ready afterView
      afterRepresents afterBacked completeFrame rest ih => exact ih
  | retain current state view stable head tail named blocked ready afterView
      afterRepresents afterBacked rest ih => exact ih

/-- Acceptance writes only the pending slot. Across an observed fold the
complete version therefore remains exactly the initial complete version. -/
theorem ObservedAcceptanceFold.complete_preserved
    (run : ObservedAcceptanceFold origin keep initial state view stable
      heads final finalState finalView) :
    finalView origin .complete = view origin .complete := by
  induction run with
  | nil => rfl
  | advance current state view stable head tail named strict candidateValid ready afterView
      afterRepresents afterBacked completeFrame rest ih =>
    exact ih.trans completeFrame
  | retain current state view stable head tail named blocked ready afterView
      afterRepresents afterBacked rest ih =>
    have sameRows : rows ready.afterCommit.db "heads" = rows state.db "heads" := by
      have kept := obsolete_preserves_heads head keep state ready
      rw [obsolete_executes head keep state ready] at kept
      exact kept
    have kept := represented_slot_eq stable.represents afterRepresents sameRows origin .complete
    exact ih.trans kept

/-- Factual execution trace, independent of the semantic rank proof. -/
inductive AcceptanceExecution (keep : Nat) : State → List Head → State → Prop where
  | nil (state : State) : AcceptanceExecution keep state [] state
  | cons (state next final : State) (head : Head) (tail : List Head) (answer : Acceptance)
      (ran : execute (Reconcile.accept head state.now keep) state = (.ok answer, next))
      (rest : AcceptanceExecution keep next tail final) :
      AcceptanceExecution keep state (head :: tail) final

/-- Erasing semantic bookkeeping from a fold leaves a chain consisting solely
of actual production execution equalities. -/
theorem ActualAcceptanceFold.execution
    (run : ActualAcceptanceFold origin keep initial state heads final finalState) :
    AcceptanceExecution keep state heads finalState := by
  induction run with
  | nil => exact .nil _
  | advance current state head tail named strict candidateValid ready rest ih =>
      simpa only using
        (AcceptanceExecution.cons state ready.afterCommit _ head tail .pending
          (newer_executes head keep state ready) ih)
  | retain current state head tail named blocked ready rest ih =>
      simpa only using
        (AcceptanceExecution.cons state ready.afterCommit _ head tail .notNewer
          (obsolete_executes head keep state ready) ih)

/-- Each positive fold edge is the actual M3 advertisement transition. -/
theorem newer_head_transition (head : Head) (keep : Nat) (state : State)
    (ready : NewerReady state head keep)
    (before : HeadView.Represents state.db view)
    (backed : HeadView.Backed state.db view)
    (after : HeadView.Represents ready.afterCommit.db nextView) :
    HeadTransition [] view nextView := by
  apply AcceptanceTransition.refines head state.now keep state
    ready.noOpenTransaction before backed
  simpa [newer_executes head keep state ready] using after

/-- Each blocked fold edge is likewise the actual M3 advertisement transition;
the stronger raw-table conclusion says it is specifically the keep case. -/
theorem obsolete_head_transition (head : Head) (keep : Nat) (state : State)
    (ready : ObsoleteReady state head keep)
    (before : HeadView.Represents state.db view)
    (backed : HeadView.Backed state.db view)
    (after : HeadView.Represents ready.afterCommit.db nextView) :
    HeadTransition [] view nextView := by
  apply AcceptanceTransition.refines head state.now keep state
    ready.noOpenTransaction before backed
  simpa [obsolete_executes head keep state ready] using after

/-- The ghost latest rank of an actual healthy fold is fully determined by
its initial floor and offered signed heads. -/
theorem ActualAcceptanceFold.final_rank
    (run : ActualAcceptanceFold origin keep initial state heads final finalState) :
    final = latestRank initial heads := by
  induction run with
  | nil => rfl
  | advance current state head tail named strict candidateValid ready rest ih =>
      simp only [latestRank, List.foldl_cons]
      rw [Nat.max_eq_right (Nat.le_of_lt strict)]
      exact ih
  | retain current state head tail named blocked ready rest ih =>
      simp only [latestRank, List.foldl_cons]
      rw [Nat.max_eq_left blocked]
      exact ih

private theorem latestRank_bounded (initial bound : Nat) (heads : List Head) :
    latestRank initial heads ≤ bound ↔
      initial ≤ bound ∧ ∀ head ∈ heads, rank head ≤ bound := by
  induction heads generalizing initial with
  | nil => simp [latestRank]
  | cons head tail ih =>
      change latestRank (max initial (rank head)) tail ≤ bound ↔
        initial ≤ bound ∧ ∀ candidate ∈ head :: tail, rank candidate ≤ bound
      rw [ih]
      simp only [Nat.max_le, List.mem_cons, forall_eq_or_imp]
      constructor
      · rintro ⟨⟨initialBound, headBound⟩, tailBound⟩
        exact ⟨initialBound, headBound, tailBound⟩
      · rintro ⟨initialBound, headBound, tailBound⟩
        exact ⟨⟨initialBound, headBound⟩, tailBound⟩

/-- If the stable greatest valid head was actually delivered, folding the
production acceptance order reaches exactly its rank.  The upper bound is
normally obtained from `LatestValid`; membership is the separate delivery
obligation discharged by advertisement scheduling. -/
theorem latestRank_eq_rank_of_member
    (initialBound : initial ≤ rank latest)
    (delivered : latest ∈ heads)
    (greatest : ∀ head ∈ heads, rank head ≤ rank latest) :
    latestRank initial heads = rank latest := by
  apply Nat.le_antisymm
  · exact (latestRank_bounded initial (rank latest) heads).mpr
      ⟨initialBound, greatest⟩
  · exact (latestRank_bounded initial (latestRank initial heads) heads).mp
      (Nat.le_refl _)|>.2 latest delivered

/-- Actual raw complete/pending observations therefore select the delivered
greatest head itself, not merely the same numeric rank. -/
theorem ObservedAcceptanceFold.selects_delivered_latest
    (run : ObservedAcceptanceFold origin keep initial state view stable
      heads final finalState finalView)
    (initialBound : initial ≤ rank latest)
    (delivered : latest ∈ heads)
    (greatest : ∀ head ∈ heads, rank head ≤ rank latest)
    (latestValid : latest.root.size = 32) :
    selectedVersion finalView origin = some (⟨latest.seq, latest.root⟩ : HeadVersion) := by
  have selectedRank : optionRank (selectedVersion finalView origin) = rank latest := by
    rw [selectedVersion_rank, run.final_stable.maximum, run.actual.final_rank,
      latestRank_eq_rank_of_member initialBound delivered greatest]
  cases selectedEq : selectedVersion finalView origin with
  | none =>
      rw [selectedEq] at selectedRank
      simp [optionRank, rank] at selectedRank
      omega
  | some selected =>
      apply congrArg some
      apply versionRank_injective selected ⟨latest.seq, latest.root⟩
      · exact run.final_stable.selected_valid selectedEq
      · exact latestValid
      · simpa [selectedEq, optionRank, rank, versionRank] using selectedRank

/-- Membership, not ordering or multiplicity, determines the semantic latest
rank.  This is the fold counterpart of planner selection invariance. -/
theorem latestRank_eq_of_same (same : ∀ head, head ∈ left ↔ head ∈ right) :
    latestRank initial left = latestRank initial right := by
  apply Nat.le_antisymm
  · apply (latestRank_bounded initial _ left).mpr
    refine ⟨(latestRank_bounded initial _ right).mp (Nat.le_refl _)|>.1, ?_⟩
    intro head member
    exact (latestRank_bounded initial _ right).mp (Nat.le_refl _)|>.2 head ((same head).mp member)
  · apply (latestRank_bounded initial _ right).mpr
    refine ⟨(latestRank_bounded initial _ left).mp (Nat.le_refl _)|>.1, ?_⟩
    intro head member
    exact (latestRank_bounded initial _ left).mp (Nat.le_refl _)|>.2 head ((same head).mpr member)

/-- Two actual healthy acceptance folds over the same set of signed heads end
at the same stable latest version rank, regardless of order and duplicates. -/
theorem actual_folds_same_latest
    (same : ∀ head, head ∈ left ↔ head ∈ right)
    (leftRun : ActualAcceptanceFold origin keep initial leftState left leftFinal leftFinalState)
    (rightRun : ActualAcceptanceFold origin keep initial rightState right rightFinal rightFinalState) :
    leftFinal = rightFinal := by
  rw [leftRun.final_rank, rightRun.final_rank, latestRank_eq_of_same same]

end Synchronicity.AcceptanceProgress
