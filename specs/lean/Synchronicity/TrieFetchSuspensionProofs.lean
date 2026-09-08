import VerifiedCore.Trie.Fetch
import Synchronicity.SuspensionProofs
import Synchronicity.TriePreflightTransactions

/-! The executable requesting operation may inspect and admit data inside a
transaction, but a network wait must occur after that transaction has closed.
The certificates below quantify over every possible host reply. -/
namespace Synchronicity.TrieFetchSuspensionProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie SuspensionProofs

/-- Only peer effects suspend the requesting operation. -/
def guard : Guard Fetch.Effects where
  opens := fun effect => match effect with
    | .left (.left storage) => opensStorage storage
    | _ => none
  closes := fun effect => match effect with
    | .left (.left storage) => closesStorage storage
    | _ => none
  suspends := fun effect => match effect with
    | .right (.right (.right (.left _))) => true
    | _ => false

private theorem mapped_without_waits (program : Program E A)
    (inject : {B : Type} → E B → F B) (g : Guard F)
    (quiet : ∀ {B} (effect : E B), g.suspends (inject effect) = false) (isOpen : Bool) :
    Balanced g isOpen (program.mapEffects inject) (fun _ _ => True) := by
  induction program generalizing isOpen with
  | pure value => exact .pure trivial
  | request effect resume ih =>
    exact .request (by simp [quiet]) fun reply => ih reply _

/-- No wait occurs in this program, regardless of the initial transaction
state. Unlike a read-only certificate, it need not preserve that state. -/
private def NoWait (program : Program Fetch.Effects A) : Prop :=
  ∀ isOpen, Balanced guard isOpen program (fun _ _ => True)

private theorem NoWait.pure (value : A) : NoWait (Program.pure value) :=
  fun _ => .pure trivial

private theorem NoWait.bind {program : Program Fetch.Effects A}
    {next : A → Program Fetch.Effects B} (head : NoWait program)
    (tail : ∀ value, NoWait (next value)) : NoWait (program.bind next) := by
  intro isOpen
  exact Balanced.bind (head isOpen) fun value openNow _ => tail value openNow

private theorem NoWait.seq {operation : Fetch.Action A} {next : A → Fetch.Action B}
    (head : NoWait operation.run) (tail : ∀ value, NoWait (next value).run) :
    NoWait (operation >>= next).run := by
  refine NoWait.bind head fun result => ?_
  cases result with
  | error _ => exact NoWait.pure _
  | ok value => exact tail value

private theorem NoWait.request [Inject E Fetch.Effects] (effect : E (Reply A))
    (quiet : guard.suspends (Inject.inject effect) = false) : NoWait (Fetch.request effect).run := by
  intro isOpen
  exact .request (by simp [quiet]) fun _ => .pure trivial

/-- A transaction with a body that never waits is safe to compose with a
later network request. A successful commit closes it; failures terminate
this operation, even when rollback itself fails. -/
private theorem transaction_without_waits (body : Transaction → Fetch.Action A)
    (quiet : ∀ tx, NoWait (body tx).run) :
    Suspending guard (transactionOver Inject.inject Fetch.Error.host body) := by
  unfold Suspending transactionOver
  refine .request (by simp [guard, Inject.inject]) fun reply => ?_
  cases reply with
  | error failure => exact .pure fun _ h => nomatch h
  | ok tx =>
    change Balanced guard true ((body tx).run.bind _) _
    refine Balanced.bind (quiet tx true) fun result isOpen _ => ?_
    cases result with
    | error failure =>
      exact .request (by simp [guard, Inject.inject]) fun _ => .pure fun _ h => nomatch h
    | ok value =>
      refine .request (by simp [guard, Inject.inject]) fun reply => ?_
      cases reply with
      | ok _ => exact .pure fun _ _ => by simp [Guard.after, guard, Inject.inject, opensStorage, closesStorage, Except.toBool]
      | error failure =>
        exact .request (by simp [guard, Inject.inject]) fun _ => .pure fun _ h => nomatch h

private theorem key_without_waits (scope : Serve.Scope) (root : ByteArray) (owner : Option String) :
    NoWait (Memo.keyFor (E := Fetch.Effects) Fetch.Error.host scope root owner).run := by
  unfold Memo.keyFor
  refine NoWait.seq ?_ fun key => ?_
  · unfold Memo.scopedKey
    cases scope.prefixes with
    | none => exact NoWait.pure _
    | some _ => exact NoWait.request _ rfl
  · cases owner with
    | none => exact NoWait.pure _
    | some _ => exact NoWait.request _ rfl

/-- Every inspection finishes its transaction before the requester can wait
for a peer, including generation resets, full walks and certification. This
uses the actual missing-data walk, for arbitrary frontier implementations. -/
private theorem inspection_closes_before_the_next_wait [Missing.WorkSet Missing.Visit V]
    [Missing.WorkSet ByteArray H] (target : Fetch.Target) (state : Fetch.State V H) (maximum : Nat) :
    Suspending guard (Fetch.inspect target state maximum) := by
  unfold Fetch.inspect
  apply transaction_without_waits
  intro tx
  refine NoWait.seq (NoWait.request _ rfl) fun generation => ?_
  refine NoWait.seq ?_ fun result => ?_
  · apply NoWait.bind
    · intro isOpen
      apply mapped_without_waits
      intro B effect
      cases effect with
      | left storage => rfl
      | right effect =>
        cases effect with
        | left access =>
          cases access <;> simp only [Fetch.inTransaction]
          all_goals first | rfl | (split <;> rfl)
        | right redaction => cases redaction <;> rfl
    · intro result
      exact NoWait.pure _
  · obtain ⟨frontier, result⟩ := result
    cases result with
    | error error => exact NoWait.pure _
    | ok batch =>
      refine NoWait.seq (NoWait.pure _) fun batch => ?_
      split
      · exact NoWait.seq (key_without_waits _ _ _) fun _ =>
          NoWait.seq (NoWait.request _ rfl) fun _ => NoWait.pure _
      · exact NoWait.seq (NoWait.pure _) fun _ => NoWait.pure _

private theorem NoWait.forIn (items : List A) (initial : B)
    (body : A → B → Fetch.Action (ForInStep B))
    (quiet : ∀ item value, NoWait (body item value).run) :
    NoWait (forIn items initial body).run := by
  induction items generalizing initial with
  | nil => exact NoWait.pure _
  | cons item rest ih =>
    rw [List.forIn_cons]
    refine NoWait.seq (quiet item initial) fun step => ?_
    cases step with
    | done _ => exact NoWait.pure _
    | yield next => exact ih next

private theorem NoWait.within [Inject E Fetch.Effects] (operation : OperationOver E ε A)
    (translate : ε → Fetch.Error)
    (quiet : ∀ {B} (effect : E B), guard.suspends (Inject.inject effect) = false) :
    NoWait (within translate operation).run := by
  apply NoWait.bind
  · intro isOpen
    exact mapped_without_waits operation.run Inject.inject guard quiet isOpen
  · intro result
    exact NoWait.pure _

/-- An entire reply, of any length, is processed without a network wait
inside its transaction. Success commits before fetching another reply;
a validation or host failure terminates the admission. -/
private theorem admission_closes_before_the_next_wait [Missing.WorkSet ByteArray H]
    (target : Fetch.Target) (values : Bool)
    (requested served : List (ByteArray × ByteArray)) (routeValues : List ByteArray) :
    Suspending guard (Fetch.admit (H := H) target values requested served routeValues) := by
  unfold Fetch.admit
  apply transaction_without_waits
  intro tx
  refine NoWait.seq ?_ fun _ => NoWait.pure _
  apply NoWait.forIn
  intro item accumulator
  obtain ⟨hash, bytes⟩ := item
  obtain ⟨outstanding, learned⟩ := accumulator
  dsimp only
  split
  · exact NoWait.pure _
  · split
    · refine NoWait.seq (NoWait.request _ rfl) fun observed => ?_
      split
      · exact NoWait.pure _
      · split
        · exact NoWait.seq (NoWait.request _ rfl) fun _ => NoWait.pure _
        · exact NoWait.pure _
    · refine NoWait.seq (NoWait.within (Trie.verify hash bytes) _ ?_) fun verdict => ?_
      · intro B effect
        cases effect <;> rfl
      · cases verdict with
        | peerFault => exact NoWait.pure _
        | originFault _ => exact NoWait.pure _
        | accepted =>
          refine NoWait.seq (NoWait.request _ rfl) fun _ => ?_
          cases target.context.owner with
          | none => exact NoWait.pure _
          | some _ => exact NoWait.seq (NoWait.request _ rfl) fun _ => NoWait.pure _

private theorem touch_closes (target : Fetch.Target) : Suspending guard (Fetch.touch target) := by
  unfold Fetch.touch
  refine Suspending.seq (Suspending.ofRaise _ _ rfl rfl) fun _ => ?_
  apply transaction_without_waits
  intro tx
  exact NoWait.seq (NoWait.request _ rfl) fun _ => NoWait.pure _

private theorem abandon_closes (target : Fetch.Target) : Suspending guard (Fetch.abandon target) := by
  unfold Fetch.abandon
  apply transaction_without_waits
  intro tx
  exact NoWait.seq (NoWait.request _ rfl) fun _ => NoWait.pure _

/-- A complete requesting round waits for peers only between transactions,
for every possible reply and whether it makes progress, retries or retires
its pending version. -/
private theorem round_waits_only_between_transactions [Missing.WorkSet Missing.Visit V]
    [Missing.WorkSet ByteArray H] (target : Fetch.Target) (maximum retryLimit : Nat)
    (state : Fetch.State V H) : Suspending guard (Fetch.step target maximum retryLimit state) := by
  unfold Fetch.step
  refine Suspending.seq (inspection_closes_before_the_next_wait _ _ _) fun inspected => ?_
  obtain ⟨state, missing, certified⟩ := inspected
  dsimp only
  repeat' first
    | exact Suspending.ofPure _
    | (refine Suspending.seq (admission_closes_before_the_next_wait _ _ _ _ _) fun _ => ?_)
    | (refine Suspending.seq (touch_closes _) fun _ => ?_)
    | (refine Suspending.seq (abandon_closes _) fun _ => ?_)
    | (refine Suspending.seq (Suspending.ofRaise _ _ rfl rfl) fun _ => ?_)
    | split

private theorem iterate_balanced (g : Guard F)
    (body : S → Program F (Except ε (S ⊕ R))) (exhausted : ε)
    (safeBody : ∀ state, Suspending g (ExceptT.mk (body state))) (fuel : Nat)
    (program : Program F (Except ε (S ⊕ R))) (isOpen : Bool)
    (safe : Balanced g isOpen program
      (fun result openNow => ∀ value, result = .ok value → openNow = false)) :
    Balanced g isOpen (Program.iterate body exhausted fuel program)
      (fun result openNow => ∀ value, result = .ok value → openNow = false) := by
  induction fuel generalizing program isOpen with
  | zero => exact .pure fun _ h => nomatch h
  | succ fuel ih =>
    cases program with
    | pure result =>
      cases safe with
      | pure closed =>
        cases result with
        | error failure => exact .pure fun _ h => nomatch h
        | ok next =>
          cases next with
          | inl state =>
            have wasClosed := closed _ rfl
            subst isOpen
            exact ih (body state) false (safeBody state)
          | inr value => exact .pure fun _ _ => closed _ rfl
    | request effect resume =>
      cases safe with
      | request outside replies =>
        exact .request outside fun reply => ih (resume reply) _ (replies reply)

private theorem reference_check_closes (V H : Type) [Missing.WorkSet Missing.Visit V]
    [Missing.WorkSet ByteArray H] (context : Missing.Context) (root : ByteArray) :
    Suspending guard (within Fetch.Error.walk (Complete.isComplete V H context root)) := by
  have closed : TriePreflightTransactions.Closed guard
      (within (F := Fetch.Effects) Fetch.Error.walk (Complete.isComplete V H context root)).run := by
    apply TriePreflightTransactions.Closed.bind
    · apply TriePreflightTransactions.Closed.mapEffects
        (TriePreflightTransactions.reference_check_keeps_transaction_closed _ _ _ _) Inject.inject
      intro B effect reply
      cases effect with
      | left missing =>
        cases missing with
        | left _ => rfl
        | right effect => cases effect <;> rfl
      | right effect => cases effect <;> rfl
    · intro result
      exact TriePreflightTransactions.Closed.pure _
  exact closed.balanced.weaken fun _ _ wasClosed _ _ => wasClosed

/-- The whole requester holds no transaction across any network wait, for
any reference snapshot, any reply batches and any sequence of host replies.
Inspection, admission, retries and abandonment all obey the same discipline. -/
theorem fetch_waits_only_between_transactions (V H : Type)
    [Missing.WorkSet Missing.Visit V] [Missing.WorkSet ByteArray H]
    (target : Fetch.Target) (reference : Option ByteArray) (maximum retryLimit : Nat) :
    Suspending guard (Fetch.fetch V H target reference maximum retryLimit) := by
  unfold Fetch.fetch
  refine Suspending.seq (Suspending.ofRaise _ _ rfl rfl) fun generation => ?_
  have loop (checkedReference : Option ByteArray) :
      Suspending guard (OperationOver.iterate
        (Fetch.step (V := V) (H := H) target maximum retryLimit) .exhausted Missing.batchFuel
        ⟨Missing.initial target.context checkedReference target.root, generation, 0, 0⟩) := by
    apply iterate_balanced
    · intro state
      exact round_waits_only_between_transactions _ _ _ _
    · exact round_waits_only_between_transactions _ _ _ _
  cases reference with
  | none => exact loop none
  | some root =>
    refine Suspending.seq (reference_check_closes _ _ _ _) fun complete => ?_
    split <;> exact loop _

end Synchronicity.TrieFetchSuspensionProofs
