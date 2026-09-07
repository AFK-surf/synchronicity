import VerifiedCore.Trie.Fetch
import Synchronicity.SuspensionProofs

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
theorem inspection_closes_before_the_next_wait [Missing.WorkSet Missing.Visit V]
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
        | right redaction => rfl
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

end Synchronicity.TrieFetchSuspensionProofs
