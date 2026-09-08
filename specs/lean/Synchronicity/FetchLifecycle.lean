import Synchronicity.RetirementProtection
import Synchronicity.TrieFetchSuspensionProofs

/-! The production outer fetch is selection, a captured-target requester, and
settlement. These names are definitional decompositions, not a second algorithm.
Only a fresh promotion may change a different target after requesting finishes. -/
namespace Synchronicity.FetchLifecycle
open VerifiedCore VerifiedCore.Host VerifiedCore.Commands VerifiedCore.Replication SimulatedHost PrivateDatabase

abbrev Selected := Promote.Pending × Option Promote.Pending × Trie.Serve.Scope × Option Origin.Parsed

def select (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray)) : Fetch.Action (Option Selected) :=
  Fetch.lift (transactionOver Inject.inject Promote.Error.host fun tx => do
    let pending ← Promote.slot tx origin "pending"
    let some pending := pending | return none
    if expected.any (fun e => e != (pending.head.seq, pending.head.root)) then return none
    let now ← raise Promote.Error.host Clock.nowNs
    let scope ← Promote.auth (Authorization.materializationScopeIn tx origin)
    let old ← Promote.slot tx origin "complete"
    let authority ← Promote.auth (Authorization.originAuthorityIn tx origin now)
    return some (pending, old, scope, authority.provenance))

def settle (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
    (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray)
    (result : Except Promote.Error Bool) : Fetch.Action FetchReport := do
  match result with
  | .ok false => return ⟨⟨.idle, none, none⟩, true⟩
  | .ok true =>
    let now ← raise Promote.Error.host Clock.nowNs
    return ⟨← Fetch.lift (Promote.promote origin now refused), false⟩
  | .error (.domain error) =>
    if Fetch.originFault error then
      within Fetch.fetchError (Trie.Fetch.abandon target)
      return ⟨⟨.refused, some error, some key⟩, false⟩
    throw (.domain error)
  | .error error => throw error

def selected (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
    (maximum retryLimit : Nat) (selection : Option Selected) : Fetch.Action FetchReport := do
  let some (pending, old, scope, owner) := selection | return ⟨⟨.idle, none, none⟩, false⟩
  let reference := old.map (·.head.root)
  let key := (pending.head.seq, pending.head.root, reference.getD Trie.emptyRoot)
  let target : Trie.Fetch.Target := ⟨pending.head.root, Origin.canonical origin, pending.head.seq,
    ⟨scope, owner.map Origin.canonical⟩⟩
  if refused.contains key then
    within Fetch.fetchError (Trie.Fetch.abandon target)
    return ⟨⟨.refused, none, none⟩, false⟩
  let result ← Fetch.attempt (within Fetch.fetchError (Trie.Fetch.fetch (Std.HashSet Trie.Missing.Visit)
    (Std.HashSet ByteArray) target reference maximum retryLimit))
  settle origin refused target key result

theorem fetch_decomposes (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
    (refused : List (UInt64 × ByteArray × ByteArray)) (maximum retryLimit : Nat) :
    Fetch.fetch origin expected refused maximum retryLimit =
      (select origin expected >>= selected origin refused maximum retryLimit) := rfl

def allowed (row : Fields) (A : Type) : Fetch.Effects A → Prop
  | .left effect => RetirementProtection.allowed row _ effect
  | .right _ => True

theorem effects_retain (row : Fields) (effect : Fetch.Effects A) (safe : allowed row _ effect)
    (state : State) (kept : ProtectedHead.retained row state) :
    ProtectedHead.retained row (Interpreter.handle effect state).2 := by
  cases effect with
  | left effect => exact RetirementProtection.effects_retain row effect safe state kept
  | right effect =>
    cases effect <;> apply ProtectedHead.reply_retains _ _ _ _ _ _ kept <;> intro s h <;> split <;> exact h

theorem promote_read (row : Fields) (operation : Promote.Action A)
    (safe : Only PromotionReads.allowed operation.run) :
    Only (RetirementProtection.allowed row) operation.run := by
  apply safe.mono
  intro B effect good
  cases effect with
  | left effect =>
    cases effect with
    | left effect => cases effect <;> first | contradiction | trivial
    | right effect =>
      cases effect with
      | left _ => trivial
      | right effect =>
        cases effect with
        | left effect => cases effect <;> first | contradiction | trivial
        | right _ => trivial
  | right _ => trivial

theorem lift_only (row : Fields) (operation : Promote.Action A)
    (safe : Only (RetirementProtection.allowed row) operation.run) :
    Only (allowed row) (Fetch.lift operation).run := by
  apply Only.within _ _ safe
  intro B effect good
  rcases effect with effect | effect
  · rcases effect with effect | effect
    · cases effect <;> exact good
    · rcases effect with effect | effect
      · cases effect <;> exact good
      · rcases effect with effect | effect
        · cases effect <;> exact good
        · rcases effect with effect | effect
          · cases effect <;> exact good
          · rcases effect with effect | effect
            · cases effect <;> exact good
            · cases effect <;> exact good
  · cases effect <;> exact good

theorem select_only (row : Fields) (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray)) :
    Only (allowed row) (select origin expected).run := by
  unfold select
  apply lift_only
  apply Only.transaction _ _ _ trivial (fun _ => trivial) (fun _ => trivial)
  intro tx
  refine (promote_read row _ (PromotionReads.slot_only tx origin "pending")).seq fun pending => ?_
  cases pending with
  | none => exact .done _
  | some pending =>
    dsimp only
    split
    · exact .done _
    · refine Only.seq (Only.raise _ _ trivial) fun now => ?_
      refine (promote_read row _ (PromotionReads.auth_only _ (ReconciliationReadOnly.scope_only tx origin))).seq fun scope => ?_
      refine (promote_read row _ (PromotionReads.slot_only tx origin "complete")).seq fun old => ?_
      exact (promote_read row _ (PromotionReads.auth_only _ (ReconciliationReadOnly.originAuthority_only tx origin now))).seq fun _ => .done _

theorem trie_mapped (row : Fields) (effect : Trie.Fetch.Effects A)
    (safe : FetchHeadSafety.allowed row _ effect) : allowed row _ (Inject.inject effect) := by
  cases effect with
  | left effect =>
    cases effect with
    | left effect => cases effect <;> exact safe
    | right effect =>
      cases effect with
      | left effect => cases effect <;> exact safe
      | right effect => cases effect; trivial
  | right effect =>
    cases effect with
    | left effect => cases effect <;> trivial
    | right effect =>
      cases effect with
      | left effect => cases effect <;> trivial
      | right effect => cases effect <;> trivial

theorem abandon_only (row : Fields) (target : Trie.Fetch.Target)
    (different : equals row (Trie.Fetch.targetRows target) = false) :
    Only (allowed row) (within Fetch.fetchError (Trie.Fetch.abandon target) : Fetch.Action Unit).run :=
  Only.within _ _ (FetchHeadSafety.abandon_only row target different) (trie_mapped row)

/-- The entire non-publication settlement, not just its delete helper, cannot
touch a newer target. Faults and malformed-origin refusals are included. -/
theorem settle_without_publication (row : Fields) (origin : Origin.Parsed)
    (refused : List (UInt64 × ByteArray × ByteArray)) (target : Trie.Fetch.Target)
    (key : UInt64 × ByteArray × ByteArray) (result : Except Promote.Error Bool)
    (notComplete : result ≠ .ok true) (different : equals row (Trie.Fetch.targetRows target) = false) :
    Only (allowed row) (settle origin refused target key result).run := by
  unfold settle
  cases result with
  | ok result => cases result <;> first | exact .done _ | exact False.elim (notComplete rfl)
  | error error =>
    cases error with
    | host _ => exact .done _
    | domain error =>
      dsimp only
      split
      · exact (abandon_only row target different).seq fun _ => .done _
      · exact .done _

theorem promote_agrees (effect : Promote.Effects A) (state : State) :
    Interpreter.handle (Inject.inject effect : Fetch.Effects A) state = Interpreter.handle effect state := by
  rcases effect with effect | effect
  · rcases effect with effect | effect
    · cases effect <;> rfl
    · rcases effect with effect | effect
      · cases effect <;> rfl
      · rcases effect with effect | effect
        · cases effect <;> rfl
        · rcases effect with effect | effect
          · cases effect <;> rfl
          · rcases effect with effect | effect
            · cases effect <;> rfl
            · cases effect <;> rfl
  · cases effect <;> rfl

/-- A delayed successful fetch never publishes its captured head or scope.
Its actual publication is a newly executed promote on the current database. -/
theorem completed_fetch_rechecks (origin : Origin.Parsed) (refused : List (UInt64 × ByteArray × ByteArray))
    (target : Trie.Fetch.Target) (key : UInt64 × ByteArray × ByteArray)
    (state final : State) (report : FetchReport)
    (executed : execute (settle origin refused target key (.ok true)) state = (.ok report, final)) :
    ∃ now current result,
      execute (raise Promote.Error.host Clock.nowNs : Fetch.Action Int64) state = (.ok now, current) ∧
      execute (Promote.promote origin now refused) current = (.ok result, final) ∧
      report = ⟨result, false⟩ := by
  unfold settle at executed
  obtain ⟨now, current, clockRead, executed⟩ := TransactionSuccess.bind_success _ _ _ _ _ executed
  obtain ⟨result, promoted, publication, returned⟩ := TransactionSuccess.bind_success _ _ _ _ _ executed
  have same : (⟨result, false⟩ : FetchReport) = report := Except.ok.inj (congrArg Prod.fst returned)
  have finalSame : promoted = final := congrArg Prod.snd returned
  subst promoted
  exact ⟨now, current, result, clockRead,
    OperationExecution.within_success promote_agrees id _ current final result publication, same.symm⟩

/-- A certificate with just two kinds of work: effects that retain the row,
and a terminal call of the real, fresh promotion command. It does not assume
that a policy callback protects the row; the primitive certificate is checked
against raw storage, and the publication constructor names production code. -/
inductive UntilPromotion (row : Fields) (origin : Origin.Parsed)
    (refused : List (UInt64 × ByteArray × ByteArray)) : Program Fetch.Effects (Except Promote.Error FetchReport) → Prop where
  | safe {program} : Only (allowed row) program → UntilPromotion row origin refused program
  | prelude {B : Type} {program : Program Fetch.Effects B}
      {next : B → Program Fetch.Effects (Except Promote.Error FetchReport)} :
      Only (allowed row) program → (∀ value, UntilPromotion row origin refused (next value)) →
      UntilPromotion row origin refused (program.bind next)
  | fresh (now : Int64) :
      UntilPromotion row origin refused (do
        let report ← Fetch.lift (Promote.promote origin now refused)
        return (⟨report, false⟩ : FetchReport) : Fetch.Action FetchReport).run

theorem UntilPromotion.seq {operation : Fetch.Action A} {next : A → Fetch.Action FetchReport}
    (head : Only (allowed row) operation.run)
    (tail : ∀ value, UntilPromotion row origin refused (next value).run) :
    UntilPromotion row origin refused (operation >>= next).run := by
  apply UntilPromotion.prelude head
  intro result
  cases result with
  | error _ => exact .safe (.done _)
  | ok value => exact tail value

theorem settle_phases (row : Fields) (origin : Origin.Parsed)
    (refused : List (UInt64 × ByteArray × ByteArray)) (target : Trie.Fetch.Target)
    (key : UInt64 × ByteArray × ByteArray) (result : Except Promote.Error Bool)
    (different : equals row (Trie.Fetch.targetRows target) = false) :
    UntilPromotion row origin refused (settle origin refused target key result).run := by
  by_cases complete : result = .ok true
  · subst result
    exact UntilPromotion.seq (Only.raise _ _ trivial) fun now => .fresh now
  · exact .safe (settle_without_publication row origin refused target key result complete different)

/-- All work after selection either retains every noncaptured row, or passes
control to a new promotion. This covers cached refusal, arbitrary requester
outcomes, clock errors and the entire outer error adapter. -/
theorem selected_phases (row : Fields) (origin : Origin.Parsed)
    (refused : List (UInt64 × ByteArray × ByteArray)) (maximum retryLimit : Nat)
    (pending : Promote.Pending) (old : Option Promote.Pending) (scope : Trie.Serve.Scope) (owner : Option Origin.Parsed)
    (different : equals row (Trie.Fetch.targetRows
      ⟨pending.head.root, Origin.canonical origin, pending.head.seq, ⟨scope, owner.map Origin.canonical⟩⟩) = false) :
    UntilPromotion row origin refused (selected origin refused maximum retryLimit (some (pending, old, scope, owner))).run := by
  unfold selected
  dsimp only
  split
  · exact .safe ((abandon_only row _ different).seq fun _ => .done _)
  · apply UntilPromotion.seq
    · exact (Only.within _ _ (FetchHeadSafety.fetch_only _ _ row _ different _ maximum retryLimit)
        (trie_mapped row)).bind fun _ => .done _
    · intro result
      exact settle_phases row origin refused _ _ result different

/-- An actual execution that changes a noncaptured row must have reached a
fresh promotion, with that row still present immediately before promotion.
This is an execution theorem for the above production-program decomposition,
not merely a syntactic occurrence of a call somewhere in the source. -/
theorem UntilPromotion.loss_requires_fresh {program : Program Fetch.Effects (Except Promote.Error FetchReport)}
    (phases : UntilPromotion row origin refused program) (state : State) (kept : ProtectedHead.retained row state)
    (lost : row ∉ rows (execute program state).2.db "heads") :
    ∃ now current,
      ProtectedHead.retained row current ∧
      (execute (Promote.promote origin now refused) current).2 = (execute program state).2 ∧
      row ∉ rows (execute (Promote.promote origin now refused) current).2.db "heads" := by
  induction phases generalizing state with
  | safe safe =>
    exact False.elim (lost ((safe.invariant (ProtectedHead.retained row) (effects_retain row) state kept).1))
  | prelude safe rest ih =>
    rw [execute_bind] at lost
    simpa only [execute_bind] using
      ih _ _ (safe.invariant (ProtectedHead.retained row) (effects_retain row) state kept) lost
  | fresh now =>
    have same : (execute (do
        let report ← Fetch.lift (Promote.promote origin now refused)
        return (⟨report, false⟩ : FetchReport) : Fetch.Action FetchReport).run state).2 =
        (execute (Promote.promote origin now refused) state).2 := by
      simp only [bind, ExceptT.bind, ExceptT.run, ExceptT.mk, execute_bind, Fetch.lift]
      rw [OperationExecution.within_eq promote_agrees]
      generalize executed : execute (Promote.promote origin now refused) state = result
      obtain ⟨result, final⟩ := result
      cases result <;> rfl
    exact ⟨now, state, kept, same.symm, by rwa [same] at lost⟩

theorem complete_different (row : Fields) (origin : String)
    (complete : ReconciliationSlots.names row origin "complete" = true) (target : Trie.Fetch.Target) :
    equals row (Trie.Fetch.targetRows target) = false := by
  have different := PromotionBound.complete_not_pending row origin complete target.origin
  simp only [equals, List.all_cons, List.all_nil, Bool.and_true] at different
  simp only [Trie.Fetch.targetRows, equals, List.all_cons, List.all_nil, Bool.and_true]
  cases originSame : isCell (cell row "origin_id") (.text target.origin) <;> simp_all

/-- Whole outer command, from before selection through every error branch. -/
theorem fetch_complete_phases (row : Fields) (rowOrigin : String)
    (complete : ReconciliationSlots.names row rowOrigin "complete" = true)
    (origin : Origin.Parsed) (expected : Option (UInt64 × ByteArray))
    (refused : List (UInt64 × ByteArray × ByteArray)) (maximum retryLimit : Nat) :
    UntilPromotion row origin refused (Fetch.fetch origin expected refused maximum retryLimit).run := by
  rw [fetch_decomposes]
  apply UntilPromotion.seq (select_only row origin expected)
  intro selection
  cases selection with
  | none => exact .safe (.done _)
  | some selection =>
    obtain ⟨pending, old, scope, owner⟩ := selection
    exact selected_phases row origin refused maximum retryLimit pending old scope owner
      (complete_different row rowOrigin complete _)

end Synchronicity.FetchLifecycle
