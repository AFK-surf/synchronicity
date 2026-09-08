import Synchronicity.SimulatedHost

/-! Program-side certificates for transaction-private database work. The
certificate is proved from requests, not supplied as a host policy oracle. -/
namespace Synchronicity.PrivateDatabase
open VerifiedCore.Host SimulatedHost

variable {E F : Type → Type} {A B ε : Type}

inductive Only {E : Type → Type} (allowed : (B : Type) → E B → Prop) {A : Type} : Program E A → Prop where
  | done (value : A) : Only allowed (.pure value)
  | request {B : Type} {effect : E B} {next : B → Program E A}
      (safe : allowed B effect) (rest : ∀ reply, Only allowed (next reply)) :
      Only allowed (.request effect next)

variable {allowed : (B : Type) → E B → Prop}

theorem Only.mono {target : (B : Type) → E B → Prop} {program : Program E A}
    (safe : Only allowed program) (implies : ∀ {B} (effect : E B), allowed _ effect → target _ effect) :
    Only target program := by
  induction safe with
  | done value => exact .done value
  | request good rest ih => exact .request (implies _ good) ih

theorem Only.bind {program : Program E A} {next : A → Program E B}
    (head : Only allowed program) (tail : ∀ value, Only allowed (next value)) :
    Only allowed (program.bind next) := by
  induction head with
  | done value => exact tail value
  | request safe rest ih => exact .request safe ih

theorem Only.seq {operation : OperationOver E ε A} {next : A → OperationOver E ε B}
    (head : Only allowed operation.run) (tail : ∀ value, Only allowed (next value).run) :
    Only allowed (operation >>= next).run := by
  apply head.bind
  intro result
  cases result with
  | error _ => exact .done _
  | ok value => exact tail value

theorem Only.map (operation : OperationOver E ε A) (f : A → B)
    (safe : Only allowed operation.run) : Only allowed (f <$> operation).run := by
  apply safe.bind
  intro result
  cases result <;> exact .done _

theorem Only.raise [Inject F E] (error : Failure → ε) (effect : F (Reply A))
    (safe : allowed _ (Inject.inject effect)) : Only allowed (raise (F := E) error effect).run :=
  .request safe fun _ => .done _

theorem Only.mapEffects {target : (B : Type) → F B → Prop}
    (program : Program E A) (inject : {B : Type} → E B → F B)
    (head : Only allowed program) (safe : ∀ {B} (effect : E B), allowed _ effect → target _ (inject effect)) :
    Only target (program.mapEffects inject) := by
  induction head with
  | done value => exact .done value
  | request good rest ih => exact .request (safe _ good) ih

theorem Only.within [Inject E F] {target : (B : Type) → F B → Prop}
    (operation : OperationOver E ε A) (translate : ε → δ)
    (head : Only allowed operation.run)
    (safe : ∀ {B} (effect : E B), allowed _ effect → target _ (Inject.inject effect)) :
    Only target (within translate operation : OperationOver F δ A).run := by
  exact (head.mapEffects operation.run Inject.inject safe).bind fun _ => .done _

theorem Only.mapM (items : List A) (f : A → OperationOver E ε B)
    (safe : ∀ a, Only allowed (f a).run) : Only allowed (items.mapM f).run := by
  suffices ∀ acc, Only allowed (List.mapM.loop f items acc).run from this []
  intro acc
  induction items generalizing acc with
  | nil => exact .done _
  | cons item rest ih => exact (safe item).seq fun _ => ih _

theorem Only.foldlM (items : List A) (f : B → A → OperationOver E ε B)
    (safe : ∀ b a, Only allowed (f b a).run) (initial : B) :
    Only allowed (items.foldlM f initial).run := by
  induction items generalizing initial with
  | nil => exact .done _
  | cons item rest ih => exact (safe initial item).seq fun next => ih next

theorem Only.forIn (items : List A) (f : A → B → OperationOver E ε (ForInStep B))
    (safe : ∀ a b, Only allowed (f a b).run) (initial : B) :
    Only allowed (forIn items initial f).run := by
  induction items generalizing initial with
  | nil => exact .done _
  | cons item rest ih =>
    rw [List.forIn_cons]
    apply (safe item initial).seq
    intro step
    cases step with
    | done _ => exact .done _
    | yield next => exact ih next

theorem Only.preserves_observation [Interpreter E] (observe : State → O)
    (program : Program E A) (safe : Only allowed program)
    (effects : ∀ {B} (e : E B), allowed _ e → ∀ state,
      observe (Interpreter.handle e state).2 = observe state)
    (state : State) : observe (execute program state).2 = observe state := by
  induction safe generalizing state with
  | done _ => rfl
  | request good rest ih =>
    simp only [execute]
    exact (ih _ _).trans (effects _ good state)

theorem Only.iterate (body : S → OperationOver E ε (S ⊕ A)) (error : ε) (fuel : Nat)
    (safe : ∀ s, Only allowed (body s).run) (start : S) :
    Only allowed (OperationOver.iterate body error fuel start).run := by
  have loop (n : Nat) (program : Program E (Except ε (S ⊕ A))) (good : Only allowed program) :
      Only allowed (Program.iterate (fun s => (body s).run) error n program) := by
    induction n generalizing program with
    | zero => exact .done _
    | succ n ih =>
      cases good with
      | done value =>
        cases value with
        | error _ => exact .done _
        | ok result =>
          cases result with
          | inr _ => exact .done _
          | inl s => exact ih _ (safe s)
      | request good rest => exact .request good fun reply => ih _ (rest reply)
  exact loop fuel _ (safe start)

/-- The only raw storage operation that can replace committed rows is commit.
All other writes are confined to the private transaction database. -/
def storagePrivate : Storage A → Prop
  | .commit _ => False
  | _ => True

theorem reply_preserves_db (state : State) (event : String) (action : State → Result (Reply A))
    (consume : Bool) (kept : ∀ s, (action s).2.db = s.db) :
    (reply state event action consume).2.db = state.db := by
  unfold reply
  split
  · cases consume <;> simp [record, kept]
  · simp [record, kept]

theorem transaction_preserves_db (state : State) (tx : Transaction) (action : Database → A × Database) :
    (SimulatedHost.transaction state tx action).2.db = state.db := by
  unfold SimulatedHost.transaction
  split
  · split <;> rfl
  · rfl

theorem storage_preserves_db (effect : Storage A) (kept : storagePrivate effect) (state : State) :
    (storage effect state).2.db = state.db := by
  cases effect <;> simp only [storage]
  all_goals first
    | contradiction
    | (apply reply_preserves_db; intro s)
  all_goals first
    | exact transaction_preserves_db _ _ _
    | rfl
    | (repeat' first | split | rfl)

/-- A certified program cannot expose any of its partial database work,
including on an error path. The initial database and all replies are arbitrary. -/
theorem Only.preserves_db [Interpreter E] (program : Program E A) (safe : Only allowed program)
    (effects : ∀ {B} (e : E B), allowed _ e → ∀ state, (Interpreter.handle e state).2.db = state.db)
    (state : State) : (execute program state).2.db = state.db := by
  induction safe generalizing state with
  | done _ => rfl
  | request good rest ih =>
    simp only [execute]
    exact (ih _ _).trans (effects _ good state)

/-- An arbitrary finite execution prefix, including a stop before the next
request. This observes intermediate states, not merely the final result. -/
inductive Prefix {E : Type → Type} [Interpreter E] {A : Type} :
    Program E A → State → Program E A → State → Prop where
  | refl (program : Program E A) (state : State) : Prefix program state program state
  | step {B : Type} {effect : E B} {resume : B → Program E A}
      {state final : State} {tail : Program E A}
      (rest : Prefix (resume (Interpreter.handle effect state).1)
        (Interpreter.handle effect state).2 tail final) :
      Prefix (.request effect resume) state tail final

theorem Only.preserves_prefix [Interpreter E] {program tail : Program E A} {state final : State}
    (safe : Only allowed program) (path : Prefix program state tail final)
    (effects : ∀ {B} (e : E B), allowed _ e → ∀ state, (Interpreter.handle e state).2.db = state.db) :
    final.db = state.db := by
  induction path with
  | refl => rfl
  | @step B effect resume state final tail rest ih =>
    cases safe with
    | request good replies => exact (ih (replies _)).trans (effects effect good state)

end Synchronicity.PrivateDatabase
