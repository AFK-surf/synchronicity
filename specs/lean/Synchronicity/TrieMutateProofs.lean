import VerifiedCore.Trie.Mutate
import Synchronicity.TrieVerifyProofs
import Synchronicity.TrieProgramProofs

/-! The trie write path, as executed: what it stores under an address is the
canonical image that address covers, every node it builds is one the ingress
boundary admits at every peer, and the bounds every reader shares are
refused before a byte is borrowed or an effect requested. -/
namespace Synchronicity.TrieMutateProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open Synchronicity.TrieCodecProofs Synchronicity.TrieVerifyProofs

/-! ## The executable shape of the write monad -/

@[simp] theorem mapError_ok (f : ε → ε') (a : α) : Except.mapError f (.ok a : Except ε α) = .ok a := rfl
@[simp] theorem mapError_error (f : ε → ε') (e : ε) :
    Except.mapError f (.error e : Except ε α) = .error (f e) := rfl
@[simp] theorem run_bind (m : Mutate A) (k : A → Mutate B) :
    (m >>= k).run = m.run >>= ExceptT.bindCont k := rfl
@[simp] theorem program_bind_request (e : MutateEffects R) (next : R → Program MutateEffects A)
    (f : A → Program MutateEffects B) :
    (Program.request e next >>= f) = .request e (fun r => next r >>= f) := rfl
@[simp] theorem program_bind_pure (a : A) (f : A → Program MutateEffects B) :
    (Program.pure a >>= f) = f a := rfl
@[simp] theorem program_pure_eq (a : A) : (pure a : Program MutateEffects A) = .pure a := rfl
@[simp] theorem bindCont_ok (k : A → Mutate B) (a : A) :
    ExceptT.bindCont k (.ok a) = (k a).run := rfl
@[simp] theorem bindCont_error (k : A → Mutate B) (e : Error) :
    ExceptT.bindCont k (.error e) = .pure (.error e) := rfl
@[simp] theorem run_pure (a : A) : (pure a : Mutate A).run = .pure (.ok a) := rfl
@[simp] theorem run_throw (e : Error) : (throw e : Mutate A).run = .pure (.error e) := rfl
@[simp] theorem run_ite (c : Prop) [Decidable c] (t e : Mutate A) :
    (if c then t else e).run = if c then t.run else e.run := by split <;> rfl
@[simp] theorem read_run (space : String) (key : ByteArray) :
    (request (Storage.readBytes space key) : Mutate (Option ByteArray)).run =
      .request (.left (.readBytes space key)) (fun r => .pure (r.mapError Error.host)) := rfl
@[simp] theorem digest_run (bytes : ByteArray) :
    (request (Digest.blake3 bytes) : Mutate ByteArray).run =
      .request (.right (.left (.blake3 bytes))) (fun r => .pure (r.mapError Error.host)) := rfl
@[simp] theorem write_run (space : String) (key bytes : ByteArray) :
    (request (ByteWrites.putBytes space key bytes) : Mutate Unit).run =
      .request (.right (.right (.putBytes space key bytes)))
        (fun r => .pure (r.mapError Error.host)) := rfl
@[simp] theorem input_run (handle offset size : UInt64) :
    (request (Storage.readInput handle offset size) : Mutate ByteArray).run =
      .request (.left (.readInput handle offset size)) (fun r => .pure (r.mapError Error.host)) := rfl

/-! ## What a store write is

`put` asks for the digest of the tagged canonical image and stores exactly
that image under the digest: the bytes a peer will later be served, and the
bytes the boundary re-encodes. -/

theorem put_requests_tagged_digest (n : Node) :
    (put n).run = .request (.right (.left (.blake3 (tagOf n ++ encode n))))
      (fun
        | .error failure => .pure (.error (.host failure))
        | .ok hash => .request (.right (.right (.putBytes nodeSpace hash (encode n))))
          (fun
            | .error failure => .pure (.error (.host failure))
            | .ok () => .pure (.ok hash))) := by
  simp only [put, run_bind, digest_run, program_bind_request, program_bind_pure]
  congr 1
  funext reply
  cases reply with
  | error failure => simp
  | ok hash =>
    simp only [mapError_ok, bindCont_ok, run_bind, write_run, program_bind_request,
      program_bind_pure]
    congr 1
    funext reply
    cases reply with
    | error failure => simp
    | ok u => cases u; simp

/-- Every node the write path stores, the ingress boundary admits, and as
the same node: canonical image, within the key bound, invariants intact. -/
theorem stored_nodes_are_admitted {n : Node} (wf : n.wf) (within : nibbleRun n ≤ maxKeyBytes * 2)
    (invariants : checkInvariants n = .ok ()) : admit (encode n) = .ok n :=
  admit_encode wf within invariants

/-! ## Bounds are refused before any effect

An oversized key or value never borrows an input, never hashes, never reads
and never writes: the whole operation is its refusal. -/

theorem insertInput_refuses_oversized_key (root : ByteArray) (keySize valueSize : UInt64)
    (over : keySize.toNat > maxKeyBytes) :
    (insertInput root keySize valueSize).run =
      .pure (.error (.domain (.keyTooLong keySize.toNat))) := by
  simp [insertInput, over]

theorem insertInput_refuses_oversized_value (root : ByteArray) (keySize valueSize : UInt64)
    (within : ¬ keySize.toNat > maxKeyBytes) (over : valueSize.toNat > maxValueBytes) :
    (insertInput root keySize valueSize).run =
      .pure (.error (.domain (.valueTooLong valueSize.toNat))) := by
  simp [insertInput, within, over]

theorem removeInput_refuses_oversized_key (root : ByteArray) (keySize : UInt64)
    (over : keySize.toNat > maxKeyBytes) :
    (removeInput root keySize).run = .pure (.error (.domain (.keyTooLong keySize.toNat))) := by
  simp [removeInput, over]

theorem insert_refuses_oversized_key (root key value : ByteArray) (over : key.size > maxKeyBytes) :
    (insert root key value).run = .pure (.error (.domain (.keyTooLong key.size))) := by
  simp [Trie.insert, over]

theorem insert_refuses_oversized_value (root key value : ByteArray)
    (within : ¬ key.size > maxKeyBytes) (over : value.size > maxValueBytes) :
    (insert root key value).run = .pure (.error (.domain (.valueTooLong value.size))) := by
  simp [Trie.insert, within, over]

theorem remove_refuses_oversized_key (root key : ByteArray) (over : key.size > maxKeyBytes) :
    (remove root key).run = .pure (.error (.domain (.keyTooLong key.size))) := by
  simp [remove, over]

/-- The key is the same bound lookup enforces, in the same unit. -/
theorem write_bound_is_lookup_bound : maxKeyBytes = 4096 := rfl

/-- Removing from the empty trie touches nothing and answers the empty root. -/
theorem remove_from_empty (root key : ByteArray) (within : ¬ key.size > maxKeyBytes)
    (empty : isEmptyRoot root = true) :
    (remove root key).run = .pure (.ok emptyRoot) := by
  simp [remove, within, empty]

/-- Admitted inputs are borrowed in order, key then value, each checked for
its exact size before the next is asked for. -/
theorem insertInput_reads_key_first (root : ByteArray) (keySize valueSize : UInt64)
    (key : ¬ keySize.toNat > maxKeyBytes) (value : ¬ valueSize.toNat > maxValueBytes) :
    (insertInput root keySize valueSize).run = .request (.left (.readInput 0 0 keySize))
      (fun
        | .error failure => .pure (.error (.host failure))
        | .ok bytes =>
          if bytes.size != keySize.toNat then .pure (.error (.host ⟨3, 0⟩))
          else .request (.left (.readInput 1 0 valueSize))
            (fun
              | .error failure => .pure (.error (.host failure))
              | .ok payload =>
                if payload.size != valueSize.toNat then .pure (.error (.host ⟨3, 0⟩))
                else (insert root bytes payload).run)) := by
  simp only [insertInput, key, value, readMutationInput, run_bind, input_run,
    program_bind_request, program_bind_pure, ↓reduceIte]
  congr 1
  funext reply
  cases reply with
  | error failure => simp
  | ok bytes =>
    simp only [mapError_ok, bindCont_ok, run_bind, run_ite, run_throw, run_pure,
      program_bind_pure]
    split
    · simp
    · simp only [bindCont_ok, run_bind, input_run, program_bind_request, program_bind_pure]
      congr 1
      funext reply
      cases reply with
      | error failure => simp
      | ok payload =>
        simp only [mapError_ok, bindCont_ok, run_bind, run_ite, run_throw, run_pure,
          program_bind_pure]
        split <;> simp

/-! ## Execution against a content-addressed store

A store maps addresses to bytes in two namespaces; a digest is one function
of the bytes. The interpreter is structural on the program, so composition
laws need no fuel: a read answers the store, a digest answers the function,
a write extends the store, and a borrowed input is refused (the core write
programs never ask for one). -/

structure Store where
  nodes : List (ByteArray × ByteArray) := []
  values : List (ByteArray × ByteArray) := []

def Store.lookup (entries : List (ByteArray × ByteArray)) (key : ByteArray) : Option ByteArray :=
  (entries.find? (·.1 == key)).map (·.2)

def Store.read (s : Store) (space : String) (key : ByteArray) : Option ByteArray :=
  if space == nodeSpace then Store.lookup s.nodes key
  else if space == valueSpace then Store.lookup s.values key
  else none

def Store.write (s : Store) (space : String) (key bytes : ByteArray) : Store :=
  if space == nodeSpace then { s with nodes := (key, bytes) :: s.nodes }
  else if space == valueSpace then { s with values := (key, bytes) :: s.values }
  else s

def execute (d : ByteArray → ByteArray) (s : Store) : Program MutateEffects A → Option (A × Store)
  | .pure result => some (result, s)
  | .request (.left (.readBytes space key)) next => execute d s (next (.ok (s.read space key)))
  | .request (.right (.left (.blake3 bytes))) next => execute d s (next (.ok (d bytes)))
  | .request (.right (.right (.putBytes space key bytes))) next =>
    execute d (s.write space key bytes) (next (.ok ()))
  | .request (.left _) _ => none

@[simp] theorem execute_pure (d : ByteArray → ByteArray) (s : Store) (result : A) :
    execute d s (.pure result) = some (result, s) := rfl
@[simp] theorem execute_read (d : ByteArray → ByteArray) (s : Store) (space : String)
    (key : ByteArray) (next : Reply (Option ByteArray) → Program MutateEffects A) :
    execute d s (.request (.left (.readBytes space key)) next) =
      execute d s (next (.ok (s.read space key))) := rfl
@[simp] theorem execute_digest (d : ByteArray → ByteArray) (s : Store) (bytes : ByteArray)
    (next : Reply ByteArray → Program MutateEffects A) :
    execute d s (.request (.right (.left (.blake3 bytes))) next) =
      execute d s (next (.ok (d bytes))) := rfl
@[simp] theorem execute_write (d : ByteArray → ByteArray) (s : Store) (space : String)
    (key bytes : ByteArray) (next : Reply Unit → Program MutateEffects A) :
    execute d s (.request (.right (.right (.putBytes space key bytes))) next) =
      execute d (s.write space key bytes) (next (.ok ())) := rfl

/-- Execution composes: run the first program, then the continuation from
the store it left. -/
theorem execute_bind (d : ByteArray → ByteArray) (s : Store) (m : Program MutateEffects A)
    (f : A → Program MutateEffects B) :
    execute d s (m >>= f) = match execute d s m with
      | none => none
      | some (a, s') => execute d s' (f a) := by
  induction m generalizing s with
  | pure a => rfl
  | request effect next ih =>
    cases effect with
    | left storage =>
      cases storage <;> first
        | exact rfl
        | (show execute d s (.request (.left _) _) = _; simp only [execute_read]; exact ih _ s)
    | right effect =>
      cases effect with
      | left digest => cases digest; simp only [program_bind_request, execute_digest]; exact ih _ s
      | right write => cases write; simp only [program_bind_request, execute_write]; exact ih _ _

/-- The same law for an operation with its error channel. -/
theorem execute_run_bind (d : ByteArray → ByteArray) (s : Store) (m : Mutate A) (k : A → Mutate B) :
    execute d s (m >>= k).run = match execute d s m.run with
      | none => none
      | some (.error e, s') => some (.error e, s')
      | some (.ok a, s') => execute d s' (k a).run := by
  rw [run_bind, execute_bind]
  cases execute d s m.run with
  | none => rfl
  | some result =>
    obtain ⟨reply, s'⟩ := result
    cases reply <;> rfl

theorem execute_put (d : ByteArray → ByteArray) (s : Store) (n : Node) :
    execute d s (put n).run =
      some (.ok (d (tagOf n ++ encode n)), s.write nodeSpace (d (tagOf n ++ encode n)) (encode n)) := by
  rw [put_requests_tagged_digest]
  rfl


/-! ## Canonical form is maintained

A node image is canonical when it is an encoder image of a well-formed node
that satisfies the structural invariants: exactly what the ingress boundary
admits, apart from the key bound, which is a property of whole paths rather
than of one node. A store is shaped when every node it holds is canonical.
The write path only ever stores canonical nodes, so a shaped store stays
shaped through every insert and remove. -/

def Canonical (raw : ByteArray) : Prop :=
  ∃ n : Node, decode raw = .ok n ∧ encode n = raw ∧ n.wf ∧ checkInvariants n = .ok ()

def Shaped (s : Store) : Prop :=
  ∀ key raw, s.read nodeSpace key = some raw → Canonical raw

theorem canonical_encode {n : Node} (wf : n.wf) (invariants : checkInvariants n = .ok ()) :
    Canonical (encode n) :=
  ⟨n, decode_encode wf, rfl, wf, invariants⟩

theorem read_write_node (s : Store) (key bytes probe : ByteArray) :
    (s.write nodeSpace key bytes).read nodeSpace probe =
      if key == probe then some bytes else s.read nodeSpace probe := by
  simp only [Store.write, Store.read, beq_self_eq_true, ↓reduceIte, Store.lookup, List.find?_cons]
  split <;> simp_all

theorem read_write_value (s : Store) (key bytes probe : ByteArray) :
    (s.write valueSpace key bytes).read nodeSpace probe = s.read nodeSpace probe := by
  simp [Store.write, Store.read, nodeSpace, valueSpace]

theorem shaped_write_node {s : Store} (shaped : Shaped s) {key bytes : ByteArray}
    (canonical : Canonical bytes) : Shaped (s.write nodeSpace key bytes) := by
  intro probe raw held
  rw [read_write_node] at held
  split at held
  · cases held; exact canonical
  · exact shaped probe raw held

theorem shaped_write_value {s : Store} (shaped : Shaped s) (key bytes : ByteArray) :
    Shaped (s.write valueSpace key bytes) := by
  intro probe raw held
  rw [read_write_value] at held
  exact shaped probe raw held

/-- Storing a well-formed node that satisfies the invariants keeps the store
shaped, and answers the digest of its tagged image. -/
theorem put_preserves (d : ByteArray → ByteArray) {s : Store} (shaped : Shaped s) {n : Node}
    (wf : n.wf) (invariants : checkInvariants n = .ok ()) {result : Except Error ByteArray}
    {s' : Store} (ran : execute d s (put n).run = some (result, s')) :
    Shaped s' ∧ result = .ok (d (tagOf n ++ encode n)) := by
  rw [execute_put] at ran
  cases ran
  exact ⟨shaped_write_node shaped (canonical_encode wf invariants), rfl⟩


/-! ### Nibbles, prefixes and children -/

/-- Octets inside the radix-16 alphabet. -/
def Nibbles (ns : List UInt8) : Prop := ∀ n ∈ ns, n.toNat ≤ 15

theorem nibbles_nil : Nibbles [] := fun _ h => nomatch h

theorem nibbles_of_nibblesWf {ns : ByteArray} (wf : nibblesWf ns) : Nibbles ns.data.toList := wf.2

theorem nibbles_drop {ns : List UInt8} (h : Nibbles ns) (k : Nat) : Nibbles (ns.drop k) :=
  fun n mem => h n (List.mem_of_mem_drop mem)

theorem nibbles_take {ns : List UInt8} (h : Nibbles ns) (k : Nat) : Nibbles (ns.take k) :=
  fun n mem => h n (List.mem_of_mem_take mem)

theorem nibbles_append {a b : List UInt8} (ha : Nibbles a) (hb : Nibbles b) : Nibbles (a ++ b) :=
  fun n mem => (List.mem_append.mp mem).elim (ha n) (hb n)

theorem nibbles_tail {n : UInt8} {ns : List UInt8} (h : Nibbles (n :: ns)) : Nibbles ns :=
  fun m mem => h m (List.mem_cons_of_mem n mem)

theorem nibbles_head {n : UInt8} {ns : List UInt8} (h : Nibbles (n :: ns)) : n.toNat ≤ 15 :=
  h n (List.mem_cons_self ..)

theorem nibbles_keyNibbles (key : ByteArray) : Nibbles (keyNibbles key) := by
  intro n mem
  simp only [keyNibbles, List.mem_flatMap] at mem
  obtain ⟨b, _, mem⟩ := mem
  simp only [List.mem_cons, List.not_mem_nil, or_false] at mem
  have sixteen : (16 : UInt8).toNat = 16 := rfl
  have small : b.toNat < 256 := b.toNat_lt
  rcases mem with rfl | rfl
  · rw [UInt8.toNat_div, sixteen]; omega
  · rw [UInt8.toNat_mod, sixteen]; omega

theorem nibblesOf_wf {ns : List UInt8} (nib : Nibbles ns) (small : ns.length < 2 ^ 64) :
    nibblesWf (nibblesOf ns) := by
  refine ⟨?_, fun n mem => nib n ?_⟩
  · simpa [nibblesOf, ByteArray.size] using small
  · simpa [nibblesOf] using mem

theorem commonPrefix_le_left (a b : List UInt8) : commonPrefix a b ≤ a.length := by
  induction a generalizing b with
  | nil => simp [commonPrefix]
  | cons x xs ih =>
    cases b with
    | nil => simp [commonPrefix]
    | cons y ys =>
      simp only [commonPrefix, List.length_cons]
      split
      · exact Nat.succ_le_succ (ih ys)
      · exact Nat.zero_le _

theorem commonPrefix_le_right (a b : List UInt8) : commonPrefix a b ≤ b.length := by
  induction a generalizing b with
  | nil => simp [commonPrefix]
  | cons x xs ih =>
    cases b with
    | nil => simp [commonPrefix]
    | cons y ys =>
      simp only [commonPrefix, List.length_cons]
      split
      · exact Nat.succ_le_succ (ih ys)
      · exact Nat.zero_le _

/-- What follows the common prefix differs at its first octet, when both
sides continue. -/
theorem commonPrefix_heads_differ (a b : List UInt8) {x y : UInt8} {xs ys : List UInt8}
    (ha : a.drop (commonPrefix a b) = x :: xs) (hb : b.drop (commonPrefix a b) = y :: ys) :
    x ≠ y := by
  induction a generalizing b with
  | nil => simp at ha
  | cons p ps ih =>
    cases b with
    | nil => simp at hb
    | cons q qs =>
      simp only [commonPrefix] at ha hb
      split at ha
      · rename_i eq
        rw [if_pos eq] at hb
        simp only [List.drop_succ_cons] at ha hb
        exact ih qs ha hb
      · rename_i ne
        rw [if_neg ne] at hb
        simp only [List.drop_zero] at ha hb
        cases ha; cases hb
        intro eq
        exact ne ((beq_iff_eq).mpr eq)

/-- Two sequences that both end at their common prefix are the same. -/
theorem commonPrefix_exhausted (a b : List UInt8)
    (ha : a.drop (commonPrefix a b) = []) (hb : b.drop (commonPrefix a b) = []) : a = b := by
  induction a generalizing b with
  | nil =>
    simp only [commonPrefix, List.drop_zero] at hb
    exact hb.symm
  | cons p ps ih =>
    cases b with
    | nil => simp [commonPrefix] at ha
    | cons q qs =>
      simp only [commonPrefix] at ha hb
      split at ha
      · rename_i eq
        rw [if_pos eq] at hb
        simp only [List.drop_succ_cons] at ha hb
        rw [ih qs ha hb, (beq_iff_eq).mp eq]
      · simp at ha

theorem emptyChildren_length : emptyChildren.length = 16 := rfl

theorem emptyChildren_none {i : Nat} (h : i < 16) : emptyChildren[i]? = some none := by
  simp only [emptyChildren, List.getElem?_replicate, h, ↓reduceIte]

theorem length_setChild (cs : List (Option ByteArray)) (nibble : UInt8) (child : Option ByteArray) :
    (setChild cs nibble child).length = cs.length := by
  simp [setChild]

theorem countP_set_of_none {cs : List (Option ByteArray)} {i : Nat} (h : cs[i]? = some none)
    (x : ByteArray) :
    (cs.set i (some x)).countP Option.isSome = cs.countP Option.isSome + 1 := by
  induction cs generalizing i with
  | nil => simp at h
  | cons c cs ih =>
    cases i with
    | zero =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at h
      subst h
      simp
    | succ i =>
      simp only [List.getElem?_cons_succ] at h
      simp only [List.set_cons_succ, List.countP_cons, ih h]
      omega

theorem countP_set_of_some {cs : List (Option ByteArray)} {i : Nat} {y : ByteArray}
    (h : cs[i]? = some (some y)) (x : ByteArray) :
    (cs.set i (some x)).countP Option.isSome = cs.countP Option.isSome := by
  induction cs generalizing i with
  | nil => simp at h
  | cons c cs ih =>
    cases i with
    | zero =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at h
      subst h
      simp
    | succ i =>
      simp only [List.getElem?_cons_succ] at h
      simp only [List.set_cons_succ, List.countP_cons, ih h]

/-- Setting a slot to a child never loses an occupant. -/
theorem occupants_setChild_ge (cs : List (Option ByteArray)) (nibble : UInt8) (child : ByteArray)
    (value : Option Value) : occupants cs value ≤ occupants (setChild cs nibble (some child)) value := by
  simp only [occupants, setChild]
  cases probe : cs[nibble.toNat]? with
  | none =>
    rw [List.set_eq_of_length_le (by
      have := List.getElem?_eq_none_iff.mp probe
      exact this)]
    exact Nat.le_refl _
  | some slot =>
    cases slot with
    | none => rw [countP_set_of_none probe]; omega
    | some y => rw [countP_set_of_some probe]; exact Nat.le_refl _

theorem occupants_some_ge (cs : List (Option ByteArray)) (v : Value) (value : Option Value) :
    occupants cs value ≤ occupants cs (some v) := by
  simp only [occupants]
  cases value <;> simp


/-! ### Preservation, compositionally

A program preserves shape when every execution from a shaped store, under
any digest of the right width, ends in a shaped store, and its successful
answer satisfies the stated property. The nibble runs of stored nodes are
tracked by a bound that a program may raise: an insert never raises it past
the key bound, a remove raises it by what its merges push down. The bound is
what makes every merged run representable on the wire; that real tries keep
it at the key bound is the depth invariant of whole paths, stated as a
hypothesis here and proved with the denotational theorems. -/

def Width (d : ByteArray → ByteArray) : Prop := ∀ b, (d b).size = 32

/-- Every stored node's nibble run is within `B`. -/
def Runs (s : Store) (B : Nat) : Prop :=
  ∀ key raw n, s.read nodeSpace key = some raw → decode raw = .ok n → nibbleRun n ≤ B

def Preserves (m : Mutate A) (B B' : Nat) (P : A → Prop) : Prop :=
  ∀ d, Width d → ∀ s, Shaped s → Runs s B → ∀ r s', execute d s m.run = some (r, s') →
    Shaped s' ∧ Runs s' B' ∧ ∀ a, r = .ok a → P a

theorem runs_mono {s : Store} {B B' : Nat} (h : Runs s B) (le : B ≤ B') : Runs s B' :=
  fun key raw n held decoded => Nat.le_trans (h key raw n held decoded) le

theorem runs_write_node {s : Store} {B : Nat} (runs : Runs s B) {key : ByteArray} {n : Node}
    (wf : n.wf) (within : nibbleRun n ≤ B) : Runs (s.write nodeSpace key (encode n)) B := by
  intro probe raw m held decoded
  rw [read_write_node] at held
  split at held
  · cases held
    rw [decode_encode wf] at decoded
    cases decoded
    exact within
  · exact runs probe raw m held decoded

theorem runs_write_value {s : Store} {B : Nat} (runs : Runs s B) (key bytes : ByteArray) :
    Runs (s.write valueSpace key bytes) B := by
  intro probe raw m held decoded
  rw [read_write_value] at held
  exact runs probe raw m held decoded

theorem preserves_pure {a : A} {P : A → Prop} (B : Nat) (h : P a) : Preserves (pure a) B B P := by
  intro d _ s shaped runs r s' ran
  simp only [run_pure, execute_pure, Option.some.injEq, Prod.mk.injEq] at ran
  obtain ⟨rfl, rfl⟩ := ran
  exact ⟨shaped, runs, fun _ eq => by cases eq; exact h⟩

theorem preserves_throw (e : Error) (B : Nat) (P : A → Prop) :
    Preserves (throw e : Mutate A) B B P := by
  intro d _ s shaped runs r s' ran
  simp only [run_throw, execute_pure, Option.some.injEq, Prod.mk.injEq] at ran
  obtain ⟨rfl, rfl⟩ := ran
  exact ⟨shaped, runs, fun _ eq => by cases eq⟩

theorem preserves_bind {m : Mutate A} {k : A → Mutate B} {P : A → Prop} {Q : B → Prop}
    {b₀ b₁ b₂ : Nat} (hm : Preserves m b₀ b₁ P) (hk : ∀ a, P a → Preserves (k a) b₁ b₂ Q)
    (le : b₁ ≤ b₂) : Preserves (m >>= k) b₀ b₂ Q := by
  intro d width s shaped runs r s' ran
  rw [execute_run_bind] at ran
  cases first : execute d s m.run with
  | none => simp [first] at ran
  | some result =>
    obtain ⟨reply, s₁⟩ := result
    have ⟨shaped₁, runs₁, answer⟩ := hm d width s shaped runs reply s₁ first
    cases reply with
    | error e =>
      simp only [first, Option.some.injEq, Prod.mk.injEq] at ran
      obtain ⟨rfl, rfl⟩ := ran
      exact ⟨shaped₁, runs_mono runs₁ le, fun _ eq => by cases eq⟩
    | ok a =>
      simp only [first] at ran
      exact hk a (answer a rfl) d width s₁ shaped₁ runs₁ r s' ran

theorem preserves_weaken {m : Mutate A} {P Q : A → Prop} {b₀ b₁ b₂ : Nat}
    (hm : Preserves m b₀ b₁ P) (le : b₁ ≤ b₂) (h : ∀ a, P a → Q a) : Preserves m b₀ b₂ Q :=
  fun d width s shaped runs r s' ran =>
    let ⟨shaped', runs', answer⟩ := hm d width s shaped runs r s' ran
    ⟨shaped', runs_mono runs' le, fun a eq => h a (answer a eq)⟩

theorem preserves_ite (c : Prop) [Decidable c] {t e : Mutate A} {P : A → Prop} {b₀ b₁ : Nat}
    (ht : c → Preserves t b₀ b₁ P) (he : ¬ c → Preserves e b₀ b₁ P) :
    Preserves (if c then t else e) b₀ b₁ P := by
  split
  · exact ht ‹c›
  · exact he ‹¬ c›

/-- Storing a canonical node preserves shape, keeps runs within a bound the
node respects, and answers a fixed-width address. -/
theorem preserves_put {n : Node} (wf : n.wf) (invariants : checkInvariants n = .ok ())
    {b₀ b₁ : Nat} (le : b₀ ≤ b₁) (within : nibbleRun n ≤ b₁) :
    Preserves (put n) b₀ b₁ (fun h => h.size = 32) := by
  intro d width s shaped runs r s' ran
  have ⟨shaped', eq⟩ := put_preserves d shaped wf invariants ran
  rw [execute_put] at ran
  cases ran
  exact ⟨shaped', runs_write_node (runs_mono runs le) wf within,
    fun a h => by cases eq; cases h; exact width _⟩

/-- Loading answers a canonical node within the run bound, or fails without writing. -/
theorem preserves_load (address : ByteArray) (B : Nat) :
    Preserves (load address) B B
      (fun n => n.wf ∧ checkInvariants n = .ok () ∧ nibbleRun n ≤ B) := by
  intro d _ s shaped runs r s' ran
  simp only [load, run_bind, read_run, program_bind_request, program_bind_pure, mapError_ok,
    bindCont_ok, execute_read] at ran
  cases held : s.read nodeSpace address with
  | none =>
    simp only [held, run_throw, execute_pure, Option.some.injEq, Prod.mk.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨shaped, runs, fun _ eq => by cases eq⟩
  | some raw =>
    obtain ⟨n, decoded, _, wf, invariants⟩ := shaped address raw held
    have within := runs address raw n held decoded
    simp only [held, decoded, run_pure, execute_pure, Option.some.injEq, Prod.mk.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨shaped, runs, fun _ eq => by cases eq; exact ⟨wf, invariants, within⟩⟩

/-- A value the write path builds: well formed, and inline only within the ceiling. -/
def ValueOk (v : Value) : Prop := v.wf ∧ checkValue v = .ok ()

theorem preserves_valueRef (bytes : ByteArray) (small : bytes.size < 2 ^ 64) (B : Nat) :
    Preserves (valueRef bytes) B B ValueOk := by
  intro d width s shaped runs r s' ran
  simp only [valueRef] at ran
  split at ran
  · rename_i inline
    simp only [run_pure, execute_pure, Option.some.injEq, Prod.mk.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    refine ⟨shaped, runs, fun _ eq => ?_⟩
    cases eq
    exact ⟨small, by simp [checkValue, Nat.not_lt.mpr inline]⟩
  · simp only [run_bind, digest_run, program_bind_request, program_bind_pure, mapError_ok,
      bindCont_ok, execute_digest, write_run, execute_write, run_pure, execute_pure,
      Option.some.injEq, Prod.mk.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨shaped_write_value shaped _ _, runs_write_value runs _ _,
      fun _ eq => by cases eq; exact ⟨width _, rfl⟩⟩

theorem preserves_addressValue {value : Value} (ok : ValueOk value) (B : Nat) :
    Preserves (addressValue value) B B (fun h => h.size = 32) := by
  cases value with
  | hash h => exact preserves_pure B ok.1
  | inline bytes =>
    intro d width s shaped runs r s' ran
    simp only [addressValue, run_bind, digest_run, program_bind_request, program_bind_pure,
      mapError_ok, bindCont_ok, execute_digest, write_run, execute_write, run_pure,
      execute_pure, Option.some.injEq, Prod.mk.injEq] at ran
    obtain ⟨rfl, rfl⟩ := ran
    exact ⟨shaped_write_value shaped _ _, runs_write_value runs _ _,
      fun _ eq => by cases eq; exact width _⟩

theorem preserves_wrapInExtension {segment : List UInt8} (nib : Nibbles segment)
    {child : ByteArray} (width : child.size = 32) {b₀ b₁ : Nat} (le : b₀ ≤ b₁)
    (within : segment.length ≤ b₁) (small : b₁ < 2 ^ 64) :
    Preserves (wrapInExtension segment child) b₀ b₁ (fun h => h.size = 32) := by
  unfold wrapInExtension
  refine preserves_ite _ (fun _ => preserves_weaken (preserves_pure b₀ width) le fun _ h => h)
    (fun nonempty => ?_)
  refine preserves_put (n := .extension (nibblesOf segment) child)
    ⟨nibblesOf_wf nib (by omega), width⟩ ?_ le ?_
  · simp only [checkInvariants, nibblesOf, ByteArray.size, List.size_toArray]
    have : segment.length ≠ 0 := fun zero => nonempty (List.isEmpty_iff_length_eq_zero.mpr zero)
    simp [this]
  · simpa [nibbleRun, nibblesOf, ByteArray.size] using within


/-! ### Merging and collapsing -/

theorem length_occupiedFrom (first : Nat) (cs : List (Option ByteArray)) :
    (occupiedFrom first cs).length = cs.countP Option.isSome := by
  induction cs generalizing first with
  | nil => rfl
  | cons c cs ih =>
    cases c with
    | none => simp [occupiedFrom, ih]
    | some h => simp [occupiedFrom, ih]

theorem occupiedFrom_spec {first : Nat} {cs : List (Option ByteArray)} {nibble : UInt8}
    {child : ByteArray} (mem : (nibble, child) ∈ occupiedFrom first cs) :
    some child ∈ cs ∧ ∃ k, k < cs.length ∧ nibble = (first + k).toUInt8 := by
  induction cs generalizing first with
  | nil => simp [occupiedFrom] at mem
  | cons c cs ih =>
    cases c with
    | none =>
      simp only [occupiedFrom] at mem
      obtain ⟨inner, k, lt, eq⟩ := ih mem
      exact ⟨List.mem_cons_of_mem _ inner, k + 1, by simp; omega, by rw [eq]; congr 1; omega⟩
    | some h =>
      simp only [occupiedFrom, List.mem_cons, Prod.mk.injEq] at mem
      rcases mem with ⟨rfl, rfl⟩ | mem
      · exact ⟨List.mem_cons_self .., 0, by simp, by simp⟩
      · obtain ⟨inner, k, lt, eq⟩ := ih mem
        exact ⟨List.mem_cons_of_mem _ inner, k + 1, by simp; omega, by rw [eq]; congr 1; omega⟩

/-- What a loaded branch establishes about its slots and value. -/
def BranchOk (cs : List (Option ByteArray)) (value : Option Value) : Prop :=
  cs.length = 16 ∧ (∀ child ∈ cs, ∀ h, child = some h → h.size = 32) ∧
    (∀ x, value = some x → x.wf ∧ checkValue x = .ok ())

theorem branchOk_of_loaded {cs : List (Option ByteArray)} {value : Option Value}
    (wf : (Node.branch cs value).wf) (invariants : checkInvariants (.branch cs value) = .ok ()) :
    BranchOk cs value ∧ 2 ≤ occupants cs value := by
  obtain ⟨len, widths, vwf⟩ := wf
  refine ⟨⟨len, widths, fun x eq => ⟨vwf x eq, ?_⟩⟩, ?_⟩
  · subst eq
    simp only [checkInvariants] at invariants
    cases cv : checkValue x with
    | error _ => simp [cv] at invariants
    | ok _ => rfl
  · simp only [checkInvariants] at invariants
    refine Nat.le_of_not_lt fun lt => ?_
    cases value with
    | none => simp [lt] at invariants
    | some x =>
      cases cv : checkValue x with
      | error _ => simp [cv] at invariants
      | ok _ => simp [cv, lt] at invariants

theorem checkInvariants_branch {cs : List (Option ByteArray)} {value : Option Value}
    (ok : BranchOk cs value) (occupied : 2 ≤ occupants cs value) :
    checkInvariants (.branch cs value) = .ok () := by
  simp only [checkInvariants]
  cases value with
  | none => simp [Nat.not_lt.mpr occupied]
  | some x =>
    have cv := (ok.2.2 x rfl).2
    simp [cv, Nat.not_lt.mpr occupied]

theorem wf_branch {cs : List (Option ByteArray)} {value : Option Value} (ok : BranchOk cs value) :
    (Node.branch cs value).wf :=
  ⟨ok.1, ok.2.1, fun x eq => (ok.2.2 x eq).1⟩

def RouteOk (cs : List (Option ByteArray)) (value : Option ByteArray) : Prop :=
  BranchOk cs (value.map Value.hash)

theorem routeOk_of_loaded {cs : List (Option ByteArray)} {value : Option ByteArray}
    (wf : (Node.route cs value).wf) (inv : checkInvariants (.route cs value) = .ok ()) :
    RouteOk cs value ∧ 1 ≤ occupants cs (value.map Value.hash) := by
  refine ⟨⟨wf.1, wf.2.1, ?_⟩, ?_⟩
  · intro x eq
    cases value with
    | none => cases eq
    | some h =>
      cases eq
      exact ⟨wf.2.2 h rfl, rfl⟩
  · simp only [checkInvariants] at inv
    split at inv
    · cases inv
    · rename_i nonzero
      simp only [beq_iff_eq] at nonzero
      omega

theorem wf_route {cs : List (Option ByteArray)} {value : Option ByteArray}
    (ok : RouteOk cs value) : (Node.route cs value).wf := by
  refine ⟨ok.1, ok.2.1, ?_⟩
  intro h eq
  subst value
  exact (ok.2.2 (.hash h) rfl).1

theorem checkInvariants_route {cs : List (Option ByteArray)} {value : Option ByteArray}
    (occupied : 1 ≤ occupants cs (value.map Value.hash)) :
    checkInvariants (.route cs value) = .ok () := by
  simp [checkInvariants, show occupants cs (value.map Value.hash) ≠ 0 by omega]

theorem preserves_mergeDown {segment : List UInt8} (nib : Nibbles segment) (nonempty : segment ≠ [])
    {child : ByteArray} (width : child.size = 32) {L B : Nat} (within : segment.length ≤ L)
    (small : L + B < 2 ^ 64) :
    Preserves (mergeDown segment child) B (L + B) (fun h => h.size = 32) := by
  unfold mergeDown
  refine preserves_bind (preserves_load child B) (fun n ⟨wf, inv, run⟩ => ?_) (by omega)
  have nonzero : segment.length ≠ 0 := fun zero => nonempty (List.eq_nil_of_length_eq_zero zero)
  cases n with
  | leaf suffix value =>
    obtain ⟨⟨_, sufNib⟩, vwf⟩ := wf
    change suffix.size ≤ B at run
    have size : suffix.size = suffix.data.size := rfl
    have len : (segment ++ suffix.data.toList).length = segment.length + suffix.data.size := by simp
    refine preserves_put (n := .leaf (nibblesOf (segment ++ suffix.data.toList)) value)
      ⟨nibblesOf_wf (nibbles_append nib sufNib) (by omega), vwf⟩ (by simpa [checkInvariants] using inv)
      (by omega) ?_
    show (segment ++ suffix.data.toList).toArray.size ≤ L + B
    simp only [List.size_toArray, len]
    omega
  | extension below grandchild =>
    obtain ⟨⟨_, belowNib⟩, gwidth⟩ := wf
    change below.size ≤ B at run
    have size : below.size = below.data.size := rfl
    have len : (segment ++ below.data.toList).length = segment.length + below.data.size := by simp
    refine preserves_put (n := .extension (nibblesOf (segment ++ below.data.toList)) grandchild)
      ⟨nibblesOf_wf (nibbles_append nib belowNib) (by omega), gwidth⟩ ?_ (by omega) ?_
    · show (if (segment ++ below.data.toList).toArray.size == 0 then _ else _) = _
      simp only [List.size_toArray, len]
      simp [nonzero]
    · show (segment ++ below.data.toList).toArray.size ≤ L + B
      simp only [List.size_toArray, len]
      omega
  | branch cs value =>
    refine preserves_put (n := .extension (nibblesOf segment) child)
      ⟨nibblesOf_wf nib (by omega), width⟩ ?_ (by omega) ?_
    · show (if segment.toArray.size == 0 then _ else _) = _
      simp [nonzero]
    · show segment.toArray.size ≤ L + B
      simp only [List.size_toArray]
      omega
  | route cs value =>
    refine preserves_put (n := .extension (nibblesOf segment) child)
      ⟨nibblesOf_wf nib (by omega), width⟩ ?_ (by omega) ?_
    · show (if segment.toArray.size == 0 then _ else _) = _
      simp [nonzero]
    · show segment.toArray.size ≤ L + B
      simp only [List.size_toArray]
      omega

theorem preserves_collapse {cs : List (Option ByteArray)} {value : Option Value}
    (ok : BranchOk cs value) {B : Nat} (small : B + 1 < 2 ^ 64) :
    Preserves (collapse cs value) B (B + 1) (fun r => ∀ h, r = some h → h.size = 32) := by
  unfold collapse
  have widths := ok.2.1
  cases occ : occupiedChildren cs with
  | nil =>
    cases value with
    | none => exact preserves_weaken (preserves_pure B (by simp)) (by omega) fun _ h => h
    | some x =>
      obtain ⟨xwf, cv⟩ := ok.2.2 x rfl
      refine preserves_bind (preserves_put (n := .leaf (nibblesOf []) x) (b₀ := B) (b₁ := B + 1)
        ⟨nibblesOf_wf nibbles_nil (by decide), xwf⟩ (by simpa [checkInvariants] using cv) (by omega)
        (by show (0 : Nat) ≤ B + 1; exact Nat.zero_le _))
        (fun h width => preserves_pure _ (fun _ eq => by cases eq; exact width)) (Nat.le_refl _)
  | cons head tail =>
    obtain ⟨nibble, child⟩ := head
    cases tail with
    | nil =>
      cases value with
      | none =>
        have inhead : (nibble, child) ∈ occupiedFrom 0 cs := by
          show (nibble, child) ∈ occupiedChildren cs
          rw [occ]
          exact List.mem_cons_self ..
        have ⟨mem, k, lt, eq⟩ := occupiedFrom_spec inhead
        have cwidth := widths (some child) mem child rfl
        have nibNib : Nibbles [nibble] := by
          intro n h
          simp only [List.mem_cons, List.not_mem_nil, or_false] at h
          subst h
          rw [eq, Nat.zero_add]
          rw [ok.1] at lt
          rw [toNat_ofNat_of_lt (by omega)]
          omega
        have := preserves_mergeDown nibNib (by simp) cwidth (L := 1) (B := B) (by simp) (by omega)
        rw [Nat.add_comm] at this
        exact preserves_bind this
          (fun h width => preserves_pure _ (fun _ eq => by cases eq; exact width)) (Nat.le_refl _)
      | some x =>
        have two : 2 ≤ occupants cs (some x) := by
          simp only [occupants, Option.isSome_some, ↓reduceIte]
          have := length_occupiedFrom 0 cs
          rw [← occupiedChildren, occ] at this
          simp at this
          omega
        refine preserves_bind (preserves_put (b₀ := B) (b₁ := B + 1) (wf_branch ok)
          (checkInvariants_branch ok two) (by omega)
          (by show (0 : Nat) ≤ B + 1; exact Nat.zero_le _))
          (fun h width => preserves_pure _ (fun _ eq => by cases eq; exact width)) (Nat.le_refl _)
    | cons second rest =>
      have two : 2 ≤ occupants cs value := by
        simp only [occupants]
        have := length_occupiedFrom 0 cs
        rw [← occupiedChildren, occ] at this
        simp at this
        omega
      refine preserves_bind (preserves_put (b₀ := B) (b₁ := B + 1) (wf_branch ok)
        (checkInvariants_branch ok two) (by omega)
        (by show (0 : Nat) ≤ B + 1; exact Nat.zero_le _))
        (fun h width => preserves_pure _ (fun _ eq => by cases eq; exact width)) (Nat.le_refl _)


/-! ### Splitting a leaf or an extension -/

theorem branchOk_empty : BranchOk emptyChildren none := by
  refine ⟨rfl, fun child mem _ eq => ?_, fun _ eq => by cases eq⟩
  simp only [emptyChildren, List.mem_replicate] at mem
  rw [mem.2] at eq
  cases eq

theorem branchOk_value {cs : List (Option ByteArray)} {value : Option Value} (ok : BranchOk cs value)
    {x : Value} (xok : ValueOk x) : BranchOk cs (some x) :=
  ⟨ok.1, ok.2.1, fun y eq => by cases eq; exact xok⟩

theorem branchOk_setChild {cs : List (Option ByteArray)} {value : Option Value}
    (ok : BranchOk cs value) (nibble : UInt8) {child : ByteArray} (width : child.size = 32) :
    BranchOk (setChild cs nibble (some child)) value := by
  refine ⟨by rw [length_setChild, ok.1], fun c mem h eq => ?_, ok.2.2⟩
  rcases List.mem_or_eq_of_mem_set mem with inner | rfl
  · exact ok.2.1 c inner h eq
  · cases eq; exact width

theorem occupants_empty_none : occupants emptyChildren none = 0 := rfl

theorem occupants_value (cs : List (Option ByteArray)) (x : Value) :
    occupants cs (some x) = occupants cs none + 1 := by
  simp [occupants]

theorem occupants_setChild_of_none {cs : List (Option ByteArray)} {nibble : UInt8}
    (slot : cs[nibble.toNat]? = some none) (child : ByteArray) (value : Option Value) :
    occupants (setChild cs nibble (some child)) value = occupants cs value + 1 := by
  simp only [occupants, setChild, countP_set_of_none slot]
  omega

theorem setChild_getElem_ne (cs : List (Option ByteArray)) {n m : UInt8} (ne : n ≠ m)
    (child : Option ByteArray) : (setChild cs n child)[m.toNat]? = cs[m.toNat]? := by
  simp only [setChild]
  rw [List.getElem?_set_ne]
  intro eq
  exact ne (UInt8.toNat_inj.mp eq)

theorem preserves_splitLeaf {suffix : List UInt8} (sufNib : Nibbles suffix) {old : Value}
    (oldOk : ValueOk old) {key : List UInt8} (keyNib : Nibbles key) {value : Value}
    (valOk : ValueOk value) {B : Nat} (sufB : suffix.length ≤ B) (keyB : key.length ≤ B)
    (small : B < 2 ^ 64) : Preserves (splitLeaf suffix old key value) B B (fun h => h.size = 32) := by
  unfold splitLeaf
  dsimp only
  refine preserves_ite _ (fun _ => ?_) (fun ne => ?_)
  · exact preserves_put (n := .leaf (nibblesOf suffix) value)
      ⟨nibblesOf_wf sufNib (by omega), valOk.1⟩ (by simpa [checkInvariants] using valOk.2)
      (Nat.le_refl _) (by show suffix.toArray.size ≤ B; simpa using sufB)
  · have cpS := commonPrefix_le_left suffix key
    have cpK := commonPrefix_le_right suffix key
    have takeB : (key.take (commonPrefix suffix key)).length ≤ B := by
      simp only [List.length_take]; omega
    -- The branch under the common prefix, then the extension above it.
    have finish : ∀ (cs : List (Option ByteArray)) (bv : Option Value), BranchOk cs bv →
        2 ≤ occupants cs bv →
        Preserves (do
          let branch ← put (Node.branch cs bv)
          wrapInExtension (List.take (commonPrefix suffix key) key) branch) B B
          (fun h => h.size = 32) := by
      intro cs bv ok two
      refine preserves_bind (preserves_put (wf_branch ok) (checkInvariants_branch ok two)
        (Nat.le_refl _) (by show (0 : Nat) ≤ B; exact Nat.zero_le _))
        (fun branch bw => preserves_wrapInExtension (nibbles_take keyNib _) bw (Nat.le_refl _)
          takeB small) (Nat.le_refl _)
    cases hs : suffix.drop (commonPrefix suffix key) with
    | nil =>
      cases hk : key.drop (commonPrefix suffix key) with
      | nil =>
        exact absurd (beq_iff_eq.mpr (commonPrefix_exhausted suffix key hs hk)) (by simpa using ne)
      | cons nibble rest =>
        have restNib : Nibbles rest := nibbles_tail (hk ▸ nibbles_drop keyNib _)
        have restB : rest.length ≤ B := by
          have := congrArg List.length hk
          simp only [List.length_drop, List.length_cons] at this
          omega
        have slot := emptyChildren_none (i := nibble.toNat)
          (by have := nibbles_head (hk ▸ nibbles_drop keyNib _); omega)
        refine preserves_bind (preserves_put (n := .leaf (nibblesOf rest) value)
          ⟨nibblesOf_wf restNib (by omega), valOk.1⟩ (by simpa [checkInvariants] using valOk.2)
          (Nat.le_refl _) (by show rest.toArray.size ≤ B; simpa using restB))
          (fun child cw => finish _ _ (branchOk_setChild (branchOk_value branchOk_empty oldOk) nibble cw)
            (by rw [occupants_setChild_of_none slot, occupants_value, occupants_empty_none]; omega))
          (Nat.le_refl _)
    | cons nibble rest =>
      have restNib : Nibbles rest := nibbles_tail (hs ▸ nibbles_drop sufNib _)
      have restB : rest.length ≤ B := by
        have := congrArg List.length hs
        simp only [List.length_drop, List.length_cons] at this
        omega
      have slot := emptyChildren_none (i := nibble.toNat)
        (by have := nibbles_head (hs ▸ nibbles_drop sufNib _); omega)
      refine preserves_bind (preserves_put (n := .leaf (nibblesOf rest) old)
        ⟨nibblesOf_wf restNib (by omega), oldOk.1⟩ (by simpa [checkInvariants] using oldOk.2)
        (Nat.le_refl _) (by show rest.toArray.size ≤ B; simpa using restB))
        (fun child cw => ?_) (Nat.le_refl _)
      cases hk : key.drop (commonPrefix suffix key) with
      | nil =>
        exact finish _ _ (branchOk_value (branchOk_setChild branchOk_empty nibble cw) valOk)
          (by rw [occupants_value, occupants_setChild_of_none slot, occupants_empty_none]; omega)
      | cons nibble' rest' =>
        have restNib' : Nibbles rest' := nibbles_tail (hk ▸ nibbles_drop keyNib _)
        have restB' : rest'.length ≤ B := by
          have := congrArg List.length hk
          simp only [List.length_drop, List.length_cons] at this
          omega
        have differ : nibble ≠ nibble' := commonPrefix_heads_differ suffix key hs hk
        have slot' : (setChild emptyChildren nibble (some child))[nibble'.toNat]? = some none := by
          rw [setChild_getElem_ne _ differ]
          exact emptyChildren_none (by have := nibbles_head (hk ▸ nibbles_drop keyNib _); omega)
        refine preserves_bind (preserves_put (n := .leaf (nibblesOf rest') value)
          ⟨nibblesOf_wf restNib' (by omega), valOk.1⟩ (by simpa [checkInvariants] using valOk.2)
          (Nat.le_refl _) (by show rest'.toArray.size ≤ B; simpa using restB'))
          (fun child' cw' => finish _ _
            (branchOk_setChild (branchOk_setChild branchOk_empty nibble cw) nibble' cw')
            (by rw [occupants_setChild_of_none slot', occupants_setChild_of_none slot,
              occupants_empty_none]; omega))
          (Nat.le_refl _)


theorem preserves_splitExtension {segment : List UInt8} (segNib : Nibbles segment)
    {child : ByteArray} (width : child.size = 32) {key : List UInt8} (keyNib : Nibbles key)
    {value : Value} (valOk : ValueOk value) {B : Nat} (segB : segment.length ≤ B)
    (keyB : key.length ≤ B) (small : B < 2 ^ 64) :
    Preserves (splitExtension segment child key value) B B (fun h => h.size = 32) := by
  unfold splitExtension
  dsimp only
  have cpS := commonPrefix_le_left segment key
  have cpK := commonPrefix_le_right segment key
  have takeB : (key.take (commonPrefix segment key)).length ≤ B := by
    simp only [List.length_take]; omega
  have finish : ∀ (cs : List (Option ByteArray)) (bv : Option Value), BranchOk cs bv →
      2 ≤ occupants cs bv →
      Preserves (do
        let branch ← put (Node.branch cs bv)
        wrapInExtension (List.take (commonPrefix segment key) key) branch) B B
        (fun h => h.size = 32) := by
    intro cs bv ok two
    refine preserves_bind (preserves_put (wf_branch ok) (checkInvariants_branch ok two)
      (Nat.le_refl _) (by show (0 : Nat) ≤ B; exact Nat.zero_le _))
      (fun branch bw => preserves_wrapInExtension (nibbles_take keyNib _) bw (Nat.le_refl _)
        takeB small) (Nat.le_refl _)
  cases hs : segment.drop (commonPrefix segment key) with
  | nil => dsimp only; exact preserves_pure (a := child) (P := fun h => h.size = 32) B width
  | cons nibble below =>
    dsimp only
    have belowNib : Nibbles below := nibbles_tail (hs ▸ nibbles_drop segNib _)
    have belowB : below.length ≤ B := by
      have := congrArg List.length hs
      simp only [List.length_drop, List.length_cons] at this
      omega
    have slot := emptyChildren_none (i := nibble.toNat)
      (by have := nibbles_head (hs ▸ nibbles_drop segNib _); omega)
    refine preserves_ite _
      (fun _ => preserves_bind (preserves_pure (a := child) (P := fun h => h.size = 32) B width) (fun down dw => ?_) (Nat.le_refl _))
      (fun nonempty => preserves_bind (preserves_put (n := .extension (nibblesOf below) child)
        ⟨nibblesOf_wf belowNib (by omega), width⟩
        (by
          show (if below.toArray.size == 0 then _ else _) = _
          have : below.length ≠ 0 := fun zero =>
            nonempty (List.isEmpty_iff_length_eq_zero.mpr zero)
          simp [this])
        (Nat.le_refl _) (by show below.toArray.size ≤ B; simpa using belowB))
        (fun down dw => ?_) (Nat.le_refl _))
    all_goals
      cases hk : key.drop (commonPrefix segment key) with
      | nil =>
        exact finish _ _ (branchOk_value (branchOk_setChild branchOk_empty nibble dw) valOk)
          (by rw [occupants_value, occupants_setChild_of_none slot, occupants_empty_none]; omega)
      | cons nibble' rest' =>
        have restNib' : Nibbles rest' := nibbles_tail (hk ▸ nibbles_drop keyNib _)
        have restB' : rest'.length ≤ B := by
          have := congrArg List.length hk
          simp only [List.length_drop, List.length_cons] at this
          omega
        have differ : nibble ≠ nibble' := commonPrefix_heads_differ segment key hs hk
        have slot' : (setChild emptyChildren nibble (some down))[nibble'.toNat]? = some none := by
          rw [setChild_getElem_ne _ differ]
          exact emptyChildren_none (by have := nibbles_head (hk ▸ nibbles_drop keyNib _); omega)
        exact preserves_bind (preserves_put (n := .leaf (nibblesOf rest') value)
          ⟨nibblesOf_wf restNib' (by omega), valOk.1⟩ (by simpa [checkInvariants] using valOk.2)
          (Nat.le_refl _) (by show rest'.toArray.size ≤ B; simpa using restB'))
          (fun leaf lw => finish _ _
            (branchOk_setChild (branchOk_setChild branchOk_empty nibble dw) nibble' lw)
            (by rw [occupants_setChild_of_none slot', occupants_setChild_of_none slot,
              occupants_empty_none]; omega))
          (Nat.le_refl _)


/-! ### Insertion: descent and rebuild -/

/-- What a frame remembers about the level it was entered through, all of it
read from a canonical node within the run bound. -/
def FrameOk (B : Nat) : InsertFrame → Prop
  | .extension segment => nibblesWf segment ∧ segment.size ≤ B ∧ segment.size ≠ 0
  | .branch children value _ => BranchOk children value ∧ 2 ≤ occupants children value
  | .route children value _ => RouteOk children value ∧ 1 ≤ occupants children (value.map Value.hash)

def StackOk (B : Nat) (stack : List InsertFrame) : Prop := ∀ frame ∈ stack, FrameOk B frame

theorem stackOk_nil (B : Nat) : StackOk B [] := fun _ h => nomatch h

theorem stackOk_cons {B : Nat} {frame : InsertFrame} {stack : List InsertFrame}
    (h : FrameOk B frame) (rest : StackOk B stack) : StackOk B (frame :: stack) := by
  intro f mem
  rcases List.mem_cons.mp mem with rfl | inner
  · exact h
  · exact rest f inner

theorem stackOk_tail {B : Nat} {frame : InsertFrame} {stack : List InsertFrame}
    (h : StackOk B (frame :: stack)) : FrameOk B frame ∧ StackOk B stack :=
  ⟨h frame (List.mem_cons_self ..), fun f mem => h f (List.mem_cons_of_mem _ mem)⟩

theorem preserves_rebuild {B : Nat} :
    ∀ (stack : List InsertFrame) (built : ByteArray), StackOk B stack → built.size = 32 →
    Preserves (rebuild built stack) B B (fun h => h.size = 32) := by
  intro stack
  induction stack with
  | nil => intro built _ width; exact preserves_pure (a := built) (P := fun h => h.size = 32) B width
  | cons frame stack ih =>
    intro built ok width
    obtain ⟨fok, rest⟩ := stackOk_tail ok
    cases frame with
    | extension segment =>
      obtain ⟨wf, within, nonzero⟩ := fok
      unfold rebuild
      refine preserves_bind (preserves_put (n := .extension segment built) ⟨wf, width⟩ ?_
        (Nat.le_refl _) within) (fun h hw => ih h rest hw) (Nat.le_refl _)
      show (if segment.size == 0 then _ else _) = _
      simp [nonzero]
    | branch children value nibble =>
      obtain ⟨bok, two⟩ := fok
      unfold rebuild
      refine preserves_bind (preserves_put (wf_branch (branchOk_setChild bok nibble width))
        (checkInvariants_branch (branchOk_setChild bok nibble width)
          (Nat.le_trans two (occupants_setChild_ge ..)))
        (Nat.le_refl _) (by show (0 : Nat) ≤ B; exact Nat.zero_le _))
        (fun h hw => ih h rest hw) (Nat.le_refl _)
    | route children value nibble =>
      obtain ⟨bok, two⟩ := fok
      unfold rebuild
      refine preserves_bind (preserves_put (wf_route (branchOk_setChild bok nibble width))
        (checkInvariants_route
          (Nat.le_trans two (occupants_setChild_ge ..)))
        (Nat.le_refl _) (by show (0 : Nat) ≤ B; exact Nat.zero_le _))
        (fun h hw => ih h rest hw) (Nat.le_refl _)

theorem mem_of_childAt {children : List (Option ByteArray)} {nibble : UInt8} {child : ByteArray}
    (h : childAt children nibble = some child) : some child ∈ children := by
  simp only [childAt] at h
  cases probe : children[nibble.toNat]? with
  | none => simp [probe] at h
  | some slot =>
    simp only [probe, Option.getD_some] at h
    subst h
    exact List.mem_of_getElem? probe

theorem preserves_descend {B : Nat} (small : B < 2 ^ 64) {value : Value} (valOk : ValueOk value) :
    ∀ (fuel : Nat) (cursor : Option ByteArray) (rest : List UInt8) (stack : List InsertFrame),
    Nibbles rest → rest.length ≤ B → StackOk B stack →
    Preserves (descend fuel cursor rest value stack) B B
      (fun r => r.1.size = 32 ∧ StackOk B r.2) := by
  intro fuel
  induction fuel with
  | zero => intro cursor rest stack _ _ _; exact preserves_throw _ B _
  | succ fuel ih =>
    intro cursor rest stack nib restB ok
    cases cursor with
    | none =>
      unfold descend
      refine preserves_bind (preserves_put (n := .leaf (nibblesOf rest) value)
        ⟨nibblesOf_wf nib (by omega), valOk.1⟩ (by simpa [checkInvariants] using valOk.2)
        (Nat.le_refl _) (by show rest.toArray.size ≤ B; simpa using restB))
        (fun h hw => preserves_pure B ⟨hw, ok⟩) (Nat.le_refl _)
    | some address =>
      unfold descend
      refine preserves_bind (preserves_load address B) (fun n ⟨wf, inv, run⟩ => ?_) (Nat.le_refl _)
      cases n with
      | extension segment child =>
        dsimp only
        obtain ⟨segWf, width⟩ := wf
        change segment.size ≤ B at run
        have nonzero : segment.size ≠ 0 := by
          intro zero
          simp [checkInvariants, zero] at inv
        have pathLen : segment.data.toList.length = segment.size := Array.length_toList
        refine preserves_ite _ (fun _ => ?_) (fun _ => ?_)
        · exact ih (some child) _ _ (nibbles_drop nib _)
            (by simp only [List.length_drop]; omega)
            (stackOk_cons ⟨segWf, run, nonzero⟩ ok)
        · exact preserves_bind (preserves_splitExtension (nibbles_of_nibblesWf segWf) width nib valOk
            (by rw [pathLen]; exact run) restB small)
            (fun h hw => preserves_pure B ⟨hw, ok⟩) (Nat.le_refl _)
      | branch children branchValue =>
        dsimp only
        obtain ⟨bok, two⟩ := branchOk_of_loaded wf inv
        cases rest with
        | nil =>
          exact preserves_bind (preserves_put (wf_branch (branchOk_value bok valOk))
            (checkInvariants_branch (branchOk_value bok valOk)
              (Nat.le_trans two (occupants_some_ge ..)))
            (Nat.le_refl _) (by show (0 : Nat) ≤ B; exact Nat.zero_le _))
            (fun h hw => preserves_pure B ⟨hw, ok⟩) (Nat.le_refl _)
        | cons nibble rest =>
          exact ih (childAt children nibble) rest _ (nibbles_tail nib)
            (by simp only [List.length_cons] at restB; omega)
            (stackOk_cons ⟨bok, two⟩ ok)
      | route children routeValue =>
        dsimp only
        obtain ⟨bok, occupied⟩ := routeOk_of_loaded wf inv
        cases rest with
        | nil =>
          refine preserves_bind (preserves_addressValue valOk B) (fun address width => ?_) (Nat.le_refl _)
          exact preserves_bind (preserves_put
            (wf_route (value := some address) (branchOk_value bok (x := .hash address) ⟨width, rfl⟩))
            (checkInvariants_route (by simp [occupants]))
            (Nat.le_refl _) (by show (0 : Nat) ≤ B; exact Nat.zero_le _))
            (fun h hw => preserves_pure B ⟨hw, ok⟩) (Nat.le_refl _)
        | cons nibble rest =>
          exact ih (childAt children nibble) rest _ (nibbles_tail nib)
            (by simp only [List.length_cons] at restB; omega)
            (stackOk_cons ⟨bok, occupied⟩ ok)
      | leaf suffix old =>
        dsimp only
        obtain ⟨sufWf, oldWf⟩ := wf
        change suffix.size ≤ B at run
        have oldOk : ValueOk old := ⟨oldWf, by simpa [checkInvariants] using inv⟩
        have sufLen : suffix.data.toList.length = suffix.size := Array.length_toList
        exact preserves_bind (preserves_splitLeaf (nibbles_of_nibblesWf sufWf) oldOk nib valOk
          (by rw [sufLen]; exact run) restB small)
          (fun h hw => preserves_pure B ⟨hw, ok⟩) (Nat.le_refl _)

theorem preserves_insertAt {B : Nat} (small : B < 2 ^ 64) {value : Value} (valOk : ValueOk value)
    (fuel : Nat) (cursor : Option ByteArray) {rest : List UInt8} (nib : Nibbles rest)
    (restB : rest.length ≤ B) :
    Preserves (insertAt fuel cursor rest value) B B (fun h => h.size = 32) := by
  unfold insertAt
  refine preserves_bind (preserves_descend small valOk fuel cursor rest [] nib restB (stackOk_nil B))
    (fun r hr => ?_) (Nat.le_refl _)
  obtain ⟨built, stack⟩ := r
  exact preserves_rebuild stack built hr.2 hr.1

theorem keyNibbles_length (key : ByteArray) : (keyNibbles key).length = key.size * 2 :=
  Synchronicity.TrieProgramProofs.key_nibbles_length key

/-- Every insert from a shaped store leaves a shaped store, within the same
run bound, whenever that bound covers a whole key. -/
theorem insert_preserves {B : Nat} (covers : maxKeyBytes * 2 ≤ B) (small : B < 2 ^ 64)
    (root key value : ByteArray) :
    Preserves (Trie.insert root key value) B B (fun h => h.size = 32) := by
  unfold Trie.insert
  dsimp only
  refine preserves_ite _ (fun _ => preserves_bind (preserves_throw _ B (fun _ => False))
    (fun _ h => h.elim) (Nat.le_refl _)) (fun keyWithin => ?_)
  refine preserves_ite _ (fun _ => preserves_bind (preserves_throw _ B (fun _ => False))
    (fun _ h => h.elim) (Nat.le_refl _)) (fun valueWithin => ?_)
  have valueSmall : value.size < 2 ^ 64 := by
    have : ¬ value.size > maxValueBytes := valueWithin
    simp only [maxValueBytes] at this
    omega
  refine preserves_bind (preserves_valueRef value valueSmall B)
    (fun v vok => preserves_insertAt small vok _ _ (nibbles_keyNibbles key) ?_) (Nat.le_refl _)
  rw [keyNibbles_length]
  have : ¬ key.size > maxKeyBytes := keyWithin
  simp only [maxKeyBytes] at this covers
  omega


/-! ### Removal: descent and unwinding

A removal's merges push extension segments down into the nodes below them,
so the run bound grows by exactly what the frames on the key path carry:
one nibble per branch entered, one segment per extension followed. Those
frames are read from the key path, so their cost is bounded by the key. -/

def RemoveFrameOk : RemoveFrame → Prop
  | .extension address segment child =>
    Nibbles segment ∧ segment ≠ [] ∧ child.size = 32 ∧ address.size = 32
  | .branch address children value _ _ => BranchOk children value ∧ address.size = 32
  | .route address children value _ _ => RouteOk children value ∧ address.size = 32

def RStackOk (stack : List RemoveFrame) : Prop := ∀ frame ∈ stack, RemoveFrameOk frame

theorem rstackOk_nil : RStackOk [] := fun _ h => nomatch h

theorem rstackOk_cons {frame : RemoveFrame} {stack : List RemoveFrame} (h : RemoveFrameOk frame)
    (rest : RStackOk stack) : RStackOk (frame :: stack) := by
  intro f mem
  rcases List.mem_cons.mp mem with rfl | inner
  · exact h
  · exact rest f inner

theorem rstackOk_tail {frame : RemoveFrame} {stack : List RemoveFrame}
    (h : RStackOk (frame :: stack)) : RemoveFrameOk frame ∧ RStackOk stack :=
  ⟨h frame (List.mem_cons_self ..), fun f mem => h f (List.mem_cons_of_mem _ mem)⟩

/-- What unwinding a stack may push down into merged nodes. -/
def stackCost : List RemoveFrame → Nat
  | [] => 0
  | .extension _ segment _ :: stack => segment.length + stackCost stack
  | .branch _ _ _ _ _ :: stack => 1 + stackCost stack
  | .route _ _ _ _ _ :: stack => 1 + stackCost stack

def ResultOk (r : Option ByteArray) : Prop := ∀ h, r = some h → h.size = 32

theorem resultOk_none : ResultOk none := fun _ h => by cases h
theorem resultOk_some {h : ByteArray} (width : h.size = 32) : ResultOk (some h) :=
  fun _ eq => by cases eq; exact width

theorem branchOk_setChild_result {cs : List (Option ByteArray)} {value : Option Value}
    (ok : BranchOk cs value) (nibble : UInt8) {result : Option ByteArray} (rok : ResultOk result) :
    BranchOk (setChild cs nibble result) value := by
  refine ⟨by rw [length_setChild, ok.1], fun c mem h eq => ?_, ok.2.2⟩
  rcases List.mem_or_eq_of_mem_set mem with inner | rfl
  · exact ok.2.1 c inner h eq
  · exact rok h eq

theorem preserves_retainRoute {cs : List (Option ByteArray)} {value : Option ByteArray}
    (ok : RouteOk cs value) (B : Nat) :
    Preserves (retainRoute cs value) B (B + 1) ResultOk := by
  unfold retainRoute
  refine preserves_ite _
    (fun _ => preserves_weaken (preserves_pure B resultOk_none) (by omega) fun _ h => h)
    (fun occupied => ?_)
  refine preserves_bind (preserves_put (wf_route ok)
    (checkInvariants_route (by simp only [beq_iff_eq] at occupied; omega))
    (b₀ := B) (b₁ := B + 1) (by omega) (by exact Nat.zero_le _))
    (fun h width => preserves_pure _ (resultOk_some width)) (Nat.le_refl _)

theorem preserves_unwind : ∀ (stack : List RemoveFrame) (result : Option ByteArray) (b : Nat),
    RStackOk stack → ResultOk result → b + stackCost stack < 2 ^ 64 →
    Preserves (unwind result stack) b (b + stackCost stack) ResultOk := by
  intro stack
  induction stack with
  | nil =>
    intro result b _ rok _
    simp only [stackCost, Nat.add_zero]
    exact preserves_pure b rok
  | cons frame stack ih =>
    intro result b ok rok small
    obtain ⟨fok, rest⟩ := rstackOk_tail ok
    cases frame with
    | extension address segment child =>
      obtain ⟨nib, nonempty, cwidth, awidth⟩ := fok
      simp only [stackCost] at small ⊢
      unfold unwind
      cases result with
      | none =>
        try dsimp only
        exact preserves_weaken (ih none b rest resultOk_none (by omega)) (by omega) fun _ h => h
      | some replacement =>
        try dsimp only
        refine preserves_ite _ (fun _ => preserves_weaken
          (ih (some address) b rest (resultOk_some awidth) (by omega)) (by omega) fun _ h => h)
          (fun _ => ?_)
        refine preserves_bind (preserves_mergeDown nib nonempty (rok replacement rfl)
          (L := segment.length) (B := b) (Nat.le_refl _) (by omega))
          (fun merged mw => preserves_weaken
            (ih (some merged) (segment.length + b) rest (resultOk_some mw) (by omega))
            (by omega) fun _ h => h) (by omega)
    | branch address children value nibble child =>
      obtain ⟨bok, awidth⟩ := fok
      simp only [stackCost] at small ⊢
      unfold unwind
      try dsimp only
      refine preserves_ite _ (fun _ => preserves_weaken
        (ih (some address) b rest (resultOk_some awidth) (by omega)) (by omega) fun _ h => h)
        (fun _ => ?_)
      refine preserves_bind (preserves_collapse (branchOk_setChild_result bok nibble rok)
        (B := b) (by omega))
        (fun r rok' => preserves_weaken (ih r (b + 1) rest rok' (by omega)) (by omega) fun _ h => h)
        (by omega)
    | route address children value nibble child =>
      obtain ⟨bok, awidth⟩ := fok
      simp only [stackCost] at small ⊢
      unfold unwind
      try dsimp only
      refine preserves_ite _ (fun _ => preserves_weaken
        (ih (some address) b rest (resultOk_some awidth) (by omega)) (by omega) fun _ h => h)
        (fun _ => ?_)
      refine preserves_bind (preserves_retainRoute (branchOk_setChild_result bok nibble rok) b)
        (fun r rok' => preserves_weaken (ih r (b + 1) rest rok' (by omega)) (by omega) fun _ h => h)
        (by omega)

theorem preserves_descendRemove {B : Nat} (small : B + 1 < 2 ^ 64) :
    ∀ (fuel : Nat) (address : ByteArray) (rest : List UInt8) (stack : List RemoveFrame),
    address.size = 32 → Nibbles rest → RStackOk stack →
    Preserves (descendRemove fuel address rest stack) B (B + 1)
      (fun r => ResultOk r.1 ∧ RStackOk r.2 ∧ stackCost r.2 ≤ stackCost stack + rest.length) := by
  intro fuel
  induction fuel with
  | zero =>
    intro _ _ _ _ _ _
    unfold descendRemove
    exact preserves_weaken (b₁ := B) (preserves_throw _ B _) (Nat.le_succ B) fun _ h => h
  | succ fuel ih =>
    intro address rest stack awidth nib ok
    unfold descendRemove
    refine preserves_bind (preserves_load address B) (fun n ⟨wf, inv, _⟩ => ?_) (by omega)
    cases n with
    | leaf suffix value =>
      dsimp only
      refine preserves_weaken (preserves_pure B ⟨?_, ok, Nat.le_add_right _ _⟩) (by omega)
        fun _ h => h
      split
      · exact resultOk_none
      · exact resultOk_some awidth
    | extension segment child =>
      dsimp only
      obtain ⟨segWf, cwidth⟩ := wf
      have nonzero : segment.size ≠ 0 := by
        intro zero
        simp [checkInvariants, zero] at inv
      have pathLen : segment.data.toList.length = segment.size := Array.length_toList
      have nonempty : segment.data.toList ≠ [] := fun empty => by
        rw [empty] at pathLen
        exact nonzero (by simpa using pathLen.symm)
      refine preserves_ite _ (fun _ => preserves_weaken
        (preserves_pure B ⟨resultOk_some awidth, ok, Nat.le_add_right _ _⟩) (by omega)
        fun _ h => h)
        (fun isPrefix => ?_)
      have pre : segment.data.toList <+: rest := by
        simp only [Bool.not_eq_true', Bool.not_eq_false] at isPrefix
        exact List.isPrefixOf_iff_prefix.mp isPrefix
      have lenLe := pre.length_le
      refine preserves_weaken (ih child (rest.drop segment.data.toList.length)
        (.extension address segment.data.toList child :: stack) cwidth (nibbles_drop nib _)
        (rstackOk_cons ⟨nibbles_of_nibblesWf segWf, nonempty, cwidth, awidth⟩ ok))
        (Nat.le_refl _) (fun r ⟨rok, sok, cost⟩ => ⟨rok, sok, ?_⟩)
      simp only [stackCost, List.length_drop] at cost ⊢
      omega
    | branch children value =>
      dsimp only
      obtain ⟨bok, _⟩ := branchOk_of_loaded wf inv
      cases rest with
      | nil =>
        cases value with
        | none =>
          try dsimp only
          exact preserves_weaken (preserves_pure B ⟨resultOk_some awidth, ok, Nat.le_add_right _ _⟩)
            (by omega) fun _ h => h
        | some x =>
          try dsimp only
          have bok' : BranchOk children none := ⟨bok.1, bok.2.1, fun _ h => by cases h⟩
          exact preserves_bind (preserves_collapse bok' (B := B) small)
            (fun r rok => preserves_pure _ ⟨rok, ok, Nat.le_add_right _ _⟩) (Nat.le_refl _)
      | cons nibble rest =>
        dsimp only
        cases probe : childAt children nibble with
        | none =>
          try dsimp only
          exact preserves_weaken (preserves_pure B ⟨resultOk_some awidth, ok, Nat.le_add_right _ _⟩)
            (by omega) fun _ h => h
        | some child =>
          try dsimp only
          have cwidth := bok.2.1 (some child) (mem_of_childAt probe) child rfl
          refine preserves_weaken (ih child rest (.branch address children value nibble child :: stack)
            cwidth (nibbles_tail nib) (rstackOk_cons ⟨bok, awidth⟩ ok))
            (Nat.le_refl _) (fun r ⟨rok, sok, cost⟩ => ⟨rok, sok, ?_⟩)
          simp only [stackCost, List.length_cons] at cost ⊢
          omega
    | route children value =>
      dsimp only
      obtain ⟨bok, _⟩ := routeOk_of_loaded wf inv
      cases rest with
      | nil =>
        cases value with
        | none =>
          try dsimp only
          exact preserves_weaken (preserves_pure B ⟨resultOk_some awidth, ok, Nat.le_add_right _ _⟩)
            (by omega) fun _ h => h
        | some x =>
          try dsimp only
          have bok' : BranchOk children none := ⟨bok.1, bok.2.1, fun _ h => by cases h⟩
          exact preserves_bind (preserves_retainRoute (value := none) bok' B)
            (fun r rok => preserves_pure _ ⟨rok, ok, Nat.le_add_right _ _⟩) (Nat.le_refl _)
      | cons nibble rest =>
        dsimp only
        cases probe : childAt children nibble with
        | none =>
          try dsimp only
          exact preserves_weaken (preserves_pure B ⟨resultOk_some awidth, ok, Nat.le_add_right _ _⟩)
            (by omega) fun _ h => h
        | some child =>
          try dsimp only
          have cwidth := bok.2.1 (some child) (mem_of_childAt probe) child rfl
          refine preserves_weaken (ih child rest (.route address children value nibble child :: stack)
            cwidth (nibbles_tail nib) (rstackOk_cons ⟨bok, awidth⟩ ok))
            (Nat.le_refl _) (fun r ⟨rok, sok, cost⟩ => ⟨rok, sok, ?_⟩)
          simp only [stackCost, List.length_cons] at cost ⊢
          omega

theorem preserves_removeAt {B : Nat} (fuel : Nat) {address : ByteArray} (awidth : address.size = 32)
    {rest : List UInt8} (nib : Nibbles rest) (small : B + 1 + rest.length < 2 ^ 64) :
    Preserves (removeAt fuel address rest) B (B + 1 + rest.length) ResultOk := by
  unfold removeAt
  refine preserves_bind (preserves_descendRemove (by omega) fuel address rest [] awidth nib rstackOk_nil)
    (fun r ⟨rok, sok, cost⟩ => ?_) (by omega)
  obtain ⟨result, stack⟩ := r
  dsimp only at rok sok cost ⊢
  simp only [stackCost, Nat.zero_add] at cost
  exact preserves_weaken (preserves_unwind stack result (B + 1) sok rok (by omega)) (by omega)
    fun _ h => h

theorem emptyRoot_width : emptyRoot.size = 32 := rfl

/-- Every remove from a shaped store leaves a shaped store; what its merges
push down is bounded by the key, so the run bound grows by at most a key. -/
theorem remove_preserves {B : Nat} (small : B + 1 + maxKeyBytes * 2 < 2 ^ 64)
    {root : ByteArray} (rwidth : root.size = 32) (key : ByteArray) :
    Preserves (remove root key) B (B + 1 + maxKeyBytes * 2) (fun h => h.size = 32) := by
  unfold remove
  dsimp only
  refine preserves_ite _ (fun _ => preserves_weaken (preserves_bind (preserves_throw _ B (fun _ => False))
    (fun _ h => h.elim) (Nat.le_refl _)) (by omega) fun _ h => h) (fun keyWithin => ?_)
  refine preserves_ite _ (fun _ => preserves_weaken (preserves_pure B emptyRoot_width) (by omega)
    fun _ h => h) (fun _ => ?_)
  have keyLen : (keyNibbles key).length ≤ maxKeyBytes * 2 := by
    rw [keyNibbles_length]
    have : ¬ key.size > maxKeyBytes := keyWithin
    omega
  refine preserves_bind (preserves_removeAt depthBudget rwidth (nibbles_keyNibbles key) (by omega))
    (fun r rok => ?_) (by omega)
  cases r with
  | none =>
    dsimp only
    exact preserves_weaken (preserves_pure (a := emptyRoot) (P := fun h => h.size = 32) _
      emptyRoot_width) (by omega) fun _ h => h
  | some h =>
    dsimp only
    exact preserves_weaken (preserves_pure (a := h) (P := fun h => h.size = 32) _ (rok h rfl))
      (by omega) fun _ h => h

end Synchronicity.TrieMutateProofs
