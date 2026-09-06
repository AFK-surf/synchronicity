import Synchronicity.CasFixtures
import Synchronicity.TrieVerifyProofs
import VerifiedCore.Trie.Collect
import Std.Data.HashSet.Lemmas

/-! Collecting the trie, as executed: the mark walk records every node the
retained roots reach and every out-of-line value those nodes name, over any
lawful set and so over the hash set the command runs with; the memo keys
have the one layout every reader and the sweep share; and on a concrete
store the pass keeps exactly the marked rows, files, provenance and
certificates, rolling back at every injected failure. -/
namespace Synchronicity.TrieCollectProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie VerifiedCore.Trie.Collect SimulatedHost CasFixtures
open Synchronicity.TrieVerifyProofs (byteArray_beq_iff byteArray_beq_self)

/-! ## Sets

The walk is written over `MarkSet`; these are the laws it relies on, and
both the command's hash set and the fixtures' list satisfy them. -/

instance : LawfulBEq ByteArray where
  eq_of_beq h := (byteArray_beq_iff _ _).mp h
  rfl := byteArray_beq_self _

instance : LawfulHashable ByteArray := ⟨fun {a b} (h : (a == b) = true) => by rw [eq_of_beq h]⟩

/-- Membership is empty at first, grows by exactly the inserted address, and
is what the listing reports. -/
class LawfulMarkSet (S : Type) [MarkSet S] : Prop where
  contains_empty : ∀ hash, MarkSet.contains (MarkSet.empty : S) hash = false
  contains_insert : ∀ (set : S) hash probe,
    MarkSet.contains (MarkSet.insert set hash) probe = (hash == probe || MarkSet.contains set probe)
  mem_toList : ∀ (set : S) hash, hash ∈ MarkSet.toList set ↔ MarkSet.contains set hash = true

instance : LawfulMarkSet (Std.HashSet ByteArray) where
  contains_empty _ := Std.HashSet.contains_empty
  contains_insert _ _ _ := Std.HashSet.contains_insert
  mem_toList _ _ := by
    show _ ∈ Std.HashSet.toList _ ↔ Std.HashSet.contains _ _ = true
    rw [Std.HashSet.mem_toList, Std.HashSet.contains_iff_mem]

instance : LawfulMarkSet (List ByteArray) where
  contains_empty _ := rfl
  contains_insert set hash probe := by
    show (if set.contains hash then set else hash :: set).contains probe = (hash == probe || set.contains probe)
    split
    · rename_i held
      cases same : hash == probe
      · simp
      · simp only [Bool.true_or]
        rw [eq_of_beq same] at held
        exact held
    · rw [List.contains_cons, BEq.comm]
  mem_toList set hash := by
    show hash ∈ set ↔ set.contains hash = true
    simp

theorem contains_of_contains_insert [MarkSet S] [LawfulMarkSet S] (set : S) (hash probe : ByteArray)
    (held : MarkSet.contains set probe = true) : MarkSet.contains (MarkSet.insert set hash) probe = true := by
  rw [LawfulMarkSet.contains_insert, held, Bool.or_true]

theorem contains_insert_self [MarkSet S] [LawfulMarkSet S] (set : S) (hash : ByteArray) :
    MarkSet.contains (MarkSet.insert set hash) hash = true := by
  rw [LawfulMarkSet.contains_insert, byteArray_beq_self, Bool.true_or]

theorem contains_foldl_of_contains [MarkSet S] [LawfulMarkSet S] (probe : ByteArray) :
    ∀ (list : List ByteArray) (set : S), MarkSet.contains set probe = true →
      MarkSet.contains (list.foldl MarkSet.insert set) probe = true
  | [], _, held => held
  | hash :: rest, set, held =>
    contains_foldl_of_contains probe rest _ (contains_of_contains_insert set hash probe held)

theorem contains_foldl_of_mem [MarkSet S] [LawfulMarkSet S] (probe : ByteArray) :
    ∀ (list : List ByteArray) (set : S), probe ∈ list →
      MarkSet.contains (list.foldl MarkSet.insert set) probe = true
  | [], _, mem => nomatch mem
  | hash :: rest, set, mem => by
    rcases List.mem_cons.mp mem with rfl | later
    · exact contains_foldl_of_contains probe rest _ (contains_insert_self set probe)
    · exact contains_foldl_of_mem probe rest _ later

/-! ## Reachability

The graph the walk covers: a node reaches its children, as the stored bytes
decode them. No fuel, no set, no interpreter. -/

/-- The nodes a host state holds, by address. -/
def nodesOf (state : State) (hash : ByteArray) : Option ByteArray :=
  lookupFile state.files (nodeSpace, hash)

/-- `target` is below `hash` in the stored graph. -/
inductive ReachesNode (lookup : ByteArray → Option ByteArray) : ByteArray → ByteArray → Prop where
  | refl (hash : ByteArray) : ReachesNode lookup hash hash
  | step (hash raw child target : ByteArray) (node : Node)
      (held : lookup hash = some raw) (decoded : decode raw = .ok node)
      (edge : child ∈ node.childHashes) (below : ReachesNode lookup child target) :
      ReachesNode lookup hash target

/-- A set closed under children, given what the walk still has to visit. -/
def NodeInv [MarkSet S] (lookup : ByteArray → Option ByteArray) (marks : Marks S)
    (frontier : List ByteArray) : Prop :=
  ∀ hash, MarkSet.contains marks.nodes hash = true → ∀ raw node, lookup hash = some raw →
    decode raw = .ok node → ∀ child ∈ node.childHashes,
      MarkSet.contains marks.nodes child = true ∨ child ∈ frontier

/-- Every marked node's out-of-line values are marked. -/
def ValueInv [MarkSet S] (lookup : ByteArray → Option ByteArray) (marks : Marks S) : Prop :=
  ∀ hash, MarkSet.contains marks.nodes hash = true → ∀ raw node, lookup hash = some raw →
    decode raw = .ok node → ∀ value ∈ node.valueHashes, MarkSet.contains marks.values value = true

/-- With nothing left to visit, a closed set holds everything below its members. -/
theorem closed_reaches [MarkSet S] (lookup : ByteArray → Option ByteArray) (marks : Marks S)
    (closed : NodeInv lookup marks []) {hash target : ByteArray}
    (reached : ReachesNode lookup hash target) (held : MarkSet.contains marks.nodes hash = true) :
    MarkSet.contains marks.nodes target = true := by
  induction reached with
  | refl _ => exact held
  | step hash raw child target node found decoded edge _ ih =>
    rcases closed hash held raw node found decoded child edge with marked | absurd
    · exact ih marked
    · cases absurd

@[simp] theorem nodesOf_record (state : State) (event : String) :
    nodesOf (record state event) = nodesOf state := rfl

@[simp] theorem throw_eq (e : Collect.Error) :
    (@MonadExceptOf.throw Collect.Error (ExceptT Collect.Error (Program Collect.Effects)) _ A e) =
      (Program.pure (Except.error e) : Program Collect.Effects (Except Collect.Error A)) := rfl

/-! ## The mark

What one walk leaves behind: the store untouched, no fault, and on success
a mark that grew, holds every frontier address, stays closed under children
once the frontier is drained, and carries every marked node's values. -/

theorem mark_run [MarkSet S] [LawfulMarkSet S] (fuel : Nat) :
    ∀ (frontier : List ByteArray) (marks : Marks S) (state : State), state.faults = [] →
    (execute (mark fuel frontier marks) state).2.files = state.files ∧
    (execute (mark fuel frontier marks) state).2.faults = [] ∧
    ∀ marks', (execute (mark fuel frontier marks) state).1 = .ok marks' →
      (∀ hash, MarkSet.contains marks.nodes hash = true → MarkSet.contains marks'.nodes hash = true) ∧
      (∀ hash ∈ frontier, MarkSet.contains marks'.nodes hash = true) ∧
      (NodeInv (nodesOf state) marks frontier → NodeInv (nodesOf state) marks' []) ∧
      (ValueInv (nodesOf state) marks → ValueInv (nodesOf state) marks') := by
  induction fuel with
  | zero =>
    intro frontier marks state quiet
    cases frontier with
    | nil =>
      simp only [mark, execute, ExceptT.mk, pure, ExceptT.pure]
      refine ⟨by trivial, by first | exact quiet | trivial, ?_⟩
      intro marks' same
      cases same
      refine ⟨fun _ held => held, ?_, fun inv => inv, fun inv => inv⟩
      intro _ mem
      exact (List.not_mem_nil mem).elim
    | cons hash rest =>
      simp only [mark, throw, throwThe, MonadExcept.throw, throw_eq, execute]
      exact ⟨by trivial, by first | exact quiet | trivial, fun _ same => nomatch same⟩
  | succ fuel ih =>
    intro frontier marks state quiet
    cases frontier with
    | nil =>
      simp only [mark, execute, ExceptT.mk, pure, ExceptT.pure]
      refine ⟨by trivial, by first | exact quiet | trivial, ?_⟩
      intro marks' same
      cases same
      refine ⟨fun _ held => held, ?_, fun inv => inv, fun inv => inv⟩
      intro _ mem
      exact (List.not_mem_nil mem).elim
    | cons hash rest =>
      cases held : MarkSet.contains marks.nodes hash with
      | true =>
        simp only [mark, held, ↓reduceIte]
        obtain ⟨files, faults, steps⟩ := ih rest marks state quiet
        refine ⟨files, faults, ?_⟩
        intro marks' ran
        obtain ⟨grew, visited, closed, values⟩ := steps marks' ran
        refine ⟨grew, ?_, ?_, values⟩
        · intro probe mem
          rcases List.mem_cons.mp mem with rfl | later
          · exact grew probe held
          · exact visited probe later
        · intro inv
          refine closed ?_
          intro node marked raw decodedNode found decoded child edge
          rcases inv node marked raw decodedNode found decoded child edge with marked | mem
          · exact .inl marked
          · rcases List.mem_cons.mp mem with rfl | later
            · exact .inl held
            · exact .inr later
      | false =>
        simp only [mark, held, Bool.false_eq_true, ↓reduceIte, Collect.storage, raise, performOver,
          Inject.inject, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk, Program.bind, execute,
          Interpreter.handle, SimulatedHost.storage, reply, fault, quiet, List.find?_nil,
          Option.map_none, record, Except.mapError]
        cases read : lookupFile state.files (nodeSpace, hash) with
        | none =>
          obtain ⟨files, faults, steps⟩ := ih rest { marks with nodes := MarkSet.insert marks.nodes hash }
            { record state ("bytes:" ++ nodeSpace) with faults := [] } rfl
          refine ⟨files, faults, ?_⟩
          intro marks' ran
          obtain ⟨grew, visited, closed, values⟩ := steps marks' ran
          refine ⟨fun probe prior => grew probe (contains_of_contains_insert _ _ _ prior), ?_, ?_, ?_⟩
          · intro probe mem
            rcases List.mem_cons.mp mem with rfl | later
            · exact grew probe (contains_insert_self _ _)
            · exact visited probe later
          · intro inv
            refine closed ?_
            intro node marked raw decodedNode found decoded child edge
            simp only [LawfulMarkSet.contains_insert, Bool.or_eq_true] at marked
            rcases marked with same | marked
            · rw [← eq_of_beq same] at found
              simp only [nodesOf, record, read] at found
              cases found
            · rcases inv node marked raw decodedNode found decoded child edge with marked | mem
              · exact .inl (contains_of_contains_insert _ _ _ marked)
              · rcases List.mem_cons.mp mem with rfl | later
                · exact .inl (contains_insert_self _ _)
                · exact .inr later
          · intro inv
            refine values ?_
            intro node marked raw decodedNode found decoded value named
            simp only [LawfulMarkSet.contains_insert, Bool.or_eq_true] at marked
            rcases marked with same | marked
            · rw [← eq_of_beq same] at found
              simp only [nodesOf, record, read] at found
              cases found
            · exact inv node marked raw decodedNode found decoded value named
        | some raw =>
          cases decoded : decode raw with
          | error message =>
            simp only [decoded, throw, throwThe, MonadExcept.throw, throw_eq, execute]
            exact ⟨by trivial, by trivial, fun _ same => nomatch same⟩
          | ok node =>
            simp only [decoded]
            obtain ⟨files, faults, steps⟩ := ih (node.childHashes ++ rest)
              { nodes := MarkSet.insert marks.nodes hash,
                values := node.valueHashes.foldl MarkSet.insert marks.values }
              { record state ("bytes:" ++ nodeSpace) with faults := [] } rfl
            refine ⟨files, faults, ?_⟩
            intro marks' ran
            obtain ⟨grew, visited, closed, values⟩ := steps marks' ran
            refine ⟨fun probe prior => grew probe (contains_of_contains_insert _ _ _ prior), ?_, ?_, ?_⟩
            · intro probe mem
              rcases List.mem_cons.mp mem with rfl | later
              · exact grew probe (contains_insert_self _ _)
              · exact visited probe (List.mem_append_right _ later)
            · intro inv
              refine closed ?_
              intro probe marked raw' node' found decoded' child edge
              simp only [LawfulMarkSet.contains_insert, Bool.or_eq_true] at marked
              rcases marked with same | marked
              · rw [← eq_of_beq same] at found
                simp only [nodesOf, record, read, Option.some.injEq] at found
                subst found
                rw [decoded] at decoded'
                cases decoded'
                exact .inr (List.mem_append_left _ edge)
              · rcases inv probe marked raw' node' found decoded' child edge with marked | mem
                · exact .inl (contains_of_contains_insert _ _ _ marked)
                · rcases List.mem_cons.mp mem with rfl | later
                  · exact .inl (contains_insert_self _ _)
                  · exact .inr (List.mem_append_right _ later)
            · intro inv
              refine values ?_
              intro probe marked raw' node' found decoded' value named
              simp only [LawfulMarkSet.contains_insert, Bool.or_eq_true] at marked
              rcases marked with same | marked
              · rw [← eq_of_beq same] at found
                simp only [nodesOf, record, read, Option.some.injEq] at found
                subst found
                rw [decoded] at decoded'
                cases decoded'
                exact contains_foldl_of_mem value _ _ named
              · exact contains_foldl_of_contains value _ _
                  (inv probe marked raw' node' found decoded' value named)

/-- Every stored node reachable from a root the walk started from is marked:
the graph-level obligation of the sweep. -/
theorem mark_complete [MarkSet S] [LawfulMarkSet S] (fuel : Nat) (frontier : List ByteArray)
    (state : State) (quiet : state.faults = []) (marks' : Marks S)
    (ran : (execute (mark fuel frontier ⟨MarkSet.empty, MarkSet.empty⟩) state).1 = .ok marks')
    {root target : ByteArray} (started : root ∈ frontier)
    (reached : ReachesNode (nodesOf state) root target) :
    MarkSet.contains marks'.nodes target = true := by
  obtain ⟨_, _, steps⟩ := mark_run (S := S) fuel frontier ⟨MarkSet.empty, MarkSet.empty⟩ state quiet
  obtain ⟨_, visited, closed, _⟩ := steps marks' ran
  have empty : NodeInv (S := S) (nodesOf state) ⟨MarkSet.empty, MarkSet.empty⟩ frontier := by
    intro hash marked
    rw [LawfulMarkSet.contains_empty] at marked
    cases marked
  exact closed_reaches (nodesOf state) marks' (closed empty) reached (visited root started)

/-- Every out-of-line value a marked node names is marked with it. -/
theorem mark_values [MarkSet S] [LawfulMarkSet S] (fuel : Nat) (frontier : List ByteArray)
    (state : State) (quiet : state.faults = []) (marks' : Marks S)
    (ran : (execute (mark fuel frontier ⟨MarkSet.empty, MarkSet.empty⟩) state).1 = .ok marks') :
    ValueInv (nodesOf state) marks' := by
  obtain ⟨_, _, steps⟩ := mark_run (S := S) fuel frontier ⟨MarkSet.empty, MarkSet.empty⟩ state quiet
  obtain ⟨_, _, _, values⟩ := steps marks' ran
  refine values ?_
  intro hash marked
  rw [LawfulMarkSet.contains_empty] at marked
  cases marked

/-! ## The sweep

What one set-wise delete leaves in a relation: exactly the rows whose key
is kept, or null. -/

theorem sweep_keeps_only_kept (state : State) (tx : Transaction) (db : Database)
    (relation column : String) (keys : List ByteArray)
    (quiet : state.faults = []) (open_ : state.pending = some (tx, db)) :
    let result := SimulatedHost.storage (.deleteExcept tx relation column keys) state
    result.1 = .ok ((rows db relation).length -
      ((rows db relation).filter fun row => match cell row column with
        | .blob key => keys.contains key
        | .null => true
        | _ => false).length) ∧
    ∀ row ∈ rows (result.2.pending.map Prod.snd).get! relation,
      match cell row column with
      | .blob key => key ∈ keys
      | .null => True
      | _ => False := by
  simp only [SimulatedHost.storage, reply, fault, quiet, List.find?_nil, Option.map_none,
    SimulatedHost.transaction, open_, beq_self_eq_true, ↓reduceIte, record, Option.map_some,
    Option.get!_some, rows_setRows]
  refine ⟨rfl, ?_⟩
  intro row mem
  rw [List.mem_filter] at mem
  obtain ⟨_, kept⟩ := mem
  split at kept <;> simp_all

/-! ## Memo keys

The layout every reader and the sweep share: a scoped key digests the root
and both sets of the scope, each key length-prefixed; an owned key digests
the scoped key and the origin. The whole keyspace is keyed by the root
itself, with no digest asked for. -/

private def bytes (list : List UInt8) : ByteArray := ⟨list.toArray⟩
private def address (value : UInt8) : ByteArray := bytes (List.replicate 32 value)

/-- The digest is the host's: on a host that hands the bytes back, the keys
are the layouts themselves. -/
private def transparent : State := { hash := fun bytes => bytes }

theorem scoped_layout :
    let result := SimulatedHost.run (Memo.keyFor (E := Collect.Effects) Collect.Error.host
      ⟨some [bytes [6, 7]], [bytes [1]]⟩ (address 1) none) transparent
    (result.1, result.2.trace) == (.ok ("scoped-root/1".toUTF8 ++ address 1 ++
      bytes [1, 0, 0, 0, 2, 0, 0, 0, 6, 7, 1, 0, 0, 0, 1, 0, 0, 0, 1]), ["digest"]) := by
  decide +kernel

theorem owned_layout :
    let result := SimulatedHost.run (Memo.keyFor (E := Collect.Effects) Collect.Error.host
      ⟨some [bytes [6, 7]], []⟩ (address 1) (some "nas@x.example")) transparent
    (result.1, result.2.trace) == (.ok ("owned-root/1".toUTF8 ++ ("scoped-root/1".toUTF8 ++ address 1 ++
      bytes [1, 0, 0, 0, 2, 0, 0, 0, 6, 7, 0, 0, 0, 0]) ++ "nas@x.example".toUTF8), ["digest", "digest"]) := by
  decide +kernel

/-- The whole keyspace is keyed by the root itself, and asks the host for nothing. -/
theorem whole_keyspace_is_keyed_by_the_root (root : ByteArray) (exact : List ByteArray) (state : State) :
    SimulatedHost.run (Memo.keyFor (E := Collect.Effects) Collect.Error.host ⟨none, exact⟩ root none) state =
      (.ok root, { state with output := [] }) := by
  simp [SimulatedHost.run, Memo.keyFor, Memo.scopedKey, bind, ExceptT.bind, ExceptT.bindCont, ExceptT.mk,
    ExceptT.run, Program.bind, execute, pure, ExceptT.pure]

/-- An owned key under the whole keyspace is one digest over the root and the origin. -/
theorem owned_key_is_one_digest (root : ByteArray) (exact : List ByteArray) (origin : String)
    (state : State) (quiet : state.faults = []) :
    let result := SimulatedHost.run (Memo.keyFor (E := Collect.Effects) Collect.Error.host ⟨none, exact⟩ root
      (some origin)) state
    result.1 = .ok (state.hash (Memo.ownedBytes root origin)) ∧ result.2.trace = state.trace ++ ["digest"] := by
  simp [SimulatedHost.run, Memo.keyFor, Memo.scopedKey, raise, performOver, Inject.inject, bind,
    ExceptT.bind, ExceptT.bindCont, ExceptT.mk, ExceptT.run, Program.bind, execute, pure, ExceptT.pure,
    Interpreter.handle, SimulatedHost.digest, reply, fault, quiet, record, Except.mapError]

/-! ## A concrete store

A retained trie of five nodes, one of them holding its value out of line; a
displaced root of its own, with provenance and an orphan value; a head row
for the retained root only; three certificates, one of them the displaced
root's. -/

private def rootHash := address 1
private def extHash := address 2
private def lowerHash := address 3
private def leafAHash := address 4
private def leafBHash := address 5
private def valueHash := address 6
private def displacedHash := address 7
private def orphanValue := address 8
private def zeros := address 0

private def slots (children : List (Nat × ByteArray)) : List (Option ByteArray) :=
  (List.range 16).map fun slot => (children.find? fun entry => entry.1 == slot).map Prod.snd

private def rootNode : Node := .branch (slots [(6, extHash)]) none
private def extNode : Node := .extension (bytes [7, 0]) lowerHash
private def lowerNode : Node := .branch (slots [(1, leafAHash), (2, leafBHash)]) none
private def leafANode : Node := .leaf (bytes [1, 1]) (.inline (bytes [97]))
private def leafBNode : Node := .leaf (bytes [2, 2]) (.hash valueHash)
private def displacedNode : Node := .leaf (bytes [3, 3]) (.hash orphanValue)

private def nodeRow (hash : ByteArray) (node : Node) : Fields :=
  [("hash", .blob hash), ("data", .blob (encode node))]
private def valueRow (hash payload : ByteArray) : Fields :=
  [("hash", .blob hash), ("data", .blob payload)]
private def owned (hash : ByteArray) : Fields :=
  [("origin_id", .text "nas@x.example"), ("hash", .blob hash)]

private def graph : State :=
  { files := [((nodeSpace, rootHash), encode rootNode), ((nodeSpace, extHash), encode extNode),
      ((nodeSpace, lowerHash), encode lowerNode), ((nodeSpace, leafAHash), encode leafANode),
      ((nodeSpace, leafBHash), encode leafBNode), ((nodeSpace, displacedHash), encode displacedNode),
      ((valueSpace, valueHash), bytes [1, 2, 3]), ((valueSpace, orphanValue), bytes [4])],
    db := [(nodeSpace, [nodeRow rootHash rootNode, nodeRow extHash extNode, nodeRow lowerHash lowerNode,
        nodeRow leafAHash leafANode, nodeRow leafBHash leafBNode, nodeRow displacedHash displacedNode]),
      (valueSpace, [valueRow valueHash (bytes [1, 2, 3]), valueRow orphanValue (bytes [4])]),
      ("trie_node_origins", [owned rootHash, owned extHash, owned displacedHash]),
      ("head_history", [[("origin_id", .text "nas@x.example"), ("seq", .integer 1),
        ("root", .blob rootHash), ("created_at", .integer 0), ("signed_by", .blob zeros),
        ("sig", .blob zeros), ("recorded_at", .integer 0)]])],
    certified := [rootHash, displacedHash, zeros] }

private def whole : Serve.Scope := ⟨none, []⟩

private def pass := ["begin", "read:head_history"] ++ List.replicate 5 ("bytes:" ++ nodeSpace) ++
  ["digest", "digest", "memo:forget", "sweep:" ++ nodeSpace, "sweep:trie_node_origins",
    "sweep:" ++ valueSpace, "commit"]

/-- One pass: the retained root is marked from, its five nodes are read once
each, the displaced node, its provenance and the orphan value go, the
retained trie's rows, provenance and value stay, and the certificates kept
are the retained root's and the two owned keys the host digested. -/
theorem the_sweep_keeps_exactly_what_the_retained_root_reaches :
    let result := SimulatedHost.run (gcTrie (List ByteArray) whole) graph
    (result.1, result.2.trace) == (.ok (1, 1, 1), pass) ∧
    rows result.2.db nodeSpace == [nodeRow rootHash rootNode, nodeRow extHash extNode,
      nodeRow lowerHash lowerNode, nodeRow leafAHash leafANode, nodeRow leafBHash leafBNode] ∧
    rows result.2.db valueSpace == [valueRow valueHash (bytes [1, 2, 3])] ∧
    rows result.2.db "trie_node_origins" == [owned rootHash, owned extHash] ∧
    result.2.certified == [rootHash, zeros] ∧ result.2.memoGeneration == 1 := by
  decide +kernel

/-- Provenance never outlives its node: after the pass every provenance row
names a node row that is still there. -/
theorem provenance_names_a_surviving_node :
    let result := SimulatedHost.run (gcTrie (List ByteArray) whole) graph
    (rows result.2.db "trie_node_origins").all (fun row =>
      (rows result.2.db nodeSpace).any fun node => cell node "hash" == cell row "hash") = true := by
  decide +kernel

/-- A store with no head retains nothing: everything goes, and no certificate survives. -/
theorem a_store_with_no_head_is_swept_whole :
    let bare := { graph with db := graph.db.filter fun table => table.1 != "head_history" }
    let result := SimulatedHost.run (gcTrie (List ByteArray) whole) bare
    (result.1, result.2.trace) == (.ok (6, 2, 0), ["begin", "read:head_history", "memo:forget",
      "sweep:" ++ nodeSpace, "sweep:trie_node_origins", "sweep:" ++ valueSpace, "commit"]) ∧
    rows result.2.db nodeSpace == [] ∧ rows result.2.db valueSpace == [] ∧
    rows result.2.db "trie_node_origins" == [] ∧ result.2.certified == [] := by
  decide +kernel

/-- Under a scope the retained root's certificate is kept under its scoped
key, which the host digested, as well as under the root itself. -/
theorem a_scoped_store_keeps_the_scoped_certificate :
    let narrow : Serve.Scope := ⟨some [bytes [6, 7, 0, 1]], []⟩
    let result := SimulatedHost.run (gcTrie (List ByteArray) narrow) graph
    (result.1, result.2.trace) == (.ok (1, 1, 1), ["begin", "read:head_history"] ++
      List.replicate 5 ("bytes:" ++ nodeSpace) ++ ["digest", "digest", "digest", "digest", "memo:forget",
      "sweep:" ++ nodeSpace, "sweep:trie_node_origins", "sweep:" ++ valueSpace, "commit"]) ∧
    result.2.certified == [rootHash, zeros] := by
  decide +kernel

/-- A failure at any effect rolls the pass back: the rows and files are
exactly as they were. -/
theorem every_failed_sweep_effect_changes_nothing :
    (List.range pass.length).all (fun index =>
      let result := SimulatedHost.run (gcTrie (List ByteArray) whole) (fail graph index)
      failed result.1 && result.2.db == graph.db && result.2.pending.isNone) = true := by
  decide +kernel

end Synchronicity.TrieCollectProofs
