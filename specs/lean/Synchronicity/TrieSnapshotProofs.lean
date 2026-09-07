import Synchronicity.TrieProgramProofs

/-! Snapshot meaning for the user-facing read and synchronization promises.

Membership is a finite path in the stored graph, not successful traversal or
a completeness flag. A replica can hold only part of a published graph; the
theorems below connect its actual reads to that independent meaning. They do
not assume that a refusal certifies absence, and do not establish that fetch
has obtained every required path. -/
namespace Synchronicity.TrieSnapshotProofs
open VerifiedCore VerifiedCore.Host VerifiedCore.Trie
open TrieProgramProofs

/-- The entries of a published snapshot, including the distinguished empty
snapshot and the public key-size bound. -/
def Entry (store : RawSnapshot) (root key bytes : ByteArray) : Prop :=
  key.size ≤ maxKeyBytes ∧ root.data.all (· == 0) = false ∧
    GraphValue store root (keyNibbles key) bytes

/-- Permissions select entries; the grant predicate is supplied by the
authorization domain, independently of serving and fetching decisions. -/
def SharedEntry (allowed : ByteArray → Prop) (store : RawSnapshot)
    (root key bytes : ByteArray) : Prop :=
  allowed key ∧ Entry store root key bytes

/-- Every raw record held by `part` is the corresponding record in `whole`.
Hash verification/provenance must establish this relation at receive time;
the relation itself grants no authority to receive another record. -/
def RecordsIncluded (part whole : RawSnapshot) : Prop :=
  ∀ space key bytes, (space = nodeSpace ∨ space = valueSpace) →
    part space key = some bytes → whole space key = some bytes

theorem graph_value_preserved (included : RecordsIncluded part whole)
    (entry : GraphValue part root key bytes) : GraphValue whole root key bytes := by
  have value : ∀ {v bytes}, ValueDenotes part v bytes → ValueDenotes whole v bytes := by
    intro v bytes denotes
    cases denotes with
    | inline bytes => exact .inline bytes
    | stored hash bytes held => exact .stored hash bytes (included _ _ _ (.inr rfl) held)
  induction entry with
  | leaf address raw suffix v bytes held decoded denotes =>
    exact .leaf address raw suffix v bytes (included _ _ _ (.inl rfl) held) decoded (value denotes)
  | branchValue address raw children v bytes held decoded denotes =>
    exact .branchValue address raw children v bytes
      (included _ _ _ (.inl rfl) held) decoded (value denotes)
  | extension address raw segment child tail bytes held decoded nonempty _ ih =>
    exact .extension address raw segment child tail bytes
      (included _ _ _ (.inl rfl) held) decoded nonempty ih
  | branchChild address raw children v nibble child tail bytes held decoded edge _ ih =>
    exact .branchChild address raw children v nibble child tail bytes
      (included _ _ _ (.inl rfl) held) decoded edge ih

/-- At the production read budget, reading a value is exactly membership in
the selected snapshot. The statement includes empty roots and oversized keys. -/
theorem read_exactly_snapshot (store : RawSnapshot) (root key bytes : ByteArray) :
    executeReads store (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some bytes))) ↔ Entry store root key bytes := by
  constructor
  · exact get_semantic_sound store _ root key bytes
  · intro ⟨bounded, nonzero, path⟩
    exact get_semantic_complete path bounded nonzero

/-- An authenticated partial replica cannot invent a snapshot entry. Missing
records may prevent a read, but any successful read has the publisher's value. -/
theorem replica_read_belongs_to_snapshot (included : RecordsIncluded replica publisher)
    (returned : executeReads replica (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some bytes)))) : Entry publisher root key bytes := by
  obtain ⟨bounded, nonzero, path⟩ := (read_exactly_snapshot replica root key bytes).mp returned
  exact ⟨bounded, nonzero, graph_value_preserved included path⟩

/-- Keeping the records of an existing snapshot preserves every successful
read of that version. This applies even when additional unrelated records
have arrived, and is the semantic preservation obligation for receive/GC. -/
theorem retained_snapshot_still_reads (included : RecordsIncluded before after)
    (returned : executeReads before (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some bytes)))) :
    executeReads after (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some bytes))) := by
  exact (read_exactly_snapshot after root key bytes).mpr
    (replica_read_belongs_to_snapshot included returned)

/-- Two authenticated replicas which can read the same key of the same
published version return identical bytes, irrespective of other local data.
This is agreement of successful reads, not eventual availability. -/
theorem replicas_agree_on_read (leftIncluded : RecordsIncluded left publisher)
    (rightIncluded : RecordsIncluded right publisher)
    (leftRead : executeReads left (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some leftBytes))))
    (rightRead : executeReads right (maxKeyBytes * 2 + 2) (Trie.get root key).run =
      some (.ok (.ok (some rightBytes)))) : leftBytes = rightBytes := by
  exact graph_value_unique
    (replica_read_belongs_to_snapshot leftIncluded leftRead).2.2
    (replica_read_belongs_to_snapshot rightIncluded rightRead).2.2

end Synchronicity.TrieSnapshotProofs
