import Synchronicity.TrieFetchCompletion
import Synchronicity.ByteArrayProofs
import VerifiedCore.Trie.Missing

/-! Structural decomposition of a publisher requirement at one decoded node.
This is independent of the missing-walk frontier invariant: callers decide
whether direct evidence is already present, deferred, or pushed as a child. -/
namespace Synchronicity.TrieMissingTransfer
open VerifiedCore VerifiedCore.Trie VerifiedCore.Trie.Missing
open TrieFetchCompletion

/-- Every requirement rooted at a decoded publisher node is either evidence
for that node/provenance, a value referenced directly by it, or a requirement
rooted at one of the exact relative children emitted by production
`pairedChildren none`. -/
theorem needs_direct_or_child
    {publisher : TrieProgramProofs.RawSnapshot} {scope : Serve.Scope}
    {owner : Option String} {hash raw : ByteArray} {node : Node}
    {path : List UInt8} {evidence : Evidence}
    (held : publisher nodeSpace hash = some raw)
    (decoded : decode raw = .ok node)
    (needed : Needs publisher scope owner hash path evidence) :
    evidence = .node hash raw ∨
      (∃ origin, owner = some origin ∧ evidence = .provenance origin hash) ∨
      (∃ address bytes, evidence = .value address bytes ∧
        address ∈ node.valueHashes ∧ publisher valueSpace address = some bytes ∧
        scope.admitsValue path node = true) ∨
      ∃ child, child ∈ pairedChildren none node ∧
        Needs publisher scope owner child.hash (path ++ child.path.toList) evidence := by
  cases needed with
  | @node owner hash nodeRaw path admitted nodeHeld =>
    have sameRaw : raw = nodeRaw := Option.some.inj (held.symm.trans nodeHeld)
    subst nodeRaw
    exact Or.inl rfl
  | @provenance origin hash nodeRaw path admitted nodeHeld =>
    have sameRaw : raw = nodeRaw := Option.some.inj (held.symm.trans nodeHeld)
    subst nodeRaw
    exact Or.inr (Or.inl ⟨origin, rfl, rfl⟩)
  | @value owner hash valueRaw address bytes path valueNode heldNode valueDecoded admitted named heldValue =>
    have sameRaw : raw = valueRaw := Option.some.inj (held.symm.trans heldNode)
    subst valueRaw
    have sameNode : node = valueNode := Except.ok.inj (decoded.symm.trans valueDecoded)
    subst valueNode
    exact Or.inr (Or.inr (Or.inl ⟨address, bytes, rfl, named, heldValue, admitted⟩))
  | @extension owner hash extensionRaw segment child path evidence heldNode nodeDecoded
      nonempty below =>
    have sameRaw : raw = extensionRaw := Option.some.inj (held.symm.trans heldNode)
    subst extensionRaw
    have sameNode : node = .extension segment child := Except.ok.inj (decoded.symm.trans nodeDecoded)
    subst node
    refine Or.inr (Or.inr (Or.inr ⟨⟨none, child, segment, false⟩, ?_, ?_⟩))
    · simp [pairedChildren]
    · simpa [ByteArrayProofs.toList_eq_data] using below
  | @branch owner hash branchRaw child path evidence children value nibble heldNode
      nodeDecoded edge below =>
    have sameRaw : raw = branchRaw := Option.some.inj (held.symm.trans heldNode)
    subst branchRaw
    have sameNode : node = .branch children value := Except.ok.inj (decoded.symm.trans nodeDecoded)
    subst node
    let position : Position := ⟨none, child, ⟨#[nibble]⟩, false⟩
    refine Or.inr (Or.inr (Or.inr ⟨position, ?_, ?_⟩))
    · simp only [pairedChildren]
      apply List.mem_filterMap.mpr
      refine ⟨(some child, nibble.toNat), ?_, ?_⟩
      · exact List.mk_mem_zipIdx_iff_getElem?.mpr edge
      · simp [position]
    · simpa [position, ByteArrayProofs.toList_eq_data] using below
  | @route owner hash routeRaw child path evidence children value nibble heldNode
      nodeDecoded edge below =>
    have sameRaw : raw = routeRaw := Option.some.inj (held.symm.trans heldNode)
    subst routeRaw
    have sameNode : node = .route children value := Except.ok.inj (decoded.symm.trans nodeDecoded)
    subst node
    let position : Position := ⟨none, child, ⟨#[nibble]⟩, false⟩
    refine Or.inr (Or.inr (Or.inr ⟨position, ?_, ?_⟩))
    · simp only [pairedChildren]
      apply List.mem_filterMap.mpr
      refine ⟨(some child, nibble.toNat), ?_, ?_⟩
      · exact List.mk_mem_zipIdx_iff_getElem?.mpr edge
      · simp [position]
    · simpa [position, ByteArrayProofs.toList_eq_data] using below

end Synchronicity.TrieMissingTransfer
