import VerifiedCore.Host

/-! What a structural walk over the trie asks its host besides raw node
reads: whether a peer refused to show a node, so a walk over what this
store holds can tell "absent" from "refused", and, for the walk a head
promotion applies, the materializer that takes each change as it is found.
Neither carries policy: which positions are walked, what a change is and
in what order it is handed over are the program's. -/
namespace VerifiedCore.Host

inductive Redaction : Type → Type where
  /-- Whether a peer told this store it may not see the node at the nibble
  position `path`, or at any position for `none`. -/
  | isRedacted (hash : ByteArray) (path : Option ByteArray) : Redaction (Reply Bool)

inductive Apply : Type → Type where
  /-- Hand one change to the materializer, in walk order: the key, its kind
  (0 added, 1 changed, 2 deleted) and the new value's bytes when there is
  one. A refusal is this host's failure and stops the walk. -/
  | applyChange (key : ByteArray) (kind : UInt64) (new : Option ByteArray) : Apply (Reply Unit)

end VerifiedCore.Host
