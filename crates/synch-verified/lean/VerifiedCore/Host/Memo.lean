import VerifiedCore.Host

/-! The completeness memo: the certificates a host keeps for "this store holds
all of that root", which a non-monotone mutation of the trie must forget.
Forgetting is bound to the mutating transaction as a lease is: the host keeps
certification disabled until that transaction's edge, commit or rollback, so
a reader that started before the mutation cannot certify its stale snapshot
afterwards. Which certificates survive is the program's decision. -/
namespace VerifiedCore.Host

inductive Memo : Type → Type where
  /-- Forget every completeness certificate but those keyed by `keep`, and
  keep certification disabled until the enclosing transaction ends. -/
  | forgetExcept (keep : List ByteArray) : Memo (Reply Unit)

end VerifiedCore.Host
