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
  /-- Whether this key has a certificate visible outside all invalidating
  mutations. The key's scope and provenance layout belong to the caller. -/
  | isKnown (key : ByteArray) : Memo (Reply Bool)
  /-- The host's monotone generation ticket, advanced at both edges of an
  invalidating mutation and never wrapped back to an earlier ticket. -/
  | generation : Memo (Reply UInt64)
  /-- Certify only while the ticket is current and the host permits it.
  A transactional view may validate its ticket without caching an answer
  about writes that can still roll back. -/
  | certify (key : ByteArray) (generation : UInt64) : Memo (Reply Bool)

end VerifiedCore.Host
