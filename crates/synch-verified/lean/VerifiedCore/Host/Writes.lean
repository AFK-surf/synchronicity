import VerifiedCore.Host

/-! Raw content-addressed writes. The operation chooses the namespace, the
address and the bytes; the host stores them literally. Which address a node
belongs under, and that the bytes are its canonical image, are the
requesting operation's decisions, proved where it makes them. -/
namespace VerifiedCore.Host

inductive ByteWrites : Type → Type where
  /-- Store `bytes` under `key` in the namespace, replacing nothing that
  differs: content addressing makes an existing entry identical. -/
  | putBytes (space : String) (key bytes : ByteArray) : ByteWrites (Reply Unit)

end VerifiedCore.Host
