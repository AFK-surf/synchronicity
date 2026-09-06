import VerifiedCore.Host

/-! Raw source observation and immutable byte storage. Input-length policy and
inline selection belong to the requesting Lean operation, never the host. -/
namespace VerifiedCore.Host

inductive SourceIO : Type → Type where
  | stat (space : String) (key : ByteArray) : SourceIO (Reply UInt64)
  /-- Read up to count bytes at offset. For a positive count, empty means EOF;
  successful bytes never exceed count. Sequential offsets must also work for
  stream handles; unsupported random access may fail. This does not capture
  the rest of a file or interpret its metadata. -/
  | readSome (handle offset count : UInt64) : SourceIO (Reply ByteArray)
  /-- Retain immutable raw bytes under a fresh invocation-owned file handle.
  FileIO.readAt/readSome access them; FileIO.close consumes the handle. -/
  | freeze (bytes : ByteArray) : SourceIO (Reply UInt64)

end VerifiedCore.Host
