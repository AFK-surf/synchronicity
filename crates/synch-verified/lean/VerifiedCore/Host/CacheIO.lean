import VerifiedCore.Host

/-! Literal local byte writes. No cache coverage, admission, size settlement,
retention or database policy is delegated to this capability. -/
namespace VerifiedCore.Host

inductive CacheIO : Type → Type where
  /-- Raw regular-file presence, matching the local platform's is_file query. -/
  | isFile (space : String) (key : ByteArray) : CacheIO (Reply Bool)
  /-- Write exactly these bytes at the named offset, creating parents/file
  if needed. Preserve every byte outside the range; do not truncate or flush. -/
  | writeAt (space : String) (key : ByteArray) (offset : UInt64) (bytes : ByteArray) : CacheIO (Reply Unit)
  /-- Flush prior keyed writes and their parent directory entries where the
  configured cache filesystem supports directory synchronization. -/
  | flush (space : String) (key : ByteArray) : CacheIO (Reply Unit)
  /-- Write to a live Resources-owned temporary without consuming or flushing
  it. Creation, publication and abandonment belong to the requesting program. -/
  | writeTemporary (handle offset : UInt64) (bytes : ByteArray) : CacheIO (Reply Unit)

end VerifiedCore.Host
