import VerifiedCore.Host

/-! The object store as a directory, for the sweeps: what each object's
files cost on disk, when they were last written, and which objects have
files at all. The layout (where a root's files live, how the store is
partitioned) stays the host's; what is evicted, collected or unlinked, and
in what order, is the program's. -/
namespace VerifiedCore.Host

inductive Sweep : Type → Type where
  /-- The bytes the keyed file occupies on disk (its allocated blocks, not
  its length), zero when there is no such file. -/
  | fileBytes (space : String) (key : ByteArray) : Sweep (Reply UInt64)
  /-- When the keyed regular file was last modified, in unix nanoseconds;
  `none` when there is no such regular file or its time cannot be read. -/
  | fileModified (space : String) (key : ByteArray) : Sweep (Reply (Option Int64))
  /-- The roots named by object files in the store, one host-chosen page at a
  time: the 32-byte roots of page `page` concatenated, or `none` past the
  last page. The host partitions one listing taken at the first request, so
  the pages together cover the store as it was then. -/
  | listObjects (page : UInt64) : Sweep (Reply (Option ByteArray))

end VerifiedCore.Host
