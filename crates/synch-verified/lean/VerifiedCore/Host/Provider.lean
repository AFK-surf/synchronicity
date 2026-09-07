import VerifiedCore.Host.Access

/-! Raw immutable provider objects. The caller owns every availability, size,
repair and adoption decision. These requests suspend the native invocation;
no transaction or remover's connection section may survive the wait. -/
namespace VerifiedCore.Host

/-- The configured provider maps a literal namespace/key to an immutable
object. A successful read returns exactly the requested bytes; only an
actual provider not-found response has `FileFailureKind.missing`. Other
failures keep their original host token and never imply missing content.
The FileReply envelope is shared with keyed local object I/O. -/
inductive Provider : Type → Type where
  | stat (space : String) (key : ByteArray) : Provider (FileReply UInt64)
  | readAll (space : String) (key : ByteArray) : Provider (FileReply ByteArray)
  | readRange (space : String) (key : ByteArray) (offset count : UInt64) :
      Provider (FileReply ByteArray)

end VerifiedCore.Host
