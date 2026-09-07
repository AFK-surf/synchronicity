import VerifiedCore.Host.Access
import VerifiedCore.Host.Resources

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

/-- Transport self-test output; absence stays distinct from another failure. -/
structure ProviderProbed where
  size : UInt64
  whole : ByteArray
  ranged : ByteArray
  missing : Bool
  deriving BEq

/-- Exercise all provider packets and cleanup ownership. Mode 1 holds a SQL
transaction; 2 holds a remover section; 3 holds a writer lease; 4 releases a
remover token before asking, even if that release reports an error. -/
def Provider.probe (key : ByteArray) (mode : UInt64) :
    OperationOver (EffectSum Storage (EffectSum Lease Provider)) Failure ProviderProbed :=
  let ask : OperationOver (EffectSum Storage (EffectSum Lease Provider)) Failure ProviderProbed := do
    let stat ← observe (Provider.stat "probe" key)
    let size ← match stat with
      | .ok size => pure size
      | .error failure =>
        if failure.kind == .missing then pure 0 else throw failure.failure
    if stat matches .error _ then return ⟨0, ByteArray.empty, ByteArray.empty, true⟩
    let whole ← observe (Provider.readAll "probe" key)
    let bytes ← match whole with
      | .ok bytes => pure bytes
      | .error failure =>
        if failure.kind == .missing then pure ByteArray.empty else throw failure.failure
    if whole matches .error _ then return ⟨size, ByteArray.empty, ByteArray.empty, true⟩
    let range ← observe (Provider.readRange "probe" key 1 2)
    match range with
    | .ok ranged => return ⟨size, bytes, ranged, false⟩
    | .error failure =>
      if failure.kind == .missing then return ⟨size, bytes, ByteArray.empty, true⟩
      else throw failure.failure
  if mode == 1 then transactionOver Inject.inject id fun _ => ask
  else if mode == 2 then do
    let token ← raise id (Lease.order "cas")
    ensure ask (raise id (Lease.release token))
  else if mode == 3 then do
    let token ← raise id (Lease.acquire "cas_writers" key)
    ensure ask (raise id (Lease.release token))
  else if mode == 4 then do
    let token ← raise id (Lease.order "cas")
    try raise id (Lease.release token) catch _ => pure ()
    ask
  else ask

end VerifiedCore.Host
