import VerifiedCore.Host

/-! Raw invocation-owned filesystem resources and keyed lifetime protection. No operation
selects a CAS layout, interprets durability policy or commits metadata here. -/
namespace VerifiedCore.Host

/-- Generic owned-resource scope. Cleanup runs after either outcome, with its
error reported only when the body succeeded. Resource operations themselves
consume handles as documented; there is no retry after a failed release. -/
def ensure {E : Type → Type} {ε A : Type}
    (body : OperationOver E ε A) (cleanup : OperationOver E ε Unit) : OperationOver E ε A :=
  ExceptT.mk do
    let result ← body.run
    let final ← cleanup.run
    return match result with
      | .error error => .error error
      | .ok value => final.map (fun _ => value)

/-- Failed acquisition has no acquired resource to bracket. Release an
enclosing, still-owned resource without replacing the primary error. -/
def onFailure {E : Type → Type} {ε A : Type}
    (body : OperationOver E ε A) (cleanup : OperationOver E ε Unit) : OperationOver E ε A :=
  ExceptT.mk do
    match ← body.run with
    | .ok value => return .ok value
    | .error error =>
      let _ ← cleanup.run
      return .error error

inductive SyncStatus where
  | synced | unsupported
  deriving BEq, DecidableEq

inductive Resources : Type → Type where
  /-- Create an empty exclusive temporary in the indicated namespace, on the
  same filesystem as its eventual target. Each successful call owns a fresh
  handle distinct from every other live resource in this invocation. Creation
  and live-resource registration are atomic against temporary-file sweeping. -/
  | createTemporary (space : String) : Resources (Reply UInt64)
  /-- Flush all previously accepted writes to the named owned temporary. -/
  | flush (handle : UInt64) : Resources (Reply Unit)
  /-- Atomically replace one keyed target with the owned temporary. Success
  consumes the temporary; failure leaves it owned. This is not a two-file
  transaction, and never acknowledges parent-directory synchronization. -/
  | replace (handle : UInt64) (space : String) (key : ByteArray) : Resources (Reply Unit)
  /-- Idempotently close/unlink only the invocation-owned temporary. A token
  consumed by replace is a no-op: never unlink its published target. Failure
  consumes the token too; host abandonment cleanup retains any needed fallback. -/
  | discard (handle : UInt64) : Resources (Reply Unit)
  /-- Distinguish a platform's lack of directory synchronization support from
  an actual failed synchronization. Include newly created namespace ancestor
  entries down to the configured durable storage root, not just the target's
  immediate directory. Policy for unsupported lives in Lean. -/
  | syncParent (space : String) (key : ByteArray) : Resources (Reply SyncStatus)

inductive Lease : Type → Type where
  /-- Register keyed protection against removal and return an owned token.
  Acquisition is ordered against the remover's check-and-unlink critical
  section. Multiple concurrent tokens are allowed; this is not an exclusive
  writer lock. It must not be acquired inside a database transaction. -/
  | acquire (space : String) (key : ByteArray) : Lease (Reply UInt64)
  /-- Consume the token, including on reported failure. Abandonment releases
  outstanding tokens; a caller must never retry release after an error. -/
  | release (token : UInt64) : Lease (Reply Unit)

end VerifiedCore.Host
