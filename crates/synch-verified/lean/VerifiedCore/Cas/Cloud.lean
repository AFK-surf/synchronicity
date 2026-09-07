import VerifiedCore.Cas.Project
import VerifiedCore.Cas.Durable
import VerifiedCore.Cas.Receive
import VerifiedCore.Host.Provider
import VerifiedCore.Host.CacheIO

/-! Whole cloud cache restoration. Provider acknowledgement, metadata
adoption, missing-copy healing, cache hydration and verified-range publication
are composed here. The host transports raw objects and writes literal bytes;
it never chooses a CAS transition or resumes with an already decided plan. -/
namespace VerifiedCore.Cas.Cloud
open Host

inductive Error where
  | host (failure : Failure)
  | project (error : Project.Error)
  | durable (error : Durable.Error)
  | receive (error : Receive.Error)
  | missingBlob (root : ByteArray)
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  | cacheBusy
  | invalidRange (start stop size : UInt64)
  | unalignedRange
  | incompleteInline
  | protocol
  deriving BEq, DecidableEq

abbrev Effects := EffectSum Receive.Effects
  (EffectSum Durable.Effects (EffectSum Provider (EffectSum CacheIO Resources)))
abbrev Action (A : Type) := OperationOver Effects Error A

def provider (effect : Provider (FileReply A)) : Action (FileReply A) := observe effect
def cache (effect : CacheIO (Reply A)) : Action A := raise Error.host effect
def resource (effect : Resources (Reply A)) : Action A := raise Error.host effect
def lease (effect : Lease (Reply A)) : Action A := raise Error.host effect
def clock : Action Int64 := raise Error.host Clock.nowNs

def blob (root : ByteArray) : Action (Option Project.Blob) := within Error.project (Project.blob root)

def leased (root : ByteArray) (body : Action A) : Action A := do
  let token ← lease (.acquire "cas_writers" root)
  ensure body (lease (.release token))

/-- The remover's ordering section ends before any provider request. -/
def clearCache (root : ByteArray) : Action Bool := do
  let token ← lease (.order "cas")
  ensure (within Error.durable (Durable.clearCache root)) (lease (.release token))

/-- Only authoritative absence withdraws availability and creates repair
intents. A failed repair wins over the original missing-copy failure, as in
local read recovery; other provider failures never mutate the claim. -/
def providerBytes (root : ByteArray) (effect : Provider (FileReply ByteArray)) : Action ByteArray := do
  match ← provider effect with
  | .ok bytes => return bytes
  | .error failure =>
    if failure.kind == .missing then
      let _ ← within Error.durable (Durable.healMissing root)
    throw (.host failure.failure)

/-- Availability requires both raw final objects, not a provider-side CAS
policy callback. Missing either is absence; another failure remains an error. -/
def pairSize? (root : ByteArray) : Action (Option UInt64) := do
  match ← provider (.stat "cas_payload" root) with
  | .error failure =>
    if failure.kind == .missing then return none
    else throw (.host failure.failure)
  | .ok size =>
    match ← provider (.stat "cas_outboard" root) with
    | .ok _ => return some size
    | .error failure =>
      if failure.kind == .missing then return none
      else throw (.host failure.failure)

def attestsSize (row : Project.Blob) : Bool :=
  row.durable || row.complete ||
    spansContain (Serve.spansOf row.verifiedGroups) ((groupCount row.size).toNat - 1)

def adoptIfPresent (root : ByteArray) (size : UInt64) : Action Bool := do
  let current ← blob root
  let mut replaceClaim := false
  if let some row := current then
    if row.size != size then
      if attestsSize row then throw (.sizeMismatch root row.size size)
      replaceClaim := true
    if row.durable then return true
  let some stored ← pairSize? root | return false
  if stored != size then throw (.sizeMismatch root stored size)
  if replaceClaim then
    if !(← clearCache root) then throw .cacheBusy
  within Error.durable (Durable.adoptDurable root size (← clock))
  return true

def rowOrAdopt (root : ByteArray) (size : UInt64) : Action (Option Project.Blob) := do
  if let some row ← blob root then return some row
  if !(← adoptIfPresent root size) then return none
  let some row ← blob root | throw (.missingBlob root)
  return some row

/-- Outboard publication uses an owned temporary and never claims payload
coverage. Cache directory-sync unavailability is explicitly tolerated; real
flush/replace/sync failures still propagate. -/
def outboard (root : ByteArray) (force : Bool := false) : Action ByteArray := do
  if !force then
    let cached ← try raise Error.host (Storage.readBytes "cas_outboard" root) catch _ => pure none
    if let some bytes := cached then return bytes
  let bytes ← providerBytes root (.readAll "cas_outboard" root)
  let temporary ← resource (.createTemporary "cas_outboard")
  ensure (do
    cache (.writeTemporary temporary 0 bytes)
    resource (.flush temporary)
    resource (.replace temporary "cas_outboard" root)
    let _ ← resource (.syncParent "cas_outboard" root)
    pure ()) (resource (.discard temporary))
  return bytes

/-- A provider range is trusted storage data, not a peer Bao slice. The
provider's immutable-object contract supplies exact content bytes; this
operation checks bounds/alignment and publishes only after local flush.
The enclosing hydration owns the writer lease throughout. -/
def cacheTrustedRange (root : ByteArray) (size offset : UInt64) (bytes : ByteArray) : Action Unit := do
  let stop := offset.toNat + bytes.size
  if offset > size || stop > size.toNat then
    throw (.invalidRange offset stop.toUInt64 size)
  if offset.toNat % 16384 != 0 || (stop != size.toNat && stop % 16384 != 0) then throw .unalignedRange
  let served := if size == 0 then IngestCommit.fullSpan size
    else normalizeSpans (groupCount size).toNat [⟨offset.toNat / 16384, (stop + 16383) / 16384⟩]
  if served.isEmpty then return ()
  within Error.receive (Receive.admit root size)
  if (← within Error.receive (Receive.metadata? root)).any (·.complete) then return ()
  if size ≤ Receive.inlineMax then
    if offset != 0 || stop != size.toNat then throw .incompleteInline
    let _ ← within Error.receive (Receive.commit root size served (some bytes) (← clock) .cache)
    return ()
  cache (.writeAt "cas_payload" root offset bytes)
  cache (.flush "cas_payload" root)
  let outcome ← within Error.receive (Receive.commit root size served none (← clock) .cache)
  within Error.receive (Receive.settle root outcome)

def windowBytes : Nat := 8 * 1024 * 1024

def hydrateStep (root : ByteArray) (size : UInt64) (stop offset : Nat) : Action (Nat ⊕ Unit) := do
  if offset ≥ stop then return .inr ()
  let endOffset := min (offset + windowBytes) stop
  let bytes ← providerBytes root (.readRange "cas_payload" root offset.toUInt64 (endOffset - offset).toUInt64)
  if bytes.size != endOffset - offset then throw .protocol
  cacheTrustedRange root size offset.toUInt64 bytes
  return .inl endOffset

/-- The recursion budget counts provider windows, not host effects. Every
window's transaction and cleanup run to completion before the next window;
there is no effect budget that could cut off a pending rollback. -/
def hydrateWindows (root : ByteArray) (size : UInt64) (stop : Nat) : Nat → Nat → Action Unit
  | 0, _ => throw .protocol
  | remaining + 1, offset => do
    match ← hydrateStep root size stop offset with
    | .inr () => return ()
    | .inl next => hydrateWindows root size stop remaining next

def hydrate (root : ByteArray) (size : UInt64) (groups : List GroupSpan) : Action Unit := do
  if groups.isEmpty then return ()
  leased root do
    let _ ← outboard root
    if size == 0 then return ← cacheTrustedRange root size 0 ByteArray.empty
    for span in groups do
      let start := min (span.start * 16384) size.toNat
      let stop := min (span.stop * 16384) size.toNat
      hydrateWindows root size stop ((stop - start) / windowBytes + 2) start

/-- Restore the complete durable object into cache. Existing inline bytes or
complete files need no provider wait; only real provider absence heals the
durable claim. A non-durable partial row retains its historical no-op behavior. -/
def ensureCached (root : ByteArray) (size : UInt64) : Action Unit := do
  let some row ← rowOrAdopt root size | throw (.missingBlob root)
  if row.durable && row.size != size then throw (.sizeMismatch root row.size size)
  if row.inline.isSome then return ()
  if row.complete then
    let present ← if ← cache (.isFile "cas_payload" root) then cache (.isFile "cas_outboard" root) else pure false
    if present then return ()
    if !(← clearCache root) then throw .cacheBusy
    if !row.durable then throw (.missingBlob root)
  if !row.durable then return ()
  hydrate root size (IngestCommit.fullSpan size)

/-- Subtract sorted disjoint saved runs in a merge pass. Each recursive step
consumes a wanted or saved run, even when it retains a shortened suffix. -/
def subtractSpans : List GroupSpan → List GroupSpan → List GroupSpan
  | [], _ => []
  | wanted, [] => wanted
  | want :: rest, held :: tail =>
    if want.stop ≤ held.start then want :: subtractSpans rest (held :: tail)
    else if held.stop ≤ want.start then subtractSpans (want :: rest) tail
    else
      let before := if want.start < held.start then [⟨want.start, held.start⟩] else []
      if held.stop < want.stop then
        before ++ subtractSpans (⟨held.stop, want.stop⟩ :: rest) tail
      else before ++ subtractSpans rest (held :: tail)
termination_by wanted held => wanted.length + held.length

/-- Restore only requested missing groups. Adoption may invalidate an old
unattested size claim, so coverage is re-read after adoption before deciding
which bytes can be skipped. -/
def ensureRanges (root : ByteArray) (size : UInt64) (requested : List (UInt64 × UInt64)) : Action Unit := do
  let some row ← rowOrAdopt root size | return ()
  if row.durable && row.size != size then throw (.sizeMismatch root row.size size)
  if !row.durable then
    if !(← adoptIfPresent root size) then return ()
  let some current ← blob root | throw (.missingBlob root)
  if current.inline.isSome then return ()
  let wanted := normalizeSpans (groupCount size).toNat (Serve.spansOf requested)
  -- A single whole operation owns range subtraction as well as hydration.
  hydrate root size (subtractSpans wanted (Serve.spansOf current.verifiedGroups))

end VerifiedCore.Cas.Cloud
