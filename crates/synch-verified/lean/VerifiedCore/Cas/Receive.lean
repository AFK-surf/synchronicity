import VerifiedCore.Cas.IngestCommit
import VerifiedCore.Cas.Serve
import VerifiedCore.Host.Resources

/-! Receiving an object from a peer: a verified slice, a tree proof, and the
promotion of a local donor's bytes that a proof vouches for. The program
owns the write lease, the cheap size refusal, the row read and its complete
short-circuit, the inline-versus-file policy, the order of flush and commit,
the settlement of what was received, and the trim of a completed object.
The Bao service decodes, verifies, writes and copies exactly what the
program names; only what the program named is ever committed. -/
namespace VerifiedCore.Cas.Receive

open Host

inductive Error where
  | host (failure : Failure)
  | malformed
  | columnType (index : Nat) (column : String) (actual : Codec.CellType)
  | column (column : String) (reason : String)
  /-- The row's claim cannot yield to the offered size. -/
  | sizeMismatch (root : ByteArray) (recorded offered : UInt64)
  | protocol
  deriving BEq, DecidableEq

/-- A subtree a proof established: its position and width in groups, the
chaining value chained back to the root, and whether it is whole (aligned, a
full power of two of groups, entirely inside the object). -/
structure ProvenSubtree where
  start : UInt64
  groups : UInt64
  cv : ByteArray
  whole : Bool
  deriving BEq, DecidableEq

abbrev Effects := EffectSum IngestCommit.Effects (EffectSum Lease Bao)
abbrev Action (A : Type) := OperationOver Effects Error A

def access (effect : Access (Reply A)) : Action A := raise Error.host effect
def lease (effect : Lease (Reply A)) : Action A := raise Error.host effect
def bao (effect : Bao (Reply A)) : Action A := raise Error.host effect

/-- Objects at or below this size are held inline in the row. -/
def inlineMax : UInt64 := 16384

def translateCommit : IngestCommit.Error → Error
  | .host failure => .host failure
  | .metadata .malformed => .malformed
  | .metadata (.columnType index column actual) => .columnType index column actual
  | .sizeMismatch root recorded offered => .sizeMismatch root recorded offered

def translateRead : Read.Error → Error
  | .host failure => .host failure
  | .malformed | .missingBlob | .range _ _ _ | .unavailable | .shortInline => .malformed
  | .columnType index column actual => .columnType index column actual
  | .column column reason => .column column reason
  | .protocol => .protocol

/-- The cheap refusal, the same settlement the commit makes again. -/
def admit (root : ByteArray) (size : UInt64) : Action Unit :=
  within translateCommit (IngestCommit.admit root size)

def commit (root : ByteArray) (size : UInt64) (spans : List GroupSpan) (inline : Option ByteArray)
    (now : Int64) (tier : IngestCommit.Tier) : Action IngestCommit.Outcome :=
  within translateCommit (IngestCommit.commitGroups root size spans inline now tier)

/-- The row, if there is one, through the read path's statement and decoder. -/
def metadata? (root : ByteArray) : Action (Option Read.Metadata) := do
  let scan ← access (.snapshot ⟨"blobs", [("root", .blob root)], [], []⟩
    ["root", "size", "complete", "bitmap", "inline", "last_access", "durable"])
  match scan.rows with
  | row :: _ => ExceptT.mk (.pure ((Read.decodeRow row).map some |>.mapError translateRead))
  | [] => match scan.failure with
    | some failure => throw (.host failure)
    | none => pure none

/-- Every write of an object runs under its write lease: taken before the row
is read and held past the commit, so a sweep deciding the object collectable
in between cannot unlink the bytes out from under the row about to be
written. Release is requested exactly once, whatever the body did. -/
def leased (root : ByteArray) (body : Action A) : Action A := do
  let token ← lease (.acquire "cas_writers" root)
  ensure body (lease (.release token))

def window (size : UInt64) (served : List (UInt64 × UInt64)) : List GroupSpan :=
  normalizeSpans (groupCount size).toNat (Serve.spansOf served)

/-- Trim only after a commit that completed the object: then the final group
is held and the size is a fact rather than a claim. -/
def settle (root : ByteArray) (outcome : IngestCommit.Outcome) : Action Unit := do
  if outcome.complete then bao (.trimObject root outcome.size)

/-- Decode a received slice of the served groups within the object and commit
exactly those groups. A small object is decoded into its inline buffer; a
large one into its files, which reach stable storage before the row advances
to cover them, so a crash cannot leave the index claiming groups the disk
never received. -/
def writeSlice (root : ByteArray) (size : UInt64) (served : List (UInt64 × UInt64))
    (input : UInt64) (now : Int64) (tier : IngestCommit.Tier) : Action (List (UInt64 × UInt64)) := do
  let spans := window size served
  if spans.isEmpty then return []
  leased root do
    admit root size
    let row ← metadata? root
    if row.any (·.complete) then return []
    if size ≤ inlineMax then
      let buffer ← bao (.decodeInline root size (row.bind (·.inline)) (Serve.pairsOf spans) input)
      let _ ← commit root size spans (some buffer) now tier
      return Serve.pairsOf spans
    bao (.decodeSlice root size (Serve.pairsOf spans) input)
    bao (.flushObject root)
    let outcome ← commit root size spans none now tier
    settle root outcome
    return Serve.pairsOf spans

/-- Verify a received proof over the served groups and record its tree: the
nodes reach stable storage, then the row is committed holding no new group,
so an object first met through a proof is held-nothing rather than absent.
A proof without interior nodes records nothing. -/
def writeProof (root : ByteArray) (size : UInt64) (served : List (UInt64 × UInt64))
    (level input : UInt64) (now : Int64) (tier : IngestCommit.Tier) : Action (List ProvenSubtree) := do
  let spans := window size served
  leased root do
    admit root size
    let (wrote, proven) ← bao (.writeProof root size (Serve.pairsOf spans) level input)
    if wrote then
      bao (.flushObject root)
      let _ ← commit root size [] none now tier
    return proven.map fun (start, groups, cv, whole) => ⟨start, groups, cv, whole⟩

def overlaps (spans : List GroupSpan) (start stop : Nat) : Bool :=
  spans.any fun span => span.start < stop && start < span.stop

def covers (spans : List GroupSpan) (start stop : Nat) : Bool :=
  start ≥ stop || spans.any fun span => span.start ≤ start && stop ≤ span.stop

def isPowerOfTwo (n : Nat) : Bool := n != 0 && (n &&& (n - 1)) == 0

/-- Whether a proven subtree may be promoted from a donor: it overlaps no
group this node already verified (copying over a verified group would risk
the one thing the bitmap promises); it is a single group or a whole subtree,
the two shapes whose chaining values are comparable across objects; the
donor holds every group of it; and the run's extent is the same in both
objects, since a claim a few bytes short of the object would otherwise copy
the final run truncated while both chaining values still cover the whole. -/
def eligible (held : List GroupSpan) (size donorSize : UInt64) (donorHeld : List GroupSpan)
    (subtree : ProvenSubtree) : Bool :=
  let start := subtree.start.toNat
  let stop := start + subtree.groups.toNat
  let startByte := start * 16384
  let stopByte := max (min (stop * 16384) size.toNat) startByte
  let donorStop := min (stop * 16384) donorSize.toNat
  !overlaps held start stop &&
    (subtree.groups.toNat ≤ 1 ||
      (isPowerOfTwo subtree.groups.toNat && start % subtree.groups.toNat == 0 &&
        stop * 16384 ≤ size.toNat)) &&
    stopByte ≤ donorSize.toNat && covers donorHeld start stop && stopByte == donorStop

def spanOf (subtree : ProvenSubtree) : GroupSpan :=
  ⟨subtree.start.toNat, subtree.start.toNat + subtree.groups.toNat⟩

/-- Promote every proven subtree the donor's own tree agrees with: the
service compares chaining values and copies a run only on a match, the
decisions about which runs may be asked for are the program's, and the
copied runs reach stable storage before they are committed. -/
def promote (donor root : ByteArray) (size : UInt64) (proven : List ProvenSubtree)
    (now : Int64) (tier : IngestCommit.Tier) : Action (List (UInt64 × UInt64)) := do
  -- Inline objects never delta: one group is smaller than the round trip
  -- that would discover it could be reused.
  if size ≤ inlineMax || proven.isEmpty then return []
  leased root do
    admit root size
    let row ← metadata? root
    if row.any (·.complete) then return []
    let held := match row with
      | none => []
      | some row => Serve.held row
    let some donorRow ← metadata? donor | return []
    let donorHeld := Serve.held donorRow
    -- A donor with nothing verified, an inline donor (a single group, whose
    -- only hash carries the root flag and can equal no chaining value) or a
    -- single-group donor has nothing to give.
    if donorHeld.isEmpty || donorRow.inline.isSome || groupCount donorRow.size ≤ 1 then return []
    let promoted ← proven.foldlM (init := ([] : List GroupSpan)) fun promoted subtree => do
      if !eligible held size donorRow.size donorHeld subtree then return promoted
      let copied ← bao (.promoteRun donor root size subtree.start subtree.groups subtree.cv)
      return if copied then promoted ++ [spanOf subtree] else promoted
    if promoted.isEmpty then return []
    let spans := normalizeSpans (groupCount size).toNat promoted
    bao (.flushObject root)
    let outcome ← commit root size spans none now tier
    settle root outcome
    return Serve.pairsOf spans

end VerifiedCore.Cas.Receive
