import VerifiedCore.Cas.IngestCommit
import VerifiedCore.Host.Access
import VerifiedCore.Host.Construct
import VerifiedCore.Host.Resources

/-! Internal captured-source ingestion, composed by the production Input command.
The source is already opened and its length captured. Input owns inline selection
and input acquisition; Rust interprets only the raw resource effects.
This program owns the source immediately on entry, has the host build the
out-of-line data into owned temporaries, publishes the two files and commits
metadata under one root-keyed lease. -/
namespace VerifiedCore.Cas.Ingest
open VerifiedCore.Host

abbrev Effects := EffectSum (EffectSum FileIO Construct)
  (EffectSum IngestCommit.Effects (EffectSum Resources Lease))

/-- Immutable platform/backend durability policy, not an implementation toggle. -/
inductive DirectoryPolicy where
  | requireSync | allowUnsupported
  deriving BEq, DecidableEq

inductive Error where
  | host (failure : Failure)
  | metadata (error : IngestCommit.Error)
  | protocol
  | directorySyncUnsupported
  deriving BEq, DecidableEq

abbrev Action (A : Type) := OperationOver Effects Error A

def resource (effect : Resources (Reply A)) : Action A := raise Error.host effect
def lease (effect : Lease (Reply A)) : Action A := raise Error.host effect
def closeSource (source : UInt64) : Action Unit := raise Error.host (FileIO.close source)

/-- One host effect streams the captured source into the owned payload and
outboard temporaries and returns the root. The program checks the root's
width; a malformed reply is a protocol failure, never a published object. -/
def construct (source payload outboard size : UInt64) : Action ByteArray := do
  let root ← raise Error.host (Construct.build source payload outboard size)
  if root.size != 32 then throw .protocol
  return root

def commit (root : ByteArray) (size : UInt64) (now : Int64) (tier : IngestCommit.Tier) : Action Unit :=
  within Error.metadata (IngestCommit.commitComplete root size none now tier)

/-- Unsupported directory synchronization is an explicit platform limitation,
not an I/O failure silently swallowed by a filesystem adapter. -/
def syncParent (space : String) (root : ByteArray) (policy : DirectoryPolicy) : Action Unit := do
  match ← resource (.syncParent space root) with
  | .synced => pure ()
  | .unsupported => match policy with
    | .requireSync => throw .directorySyncUnsupported
    | .allowUnsupported => pure ()

/-- Both temporary contents reach their flush boundary before either final
name changes. Replacement is ordered but not atomic across both files: after
a failed second replacement the first published file remains. Cleanup must
never remove published targets, and metadata is not committed on that path. -/
def publish (payload outboard : UInt64) (root : ByteArray) (size : UInt64)
    (now : Int64) (tier : IngestCommit.Tier) (policy : DirectoryPolicy) : Action ByteArray := do
  resource (.flush payload)
  resource (.flush outboard)
  resource (.replace payload "cas_payload" root)
  resource (.replace outboard "cas_outboard" root)
  syncParent "cas_payload" root policy
  syncParent "cas_outboard" root policy
  commit root size now tier
  return root

/-- Whole captured-source, out-of-line path. Every successful temporary
acquisition is bracketed immediately. If acquisition itself fails, source
ownership ends there; otherwise it ends immediately after construction.
Thus source close is requested exactly once, even when close reports failure.
The root lease brackets flush, publication, directory sync and metadata commit.
No hash/group/span/settlement plan crosses this operation's boundary. -/
def run (source size : UInt64) (now : Int64) (tier : IngestCommit.Tier)
    (policy : DirectoryPolicy := .requireSync) : Action ByteArray := do
  let payload ← onFailure (resource (.createTemporary "cas_payload")) (closeSource source)
  ensure (do
    let outboard ← onFailure (resource (.createTemporary "cas_outboard")) (closeSource source)
    if outboard == payload then
      -- A malformed host reply must not start construction or double-discard
      -- the same temporary. The outer scope owns this one token's cleanup.
      ensure (throw .protocol) (closeSource source)
    else
      ensure (do
        let root ← ensure (construct source payload outboard size) (closeSource source)
        let token ← lease (.acquire "cas_writers" root)
        ensure (publish payload outboard root size now tier policy) (lease (.release token)))
        (resource (.discard outboard)))
    (resource (.discard payload))

end VerifiedCore.Cas.Ingest
