import VerifiedCore.Host.Digest
import VerifiedCore.Trie.Serve

/-! The keys completeness answers are memoized under. "Do I hold all of
this?" is a question about a root *and* a scope: a memo keyed by the root
alone would answer a wider scope with a narrower one's answer, so a scoped
answer is keyed by a digest over the root and the scope's two sets, and an
answer "as this origin's own" by a further digest over that key and the
origin, since a trie held whole is not held whole with provenance. The
digest is the host's; the layout is this module's, and every reader and
the sweep that retains certificates share it. -/
namespace VerifiedCore.Trie.Memo

open Host

/-- A length as four little-endian bytes. -/
def u32le (n : Nat) : ByteArray :=
  ⟨#[(n % 256).toUInt8, (n / 256 % 256).toUInt8, (n / 65536 % 256).toUInt8, (n / 16777216 % 256).toUInt8]⟩

/-- A set of keys: its size, then each key with its own length. -/
def lengthPrefixed (set : List ByteArray) : ByteArray :=
  set.foldl (fun acc key => acc ++ u32le key.size ++ key) (u32le set.length)

/-- What a scoped answer's key digests. -/
def scopedBytes (prefixes exact : List ByteArray) (root : ByteArray) : ByteArray :=
  "scoped-root/1".toUTF8 ++ root ++ lengthPrefixed prefixes ++ lengthPrefixed exact

/-- What an owned answer's key digests, over the scoped key. -/
def ownedBytes (narrowed : ByteArray) (origin : String) : ByteArray :=
  "owned-root/1".toUTF8 ++ narrowed ++ origin.toUTF8

/-- The key of an answer for `root` under `scope`: the root itself for the
whole keyspace, a digest over the root and the scope otherwise. -/
def scopedKey [Inject Digest E] (hostError : Failure → ε) (scope : Serve.Scope) (root : ByteArray) :
    OperationOver E ε ByteArray :=
  match scope.prefixes with
  | none => pure root
  | some prefixes => raise hostError (Digest.blake3 (scopedBytes prefixes scope.exact root))

/-- The key of an answer for `root` under `scope`, as `owner`'s own when an
owner is given. -/
def keyFor [Inject Digest E] (hostError : Failure → ε) (scope : Serve.Scope) (root : ByteArray)
    (owner : Option String) : OperationOver E ε ByteArray := do
  let narrowed ← scopedKey hostError scope root
  match owner with
  | none => pure narrowed
  | some origin => raise hostError (Digest.blake3 (ownedBytes narrowed origin))

end VerifiedCore.Trie.Memo
