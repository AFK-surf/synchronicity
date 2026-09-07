import Std.Data.TreeMap.Basic

/-! The complete head-exchange decision. Inputs are advertised versions and
the signed heads the caller can serve; outputs select pushes and origins to
request. Authentication, availability, and adoption are separate operations.
Neither the order of the two advertised slots nor duplicate advertisements
may hide a newer version. Indexing keeps the operation O(n log n).
-/
namespace VerifiedCore.Replication.Exchange

structure Advertised where
  origin : String
  seq : UInt64
  root : ByteArray

structure ExchangePlan where
  push : List UInt64
  want : List String

/-- Positive ordering key: sequence followed by the unsigned big-endian hash.
Native admission requires exactly 32 hash bytes. Zero means no version. -/
def version (head : Advertised) : Nat :=
  1 + head.root.data.foldl (fun n byte => n * 256 + byte.toNat) head.seq.toNat

abbrev Index := Std.TreeMap String Nat

def add (index : Index) (head : Advertised) : Index :=
  index.insert head.origin (max (index.getD head.origin 0) (version head))

def index (heads : List Advertised) : Index := heads.foldl add {}

def requested (ours theirs : Index) : List String :=
  (theirs.toList.filter (fun (origin, best) => ours.getD origin 0 < best)).map (·.1)

/-- Every push is an index into the supplied servable heads. No advertised
pending head can become a push merely because its summary is newer. -/
def plan (ours theirs servable : List Advertised) : ExchangePlan :=
  let remote := index theirs
  ⟨(servable.zipIdx.filter (fun (head, _) =>
      remote.getD head.origin 0 < version head)).map (fun (_, position) => position.toUInt64),
   requested (index ours) remote⟩

end VerifiedCore.Replication.Exchange
