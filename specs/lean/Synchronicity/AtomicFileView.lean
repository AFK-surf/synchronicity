import Synchronicity.SnapshotViewProgress

/-! Operation-independent publication specification. A visible replacement
is indivisible: the selected version, exact permitted records, and persistent
content obligations describe one ready view. Pending/history bookkeeping is
not part of the public file-list observation. -/
namespace Synchronicity.AtomicFileView
open VerifiedCore VerifiedCore.Host Replication SimulatedHost

def projection (origin : String) (db : Database) :=
  (rows db "entries", rows db "pins", rows db "content_want",
    (rows db "heads").filter (fun row => equals row [("origin_id", .text origin), ("slot", .text "complete")]))

def Installed (db : Database) (head : Head) : Prop :=
  (∃ row ∈ rows db "heads", equals row [("origin_id", .text (Origin.canonical head.origin)), ("slot", .text "complete")] = true) ∧
  (∀ row ∈ rows db "heads", equals row [("origin_id", .text (Origin.canonical head.origin)), ("slot", .text "complete")] = true →
    cell row "seq" = .integer head.seq.toInt64 ∧ cell row "root" = .blob head.root)

def Ready (services : MaterializedView.Services) (snapshot : TrieProgramProofs.RawSnapshot)
    (origin : Origin.Parsed) (scope : Trie.Serve.Scope) (replicas : List Materialize.Target)
    (before after : Database) : Prop :=
  ∃ head, head.origin = origin ∧ Installed after head ∧
    SnapshotViewProgress.ExactFiles services snapshot head.root
      (fun key => scope.admitsKeyPath (Trie.keyNibbles key) = true) after (Origin.canonical origin) ∧
    MaterializedView.CurrentRequirements replicas after ∧ MaterializedView.ForeverRequirements replicas before after

/-- At any public observation the old view remains intact, or one complete
new view is visible. The allowed policies are supplied independently of the
operation; readiness is about records and obligations, never return flags. -/
def AtomicReplacement (services : MaterializedView.Services) (snapshot : TrieProgramProofs.RawSnapshot)
    (origin : Origin.Parsed) (policies : Trie.Serve.Scope → List Materialize.Target → Prop)
    (before after : Database) : Prop :=
  projection (Origin.canonical origin) after = projection (Origin.canonical origin) before ∨
    ∃ scope replicas, policies scope replicas ∧ Ready services snapshot origin scope replicas before after

end Synchronicity.AtomicFileView
