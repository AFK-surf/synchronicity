import VerifiedCore.Cas.Program
import VerifiedCore.Cas.Read
import VerifiedCore.Cas.IngestCommit
import VerifiedCore.Cas.Ingest
import VerifiedCore.Cas.Input
import VerifiedCore.Entry
import VerifiedCore.Trie.Program
import VerifiedCore.Trie.Verify
import VerifiedCore.Replication.History

/-!
The executable core: every production Lean operation is a complete command
imported from `Entry`, driving raw host effects. Nothing else is exported.
-/
