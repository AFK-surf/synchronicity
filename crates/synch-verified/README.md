# Statically linked whole Lean operations

Production paths use one implementation: complete Lean commands over raw host
services, or pure Rust. There is no optional Lean backend and no Rust caller
asking Lean for a scalar settlement, bitmap plan, scope predicate, walk step or
completeness-cache transition.

Local complete ingestion, local reads/repair, CAS acquisition/deletion/unpin/
expiry, trie lookup and history retention remain mandatory whole Lean commands.
Partial/cloud CAS orchestration, scope/walk and completeness coordination stay
in Rust. Their fine-grained native exports and adapters have been removed.
No further domain migration is authorized by this boundary cleanup.

`VerifiedCore/Host.lean` supplies a typed executable effect monad and transaction
combinator. New `Cas/Program`, `Trie/Program` and `Replication/History` modules
implement acquisition, lookup (including the postcard codec), and retention
over raw storage effects. CAS pin/possession acquisition now uses that complete
operation in production. The shared synchronous continuation interpreter asks
Rust only for raw storage effects; Lean owns begin/read/mutate/commit/rollback.
The old acquisition snapshot/planner API and Rust orchestration are deleted.
CAS deletion also owns raw protection reads, transaction completion and file
cleanup; its snapshot/planner ABI and Rust phase executor are removed.
Trie lookup also runs as a complete native Lean operation over raw byte reads;
the former Rust lookup traversal is removed. History retention now runs as a
complete Lean operation over raw scans and a separate Ed25519 primitive; the
Rust retention loop and receipt/fork helpers are removed. Raw scans retain
rows before a trailing host failure so Lean owns first-error selection.
No selectable backend is added.

Local CAS reads execute `Cas/Read.lean`, including metadata/bitmap decoding,
bounds, coverage, inline reads and transactional missing/truncated-file
repair. Both Rust read algorithms and the local healing transaction are removed.
Raw snapshots release their connection before file I/O; the program opens the
payload once and asks the host for one `FileIO.transfer` of the admitted range
straight into a private Rust buffer, published only after a successful
terminal byte count. The payload of a file read is never a Lean value. File,
clock, output and relational capabilities remain independent of CAS policy.
Same-source read/codec/healing proofs and native/SQLite fault tests cover
this boundary; cloud hydration and Bao serving/import remain Rust operations.

Production local ingestion runs `Cas/Input.run` and `Cas/Ingest.run` in Lean:
input length policy, inline choice, temporary-resource lifecycle, writer-lease
lifetime, publication ordering and the metadata transaction. Object
construction is a host service the program directs: `Construct.build`
streams the captured source into the owned payload and outboard temporaries
and replies with the root, and `Construct.hash` answers the root of an inline
object. Verified Bao streaming is out of scope for the Lean core; `blake3` and
`bao-tree` do that work in the store's resource pool, as they do for the cloud
paths. `Store::ingest_bytes` and `Store::ingest_file` call the whole Lean
command unconditionally; the old Rust orchestration and ingestion-only test
hooks are deleted. The architecture document records changing-file behavior,
temporary-file/GC hazards and durability gates.

`Cas/IngestCommit.lean` owns claim decoding, settlement and atomic
metadata mutation over raw storage effects, without exposing a Rust planner
facade. Its transaction/error proofs cover the executed code, not a manually paired
Rust model. Native cryptographic and Bao-layout correctness are trust
assumptions on the host's construction service.

`Cas/Ingest.lean` composes the construction request and metadata commit with
raw temporary-file and keyed-lease effects for an already captured, out-of-line
source. Lean owns cleanup, both flushes before publication, directory-sync
policy, and lease release after the transaction. Fault traces cover every
effect on the empty-source execution path, including a root reply of the
wrong width, which is rejected before any lease, flush or name. `Cas/Input.run`
adds byte/file input acquisition and inline/EOF policy, with a whole-command
native facade and a raw filesystem/lease interpreter. Real SQLite/file tests
check roots, payloads, Bao layout and failure cleanup, including a 14-case
effect-failure matrix, deferred COMMIT rollback and deterministic
GC/publication concurrency. The growing-small-file collector retains chunks
and flattens once, with universal Lean order/length proofs, avoiding
suspended prefix copies. The focused CI/static-link gate covers Linux, macOS
and Windows; configuration is not execution evidence, and the
growing-small-file path still retains whole captured input.

The acquisition cutover is checked against real SQLite, including abandoned
transactions, automatic rollback, deferred commit failure, UPSERT timestamp
preservation and the existing typed errors for corrupt durability cells.
`HostWireProofs` checks Lean-side reply framing and continuation behavior;
native tests check the C/Rust transport. Neither is a proof of physical I/O.

Acquisition checkpoint validation (`e543883`): all 475 tests across `synch-verified`,
`synch-store` and `synch-engine`; focused all-target Clippy with warnings denied;
the full Lean warnings-as-errors proof build. Builds were run
sequentially with bounded compiler memory after the development-session OOM.
This does not claim the remaining domains or new cross-platform CI are complete.

### Domain boundary

The CAS algorithms live in `lean/VerifiedCore/Cas.lean` and `Cas/Program.lean`,
independently of the trie module. Pin/possession and deletion are complete
monadic operations. The deletion snapshot/planner ABI has been removed; its
pure decision is internal Lean code, consumed and proved by the operation.
There are no Lean callbacks registered with SQLite.

The Rust facade retains ordering locks while Lean requests raw reads,
transactional mutations, commit/rollback and post-commit file removals. Lean
selects best-effort cleanup and primary-error handling. SQL semantics, locks,
primitive I/O and ABI decoding remain explicit trust boundaries.
`CasLifecycleProofs.lean` proves the executed deletion outcome agrees with its
proved decision, transaction failure prevents cleanup, and committed deletion
attempts both files irrespective of unlink errors. Raw counter/file services
use a separate capability from SQL; relational existence reads remain bounded.
Bulk operations must remain batched; do not add per-row SQL callbacks.

Supported targets are native Linux GNU and macOS (x86-64/arm64), and Windows
x86-64 GNU/LLVM. OpenBSD and Linux musl are not supported by this Rust/native package; the control plane retains OpenBSD support. The build
rejects incompatible runtime architecture/ABI instead of linking host archives
into a cross-target binary. Release CI uses architecture-matched runners.

Install Lean 4.30.0 through elan, then from the repository root:

```sh
cargo test -p synch-verified
cargo test -p synch-mpt -p synch-store
cargo test -p synch-engine --test delegation
cargo build --release --bin synch
cargo run --release -p synch-verified --example decisions
cd specs/lean && lake build --wfail
```

### The generated boundary

The host boundary is declared once, in Lean, and generated on both sides by
`lean/Hostgen.lean`, a Lean program that reflects over the executable core:

- the effect algebras (`lean/VerifiedCore/Host*.lean`, `Crypto.lean`) yield
  `lean/VerifiedCore/Host/Generated.lean` (tags, names, request encoders,
  reply decoders and `WireEffect` instances) and, in Rust, the host traits,
  the request `Frame` enum with its decoder, the dispatch of each frame to
  its service and the `host_unexpected!` stubs test doubles fill their
  `impl` blocks with;
- the command and outcome types (`lean/VerifiedCore/Commands.lean` and the
  domain types it names) yield `lean/VerifiedCore/Commands/Generated.lean`
  (`Encode`/`Decode` instances) and the mirrored Rust enums and structs with
  their codecs.

The Lean side is kept in the tree; the Rust side is a build product that
`build.rs` prints into Cargo's output directory and `lib.rs` includes, so it
is never committed. Only the tag table and the routing of each algebra to a
Rust service are written by hand, in the generator. After changing an
algebra or a command type, run
`cd crates/synch-verified/lean && lake env lean --run Hostgen.lean` and
commit the Lean output; `build.rs` and CI run it with `--check`, so a stale
copy fails the build instead of drifting from the Rust it faces. One native
entry point,
`synch_lean_start`, takes an encoded `Command`; `Entry.lean` maps each
operation's domain result onto its outcome type, and the Rust facades in
`src/cas.rs`, `src/history.rs` and `src/trie.rs` only bind capabilities and
decode terminals.

### Windows

Lean ships an LLVM/MinGW UCRT runtime, not an MSVC C++ runtime. Install the
MSYS2 CLANG64 toolchain and `rustup target add x86_64-pc-windows-gnullvm`.
In PowerShell (adjust the MSYS2 installation prefix if needed):

```powershell
$env:CARGO_BUILD_TARGET = "x86_64-pc-windows-gnullvm"
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER = "C:/msys64/clang64/bin/clang.exe"
$env:CC_x86_64_pc_windows_gnullvm = "C:/msys64/clang64/bin/clang.exe"
$env:AR_x86_64_pc_windows_gnullvm = "C:/msys64/clang64/bin/llvm-ar.exe"
$env:PATH = "C:/msys64/clang64/bin;" + $env:PATH
cargo test -p synch-verified
cargo build --release --bin synch
```

Windows artifacts now use the `x86_64-pc-windows-gnullvm` suffix instead of
`x86_64-pc-windows-msvc`. They remain native Windows executables. CI installs
the same toolchain through `.github/actions/setup-lean-core`. Linux release
artifacts use `linux-gnu` instead of `linux-musl` and require system glibc.

No generated C is checked in. Cargo generates it in its own `OUT_DIR`, so
parallel target/profile builds do not race on shared generated artifacts.
The proof package in `specs/lean` depends only on this core; neither it nor
the native build needs Mathlib.
The build checks the Lean version and runtime target triple before linking.
The toolchain's Std, Init, runtime, GMP and libuv archives are linked statically.
Linux and Windows also link the bundled C++ support statically; macOS uses
Apple's system libc++. OS libraries remain dynamic dependencies.

## Proof and trust boundary

The whole-operation proof modules in `specs/lean` import the exact production
Lean sources. Their individual theorem scopes and host assumptions remain
explicit; they do not prove arbitrary filesystem/database behavior, native
cryptographic primitives, the Rust interpreters, the C adapter or the compiler.

Nothing in `specs/lean` models Rust. Scoped walks, completeness certificates,
cloud and network ingestion and every other Rust path are covered by
regression tests, not by Lean theorems, and no anchor pairs a Lean definition
with a Rust site.

## ABI and ownership

Only one command constructor (`synch_adapter_start`, taking an encoded
`Command`), the packet/resume transport and runtime/object lifetime functions
cross the ABI. Rust executes raw effects synchronously and
returns their results to Lean. Handles and packets are invocation-owned and
thread-confined; no shared scope/walk/cache object graphs cross foreign threads.
The runtime initializes once per process and initializes/finalizes calling
threads through TLS. Resume transfers the owned continuation; packets retain
independent byte-array ownership. Strict framing and original host errors are
preserved, and read output stays private until a successful terminal result.

The `decisions` example is now a static-link smoke check of a complete lookup,
not a scalar predicate benchmark. The architecture document retains historical
measurements and the unresolved local-ingestion throughput/captured-input-memory
limitations. See [architecture](../../docs/LEAN-CORE-ARCHITECTURE.md) for operation
contracts and the serial 4-GiB validation policy.
