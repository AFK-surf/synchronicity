# Statically linked, verified Lean decisions

This is the first implementation milestone, not another handwritten model.
`lean/VerifiedCore.lean` contains the executable authorization and CAS size
settlement functions. Cargo compiles that source to C and statically links it
with Lean's runtime. `specs/lean` imports the **same source package** and proves
the functions agree with the abstract scope and CAS contracts.

## Mandatory integration

Every build uses Lean 4.30.0 for scope/path/key/node/payload decisions and CAS
size settlement. The corresponding Rust implementations and feature flags
have been deleted. The shared `synch-core::group_count` API also delegates to
Lean. Rust code in the native tests/example is an independent test oracle,
not a selectable production backend.

Supported targets are native Linux GNU and macOS (x86-64/arm64), and Windows
x86-64 GNU/LLVM. OpenBSD and Linux musl support has been removed. The build
rejects incompatible runtime architecture/ABI instead of linking host archives
into a cross-target binary. Release CI uses architecture-matched runners.

Install Lean 4.30.0 through elan, then from the repository root:

```sh
cargo test -p synch-verified
cargo test -p synch-mpt -p synch-store
cargo test -p synch-engine --test delegation
cargo build --release --bin synch
cargo run --release -p synch-verified --example decisions
cd specs/lean && lake build --wfail && ./check-anchors.sh
```

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
Mathlib is needed for the proof build, not the native build or runtime.
The build checks the Lean version and runtime target triple before linking.
The toolchain's Init, runtime, GMP and libuv archives are linked statically.
Linux and Windows also link the bundled C++ support statically; macOS uses
Apple's system libc++. OS libraries remain dynamic dependencies.

## What is proved

`specs/lean/Synchronicity/VerifiedCoreProofs.lean` proves:

- scope position, subtree, key, node and payload decisions match the existing
  positional predicates, including exact grants and refused spine values;
- exported node/payload decisions implement those predicates for decoded shapes;
- UInt64 group counting agrees with the unbounded CAS definition, including
  zero and `u64::MAX`, without overflow;
- settlement accepts exactly the allowed claims, resets bits exactly when
  required, and implements `Cas.Settles` given the row's representation facts.

This does not prove the C adapter, Rust node-to-shape mapping, SQL row decoding,
or that the caller holds the transaction lock. Those remain explicit trust
boundaries tested by native property tests and real subsystem regressions.
Neither cryptographic verification nor filesystem effects have moved to Lean
in this milestone. The Lean compiler/runtime and native toolchain remain
trusted, as do the standard library's implemented primitives.

## ABI and lifecycle

Only the adapter handles `lean_object` pointers. Rust owns an opaque immutable
scope through `Arc`; it cannot construct arbitrary Lean values. The C adapter
copies input bytes, converts path arrays via Lean exports, marks the complete
scope graph multi-threaded before sharing, and supplies a fresh owned Lean
reference to each consuming export. Scope contents are never mutated.

Initialization is once per process. Foreign Rust threads are initialized lazily
and finalized through TLS. A scope stored in an older Rust TLS slot may outlive
that guard; its final destructor temporarily reinitializes the thread before
releasing the object. Dedicated tests cover cross-thread calls/drop and this
TLS destruction ordering. Allocation failure is not recoverable at this ABI.

The scalar settlement API accepts normalized booleans and bounded integers,
returns a checked discriminant, and carries no erased proof arguments. The
caller supplies the actual row facts from its transaction. Unknown shape tags
fail closed in Lean; they cannot be manufactured through the public Rust enum.

## Performance and next gates

The `decisions` example is an informational benchmark, not a CI timing gate.
An initial run here measured 330–826 ns per Lean payload decision versus
14–64 ns for the Rust oracle across full, 1-, 16- and 64-prefix scopes. The
native benchmark executable was 2.9 MiB and had no dynamic Lean dependencies.
These are workload/machine-specific observations, not production guarantees.
Per-call byte copies and conversion to lists dominate small predicates.

Next: optimize/batch the boundary, benchmark real trie walks, and expand the
source-based proofs as the incremental walker and promotion planner move.
Moving a policy into Lean does not by itself verify the external effects that
Rust performs in response.
