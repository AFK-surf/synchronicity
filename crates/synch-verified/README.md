# Building the executable Lean core

This crate compiles and links the Lean operations used by production Rust APIs.
The single [Rust/Lean architecture and proof contract](../../docs/RUST-LEAN-PROOFS.md)
contains operation ownership, user-facing proof goals, checked evidence, trusted
host contracts, remaining migrations and validation limits. Keep those accounts
there; this README covers build and boundary-generation commands.

Supported targets are native Linux GNU and macOS (x86-64/arm64), and Windows
x86-64 GNU/LLVM. OpenBSD and Linux musl are not supported by this Rust/native package; the control plane retains OpenBSD support. The build
rejects incompatible runtime architecture/ABI instead of linking host archives
into a cross-target binary. Release CI uses architecture-matched runners.

Install Lean 4.33.1 through elan, then from the repository root:

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
