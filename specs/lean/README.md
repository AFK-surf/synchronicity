# Proof package

This package imports the executable Lean core that Cargo compiles and links
into `synch`. The canonical [Rust/Lean architecture and proof contract](../../docs/LEAN.md)
contains the user-facing goals, checked scopes, host
assumptions and remaining migration/proof plan. Keep those descriptions there.

The package depends only on the core and the pinned toolchain; no Mathlib.

```sh
cd specs/lean
lake build --wfail
```

Run the [standalone kernel checks in CI](../../.github/workflows/ci.yml) after
building; in memory-constrained environments, check modules serially.

CI also audits axioms and rejects `sorryAx` or unapproved assumptions. Native
interpreter/platform tests are separate evidence; the proof build does not verify
SQLite, the filesystem, cryptographic primitives or the Rust runtime.

For core build prerequisites and native integration, see the
[`synch-verified` README](../../crates/synch-verified/README.md).
