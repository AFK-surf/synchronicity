# Proof package

This package imports the executable Lean core that Cargo compiles and links
into `synch`. The canonical [Rust/Lean architecture and proof contract](../../docs/RUST-LEAN-PROOFS.md)
contains the user-facing goals, current theorem scopes, module audit, host
assumptions and remaining migration/proof plan. Keep those descriptions there.

The package depends only on the core and the pinned toolchain; no Mathlib.

```sh
cd specs/lean
lake build --wfail
```

Run the [bounded standalone kernel check](../../docs/RUST-LEAN-PROOFS.md#validation-and-completion-gates)
after building; the prefix-wide checker starts modules concurrently.

CI also audits axioms and rejects `sorryAx` or unapproved assumptions. Native
interpreter/platform tests are separate evidence; the proof build does not verify
SQLite, the filesystem, cryptographic primitives or the Rust runtime.

For core build prerequisites and native integration, see the
[`synch-verified` README](../../crates/synch-verified/README.md).
