# Repository Guidelines

## Project Structure & Module Organization

This is a Rust 2021 workspace (minimum Rust 1.91). Libraries and binaries live in `crates/synch-*`; code belongs in each crate's `src/`, integration tests in `tests/`, and harnesses in `examples/`. `control-plane/` contains a Gleam/Erlang backend, `control-plane/web/` the React/TypeScript SPA, and `control-plane/e2e/` cross-system tests. Formal models live under `specs/`: the TLA+ recovery model, and Lean proofs about the executable Lean core in `crates/synch-verified`. Consult `DESIGN.md` for architecture and `docs/` for subsystem contracts. `vendor/russh/` is patched; change it only with corresponding patch documentation.

## Lean Architecture and Proof Goals

Read [docs/LEAN.md](docs/LEAN.md) before changing the Rust/Lean boundary or proof goals. It is the canonical overview of architecture, migration status, checked guarantees, trust assumptions and remaining work. Design high-level theorems around real system properties that matter to users and can be explained in plain words; prove helpers only when they support those properties. Keep implementation details and precise assumptions beside the code. Keep `docs/LEAN.md` human-readable, under 20KB and about overall system status, without PR-specific scope or history. Update it when ownership or proof coverage changes, and distinguish migrated code from proved guarantees.

Organize the proof entry points to mirror the goal hierarchy in `docs/LEAN.md` (P1–P8 and their specialized M1–M8 goals). Each goal needs an explicitly named property and a corresponding top-level theorem whose statement expresses that user-facing guarantee. Link the goal in the document to its proof entry point; keep operation-level theorems and helper lemmas beneath that goal as supporting results. A collection of component proofs, or a conjunction merely bundling them, does not establish a completed goal: mark the goal complete only when its top-level theorem proves the stated property for the relevant production executions under explicit assumptions.

Express goal properties as operation-independent domain invariants or transition relations, not a growing enumeration of command-specific violations. Prove that actual operations refine that common specification. Derive permissions (such as consuming a captured version) from actual reads or continuation provenance; do not assume the desired refinement in execution constructors.

## Build, Test, and Development Commands

- `cargo build --release` builds workspace binaries into `target/release/`.
- `cargo test --workspace` runs the normal Rust suite; use `cargo test -p synch-net` for a focused crate.
- `cargo fmt --all --check` verifies formatting.
- `cargo clippy --workspace --all-targets -- -D warnings` applies the primary lint gate.
- `cd control-plane && make -C csqlite && gleam test` builds the SQLite port and tests the backend.
- `cd control-plane && just dev` starts the backend on port 8080 and the Vite dev server.
- `cd control-plane && just web-build` type-checks, tests, and builds the SPA.
- `cd specs/lean && lake build --wfail` checks the Lean core proofs without tolerating warnings.
- `cd crates/synch-verified/lean && lake env lean --run Hostgen.lean` regenerates the checked-in Lean codecs of the host boundary after changing an effect algebra or command type; `--check` verifies them. The Rust glue is printed into Cargo's output directory by `build.rs` and is never committed.

Cloud and end-to-end suites require Docker, DNS tools, or provider emulators; follow the relevant README or CI workflow.

Gleam is needed to develop and test the control plane. In ephemeral development environments (e.g. Claude Code Web), install `asdf` and install Gleam + Erlang with it.

## Coding Style & Naming Conventions

Use four-space indentation and let `rustfmt` own Rust layout. Follow Rust conventions: `snake_case` modules/functions/tests, `CamelCase` types and traits, and `SCREAMING_SNAKE_CASE` constants. Keep public APIs narrow; workspace lints flag unreachable exports and missing `Debug`. Format Gleam with `gleam format`; in `control-plane/web`, follow existing TypeScript/React patterns and run `npm run lint` (Oxlint). Preserve security, protocol, and portability comments.

## Testing Guidelines

Place unit tests near implementation and integration tests in `<crate>/tests/*.rs`; frontend tests use `*.test.ts`. Name tests after observable behavior. Add regression coverage for bug fixes, especially trust boundaries and cross-platform behavior. The `synch-engine` and ignored `synch-mpt` stress tests are intentionally separated in CI; run targeted variants when touching those areas.

- Test meaningful behavior, not trivial properties or code that is correct by construction.
- When proofs cover the same operation and assumptions, keep only the necessary native and host-boundary checks.
- Exercise production code with independent expectations and assertions that establish what the test name claims.
- Test shared codecs once per mechanism; rely on Hostgen and compilation for generated layouts and conversions.
- Prune redundant tests during refactors while preserving fault, cancellation, validation and platform regressions.
- Run relevant checks; broaden or repeat them only for new changes, failures or unresolved concerns.

## Commit & Pull Request Guidelines

History favors concise, imperative subjects, optionally scoped (`mptsync: ...`, `fix(sock): ...`). Explain the user-visible or invariant-level outcome. Pull requests should include rationale, linked issues, commands run, and platform or migration impact. Include screenshots for dashboard changes and update docs and the core proofs when guarantees change. Never commit credentials; use documented `SYNCH_*` and `CP_*` environment variables.
