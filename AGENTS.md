# Repository Guidelines

## Project Structure & Module Organization

This is a Rust 2021 workspace (minimum Rust 1.91). Libraries and binaries live in `crates/synch-*`; code belongs in each crate's `src/`, integration tests in `tests/`, and harnesses in `examples/`. `control-plane/` contains a Gleam/Erlang backend, `control-plane/web/` the React/TypeScript SPA, and `control-plane/e2e/` cross-system tests. Formal models live under `specs/`: the TLA+ recovery model, and Lean proofs about the executable Lean core in `crates/synch-verified`. Consult `DESIGN.md` for architecture and `docs/` for subsystem contracts. `vendor/russh/` is patched; change it only with corresponding patch documentation.

## Lean Architecture and Proof Goals

Read [docs/LEAN.md](docs/LEAN.md) before changing the Rust/Lean boundary or proof goals. It is the canonical overview of architecture, migration status, checked guarantees, trust assumptions and remaining work. Design high-level theorems around real system properties that matter to users and can be explained in plain words; prove helpers only when they support those properties. Keep implementation details and precise assumptions beside the code. Keep `docs/LEAN.md` human-readable, under 20KB and about overall system status, without PR-specific scope or history. Update it when ownership or proof coverage changes, and distinguish migrated code from proved guarantees.

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

Choose tests by the behavior or failure they can independently detect, not by the number of functions or branches:

- Test meaningful system behavior and concrete boundary risks. Do not add tests merely for getters, direct forwarding, field mapping, or other trivial properties that are correct by construction.
- Before adding examples for a Lean-owned property, check whether a theorem already covers the same executable operation under the relevant assumptions. Avoid restating a proved algorithm with sample matrices or a second implementation. Keep a small set of native integration checks for the Rust/Lean boundary, integer limits, ownership and real host behavior. Fixed-input theorems, concrete Lean fixtures and bounded models do not establish broader guarantees.
- Let Hostgen checks and compilation enforce generated types, field layouts and mechanical conversions. Test shared codecs once per meaningful mechanism, including malformed nested tags, hostile lengths, truncation and trailing data; do not repeat these checks for every generated command or variant. Preserve independent protocol compatibility vectors where they establish a separate contract.
- Exercise the actual production path. Never copy a production branch into the test body and assert that the copy behaves correctly. Do not derive expected results using the same helper being tested; use independent observations or expectations.
- Make assertions establish what the test name claims. A cancellation or drop test must observe resource release or retained state; successfully starting another operation does not prove that the previous continuation was released. Test partial-write cleanup through the real runner, not a test-local reconstruction of its cleanup sequence.
- Preserve regressions for original host errors, failure ordering, cancellation, transaction/resource lifetimes, partial-output rejection, raw storage types, validation bypasses and platform behavior. Lean proofs do not verify Rust interpreters, SQLite, filesystems or external services. Assert exact call sequences only when the ordering itself is the contract being protected.
- When refactoring, remove or consolidate superseded and redundant tests alongside the implementation. Replace misleading tests with meaningful coverage where needed; do not delete host-boundary coverage solely because the domain algorithm is proved. Run the relevant checks, and broaden or repeat them only for new changes, failures or unresolved concerns.

## Commit & Pull Request Guidelines

History favors concise, imperative subjects, optionally scoped (`mptsync: ...`, `fix(sock): ...`). Explain the user-visible or invariant-level outcome. Pull requests should include rationale, linked issues, commands run, and platform or migration impact. Include screenshots for dashboard changes and update docs and the core proofs when guarantees change. Never commit credentials; use documented `SYNCH_*` and `CP_*` environment variables.
