# Repository Guidelines

## Project Structure & Module Organization

This is a Rust 2021 workspace (minimum Rust 1.91). Libraries and binaries live in `crates/synch-*`; code belongs in each crate's `src/`, integration tests in `tests/`, and harnesses in `examples/`. `control-plane/` contains a Gleam/Erlang backend, `control-plane/web/` the React/TypeScript SPA, and `control-plane/e2e/` cross-system tests. Formal models live under `specs/` (TLA+ and Lean). Consult `DESIGN.md` for architecture and `docs/` for subsystem contracts. `vendor/russh/` is patched; change it only with corresponding patch documentation.

## Build, Test, and Development Commands

- `cargo build --release` builds workspace binaries into `target/release/`.
- `cargo test --workspace` runs the normal Rust suite; use `cargo test -p synch-net` for a focused crate.
- `cargo fmt --all --check` verifies formatting.
- `cargo clippy --workspace --all-targets -- -D warnings` applies the primary lint gate.
- `cd control-plane && make -C csqlite && gleam test` builds the SQLite port and tests the backend.
- `cd control-plane && just dev` starts the backend on port 8080 and the Vite dev server.
- `cd control-plane && just web-build` type-checks, tests, and builds the SPA.
- `cd specs/lean && lake build --wfail` checks Lean proofs without tolerating warnings.

Cloud and end-to-end suites require Docker, DNS tools, or provider emulators; follow the relevant README or CI workflow.

Gleam is needed to develop and test the control plane. In ephemeral development environments (e.g. Claude Code Web), install `asdf` and install Gleam + Erlang with it.

## Coding Style & Naming Conventions

Use four-space indentation and let `rustfmt` own Rust layout. Follow Rust conventions: `snake_case` modules/functions/tests, `CamelCase` types and traits, and `SCREAMING_SNAKE_CASE` constants. Keep public APIs narrow; workspace lints flag unreachable exports and missing `Debug`. Format Gleam with `gleam format`; in `control-plane/web`, follow existing TypeScript/React patterns and run `npm run lint` (Oxlint). Preserve security, protocol, and portability comments.

## Testing Guidelines

Place unit tests near implementation and integration tests in `<crate>/tests/*.rs`; frontend tests use `*.test.ts`. Name tests after observable behavior. Add regression coverage for bug fixes, especially trust boundaries and cross-platform behavior. The `synch-engine` and ignored `synch-mpt` stress tests are intentionally separated in CI; run targeted variants when touching those areas.

## Commit & Pull Request Guidelines

History favors concise, imperative subjects, optionally scoped (`mptsync: ...`, `fix(sock): ...`). Explain the user-visible or invariant-level outcome. Pull requests should include rationale, linked issues, commands run, and platform or migration impact. Include screenshots for dashboard changes and update docs or formal-model anchors when guarantees change. Never commit credentials; use documented `SYNCH_*` and `CP_*` environment variables.
