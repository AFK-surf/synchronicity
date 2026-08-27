# Hecatia protocol synchronization

## Goal

Hecatia must compile against the control protocol owned by the daemon in this
repository, and its default test command must fail when the app copy drifts.

## Current state

Hecatia was moved under `apps/Hecatia`, but `Scripts/sync-proto.sh` still looks
for a sibling `synchronicity` checkout. The default check therefore skips. The
app copy has also retained fields that the daemon has reserved, so generated
Swift code can report values the daemon no longer sends.

## Changes

1. Add an end-to-end script test for the default path, missing canonical proto,
   and real drift detection.
2. Resolve the daemon proto from the monorepo root and fail if it is missing.
3. Replace the app copy with the daemon-owned proto and update Swift callers to
   use only the current response contract.
4. Cover the delete-result presentation with Swift regression tests.

Adding a dedicated macOS GitHub Actions job is intentionally outside this
change and will follow separately.

## Consequences

Without this change, `make test` can pass while the bundled schema is stale;
successful deletes can be reported as missing, and removed sequence fields can
be rendered as zero. After the change, the checked-in copy and generated client
match the daemon, idempotent delete success is silent, and future drift fails
the default local test command.

## Acceptance criteria

- `Scripts/test-proto-sync.sh` passes and proves that drift or a missing
  canonical proto fails.
- `Scripts/sync-proto.sh check` passes from any working directory.
- Swift tests and audits pass, and the release configuration builds.
- A current released daemon can be launched and browsed by the built app; a
  successful local delete does not produce a false “no copy” alert.
