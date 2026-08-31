# Cue Integration Review Fixes

## Goal

Keep Cue Workspace provisioning idempotent under concurrent retries and keep
device enrollment inside the Synchronicity org that owns the device.

## Current state

- The first Workspace lookup happens before the serialized zone transaction.
  Two callers can both observe a missing mapping, after which the loser returns
  a uniqueness conflict instead of reusing the mapping committed by the winner.
- Lookup by a live node key returns only the device id. The enrollment path can
  therefore attach a device owned by one org to a network owned by another org.

## Proposed changes

1. Add deterministic regressions for a concurrent duplicate Workspace request
   and for enrolling one live node key through two Workspace orgs.
2. Recheck the Workspace mapping after the create path acquires the SQLite
   writer transaction, reusing the committed mapping when another caller won.
3. Return the owning org with an existing device-key lookup and reject a target
   org mismatch before any network membership or zone mutation.
4. Keep ordinary sequential reuse on the no-publication fast path and preserve
   the existing response schema.

## If unchanged

A benign concurrent retry can become a terminal Cue provisioning failure, and
a user can attach a public node key owned by another tenant to their own
Workspace network, leaving ownership, management, publication, and deletion
semantics inconsistent.

## Result after the change

Concurrent duplicate provisioning returns the one committed Workspace mapping,
and a live node key can only be reused inside its owning org.

## Acceptance criteria

- Both regressions fail on PR head `2e5084902c022e4cdf120ca2a162b4cfb5e65b37`
  and pass after the repair.
- Concurrent responses are successful and identify the same org and network.
- Cross-org enrollment returns 409 and creates no cross-org membership.
- `gleam test`, formatting, and `git diff --check` pass.
- A manual paired-request smoke confirms the response/status contracts consumed
  by Cue.

## Implementation order

1. Add and run the failing regressions.
2. Remove the pre-transaction-only mapping decision and unscoped device lookup.
3. Reimplement them with the transaction recheck and owning-org guard.
4. Run automated and manual validation, then update PR #101.
