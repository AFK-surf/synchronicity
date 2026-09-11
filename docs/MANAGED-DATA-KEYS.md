# Org-scoped managed-data API keys

Mint an API key with `role: "managed_data"` using the existing signed-in
owner/admin API-key creation flow, or choose **org key · managed data only** in
Settings. It names one org, not one network. Like a join key, its kind cannot be
changed after minting; rename, expiry changes and revocation use the existing
key-management APIs. The token format, hashed storage and expiry checks are
unchanged. A managed-data key cannot create or manage other keys.

## Allowed surface

Only networks with **cloud hosting enabled** in that org are accessible:

- GET `…/networks/<net>/browse`: hosted browse/write status.
- GET `…/browse/ls`, `…/browse/stat`, `…/browse/file`: listing, metadata and bytes.
- PUT/DELETE `…/browse/file`: writes to the hosted member's own view.
- GET `…/delegations`, `…/replication`: queries answered by the hosted member.
- PUT/DELETE `…/delegations/<key>`: the hosted member's delegate mutations.

The existing browsing toggle still gates reads. Write availability continues to
follow the existing cloud-hosting gate. Origin selectors may select replicated
data, but the serving process is always the managed data plane.

Read routing requires a browse attachment whose device-key id and origin match
an authenticated write-tunnel attachment for that network. A customer-chosen
`cloud-*` label is not sufficient. If the hosted attachment is absent, reads do
not fall back to customer daemons. Legacy org-member/admin keys retain their
existing routing behavior.

## Explicitly unavailable

No org/network discovery or administration, network creation/deletion, hosting
or browse-toggle changes, formal device enrollment or device-key management,
member/account/API-key management, or deployment/fleet `/dp/v1` access. Public
unauthenticated endpoints remain public; they do not gain authority from this
credential. A different org is not discoverable through an allowed route.

This key is **not** the fleet's data-plane credential. It cannot attach a data
plane, register a hosting slot, publish DNS membership or connect directly as a
Synchronicity peer. Normal org routes reject its distinct principal by default;
only managed-data handlers opt into its permission gate.

Revoking or expiring the API key prevents subsequent authenticated requests.
It does not undo file writes or revoke delegations already signed by the hosted
member. Revoke those grants separately with an authorized credential. This is
an org-wide data-operation key, not a per-space or read-only credential.

## Migration and verification

Schema v15 rebuilds `api_keys` to add the managed-data kind, preserving existing
ids, token hashes, scope, expiry and usage stamps. New code must be deployed
before minting the new kind; older builds refuse the newer schema. No Rust/DP
protocol change is required.
