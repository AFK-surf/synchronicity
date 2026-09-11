# Hosted delegation API

A hosted network's member can register a delegate without operating a named
issuer node locally. The control plane authenticates the existing session or
org API key, checks network membership and cloud hosting, and forwards the
request to the assigned data plane's slot 1. The data plane publishes its own
ordinary signed delegation record using the same engine operations as
`synch delegate add` and `synch delegate rm`.

There is no invitation entity, bearer invitation token, redemption workflow,
new database table, or DNS membership mutation. Applications collect the
joining device's public key and submit it through an authenticated caller.
Never send an org API key to an untrusted joining device.

## API

Both operations require the existing **member** org permission. Join keys and
data-plane credentials cannot call them. They work on control-plane replicas
as well as the primary because they write no control-plane state.

- `PUT /api/orgs/<org>/networks/<net>/delegations/<device-public-key>`
  with `{"spaces":["docs"],"expires_at":<unix-seconds>}` creates or replaces the
  hosted member's grant. The expiry is absolute: retrying does not extend it.
- `DELETE` on that same path withdraws this issuer's grant. Already absent is
  success; another issuer's grant is never removed.
- The existing `GET …/delegations` reports replicated grants; it retains its
  existing browse permission/toggle behavior.

A successful mutation returns `{"ok":true,"issuer":"cloud-1@…"}` after local
publication. Replication is asynchronous. A timeout means **unknown outcome**:
retry the same operation. The last published mutation wins; do not retry an old
PUT after deciding to revoke it. Revocation propagates normally and is not a
promise to terminate every application connection already established.

The engine validates device keys, self-delegation, explicit distinct space
names, nonempty scope and future expiry. Wildcards are not supported. Expiry
must fit signed Unix nanoseconds. Expired grants do not authorize access;
ordinary expiry is not an application process timer.

Hosting disabled is 409, no attached writer or a failed operation is 503,
malformed grant is 400, and the bounded concurrent-request limit is 429.
A writer older than protocol v2 returns 409 without sending an unknown opcode.
Other errors retain the existing org authentication semantics.

## Joining

The joining device generates and retains its own private key (`synch init`).
An authenticated application submits only its public key and the desired scope
and deadline. After the grant is published, the device can trust the returned
issuer's key, or discover the network through
`synch domain set <network-domain> --delegate`, then start its daemon. It stays
a key-identified delegate, not a zone-named full member. Any invitation UX,
public-key handoff or bootstrap script belongs to the calling application.

## Transport and persistence

Write-tunnel protocol v2 adds `delegate` with a nested `mutation` (`action` is
`put` or `delete`) and a `delegated` acknowledgement carrying the request id.
File operations remain compatible with v1. Normal daemon browse tunnels stay
read-only; this decoder is linked only into the managed data plane.

The existing hosted node trie/database and its existing replication/recovery
path hold the grant. No parallel invitation store or reconciliation state
machine is introduced. A hosted member's grant can be observed from other
members through normal delegation replication. This is network admission, not
an application-specific permission or an authentication credential minting API.
