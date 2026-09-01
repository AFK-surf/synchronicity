// JSON API client: cookie session + CSRF double-submit header.

let csrfToken = ''

export function setCsrf(token: string) {
  csrfToken = token
}

export class ApiError extends Error {
  status: number
  code: string
  // Where the request should have gone, when this node could not take it.
  // Empty for every other failure. Set by a read-only replica, which
  // refuses writes with the address of the node that holds the pen.
  primary: string

  constructor(status: number, code: string, message: string, primary = '') {
    super(message)
    this.status = status
    this.code = code
    this.primary = primary
  }
}

async function handle<T>(resp: Response): Promise<T> {
  if (resp.status === 401) {
    window.location.href = '/login'
    throw new ApiError(401, 'unauthenticated', 'signed out')
  }
  const body = await resp.json().catch(() => null)
  if (!resp.ok) {
    const err = body?.error ?? { code: 'error', message: `HTTP ${resp.status}` }
    throw new ApiError(resp.status, err.code, err.message, err.primary ?? '')
  }
  return body as T
}

export function get<T>(path: string): Promise<T> {
  return fetch(path, { credentials: 'same-origin' }).then((r) => handle<T>(r))
}

export function send<T>(
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<T> {
  return fetch(path, {
    method,
    credentials: 'same-origin',
    headers: {
      'x-csrf': csrfToken,
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  }).then((r) => handle<T>(r))
}

// -- shapes -----------------------------------------------------------------

export interface Me {
  user: { id: string; email: string; name: string }
  csrf: string
  orgs: OrgRef[]
}

// Which sign-in methods this deployment has configured. The login and
// settings screens offer only the ones that are true; the rest would
// answer "provider not configured" if anyone reached them.
export interface AuthMethods {
  google: boolean
  github: boolean
  magic_link: boolean
  oidc: boolean
  // The node that takes the writes, when this one does not: a replica
  // serves the dashboard off a read-only copy and mints no session, so it
  // offers no method and names the node that does. Empty on the primary,
  // which is that node.
  primary: string
}

export interface OrgRef {
  id: string
  slug: string
  name: string
  role: 'owner' | 'admin' | 'member'
}

export interface OrgDetail {
  id: string
  slug: string
  role: string
  networks: string[]
  device_count: number
}

export interface NetworkSummary {
  name: string
  device_count: number
  // Whether an operator-run replica is hosted on this network
  // (`docs/CLOUD-DATAPLANE.md` §2). The column behind it is an integer; the
  // API answers a boolean, so this is a switch here too.
  cloud_hosted: boolean
}

export interface DeviceKeyRow {
  device_id: string
  label: string
  relay: string
  addr: string
  key_id: string
  nk: string
  state: 'active' | 'retiring' | ''
  added_at: number
}

export interface NetworkDetail {
  domain: string
  soa_serial: number
  sig_expires_at: number
  last_published_at: number
  cloud_hosted: boolean
  devices: DeviceKeyRow[]
}

export interface DeviceRow {
  device_id: string
  label: string
  relay: string
  addr: string
  key_id: string
  nk: string
  state: string
  networks: string
}

export interface MemberRow {
  user_id: string
  email: string
  name: string
  role: string
}

export interface AuditRow {
  id: number
  at: number
  actor: string
  action: string
  detail: string
}

// What /api/invites/preview says about a token: the invite page renders it
// before any session exists. `status` is the server's word for whether the
// token can still be accepted.
export interface InvitePreview {
  org: string
  org_name: string
  email: string
  role: string
  expires_at: number
  status: 'valid' | 'expired' | 'accepted'
}

// One org-scoped API key, as the settings list sees it. Never the token:
// that value exists once, in the reply to the request that minted it.
//
// `expires_at` and `last_used_at` are 0 for "never expires" and "never
// used" — the server sends a number rather than a null so the two absent
// cases test the same way as every other timestamp on this page.
export interface ApiKeyRow {
  id: string
  name: string
  prefix: string
  // `admin` and `member` are org keys, reaching whatever that role reaches
  // across the org. `join` is a join key: one network, one operation.
  role: 'admin' | 'member' | 'join'
  created_at: number
  expires_at: number
  last_used_at: number
  // The minter's email, not their id — the question a list answers is "who
  // made this", and it is the column to read when somebody leaves the org.
  created_by_email: string
  // The network a join key is scoped to; empty for an org key.
  network: string
}

// What minting one answers with. `token` is shown once and then cannot be
// recovered from anywhere — the server keeps only its SHA-256.
export interface MintedApiKey {
  id: string
  name: string
  role: string
  network: string
  prefix: string
  expires_at: number
  token: string
}

export interface OidcConfig {
  issuer: string
  client_id: string
  authorization_endpoint: string
  token_endpoint: string
  discovered_at: number
}

// -- cloud browse -----------------------------------------------------------

export interface BrowseDevice {
  session: string
  device: string
  origin: string
  spaces: string[]
  protocol: number
  attached_at: number
}

export interface BrowseStatus {
  enabled: boolean
  devices: BrowseDevice[]
  attach_url: string
}

/// One delegated device key, as an attached daemon reports it.
///
/// `live` is the daemon's answer and not a date comparison to redo here:
/// derived trust dies with its source, so a grant whose issuer has been
/// removed, or has lapsed from DNS, is dead well before `not_after`.
export interface Delegation {
  key: string
  issuer: string
  spaces: string[]
  live: boolean
  not_after: number
  added_at: number
  note: string
}

export interface Delegations {
  device: string
  origin: string
  delegations: Delegation[]
}

/// One replica, as the node holding it reports it
/// (`docs/REPLICATION.md` §8).
///
/// `wanted` includes `unreachable`, because that is what the node means by it.
/// Objects no provider has answered for are not a backlog that is draining;
/// they are versions that are probably already gone, and telling those two
/// apart is most of why anyone watches a replica. Subtract for the backlog,
/// the way `synch replica ls` does.
///
/// `budget`, `oldest_want` and `next_release` are `0` for "none", not for a
/// value of zero — the same convention `Delegation.not_after` uses.
export interface ReplicaSpace {
  space: string
  policy: 'current' | 'forever'
  grace_secs: number
  budget: number
  held: number
  held_bytes: number
  releasing: number
  releasing_bytes: number
  wanted: number
  wanted_bytes: number
  unreachable: number
  unreachable_bytes: number
  held_back: number
  oldest_want: number
  next_release: number
  // Synchronization health; release sweeps continue from complete heads.
  view_complete: boolean
  view_reason: string
}

/// One node's replication report, or its refusal to give one.
///
/// `error` is empty when the node answered. A node that replicates nothing and
/// a node that could not be asked have identical counts and call for entirely
/// different actions, so they are told apart by this field and not by reading
/// the numbers.
///
/// `outdated` is its own case: the node speaks a tunnel version older than the
/// replication query, so it was never asked — asking would have ended its
/// tunnel. Nothing is wrong with it beyond its age.
export interface NodeReplication {
  device: string
  origin: string
  spaces: ReplicaSpace[]
  error: string
  message: string
}

export interface Replication {
  nodes: NodeReplication[]
  /// How many attached nodes replicate each space. Nodes that refused
  /// contribute nothing, so this counts what was measured and not what was
  /// assumed.
  spaces: { space: string; replicas: number }[]
}

export interface BrowseVersion {
  root: string
  kind: string
  symlink_target: string
  size: number
  mtime_ns: number
  seq: number
  attestors: string[]
}

export interface BrowseEntry {
  name: string
  path: string
  kind: 'dir' | 'file' | 'symlink' | 'tombstone'
  size: number
  mtime_ns: number
  versions: number
  origin: string
  root: string
  all: BrowseVersion[]
}

export interface BrowseListing {
  device: string
  origin: string
  space: string
  path: string
  entries: BrowseEntry[]
  cursor: string
}

export interface BrowseVersions {
  device: string
  space: string
  path: string
  versions: BrowseVersion[]
}

// Space and path are query parameters, never path segments: a file path may
// contain anything, including the separators a route would split on.
export function browseQuery(params: Record<string, string>): string {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== '') query.set(key, value)
  }
  const rendered = query.toString()
  return rendered === '' ? '' : `?${rendered}`
}

// -- cloud hosting ----------------------------------------------------------

/// What a route that reshapes the zone answers with: the flat `ok` plus the
/// serial the publish committed at, and the route's own payload nested under
/// `result`. Every zone-shaping call replies in this envelope — adding a
/// device does, and so does this switch — so the payload is never at the top
/// level however small it is.
export interface ZoneMutation<T> {
  ok: boolean
  soa_serial: number
  result: T
}

/// The cloud-hosting switch's payload. `devices_removed` is what turning it
/// off took out of the network in the same commit — 0 on the way in.
export interface CloudHostingResult {
  enabled: boolean
  devices_removed: number
}

/// Turn managed replica hosting on or off for one network
/// (`docs/CLOUD-DATAPLANE.md` §2). Admin-gated, like the browse switch, and a
/// zone mutation in both directions: enabling republishes so the data plane's
/// poll notices, and disabling removes the hosted device rows with the same
/// commit that clears the flag.
export function setCloudHosting(
  slug: string,
  network: string,
  enabled: boolean,
): Promise<ZoneMutation<CloudHostingResult>> {
  return send(
    'PUT',
    `/api/orgs/${slug}/networks/${network}/cloud-hosting/enabled`,
    { enabled },
  )
}
