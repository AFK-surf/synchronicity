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
