// JSON API client: cookie session + CSRF double-submit header.

let csrfToken = ''

export function setCsrf(token: string) {
  csrfToken = token
}

export class ApiError extends Error {
  status: number
  code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
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
    throw new ApiError(resp.status, err.code, err.message)
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

export interface OidcConfig {
  issuer: string
  client_id: string
  authorization_endpoint: string
  token_endpoint: string
  discovered_at: number
}
