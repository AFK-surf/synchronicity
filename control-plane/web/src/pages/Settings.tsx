import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router'
import {
  get,
  send,
  type ApiKeyRow,
  type AuditRow,
  type MemberRow,
  type MintedApiKey,
  type NetworkSummary,
  type OidcConfig,
} from '../lib/api'
import { useTitle } from '../lib/title'
import { ErrorNote, useAuthMethods, useMe } from './Shell'

export function Settings() {
  const { slug = '' } = useParams()
  useTitle(`${slug} settings`)
  const { data: me } = useMe()
  const role = me?.orgs.find((o) => o.slug === slug)?.role
  return (
    <div className="space-y-10">
      <Members slug={slug} myRole={role ?? 'member'} myId={me?.user.id ?? ''} />
      {(role === 'owner' || role === 'admin') && (
        // Keyed on the org: this route is one element, so switching :slug
        // re-renders without remounting, and a minted token held in state
        // would appear under the next org's heading.
        <ApiKeys key={slug} slug={slug} />
      )}
      {role === 'owner' && <Oidc slug={slug} />}
      {(role === 'owner' || role === 'admin') && <Audit slug={slug} />}
      <LinkedIdentities />
      {role === 'owner' && <DeleteOrg slug={slug} />}
    </div>
  )
}

function Members({
  slug,
  myRole,
  myId,
}: {
  slug: string
  myRole: string
  myId: string
}) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('member')
  const canAdmin = myRole === 'owner' || myRole === 'admin'
  const { data: members, error } = useQuery({
    queryKey: ['members', slug],
    queryFn: () => get<MemberRow[]>(`/api/orgs/${slug}/members`),
  })
  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['members', slug] })
  const invite = useMutation({
    mutationFn: () => send('POST', `/api/orgs/${slug}/invites`, { email, role }),
    onSuccess: () => setEmail(''),
  })
  const changeRole = useMutation({
    mutationFn: (args: { user: string; role: string }) =>
      send('PATCH', `/api/orgs/${slug}/members/${args.user}`, {
        role: args.role,
      }),
    onSuccess: refresh,
  })
  const remove = useMutation({
    mutationFn: (user: string) =>
      send('DELETE', `/api/orgs/${slug}/members/${user}`),
    onSuccess: refresh,
  })
  const transfer = useMutation({
    mutationFn: (user: string) =>
      send('POST', `/api/orgs/${slug}/transfer`, { to: user }),
    onSuccess: () => {
      refresh()
      // The acting owner just became an admin: what this page offers is
      // role-dependent, and `me` is where the role comes from.
      queryClient.invalidateQueries({ queryKey: ['me'] })
    },
  })
  // Leaving is the same DELETE as removing anyone else, aimed at your own
  // row — but the aftermath is `DeleteOrg`'s rather than `remove`'s: the
  // page you are standing on now answers 404 for you, so every org-scoped
  // query goes with the membership and the picker is refetched without it.
  const leave = useMutation({
    mutationFn: () => send('DELETE', `/api/orgs/${slug}/members/${myId}`),
    onSuccess: async () => {
      queryClient.removeQueries({
        predicate: (q) => Array.isArray(q.queryKey) && q.queryKey[1] === slug,
      })
      await queryClient.invalidateQueries({ queryKey: ['me'] })
      navigate('/')
    },
  })

  return (
    <section>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
        Members
      </h2>
      <div className="overflow-x-auto rounded-lg border border-neutral-800">
        <table className="w-full text-sm">
          <tbody className="divide-y divide-neutral-800">
            {(members ?? []).map((m) => (
              <tr key={m.user_id}>
                <td className="px-4 py-2">{m.email}</td>
                <td className="px-4 py-2 text-neutral-500">{m.name}</td>
                <td className="px-4 py-2">
                  {myRole === 'owner' && m.user_id !== myId ? (
                    <select
                      value={m.role}
                      onChange={(e) =>
                        changeRole.mutate({ user: m.user_id, role: e.target.value })
                      }
                      className="rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-xs"
                    >
                      <option value="owner">owner</option>
                      <option value="admin">admin</option>
                      <option value="member">member</option>
                    </select>
                  ) : (
                    <span className="text-neutral-400">{m.role}</span>
                  )}
                </td>
                <td className="px-4 py-2 text-right">
                  <div className="flex justify-end gap-2">
                    {myRole === 'owner' && m.user_id !== myId && (
                      <button
                        onClick={() => {
                          if (
                            window.confirm(
                              `Transfer ownership to ${m.email}? They become an owner; you step down to admin.`,
                            )
                          )
                            transfer.mutate(m.user_id)
                        }}
                        className="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800"
                      >
                        Transfer ownership
                      </button>
                    )}
                    {canAdmin && m.user_id !== myId && (
                      <button
                        onClick={() => {
                          if (window.confirm(`Remove ${m.email} from the org?`))
                            remove.mutate(m.user_id)
                        }}
                        className="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800"
                      >
                        Remove
                      </button>
                    )}
                    {/* Offered at every role, the owner's included: a sole
                        owner is refused by the server with the two ways out
                        named, and hiding the button would say instead that
                        leaving is something only some members may do. */}
                    {m.user_id === myId && (
                      <button
                        onClick={() => {
                          if (
                            window.confirm(
                              `Leave ${slug}? You lose access to its networks, devices and files until you are invited back.`,
                            )
                          )
                            leave.mutate()
                        }}
                        disabled={leave.isPending}
                        className="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800 disabled:opacity-50"
                      >
                        Leave org
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ErrorNote
        error={
          error ||
          changeRole.error ||
          remove.error ||
          transfer.error ||
          leave.error
        }
      />
      {canAdmin && (
        <form
          className="mt-3 flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            invite.mutate()
          }}
        >
          <input
            type="email"
            required
            placeholder="invite by email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="min-w-64 rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm"
          />
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="rounded-md border border-neutral-700 bg-neutral-950 px-2 py-2 text-sm"
          >
            <option value="member">member</option>
            <option value="admin">admin</option>
          </select>
          <button className="rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-950">
            Send invite
          </button>
          {invite.isSuccess && (
            <span className="self-center text-sm text-emerald-400">
              Invite sent.
            </span>
          )}
          <ErrorNote error={invite.error} />
        </form>
      )}
    </section>
  )
}

// How long a new key lives, offered as durations rather than dates: the
// server takes seconds from now, so minting never depends on this browser's
// clock agreeing with the service's.
const EXPIRIES = [
  { label: 'no expiry', seconds: 0 },
  { label: '30 days', seconds: 30 * 86400 },
  { label: '90 days', seconds: 90 * 86400 },
  { label: '1 year', seconds: 365 * 86400 },
]

function stamp(at: number) {
  return at === 0 ? '—' : new Date(at * 1000).toLocaleString()
}

function ApiKeys({ slug }: { slug: string }) {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [role, setRole] = useState('member')
  const [network, setNetwork] = useState('')
  const [expiresIn, setExpiresIn] = useState(0)
  // The token, held only until the operator navigates away. Nothing can
  // fetch it back, so the panel says so plainly rather than offering a
  // "show again" that would have to lie.
  const [minted, setMinted] = useState<MintedApiKey | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: keys, error } = useQuery({
    queryKey: ['api-keys', slug],
    queryFn: () => get<ApiKeyRow[]>(`/api/orgs/${slug}/api-keys`),
  })
  // A join key names a network, so the form has to offer the org's. Nothing
  // else on this panel needs them.
  const { data: networks } = useQuery({
    queryKey: ['networks', slug],
    queryFn: () => get<NetworkSummary[]>(`/api/orgs/${slug}/networks`),
  })
  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['api-keys', slug] })
  const create = useMutation({
    mutationFn: () =>
      send<MintedApiKey>('POST', `/api/orgs/${slug}/api-keys`, {
        name,
        role,
        // Sent only for a join key: the server refuses a network on an org
        // key, because it would be a bound nothing enforces.
        ...(role === 'join' ? { network } : {}),
        expires_in: expiresIn,
      }),
    onSuccess: (key) => {
      setMinted(key)
      setName('')
      setRole('member')
      setNetwork('')
      setExpiresIn(0)
      refresh()
    },
  })
  // Any of the three fields PATCH takes. The kind is not among them and
  // cannot be: it is settled when the key is minted.
  const update = useMutation({
    mutationFn: (args: {
      id: string
      name?: string
      role?: string
      expires_in?: number
    }) => {
      const { id, ...fields } = args
      return send('PATCH', `/api/orgs/${slug}/api-keys/${id}`, fields)
    },
    onSuccess: refresh,
  })
  const revoke = useMutation({
    mutationFn: (id: string) =>
      send('DELETE', `/api/orgs/${slug}/api-keys/${id}`),
    onSuccess: refresh,
  })
  // Advisory only, and the one thing on this panel that trusts the browser's
  // clock: the server is what actually refuses an expired key, and it does so
  // against its own. A skewed clock here mislabels a row, nothing more.
  const now = Date.now() / 1000

  return (
    <section>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
        API keys
      </h2>
      <p className="mb-3 text-sm text-neutral-400">
        For programs rather than people: send the token as{' '}
        <span className="font-mono">Authorization: Bearer …</span>. An{' '}
        <strong className="font-medium text-neutral-300">org key</strong>{' '}
        reaches this org only, at the role it was given, and can never manage
        members, sign-in configuration or other keys. A{' '}
        <strong className="font-medium text-neutral-300">join key</strong> is
        narrower still: one network, and the only thing it can do is add a
        device to it — which is what makes it safe to bake into a provisioning
        image.
      </p>
      {minted && (
        // role="status" and aria-live: the one sentence a screen-reader user
        // must not miss on this page is the one saying a secret is on screen
        // once. A panel inserted silently says it to nobody.
        <div
          role="status"
          aria-live="polite"
          className="mb-3 rounded-lg border border-emerald-900/60 bg-emerald-950/30 p-4 text-sm"
        >
          <div className="font-medium text-emerald-300">
            {minted.name} created
            {minted.role === 'join' ? ` for ${minted.network}` : ''}. Copy it
            now — this is the only time it is shown.
          </div>
          <code className="mt-2 block break-all rounded bg-neutral-950 p-2 font-mono text-xs">
            {minted.token}
          </code>
          <div className="mt-2 flex items-center gap-2">
            <button
              onClick={() => {
                navigator.clipboard?.writeText(minted.token).then(
                  () => setCopied(true),
                  // Clipboard access can be refused; the token is selectable
                  // either way, so say nothing rather than claim success.
                  () => setCopied(false),
                )
              }}
              className="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-300 hover:bg-neutral-800"
            >
              Copy token
            </button>
            <button
              onClick={() => {
                setMinted(null)
                setCopied(false)
              }}
              className="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800"
            >
              Dismiss
            </button>
            {copied && (
              <span className="text-xs text-emerald-400">Copied.</span>
            )}
          </div>
        </div>
      )}
      {(keys ?? []).length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-neutral-800">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-neutral-500">
              <tr className="border-b border-neutral-800">
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Prefix</th>
                <th className="px-4 py-2 font-medium">Scope</th>
                <th className="px-4 py-2 font-medium">Created by</th>
                <th className="px-4 py-2 font-medium">Last used</th>
                <th className="px-4 py-2 font-medium">Expires</th>
                <th className="px-4 py-2">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800">
              {(keys ?? []).map((k) => (
                <tr key={k.id}>
                  <td className="px-4 py-2">
                    {/* Uncontrolled, keyed on the server's value: a rename
                        that fails remounts the input back to what the server
                        still holds, with no per-row state to keep in step. */}
                    <input
                      key={`${k.id}:${k.name}`}
                      defaultValue={k.name}
                      aria-label={`Name of ${k.name}`}
                      disabled={update.isPending}
                      onBlur={(e) => {
                        const next = e.target.value.trim()
                        if (next !== '' && next !== k.name)
                          update.mutate({ id: k.id, name: next })
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') e.currentTarget.blur()
                        if (e.key === 'Escape') {
                          e.currentTarget.value = k.name
                          e.currentTarget.blur()
                        }
                      }}
                      className="w-40 rounded border border-transparent bg-transparent px-1 py-0.5 hover:border-neutral-700 focus:border-neutral-600 focus:bg-neutral-950 disabled:opacity-50"
                    />
                    {k.expires_at !== 0 && k.expires_at <= now && (
                      <span className="ml-2 text-xs text-amber-400">
                        expired
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-neutral-500">
                    {k.prefix}…
                  </td>
                  <td className="px-4 py-2">
                    {/* A join key's kind is settled at minting — changing it
                        would need a network it was never given, or would hand
                        a deployed secret a reach nobody audited it for. So it
                        reads rather than selects, and names its network. */}
                    {k.role === 'join' ? (
                      <span className="text-xs text-neutral-400">
                        join · <span className="font-mono">{k.network}</span>
                      </span>
                    ) : (
                      <select
                        value={k.role}
                        aria-label={`Role for ${k.name}`}
                        disabled={update.isPending}
                        onChange={(e) =>
                          update.mutate({ id: k.id, role: e.target.value })
                        }
                        className="rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-xs disabled:opacity-50"
                      >
                        <option value="admin">admin</option>
                        <option value="member">member</option>
                      </select>
                    )}
                  </td>
                  {/* Who minted it — the column to read when somebody leaves
                      the org, since a key outlives its minter's membership. */}
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-neutral-500">
                    {k.created_by_email}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-neutral-500">
                    {stamp(k.last_used_at)}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-neutral-500">
                    {/* The server takes a duration from now, so that is what
                        this offers: the current expiry is shown as the label
                        and the choices reset it, they do not extend it. */}
                    <select
                      value=""
                      aria-label={`Change expiry of ${k.name}`}
                      disabled={update.isPending}
                      onChange={(e) =>
                        update.mutate({
                          id: k.id,
                          expires_in: Number(e.target.value),
                        })
                      }
                      className="rounded border border-transparent bg-transparent px-1 py-0.5 text-xs hover:border-neutral-700 focus:border-neutral-600 focus:bg-neutral-950 disabled:opacity-50"
                    >
                      <option value="">{stamp(k.expires_at)}</option>
                      {EXPIRIES.map((choice) => (
                        <option key={choice.seconds} value={choice.seconds}>
                          set to {choice.label}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-2 text-right">
                    <button
                      aria-label={`Revoke ${k.name}`}
                      // Disabled while a revoke is in flight: a second DELETE
                      // for the same row answers 404, which would render as a
                      // failure of an operation that had in fact succeeded.
                      disabled={revoke.isPending}
                      onClick={() => {
                        if (
                          window.confirm(
                            `Revoke ${k.name}? Anything using this token stops working at once.`,
                          )
                        )
                          revoke.mutate(k.id)
                      }}
                      className="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800 disabled:opacity-50"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ErrorNote error={error || update.error || revoke.error} />
      <form
        className="mt-3 flex flex-wrap gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          create.mutate()
        }}
      >
        <input
          required
          aria-label="Name for the new API key"
          placeholder="what is this key for?"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="min-w-64 rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm"
        />
        <select
          value={role}
          aria-label="What the new API key may do"
          onChange={(e) => setRole(e.target.value)}
          className="rounded-md border border-neutral-700 bg-neutral-950 px-2 py-2 text-sm"
        >
          <option value="member">org key · member</option>
          <option value="admin">org key · admin</option>
          {/* A join key is scoped to a network, so there has to be one. The
              option stays visible and disabled rather than vanishing: an
              absent choice reads as a missing feature. */}
          <option value="join" disabled={(networks ?? []).length === 0}>
            join key · one network
            {(networks ?? []).length === 0 ? ' (no networks yet)' : ''}
          </option>
        </select>
        {role === 'join' && (
          <select
            required
            value={network}
            aria-label="Network the join key may add devices to"
            onChange={(e) => setNetwork(e.target.value)}
            className="rounded-md border border-neutral-700 bg-neutral-950 px-2 py-2 text-sm"
          >
            <option value="">choose a network…</option>
            {(networks ?? []).map((n) => (
              <option key={n.name} value={n.name}>
                {n.name}
              </option>
            ))}
          </select>
        )}
        <select
          value={expiresIn}
          aria-label="How long the new API key lives"
          onChange={(e) => setExpiresIn(Number(e.target.value))}
          className="rounded-md border border-neutral-700 bg-neutral-950 px-2 py-2 text-sm"
        >
          {EXPIRIES.map((choice) => (
            <option key={choice.seconds} value={choice.seconds}>
              {choice.label}
            </option>
          ))}
        </select>
        <button
          disabled={create.isPending || (role === 'join' && network === '')}
          className="rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-950 disabled:opacity-50"
        >
          Create key
        </button>
        <ErrorNote error={create.error} />
      </form>
    </section>
  )
}

function Oidc({ slug }: { slug: string }) {
  const queryClient = useQueryClient()
  const [issuer, setIssuer] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const { data: config } = useQuery({
    queryKey: ['oidc', slug],
    queryFn: () => get<OidcConfig | null>(`/api/orgs/${slug}/oidc`),
  })
  const save = useMutation({
    mutationFn: () =>
      send('PUT', `/api/orgs/${slug}/oidc`, {
        issuer,
        client_id: clientId,
        client_secret: clientSecret,
      }),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['oidc', slug] }),
  })
  const remove = useMutation({
    mutationFn: () => send('DELETE', `/api/orgs/${slug}/oidc`),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['oidc', slug] }),
  })

  return (
    <section>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
        Single sign-on (custom OIDC)
      </h2>
      {config && (
        <div className="mb-3 rounded-lg border border-neutral-800 p-4 text-sm">
          <div>
            Issuer: <span className="font-mono">{config.issuer}</span>
          </div>
          <div className="text-neutral-500">
            client_id {config.client_id} · discovered{' '}
            {new Date(config.discovered_at * 1000).toLocaleString()}
          </div>
          <div className="mt-2 text-neutral-400">
            Members sign in at{' '}
            <span className="font-mono">/auth/oidc/{slug}</span>. Identities
            from this issuer never auto-link to existing accounts.
          </div>
          <button
            onClick={() => {
              if (
                window.confirm(
                  'Remove the OIDC provider? Sign-ins and linked identities from this issuer stop working.',
                )
              )
                remove.mutate()
            }}
            className="mt-3 rounded border border-red-900 px-2 py-1 text-xs text-red-400 hover:bg-red-950"
          >
            Remove provider
          </button>
        </div>
      )}
      <form
        className="grid gap-3 sm:grid-cols-3"
        onSubmit={(e) => {
          e.preventDefault()
          save.mutate()
        }}
      >
        <input
          placeholder="issuer URL"
          value={issuer}
          onChange={(e) => setIssuer(e.target.value)}
          required
          className="rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm"
        />
        <input
          placeholder="client_id"
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          required
          className="rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm"
        />
        <input
          placeholder="client_secret"
          type="password"
          value={clientSecret}
          onChange={(e) => setClientSecret(e.target.value)}
          required
          className="rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm"
        />
        <div className="sm:col-span-3">
          <button
            disabled={save.isPending}
            className="rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-950 disabled:opacity-50"
          >
            {save.isPending ? 'Running discovery…' : 'Save (runs discovery)'}
          </button>
          <ErrorNote error={save.error} />
        </div>
      </form>
    </section>
  )
}

function Audit({ slug }: { slug: string }) {
  const { data: entries } = useQuery({
    queryKey: ['audit', slug],
    queryFn: () => get<AuditRow[]>(`/api/orgs/${slug}/audit`),
  })
  return (
    <section>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
        Audit log
      </h2>
      <div className="overflow-x-auto rounded-lg border border-neutral-800">
        <table className="w-full text-sm">
          <tbody className="divide-y divide-neutral-800">
            {(entries ?? []).map((e) => (
              <tr key={e.id}>
                <td className="whitespace-nowrap px-4 py-2 text-neutral-500">
                  {new Date(e.at * 1000).toLocaleString()}
                </td>
                <td className="px-4 py-2 font-mono text-xs">{e.action}</td>
                <td className="px-4 py-2 text-neutral-500">{e.actor}</td>
                <td className="max-w-md truncate px-4 py-2 font-mono text-xs text-neutral-500">
                  {e.detail}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function DeleteOrg({ slug }: { slug: string }) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [confirm, setConfirm] = useState('')
  const remove = useMutation({
    mutationFn: () => send('DELETE', `/api/orgs/${slug}`, { confirm }),
    onSuccess: async () => {
      // Drop every org-scoped query with the org rather than leaving it
      // stale: Back within the stale window would otherwise remount a
      // ghost page whose actions can only 404. 'me' is refetched so the
      // org picker no longer offers what is gone.
      queryClient.removeQueries({
        predicate: (q) => Array.isArray(q.queryKey) && q.queryKey[1] === slug,
      })
      await queryClient.invalidateQueries({ queryKey: ['me'] })
      navigate('/')
    },
  })

  return (
    <section className="rounded-lg border border-red-900/60 p-4">
      <h2 className="mb-2 text-sm font-medium uppercase tracking-wide text-red-400">
        Delete organization
      </h2>
      <p className="text-sm text-neutral-400">
        Deletes {slug} with everything it owns: networks, devices and their
        keys, invites, members and the org's sign-in configuration. Members'
        records leave DNS on the next publish. The audit trail is kept. This
        cannot be undone.
      </p>
      <form
        className="mt-3 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          remove.mutate()
        }}
      >
        <input
          placeholder={`type ${slug} to confirm`}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          className="rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm"
        />
        <button
          disabled={confirm !== slug || remove.isPending}
          className="rounded-md bg-red-900 px-3 py-2 text-sm font-medium text-red-50 hover:bg-red-800 disabled:opacity-50"
        >
          Delete forever
        </button>
      </form>
      <ErrorNote error={remove.error} />
    </section>
  )
}

function LinkedIdentities() {
  const linked = new URLSearchParams(window.location.search).get('linked')
  const { data: methods } = useAuthMethods()
  // Only the providers this deployment configured can be linked; the rest
  // would send the user to a "provider not configured" page.
  const linkable = [
    { key: 'google', label: 'Link Google', on: methods?.google },
    { key: 'github', label: 'Link GitHub', on: methods?.github },
  ].filter((provider) => provider.on)
  if (linkable.length === 0) return null

  return (
    <section>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
        Linked sign-in methods
      </h2>
      {linked && (
        <p className="mb-2 text-sm text-emerald-400">
          {linked} identity linked to this account.
        </p>
      )}
      <p className="text-sm text-neutral-400">
        Link another sign-in method to this account:
      </p>
      <div className="mt-2 flex gap-2">
        {linkable.map((provider) => (
          <a
            key={provider.key}
            href={`/auth/start/${provider.key}?link=1`}
            className="rounded border border-neutral-700 px-3 py-1.5 text-sm hover:bg-neutral-800"
          >
            {provider.label}
          </a>
        ))}
      </div>
    </section>
  )
}
