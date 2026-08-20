import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router'
import {
  get,
  send,
  type AuditRow,
  type MemberRow,
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
