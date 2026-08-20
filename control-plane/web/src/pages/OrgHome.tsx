import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router'
import { get, send, type NetworkSummary } from '../lib/api'
import { useTitle } from '../lib/title'
import { isDnsLabel } from '../lib/zbase32'
import { ErrorNote, useMe } from './Shell'

export function OrgHome({ pick = false }: { pick?: boolean }) {
  const { slug } = useParams()
  const { data: me } = useMe()
  if (pick || !slug) {
    return <PickOrCreateOrg />
  }
  const role = me?.orgs.find((o) => o.slug === slug)?.role
  return <Networks slug={slug} canAdmin={role === 'owner' || role === 'admin'} />
}

function PickOrCreateOrg() {
  useTitle('Organizations')
  const { data: me } = useMe()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [slug, setSlug] = useState('')
  const [name, setName] = useState('')
  const create = useMutation({
    mutationFn: () => send('POST', '/api/orgs', { slug, name }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['me'] })
      navigate(`/o/${slug}`)
    },
  })

  return (
    <div className="mx-auto max-w-md space-y-8">
      {me && me.orgs.length > 0 && (
        <div>
          <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
            Your organizations
          </h2>
          <ul className="divide-y divide-neutral-800 rounded-lg border border-neutral-800">
            {me.orgs.map((o) => (
              <li key={o.id}>
                <Link
                  to={`/o/${o.slug}`}
                  className="flex items-center justify-between px-4 py-3 hover:bg-neutral-900"
                >
                  <span>{o.name}</span>
                  <span className="text-sm text-neutral-500">
                    {o.slug} · {o.role}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
          Create an organization
        </h2>
        <form
          className="space-y-3 rounded-lg border border-neutral-800 p-4"
          onSubmit={(e) => {
            e.preventDefault()
            create.mutate()
          }}
        >
          <input
            placeholder="Name (display)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            className="w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm"
          />
          <div>
            <input
              placeholder="slug (becomes a DNS label)"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              required
              className="w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm"
            />
            {slug && !isDnsLabel(slug) && (
              <p className="mt-1 text-xs text-amber-400">
                Must be [a-z0-9-], 1–63 chars, no leading/trailing hyphen. This
                names your zones and cannot change later.
              </p>
            )}
          </div>
          <button
            disabled={!isDnsLabel(slug) || create.isPending}
            className="rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-950 hover:bg-neutral-200 disabled:opacity-50"
          >
            Create
          </button>
          <ErrorNote error={create.error} />
        </form>
      </div>
    </div>
  )
}

function Networks({ slug, canAdmin }: { slug: string; canAdmin: boolean }) {
  useTitle(`${slug} networks`)
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const { data: networks, error } = useQuery({
    queryKey: ['networks', slug],
    queryFn: () => get<NetworkSummary[]>(`/api/orgs/${slug}/networks`),
  })
  const create = useMutation({
    mutationFn: () => send('POST', `/api/orgs/${slug}/networks`, { name }),
    onSuccess: () => {
      setName('')
      queryClient.invalidateQueries({ queryKey: ['networks', slug] })
    },
  })
  const remove = useMutation({
    mutationFn: (network: string) =>
      send('DELETE', `/api/orgs/${slug}/networks/${network}`, {
        confirm: network,
      }),
    onSuccess: (network) => {
      queryClient.invalidateQueries({ queryKey: ['networks', slug] })
      // The detail and browse pages keyed by this network go with it, so
      // Back cannot remount them from cache.
      queryClient.removeQueries({
        predicate: (q) =>
          Array.isArray(q.queryKey) &&
          q.queryKey[1] === slug &&
          q.queryKey[2] === network,
      })
    },
  })
  const askRemove = (network: string) => {
    const answer = window.prompt(
      `Delete the network ${network}? Its members' records leave DNS on the next publish; devices are unassigned, not deleted. Type the network name to confirm.`,
    )
    if (answer === network) remove.mutate(network)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-white">Networks</h1>
        {canAdmin && (
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              create.mutate()
            }}
          >
            <input
              placeholder="new network name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="rounded-md border border-neutral-700 bg-neutral-950 px-3 py-1.5 font-mono text-sm"
            />
            <button
              disabled={!isDnsLabel(name) || create.isPending}
              className="rounded-md bg-white px-3 py-1.5 text-sm font-medium text-neutral-950 disabled:opacity-50"
            >
              Create
            </button>
          </form>
        )}
      </div>
      <ErrorNote error={error || create.error || remove.error} />
      <p className="text-sm text-neutral-400">
        Each network is one synchronicity cluster: every device in it fully
        trusts the others.
      </p>
      <ul className="divide-y divide-neutral-800 rounded-lg border border-neutral-800">
        {(networks ?? []).map((n) => (
          <li key={n.name} className="flex items-center">
            <Link
              to={`/o/${slug}/networks/${n.name}`}
              className="flex flex-1 items-center justify-between px-4 py-3 hover:bg-neutral-900"
            >
              <span className="font-mono">{n.name}</span>
              <span className="text-sm text-neutral-500">
                {n.device_count} device{n.device_count === 1 ? '' : 's'}
              </span>
            </Link>
            {canAdmin && (
              <button
                onClick={() => askRemove(n.name)}
                disabled={remove.isPending}
                className="mr-4 rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800 disabled:opacity-50"
              >
                Delete
              </button>
            )}
          </li>
        ))}
        {networks?.length === 0 && (
          <li className="px-4 py-6 text-sm text-neutral-500">
            No networks yet{canAdmin ? ' — create one above.' : '.'}
          </li>
        )}
      </ul>
    </div>
  )
}
