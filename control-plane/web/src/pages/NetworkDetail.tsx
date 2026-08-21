import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router'
import {
  ApiError,
  get,
  send,
  type Delegations as DelegationsPayload,
  type DeviceKeyRow,
  type DeviceRow,
  type NetworkDetail as Detail,
  type NodeReplication,
  type ReplicaSpace,
  type Replication as ReplicationPayload,
} from '../lib/api'
import { agoNs, bytes, duration } from '../lib/format'
import { useTitle } from '../lib/title'
import { isDeviceKey, isDeviceLabel } from '../lib/zbase32'
import { ErrorNote, useMe } from './Shell'

export function NetworkDetail() {
  const { slug = '', name = '' } = useParams()
  useTitle(name)
  const queryClient = useQueryClient()
  const { data: me } = useMe()
  const role = me?.orgs.find((o) => o.slug === slug)?.role
  const isAdmin = role === 'owner' || role === 'admin'
  const { data, error } = useQuery({
    queryKey: ['network', slug, name],
    queryFn: () => get<Detail>(`/api/orgs/${slug}/networks/${name}`),
  })
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['network', slug, name] })
    queryClient.invalidateQueries({ queryKey: ['devices', slug] })
  }

  if (error) return <ErrorNote error={error} />
  if (!data) return <div className="text-neutral-400">Loading…</div>

  // Group key rows into devices.
  const devices = new Map<string, DeviceKeyRow[]>()
  for (const row of data.devices) {
    const rows = devices.get(row.device_id) ?? []
    rows.push(row)
    devices.set(row.device_id, rows)
  }

  return (
    <div className="space-y-8">
      <nav className="text-sm">
        <Link
          to={`/o/${slug}/networks/${name}/files`}
          className="text-teal-300 hover:underline"
        >
          Files →
        </Link>
      </nav>
      <ZoneStatus data={data} />
      <DeviceTable
        slug={slug}
        network={name}
        devices={devices}
        isAdmin={isAdmin}
        onChange={refresh}
      />
      <AddDevice slug={slug} network={name} onChange={refresh} />
      <DelegatedTrust slug={slug} network={name} />
      <ReplicationPanel slug={slug} network={name} />
      <ConnectPanel domain={data.domain} />
    </div>
  )
}

function ZoneStatus({ data }: { data: Detail }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-4">
      <div className="flex flex-wrap items-baseline gap-x-8 gap-y-2">
        <div>
          <div className="text-xs uppercase tracking-wide text-neutral-500">
            Membership domain
          </div>
          <div className="font-mono text-lg text-white">{data.domain}</div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-neutral-500">
            SOA serial
          </div>
          <div className="font-mono">{data.soa_serial}</div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-neutral-500">
            Last published
          </div>
          <div>{timeAgo(data.last_published_at)}</div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-neutral-500">
            Signatures valid until
          </div>
          <div>{new Date(data.sig_expires_at * 1000).toLocaleString()}</div>
        </div>
      </div>
    </div>
  )
}

/// Who the cluster admits on a delegation, read from whichever daemon is
/// attached.
///
/// Not managed here, and deliberately: a delegation is a record its issuer
/// publishes under its own key, so only that node can sign one. The control
/// plane can report it and nothing more, which is why this panel has no
/// buttons.
function DelegatedTrust({ slug, network }: { slug: string; network: string }) {
  const { data, error, isLoading } = useQuery({
    queryKey: ['delegations', slug, network],
    queryFn: () =>
      get<DelegationsPayload>(`/api/orgs/${slug}/networks/${network}/delegations`),
    retry: false,
  })

  // A network with no daemon attached, or with the tunnel switched off, is an
  // ordinary state rather than a fault: say so quietly and show nothing else.
  const unavailable =
    error instanceof ApiError &&
    (error.code === 'no-device-attached' || error.code === 'browse-disabled')

  return (
    <div>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
        Delegated trust
      </h2>
      {isLoading && <div className="text-sm text-neutral-500">Loading…</div>}
      {unavailable && (
        <div className="text-sm text-neutral-500">
          No attached daemon to ask.
        </div>
      )}
      {error && !unavailable && <ErrorNote error={error} />}
      {data && (
        <>
          <div className="overflow-x-auto rounded-lg border border-neutral-800">
            <table className="w-full text-sm">
              <thead className="bg-neutral-900 text-left text-neutral-400">
                <tr>
                  <th className="px-4 py-2 font-medium">key</th>
                  <th className="px-4 py-2 font-medium">spaces</th>
                  <th className="px-4 py-2 font-medium">issued by</th>
                  <th className="px-4 py-2 font-medium">expires</th>
                  <th className="px-4 py-2 font-medium">state</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-800">
                {data.delegations.map((d) => (
                  <tr key={`${d.issuer}/${d.key}`} className={d.live ? '' : 'opacity-60'}>
                    <td className="px-4 py-2 font-mono text-xs" title={d.key}>
                      {d.key.slice(0, 12)}…
                    </td>
                    <td className="px-4 py-2">{d.spaces.join(', ')}</td>
                    <td className="px-4 py-2 font-mono text-xs">{d.issuer}</td>
                    <td className="px-4 py-2 text-neutral-400">
                      {d.not_after === 0 ? '—' : remaining(d.not_after)}
                    </td>
                    <td className="px-4 py-2">
                      {d.live ? (
                        <span className="text-teal-300">live</span>
                      ) : (
                        // Shown rather than filtered away: "never delegated"
                        // and "delegated, and the issuer is gone" are
                        // different states calling for different actions.
                        <span className="text-neutral-500">lapsed</span>
                      )}
                    </td>
                  </tr>
                ))}
                {data.delegations.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-neutral-500">
                      No keys have been delegated into this network.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-xs text-neutral-500">
            Answered by {data.device}. Delegations reach every member, so any
            attached node speaks for the whole network — and only the issuing
            node can add or revoke one.
          </p>
        </>
      )}
    </div>
  )
}

/// What each attached node replicates, and how far behind it is
/// (`docs/REPLICATION.md` §8).
///
/// Every attached node is asked and every answer is labelled with who gave it.
/// Replication is a per-node decision — one node replicates `media`, its
/// neighbour does not, and both are correct — so a fleet-wide number with no
/// node against it would be a number about nothing.
///
/// Like the panel above, this has no buttons. What a node replicates is set
/// with `synch space set` on that node; the control plane can report it and
/// nothing more.
function ReplicationPanel({
  slug,
  network,
}: {
  slug: string
  network: string
}) {
  const { data, error, isLoading } = useQuery({
    queryKey: ['replication', slug, network],
    queryFn: () =>
      get<ReplicationPayload>(
        `/api/orgs/${slug}/networks/${network}/replication`,
      ),
    retry: false,
    // A backlog moves while someone is watching it, and a stale count is the
    // one thing this panel must not show: an operator reading "12 unreachable"
    // needs to know it is 12 now.
    refetchInterval: 15_000,
  })

  const unavailable =
    error instanceof ApiError &&
    (error.code === 'no-device-attached' || error.code === 'browse-disabled')

  const replicating = data?.nodes.filter((n) => n.spaces.length > 0) ?? []

  return (
    <div>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
        Replication
      </h2>
      {isLoading && <div className="text-sm text-neutral-500">Loading…</div>}
      {unavailable && (
        <div className="text-sm text-neutral-500">
          No attached daemon to ask.
        </div>
      )}
      {error && !unavailable && <ErrorNote error={error} />}
      {data && (
        <>
          <SpaceCoverage spaces={data.spaces} />
          {replicating.length === 0 && data.spaces.length === 0 && (
            <div className="rounded-lg border border-neutral-800 px-4 py-6 text-sm text-neutral-500">
              No attached node replicates a space in this network. Turn it on
              with <code className="text-neutral-400">synch space set</code>{' '}
              <code className="text-neutral-400">--replicate tree</code> on a
              node that should hold every version.
            </div>
          )}
          {replicating.length > 0 && (
            <div className="overflow-x-auto rounded-lg border border-neutral-800">
              <table className="w-full text-sm">
                <thead className="bg-neutral-900 text-left text-neutral-400">
                  <tr>
                    <th className="px-4 py-2 font-medium">node</th>
                    <th className="px-4 py-2 font-medium">space</th>
                    <th className="px-4 py-2 font-medium">policy</th>
                    <th className="px-4 py-2 font-medium">held</th>
                    <th className="px-4 py-2 font-medium">wanted</th>
                    <th className="px-4 py-2 font-medium">unreachable</th>
                    <th className="px-4 py-2 font-medium">releasing</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-800">
                  {replicating.flatMap((node) =>
                    node.spaces.map((space) => (
                      <SpaceRow
                        key={`${node.origin}/${space.space}`}
                        node={node}
                        space={space}
                      />
                    )),
                  )}
                </tbody>
              </table>
            </div>
          )}
          <Unanswered nodes={data.nodes} />
        </>
      )}
    </div>
  )
}

/// How many nodes hold each space — the one fact the per-node table cannot
/// show.
///
/// A space one node replicates keeps every superseded version in exactly one
/// place. Read node by node that looks the same as a space three nodes hold,
/// which is why it is called out here and not left to be counted by eye.
function SpaceCoverage({
  spaces,
}: {
  spaces: { space: string; replicas: number }[]
}) {
  if (spaces.length === 0) return null
  return (
    <div className="mb-3 flex flex-wrap gap-2">
      {spaces.map(({ space, replicas }) => (
        <span
          key={space}
          className={`rounded-md border px-3 py-1 text-sm ${
            replicas === 1
              ? 'border-amber-900/60 bg-amber-950/30 text-amber-200'
              : 'border-neutral-800 bg-neutral-900/50 text-neutral-300'
          }`}
          title={
            replicas === 1
              ? 'one attached node replicates this space, so its superseded versions exist in one place'
              : `${replicas} attached nodes replicate this space`
          }
        >
          <span className="font-mono">{space}</span>{' '}
          <span className="text-neutral-500">
            {replicas === 1 ? '1 replica' : `${replicas} replicas`}
          </span>
        </span>
      ))}
    </div>
  )
}

function SpaceRow({
  node,
  space,
}: {
  node: NodeReplication
  space: ReplicaSpace
}) {
  // `wanted` carries `unreachable` inside it. The backlog is what is left
  // after taking those out — objects still worth waiting for — and the two are
  // shown apart because a queue that is draining and a queue that is dead need
  // different things done about them.
  const backlog = Math.max(0, space.wanted - space.unreachable)
  const backlogBytes = Math.max(0, space.wanted_bytes - space.unreachable_bytes)
  return (
    <tr>
      <td className="px-4 py-2">
        <div>{node.device}</div>
        <div className="font-mono text-xs text-neutral-500">{node.origin}</div>
      </td>
      <td className="px-4 py-2 font-mono">{space.space}</td>
      <td className="px-4 py-2">
        <div>{space.policy}</div>
        <div className="text-xs text-neutral-500">
          {space.policy === 'tree'
            ? `grace ${duration(space.grace_secs)}`
            : 'releases nothing'}
        </div>
      </td>
      <td className="px-4 py-2">
        <div>{space.held.toLocaleString()}</div>
        <div className="text-xs text-neutral-500">
          {bytes(space.held_bytes)}
          {space.budget > 0 && ` of ${bytes(space.budget)}`}
        </div>
      </td>
      <td className="px-4 py-2">
        <div>{backlog.toLocaleString()}</div>
        <div className="text-xs text-neutral-500">
          {backlog > 0
            ? `${bytes(backlogBytes)}, oldest ${agoNs(space.oldest_want)}`
            : '—'}
        </div>
      </td>
      <td className="px-4 py-2">
        {space.unreachable > 0 ? (
          <>
            <div
              className="text-amber-300"
              title="no provider has answered for these — they may already be gone"
            >
              {space.unreachable.toLocaleString()}
            </div>
            <div className="text-xs text-neutral-500">
              {bytes(space.unreachable_bytes)}
            </div>
          </>
        ) : (
          <span className="text-neutral-600">0</span>
        )}
      </td>
      <td className="px-4 py-2">
        {!space.view_complete ? (
          // Ahead of the count, because it explains it: a paused view is why
          // nothing is leaving, and reading "0 releasing" without it says the
          // replica is idle when it is stuck.
          <div className="text-amber-300" title={space.view_reason}>
            paused
          </div>
        ) : (
          <div>{space.releasing.toLocaleString()}</div>
        )}
        <div className="text-xs text-neutral-500">
          {!space.view_complete
            ? space.view_reason
            : space.releasing > 0
              ? `${bytes(space.releasing_bytes)}, soonest ${remaining(space.next_release)}`
              : space.held_back > 0
                ? `${space.held_back.toLocaleString()} held back: too few peers`
                : '—'}
        </div>
      </td>
    </tr>
  )
}

/// The nodes that were asked and did not answer.
///
/// Listed rather than dropped: a daemon that could not say what it replicates
/// leaves a hole in every count above, and a panel that quietly rendered the
/// rest would be reporting a smaller fleet as though it were the whole one.
function Unanswered({ nodes }: { nodes: NodeReplication[] }) {
  const silent = nodes.filter((node) => node.error !== '')
  if (silent.length === 0) return null
  return (
    <ul className="mt-2 space-y-1 text-xs text-neutral-500">
      {silent.map((node) => (
        <li key={node.origin}>
          <span className="text-neutral-400">{node.device}</span> did not
          answer: {node.message || node.error}
        </li>
      ))}
    </ul>
  )
}

/// How long is left, in the coarsest unit that is still true.
///
/// `0` is the daemon's "never", not the epoch: without the guard it would
/// render as "expired", which is the opposite of what an absent end date means.
function remaining(at: number): string {
  if (!Number.isFinite(at) || at <= 0) return '—'
  const secs = Math.floor(at / 1e9 - Date.now() / 1000)
  if (secs <= 0) return 'expired'
  const days = Math.floor(secs / 86400)
  if (days > 0) return `${days}d`
  const hours = Math.floor(secs / 3600)
  if (hours > 0) return `${hours}h`
  return `${Math.max(1, Math.floor(secs / 60))}m`
}

function DeviceTable({
  slug,
  network,
  devices,
  isAdmin,
  onChange,
}: {
  slug: string
  network: string
  devices: Map<string, DeviceKeyRow[]>
  isAdmin: boolean
  onChange: () => void
}) {
  return (
    <div>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
        Devices in this network
      </h2>
      <div className="overflow-x-auto rounded-lg border border-neutral-800">
        <table className="w-full text-sm">
          <thead className="bg-neutral-900 text-left text-neutral-400">
            <tr>
              <th className="px-4 py-2 font-medium">label</th>
              <th className="px-4 py-2 font-medium">keys</th>
              <th className="px-4 py-2 font-medium">hints</th>
              <th className="px-4 py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-800">
            {[...devices.entries()].map(([deviceId, rows]) => (
              <DeviceRowView
                key={deviceId}
                slug={slug}
                network={network}
                deviceId={deviceId}
                rows={rows}
                isAdmin={isAdmin}
                onChange={onChange}
              />
            ))}
            {devices.size === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-neutral-500">
                  No devices yet — add one below, then assign it here.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function DeviceRowView({
  slug,
  network,
  deviceId,
  rows,
  isAdmin,
  onChange,
}: {
  slug: string
  network: string
  deviceId: string
  rows: DeviceKeyRow[]
  isAdmin: boolean
  onChange: () => void
}) {
  const [rotating, setRotating] = useState(false)
  const [newKey, setNewKey] = useState('')
  const label = rows[0].label
  const rotationOpen = rows.filter((r) => r.state !== '').length > 1
  const retiring = rows.find((r) => r.state === 'retiring')

  const act = useMutation({
    mutationFn: (path: string) => send('POST', path),
    onSuccess: onChange,
  })
  const rotate = useMutation({
    mutationFn: () =>
      send('POST', `/api/orgs/${slug}/devices/${deviceId}/keys`, { nk: newKey }),
    onSuccess: () => {
      setRotating(false)
      setNewKey('')
      onChange()
    },
  })
  const unassign = useMutation({
    mutationFn: () =>
      send(
        'DELETE',
        `/api/orgs/${slug}/networks/${network}/devices/${deviceId}`,
      ),
    onSuccess: onChange,
  })

  return (
    <tr className="align-top">
      <td className="px-4 py-3 font-mono text-white">{label}</td>
      <td className="px-4 py-3">
        <div className="space-y-1">
          {rows
            .filter((r) => r.state !== '')
            .map((r) => (
              <div key={r.key_id} className="flex items-center gap-2">
                <StateBadge state={r.state} />
                <span
                  className="max-w-[16rem] truncate font-mono text-xs text-neutral-400"
                  title={r.nk}
                >
                  {r.nk}
                </span>
                {r.state === 'retiring' && (
                  <button
                    onClick={() => {
                      if (
                        window.confirm(
                          'Retire the old key? Do this only after the device has re-keyed and peers have picked up the new binding (synch key ls).',
                        )
                      )
                        act.mutate(
                          `/api/orgs/${slug}/devices/${deviceId}/keys/${r.key_id}/retire`,
                        )
                    }}
                    className="rounded border border-neutral-700 px-1.5 py-0.5 text-xs hover:bg-neutral-800"
                  >
                    Retire
                  </button>
                )}
                {isAdmin && (
                  <button
                    onClick={() => {
                      const answer = window.prompt(
                        `Revoke this key immediately? It leaves DNS on the next publish, but peers may keep trusting it for up to TTL + grace (≈15 minutes) — DNS is not a kill switch. Type the device label (${label}) to confirm.`,
                      )
                      if (answer === label)
                        act.mutate(
                          `/api/orgs/${slug}/devices/${deviceId}/keys/${r.key_id}/revoke`,
                        )
                    }}
                    className="rounded border border-red-900 px-1.5 py-0.5 text-xs text-red-400 hover:bg-red-950"
                  >
                    Revoke
                  </button>
                )}
              </div>
            ))}
          {rotationOpen && (
            <p className="text-xs text-amber-400">
              Rotation window open — after the device has re-keyed and synced,
              retire the old key.
            </p>
          )}
          {!rotationOpen && !rotating && (
            <button
              onClick={() => setRotating(true)}
              className="text-xs text-neutral-500 hover:text-white"
            >
              + add new key (rotate)
            </button>
          )}
          {rotating && (
            <form
              className="flex gap-2 pt-1"
              onSubmit={(e) => {
                e.preventDefault()
                rotate.mutate()
              }}
            >
              <input
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
                placeholder="new key from `synch key rotate`"
                className="w-64 rounded border border-neutral-700 bg-neutral-950 px-2 py-1 font-mono text-xs"
              />
              <button
                disabled={!isDeviceKey(newKey) || rotate.isPending}
                className="rounded bg-white px-2 py-1 text-xs font-medium text-neutral-950 disabled:opacity-50"
              >
                Open rotation
              </button>
            </form>
          )}
          <ErrorNote error={act.error || rotate.error} />
          {retiring && null}
        </div>
      </td>
      <td className="px-4 py-3 text-xs text-neutral-500">
        {rows[0].relay && <div>relay={rows[0].relay}</div>}
        {rows[0].addr && <div>addr={rows[0].addr}</div>}
      </td>
      <td className="px-4 py-3 text-right">
        <button
          onClick={() => {
            if (window.confirm(`Remove ${label} from this network?`))
              unassign.mutate()
          }}
          className="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800"
        >
          Unassign
        </button>
      </td>
    </tr>
  )
}

function StateBadge({ state }: { state: string }) {
  const styles =
    state === 'active'
      ? 'bg-emerald-950 text-emerald-300 border-emerald-900'
      : 'bg-amber-950 text-amber-300 border-amber-900'
  return (
    <span className={`rounded border px-1.5 py-0.5 text-xs ${styles}`}>
      {state}
    </span>
  )
}

function AddDevice({
  slug,
  network,
  onChange,
}: {
  slug: string
  network: string
  onChange: () => void
}) {
  const [label, setLabel] = useState('')
  const [nk, setNk] = useState('')
  const [relay, setRelay] = useState('')
  const [addr, setAddr] = useState('')
  const { data: existing } = useQuery({
    queryKey: ['devices', slug],
    queryFn: () => get<DeviceRow[]>(`/api/orgs/${slug}/devices`),
  })
  const assign = useMutation({
    mutationFn: (deviceId: string) =>
      send('PUT', `/api/orgs/${slug}/networks/${network}/devices/${deviceId}`),
    onSuccess: onChange,
  })
  const create = useMutation({
    mutationFn: async () => {
      const created = await send<{ result: { device_id: string } }>(
        'POST',
        `/api/orgs/${slug}/devices`,
        { label, nk, relay: relay || undefined, addr: addr || undefined },
      )
      await send(
        'PUT',
        `/api/orgs/${slug}/networks/${network}/devices/${created.result.device_id}`,
      )
    },
    onSuccess: () => {
      setLabel('')
      setNk('')
      setRelay('')
      setAddr('')
      onChange()
    },
  })

  const assignable = (existing ?? []).filter(
    (d) => d.state === 'active' && !d.networks.split(',').includes(network),
  )
  const uniqueAssignable = [...new Map(assignable.map((d) => [d.device_id, d])).values()]

  return (
    <div className="rounded-lg border border-neutral-800 p-4">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-neutral-400">
        Add a device
      </h2>
      <form
        className="grid gap-3 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault()
          create.mutate()
        }}
      >
        <div>
          <input
            placeholder="label (e.g. nas)"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className="w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm"
          />
          {label && !isDeviceLabel(label) && (
            <p className="mt-1 text-xs text-amber-400">[a-z0-9-], 1–63 chars</p>
          )}
        </div>
        <div>
          <input
            placeholder="device key from `synch id`"
            value={nk}
            onChange={(e) => setNk(e.target.value.trim())}
            className="w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm"
          />
          {nk && !isDeviceKey(nk) && (
            <p className="mt-1 text-xs text-amber-400">
              Expected 52 z-base-32 characters
            </p>
          )}
        </div>
        <input
          placeholder="relay hint (optional URL)"
          value={relay}
          onChange={(e) => setRelay(e.target.value)}
          className="w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm"
        />
        <input
          placeholder="addr hint (optional host:port)"
          value={addr}
          onChange={(e) => setAddr(e.target.value)}
          className="w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-sm"
        />
        <div className="sm:col-span-2">
          <button
            disabled={
              !isDeviceLabel(label) || !isDeviceKey(nk) || create.isPending
            }
            className="rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-950 disabled:opacity-50"
          >
            Add & assign to {network}
          </button>
          <ErrorNote error={create.error} />
        </div>
      </form>
      {uniqueAssignable.length > 0 && (
        <div className="mt-4 border-t border-neutral-800 pt-3 text-sm">
          <span className="text-neutral-400">Or assign an existing device: </span>
          {uniqueAssignable.map((d) => (
            <button
              key={d.device_id}
              onClick={() => assign.mutate(d.device_id)}
              className="mr-2 rounded border border-neutral-700 px-2 py-0.5 font-mono text-xs hover:bg-neutral-800"
            >
              {d.label}
            </button>
          ))}
          <ErrorNote error={assign.error} />
        </div>
      )}
    </div>
  )
}

function ConnectPanel({ domain }: { domain: string }) {
  const snippet = [
    `# New device — create its identity and join this network in one step:`,
    `synch init --domain ${domain}`,
    `synch daemon run &`,
    `synch id                                   # print its key, add it above`,
    ``,
    `# Existing device — already initialized elsewhere, just join this domain:`,
    `synch domain set ${domain}`,
  ].join('\n')
  return (
    <div className="rounded-lg border border-neutral-800 p-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-sm font-medium uppercase tracking-wide text-neutral-400">
          Connect a cluster
        </h2>
        <button
          onClick={() => navigator.clipboard.writeText(snippet)}
          className="rounded border border-neutral-700 px-2 py-1 text-xs hover:bg-neutral-800"
        >
          Copy
        </button>
      </div>
      <pre className="overflow-x-auto rounded-md bg-neutral-950 p-3 font-mono text-xs leading-relaxed text-neutral-300">
        {snippet}
      </pre>
      <p className="mt-2 text-xs text-neutral-500">
        Trust anchor + DS record:{' '}
        <a href="/api/zone/anchor" className="underline hover:text-white">
          /api/zone/anchor
        </a>
      </p>
    </div>
  )
}

function timeAgo(unix: number): string {
  if (!unix) return '—'
  const seconds = Math.floor(Date.now() / 1000 - unix)
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}
