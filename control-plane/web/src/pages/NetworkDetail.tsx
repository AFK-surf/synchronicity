import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router'
import {
  get,
  send,
  type DeviceKeyRow,
  type DeviceRow,
  type NetworkDetail as Detail,
} from '../lib/api'
import { isDeviceKey, isDeviceLabel } from '../lib/zbase32'
import { ErrorNote, useMe } from './Shell'

export function NetworkDetail() {
  const { slug = '', name = '' } = useParams()
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
    `# On each device — print its key, add it above, then join the domain:`,
    `synch id`,
    `synch domain add ${domain}`,
    ``,
    `# Air-gapped / direct mode (anchor from /api/zone/anchor):`,
    `synch --doh ${window.location.origin}/dns-query \\`,
    `      --dnssec-anchor anchor.key domain add ${domain}`,
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
