import { useRef, useState } from 'react'
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { Link, useParams, useSearchParams } from 'react-router'
import {
  browseQuery,
  get,
  send,
  type BrowseEntry,
  type BrowseListing,
  type BrowseStatus,
  type BrowseVersion,
} from '../lib/api'
import { ErrorNote, useMe } from './Shell'

// A scanning UI: breadcrumb, entry table, and a version drawer that opens
// only when a path diverges. Downloads are plain links — the browser owns
// progress, cancel and resume, and no file ever lands in this tab's memory.
export function NetworkFiles() {
  const { slug = '', name = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const space = params.get('space') ?? ''
  const path = params.get('path') ?? ''
  const { data: me } = useMe()
  const role = me?.orgs.find((o) => o.slug === slug)?.role
  const isAdmin = role === 'owner' || role === 'admin'
  const base = `/api/orgs/${slug}/networks/${name}/browse`

  const status = useQuery({
    queryKey: ['browse-status', slug, name],
    queryFn: () => get<BrowseStatus>(base),
  })

  if (status.error) return <ErrorNote error={status.error} />
  if (!status.data) return <div className="text-neutral-400">Loading…</div>

  const spaces = [
    ...new Set(status.data.devices.flatMap((d) => d.spaces)),
  ].sort()
  const chosen = space === '' ? (spaces[0] ?? '') : space

  return (
    <div className="space-y-6">
      <Header slug={slug} network={name} status={status.data} />
      {!status.data.enabled ? (
        <Disabled slug={slug} network={name} isAdmin={isAdmin} />
      ) : status.data.devices.length === 0 ? (
        <NoDaemon />
      ) : (
        <>
          <SpacePicker
            spaces={spaces}
            chosen={chosen}
            onPick={(next) => setParams({ space: next })}
          />
          {chosen !== '' && (
            <Directory
              base={base}
              space={chosen}
              path={path}
              onNavigate={(next) => setParams({ space: chosen, path: next })}
            />
          )}
        </>
      )}
    </div>
  )
}

function Header({
  slug,
  network,
  status,
}: {
  slug: string
  network: string
  status: BrowseStatus
}) {
  const attached = status.devices.length
  return (
    <div className="flex flex-wrap items-center gap-3">
      <h1 className="text-lg font-semibold text-white">
        <Link
          to={`/o/${slug}/networks/${network}`}
          className="text-neutral-400 hover:text-white"
        >
          {network}
        </Link>
        <span className="px-2 text-neutral-600">/</span>
        Files
      </h1>
      {attached > 0 && (
        <span className="ml-auto inline-flex items-center gap-2 rounded-full border border-teal-900 bg-teal-950/40 px-3 py-1 text-xs font-medium text-teal-300">
          <span className="h-2 w-2 rounded-full bg-teal-400" />
          via {status.devices[0].device}
          {attached > 1 && ` · ${attached} attached`}
        </span>
      )}
    </div>
  )
}

// Browsing is off for this network. The admin toggle is right here when the
// viewer can flip it, and named rather than hidden when they cannot.
function Disabled({
  slug,
  network,
  isAdmin,
}: {
  slug: string
  network: string
  isAdmin: boolean
}) {
  const queryClient = useQueryClient()
  const enable = useMutation({
    mutationFn: () =>
      send('PUT', `/api/orgs/${slug}/networks/${network}/browse/enabled`, {
        enabled: true,
      }),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['browse-status', slug, network] }),
  })
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6">
      <p className="text-neutral-300">
        File browsing is off for this network.
      </p>
      <p className="mt-1 text-sm text-neutral-500">
        An org admin can enable it here. Nodes of this cluster attach on
        their own once it is on — an operator can still opt one out with{' '}
        <code className="text-neutral-300">synch cloud disable</code>.
      </p>
      {isAdmin ? (
        <div className="mt-4">
          <button
            onClick={() => enable.mutate()}
            disabled={enable.isPending}
            className="rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-950 disabled:opacity-50"
          >
            Enable file browsing
          </button>
          <ErrorNote error={enable.error} />
        </div>
      ) : (
        <p className="mt-4 text-sm text-neutral-500">
          You are a member of this org, so an owner or admin has to turn it on.
        </p>
      )}
    </div>
  )
}

// Enabled, but nothing has attached. Daemons attach on their own, so this
// means no node of the cluster is running one — or the one that is has opted
// out.
function NoDaemon() {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6">
      <p className="text-neutral-300">No daemon is attached yet.</p>
      <p className="mt-1 text-sm text-neutral-500">
        Daemons attach on their own — there is no command to run. Check that a
        node of this cluster is running <code className="text-neutral-300">
        synch daemon run</code> and has not opted out with{' '}
        <code className="text-neutral-300">synch cloud disable</code>.
      </p>
      <p className="mt-3 text-sm text-neutral-500">
        There is no URL to configure either way. The node finds this control
        plane on its own, from the same DNSSEC-signed zone that names its
        membership.
      </p>
    </div>
  )
}

function SpacePicker({
  spaces,
  chosen,
  onPick,
}: {
  spaces: string[]
  chosen: string
  onPick: (space: string) => void
}) {
  if (spaces.length <= 1) return null
  return (
    <div className="flex flex-wrap gap-2 text-sm">
      {spaces.map((space) => (
        <button
          key={space}
          onClick={() => onPick(space)}
          className={
            space === chosen
              ? 'rounded-md border border-neutral-600 bg-neutral-800 px-3 py-1 font-mono text-white'
              : 'rounded-md border border-neutral-800 px-3 py-1 font-mono text-neutral-400 hover:bg-neutral-900'
          }
        >
          {space}
        </button>
      ))}
    </div>
  )
}

function Directory({
  base,
  space,
  path,
  onNavigate,
}: {
  base: string
  space: string
  path: string
  onNavigate: (path: string) => void
}) {
  const [open, setOpen] = useState('')
  // Downloads target a hidden same-origin iframe rather than the top window, so
  // a refused download (a plain-text 4xx/5xx with no attachment) renders in the
  // frame and never replaces the Files page. A successful download carries
  // Content-Disposition: attachment, which the browser streams straight to disk
  // — the iframe navigation is cancelled — so large files never touch memory
  // here. The iframe's load fires only for the error case, where its body text
  // is the message to surface.
  const [downloadError, setDownloadError] = useState('')
  const frame = useRef<HTMLIFrameElement>(null)
  const onFrameLoad = () => {
    try {
      const text = frame.current?.contentDocument?.body?.innerText?.trim() ?? ''
      if (text !== '') setDownloadError(text)
    } catch {
      // Same-origin, so this should not throw; if it somehow does, a download
      // that failed silently is better than a crash.
    }
  }
  const startDownload = () => setDownloadError('')
  // Paginated at the source: a directory of a million paths is a paged read,
  // not one giant frame crossing the tunnel.
  const listing = useInfiniteQuery({
    queryKey: ['browse-ls', base, space, path],
    initialPageParam: '',
    queryFn: ({ pageParam }) =>
      get<BrowseListing>(
        `${base}/ls${browseQuery({ space, path, all: '1', cursor: pageParam })}`,
      ),
    getNextPageParam: (last) => (last.cursor === '' ? undefined : last.cursor),
  })

  if (listing.error) return <ErrorNote error={listing.error} />
  if (!listing.data) return <div className="text-neutral-400">Loading…</div>

  const entries = listing.data.pages.flatMap((page) => page.entries)
  const device = listing.data.pages[0]?.device ?? ''

  return (
    <div>
      <iframe
        ref={frame}
        name="synch-dl"
        title="download"
        onLoad={onFrameLoad}
        className="hidden"
      />
      {downloadError !== '' && (
        <div className="mb-3 flex items-start gap-3 rounded-md border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-300">
          <span className="flex-1">Download failed: {downloadError}</span>
          <button
            onClick={() => setDownloadError('')}
            className="text-red-400 hover:text-red-200"
          >
            dismiss
          </button>
        </div>
      )}
      <Breadcrumb space={space} path={path} onNavigate={onNavigate} />
      <div className="overflow-x-auto rounded-lg border border-neutral-800">
        <table className="w-full text-sm">
          <thead className="bg-neutral-900 text-left text-neutral-400">
            <tr>
              <th className="w-1/2 px-4 py-2 font-medium">name</th>
              <th className="px-4 py-2 font-medium">size</th>
              <th className="px-4 py-2 font-medium">modified</th>
              <th className="px-4 py-2 font-medium">versions</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-800">
            {entries.map((entry) => (
              <Row
                key={entry.path}
                base={base}
                space={space}
                entry={entry}
                opened={open === entry.path}
                onOpen={() => setOpen(open === entry.path ? '' : entry.path)}
                onNavigate={onNavigate}
                onDownload={startDownload}
              />
            ))}
            {entries.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-neutral-500">
                  Nothing here.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {listing.hasNextPage && (
        <button
          onClick={() => listing.fetchNextPage()}
          disabled={listing.isFetchingNextPage}
          className="mt-3 rounded-md border border-neutral-700 px-3 py-1.5 text-sm hover:bg-neutral-900 disabled:opacity-50"
        >
          {listing.isFetchingNextPage ? 'Loading…' : 'Load more'}
        </button>
      )}
      <p className="mt-2 text-xs text-neutral-500">
        Served by {device}. Two attached daemons may answer differently while
        the cluster converges — that is anti-entropy, not an error, and nothing
        is merged here.
      </p>
    </div>
  )
}

function Breadcrumb({
  space,
  path,
  onNavigate,
}: {
  space: string
  path: string
  onNavigate: (path: string) => void
}) {
  const parts = path.split('/').filter((part) => part !== '')
  return (
    <div className="mb-3 flex flex-wrap items-center text-sm text-neutral-400">
      <button
        onClick={() => onNavigate('')}
        className="font-mono font-semibold text-white hover:underline"
      >
        {space}
      </button>
      {parts.map((part, index) => (
        <span key={index} className="flex items-center">
          <span className="px-1 text-neutral-600">/</span>
          <button
            onClick={() => onNavigate(parts.slice(0, index + 1).join('/'))}
            className="font-mono hover:text-white hover:underline"
          >
            {part}
          </button>
        </span>
      ))}
    </div>
  )
}

function Row({
  base,
  space,
  entry,
  opened,
  onOpen,
  onNavigate,
  onDownload,
}: {
  base: string
  space: string
  entry: BrowseEntry
  opened: boolean
  onOpen: () => void
  onNavigate: (path: string) => void
  onDownload: () => void
}) {
  const divergent = entry.versions > 1
  return (
    <>
      <tr className="align-top">
        <td className="px-4 py-3">
          {entry.kind === 'dir' ? (
            <button
              onClick={() => onNavigate(entry.path)}
              className="font-mono text-amber-300 hover:underline"
            >
              {entry.name}/
            </button>
          ) : (
            <span className="font-mono text-neutral-200">{entry.name}</span>
          )}
        </td>
        <td className="px-4 py-3 text-neutral-400">
          {entry.kind === 'dir' ? '—' : bytes(entry.size)}
        </td>
        <td className="px-4 py-3 text-neutral-500">
          {entry.kind === 'dir' ? '—' : day(entry.mtime_ns)}
        </td>
        <td className="px-4 py-3">
          {entry.kind === 'dir' ? (
            <span className="text-neutral-500">—</span>
          ) : divergent ? (
            <span className="rounded-full border border-amber-900 bg-amber-950/40 px-2 py-0.5 text-xs font-semibold text-amber-300">
              {entry.versions} versions
            </span>
          ) : (
            <span className="text-neutral-500">1</span>
          )}
        </td>
        <td className="px-4 py-3 text-right">
          {entry.kind === 'dir' ? null : divergent ? (
            <button
              onClick={onOpen}
              className="text-sm font-medium text-teal-300 hover:underline"
            >
              {opened ? 'close' : 'choose…'}
            </button>
          ) : (
            <a
              href={`${base}/file${browseQuery({ space, path: entry.path })}`}
              target="synch-dl"
              rel="noopener"
              onClick={onDownload}
              className="text-sm font-medium text-teal-300 hover:underline"
            >
              download
            </a>
          )}
        </td>
      </tr>
      {opened && (
        <tr>
          <td colSpan={5} className="bg-neutral-950 px-4 py-3">
            <Drawer
              base={base}
              space={space}
              entry={entry}
              onDownload={onDownload}
            />
          </td>
        </tr>
      )}
    </>
  )
}

// A divergent path is never resolved here. Downloading one version is a read
// of that version; adopting one is a node's own publish, and this surface
// cannot write.
function Drawer({
  base,
  space,
  entry,
  onDownload,
}: {
  base: string
  space: string
  entry: BrowseEntry
  onDownload: () => void
}) {
  // The daemon orders versions with the newest-wins pick last, which is the
  // one the plain download link would have taken.
  const versions = [...entry.all].reverse()
  return (
    <div>
      <p className="mb-2 text-xs text-neutral-500">
        {entry.name} — divergent: pick the version to download. The cluster
        resolves nothing for you.
      </p>
      <div className="space-y-2">
        {versions.map((version, index) => (
          <VersionRow
            key={`${version.root}-${version.seq}`}
            base={base}
            space={space}
            path={entry.path}
            version={version}
            newest={index === 0}
            onDownload={onDownload}
          />
        ))}
      </div>
    </div>
  )
}

function VersionRow({
  base,
  space,
  path,
  version,
  newest,
  onDownload,
}: {
  base: string
  space: string
  path: string
  version: BrowseVersion
  newest: boolean
  onDownload: () => void
}) {
  const from = version.attestors[0] ?? ''
  return (
    <div
      className={
        newest
          ? 'flex flex-wrap items-baseline gap-x-4 gap-y-1 rounded-md border border-teal-900 bg-teal-950/30 px-3 py-2'
          : 'flex flex-wrap items-baseline gap-x-4 gap-y-1 rounded-md border border-neutral-800 px-3 py-2'
      }
    >
      <code className="font-mono text-xs text-neutral-200">
        {from} · seq {version.seq}
      </code>
      <span className="text-xs text-neutral-500">
        {bytes(version.size)} · {day(version.mtime_ns)} · attested by{' '}
        {version.attestors.join(', ')}
      </span>
      <code
        className="max-w-[16rem] truncate font-mono text-[11px] text-neutral-600"
        title={version.root}
      >
        {version.root}
      </code>
      <a
        href={`${base}/file${browseQuery({ space, path, from })}`}
        target="synch-dl"
        rel="noopener"
        onClick={onDownload}
        className="ml-auto text-xs font-semibold text-teal-300 hover:underline"
      >
        download ↓{newest ? ' (newest)' : ''}
      </a>
    </div>
  )
}

function bytes(size: number): string {
  if (!Number.isFinite(size) || size < 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = size
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`
}

function day(mtimeNs: number): string {
  // The mtime comes from a semi-trusted daemon, so an out-of-range value must
  // render as a dash rather than throw a RangeError that (with no error
  // boundary above) would blank the whole table.
  if (!Number.isFinite(mtimeNs) || mtimeNs === 0) return '—'
  const date = new Date(mtimeNs / 1_000_000)
  const iso = Number.isNaN(date.getTime()) ? '' : date.toISOString()
  return iso === '' ? '—' : iso.slice(0, 10)
}
