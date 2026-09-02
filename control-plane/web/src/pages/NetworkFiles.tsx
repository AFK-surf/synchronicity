import { useCallback, useEffect, useRef, useState } from 'react'
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
  writeFile,
  type BrowseDevice,
  type BrowseEntry,
  type BrowseListing,
  type BrowseStatus,
  type BrowseVersion,
  type BrowseWrites,
  type WithdrawnFile,
  type WrittenFile,
} from '../lib/api'
import { bytes } from '../lib/format'
import {
  IMAGE_PREVIEW_CAP,
  TEXT_PREVIEW_CAP,
  imageMime,
  previewKind,
  prettyIfJson,
} from '../lib/preview'
import { useTitle } from '../lib/title'
import { ErrorNote, useMe } from './Shell'

// A scanning UI: breadcrumb, entry table, and a version drawer that opens
// only when a path diverges. Downloads are plain links — the browser owns
// progress, cancel and resume, and no downloaded file lands in this tab's
// memory. Previews are the deliberate exception: images and text only, both
// capped, rendered as decoded bytes and never as markup, because the
// endpoint serves every file as hostile octets and the preview keeps
// treating it that way.
export function NetworkFiles() {
  const { slug = '', name = '' } = useParams()
  useTitle(`${name} files`)
  const [params, setParams] = useSearchParams()
  const space = params.get('space') ?? ''
  const path = params.get('path') ?? ''
  const origin = params.get('origin') ?? ''
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
  // Which node serves the reading. Unset means automatic — any attached
  // holder — and a pin that names a node not holding the chosen space (a
  // stale URL, a node that left) reads as unset rather than as an error.
  const nodes = status.data.devices.filter((d) => d.spaces.includes(chosen))
  const pinned = nodes.some((n) => n.origin === origin) ? origin : ''

  return (
    <div className="space-y-6">
      <Header slug={slug} network={name} status={status.data} />
      {!status.data.enabled ? (
        <Disabled slug={slug} network={name} isAdmin={isAdmin} />
      ) : status.data.devices.length === 0 ? (
        <NoDaemon />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
            <SpacePicker
              spaces={spaces}
              chosen={chosen}
              onPick={(next) => setParams({ space: next, origin: pinned })}
            />
            <NodePicker
              nodes={nodes}
              chosen={pinned}
              onPick={(next) => setParams({ space: chosen, origin: next })}
            />
          </div>
          {chosen !== '' && (
            <Directory
              base={base}
              space={chosen}
              path={path}
              origin={pinned}
              writes={status.data.writes}
              onNavigate={(next) =>
                setParams({ space: chosen, origin: pinned, path: next })
              }
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
          {attached} {attached === 1 ? 'node' : 'nodes'} attached
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
        <code className="text-neutral-300">synch control-plane disable</code>.
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
        <code className="text-neutral-300">synch control-plane disable</code>.
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

// Which attached node serves the reading — always visible when one holds the
// space, so the answer to "which node am I browsing through" is on the page
// rather than buried in a footer. One holder is named as a chip: a selector
// between "automatic" and the same node is a choice with one outcome. The
// origin — not the label, which is for people and may repeat — is what the
// API selects by.
function NodePicker({
  nodes,
  chosen,
  onPick,
}: {
  nodes: BrowseDevice[]
  chosen: string
  onPick: (origin: string) => void
}) {
  if (nodes.length === 0) return null
  if (nodes.length === 1) {
    return (
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="text-xs text-neutral-500">via</span>
        <span
          title={nodes[0].origin}
          className="rounded-md border border-neutral-800 bg-neutral-900 px-3 py-1 font-mono text-neutral-300"
        >
          {nodes[0].device}
        </span>
      </div>
    )
  }
  const option = (origin: string, label: string, title: string) => (
    <button
      key={origin}
      title={title}
      onClick={() => onPick(origin)}
      className={
        origin === chosen
          ? 'rounded-md border border-neutral-600 bg-neutral-800 px-3 py-1 font-mono text-white'
          : 'rounded-md border border-neutral-800 px-3 py-1 font-mono text-neutral-400 hover:bg-neutral-900'
      }
    >
      {label}
    </button>
  )
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      <span className="text-xs text-neutral-500">via</span>
      {option('', 'automatic', 'any attached node holding this space')}
      {nodes.map((node) =>
        option(node.origin, node.device, node.origin),
      )}
    </div>
  )
}

function Directory({
  base,
  space,
  path,
  origin,
  writes,
  onNavigate,
}: {
  base: string
  space: string
  path: string
  origin: string
  writes: BrowseWrites
  onNavigate: (path: string) => void
}) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useState('')
  // What the last write did, in words: an upload is expected to make
  // divergence where a customer already published the path, and a delete
  // withdraws the cloud's version and never a customer's — both are worth
  // saying rather than showing a green tick.
  const [written, setWritten] = useState('')
  const [writeError, setWriteError] = useState('')
  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['browse-ls', base, space] })
  const upload = useMutation({
    mutationFn: (file: File) =>
      writeFile(
        `${base}/file${browseQuery({
          space,
          path: path === '' ? file.name : `${path}/${file.name}`,
        })}`,
        'PUT',
        file,
      ) as Promise<WrittenFile>,
    onSuccess: (result) => {
      setWriteError('')
      setWritten(
        `${result.path} published as ${result.device}'s version (${bytes(result.size)}, root ${result.root.slice(0, 12)}…). Where another node publishes this path, both versions now show.`,
      )
      refresh()
    },
    onError: (error: Error) => {
      setWritten('')
      setWriteError(error.message)
    },
  })
  const remove = useMutation({
    mutationFn: (entryPath: string) =>
      writeFile(
        `${base}/file${browseQuery({ space, path: entryPath })}`,
        'DELETE',
      ) as Promise<WithdrawnFile>,
    onSuccess: (result) => {
      setWriteError('')
      setWritten(
        result.withdrawn
          ? result.still_published
            ? `${result.device}'s version of ${result.path} is withdrawn; another node still publishes this file, and only that node can retract it.`
            : `${result.device}'s version of ${result.path} is withdrawn.`
          : result.still_published
            ? `${result.device} had no version of ${result.path} to withdraw; the file is another node's, and only that node can retract it.`
            : `${result.device} had no version of ${result.path} to withdraw.`,
      )
      refresh()
    },
    onError: (error: Error) => {
      setWritten('')
      setWriteError(error.message)
    },
  })
  // Which file's preview row is expanded — a second, independent drawer so
  // a divergent path can show its versions and a preview at once.
  const [preview, setPreview] = useState('')
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
    queryKey: ['browse-ls', base, space, path, origin],
    initialPageParam: '',
    queryFn: ({ pageParam }) =>
      get<BrowseListing>(
        `${base}/ls${browseQuery({
          space,
          path,
          origin,
          all: '1',
          cursor: pageParam,
        })}`,
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
      {writes.enabled && (
        <Uploader
          writes={writes}
          pending={upload.isPending}
          onPick={(file) => upload.mutate(file)}
        />
      )}
      {written !== '' && (
        <div className="mb-3 flex items-start gap-3 rounded-md border border-teal-900 bg-teal-950/40 px-3 py-2 text-sm text-teal-200">
          <span className="flex-1">{written}</span>
          <button
            onClick={() => setWritten('')}
            className="text-teal-400 hover:text-teal-200"
          >
            dismiss
          </button>
        </div>
      )}
      {writeError !== '' && (
        <div className="mb-3 flex items-start gap-3 rounded-md border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-300">
          <span className="flex-1">Write failed: {writeError}</span>
          <button
            onClick={() => setWriteError('')}
            className="text-red-400 hover:text-red-200"
          >
            dismiss
          </button>
        </div>
      )}
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
                origin={origin}
                entry={entry}
                opened={open === entry.path}
                onOpen={() => setOpen(open === entry.path ? '' : entry.path)}
                previewed={preview === entry.path}
                onPreview={() =>
                  setPreview(preview === entry.path ? '' : entry.path)
                }
                onNavigate={onNavigate}
                onDownload={startDownload}
                canDelete={writes.enabled && writes.attached}
                onDelete={() => {
                  if (
                    window.confirm(
                      `Withdraw the cloud's version of ${entry.path}? A version another node publishes stays; only that node can retract it.`,
                    )
                  )
                    remove.mutate(entry.path)
                }}
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

// The upload control: a file picker, present exactly while the network is
// hosted, and grayed with its reason while the hosted replica's write tunnel
// is not attached to this node. One file per pick; the path is the directory
// being shown plus the file's own name.
function Uploader({
  writes,
  pending,
  onPick,
}: {
  writes: BrowseWrites
  pending: boolean
  onPick: (file: File) => void
}) {
  const ready = writes.attached && !pending
  return (
    <div className="mb-3 flex flex-wrap items-center gap-3 text-sm">
      <label
        className={
          ready
            ? 'cursor-pointer rounded-md bg-white px-3 py-1.5 font-medium text-neutral-950'
            : 'rounded-md border border-neutral-800 px-3 py-1.5 text-neutral-500'
        }
      >
        {pending ? 'Uploading…' : 'Upload a file'}
        <input
          type="file"
          className="hidden"
          disabled={!ready}
          onChange={(event) => {
            const file = event.target.files?.[0]
            event.target.value = ''
            if (file) onPick(file)
          }}
        />
      </label>
      <span className="text-xs text-neutral-500">
        {writes.attached
          ? `Published into this directory as ${writes.device}'s own version.`
          : 'The hosted replica is not attached to this node yet; uploads wait for it.'}
      </span>
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
  origin,
  entry,
  opened,
  onOpen,
  previewed,
  onPreview,
  onNavigate,
  onDownload,
  canDelete,
  onDelete,
}: {
  base: string
  space: string
  origin: string
  entry: BrowseEntry
  opened: boolean
  onOpen: () => void
  previewed: boolean
  onPreview: () => void
  onNavigate: (path: string) => void
  onDownload: () => void
  canDelete: boolean
  onDelete: () => void
}) {
  const divergent = entry.versions > 1
  // Only a plain file with a name the preview can render is clickable —
  // symlinks and tombstones download, as before.
  const previewable = entry.kind === 'file' && previewKind(entry.name) !== null
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
          ) : previewable ? (
            <button
              onClick={onPreview}
              title="preview"
              className="font-mono text-neutral-200 hover:underline"
            >
              {entry.name}
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
              href={`${base}/file${browseQuery({
                space,
                path: entry.path,
                origin,
              })}`}
              target="synch-dl"
              rel="noopener"
              onClick={onDownload}
              className="text-sm font-medium text-teal-300 hover:underline"
            >
              download
            </a>
          )}
          {entry.kind !== 'dir' && canDelete && (
            <button
              onClick={onDelete}
              title="withdraw the cloud's version of this path"
              className="ml-3 text-sm font-medium text-neutral-500 hover:text-red-300 hover:underline"
            >
              withdraw
            </button>
          )}
        </td>
      </tr>
      {opened && (
        <tr>
          <td colSpan={5} className="bg-neutral-950 px-4 py-3">
            <Drawer
              base={base}
              space={space}
              origin={origin}
              entry={entry}
              onDownload={onDownload}
            />
          </td>
        </tr>
      )}
      {previewed && (
        <tr>
          <td colSpan={5} className="bg-neutral-950 px-4 py-3">
            {/* The same URL the plain download link takes: the daemon's
                newest-wins pick. Per-version previews live in the drawer. */}
            <Preview
              name={entry.name}
              size={entry.size}
              url={`${base}/file${browseQuery({
                space,
                path: entry.path,
                origin,
              })}`}
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
  origin,
  entry,
  onDownload,
}: {
  base: string
  space: string
  origin: string
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
            origin={origin}
            path={entry.path}
            name={entry.name}
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
  origin,
  path,
  name,
  version,
  newest,
  onDownload,
}: {
  base: string
  space: string
  origin: string
  path: string
  name: string
  version: BrowseVersion
  newest: boolean
  onDownload: () => void
}) {
  const [show, setShow] = useState(false)
  const from = version.attestors[0] ?? ''
  return (
    <div
      className={
        newest
          ? 'rounded-md border border-teal-900 bg-teal-950/30 px-3 py-2'
          : 'rounded-md border border-neutral-800 px-3 py-2'
      }
    >
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
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
        {previewKind(name) !== null && (
          <button
            onClick={() => setShow(!show)}
            className="text-xs font-semibold text-teal-300 hover:underline"
          >
            {show ? 'hide preview' : 'preview'}
          </button>
        )}
        <a
          href={`${base}/file${browseQuery({ space, path, origin, from })}`}
          target="synch-dl"
          rel="noopener"
          onClick={onDownload}
          className="ml-auto text-xs font-semibold text-teal-300 hover:underline"
        >
          download ↓{newest ? ' (newest)' : ''}
        </a>
      </div>
      {/* Seeing a version is how you choose between divergent ones, so the
          preview sits with the download it stands in for. */}
      {show && (
        <div className="mt-2">
          <Preview
            name={name}
            size={version.size}
            url={`${base}/file${browseQuery({ space, path, origin, from })}`}
          />
        </div>
      )}
    </div>
  )
}

// What a preview holds. Text is a string bound for a React text node;
// an image is an object URL bound for an <img>. Neither form is ever
// parsed as markup, which is the whole safety argument for previewing
// hostile files at all.
type PreviewState =
  | { state: 'loading' }
  | { state: 'failed'; message: string }
  | { state: 'text'; body: string; truncated: boolean; device: string }
  | { state: 'image'; url: string; device: string }

// Fetches the bytes for a preview and holds them for exactly as long as the
// preview is mounted: an abort on cleanup, an object URL revoked with it.
// The fetch is a read like the download link's — cookies, no CSRF — capped
// through the endpoint's single-range support.
function usePreview(
  url: string,
  name: string,
  size: number,
): [PreviewState, (message: string) => void] {
  const [preview, setPreview] = useState<PreviewState>({ state: 'loading' })
  useEffect(() => {
    const kind = previewKind(name)
    if (kind === null) {
      // The row only offers the toggle for renderable names; this answers
      // for itself rather than trust its callers.
      setPreview({ state: 'failed', message: 'this file has no preview' })
      return
    }
    if (kind === 'image' && size > IMAGE_PREVIEW_CAP) {
      setPreview({
        state: 'failed',
        message: `${bytes(size)} is past the ${bytes(IMAGE_PREVIEW_CAP)} preview cap — download it instead`,
      })
      return
    }
    const controller = new AbortController()
    setPreview({ state: 'loading' })
    // Text past the cap previews as its first MiB — one clean range, the
    // truncation labelled in the header below.
    const headers =
      kind === 'text' && size > TEXT_PREVIEW_CAP
        ? { range: `bytes=0-${TEXT_PREVIEW_CAP - 1}` }
        : undefined
    let objectUrl = ''
    fetch(url, {
      credentials: 'same-origin',
      headers,
      signal: controller.signal,
    })
      .then(async (resp) => {
        if (!resp.ok) {
          // This endpoint's refusals are plain text, same as the download
          // iframe surfaces.
          throw new Error(
            (await resp.text()).trim() || `HTTP ${resp.status}`,
          )
        }
        const device = resp.headers.get('x-synch-device') ?? ''
        if (kind === 'text') {
          setPreview({
            state: 'text',
            body: await resp.text(),
            truncated: resp.status === 206,
            device,
          })
        } else {
          const blob = new Blob([await resp.arrayBuffer()], {
            type: imageMime(name),
          })
          objectUrl = URL.createObjectURL(blob)
          setPreview({ state: 'image', url: objectUrl, device })
        }
      })
      .catch((err: unknown) => {
        // An abort is the preview closing, not a failure to report.
        if (controller.signal.aborted) return
        const message =
          err instanceof Error && err.message !== '' ? err.message : ''
        setPreview({
          state: 'failed',
          message: message === '' ? 'preview failed' : message,
        })
      })
    return () => {
      controller.abort()
      if (objectUrl !== '') URL.revokeObjectURL(objectUrl)
    }
  }, [url, name, size])
  // For an <img> that refuses to decode: the extension promised an image
  // the bytes did not keep.
  const fail = useCallback((message: string) => {
    setPreview({ state: 'failed', message })
  }, [])
  return [preview, fail]
}

// One file, pulled into the tab to be looked at rather than saved.
function Preview({
  name,
  size,
  url,
}: {
  name: string
  size: number
  url: string
}) {
  const [preview, fail] = usePreview(url, name, size)
  const loaded =
    preview.state === 'text' || preview.state === 'image'
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-baseline gap-x-4 gap-y-1 text-xs text-neutral-500">
        <span className="font-mono text-neutral-300">{name}</span>
        {preview.state === 'text' && preview.truncated && (
          <span className="text-amber-400/80">
            first {bytes(TEXT_PREVIEW_CAP)} of {bytes(size)} — download for
            the rest
          </span>
        )}
        {loaded && preview.device !== '' && <span>via {preview.device}</span>}
      </div>
      {preview.state === 'loading' && (
        <div className="text-sm text-neutral-400">Loading…</div>
      )}
      {preview.state === 'failed' && (
        <div className="rounded-md border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-300">
          {preview.message}
        </div>
      )}
      {preview.state === 'text' &&
        (preview.body === '' ? (
          <p className="text-sm text-neutral-500">Empty file.</p>
        ) : (
          <pre className="max-h-96 overflow-auto rounded-md border border-neutral-800 bg-neutral-900 p-3 font-mono text-xs leading-relaxed text-neutral-200">
            {prettyIfJson(name, preview.body)}
          </pre>
        ))}
      {preview.state === 'image' && (
        <img
          src={preview.url}
          alt={name}
          onError={() =>
            fail('these bytes will not decode as an image — the extension may be lying')
          }
          className="max-h-[32rem] max-w-full rounded-md border border-neutral-800 bg-neutral-900"
        />
      )}
    </div>
  )
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
