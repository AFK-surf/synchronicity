import { useQuery } from '@tanstack/react-query'
import { Link, Outlet, useNavigate, useParams } from 'react-router'
import {
  ApiError,
  get,
  send,
  setCsrf,
  type AuthMethods,
  type Me,
} from '../lib/api'

export function useMe() {
  return useQuery({
    queryKey: ['me'],
    queryFn: async () => {
      const me = await get<Me>('/api/me')
      setCsrf(me.csrf)
      return me
    },
  })
}

// Configuration, not session state: it answers before anyone signs in,
// and it cannot change while the page is open.
export function useAuthMethods() {
  return useQuery({
    queryKey: ['auth-methods'],
    queryFn: () => get<AuthMethods>('/api/auth/methods'),
    staleTime: Infinity,
  })
}

export function Shell() {
  const { data: me, isLoading } = useMe()
  const { data: methods } = useAuthMethods()
  const { slug } = useParams()
  const navigate = useNavigate()

  if (isLoading) {
    return <div className="p-8 text-neutral-400">Loading…</div>
  }
  if (!me) return null

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100">
      <header className="border-b border-neutral-800 bg-neutral-900/60">
        <div className="mx-auto flex max-w-5xl items-center gap-4 px-4 py-3">
          <Link to="/" className="font-semibold tracking-tight text-white">
            synchronicity
          </Link>
          <span className="text-neutral-600">/</span>
          <select
            className="rounded-md border border-neutral-700 bg-neutral-900 px-2 py-1 text-sm"
            value={slug ?? ''}
            onChange={(e) => {
              if (e.target.value === '') navigate('/pick')
              else navigate(`/o/${e.target.value}`)
            }}
          >
            <option value="">select org…</option>
            {me.orgs.map((o) => (
              <option key={o.id} value={o.slug}>
                {o.name} ({o.role})
              </option>
            ))}
          </select>
          {slug && (
            <nav className="flex gap-3 text-sm text-neutral-400">
              <Link to={`/o/${slug}`} className="hover:text-white">
                Networks
              </Link>
              <Link to={`/o/${slug}/settings`} className="hover:text-white">
                Settings
              </Link>
            </nav>
          )}
          <div className="ml-auto flex items-center gap-3 text-sm text-neutral-400">
            <span>{me.user.email}</span>
            {/* Signing out is a write — the session is a row, and revoking it
                is deleting that row — so on a read-only node it happens where
                the row lives. A button posting here would be refused, and a
                button that says "Sign out" and leaves the session live is
                worse than a link that goes where it can be ended. */}
            {methods?.primary ? (
              <a
                className="rounded-md border border-neutral-700 px-2 py-1 hover:bg-neutral-800"
                href={`${methods.primary}/`}
              >
                Sign out on the primary
              </a>
            ) : (
              <button
                className="rounded-md border border-neutral-700 px-2 py-1 hover:bg-neutral-800"
                onClick={async () => {
                  // The redirect runs whatever the answer was: a logout that
                  // could not reach the server must still take the operator
                  // off a page that is about to 401 on every query.
                  try {
                    await send('POST', '/api/logout')
                  } finally {
                    window.location.href = '/login'
                  }
                }}
              >
                Sign out
              </button>
            )}
          </div>
        </div>
      </header>
      {/* Said once, up front, rather than one refused request at a time: on
          a read-only node every read is live and every change belongs to the
          primary, and a user who learns that from a 409 has already lost the
          form they filled in. */}
      {methods?.primary && (
        <div className="border-b border-sky-900 bg-sky-950/50">
          <div className="mx-auto flex max-w-5xl flex-wrap items-center gap-2 px-4 py-2 text-sm text-sky-200">
            <span>
              Read-only node — listings, files and history are live here;
              changes are made on the primary.
            </span>
            <a
              className="ml-auto rounded-md border border-sky-800 px-2 py-1 hover:bg-sky-900/50"
              href={methods.primary}
            >
              Open the primary
            </a>
          </div>
        </div>
      )}
      <main className="mx-auto max-w-5xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  )
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null
  const message = error instanceof Error ? error.message : String(error)
  // A refusal that names another node is not a failure to report and forget:
  // the work the user just did is still valid, somewhere else, and the link
  // is the difference between a dead end and a redirect they make themselves.
  const primary = error instanceof ApiError ? error.primary : ''
  return (
    <p className="mt-2 rounded-md border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-300">
      {message}
      {primary && (
        <>
          {' '}
          <a className="underline hover:text-red-200" href={primary}>
            Open the primary
          </a>
        </>
      )}
    </p>
  )
}
