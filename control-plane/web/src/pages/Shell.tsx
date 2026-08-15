import { useQuery } from '@tanstack/react-query'
import { Link, Outlet, useNavigate, useParams } from 'react-router'
import { get, send, setCsrf, type Me } from '../lib/api'

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

export function Shell() {
  const { data: me, isLoading } = useMe()
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
            <button
              className="rounded-md border border-neutral-700 px-2 py-1 hover:bg-neutral-800"
              onClick={async () => {
                await send('POST', '/api/logout')
                window.location.href = '/login'
              }}
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  )
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null
  const message = error instanceof Error ? error.message : String(error)
  return (
    <p className="mt-2 rounded-md border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-300">
      {message}
    </p>
  )
}
