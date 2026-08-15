import { useState } from 'react'
import { useNavigate } from 'react-router'
import { get, send, setCsrf, type Me } from '../lib/api'
import { ErrorNote } from './Shell'

export function InviteAccept() {
  const token = new URLSearchParams(window.location.search).get('token') ?? ''
  const navigate = useNavigate()
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  async function accept() {
    setBusy(true)
    try {
      const me = await get<Me>('/api/me')
      setCsrf(me.csrf)
      const result = await send<{ org: string }>('POST', '/api/invites/accept', {
        token,
      })
      navigate(`/o/${result.org}`)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-950 text-neutral-100">
      <div className="w-full max-w-sm space-y-4 rounded-xl border border-neutral-800 bg-neutral-900 p-8">
        <h1 className="text-lg font-semibold text-white">
          Organization invitation
        </h1>
        {token ? (
          <>
            <p className="text-sm text-neutral-400">
              Accept this invitation with your signed-in account. If you are
              not signed in yet, sign in first and then reopen the invite link.
            </p>
            <button
              onClick={accept}
              disabled={busy}
              className="w-full rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-950 disabled:opacity-50"
            >
              Accept invitation
            </button>
            <a
              href={`/login`}
              className="block text-center text-sm text-neutral-400 underline"
            >
              Go to sign-in
            </a>
            <ErrorNote error={error} />
          </>
        ) : (
          <p className="text-sm text-red-400">Missing invite token.</p>
        )}
      </div>
    </div>
  )
}
