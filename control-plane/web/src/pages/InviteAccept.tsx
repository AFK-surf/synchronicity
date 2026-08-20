import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router'
import {
  ApiError,
  get,
  send,
  setCsrf,
  type InvitePreview,
  type Me,
} from '../lib/api'
import { useTitle } from '../lib/title'
import { ErrorNote } from './Shell'

export function InviteAccept() {
  useTitle('Invitation')
  const token = new URLSearchParams(window.location.search).get('token') ?? ''
  const navigate = useNavigate()
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const { data: invite, error: previewError } = useQuery({
    queryKey: ['invite-preview', token],
    queryFn: () =>
      get<InvitePreview>(
        `/api/invites/preview?token=${encodeURIComponent(token)}`,
      ),
    enabled: token !== '',
    retry: false,
  })

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
        {!token ? (
          <p className="text-sm text-red-400">Missing invite token.</p>
        ) : !invite ? (
          // A 404 is the page's own answer; anything else is the control
          // plane being unreachable, which is not the link's fault.
          previewError ? (
            previewError instanceof ApiError && previewError.status === 404 ? (
              <p className="text-sm text-red-400">
                This invitation link is invalid — it may have been mistyped, or
                the invitation was revoked with its org.
              </p>
            ) : (
              <p className="text-sm text-neutral-400">
                Could not reach the control plane. Reload to try again.
              </p>
            )
          ) : (
            <p className="text-sm text-neutral-400">Looking up the invite…</p>
          )
        ) : (
          <>
            <div className="rounded-lg border border-neutral-800 p-4">
              <div className="text-base font-medium text-white">
                {invite.org_name}
              </div>
              <div className="mt-1 font-mono text-xs text-neutral-500">
                {invite.org}
              </div>
              <dl className="mt-3 space-y-1 text-sm">
                <div className="flex justify-between gap-4">
                  <dt className="text-neutral-500">Invited as</dt>
                  <dd>{invite.email}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-neutral-500">Role</dt>
                  <dd className="font-mono">{invite.role}</dd>
                </div>
                <div className="flex justify-between gap-4">
                  <dt className="text-neutral-500">Expires</dt>
                  <dd>
                    {/* Second-granularity expiry: the time of day is the
                        difference between "valid" and "already dead" on the
                        last day. */}
                    {new Date(invite.expires_at * 1000).toLocaleString()}
                  </dd>
                </div>
              </dl>
            </div>
            {invite.status === 'valid' ? (
              <>
                <p className="text-sm text-neutral-400">
                  Accepting adds your signed-in account to this org. If you are
                  not signed in yet, sign in first and then reopen the invite
                  link.
                </p>
                <button
                  onClick={accept}
                  disabled={busy}
                  className="w-full rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-950 disabled:opacity-50"
                >
                  Accept invitation
                </button>
                <ErrorNote error={error} />
              </>
            ) : invite.status === 'accepted' ? (
              <p className="text-sm text-amber-400">
                This invitation has already been accepted. If that was you, the
                org is already in your list — sign in and check.
              </p>
            ) : (
              <p className="text-sm text-amber-400">
                This invitation has expired. Ask an admin of {invite.org_name}{' '}
                to send a new one.
              </p>
            )}
            <a href="/login" className="block text-center text-sm text-neutral-400 underline">
              Go to sign-in
            </a>
          </>
        )}
      </div>
    </div>
  )
}
