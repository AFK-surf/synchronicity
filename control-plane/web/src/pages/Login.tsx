import { useState } from 'react'
import { send } from '../lib/api'
import { useAuthMethods } from './Shell'

/// The host of an origin, for a link that reads as a place rather than a
/// URL. A value the server validated as an origin, so a parse failure is not
/// a case worth branching on — show what was configured.
function hostOf(origin: string): string {
  try {
    return new URL(origin).host
  } catch {
    return origin
  }
}

export function Login() {
  const [email, setEmail] = useState('')
  const [orgSlug, setOrgSlug] = useState('')
  const [sent, setSent] = useState(false)
  const error = new URLSearchParams(window.location.search).get('error')
  // Nothing is drawn until the deployment says what it has configured:
  // offering a method that answers "provider not configured" is worse
  // than a moment of blank space.
  const { data: methods, isPending, isError } = useAuthMethods()

  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-950 text-neutral-100">
      <div className="w-full max-w-sm space-y-6 rounded-xl border border-neutral-800 bg-neutral-900 p-8">
        <div>
          <h1 className="text-lg font-semibold text-white">
            synchronicity control plane
          </h1>
          <p className="mt-1 text-sm text-neutral-400">
            Managed membership zones for your clusters.
          </p>
        </div>

        {error === 'needs-link' && (
          <p className="rounded-md border border-amber-900 bg-amber-950/50 px-3 py-2 text-sm text-amber-300">
            An account with this email already exists. Sign in with your
            existing method, then link this identity from Settings.
          </p>
        )}
        {error === 'bad-magic-link' && (
          <p className="rounded-md border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-300">
            That sign-in link is invalid or expired. Request a new one.
          </p>
        )}

        {/* A read-only node mints no session, so the whole form would be a
            row of buttons that 404. What it has instead is the address of the
            node that does — the one fact it holds that a blank screen does
            not. */}
        {methods?.primary && (
          <div className="space-y-3">
            <p className="rounded-md border border-sky-900 bg-sky-950/50 px-3 py-2 text-sm text-sky-200">
              This node serves a read-only copy of the control plane. Signing
              in — and every change — happens on the primary.
            </p>
            <a
              href={`${methods.primary}/login`}
              className="block w-full rounded-md bg-white px-4 py-2 text-center text-sm font-medium text-neutral-950 hover:bg-neutral-200"
            >
              Sign in at {hostOf(methods.primary)}
            </a>
            <p className="text-xs text-neutral-500">
              Once signed in, come back here: this node answers every read.
            </p>
          </div>
        )}

        {isPending && (
          <p className="text-sm text-neutral-500">Loading sign-in methods…</p>
        )}
        {isError && (
          <p className="rounded-md border border-red-900 bg-red-950/50 px-3 py-2 text-sm text-red-300">
            Could not reach the control plane. Reload to try again.
          </p>
        )}

        {methods && !methods.primary && (methods.google || methods.github) && (
          <div className="space-y-2">
            {methods.google && (
              <a
                href="/auth/start/google"
                className="block w-full rounded-md border border-neutral-700 px-4 py-2 text-center text-sm hover:bg-neutral-800"
              >
                Continue with Google
              </a>
            )}
            {methods.github && (
              <a
                href="/auth/start/github"
                className="block w-full rounded-md border border-neutral-700 px-4 py-2 text-center text-sm hover:bg-neutral-800"
              >
                Continue with GitHub
              </a>
            )}
          </div>
        )}

        {methods?.magic_link && !methods.primary && (
          <div className="border-t border-neutral-800 pt-4">
            {sent ? (
              <p className="text-sm text-neutral-300">
                If that address is valid, a sign-in link is on its way.
              </p>
            ) : (
              <form
                className="flex gap-2"
                onSubmit={async (e) => {
                  e.preventDefault()
                  await send('POST', '/auth/magic', { email })
                  setSent(true)
                }}
              >
                <input
                  type="email"
                  required
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="min-w-0 flex-1 rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm"
                />
                <button className="rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-950 hover:bg-neutral-200">
                  Email link
                </button>
              </form>
            )}
          </div>
        )}

        {methods?.oidc && !methods.primary && (
          <div className="border-t border-neutral-800 pt-4">
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                if (orgSlug) window.location.href = `/auth/oidc/${orgSlug}`
              }}
            >
              <input
                placeholder="org slug (SSO)"
                value={orgSlug}
                onChange={(e) => setOrgSlug(e.target.value)}
                className="min-w-0 flex-1 rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm"
              />
              <button className="rounded-md border border-neutral-700 px-3 py-2 text-sm hover:bg-neutral-800">
                Org sign-in
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  )
}
