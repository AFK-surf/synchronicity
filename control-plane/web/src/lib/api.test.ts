import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, setCloudHosting, setCsrf } from './api'

// The client is a thin shell over `fetch`, so the stub is a thin shell too:
// enough of a `Response` for `handle` to read, and nothing else. Built by
// hand rather than with the platform `Response` so the test says exactly which
// three fields the client depends on.
function stubFetch(status: number, body: unknown) {
  const fetchMock = vi.fn(async () => {
    return {
      status,
      ok: status >= 200 && status < 300,
      json: async () => body,
    } as unknown as Response
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('setCloudHosting', () => {
  it('puts the switch to the network route with the CSRF header', async () => {
    setCsrf('csrf-token')
    const fetchMock = stubFetch(200, {
      ok: true,
      soa_serial: 4183,
      result: { enabled: true, devices_removed: 0 },
    })

    await setCloudHosting('acme', 'prod', true)

    const [path, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ]
    expect(path).toBe('/api/orgs/acme/networks/prod/cloud-hosting/enabled')
    expect(init.method).toBe('PUT')
    expect(init.body).toBe('{"enabled":true}')
    expect(init.headers).toMatchObject({
      'x-csrf': 'csrf-token',
      'content-type': 'application/json',
    })
  })

  it('reads the payload out of the zone-mutation envelope', async () => {
    // Both directions reshape the zone, so this route answers `{ok,
    // soa_serial, result}` like every other zone-shaping call and *not* a flat
    // `{ok, enabled}`. Turning it off reports the hosted devices the same
    // commit removed, which is the number worth showing back.
    stubFetch(200, {
      ok: true,
      soa_serial: 4184,
      result: { enabled: false, devices_removed: 1 },
    })

    const reply = await setCloudHosting('acme', 'prod', false)

    expect(reply.soa_serial).toBe(4184)
    expect(reply.result).toEqual({ enabled: false, devices_removed: 1 })
  })

  it('raises the server refusal with its code', async () => {
    // A member flipping an admin-gated switch: the code is what the UI shows,
    // so it has to survive the client.
    stubFetch(403, {
      error: { code: 'forbidden', message: 'requires admin role' },
    })

    const failure = await setCloudHosting('acme', 'prod', true).catch(
      (e: unknown) => e,
    )

    expect(failure).toBeInstanceOf(ApiError)
    expect((failure as ApiError).status).toBe(403)
    expect((failure as ApiError).code).toBe('forbidden')
    expect((failure as ApiError).message).toBe('requires admin role')
  })
})
