import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { agoNs, bytes, duration } from './format'

describe('bytes', () => {
  it('uses the largest unit that leaves the number readable', () => {
    expect(bytes(0)).toBe('0 B')
    expect(bytes(512)).toBe('512 B')
    expect(bytes(2048)).toBe('2.0 KB')
    expect(bytes(1024 ** 4)).toBe('1.0 TB')
    // Beyond the last unit it keeps counting rather than falling off it.
    expect(bytes(4 * 1024 ** 4)).toBe('4.0 TB')
  })

  it('renders a value it cannot trust as a dash', () => {
    // These come from a daemon over a tunnel, so the panel has to survive
    // every one of them: a blank cell beats an exception that takes the whole
    // table with it.
    expect(bytes(-1)).toBe('—')
    expect(bytes(Number.NaN)).toBe('—')
    expect(bytes(Number.POSITIVE_INFINITY)).toBe('—')
  })
})

describe('agoNs', () => {
  // The clock is frozen: reading `Date.now()` for the expectation and then
  // again inside the function puts a real millisecond between them, which is
  // enough to turn "5m ago" into "4m ago" on the boundary.
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('reads zero as never rather than as 1970', () => {
    expect(agoNs(0)).toBe('—')
    expect(agoNs(Number.NaN)).toBe('—')
  })

  it('coarsens as the instant recedes', () => {
    const now = Date.now() * 1e6
    expect(agoNs(now)).toBe('just now')
    expect(agoNs(now - 5 * 60 * 1e9)).toBe('5m ago')
    expect(agoNs(now - 3 * 3600 * 1e9)).toBe('3h ago')
    expect(agoNs(now - 9 * 86400 * 1e9)).toBe('9d ago')
  })
})

describe('duration', () => {
  it('uses the coarsest unit that is still exact', () => {
    // A grace window is configured in round units, so reporting 30 days as
    // "29d" would misquote the number the operator typed.
    expect(duration(2_592_000)).toBe('30d')
    expect(duration(3600)).toBe('1h')
    expect(duration(90)).toBe('90s')
    expect(duration(0)).toBe('—')
  })
})
