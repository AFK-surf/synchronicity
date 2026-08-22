/// Rendering helpers for numbers that arrive from a daemon.
///
/// Everything here takes a value the control plane relayed rather than
/// computed, so every function has to survive a missing field, a negative one,
/// or one large enough to be nonsense. A helper that throws here blanks the
/// panel it was called from — these pages have no error boundary above them.

/// A byte count, in the largest unit that leaves it readable.
export function bytes(size: number): string {
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

/// How long ago a unix-nanosecond instant was, in the coarsest unit still
/// true. `0` is the daemon's "never", not the epoch.
export function agoNs(at: number): string {
  if (!Number.isFinite(at) || at <= 0) return '—'
  const secs = Math.floor(Date.now() / 1000 - at / 1e9)
  if (secs < 60) return 'just now'
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`
  return `${Math.floor(secs / 86400)}d ago`
}

/// A duration in seconds, in the coarsest unit that is still exact — a grace
/// window is configured in round days or hours, and rounding it to "29d"
/// would misreport the number an operator typed.
export function duration(secs: number): string {
  if (!Number.isFinite(secs) || secs <= 0) return '—'
  const units: [number, string][] = [
    [86400, 'd'],
    [3600, 'h'],
    [60, 'm'],
  ]
  for (const [size, suffix] of units) {
    if (secs % size === 0) return `${secs / size}${suffix}`
  }
  return `${secs}s`
}
