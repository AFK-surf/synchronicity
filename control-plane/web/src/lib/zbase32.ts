// Client-side sanity check for pasted device keys: 52 characters of the
// z-base-32 alphabet (a 32-byte Ed25519 key as printed by `synch id`).
// The server re-validates; this only catches paste accidents early.

const ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'

export function isDeviceKey(value: string): boolean {
  if (value.length !== 52) return false
  for (const ch of value) {
    if (!ALPHABET.includes(ch)) return false
  }
  return true
}

export function isDeviceLabel(value: string): boolean {
  return /^[a-z0-9-]{1,63}$/.test(value)
}

export function isDnsLabel(value: string): boolean {
  return (
    /^[a-z0-9-]{1,63}$/.test(value) &&
    !value.startsWith('-') &&
    !value.endsWith('-')
  )
}
