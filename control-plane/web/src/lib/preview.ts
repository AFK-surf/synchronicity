// What the file browser will preview, and how much of it.
//
// The download endpoint answers every file as application/octet-stream with
// Content-Disposition: attachment, because stored files are hostile content:
// one HTML document rendered on the control plane's origin would be a
// stored-XSS machine. A preview works inside that boundary — the SPA
// fetches the bytes and renders them as escaped text or as an image
// element, neither of which ever reaches the HTML parser. Classification is
// by extension, the one hint a name carries; everything else downloads, as
// before.

// Images the browser can decode from an object URL. An SVG loaded through
// an <img> has scripting disabled, so it previews as safely as the rest.
const IMAGE_MIME: Record<string, string> = {
  avif: 'image/avif',
  bmp: 'image/bmp',
  gif: 'image/gif',
  ico: 'image/x-icon',
  jpeg: 'image/jpeg',
  jpg: 'image/jpeg',
  png: 'image/png',
  svg: 'image/svg+xml',
  webp: 'image/webp',
}

// Text is shown as source, never parsed — HTML and XML included.
const TEXT_EXTENSIONS = new Set([
  // Notes and documents.
  'csv',
  'log',
  'markdown',
  'md',
  'mdx',
  'rst',
  'tsv',
  'txt',
  // Structured config.
  'cfg',
  'conf',
  'env',
  'ini',
  'json',
  'jsonc',
  'jsonl',
  'properties',
  'toml',
  'xml',
  'yaml',
  'yml',
  // Source code, rendered as source.
  'bash',
  'c',
  'cc',
  'cjs',
  'cpp',
  'css',
  'diff',
  'gleam',
  'go',
  'h',
  'hh',
  'htm',
  'html',
  'java',
  'js',
  'jsx',
  'kt',
  'mjs',
  'patch',
  'py',
  'rb',
  'rs',
  'sh',
  'sql',
  'swift',
  'ts',
  'tsx',
  'zig',
  'zsh',
  // Extensionless files, listed by whole name.
  'changelog',
  'dockerfile',
  'gitattributes',
  'gitignore',
  'justfile',
  'license',
  'makefile',
  'readme',
])

// A preview lands in the tab's memory, where a download never does, so both
// kinds are capped: text past the cap previews as its first MiB (the
// endpoint serves single ranges), while a larger image declines to load.
export const TEXT_PREVIEW_CAP = 1_048_576
export const IMAGE_PREVIEW_CAP = 16_777_216

function extOf(name: string): string {
  const dot = name.lastIndexOf('.')
  // No dot, or only a leading one: the whole name is the key, which is how
  // extensionless files (Makefile, LICENSE, .gitignore) get listed.
  if (dot === -1) return name.toLowerCase()
  if (dot === 0) return name.slice(1).toLowerCase()
  return name.slice(dot + 1).toLowerCase()
}

export function previewKind(name: string): 'image' | 'text' | null {
  const ext = extOf(name)
  if (ext in IMAGE_MIME) return 'image'
  return TEXT_EXTENSIONS.has(ext) ? 'text' : null
}

// The type stamped on the preview blob. Only previewable names ask.
export function imageMime(name: string): string {
  return IMAGE_MIME[extOf(name)] ?? 'application/octet-stream'
}

// A .json preview reads best pretty-printed; everything else — including a
// .json that does not parse — is shown exactly as stored.
export function prettyIfJson(name: string, body: string): string {
  if (extOf(name) !== 'json') return body
  try {
    return JSON.stringify(JSON.parse(body), null, 2)
  } catch {
    return body
  }
}
