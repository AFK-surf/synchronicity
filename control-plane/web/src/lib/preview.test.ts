import { describe, expect, it } from 'vitest'
import {
  IMAGE_PREVIEW_CAP,
  TEXT_PREVIEW_CAP,
  imageMime,
  previewKind,
  prettyIfJson,
} from './preview'

describe('previewKind', () => {
  it('classifies images by extension, case-insensitively', () => {
    expect(previewKind('logo.png')).toBe('image')
    expect(previewKind('photo.JPEG')).toBe('image')
    expect(previewKind('icon.svg')).toBe('image')
    expect(previewKind('shot.webp')).toBe('image')
  })
  it('classifies text by extension, case-insensitively', () => {
    expect(previewKind('notes.txt')).toBe('text')
    expect(previewKind('state.JSON')).toBe('text')
    expect(previewKind('README.md')).toBe('text')
    expect(previewKind('config.yaml')).toBe('text')
  })
  it('takes a name without a dot as its own extension', () => {
    expect(previewKind('Makefile')).toBe('text')
    expect(previewKind('.gitignore')).toBe('text')
    expect(previewKind('archive.tar.gz')).toBeNull()
  })
  it('refuses what it cannot render', () => {
    expect(previewKind('report.pdf')).toBeNull()
    expect(previewKind('bundle.zip')).toBeNull()
    expect(previewKind('movie.mkv')).toBeNull()
    expect(previewKind('no-extension')).toBeNull()
    expect(previewKind('')).toBeNull()
  })
})

describe('imageMime', () => {
  it('maps each image extension to its type', () => {
    expect(imageMime('a.png')).toBe('image/png')
    expect(imageMime('b.JPG')).toBe('image/jpeg')
    expect(imageMime('c.svg')).toBe('image/svg+xml')
  })
  it('falls back to an opaque stream for non-images', () => {
    expect(imageMime('a.txt')).toBe('application/octet-stream')
  })
})

describe('prettyIfJson', () => {
  it('pretty-prints a .json body', () => {
    expect(prettyIfJson('a.json', '{"b":1}')).toBe('{\n  "b": 1\n}')
  })
  it('shows a .json that does not parse exactly as stored', () => {
    expect(prettyIfJson('x.json', 'not json')).toBe('not json')
  })
  it('leaves every other name alone', () => {
    expect(prettyIfJson('a.md', '{"b":1}')).toBe('{"b":1}')
    expect(prettyIfJson('a.jsonl', '{"b":1}')).toBe('{"b":1}')
  })
})

describe('caps', () => {
  it('are the sizes the UI promises: 1 MiB of text, 16 MiB of image', () => {
    expect(TEXT_PREVIEW_CAP).toBe(1024 * 1024)
    expect(IMAGE_PREVIEW_CAP).toBe(16 * 1024 * 1024)
  })
})
