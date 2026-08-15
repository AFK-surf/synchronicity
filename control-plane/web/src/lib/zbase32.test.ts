import { describe, expect, it } from 'vitest'
import { isDeviceKey, isDeviceLabel, isDnsLabel } from './zbase32'

describe('isDeviceKey', () => {
  it('accepts a 52-char z-base-32 key', () => {
    expect(
      isDeviceKey('g6a745g6j3uikptr6r1y7bri331jny6icdjiwfm6sh4uc38p73fo'),
    ).toBe(true)
  })
  it('rejects wrong length', () => {
    expect(isDeviceKey('abc')).toBe(false)
    expect(isDeviceKey('')).toBe(false)
  })
  it('rejects characters outside the alphabet', () => {
    // l, v, 0 and 2 are not in z-base-32
    expect(
      isDeviceKey('l6a745g6j3uikptr6r1y7bri331jny6icdjiwfm6sh4uc38p73fo'),
    ).toBe(false)
    expect(
      isDeviceKey('06a745g6j3uikptr6r1y7bri331jny6icdjiwfm6sh4uc38p73fo'),
    ).toBe(false)
  })
})

describe('labels', () => {
  it('device labels allow leading/trailing hyphens', () => {
    expect(isDeviceLabel('-nas-')).toBe(true)
    expect(isDeviceLabel('nas')).toBe(true)
    expect(isDeviceLabel('NAS')).toBe(false)
    expect(isDeviceLabel('')).toBe(false)
  })
  it('dns labels forbid leading/trailing hyphens', () => {
    expect(isDnsLabel('-bad')).toBe(false)
    expect(isDnsLabel('bad-')).toBe(false)
    expect(isDnsLabel('good-name')).toBe(true)
  })
})
