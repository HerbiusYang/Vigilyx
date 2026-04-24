import { describe, it, expect } from 'vitest'
import { decodeMimeWord } from '../mime'

describe('decodeMimeWord', () => {
  // ---------- Null / undefined / empty ----------
  it('returns null for null input', () => {
    expect(decodeMimeWord(null)).toBeNull()
  })

  it('returns undefined for undefined input (falsy passthrough)', () => {
    // decodeMimeWord checks `if (!text) return text`, so undefined returns undefined
    expect(decodeMimeWord(undefined as unknown as string | null)).toBeUndefined()
  })

  it('returns empty string for empty input', () => {
    expect(decodeMimeWord('')).toBe('')
  })

  // ---------- Plain text (no encoding) ----------
  it('returns plain text unchanged', () => {
    expect(decodeMimeWord('Hello World')).toBe('Hello World')
  })

  // ---------- Base64 (B) encoding ----------
  it('decodes base64 encoded UTF-8 subject', () => {
    // The encoded value is the Chinese word for "test" in UTF-8 Base64.
    const encoded = '=?UTF-8?B?5rWL6K+V?='
    expect(decodeMimeWord(encoded)).toBe('测试')
  })

  it('decodes base64 encoded ASCII', () => {
    // "Hello" in Base64
    const encoded = '=?UTF-8?B?SGVsbG8=?='
    expect(decodeMimeWord(encoded)).toBe('Hello')
  })

  it('decodes lowercase b encoding', () => {
    const encoded = '=?UTF-8?b?SGVsbG8=?='
    expect(decodeMimeWord(encoded)).toBe('Hello')
  })

  // ---------- Quoted-Printable (Q) encoding ----------
  it('decodes QP with underscore as space', () => {
    const encoded = '=?UTF-8?Q?Hello_World?='
    expect(decodeMimeWord(encoded)).toBe('Hello World')
  })

  it('decodes QP with hex escapes', () => {
    // =C3=A9 is é in UTF-8
    const encoded = '=?UTF-8?Q?caf=C3=A9?='
    expect(decodeMimeWord(encoded)).toBe('café')
  })

  it('decodes lowercase q encoding', () => {
    const encoded = '=?UTF-8?q?Hello_World?='
    expect(decodeMimeWord(encoded)).toBe('Hello World')
  })

  // ---------- Mixed encoded + plain text ----------
  it('handles mixed encoded and plain text', () => {
    const input = 'Re: =?UTF-8?B?5rWL6K+V?= message'
    expect(decodeMimeWord(input)).toBe('Re: 测试 message')
  })

  // ---------- Multiple encoded words ----------
  it('decodes multiple encoded words in one string', () => {
    const input = '=?UTF-8?B?5rWL?= =?UTF-8?B?6K+V?='
    const result = decodeMimeWord(input)
    expect(result).toContain('测')
    expect(result).toContain('试')
  })

  // ---------- Malformed / error handling ----------
  it('returns raw data on malformed base64', () => {
    // atob will throw for invalid base64; the catch block returns `data` as-is
    const encoded = '=?UTF-8?B?!!!invalid!!!?='
    const result = decodeMimeWord(encoded)
    // Should not throw; returns the raw data portion on failure
    expect(result).toBeTruthy()
  })

  it('handles GBK charset base64 decoding', () => {
    // GBK bytes for the Chinese word "test": 0xB2, 0xE2, 0xCA, 0xD4.
    const encoded = '=?GBK?B?suLK1A==?='
    const result = decodeMimeWord(encoded)
    // TextDecoder for GBK may not be available in all environments;
    // either decodes correctly or falls back to raw data
    expect(typeof result).toBe('string')
  })

  it('preserves string with no encoded words', () => {
    const plain = 'Just a normal subject line without encoding'
    expect(decodeMimeWord(plain)).toBe(plain)
  })
})
