import { describe, it, expect } from 'vitest'
import { validatePasswordInput, getPasswordStrength } from '../passwordPolicy'

describe('validatePasswordInput', () => {
  // ---------- Length & whitespace ----------
  it('rejects password shorter than 12 characters', () => {
    expect(validatePasswordInput('Abc!1234567')).toBe('新密码至少需要 12 位')
  })

  it('rejects empty string', () => {
    expect(validatePasswordInput('')).toBe('新密码不能仅由空白字符组成')
  })

  it('rejects whitespace-only password', () => {
    expect(validatePasswordInput('            ')).toBe('新密码不能仅由空白字符组成')
  })

  it('rejects tab/newline whitespace', () => {
    expect(validatePasswordInput('   \t  \n   ')).not.toBeNull()
  })

  it('rejects password with null byte control character', () => {
    expect(validatePasswordInput('SecureP@ss\x00word1')).toBe('新密码不能包含控制字符')
  })

  it('rejects password with low control characters', () => {
    expect(validatePasswordInput('Pass\x1Fword!123')).toBe('新密码不能包含控制字符')
  })

  it('rejects password with DEL control character', () => {
    expect(validatePasswordInput('Pass\x7Fword!123')).toBe('新密码不能包含控制字符')
  })

  // ---------- Common weak passwords ----------
  // normalizePassword: lowercase + strip non-alphanumeric
  // "Password123!" → "password123" which is in COMMON_WEAK_PASSWORDS
  it('rejects "password123" variant (Password123!)', () => {
    expect(validatePasswordInput('Password123!')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  // "changeme123!X" → "changeme123x" — NOT in set (set has "changeme123")
  // But "Welcome123!!" → "welcome123" which IS in set — only if length matches
  // Actually normalized "welcome123" from "Welcome123!!" — that's 10 chars normalized
  // The set has "welcome123" (10 chars). "Welcome123!!" is 12 raw chars, normalized "welcome123" is in set.
  it('rejects "welcome123" variant', () => {
    expect(validatePasswordInput('Welcome123!!')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  // "Letmein123!!" → "letmein123" which IS in set
  it('rejects "letmein123" variant', () => {
    expect(validatePasswordInput('Letmein123!!')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  // ---------- Repeated characters ----------
  it('rejects password with all repeated characters', () => {
    expect(validatePasswordInput('aaaaaaaaaaaa')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  it('rejects repeated characters after normalization', () => {
    // "AAAAAAAAAAAA" normalized → "aaaaaaaaaaaa" all same char
    expect(validatePasswordInput('AAAAAAAAAAAA')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  it('rejects "111111111111" as repeated character', () => {
    expect(validatePasswordInput('111111111111')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  // ---------- Keyboard / alphabetical sequences ----------
  // normalizePassword("Qwertyuiop!1") → "qwertyuiop1"
  // isObviousSequence checks if WEAK_SEQUENCES string includes "qwertyuiop1"
  // The keyboard sequence is "qwertyuiopasdfghjklzxcvbnm..." which does NOT contain "qwertyuiop1"
  // So this is NOT rejected as a sequence. But "qwertyuiop" (normalized from "Qwertyuiop!!") IS in COMMON_WEAK_PASSWORDS set
  it('rejects "qwertyuiop" in COMMON_WEAK_PASSWORDS', () => {
    expect(validatePasswordInput('Qwertyuiop!!')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  // normalizePassword("Abcdefghijkl") → "abcdefghijkl" which is substring of alpha sequence
  it('rejects alphabetical sequence abcdefghijkl', () => {
    expect(validatePasswordInput('Abcdefghijkl')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  // normalizePassword("012345678901") → "012345678901" which is substring of numeric sequence
  it('rejects numeric sequence 012345678901', () => {
    expect(validatePasswordInput('012345678901')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  // normalizePassword("123456789012") → in COMMON_WEAK_PASSWORDS set
  it('rejects 123456789012 in COMMON_WEAK_PASSWORDS', () => {
    expect(validatePasswordInput('123456789012')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  // ---------- Character class requirements (12-15 chars) ----------
  it('rejects 12-char password with only 2 character classes (lower+digits)', () => {
    // "abcxyz123456" → normalized "abcxyz123456" (not in weak list/sequences)
    // 2 classes (lower + digits) < 3 required for 12-15 chars
    expect(validatePasswordInput('abcxyz123456')).toBe(
      '12-15 位密码需至少包含大写字母、小写字母、数字、符号中的 3 类',
    )
  })

  it('accepts 12-char password with 3 character classes', () => {
    expect(validatePasswordInput('Abcxyz123456')).toBeNull()
  })

  it('accepts 15-char password with 3 character classes', () => {
    expect(validatePasswordInput('Abcxyz123456abc')).toBeNull()
  })

  it('rejects 14-char password with only upper+lower that is also a sequence', () => {
    // "AbcdeFGHijklmn" → normalized "abcdefghijklmn" which is a substring of alpha sequence
    // So it's rejected as "common/simple" BEFORE reaching the class check
    expect(validatePasswordInput('AbcdeFGHijklmn')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  it('rejects 14-char password with only 2 classes that is not a sequence', () => {
    // "AbMnXyAbMnXyAb" — normalized "abmnxyabmnxyab" not in sequences
    // 2 classes: upper + lower
    expect(validatePasswordInput('AbMnXyAbMnXyAb')).toBe(
      '12-15 位密码需至少包含大写字母、小写字母、数字、符号中的 3 类',
    )
  })

  // ---------- Character class requirements (>= 16 chars) ----------
  it('accepts 16-char password with 2 classes that is not a sequence', () => {
    // Use a pattern that won't match any sequence
    expect(validatePasswordInput('HxMzKqWpRtYsLnBv')).toBeNull()
  })

  it('rejects 16-char password with only 1 class that is not a sequence', () => {
    // "xzmqwprtysulnbvk" → all lowercase, 1 class < 2 required
    // normalizePassword → same string, not in set, not repeated, 
    // but need to make sure it's not a sequence either
    expect(validatePasswordInput('xzmqwprtysulnbvk')).toBe(
      '新密码至少需要包含 2 类字符',
    )
  })

  it('accepts 20-char passphrase with 2 classes (not a sequence)', () => {
    expect(validatePasswordInput('Thxmzisalongsecurval')).toBeNull()
  })

  // ---------- Valid passwords ----------
  it('accepts strong password with 4 classes', () => {
    expect(validatePasswordInput('Str0ng!Pass@9')).toBeNull()
  })

  it('accepts 12-char with 3 classes including symbols', () => {
    expect(validatePasswordInput('hello!World1')).toBeNull()
  })

  // ---------- Edge cases ----------
  it('handles exactly 12 characters at boundary', () => {
    // 11 chars → too short
    expect(validatePasswordInput('Abc!1234567')).toBe('新密码至少需要 12 位')
    // 12 chars with 3 classes → valid
    expect(validatePasswordInput('Abc!12345678')).toBeNull()
  })

  it('handles exactly 16 characters at boundary (15 vs 16)', () => {
    // 15 chars with 2 classes (upper+lower), not a sequence
    expect(validatePasswordInput('HxMzKqWpRtYsLnB')).toBe(
      '12-15 位密码需至少包含大写字母、小写字母、数字、符号中的 3 类',
    )
    // 16 chars with 2 classes (upper+lower), not a sequence → OK
    expect(validatePasswordInput('HxMzKqWpRtYsLnBv')).toBeNull()
  })

  it('accepts Unicode characters (Chinese passphrase)', () => {
    // Unicode chars count as "symbol" class since they match [^A-Za-z0-9]
    expect(validatePasswordInput('这是一个安全的密码test1')).toBeNull()
  })

  // Sequences that include digits mixed in are NOT caught by isObviousSequence
  // because normalizePassword strips only non-alphanumeric, keeping digits
  it('rejects "adminadmin" variant from COMMON_WEAK_PASSWORDS', () => {
    // "Adminadmin!!" → normalized "adminadmin" which IS in set
    expect(validatePasswordInput('Adminadmin!!')).toBe(
      '新密码过于常见或模式过于简单，请使用更强的密码',
    )
  })

  it('accepts a non-trivial 12-char password with 3 classes', () => {
    expect(validatePasswordInput('MyP@ss789xyz')).toBeNull()
  })
})

describe('getPasswordStrength', () => {
  it('returns -1 for empty string', () => {
    expect(getPasswordStrength('')).toBe(-1)
  })

  it('returns 0 for weak password (too short)', () => {
    expect(getPasswordStrength('Abc!123')).toBe(0)
  })

  it('returns 0 for weak password (common)', () => {
    expect(getPasswordStrength('Password123!')).toBe(0)
  })

  it('returns 0 for password with only 1 class >= 16 chars', () => {
    // All lowercase, not a sequence
    expect(getPasswordStrength('xzmqwprtysulnbvk')).toBe(0)
  })

  it('returns 0 for alphabetical sequence', () => {
    // "Abcdefghijklmnop" → normalized to sequence → rejected
    expect(getPasswordStrength('Abcdefghijklmnop')).toBe(0)
  })

  it('returns 1 for medium password (valid, 12-19 chars, < 4 classes)', () => {
    expect(getPasswordStrength('Abcxyz123456')).toBe(1)
  })

  it('returns 2 for strong password (>= 20 chars, non-sequence)', () => {
    expect(getPasswordStrength('Thxmzisalongsecurval')).toBe(2)
  })

  it('returns 2 for password with 4 character classes', () => {
    expect(getPasswordStrength('Str0ng!Pass@9')).toBe(2)
  })

  it('returns 1 for 16+ chars with 2 classes (valid, not sequence)', () => {
    expect(getPasswordStrength('HxMzKqWpRtYsLnBv')).toBe(1)
  })
})
