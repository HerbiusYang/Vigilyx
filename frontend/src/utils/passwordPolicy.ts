import i18n from '../i18n'

const MIN_PASSWORD_LENGTH = 12
const PASSPHRASE_PASSWORD_LENGTH = 16

const COMMON_WEAK_PASSWORDS = new Set([
  '12345678',
  '123456789',
  '1234567890',
  '123456789012',
  'admin123',
  'adminadmin',
  'changeme123',
  'letmein123',
  'password',
  'password123',
  'qwerty123',
  'qwertyuiop',
  'welcome123',
])

const WEAK_SEQUENCES = [
  '012345678901234567890123456789',
  'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz',
  'qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm',
]

export function getPasswordPolicyHint(): string {
  return i18n.t('password.policyHint')
}

function normalizePassword(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function countCharacterClasses(password: string): number {
  let classes = 0
  if (/[a-z]/.test(password)) classes += 1
  if (/[A-Z]/.test(password)) classes += 1
  if (/\d/.test(password)) classes += 1
  if (/[^A-Za-z0-9]/.test(password)) classes += 1
  return classes
}

function isObviousSequence(normalizedPassword: string): boolean {
  if (normalizedPassword.length < 8) return false

  return WEAK_SEQUENCES.some((sequence) => {
    const reversed = Array.from(sequence).reverse().join('')
    return sequence.includes(normalizedPassword) || reversed.includes(normalizedPassword)
  })
}

function isCommonWeakPassword(normalizedPassword: string): boolean {
  if (!normalizedPassword) return false

  const repeatedCharacter = normalizedPassword.split('').every((char) => char === normalizedPassword[0])
  return repeatedCharacter || COMMON_WEAK_PASSWORDS.has(normalizedPassword) || isObviousSequence(normalizedPassword)
}

export function validatePasswordInput(password: string): string | null {
  if (password.trim().length === 0) {
    return i18n.t('password.noWhitespaceOnly')
  }

  if (/[\u0000-\u001F\u007F]/.test(password)) {
    return i18n.t('password.noControlChars')
  }

  if (password.length < MIN_PASSWORD_LENGTH) {
    return i18n.t('password.tooShort')
  }

  const normalizedPassword = normalizePassword(password)
  if (isCommonWeakPassword(normalizedPassword)) {
    return i18n.t('password.tooCommon')
  }

  const classes = countCharacterClasses(password)
  if (classes < 2) {
    return i18n.t('password.needTwoClasses')
  }

  if (password.length < PASSPHRASE_PASSWORD_LENGTH && classes < 3) {
    return i18n.t('password.needThreeClasses')
  }

  return null
}

export function getPasswordStrength(password: string): -1 | 0 | 1 | 2 {
  if (!password) return -1

  if (validatePasswordInput(password)) return 0

  const classes = countCharacterClasses(password)
  if (password.length >= 20 || classes >= 4) return 2

  return 1
}
