import { describe, expect, it } from 'vitest'

import en from './locales/en.json'
import zh from './locales/zh.json'

function flattenTranslations(
  value: Record<string, unknown>,
  prefix = '',
  output = new Map<string, string>(),
) {
  for (const [key, child] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (typeof child === 'string') {
      output.set(path, child)
    } else if (child && typeof child === 'object' && !Array.isArray(child)) {
      flattenTranslations(child as Record<string, unknown>, path, output)
    }
  }
  return output
}

function interpolationVariables(value: string) {
  return [...value.matchAll(/{{\s*([^},\s]+)[^}]*}}/g)]
    .map((match) => match[1])
    .sort()
}

describe('translation catalog contract', () => {
  const zhEntries = flattenTranslations(zh)
  const enEntries = flattenTranslations(en)

  it('keeps Chinese and English keys exactly aligned', () => {
    expect([...zhEntries.keys()].sort()).toEqual([...enEntries.keys()].sort())
  })

  it('does not ship blank user-facing translations', () => {
    for (const [key, value] of [...zhEntries, ...enEntries]) {
      expect(value.trim(), `${key} must not be blank`).not.toBe('')
    }
  })

  it('keeps interpolation variables aligned between languages', () => {
    for (const [key, zhValue] of zhEntries) {
      const enValue = enEntries.get(key)
      expect(enValue, `${key} must exist in English`).toBeDefined()
      expect(interpolationVariables(zhValue), `${key} variables differ`).toEqual(
        interpolationVariables(enValue!),
      )
    }
  })
})
