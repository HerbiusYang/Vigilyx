import { beforeEach, describe, expect, it } from 'vitest'

import i18n from '../../i18n'
import type { DispositionRule } from '../../types'
import { describeRuleConditions } from './ruleFormHelpers'

function ruleWithCategories(categories: string[]): DispositionRule {
  return {
    id: 'rule-1',
    name: 'test rule',
    enabled: true,
    priority: 1,
    conditions: JSON.stringify({ categories }),
    actions: JSON.stringify([{ type: 'log' }]),
    created_at: '2026-08-15T00:00:00Z',
    updated_at: '2026-08-15T00:00:00Z',
  }
}

describe('describeRuleConditions category chips', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
  })

  it('renders known detection categories as localized labels instead of raw snake_case', () => {
    // PoC: before the fix the chip joined raw ids, so a rule matching the
    // fourth-round llm_injection_suspected category displayed raw English
    // snake_case to Chinese operators.
    const chips = describeRuleConditions(ruleWithCategories(['llm_injection_suspected', 'phishing']))

    expect(chips).toHaveLength(1)
    expect(chips[0]).toContain('疑似 LLM 提示注入')
    expect(chips[0]).toContain('钓鱼')
    expect(chips[0]).not.toContain('llm_injection_suspected')
  })

  it('keeps unknown categories visible as the raw id', () => {
    const chips = describeRuleConditions(ruleWithCategories(['some_future_category']))

    expect(chips[0]).toContain('some_future_category')
  })

  it('uses the English labels when English is selected', async () => {
    await i18n.changeLanguage('en')
    const chips = describeRuleConditions(ruleWithCategories(['llm_injection_suspected']))

    expect(chips[0]).toContain('Suspected LLM Prompt Injection')
    expect(chips[0]).not.toContain('llm_injection_suspected')
  })
})
