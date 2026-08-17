import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import { createSecurityVerdict } from '../../test/factories'
import type { ModuleResult } from '../../types'
import SecurityAnalysisView, { getModuleExecutionState } from './SecurityAnalysisView'

function moduleResult(overrides: Partial<ModuleResult> = {}): ModuleResult {
  return {
    module_id: 'link_reputation',
    module_name: 'URL Reputation Query',
    pillar: 'link',
    threat_level: 'safe',
    confidence: 0,
    categories: [],
    summary: 'No reputation finding',
    evidence: [],
    details: {},
    duration_ms: 0,
    analyzed_at: '2026-08-11T02:38:36Z',
    ...overrides,
  }
}

function renderView(results: ModuleResult[]) {
  return render(
    <SecurityAnalysisView
      verdict={createSecurityVerdict()}
      moduleResults={results}
      expandedModules={null}
      toggleModuleExpand={vi.fn()}
      feedbackDone={false}
      feedbackType={null}
      feedbackComment=""
      feedbackSubmitting={false}
      setFeedbackType={vi.fn()}
      setFeedbackComment={vi.fn()}
      submitFeedback={vi.fn()}
    />,
  )
}

describe('SecurityAnalysisView module availability', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
  })

  it('shows and expands a timed-out link reputation module instead of labeling it safe', () => {
    const timedOut = moduleResult({
      categories: ['inspection_module_timeout'],
      summary: 'Module timed out; inspection is incomplete',
      details: { execution_status: 'timeout', timeout_ms: 8000 },
      duration_ms: 8000,
    })

    renderView([timedOut])

    expect(screen.getByRole('status')).toHaveTextContent('链接信誉检测不可用')
    expect(screen.getAllByText('检测超时').length).toBeGreaterThan(0)
    expect(screen.getByText('Module timed out; inspection is incomplete')).toBeVisible()
    expect(screen.getAllByText('安全')).toHaveLength(1)
  })

  it('recognizes the persisted failure category when details are absent', () => {
    const failed = moduleResult({ categories: ['inspection_module_failed'], details: null })

    expect(getModuleExecutionState(failed)).toBe('failed')
  })

  it('does not show a degradation notice for a completed safe result', () => {
    renderView([moduleResult()])

    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(screen.getAllByText('安全').length).toBeGreaterThanOrEqual(2)
  })

  it('localizes every analyst feedback option without leaking i18n keys', () => {
    renderView([])

    expect(screen.getByRole('button', { name: '社工攻击' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '其他威胁' })).toBeInTheDocument()
    expect(screen.queryByText('emailSecurity.feedbackSocialEngineering')).not.toBeInTheDocument()
    expect(screen.queryByText('emailSecurity.feedbackOtherThreat')).not.toBeInTheDocument()
  })

  const previouslyUnlocalizedModules = [
    ['html_pixel_art', 'HTML Pixel Art Detection', 'HTML 像素图扫描', 'HTML Pixel-Art Scan'],
    ['landing_page_scan', 'Landing Page Scan backend', '落地页扫描', 'Landing Page Scan'],
    ['attach_qr_scan', 'Attachment QR Scan backend', '附件二维码扫描', 'Attachment QR Scan'],
    ['rmm_detect', 'RMM Weaponization Detection', '远程管理诱导检测', 'Remote Management Lure Detection'],
    ['prompt_injection_scan', 'Prompt Injection Detection', '提示注入扫描', 'Prompt Injection Scan'],
    ['aitm_detect', 'AitM Phishing Detection', '中间人钓鱼检测', 'AiTM Detection'],
    ['toad_detect', 'TOAD backend label', '电话回拨钓鱼检测', 'Telephone-Oriented Attack Detection'],
    ['sandbox_scan', 'Sandbox backend label', '附件沙箱检测', 'Attachment Sandbox Scan'],
  ] as const

  it('localizes every extended module name in Chinese without leaking backend labels or i18n keys', () => {
    renderView(previouslyUnlocalizedModules.map(([moduleId, backendName]) => moduleResult({
      module_id: moduleId,
      module_name: backendName,
    })))

    for (const [, backendName, chineseName] of previouslyUnlocalizedModules) {
      expect(screen.getAllByText(chineseName).length).toBeGreaterThan(0)
      expect(screen.queryByText(backendName)).not.toBeInTheDocument()
    }
    expect(screen.queryByText('emailSecurity.modulePixelArt')).not.toBeInTheDocument()
  })

  it('uses the same complete mapping when English is selected', async () => {
    await i18n.changeLanguage('en')
    renderView(previouslyUnlocalizedModules.map(([moduleId, backendName]) => moduleResult({
      module_id: moduleId,
      module_name: backendName,
    })))

    for (const [, backendName, , englishName] of previouslyUnlocalizedModules) {
      expect(screen.getAllByText(englishName).length).toBeGreaterThan(0)
      expect(screen.queryByText(backendName)).not.toBeInTheDocument()
    }
  })
})

describe('SecurityAnalysisView LLM second opinion', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
  })

  function semanticModule(llmAnalysis: Record<string, unknown>): ModuleResult {
    return moduleResult({
      module_id: 'semantic_scan',
      module_name: 'Semantic Analysis',
      threat_level: 'medium',
      confidence: 0.5,
      categories: ['llm_injection_suspected'],
      summary: 'Local NLP uncertain; LLM second opinion consulted',
      details: { nlp_details: { llm_analysis: llmAnalysis } },
    })
  }

  it('surfaces a suspected prompt injection that the backend flagged on the LLM card', () => {
    // PoC: before the fix getLlmAnalysis dropped injection_suspected, so an
    // email carrying "ignore previous instructions" could steer the LLM to
    // answer "safe" and the UI showed that verdict with zero warning.
    renderView([semanticModule({
      provider: 'claude',
      model: 'claude-sonnet',
      verdict: 'safe',
      confidence: 0.62,
      reasoning: 'This appears to be a routine notification.',
      injection_suspected: true,
    })])

    expect(screen.getByText('疑似提示注入')).toBeInTheDocument()
    expect(screen.getByText('LLM 研判可能受邮件内容影响，仅供参考')).toBeInTheDocument()
    // The injected-content category is rendered via the localized label layer.
    expect(screen.getByText('疑似 LLM 提示注入')).toBeInTheDocument()
    expect(screen.queryByText('llm_injection_suspected')).not.toBeInTheDocument()
  })

  it('keeps the advisory hint but no injection badge when the LLM answer is clean', () => {
    renderView([semanticModule({
      provider: 'openai',
      model: 'gpt-x',
      verdict: 'medium',
      confidence: 0.55,
      reasoning: 'Urgency wording detected.',
      injection_suspected: false,
    })])

    expect(screen.getByText('LLM 研判可能受邮件内容影响，仅供参考')).toBeInTheDocument()
    expect(screen.queryByText('疑似提示注入')).not.toBeInTheDocument()
  })

  it('falls back to the raw id for categories without a translation yet', () => {
    renderView([moduleResult({
      threat_level: 'low',
      confidence: 0.2,
      categories: ['phishing', 'some_future_category'],
      summary: 'One known and one unknown category',
    })])

    expect(screen.getByText('钓鱼')).toBeInTheDocument()
    expect(screen.getByText('some_future_category')).toBeInTheDocument()
  })
})
