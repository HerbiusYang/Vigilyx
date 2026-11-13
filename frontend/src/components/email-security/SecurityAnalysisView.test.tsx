import { render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import { createSecurityVerdict } from '../../test/factories'
import type { FusionDetails, ModuleResult, ShadowFusionResult } from '../../types'
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

function renderView(results: ModuleResult[], verdict = createSecurityVerdict()) {
  return render(
    <SecurityAnalysisView
      verdict={verdict}
      moduleResults={results}
      expandedModules={null}
      toggleModuleExpand={vi.fn()}
      onOpenFeedback={vi.fn()}
    />,
  )
}

function fusionDetails(overrides: Partial<FusionDetails> = {}): FusionDetails {
  return {
    fused_bpa: { b: 0.08, d: 0.72, u: 0.2 },
    k_conflict: 0.04,
    risk_single: 0.08,
    eta: 0.3,
    engine_details: [],
    credibility_weights: {},
    fusion_method: 'clustered_ds_v2',
    ...overrides,
  }
}

function shadowFusion(overrides: Partial<ShadowFusionResult> = {}): ShadowFusionResult {
  return {
    model: 'clustered_ds_v2',
    model_version: 2,
    fused_bpa: { b: 0.31, d: 0.24, u: 0.45 },
    k_conflict: 0.12,
    risk_base: 0.421,
    risk_constrained: 0.673,
    epistemic_state: 'threat_supported',
    source_details: [],
    active_constraints: [{
      id: 'confirmed_malicious_anchor',
      lower: 0.67,
      upper: 1,
      basis: ['url:https://malicious.example.test/'],
    }],
    artifact_count: 3,
    fallback_artifact_count: 1,
    ...overrides,
  }
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

  it('renders sub-millisecond module work without displaying a misleading zero', () => {
    renderView([moduleResult({ duration_ms: 0 })])

    expect(screen.getAllByText('<1ms').length).toBeGreaterThan(0)
    expect(screen.queryByText('0ms')).not.toBeInTheDocument()
  })

  it('opens the shared analyst review flow instead of submitting a type directly', () => {
    renderView([])
    expect(screen.getByRole('button', { name: '纠正或确认判定' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '社工攻击' })).not.toBeInTheDocument()
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

describe('SecurityAnalysisView fusion model comparison', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
  })

  it('shows authoritative V2 risk, raw belief and the operator identity minimum separately', () => {
    const primary = shadowFusion({
      fused_bpa: { b: 0.11767, d: 0, u: 0.88233 },
      risk_base: 0.11767, risk_constrained: 0.4, epistemic_state: 'unknown',
      active_constraints: [{ id: 'operator_identity_review_minimum', lower: 0.4, upper: 1, basis: ['identity_anomaly:random_domain'] }],
    })
    renderView([], createSecurityVerdict({
      threat_level: 'medium',
      fusion_details: fusionDetails({ primary_result: primary, risk_single: 0.4, shadow_results: [shadowFusion()] }),
    }))
    const panel = screen.getByTestId('fusion-v2-primary')
    expect(within(panel).getAllByText('40.0%').length).toBeGreaterThan(0)
    expect(within(panel).getAllByText('11.8%').length).toBeGreaterThan(0)
    expect(within(panel).getByRole('note')).toHaveTextContent('原始 Bel 保持不变')
    expect(screen.queryByTestId('fusion-v1')).not.toBeInTheDocument()
    expect(screen.queryByText('V2 实验模型')).not.toBeInTheDocument()
    expect(screen.queryByText('67.3%')).not.toBeInTheDocument()
  })

  it('keeps historical V2 shadows explicitly non-authoritative', () => {
    const olderV2 = shadowFusion({
      model_version: 1,
      risk_base: 0.18,
      risk_constrained: 0.219,
    })
    const latestV2 = shadowFusion()

    renderView([], createSecurityVerdict({
      fusion_details: fusionDetails({
        shadow_results: [
          olderV2,
          shadowFusion({ model: 'llr_shadow', model_version: 1, risk_constrained: 0.91 }),
          latestV2,
        ],
      }),
    }))

    const v2 = screen.getByRole('region', { name: 'V2 实验模型' })

    expect(screen.queryByTestId('fusion-v1')).not.toBeInTheDocument()
    expect(within(v2).getByText('67.3%')).toBeVisible()
    expect(within(v2).queryByText('21.9%')).not.toBeInTheDocument()
    expect(within(v2).getByText('这是历史模型对比结果；请重新分析邮件以生成当前正式 V2 判定。')).toBeVisible()
    expect(within(v2).getByText('confirmed_malicious_anchor [0.67, 1.00]')).toBeVisible()
  })

  it('shows a non-error V2 empty state for historical verdicts', () => {
    renderView([], createSecurityVerdict({ fusion_details: fusionDetails() }))

    expect(screen.getByTestId('fusion-v2-empty')).toHaveTextContent(
      '该历史记录暂无正式 V2 判定，请重新分析邮件以应用当前策略。',
    )
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
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

describe('SecurityAnalysisView semantic observations', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
  })

  it('shows observation-only context and verification states without exposing raw URLs', () => {
    renderView([moduleResult({
      module_id: 'semantic_scan',
      module_name: 'Semantic Analysis',
      threat_level: 'medium',
      confidence: 0.4,
      summary: 'Semantic facts extracted',
      details: {
        semantic_context: {
          schema_version: 3,
          coverage: 'incomplete',
          coverage_reason: 'parser link extraction reached its configured limit',
          claims: [{
            source_span_id: 'plain_text:12:42',
            source_part: 'plain_text',
            actor_role: 'sender',
            target_role: 'recipient',
            speech_act: 'request',
            polarity: 'action',
            quote_or_forward_status: 'original',
            actions: ['verify'],
            objects: ['account'],
            link_ids: ['link-id-1'],
            counter_context_ids: [],
          }],
          links: [{
            link_id: '1234567890abcdef',
            extraction_source: 'href',
            original_url: 'https://secret.example.test/reset?token=private',
            transport_status: 'not_attempted',
            content_status: 'not_observed',
            ownership_status: 'unknown',
          }],
        },
        semantic_scenarios: [{
          scenario_id: 'account_access_request',
          claim_ids: ['plain_text:12:42'],
          link_ids: ['link-id-1'],
          counter_context_ids: [],
          coverage: 'incomplete',
          resolution: 'ambiguous',
          resolution_reason: 'inspection_incomplete',
        }],
      },
    })])

    const observation = screen.getByRole('region', { name: '语义上下文观察' })
    expect(within(observation).getByText('观察态·不参与当前判定')).toBeVisible()
    expect(within(observation).getByText(/来源: 纯文本/)).toBeVisible()
    expect(within(observation).getByText(/Actor: 发件人/)).toBeVisible()
    expect(within(observation).getByText(/Speech act: 请求/)).toBeVisible()
    expect(within(observation).getByText(/账户访问请求/)).toBeVisible()
    expect(within(observation).getByText(/关联关系待确认/)).toBeVisible()
    expect(within(observation).getByText(/检查覆盖不完整/)).toBeVisible()
    expect(within(observation).getByText(/Transport: 未尝试/)).toBeVisible()
    expect(screen.queryByText(/secret\.example\.test/)).not.toBeInTheDocument()
    expect(screen.queryByText(/token=private/)).not.toBeInTheDocument()
  })

  it('shows the shadow-mode text classifier outcome without exposing email-token features', () => {
    renderView([moduleResult({
      module_id: 'semantic_scan',
      module_name: 'Semantic Analysis',
      // Safe modules start collapsed; a Low result renders expanded.
      threat_level: 'low',
      confidence: 0.2,
      summary: 'No semantic risk relation',
      details: {
        semantic_text_classifier: {
          status: 'scored',
          model_id: 'semantic_text_classifier_v2_syn1',
          route: 'lexical',
          cjk_ratio: 0.02,
          probability: 0.72,
          threshold: 0.5,
          active_features: 14,
          text_units: 88,
          fired: true,
          shadow: true,
          top_features: [['t:alicesmith', 1.2]],
        },
      },
    })])

    const classifier = screen.getByRole('region', { name: '本地文本分类器' })
    expect(within(classifier).getByText('影子模式·不参与判定')).toBeVisible()
    expect(within(classifier).getByText('semantic_text_classifier_v2_syn1')).toBeVisible()
    expect(within(classifier).getByText(/结果: 命中/)).toBeVisible()
    expect(within(classifier).getByText(/概率: 72\.0% \/ 阈值 50\.0%/)).toBeVisible()
    expect(within(classifier).getByText(/路由: 词法模型/)).toBeVisible()
    expect(screen.queryByText(/alicesmith/)).not.toBeInTheDocument()
  })

  it('shows an inactive classifier status without a mode badge', () => {
    renderView([moduleResult({
      module_id: 'semantic_scan',
      module_name: 'Semantic Analysis',
      // Safe modules start collapsed; a Low result renders expanded.
      threat_level: 'low',
      confidence: 0.2,
      summary: 'No semantic risk relation',
      details: {
        semantic_text_classifier: {
          // Most common production status: too little text to score.
          status: 'short_text',
          cjk_ratio: 0,
          active_features: 0,
          text_units: 12,
          fired: false,
          top_features: [],
        },
      },
    })])

    const classifier = screen.getByRole('region', { name: '本地文本分类器' })
    expect(within(classifier).getByText(/状态: 文本过短，未评分/)).toBeVisible()
    expect(within(classifier).queryByText('影子模式·不参与判定')).not.toBeInTheDocument()
    expect(within(classifier).queryByText(/结果:/)).not.toBeInTheDocument()
  })

  it('shows the shadow-mode intent model score and member logits', () => {
    renderView([moduleResult({
      module_id: 'semantic_scan',
      module_name: 'Semantic Analysis',
      // Safe modules start collapsed; a Low result renders expanded.
      threat_level: 'low',
      confidence: 0.2,
      summary: 'No semantic risk relation',
      details: {
        semantic_intent_model: {
          status: 'ok',
          mode: 'shadow',
          model_version: 'semantic-intent-v1',
          score: 1.234,
          threshold: 0.4,
          flagged: true,
          members: { bge: 3.1, e5b: 2.25 },
          round_trip_ms: 212,
          input_truncated: true,
        },
      },
    })])

    const intent = screen.getByRole('region', { name: '语义意图模型' })
    expect(within(intent).getByText('影子模式·不参与判定')).toBeVisible()
    expect(within(intent).getByText('semantic-intent-v1')).toBeVisible()
    expect(within(intent).getByText(/结果: 疑似恶意/)).toBeVisible()
    expect(within(intent).getByText(/集成分数: 1\.23 \/ 阈值 0\.40/)).toBeVisible()
    expect(within(intent).getByText(/bge 3\.10 · e5b 2\.25/)).toBeVisible()
    expect(within(intent).getByText(/往返耗时: 212 ms/)).toBeVisible()
    expect(within(intent).getByText('正文过长，只送入了开头和结尾部分。')).toBeVisible()
  })

  it('marks a scored intent model hit as counting toward the verdict, on the row and in the card', () => {
    renderView([moduleResult({
      module_id: 'semantic_scan',
      module_name: 'Semantic Analysis',
      threat_level: 'low',
      confidence: 0.55,
      summary: 'Semantic intent model score 0.93 reached threshold 0.90; review required',
      categories: ['semantic_intent_model'],
      details: {
        score: 0.2,
        semantic_mode: 'intent_model',
        semantic_intent_model: {
          status: 'ok',
          mode: 'scored',
          model_version: 'semantic-intent-v2',
          score: 0.934,
          threshold: 0.9,
          dev_threshold: -0.24,
          flagged: true,
          members: { m3: 4.1, e5b: 3.2 },
          round_trip_ms: 640,
          input_truncated: false,
        },
      },
    })])

    expect(screen.getByTestId('semantic-intent-tag')).toHaveTextContent('意图模型 0.93')
    expect(screen.queryByText('AI 未配置')).not.toBeInTheDocument()
    const intent = screen.getByRole('region', { name: '语义意图模型' })
    expect(within(intent).getByText('已计入判定')).toBeVisible()
    expect(within(intent).queryByText('影子模式·不参与判定')).not.toBeInTheDocument()
    expect(within(intent).getByText(/原有的规则分析已停用/)).toBeVisible()
    expect(within(intent).getByText(/集成分数: 0\.93 \/ 阈值 0\.90/)).toBeVisible()
  })

  it('shows an intent model failure without a score', () => {
    renderView([moduleResult({
      module_id: 'semantic_scan',
      module_name: 'Semantic Analysis',
      threat_level: 'low',
      confidence: 0.2,
      summary: 'No semantic risk relation',
      details: {
        semantic_intent_model: { status: 'error', mode: 'shadow', round_trip_ms: 5, input_truncated: false, reason: 'http 503' },
      },
    })])

    const intent = screen.getByRole('region', { name: '语义意图模型' })
    expect(within(intent).getByText(/状态: 失败/)).toBeVisible()
    expect(within(intent).getByText(/原因: http 503/)).toBeVisible()
    expect(within(intent).queryByText(/结果:/)).not.toBeInTheDocument()
    expect(within(intent).queryByText(/集成分数/)).not.toBeInTheDocument()
  })

  it('lists attachment text analyzed by the semantic engine and skipped attachments', () => {
    renderView([moduleResult({
      module_id: 'semantic_scan',
      module_name: 'Semantic Analysis',
      threat_level: 'medium',
      confidence: 0.6,
      summary: 'Qualified extortion',
      details: {
        semantic_attachment_sources: {
          sources: [{
            filename: 'notice.txt',
            attachment_hash: 'abc',
            text_bytes: 120,
            finding_count: 1,
            semantic_context: { claims: [] },
            text_classifier: {
              status: 'scored', probability: 0.81, threshold: 0.5, fired: true, shadow: true,
              text_units: 24, active_features: 9, below_training_length: true, top_features: [],
            },
          }],
          skipped: [{ filename: 'scan.pdf', reason: 'size_limit' }],
        },
      },
    })])

    const section = screen.getByRole('region', { name: '附件语义分析' })
    expect(within(section).getByText('notice.txt')).toBeVisible()
    expect(within(section).getByText(/语义发现: 1/)).toBeVisible()
    expect(within(section).getByText(/本地文本分类器: 已评分 · 命中 · 81\.0%/)).toBeVisible()
    expect(within(section).getByText(/scan\.pdf \(超出大小上限\)/)).toBeVisible()
  })
})
