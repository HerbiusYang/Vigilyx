import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import i18n from '../../i18n'
import { createSecurityVerdict } from '../../test/factories'
import type { ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'
import FeedbackPanel from './FeedbackPanel'

vi.mock('../../utils/api', () => ({ apiFetch: vi.fn() }))
vi.mock('./DsLearningStatus', () => ({ default: () => null }))
const fetchMock = vi.mocked(apiFetch)

function response<T>(data: T, success = true, error: string | null = null): Response {
  return { ok: true, json: vi.fn().mockResolvedValue({ success, data, error } satisfies ApiResponse<T>) } as unknown as Response
}

function mount(overrides: Partial<React.ComponentProps<typeof FeedbackPanel>> = {}) {
  const props = {
    sessionId: 'session-001', verdict: createSecurityVerdict(), open: true,
    onClose: vi.fn(), onRefreshVerdict: vi.fn().mockResolvedValue(null), ...overrides,
  }
  return { ...render(<FeedbackPanel {...props} />), props }
}

const posts = () => fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')

describe('FeedbackPanel explicit analyst feedback', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
    fetchMock.mockReset()
    fetchMock.mockImplementation(async (_input, init) => init?.method === 'POST'
      ? response({ learning_status: 'recorded' })
      : response({ feedbacks: [], learning_status: null }))
  })

  it('does not submit or inherit model severity when an analyst selects a type', async () => {
    const user = userEvent.setup()
    mount({ verdict: createSecurityVerdict({ threat_level: 'critical' }) })
    await user.click(screen.getByRole('button', { name: '钓鱼邮件' }))
    expect(posts()).toHaveLength(0)
    expect(screen.getByLabelText('人工确认等级')).toHaveValue('')
    expect(screen.getByRole('button', { name: '提交反馈' })).toBeDisabled()
    expect(screen.getByText(/原始模型判定/)).toHaveTextContent('严重')
  })

  it.each(['low', 'medium', 'high', 'critical'] as const)('records explicit %s severity and the reference verdict, including confirmations', async level => {
    const user = userEvent.setup()
    mount({ verdict: createSecurityVerdict({ id: 'reviewed-verdict', threat_level: level, threat_type: 'phishing' }) })
    await user.click(screen.getByRole('button', { name: '钓鱼邮件' }))
    await user.selectOptions(screen.getByLabelText('人工确认等级'), level)
    await user.type(screen.getByLabelText('添加备注'), '独立人工复核')
    await user.click(screen.getByRole('button', { name: '提交反馈' }))
    await screen.findByText('反馈已记录，等待候选训练与验证。')
    expect(posts()).toHaveLength(1)
    expect(JSON.parse(posts()[0][1]!.body as string)).toEqual({
      feedback_type: 'phishing', corrected_threat_level: level,
      expected_verdict_id: 'reviewed-verdict', comment: '独立人工复核',
    })
    expect(screen.getByRole('button', { name: '提交反馈' })).toBeDisabled()
  })

  it('requires an explicit safe choice for legitimate feedback and clears it on type changes', async () => {
    const user = userEvent.setup()
    mount()
    await user.click(screen.getByRole('button', { name: '正常邮件' }))
    const level = screen.getByLabelText('人工确认等级')
    expect(level).toHaveValue('')
    expect(within(level).getAllByRole('option').map(option => (option as HTMLOptionElement).value)).toEqual(['', 'safe'])
    await user.selectOptions(level, 'safe')
    await user.click(screen.getByRole('button', { name: '提交反馈' }))
    await screen.findByText('反馈已记录，等待候选训练与验证。')
    expect(JSON.parse(posts()[0][1]!.body as string).corrected_threat_level).toBe('safe')
    await user.click(screen.getByRole('button', { name: '社工攻击' }))
    expect(screen.getByLabelText('人工确认等级')).toHaveValue('')
    expect(within(screen.getByLabelText('人工确认等级')).queryByRole('option', { name: '安全' })).not.toBeInTheDocument()
  })

  it('blocks a verdict changed during review instead of silently relabeling it', async () => {
    const user = userEvent.setup()
    const view = mount()
    await user.click(screen.getByRole('button', { name: '钓鱼邮件' }))
    await user.selectOptions(screen.getByLabelText('人工确认等级'), 'high')
    view.rerender(<FeedbackPanel {...view.props} verdict={createSecurityVerdict({ id: 'new-verdict' })} />)
    expect(screen.getByRole('alert')).toHaveTextContent('分析判定已更新')
    expect(screen.getByRole('button', { name: '提交反馈' })).toBeDisabled()
    expect(posts()).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: '钓鱼邮件' }))
    await user.selectOptions(screen.getByLabelText('人工确认等级'), 'medium')
    await user.click(screen.getByRole('button', { name: '提交反馈' }))
    await waitFor(() => expect(posts()).toHaveLength(1))
    expect(JSON.parse(posts()[0][1]!.body as string).expected_verdict_id).toBe('new-verdict')
  })

  it('makes transport failures visible and refreshes the reference without losing the selected label', async () => {
    const user = userEvent.setup()
    fetchMock.mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') throw new Error('Verdict changed; review again')
      return response({ feedbacks: [], learning_status: null })
    })
    const view = mount()
    await user.click(screen.getByRole('button', { name: '其他威胁' }))
    await user.selectOptions(screen.getByLabelText('人工确认等级'), 'high')
    await user.click(screen.getByRole('button', { name: '提交反馈' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('反馈保存失败: Verdict changed; review again')
    expect(view.props.onRefreshVerdict).toHaveBeenCalledOnce()
    expect(screen.queryByText('反馈已记录，等待候选训练与验证。')).not.toBeInTheDocument()
    expect(screen.getByLabelText('人工确认等级')).toHaveValue('high')
  })

  it('does not report success for a rejected response with HTTP 200', async () => {
    const user = userEvent.setup()
    fetchMock.mockImplementation(async (_input, init) => init?.method === 'POST'
      ? response(null, false, 'Review rejected') : response({ feedbacks: [], learning_status: null }))
    mount()
    await user.click(screen.getByRole('button', { name: '伪造邮件' }))
    await user.selectOptions(screen.getByLabelText('人工确认等级'), 'low')
    await user.click(screen.getByRole('button', { name: '提交反馈' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Review rejected')
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('prevents duplicate writes while submitting and distinguishes saved from trainable', async () => {
    const user = userEvent.setup()
    let finish: ((value: Response) => void) | undefined
    fetchMock.mockImplementation(async (_input, init) => init?.method === 'POST'
      ? new Promise<Response>(resolve => { finish = resolve }) : response({ feedbacks: [], learning_status: null }))
    mount()
    await user.click(screen.getByRole('button', { name: '钓鱼邮件' }))
    await user.selectOptions(screen.getByLabelText('人工确认等级'), 'high')
    await user.dblClick(screen.getByRole('button', { name: '提交反馈' }))
    expect(posts()).toHaveLength(1)
    expect(screen.getByRole('button', { name: '提交中...' })).toBeDisabled()
    await act(async () => { finish?.(response({ learning_status: 'insufficient_evidence', learning_reason: 'retained_raw_mime_missing' })) })
    expect(await screen.findByRole('status')).toHaveTextContent('反馈已保存，但证据不足')
    expect(screen.getByText(/未保留原始邮件，无法固定训练样本/)).toBeInTheDocument()
    expect(screen.queryByText(/retained_raw_mime_missing/)).not.toBeInTheDocument()
    expect(screen.getByText(/保存反馈不会立即更新当前模型/)).toBeInTheDocument()
  })

  it('loads prior feedback and keeps missing historical labels distinct from model severity', async () => {
    fetchMock.mockResolvedValue(response({
      learning_status: 'insufficient_evidence', learning_reason: 'verdict_content_changed', feedbacks: [{
        id: 'old-feedback', feedback_type: 'phishing', corrected_threat_level: null,
        original_threat_level: 'high', status: 'pending', created_at: '2026-11-01T00:00:00Z',
      }],
    }))
    mount()
    const table = await screen.findByRole('table')
    expect(within(table).getByText('未记录等级')).toBeInTheDocument()
    expect(within(table).getByText('高危')).toBeInTheDocument()
    expect(within(table).getByText('待处理')).toBeInTheDocument()
    expect(screen.getByText(/邮件内容与当次分析时不同，请重扫后重新反馈/)).toBeInTheDocument()
    expect(screen.queryByLabelText('人工确认等级')).not.toBeInTheDocument()
    expect(posts()).toHaveLength(0)
  })

  it('shows a retriable history failure without treating it as empty history', async () => {
    fetchMock.mockRejectedValue(new Error('offline'))
    mount()
    expect(await screen.findByRole('alert')).toHaveTextContent('反馈记录加载失败')
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
    expect(screen.queryByText('暂无反馈记录。')).not.toBeInTheDocument()
  })

  it('clears a prior learning reason after a successful submission even when history refresh fails', async () => {
    const user = userEvent.setup()
    let historyRequests = 0
    fetchMock.mockImplementation(async (_input, init) => {
      if (init?.method === 'POST') return response({ learning_status: 'recorded', learning_reason: null })
      if (historyRequests++ > 0) throw new Error('history refresh unavailable')
      return response({
        feedbacks: [], learning_status: 'insufficient_evidence', learning_reason: 'retained_raw_mime_missing',
      })
    })
    mount()
    expect(await screen.findByText(/未保留原始邮件，无法固定训练样本/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '钓鱼邮件' }))
    await user.selectOptions(screen.getByLabelText('人工确认等级'), 'high')
    await user.click(screen.getByRole('button', { name: '提交反馈' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('反馈记录加载失败')
    expect(screen.getByRole('status')).toHaveTextContent('反馈已记录，等待候选训练与验证。')
    expect(posts()).toHaveLength(1)
    expect(historyRequests).toBe(2)
    expect(screen.queryByText(/未保留原始邮件，无法固定训练样本/)).not.toBeInTheDocument()
    expect(screen.queryByText(new RegExp(i18n.t('emailSecurity.feedbackLearningReason')))).not.toBeInTheDocument()
  })

  it('localizes the full review form in English', async () => {
    await i18n.changeLanguage('en')
    const user = userEvent.setup()
    mount()
    await user.click(screen.getByRole('button', { name: 'Social Engineering' }))
    expect(screen.getByLabelText('Reviewed severity')).toHaveValue('')
    expect(screen.getByText(/parameters update after validation/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Other Threat' })).toBeInTheDocument()
    expect(screen.queryByText(/emailSecurity\./)).not.toBeInTheDocument()
  })
})
