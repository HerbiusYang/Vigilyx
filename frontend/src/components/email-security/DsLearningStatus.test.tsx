import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import i18n from '../../i18n'
import type { DsLearningState } from '../../types/feedback'
import { apiFetch } from '../../utils/api'
import DsLearningStatus from './DsLearningStatus'

vi.mock('../../utils/api', () => ({ apiFetch: vi.fn() }))
const fetchMock = vi.mocked(apiFetch)
const state: DsLearningState = {
  schema_version: 1, revision: 3, sample_window_limit: 256, feedback_count: 8, eligible_count: 5, excluded_count: 3,
  candidate: { parameter_version: 'candidate-3', sources: { identity: { slope: 1.2, intercept: -0.3, reliability: 0.6 } } },
  active: null, validation_status: 'pending', pending_gates: ['sealed_holdout'], updated_at: '2026-11-01T00:00:00Z',
}

function response(data = state): Response {
  return { ok: true, json: vi.fn().mockResolvedValue({ success: true, data, error: null }) } as unknown as Response
}

describe('DS candidate learning status', () => {
  beforeEach(async () => {
    await i18n.changeLanguage('zh')
    fetchMock.mockReset().mockResolvedValue(response())
  })

  it('separates recorded samples, candidate parameters and the active model', async () => {
    render(<DsLearningStatus refreshToken={null} />)
    expect(await screen.findByText('最近 256 个反馈会话：已记录 8 个 · 可训练 5 个 · 暂不纳入 3 个')).toBeInTheDocument()
    expect(screen.getByText('候选参数版本: candidate-3')).toBeInTheDocument()
    expect(screen.getByText('线上参数版本: V2 初始参数')).toBeInTheDocument()
    expect(screen.getByText('候选验证状态: 尚未通过独立验证')).toBeInTheDocument()
    expect(screen.getByText(/生成候选不表示检测效果已改善/)).toBeInTheDocument()
    expect(screen.queryByText('sealed_holdout')).not.toBeInTheDocument()
  })

  it('refreshes after a saved feedback result and through the explicit refresh action', async () => {
    const user = userEvent.setup()
    const view = render(<DsLearningStatus refreshToken={null} />)
    await screen.findByText('候选参数版本: candidate-3')
    view.rerender(<DsLearningStatus refreshToken="saved-feedback" />)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(screen.getByRole('button', { name: '刷新学习状态' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '刷新学习状态' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
  })

  it('shows at most twelve source parameter rows and preserves the active version', async () => {
    const sources = Object.fromEntries(Array.from({ length: 14 }, (_, index) => [`source-${index.toString().padStart(2, '0')}`, { slope: 1, intercept: 0, reliability: 0.8 }]))
    fetchMock.mockResolvedValue(response({ ...state, candidate: { parameter_version: '9', sources }, active: { parameter_version: 'active-2', sources: {} } }))
    const user = userEvent.setup()
    render(<DsLearningStatus refreshToken={null} />)
    await user.click(await screen.findByText('查看候选来源参数（显示 12 / 14 项）'))
    const table = screen.getByRole('table')
    expect(within(table).getAllByRole('row')).toHaveLength(13)
    expect(within(table).queryByText('source-12')).not.toBeInTheDocument()
    expect(screen.getByText('线上参数版本: active-2')).toBeInTheDocument()
  })

  it('makes unavailable status retriable without claiming that feedback is blocked', async () => {
    fetchMock.mockRejectedValue(new Error('unavailable'))
    render(<DsLearningStatus refreshToken={null} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('您仍可保存反馈')
    expect(screen.getByRole('button', { name: '刷新学习状态' })).toBeEnabled()
    expect(screen.queryByText(/线上参数版本:/)).not.toBeInTheDocument()
  })
})
