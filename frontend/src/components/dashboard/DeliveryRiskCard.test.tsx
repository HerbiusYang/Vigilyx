import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import type { SecurityStats } from '../../types'
import { apiFetch } from '../../utils/api'
import { DeliveryRiskCard } from './Dashboard'

vi.mock('../../utils/api', () => ({
  apiFetch: vi.fn(),
}))

const mockedApiFetch = vi.mocked(apiFetch)

const stats: SecurityStats = {
  total_scanned: 10_000,
  level_counts: { safe: 9_000, high: 1_000 },
  high_threats_24h: 20,
  ioc_count: 100,
  first_hop_emails_total: 2_699,
  first_hop_dangerous_total: 667,
  downstream_reused_hops_total: 417,
  dangerous_forwarded_total: 16,
  dangerous_forwarded_rate: 2.4,
  terminal_mail_servers: ['198.51.100.68'],
  delivery_stats_as_of: '2026-08-21T04:45:00.000000Z',
  delivery_stats_scope: 'all_history',
  delivery_node_comparisons: [{
    node_index: 0,
    server_ips: ['192.0.2.41'],
    comparable_total: 7,
    vendor_blocked_total: 2,
    vendor_passed_total: 5,
    terminal_delivered_total: 4,
    vendor_unconfirmed_total: 3,
    vigilyx_risky_total: 5,
    both_threat_total: 1,
    vigilyx_only_threat_total: 4,
    vendor_only_threat_total: 1,
    both_threat_rate: 50,
    vigilyx_only_threat_rate: 100,
    vendor_only_threat_rate: 50,
    vendor_unconfirmed_rate: 30,
  }],
}

describe('DeliveryRiskCard drill-down', () => {
  beforeEach(async () => {
    mockedApiFetch.mockReset()
    await i18n.changeLanguage('zh')
  })

  it('shows mutually exclusive node outcomes and separates risky subsets', () => {
    render(<MemoryRouter><DeliveryRiskCard secStats={stats} unavailable={false} /></MemoryRouter>)

    expect(screen.queryByText('各网关节点的投递结果（按 IP 分别统计）')).not.toBeInTheDocument()
    expect(screen.queryByText('近 24 小时')).not.toBeInTheDocument()
    expect(screen.getByText('全部历史')).toBeVisible()
    expect(screen.queryByText(/节点放行仅统计/)).not.toBeInTheDocument()
    expect(screen.queryByText(/不代表网关已经拦截/)).not.toBeInTheDocument()
    expect(screen.queryByText('首跳邮件总数')).not.toBeInTheDocument()
    expect(screen.queryByText('复用跳数')).not.toBeInTheDocument()
    expect(screen.queryByText('观察到风险邮件继续下游')).not.toBeInTheDocument()
    expect(screen.queryByText('风险邮件继续下游率')).not.toBeInTheDocument()
    expect(screen.getByText('网关节点 1')).toBeVisible()
    expect(screen.getByText('已确认结果')).toBeVisible()
    expect(screen.getByText('7')).toBeVisible()
    expect(screen.queryByText('已到达邮件服务器')).not.toBeInTheDocument()
    expect(screen.queryByText('网关通过')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /网关通过/ })).not.toBeInTheDocument()
    expect(screen.queryByText('SMTP 明确拒收')).not.toBeInTheDocument()
    expect(screen.queryByText('未观察到后续投递')).not.toBeInTheDocument()
    expect(screen.getByText('判定不同')).toBeVisible()
    expect(screen.getByRole('button', { name: '判定不同：5 封（71.4%）' })).toBeVisible()
    expect(screen.queryByText('风险邮件（上述结果的子集）')).not.toBeInTheDocument()
    expect(screen.getByText('节点安全策略拦截 · Vigilyx 判安全')).toBeVisible()
    expect(screen.getByRole('button', {
      name: '节点安全策略拦截 · Vigilyx 判安全：1 封（20.0%）',
    })).toBeVisible()
    expect(screen.getByText('节点放行 · Vigilyx 判风险')).toBeVisible()
    expect(screen.getByRole('button', {
      name: '节点放行 · Vigilyx 判风险：4 封（80.0%）',
    })).toBeVisible()
    expect(screen.getByText('判定相同')).toBeVisible()
    expect(screen.getByRole('button', { name: '判定相同：2 封（28.6%）' })).toBeVisible()
    expect(screen.getByText('节点安全策略拦截 · Vigilyx 判风险')).toBeVisible()
    expect(screen.getByRole('button', {
      name: '节点安全策略拦截 · Vigilyx 判风险：1 封（50.0%）',
    })).toBeVisible()
    expect(screen.getByText('节点放行 · Vigilyx 判安全')).toBeVisible()
    expect(screen.getByRole('button', {
      name: '节点放行 · Vigilyx 判安全：1 封（50.0%）',
    })).toBeVisible()
    expect(screen.queryByText(/链路终止/)).not.toBeInTheDocument()
  })

  it('uses the translated app loading label while fetching a detail list', async () => {
    mockedApiFetch.mockReturnValue(new Promise<Response>(() => {}))

    render(<MemoryRouter><DeliveryRiskCard secStats={stats} unavailable={false} /></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: /判定不同/ }))

    expect(await screen.findByText('正在加载页面...')).toBeVisible()
    expect(screen.queryByText('common.loading')).not.toBeInTheDocument()
    expect(String(mockedApiFetch.mock.calls[0]?.[0])).toContain('kind=disagreement')
  })

  it('opens the same-decision mail list without exposing the removed SMTP label', async () => {
    mockedApiFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({
        success: true,
        data: {
          items: [{
            chain_id: 'chain-001',
            session_id: '11111111-1111-4111-8111-111111111111',
            hop_index: 0,
            server_ip: '192.0.2.41',
            observed_at: '2026-08-21T04:30:00Z',
            threat_level: 'high',
            action_evidence: 'explicit_rejection',
            message_id: '<test@example.test>',
            mail_from: 'sender@example.test',
            rcpt_to: ['recipient@example.test'],
            subject: '测试钓鱼邮件',
          }],
          total: 2,
          limit: 30,
          offset: 0,
          snapshot_at: stats.delivery_stats_as_of,
          scope: 'all_history',
          kind: 'agreement',
          server_ip: '192.0.2.41',
        },
        error: null,
      }),
    } as unknown as Response)

    render(<MemoryRouter><DeliveryRiskCard secStats={stats} unavailable={false} /></MemoryRouter>)
    fireEvent.click(screen.getByRole('button', { name: /判定相同/ }))

    const dialog = await screen.findByRole('dialog', { name: '判定相同' })
    expect(within(dialog).getAllByText('结果一致')).toHaveLength(2)
    expect(within(dialog).getByText('节点安全策略拦截')).toBeVisible()
    expect(within(dialog).queryByText('SMTP 明确拒收')).not.toBeInTheDocument()
    expect(within(dialog).getByRole('link', { name: '测试钓鱼邮件' })).toHaveAttribute(
      'href',
      '/emails/11111111-1111-4111-8111-111111111111',
    )

    const requestUrl = String(mockedApiFetch.mock.calls[0]?.[0])
    expect(requestUrl).toContain('kind=agreement')
    expect(requestUrl).toContain('server_ip=192.0.2.41')
    expect(requestUrl).toContain('snapshot_at=2026-08-21T04%3A45%3A00.000000Z')
    expect(new URL(requestUrl, 'https://example.test').searchParams.has('start_date')).toBe(false)
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument()
  })

  it('shows every historical gateway instead of truncating after four nodes', () => {
    const nodes = Array.from({ length: 5 }, (_, index) => ({
      ...stats.delivery_node_comparisons![0],
      node_index: index,
      server_ips: [`192.0.2.${index + 1}`],
    }))
    render(<MemoryRouter><DeliveryRiskCard secStats={{ ...stats, delivery_node_comparisons: nodes }} unavailable={false} /></MemoryRouter>)
    expect(screen.getByText('网关节点 5')).toBeVisible()
  })

  it('does not label legacy rolling-window counts as all-history results', () => {
    render(<MemoryRouter><DeliveryRiskCard secStats={{ ...stats, delivery_stats_scope: undefined }} unavailable={false} /></MemoryRouter>)
    expect(screen.queryByText('网关节点 1')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /判定不同/ })).not.toBeInTheDocument()
  })

})
