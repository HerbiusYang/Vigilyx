import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import SetupWizard from './SetupWizard'

const { apiFetchMock, persistSetupStatusMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn(),
  persistSetupStatusMock: vi.fn(),
}))

vi.mock('../../utils/api', () => ({
  apiFetch: apiFetchMock,
}))

vi.mock('../../utils/setupStatus', () => ({
  persistSetupStatus: persistSetupStatusMock,
}))

function response(payload: unknown): Promise<Response> {
  return Promise.resolve({
    json: () => Promise.resolve(payload),
  } as Response)
}

function requestBody(init?: RequestInit): Record<string, unknown> {
  return JSON.parse(String(init?.body || '{}')) as Record<string, unknown>
}

describe('SetupWizard', () => {
  beforeEach(async () => {
    localStorage.clear()
    document.documentElement.lang = 'zh'
    await i18n.changeLanguage('zh')
    apiFetchMock.mockReset()
    persistSetupStatusMock.mockReset()
    persistSetupStatusMock.mockResolvedValue(true)

    apiFetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (init?.method === 'PUT') {
        return response({ success: true, data: requestBody(init) })
      }
      if (path === '/api/config/deployment-mode') {
        return response({ success: true, data: { mode: 'mirror', locked: false, mta_config: {} } })
      }
      if (path === '/api/config/sniffer') {
        return response({ success: true, data: { webmail_servers: [], http_ports: [80, 443, 8080] } })
      }
      if (path === '/api/security/email-alert') {
        return response({
          success: true,
          data: {
            enabled: false,
            smtp_host: '',
            smtp_port: 465,
            smtp_username: '',
            smtp_password_set: false,
            smtp_tls: 'tls',
            allow_plaintext_smtp: false,
            from_address: '',
            admin_email: '',
            min_threat_level: 'high',
          },
        })
      }
      if (path === '/api/security/ai-config') {
        return response({ success: true, data: { enabled: false, service_url: 'http://vigilyx-ai:8900' } })
      }
      if (path === '/api/system/interfaces') {
        return response({
          success: true,
          data: [{ name: 'ens224', rx_bytes: 1000, tx_bytes: 500, total_bytes: 1500, status: 'up' }],
        })
      }
      throw new Error(`Unexpected request: ${path}`)
    })
  })

  it('renders complete Chinese copy and switches the wizard to English', async () => {
    const user = userEvent.setup()
    const { unmount } = render(<SetupWizard onComplete={vi.fn()} />)

    expect(document.body).toHaveClass('setup-page')
    expect(screen.getByText('企业邮件威胁情报平台')).toBeInTheDocument()
    expect(screen.getByText('多引擎威胁检测')).toBeInTheDocument()
    expect(screen.queryByText('setup.featureMultiEngine')).not.toBeInTheDocument()
    expect(screen.getByRole('group', { name: '界面语言' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '中文' })).toHaveAttribute('aria-pressed', 'true')

    await user.click(screen.getByRole('button', { name: '英文' }))

    expect(await screen.findByText('Enterprise Email Threat Intelligence Platform')).toBeInTheDocument()
    expect(screen.getByText('Multi-engine Detection')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'English' })).toHaveAttribute('aria-pressed', 'true')
    expect(document.documentElement.lang).toBe('en')
    expect(localStorage.getItem('vigilyx-lang')).toBe('en')

    unmount()
    expect(document.body).not.toHaveClass('setup-page')
  })

  it('submits MTA downstream settings on the page where they are entered', async () => {
    const user = userEvent.setup()
    render(<SetupWizard onComplete={vi.fn()} />)

    const start = screen.getByRole('button', { name: '正在读取配置...' })
    await waitFor(() => expect(start).toHaveTextContent('开始配置'))
    await user.click(start)
    await user.click(screen.getByRole('button', { name: /MTA 网关代理/ }))
    await user.click(screen.getByRole('button', { name: '下一步' }))

    expect(await screen.findByRole('heading', { name: 'MTA 网关网络配置' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '跳过' })).not.toBeInTheDocument()

    await user.type(screen.getByLabelText(/下游 MTA 地址/), '10.1.246.33')
    const port = screen.getByRole('spinbutton', { name: '下游 MTA 端口' })
    await user.clear(port)
    await user.type(port, '2525')
    await user.click(screen.getByRole('button', { name: '下一步' }))

    expect(await screen.findByRole('heading', { name: '内部域名' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '跳过' })).not.toBeInTheDocument()
    await user.type(screen.getByLabelText(/内部域名列表/), 'corp.example.com')
    await user.click(screen.getByRole('button', { name: '下一步' }))
    expect(await screen.findByRole('heading', { name: '告警通知' })).toBeInTheDocument()

    const deploymentWrites = apiFetchMock.mock.calls
      .filter(([path, init]) => path === '/api/config/deployment-mode' && init?.method === 'PUT')
      .map(([, init]) => requestBody(init))

    expect(deploymentWrites).toContainEqual({ mode: 'mta' })
    expect(deploymentWrites).toContainEqual({
      mta_downstream_host: '10.1.246.33',
      mta_downstream_port: 2525,
    })
    expect(deploymentWrites).toContainEqual({ mta_local_domains: 'corp.example.com' })
  })

  it('shows only mirror-specific runtime guidance and Webmail settings', async () => {
    const user = userEvent.setup()
    render(<SetupWizard onComplete={vi.fn()} />)

    await waitFor(() => expect(screen.getByRole('button', { name: '开始配置' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '开始配置' }))
    await user.click(screen.getByRole('button', { name: '下一步' }))

    expect(await screen.findByRole('heading', { name: '镜像捕获网络配置' })).toBeInTheDocument()
    expect(screen.getAllByText(/SNIFFER_INTERFACE/)).toHaveLength(2)
    expect(screen.queryByLabelText('下游 MTA 地址')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '下一步' }))
    expect(await screen.findByRole('heading', { name: 'Webmail 数据采集' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '内部域名' })).not.toBeInTheDocument()
  })

  it('refreshes host interface counters while the mirror network step is visible', async () => {
    const user = userEvent.setup()
    const defaultImplementation = apiFetchMock.getMockImplementation()
    let interfaceRequests = 0
    const intervalSpy = vi.spyOn(window, 'setInterval')

    apiFetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input) === '/api/system/interfaces') {
        interfaceRequests += 1
        const rxBytes = interfaceRequests * 1024
        return response({
          success: true,
          data: [{ name: 'ens224', rx_bytes: rxBytes, tx_bytes: 512, total_bytes: rxBytes + 512, status: 'up' }],
        })
      }
      return defaultImplementation?.(input, init)
    })

    const { unmount } = render(<SetupWizard onComplete={vi.fn()} />)
    await waitFor(() => expect(screen.getByRole('button', { name: '开始配置' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '开始配置' }))
    await user.click(screen.getByRole('button', { name: '下一步' }))

    expect(await screen.findByText('RX 1 KB')).toBeInTheDocument()
    const refreshCall = intervalSpy.mock.calls.find(([, delay]) => delay === 5_000)
    expect(refreshCall).toBeDefined()

    await act(async () => {
      await (refreshCall?.[0] as () => Promise<void>)()
    })

    expect(await screen.findByText('RX 2 KB')).toBeInTheDocument()
    expect(interfaceRequests).toBe(2)

    unmount()
    intervalSpy.mockRestore()
  })

  it('does not advance when the backend rejects a configuration write', async () => {
    const user = userEvent.setup()
    render(<SetupWizard onComplete={vi.fn()} />)

    await waitFor(() => expect(screen.getByRole('button', { name: '开始配置' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '开始配置' }))
    apiFetchMock.mockImplementation(() => response({ success: false, error: '后端拒绝了配置' }))
    await user.click(screen.getByRole('button', { name: '下一步' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('后端拒绝了配置')
    expect(screen.getByRole('heading', { name: '部署模式' })).toBeInTheDocument()
  })

  it('persists optional disabled services and marks setup complete', async () => {
    const user = userEvent.setup()
    const onComplete = vi.fn()
    render(<SetupWizard onComplete={onComplete} />)

    await waitFor(() => expect(screen.getByRole('button', { name: '开始配置' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '开始配置' }))
    await user.click(screen.getByRole('button', { name: '下一步' }))
    await user.click(await screen.findByRole('button', { name: '跳过' }))
    await user.click(screen.getByRole('button', { name: '跳过' }))
    await user.click(screen.getByRole('button', { name: '下一步' }))
    await user.click(screen.getByRole('button', { name: '完成' }))

    await waitFor(() => expect(onComplete).toHaveBeenCalledOnce())
    expect(persistSetupStatusMock).toHaveBeenCalledWith(true)

    const alertWrite = apiFetchMock.mock.calls.find(
      ([path, init]) => path === '/api/security/email-alert' && init?.method === 'PUT',
    )
    const aiWrite = apiFetchMock.mock.calls.find(
      ([path, init]) => path === '/api/security/ai-config' && init?.method === 'PUT',
    )
    expect(alertWrite && requestBody(alertWrite[1])).toMatchObject({ enabled: false })
    expect(aiWrite && requestBody(aiWrite[1])).toMatchObject({ enabled: false })
  })
})
