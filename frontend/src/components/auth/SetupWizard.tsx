import { useState, useEffect, useRef, FormEvent } from 'react'
import { apiFetch } from '../../utils/api'
import { persistSetupStatus } from '../../utils/setupStatus'

interface NetInterface {
  name: string
  rx_bytes: number
  tx_bytes: number
  total_bytes: number
  status: string
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(1)} GB`
}

/** Static glow palette for the setup wizard background */
function useWizardGlows() {
  const ref = useRef<Record<string, string>>({})
  if (!Object.keys(ref.current).length) {
    ref.current = {
      '--gl-c1': '34,211,238', '--gl-c2': '99,102,241', '--gl-c3': '16,185,129', '--gl-c4': '59,130,246',
      '--gl-x1': '5%',  '--gl-y1': '10%',  '--gl-x2': '60%', '--gl-y2': '20%',
      '--gl-x3': '25%', '--gl-y3': '60%',  '--gl-x4': '70%', '--gl-y4': '50%',
      '--gl-r1': '450px', '--gl-r2': '400px', '--gl-r3': '380px', '--gl-r4': '420px',
      '--gl-br1': '45%', '--gl-br2': '50%', '--gl-br3': '42%', '--gl-br4': '48%',
      '--gl-d1': '20s', '--gl-d2': '24s', '--gl-d3': '18s', '--gl-d4': '26s',
      '--gl-delay1': '-3s', '--gl-delay2': '-8s', '--gl-delay3': '-12s', '--gl-delay4': '-5s',
      '--gl-rot-dur': '120s', '--gl-rot-delay': '0s',
    }
  }
  return ref.current
}

interface SetupWizardProps {
  onComplete: () => void
}

// Step definitions (the capture step title/subtitle changes dynamically by mode)
const STEPS = [
  { id: 'welcome', title: '欢迎使用 Vigilyx', subtitle: '初始化配置向导' },
  { id: 'deploy_mode', title: '部署模式', subtitle: '选择邮件安全检测方式' },
  { id: 'network', title: '网络配置', subtitle: '配置网络监听参数' },
  { id: 'domains', title: '内部域名', subtitle: '配置组织内部的邮件域名' },
  { id: 'sniffer', title: '数据安全监控', subtitle: '配置 Webmail 服务器和 HTTP 端口' },
  { id: 'alerts', title: '邮件告警', subtitle: '配置安全告警的邮件通知' },
  { id: 'ai', title: 'AI 分析服务', subtitle: '配置智能威胁分析' },
]

const PLATFORM_FEATURES = [
  {
    icon: 'shield',
    accent: '#22d3ee',
    title: '多引擎融合检测',
    desc: '15+ 模块并行 · DS-Murphy 证据融合',
  },
  {
    icon: 'zap',
    accent: '#f59e0b',
    title: '双模式部署',
    desc: '旁路镜像 / MTA 网关按需切换',
  },
  {
    icon: 'brain',
    accent: '#a855f7',
    title: 'AI 语义分析',
    desc: 'mDeBERTa 零样本钓鱼识别',
  },
  {
    icon: 'globe',
    accent: '#3b82f6',
    title: '威胁情报联动',
    desc: 'OTX · VirusTotal · 本地 IOC',
  },
  {
    icon: 'lock',
    accent: '#22c55e',
    title: '数据安全审计',
    desc: 'DLP 敏感数据外泄检测',
  },
  {
    icon: 'activity',
    accent: '#f43f5e',
    title: '自动化响应',
    desc: 'SOAR 告警 · Webhook · 自动隔离',
  },
]

const FEATURE_ICONS: Record<string, JSX.Element> = {
  shield: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9.5 12.5l1.8 1.8 3.7-4.1"/></svg>,
  zap: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>,
  brain: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9.5 2A5.5 5.5 0 0 0 4 7.5c0 1.58.68 3 1.76 4L12 18l6.24-6.5A5.48 5.48 0 0 0 20 7.5 5.5 5.5 0 0 0 14.5 2c-1.56 0-2.94.64-3.94 1.67L12 2.17l1.44 1.5A5.48 5.48 0 0 0 9.5 2z"/><path d="M12 18v4"/></svg>,
  globe: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
  lock: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
  activity: <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
}

export default function SetupWizard({ onComplete }: SetupWizardProps) {
  const [step, setStep] = useState(0)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const glowVars = useWizardGlows()

  // ── Step: Deploy Mode ──
  const [deployMode, setDeployMode] = useState<'mirror' | 'mta'>('mirror')
  const [mtaDownstreamHost, setMtaDownstreamHost] = useState('')
  const [mtaDownstreamPort, setMtaDownstreamPort] = useState('25')

  // ── Step: Network Capture ──
  const [interfaces, setInterfaces] = useState<NetInterface[]>([])
  const [ifaceLoading, setIfaceLoading] = useState(false)
  const [snifferIface, setSnifferIface] = useState('')
  const [smtpPorts, setSmtpPorts] = useState('25,465,587,2525,2526')
  const [pop3Ports, setPop3Ports] = useState('110,995')
  const [imapPorts, setImapPorts] = useState('143,993')

  // Load interfaces when entering the capture step
  useEffect(() => {
    if (STEPS[step]?.id !== 'network') return
    setIfaceLoading(true)
    apiFetch('/api/system/interfaces')
      .then(r => r.json())
      .then(data => {
        if (data.success && Array.isArray(data.data) && data.data.length > 0) {
          setInterfaces(data.data)
          // Auto-select the interface with most traffic
          if (!snifferIface) {
            setSnifferIface(data.data[0].name)
          }
        }
      })
      .catch(() => {})
      .finally(() => setIfaceLoading(false))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step])

  // ── Step 2: Internal Domains ──
  const [domains, setDomains] = useState('')

  // ── Step 2: Sniffer (Data Security) ──
  const [webmailServers, setWebmailServers] = useState('')
  const [httpPorts, setHttpPorts] = useState('80,443,8080')

  // ── Step 3: Email Alerts ──
  const [alertEnabled, setAlertEnabled] = useState(false)
  const [smtpHost, setSmtpHost] = useState('')
  const [smtpPort, setSmtpPort] = useState('465')
  const [smtpUser, setSmtpUser] = useState('')
  const [smtpPass, setSmtpPass] = useState('')
  const [smtpTls, setSmtpTls] = useState('tls')
  const [alertFrom, setAlertFrom] = useState('')
  const [alertTo, setAlertTo] = useState('')
  const [alertLevel, setAlertLevel] = useState('high')

  // ── Step 4: AI Service ──
  const [aiEnabled, setAiEnabled] = useState(false)
  const [aiUrl, setAiUrl] = useState('http://vigilyx-ai:8900')

  const rawStep = STEPS[step]
  // Dynamically adjust the network step title
  const currentStep = rawStep.id === 'network'
    ? {
        ...rawStep,
        title: deployMode === 'mta' ? 'MTA 网络配置' : '网络抓包',
        subtitle: deployMode === 'mta' ? '配置监听地址、下游转发和本地域名' : '配置流量捕获的网卡和协议端口',
      }
    : rawStep

  const finishSetup = async () => {
    setError(null)
    setSaving(true)

    try {
      const saved = await persistSetupStatus(true)
      if (!saved) {
        setError('引导完成状态保存失败')
        return
      }
      onComplete()
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '引导完成状态保存失败'
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  const saveStep = async () => {
    setError(null)
    setSaving(true)
    try {
      if (currentStep.id === 'deploy_mode') {
        localStorage.setItem('vigilyx-deploy-mode', deployMode)
        const body: Record<string, unknown> = { mode: deployMode }
        if (deployMode === 'mta') {
          if (mtaDownstreamHost) body.mta_downstream_host = mtaDownstreamHost
          if (mtaDownstreamPort) body.mta_downstream_port = Number(mtaDownstreamPort)
        }
        const res = await apiFetch('/api/config/deployment-mode', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        })
        const data = await res.json()
        if (!data.success) throw new Error(data.error || '保存失败')
      } else if (currentStep.id === 'network') {
        // NIC/protocol port settings are currently controlled by container env vars; the frontend only stores them in localStorage for display/reference
        localStorage.setItem('vigilyx-sniffer-iface', snifferIface)
        localStorage.setItem('vigilyx-smtp-ports', smtpPorts)
        localStorage.setItem('vigilyx-pop3-ports', pop3Ports)
        localStorage.setItem('vigilyx-imap-ports', imapPorts)
        if (deployMode === 'mta') {
          // In MTA mode, domains are saved into the mta_local_domains field of the deployment_mode config
          const domainList = domains
            .split(/[,\n]/)
            .map(d => d.trim().toLowerCase())
            .filter(Boolean)
          if (domainList.length > 0) {
            const res = await apiFetch('/api/config/deployment-mode', {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ mta_local_domains: domainList.join(',') }),
            })
            const data = await res.json()
            if (!data.success) throw new Error(data.error || '保存域名失败')
          }
        }
      } else if (currentStep.id === 'domains') {
        // Save MTA local domains into the deployment_mode config
        const domainList = domains
          .split(/[,\n]/)
          .map(d => d.trim().toLowerCase())
          .filter(Boolean)
        if (domainList.length > 0) {
          const res = await apiFetch('/api/config/deployment-mode', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mta_local_domains: domainList.join(',') }),
          })
          const data = await res.json()
          if (!data.success) throw new Error(data.error || '保存域名失败')
        }
      } else if (currentStep.id === 'sniffer') {
        const servers = webmailServers
          .split(/[,\n]/)
          .map(s => s.trim())
          .filter(Boolean)
        const ports = httpPorts
          .split(',')
          .map(p => parseInt(p.trim()))
          .filter(p => !isNaN(p) && p > 0 && p <= 65535)
        await apiFetch('/api/config/sniffer', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ webmail_servers: servers, http_ports: ports }),
        })
      } else if (currentStep.id === 'alerts') {
        if (alertEnabled) {
          await apiFetch('/api/security/email-alert', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              enabled: true,
              smtp_host: smtpHost,
              smtp_port: parseInt(smtpPort) || 465,
              smtp_username: smtpUser,
              smtp_password: smtpPass,
              smtp_tls: smtpTls,
              from_address: alertFrom,
              admin_email: alertTo,
              min_threat_level: alertLevel,
              notify_recipient: false,
              notify_admin: true,
            }),
          })
        }
      } else if (currentStep.id === 'ai') {
        await apiFetch('/api/security/ai-config', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enabled: aiEnabled,
            service_url: aiUrl,
            provider: 'local',
            api_key: '',
            model: 'mDeBERTa',
            temperature: 0.0,
            max_tokens: 512,
            timeout_secs: 30,
          }),
        })
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '保存失败'
      setError(msg)
      setSaving(false)
      return false
    }
    setSaving(false)
    return true
  }

  const handleNext = async (e?: FormEvent) => {
    e?.preventDefault()
    // Welcome step has no save
    if (step === 0) {
      setStep(1)
      return
    }
    const ok = await saveStep()
    if (!ok) return
    if (step < STEPS.length - 1) {
      setStep(step + 1)
      setError(null)
    } else {
      await finishSetup()
    }
  }

  const handleBack = () => {
    if (step > 0) {
      setStep(step - 1)
      setError(null)
    }
  }

  const handleSkip = () => {
    if (step < STEPS.length - 1) {
      setStep(step + 1)
      setError(null)
    } else {
      void finishSetup()
    }
  }

  return (
    <div className="grok-login" style={glowVars as React.CSSProperties}>
      <div className="grok-bg" />

      <div className="setup-wizard">
        {/* Progress bar */}
        <div className="setup-progress">
          {STEPS.map((s, i) => (
            <div key={s.id} className={`setup-progress-dot ${i === step ? 'active' : i < step ? 'done' : ''}`}>
              {i < step ? (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
              ) : (
                <span>{i + 1}</span>
              )}
            </div>
          ))}
          <div className="setup-progress-bar">
            <div className="setup-progress-fill" style={{ width: `${(step / (STEPS.length - 1)) * 100}%` }} />
          </div>
        </div>

        {/* Header */}
        <div className="setup-header">
          <div className="setup-step-meta">
            <span className="setup-step-chip">安全引导</span>
            <span className="setup-step-count">
              {String(step + 1).padStart(2, '0')} / {String(STEPS.length).padStart(2, '0')}
            </span>
          </div>
          <div className="setup-title-row">
            <h2 className="setup-title">{currentStep.title}</h2>
            {step === 0 && (
              <button type="button" className="setup-btn setup-btn--primary" disabled={saving} onClick={() => handleNext()}>
                {saving && <span className="grok-spinner" />}
                开始配置
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ marginLeft: 4 }}><path d="M5 12h14m-7-7 7 7-7 7"/></svg>
              </button>
            )}
          </div>
          <p className="setup-subtitle">{currentStep.subtitle}</p>
        </div>

        {error && <div className="grok-error" style={{ marginBottom: 16 }}>{error}</div>}

        {/* Step content */}
        <form onSubmit={handleNext} className="setup-body">
          {currentStep.id === 'welcome' && (
            <div className="setup-welcome">
              <div className="setup-hero-copy">
                <span className="setup-eyebrow">Email Threat Intelligence Platform</span>
                <p className="setup-welcome-text">
                  Vigilyx 是开源邮件安全分析平台，通过多引擎融合检测、AI 语义分析和威胁情报联动，实现从流量捕获到威胁处置的全链路闭环。
                </p>
              </div>

              <div className="setup-feature-grid">
                {PLATFORM_FEATURES.map(f => (
                  <div key={f.title} className="setup-feature-card">
                    <div className="setup-feature-icon" style={{ color: f.accent, borderColor: f.accent + '33', background: f.accent + '14' }}>
                      {FEATURE_ICONS[f.icon]}
                    </div>
                    <div className="setup-feature-copy">
                      <strong className="setup-feature-title">{f.title}</strong>
                      <span className="setup-feature-desc">{f.desc}</span>
                    </div>
                  </div>
                ))}
              </div>

              <p className="setup-welcome-hint">
                接下来的配置向导将帮助您完成部署模式、网络参数、域名和告警设置。每一步都可跳过，稍后在「系统设置」中随时调整。
              </p>
            </div>
          )}

          {currentStep.id === 'deploy_mode' && (
            <div className="setup-fields">
              <p className="setup-section-lead">
                Vigilyx 支持两种部署模式，选择后可在「系统设置 → 部署模式」中随时切换。
              </p>

              <div className="setup-mode-grid">
                <button
                  type="button"
                  className={`setup-mode-card ${deployMode === 'mirror' ? 'active' : ''}`}
                  data-mode="mirror"
                  onClick={() => setDeployMode('mirror')}
                >
                  <div className="setup-mode-head">
                    <span className="setup-mode-radio" aria-hidden="true" />
                    <div>
                      <div className="setup-mode-title-row">
                        <span className="setup-mode-title">旁路镜像监听</span>
                        <span className="setup-mode-badge">零侵入</span>
                      </div>
                      <p className="setup-mode-copy">
                        通过交换机镜像或旁路流量复制被动捕获邮件协议，不改变现有投递路径，适合评估与只读监控。
                      </p>
                    </div>
                  </div>
                  <div className="setup-mode-chip-row">
                    <span className="setup-chip">只读观测</span>
                    <span className="setup-chip">上线阻力低</span>
                    <span className="setup-chip">适合初期评估</span>
                  </div>
                </button>

                <button
                  type="button"
                  className={`setup-mode-card ${deployMode === 'mta' ? 'active' : ''}`}
                  data-mode="mta"
                  onClick={() => setDeployMode('mta')}
                >
                  <div className="setup-mode-head">
                    <span className="setup-mode-radio" aria-hidden="true" />
                    <div>
                      <div className="setup-mode-title-row">
                        <span className="setup-mode-title">MTA 邮件网关</span>
                        <span className="setup-mode-badge setup-mode-badge--mta">可拦截</span>
                      </div>
                      <p className="setup-mode-copy">
                        作为 SMTP 中继串联部署，实时检测并处理入站与出站邮件，支持隔离、阻断与下游安全转发。
                      </p>
                    </div>
                  </div>
                  <div className="setup-mode-chip-row">
                    <span className="setup-chip setup-chip--warn">Inline 决策</span>
                    <span className="setup-chip setup-chip--warn">隔离区</span>
                    <span className="setup-chip setup-chip--warn">DLP 出站扫描</span>
                  </div>
                </button>
              </div>
            </div>
          )}

          {currentStep.id === 'network' && deployMode === 'mta' && (
            <div className="setup-fields">
              <div className="setup-flow-shell">
                <div className="setup-flow-header">
                  <div>
                    <div className="setup-flow-kicker">拓扑演示</div>
                    <div className="setup-flow-title">MTA inline 邮件路径</div>
                  </div>
                  <div className="setup-flow-budget">
                    <span>Inline 预算</span>
                    <strong>8s</strong>
                  </div>
                </div>

                <div className="setup-flow-legend">
                  <span className="setup-flow-legend-item">实时检测</span>
                  <span className="setup-flow-legend-item">下游转发</span>
                  <span className="setup-flow-legend-item">隔离与工单</span>
                  <span className="setup-flow-legend-item">DLP 出站审计</span>
                </div>

                <div className="setup-flow-grid">
                  <div className="setup-flow-row">
                    <div className="setup-flow-label">
                      <span className="setup-flow-tag setup-flow-tag--inbound">入站</span>
                    </div>
                    <div className="setup-flow-node">
                      <strong>外部发件人</strong>
                      <span>Internet / 上游 MX</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--gateway">
                      <strong>Vigilyx MTA</strong>
                      <span>TLS / 会话接入</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--inspection">
                      <strong>Inline 检测</strong>
                      <span>内容 / 链接 / 情报 / 策略</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--delivery">
                      <strong>下游 MTA</strong>
                      <span>安全转发至企业邮箱</span>
                    </div>
                  </div>

                  <div className="setup-flow-row">
                    <div className="setup-flow-label">
                      <span className="setup-flow-tag setup-flow-tag--risk">命中阈值</span>
                    </div>
                    <div className="setup-flow-node">
                      <strong>邮件会话</strong>
                      <span>进入 SMTP 入口</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--gateway">
                      <strong>策略判定</strong>
                      <span>Inline verdict</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--quarantine">
                      <strong>隔离区</strong>
                      <span>保留原始证据链</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--quarantine">
                      <strong>审核 / 工单</strong>
                      <span>分析师复核与释放</span>
                    </div>
                  </div>

                  <div className="setup-flow-row">
                    <div className="setup-flow-label">
                      <span className="setup-flow-tag setup-flow-tag--outbound">出站</span>
                    </div>
                    <div className="setup-flow-node">
                      <strong>内部用户</strong>
                      <span>邮件客户端 / OA</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--gateway">
                      <strong>Vigilyx MTA</strong>
                      <span>发信链路接管</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--inspection">
                      <strong>DLP / 审计</strong>
                      <span>正文、附件、策略</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node">
                      <strong>外部收件人</strong>
                      <span>通过后再放行</span>
                    </div>
                  </div>
                </div>

                <div className="setup-flow-footer">
                  <div className="setup-flow-metric">
                    <strong>20+</strong>
                    <span>安全模块参与判定</span>
                  </div>
                  <div className="setup-flow-metric">
                    <strong>Inbound / Outbound</strong>
                    <span>同一套网关统一处理双向邮件</span>
                  </div>
                  <div className="setup-flow-metric">
                    <strong>Quarantine Ready</strong>
                    <span>命中阈值即可转入隔离与分析流程</span>
                  </div>
                </div>
              </div>

              <p className="setup-step-note">
                先把监听地址、下游 MTA 和本地域名对齐到真实网络拓扑，后续策略与审计数据才会更贴近生产环境。
              </p>

              {/* Listen address */}
              <label className="setup-label">
                监听地址
                <span className="setup-hint">MTA 接收邮件的网卡绑定（0.0.0.0 = 所有网卡接收）</span>
              </label>
              <div className="setup-row">
                <select className="grok-input" defaultValue="0.0.0.0" style={{ flex: 1 }}>
                  <option value="0.0.0.0">0.0.0.0 — 所有网卡</option>
                  <option value="127.0.0.1">127.0.0.1 — 仅本机</option>
                  {interfaces.map(iface => (
                    <option key={iface.name} value={iface.name}>{iface.name} — {formatBytes(iface.total_bytes)} 流量</option>
                  ))}
                </select>
                <div className="setup-inline-port">:25 / :465</div>
              </div>

              {/* Downstream relay */}
              <label className="setup-label">
                下游 MTA
                <span className="setup-hint">入站邮件检测通过后转发到的内部邮件服务器地址</span>
              </label>
              <div className="setup-row">
                <input className="grok-input" style={{ flex: 1 }}
                  value={mtaDownstreamHost} onChange={e => setMtaDownstreamHost(e.target.value)}
                  placeholder="10.1.246.33" />
                <input className="grok-input" style={{ width: 88, textAlign: 'center' }}
                  value={mtaDownstreamPort} onChange={e => setMtaDownstreamPort(e.target.value)}
                  placeholder="25" />
              </div>

            </div>
          )}

          {currentStep.id === 'network' && deployMode !== 'mta' && (
            <div className="setup-fields">
              <p className="setup-tip" style={{ marginBottom: 12, opacity: 0.7 }}>以下配置仅作为部署参考记录，实际抓包参数由容器环境变量控制（SNIFFER_INTERFACE、SMTP_PORTS 等）。</p>
              <label className="setup-label">
                监听网卡
                <span className="setup-hint">选择流量最大的网卡用于邮件协议抓包（已按流量降序排列）</span>
              </label>
              {ifaceLoading ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 0', color: 'rgba(255,255,255,0.4)', fontSize: 13 }}>
                  <span className="grok-spinner" /> 正在检测服务器网卡...
                </div>
              ) : interfaces.length > 0 ? (
                <div className="setup-iface-list">
                  {interfaces.map(iface => (
                    <button
                      key={iface.name}
                      type="button"
                      className={`setup-iface-card ${snifferIface === iface.name ? 'active' : ''}`}
                      onClick={() => setSnifferIface(iface.name)}
                    >
                      <div className="setup-iface-name">
                        {iface.name}
                        {iface.status === 'up' && <span className="setup-iface-up">UP</span>}
                        {interfaces[0]?.name === iface.name && <span className="setup-iface-rec">推荐</span>}
                      </div>
                      <div className="setup-iface-stats">
                        <span>RX {formatBytes(iface.rx_bytes)}</span>
                        <span>TX {formatBytes(iface.tx_bytes)}</span>
                      </div>
                    </button>
                  ))}
                </div>
              ) : (
                <input
                  type="text"
                  className="grok-input"
                  placeholder="eth0"
                  value={snifferIface}
                  onChange={e => setSnifferIface(e.target.value)}
                />
              )}
              {!ifaceLoading && interfaces.length === 0 && (
                <p className="setup-tip">未检测到网络接口，请手动输入网卡名称。</p>
              )}
              <div className="setup-row" style={{ marginTop: 16 }}>
                <div className="setup-field">
                  <label className="setup-label">
                    SMTP 端口
                    <span className="setup-hint">邮件发送</span>
                  </label>
                  <input type="text" className="grok-input" placeholder="25,465,587" value={smtpPorts} onChange={e => setSmtpPorts(e.target.value)} />
                </div>
                <div className="setup-field">
                  <label className="setup-label">
                    POP3 端口
                    <span className="setup-hint">邮件收取</span>
                  </label>
                  <input type="text" className="grok-input" placeholder="110,995" value={pop3Ports} onChange={e => setPop3Ports(e.target.value)} />
                </div>
                <div className="setup-field">
                  <label className="setup-label">
                    IMAP 端口
                    <span className="setup-hint">邮件访问</span>
                  </label>
                  <input type="text" className="grok-input" placeholder="143,993" value={imapPorts} onChange={e => setImapPorts(e.target.value)} />
                </div>
              </div>
            </div>
          )}

          {currentStep.id === 'domains' && (
            <div className="setup-fields">
              <label className="setup-label">
                组织内部邮件域名
                <span className="setup-hint">输入您组织使用的邮件域名，每行一个或逗号分隔</span>
              </label>
              <textarea
                className="grok-input setup-textarea"
                placeholder="example.com&#10;company.cn&#10;mail.corp.local"
                value={domains}
                onChange={e => setDomains(e.target.value)}
                rows={4}
              />
              <p className="setup-tip">
                引擎会自动学习内部域名，但手动配置可加速初始检测准确度。
              </p>
            </div>
          )}

          {currentStep.id === 'sniffer' && (
            <div className="setup-fields">
              <label className="setup-label">
                Webmail 服务器 IP
                <span className="setup-hint">需要监控 HTTP 流量的 Webmail 服务器地址，逗号分隔</span>
              </label>
              <input
                type="text"
                className="grok-input"
                placeholder="192.168.1.10, 10.0.0.20"
                value={webmailServers}
                onChange={e => setWebmailServers(e.target.value)}
              />
              <label className="setup-label" style={{ marginTop: 16 }}>
                HTTP 监听端口
                <span className="setup-hint">用于 HTTP 流量捕获的端口号，逗号分隔</span>
              </label>
              <input
                type="text"
                className="grok-input"
                placeholder="80,443,8080"
                value={httpPorts}
                onChange={e => setHttpPorts(e.target.value)}
              />
              <p className="setup-tip">
                如果不需要数据安全（HTTP 会话检测）功能，可跳过此步。
              </p>
            </div>
          )}

          {currentStep.id === 'alerts' && (
            <div className="setup-fields">
              <label className="setup-toggle-row">
                <span>启用邮件告警通知</span>
                <button
                  type="button"
                  className={`setup-toggle ${alertEnabled ? 'on' : ''}`}
                  onClick={() => setAlertEnabled(!alertEnabled)}
                >
                  <span className="setup-toggle-knob" />
                </button>
              </label>
              {alertEnabled && (
                <>
                  <div className="setup-row">
                    <div className="setup-field">
                      <label className="setup-label">SMTP 服务器</label>
                      <input type="text" className="grok-input" placeholder="smtp.example.com" value={smtpHost} onChange={e => setSmtpHost(e.target.value)} />
                    </div>
                    <div className="setup-field setup-field--sm">
                      <label className="setup-label">端口</label>
                      <input type="text" className="grok-input" placeholder="465" value={smtpPort} onChange={e => setSmtpPort(e.target.value)} />
                    </div>
                    <div className="setup-field setup-field--sm">
                      <label className="setup-label">加密</label>
                      <select className="grok-input" value={smtpTls} onChange={e => setSmtpTls(e.target.value)}>
                        <option value="tls">TLS</option>
                        <option value="starttls">STARTTLS</option>
                        <option value="none">无</option>
                      </select>
                    </div>
                  </div>
                  <div className="setup-row">
                    <div className="setup-field">
                      <label className="setup-label">用户名</label>
                      <input type="text" className="grok-input" placeholder="alert@example.com" value={smtpUser} onChange={e => setSmtpUser(e.target.value)} />
                    </div>
                    <div className="setup-field">
                      <label className="setup-label">密码</label>
                      <input type="password" className="grok-input" placeholder="SMTP 密码" value={smtpPass} onChange={e => setSmtpPass(e.target.value)} />
                    </div>
                  </div>
                  <div className="setup-row">
                    <div className="setup-field">
                      <label className="setup-label">发件地址</label>
                      <input type="email" className="grok-input" placeholder="vigilyx-alert@example.com" value={alertFrom} onChange={e => setAlertFrom(e.target.value)} />
                    </div>
                    <div className="setup-field">
                      <label className="setup-label">通知收件人</label>
                      <input type="email" className="grok-input" placeholder="admin@example.com" value={alertTo} onChange={e => setAlertTo(e.target.value)} />
                    </div>
                  </div>
                  <label className="setup-label">最低告警等级</label>
                  <div className="setup-level-pills">
                    {(['low', 'medium', 'high', 'critical'] as const).map(lv => (
                      <button
                        key={lv}
                        type="button"
                        className={`setup-pill ${alertLevel === lv ? 'active' : ''} setup-pill--${lv}`}
                        onClick={() => setAlertLevel(lv)}
                      >
                        {{ low: '低危', medium: '中危', high: '高危', critical: '严重' }[lv]}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}

          {currentStep.id === 'ai' && (
            <div className="setup-fields">
              <label className="setup-toggle-row">
                <span>启用 AI 威胁分析</span>
                <button
                  type="button"
                  className={`setup-toggle ${aiEnabled ? 'on' : ''}`}
                  onClick={() => setAiEnabled(!aiEnabled)}
                >
                  <span className="setup-toggle-knob" />
                </button>
              </label>
              {aiEnabled && (
                <>
                  <label className="setup-label" style={{ marginTop: 12 }}>
                    AI 服务地址
                    <span className="setup-hint">Docker 部署默认 http://vigilyx-ai:8900</span>
                  </label>
                  <input
                    type="text"
                    className="grok-input"
                    placeholder="http://vigilyx-ai:8900"
                    value={aiUrl}
                    onChange={e => setAiUrl(e.target.value)}
                  />
                  <p className="setup-tip">
                    AI 服务基于 mDeBERTa 零样本模型，首次启动需要下载模型（约 550MB）。
                  </p>
                </>
              )}
              {!aiEnabled && (
                <p className="setup-tip">
                  AI 服务为可选组件，关闭后引擎仍可使用规则 + 情报进行检测。
                </p>
              )}
            </div>
          )}

          {/* Footer buttons - step 0 buttons were moved to the title row */}
          {step > 0 && (
            <div className="setup-footer">
              <button type="button" className="setup-btn setup-btn--ghost" onClick={handleBack} disabled={saving}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M19 12H5m7 7-7-7 7-7"/></svg>
                上一步
              </button>
              <div className="setup-footer-right">
                <button type="button" className="setup-btn setup-btn--ghost" onClick={handleSkip} disabled={saving}>
                  跳过
                </button>
                <button type="submit" className="setup-btn setup-btn--primary" disabled={saving}>
                  {saving && <span className="grok-spinner" />}
                  {step === STEPS.length - 1 ? '完成' : '下一步'}
                  {!saving && step < STEPS.length - 1 && (
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ marginLeft: 6 }}><path d="M5 12h14m-7-7 7 7-7 7"/></svg>
                  )}
                </button>
              </div>
            </div>
          )}
        </form>
      </div>
    </div>
  )
}
