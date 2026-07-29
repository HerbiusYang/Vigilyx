import { useState, useEffect, useRef, FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import LanguageToggle from '../settings/LanguageToggle'
import { apiFetch } from '../../utils/api'
import { persistSetupStatus } from '../../utils/setupStatus'
import { formatBytes } from '../../utils/format'

import i18n from '../../i18n'

interface NetInterface {
  name: string
  rx_bytes: number
  tx_bytes: number
  total_bytes: number
  status: string
}

interface ApiEnvelope<T> {
  success: boolean
  data?: T
  error?: string
}

interface DeploymentModeData {
  mode?: string
  locked?: boolean
  mta_config?: Record<string, unknown>
}

interface SnifferConfigData {
  webmail_servers?: string[]
  http_ports?: number[]
}

interface EmailAlertData {
  enabled?: boolean
  smtp_host?: string
  smtp_port?: number
  smtp_username?: string
  smtp_password_set?: boolean
  smtp_tls?: string
  allow_plaintext_smtp?: boolean
  from_address?: string
  admin_email?: string
  min_threat_level?: string
}

interface AiConfigData {
  enabled?: boolean
  service_url?: string
}

async function loadConfig<T>(path: string): Promise<T> {
  const response = await apiFetch(path)
  const payload = await response.json() as ApiEnvelope<T>
  if (!payload.success || payload.data === undefined) {
    throw new Error(payload.error || `Failed to load ${path}`)
  }
  return payload.data
}

function parsePort(value: string): number | null {
  if (!/^\d+$/.test(value.trim())) return null
  const port = Number(value)
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null
}

function parsePortList(value: string): number[] | null {
  if (!value.trim()) return []
  const parsed = value.split(',').map(port => parsePort(port))
  if (parsed.some(port => port === null)) return null
  return [...new Set(parsed as number[])]
}

function getPlaintextSmtpLockMessage(): string {
  return i18n.t('setup.plaintextSmtpLock')
}

function normalizeSmtpUiError(message: string): string {
  if (
    message.includes('SMTP plaintext mode blocked') ||
    message.includes('allow_plaintext_smtp')
  ) {
    return getPlaintextSmtpLockMessage()
  }
  if (message.includes('No compatible authentication mechanism')) {
    return i18n.t('setup.noAuthMechanism')
  }
  if (message.includes('must either both be filled or both be left empty')) {
    return i18n.t('setup.smtpCredentialsBothOrNone')
  }
  return message
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

const FEATURE_KEYS = [
  { icon: 'shield', accent: '#22d3ee', titleKey: 'setup.featureMultiEngine', descKey: 'setup.featureMultiEngineDesc' },
  { icon: 'zap', accent: '#f59e0b', titleKey: 'setup.featureDualMode', descKey: 'setup.featureDualModeDesc' },
  { icon: 'brain', accent: '#a855f7', titleKey: 'setup.featureAi', descKey: 'setup.featureAiDesc' },
  { icon: 'globe', accent: '#3b82f6', titleKey: 'setup.featureIntel', descKey: 'setup.featureIntelDesc' },
  { icon: 'lock', accent: '#22c55e', titleKey: 'setup.featureDlp', descKey: 'setup.featureDlpDesc' },
  { icon: 'activity', accent: '#f43f5e', titleKey: 'setup.featureSoar', descKey: 'setup.featureSoarDesc' },
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
  const { t } = useTranslation()
  const [step, setStep] = useState(0)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [configLoading, setConfigLoading] = useState(true)
  const [configLoadFailed, setConfigLoadFailed] = useState(false)
  const glowVars = useWizardGlows()

  // ── Step: Deploy Mode ──
  const [deployMode, setDeployMode] = useState<'mirror' | 'mta'>('mirror')
  const [deployModeLocked, setDeployModeLocked] = useState(false)
  const [mtaDownstreamHost, setMtaDownstreamHost] = useState('')
  const [mtaDownstreamPort, setMtaDownstreamPort] = useState('25')

  // ── Step: Network Capture ──
  const [interfaces, setInterfaces] = useState<NetInterface[]>([])
  const [ifaceLoading, setIfaceLoading] = useState(false)
  const [interfaceLoadFailed, setInterfaceLoadFailed] = useState(false)

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
  const [smtpPasswordSet, setSmtpPasswordSet] = useState(false)
  const [smtpTls, setSmtpTls] = useState('tls')
  const [allowPlaintextSmtp, setAllowPlaintextSmtp] = useState(false)
  const [alertFrom, setAlertFrom] = useState('')
  const [alertTo, setAlertTo] = useState('')
  const [alertLevel, setAlertLevel] = useState('high')

  // ── Step 4: AI Service ──
  const [aiEnabled, setAiEnabled] = useState(false)
  const [aiUrl, setAiUrl] = useState('http://vigilyx-ai:8900')

  // Only show settings that belong to the selected runtime mode.
  const STEPS = [
    { id: 'welcome' as const, title: t('setup.welcomeTitle'), subtitle: t('setup.welcomeSubtitle') },
    { id: 'deploy_mode' as const, title: t('setup.deployModeTitle'), subtitle: t('setup.deployModeSubtitle') },
    {
      id: 'network' as const,
      title: deployMode === 'mta' ? t('setup.networkMtaTitle') : t('setup.networkSnifferTitle'),
      subtitle: deployMode === 'mta' ? t('setup.networkMtaSubtitle') : t('setup.networkSnifferSubtitle'),
    },
    ...(deployMode === 'mta'
      ? [{ id: 'domains' as const, title: t('setup.domainsTitle'), subtitle: t('setup.domainsSubtitle') }]
      : [{ id: 'sniffer' as const, title: t('setup.snifferTitle'), subtitle: t('setup.snifferSubtitle') }]),
    { id: 'alerts' as const, title: t('setup.alertsTitle'), subtitle: t('setup.alertsSubtitle') },
    { id: 'ai' as const, title: t('setup.aiTitle'), subtitle: t('setup.aiSubtitle') },
  ]

  const currentStep = STEPS[step]
  const isLastStep = step === STEPS.length - 1
  const canSkipCurrentStep = currentStep.id === 'sniffer'
    || currentStep.id === 'alerts'
    || currentStep.id === 'ai'
    || (currentStep.id === 'network' && deployMode === 'mirror')

  // Load server-backed settings so a reset/reopened wizard never overwrites
  // existing configuration with hard-coded defaults.
  useEffect(() => {
    let cancelled = false

    void Promise.allSettled([
      loadConfig<DeploymentModeData>('/api/config/deployment-mode'),
      loadConfig<SnifferConfigData>('/api/config/sniffer'),
      loadConfig<EmailAlertData>('/api/security/email-alert'),
      loadConfig<AiConfigData>('/api/security/ai-config'),
    ]).then(([deploymentResult, snifferResult, alertResult, aiResult]) => {
      if (cancelled) return

      const results = [deploymentResult, snifferResult, alertResult, aiResult]
      setConfigLoadFailed(results.some(result => result.status === 'rejected'))

      if (deploymentResult.status === 'fulfilled') {
        const config = deploymentResult.value
        if (config.mode === 'mirror' || config.mode === 'mta') setDeployMode(config.mode)
        setDeployModeLocked(Boolean(config.locked))
        const mta = config.mta_config
        if (mta) {
          if (typeof mta.mta_downstream_host === 'string') setMtaDownstreamHost(mta.mta_downstream_host)
          if (typeof mta.mta_downstream_port === 'number') setMtaDownstreamPort(String(mta.mta_downstream_port))
          if (typeof mta.mta_local_domains === 'string') setDomains(mta.mta_local_domains.split(',').join('\n'))
        }
      }

      if (snifferResult.status === 'fulfilled') {
        const config = snifferResult.value
        if (Array.isArray(config.webmail_servers)) setWebmailServers(config.webmail_servers.join(', '))
        if (Array.isArray(config.http_ports)) setHttpPorts(config.http_ports.join(','))
      }

      if (alertResult.status === 'fulfilled') {
        const config = alertResult.value
        setAlertEnabled(Boolean(config.enabled))
        if (typeof config.smtp_host === 'string') setSmtpHost(config.smtp_host)
        if (typeof config.smtp_port === 'number') setSmtpPort(String(config.smtp_port))
        if (typeof config.smtp_username === 'string') setSmtpUser(config.smtp_username)
        setSmtpPasswordSet(Boolean(config.smtp_password_set))
        if (typeof config.smtp_tls === 'string') setSmtpTls(config.smtp_tls)
        setAllowPlaintextSmtp(Boolean(config.allow_plaintext_smtp))
        if (typeof config.from_address === 'string') setAlertFrom(config.from_address)
        if (typeof config.admin_email === 'string') setAlertTo(config.admin_email)
        if (typeof config.min_threat_level === 'string') setAlertLevel(config.min_threat_level)
      }

      if (aiResult.status === 'fulfilled') {
        const config = aiResult.value
        setAiEnabled(Boolean(config.enabled))
        if (typeof config.service_url === 'string') setAiUrl(config.service_url)
      }
    }).finally(() => {
      if (!cancelled) setConfigLoading(false)
    })

    return () => { cancelled = true }
  }, [])

  // Interface discovery is informational: capture binding itself is controlled
  // by deployment environment variables and requires a redeploy.
  useEffect(() => {
    if (currentStep.id !== 'network' || deployMode !== 'mirror') return
    let cancelled = false
    setIfaceLoading(true)
    setInterfaceLoadFailed(false)
    apiFetch('/api/system/interfaces')
      .then(response => response.json() as Promise<ApiEnvelope<NetInterface[]>>)
      .then(payload => {
        if (cancelled) return
        if (!payload.success || !Array.isArray(payload.data)) {
          throw new Error(payload.error || 'Interface discovery failed')
        }
        setInterfaces(payload.data)
      })
      .catch(() => {
        if (!cancelled) setInterfaceLoadFailed(true)
      })
      .finally(() => {
        if (!cancelled) setIfaceLoading(false)
      })

    return () => { cancelled = true }
  }, [step, deployMode])

  const finishSetup = async () => {
    setError(null)
    setSaving(true)

    try {
      const saved = await persistSetupStatus(true)
      if (!saved) {
        setError(t('setup.saveSetupFailed'))
        return
      }
      onComplete()
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t('setup.saveSetupFailed')
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  const putConfig = async (path: string, body: Record<string, unknown>, fallbackMessage: string) => {
    const response = await apiFetch(path, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const payload = await response.json() as ApiEnvelope<unknown>
    if (!payload.success) throw new Error(payload.error || fallbackMessage)
  }

  const saveStep = async () => {
    setError(null)
    setSaving(true)
    try {
      if (currentStep.id === 'deploy_mode') {
        if (!deployModeLocked) {
          await putConfig(
            '/api/config/deployment-mode',
            { mode: deployMode },
            t('setup.saveFailed'),
          )
        }
        localStorage.setItem('vigilyx-deploy-mode', deployMode)
      } else if (currentStep.id === 'network' && deployMode === 'mta') {
        const downstreamHost = mtaDownstreamHost.trim()
        const downstreamPort = parsePort(mtaDownstreamPort)
        if (!downstreamHost) throw new Error(t('setup.downstreamRequired'))
        if (downstreamPort === null) throw new Error(t('setup.invalidPort'))

        await putConfig(
          '/api/config/deployment-mode',
          {
            mta_downstream_host: downstreamHost,
            mta_downstream_port: downstreamPort,
          },
          t('setup.saveFailed'),
        )
        localStorage.setItem('vigilyx-mta-downstream-host', downstreamHost)
        localStorage.setItem('vigilyx-mta-downstream-port', String(downstreamPort))
      } else if (currentStep.id === 'domains') {
        const domainList = domains
          .split(/[,\n]/)
          .map(d => d.trim().toLowerCase())
          .filter(Boolean)
        if (domainList.length === 0) throw new Error(t('setup.domainsRequired'))
        const normalizedDomains = [...new Set(domainList)].join(',')
        await putConfig(
          '/api/config/deployment-mode',
          { mta_local_domains: normalizedDomains },
          t('setup.saveDomainsFailed'),
        )
        localStorage.setItem('vigilyx-mta-local-domains', normalizedDomains)
      } else if (currentStep.id === 'sniffer') {
        const servers = webmailServers
          .split(/[,\n]/)
          .map(server => server.trim())
          .filter(Boolean)
        const ports = parsePortList(httpPorts)
        if (ports === null) throw new Error(t('setup.invalidPortList'))

        await putConfig(
          '/api/config/sniffer',
          { webmail_servers: [...new Set(servers)], http_ports: ports },
          t('setup.saveFailed'),
        )
      } else if (currentStep.id === 'alerts') {
        if (alertEnabled) {
          const parsedSmtpPort = parsePort(smtpPort)
          if (!smtpHost.trim() || !alertFrom.trim() || !alertTo.trim()) {
            throw new Error(t('setup.alertRequiredFields'))
          }
          if (parsedSmtpPort === null) throw new Error(t('setup.invalidPort'))
          if (smtpTls === 'none' && !allowPlaintextSmtp) {
            throw new Error(getPlaintextSmtpLockMessage())
          }
        }

        const alertBody: Record<string, unknown> = {
          enabled: alertEnabled,
          smtp_host: smtpHost.trim(),
          smtp_port: parsePort(smtpPort) ?? 465,
          smtp_username: smtpUser.trim(),
          smtp_tls: smtpTls,
          allow_plaintext_smtp: allowPlaintextSmtp,
          from_address: alertFrom.trim(),
          admin_email: alertTo.trim(),
          min_threat_level: alertLevel,
          notify_recipient: false,
          notify_admin: true,
        }
        // Omitting an unchanged blank password preserves an existing encrypted secret.
        if (smtpPass) alertBody.smtp_password = smtpPass
        await putConfig('/api/security/email-alert', alertBody, t('setup.saveFailed'))
      } else if (currentStep.id === 'ai') {
        if (aiEnabled && !aiUrl.trim()) throw new Error(t('setup.aiUrlRequired'))
        await putConfig(
          '/api/security/ai-config',
          {
            enabled: aiEnabled,
            service_url: aiUrl.trim() || 'http://vigilyx-ai:8900',
            provider: 'local',
            model: 'mDeBERTa',
            temperature: 0.0,
            max_tokens: 512,
            timeout_secs: 30,
          },
          t('setup.saveFailed'),
        )
      }
      return true
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : t('setup.saveFailed')
      setError(normalizeSmtpUiError(msg))
      return false
    } finally {
      setSaving(false)
    }
  }

  const handleNext = async (e?: FormEvent) => {
    e?.preventDefault()
    if (currentStep.id === 'welcome') {
      setStep(current => current + 1)
      return
    }
    const ok = await saveStep()
    if (!ok) return
    if (!isLastStep) {
      setStep(current => current + 1)
      setError(null)
    } else {
      await finishSetup()
    }
  }

  const handleBack = () => {
    if (step > 0) {
      setStep(current => current - 1)
      setError(null)
    }
  }

  const handleSkip = () => {
    if (!canSkipCurrentStep) return
    if (!isLastStep) {
      setStep(current => current + 1)
      setError(null)
    } else {
      void finishSetup()
    }
  }

  return (
    <div className="grok-login" style={glowVars as React.CSSProperties}>
      <div className="grok-bg" />

      <div className="setup-wizard">
        <div className="setup-toolbar">
          {/* Progress bar */}
          <div
            className="setup-progress"
            role="progressbar"
            aria-label={t('setup.progressLabel')}
            aria-valuemin={1}
            aria-valuemax={STEPS.length}
            aria-valuenow={step + 1}
            aria-valuetext={t('setup.progressText', { current: step + 1, total: STEPS.length })}
          >
            {STEPS.map((s, i) => (
              <div key={s.id} aria-hidden="true" className={`setup-progress-dot ${i === step ? 'active' : i < step ? 'done' : ''}`}>
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
          <div className="setup-language-toggle">
            <LanguageToggle variant="segmented" />
          </div>
        </div>

        {/* Header */}
        <div className="setup-header">
          <div className="setup-step-meta">
            <span className="setup-step-chip">{t('setup.initialSetup')}</span>
            <span className="setup-step-count">
              {String(step + 1).padStart(2, '0')} / {String(STEPS.length).padStart(2, '0')}
            </span>
          </div>
          <div className="setup-title-row">
            <h2 className="setup-title">{currentStep.title}</h2>
            {step === 0 && (
              <button type="button" className="setup-btn setup-btn--primary" disabled={saving || configLoading} onClick={() => handleNext()}>
                {(saving || configLoading) && <span className="grok-spinner" />}
                {configLoading ? t('setup.loadingConfig') : t('setup.startConfig')}
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ marginLeft: 4 }}><path d="M5 12h14m-7-7 7 7-7 7"/></svg>
              </button>
            )}
          </div>
          <p className="setup-subtitle">{currentStep.subtitle}</p>
        </div>

        {configLoadFailed && (
          <div className="setup-warning" role="status">{t('setup.loadConfigFailed')}</div>
        )}
        {error && <div className="grok-error" role="alert" style={{ marginBottom: 16 }}>{error}</div>}

        {/* Step content */}
        <form onSubmit={handleNext} className="setup-body">
          {currentStep.id === 'welcome' && (
            <div className="setup-welcome">
              <div className="setup-hero-copy">
                <div className="setup-hero-emblem" aria-hidden="true">
                  {FEATURE_ICONS.shield}
                </div>
                <div className="setup-hero-message">
                  <span className="setup-eyebrow">{t('setup.platformEyebrow')}</span>
                  <p className="setup-welcome-text">
                    {t('setup.welcomeText')}
                  </p>
                </div>
                <div className="setup-hero-lines" aria-hidden="true">
                  <span />
                  <span />
                  <span />
                </div>
              </div>

              <div className="setup-feature-grid">
                {FEATURE_KEYS.map((f, index) => (
                  <div
                    key={f.titleKey}
                    className="setup-feature-card"
                    style={{ '--feature-accent': f.accent } as React.CSSProperties}
                  >
                    <span className="setup-feature-index" aria-hidden="true">{String(index + 1).padStart(2, '0')}</span>
                    <div className="setup-feature-icon">
                      {FEATURE_ICONS[f.icon]}
                    </div>
                    <div className="setup-feature-copy">
                      <strong className="setup-feature-title">{t(f.titleKey)}</strong>
                      <span className="setup-feature-desc">{t(f.descKey)}</span>
                    </div>
                  </div>
                ))}
              </div>

              <p className="setup-welcome-hint">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
                  <circle cx="12" cy="12" r="9" />
                  <path d="M12 11v5M12 8h.01" />
                </svg>
                <span>{t('setup.welcomeHint')}</span>
              </p>
            </div>
          )}

          {currentStep.id === 'deploy_mode' && (
            <div className="setup-fields">
              <p className="setup-section-lead">
                {t('setup.deployModeLead')}
              </p>

              <div className="setup-mode-grid">
                <button
                  type="button"
                  className={`setup-mode-card ${deployMode === 'mirror' ? 'active' : ''}`}
                  data-mode="mirror"
                  aria-pressed={deployMode === 'mirror'}
                  disabled={deployModeLocked}
                  onClick={() => setDeployMode('mirror')}
                >
                  <div className="setup-mode-head">
                    <span className="setup-mode-radio" aria-hidden="true" />
                    <div>
                      <div className="setup-mode-title-row">
                        <span className="setup-mode-title">{t('setup.mirrorTitle')}</span>
                        <span className="setup-mode-badge">{t('setup.mirrorBadge')}</span>
                      </div>
                      <p className="setup-mode-copy">
                        {t('setup.mirrorDesc')}
                      </p>
                    </div>
                  </div>
                  <div className="setup-mode-chip-row">
                    <span className="setup-chip">{t('setup.mirrorChip1')}</span>
                    <span className="setup-chip">{t('setup.mirrorChip2')}</span>
                    <span className="setup-chip">{t('setup.mirrorChip3')}</span>
                  </div>
                </button>

                <button
                  type="button"
                  className={`setup-mode-card ${deployMode === 'mta' ? 'active' : ''}`}
                  data-mode="mta"
                  aria-pressed={deployMode === 'mta'}
                  disabled={deployModeLocked}
                  onClick={() => setDeployMode('mta')}
                >
                  <div className="setup-mode-head">
                    <span className="setup-mode-radio" aria-hidden="true" />
                    <div>
                      <div className="setup-mode-title-row">
                        <span className="setup-mode-title">{t('setup.mtaTitle')}</span>
                        <span className="setup-mode-badge setup-mode-badge--mta">{t('setup.mtaBadge')}</span>
                      </div>
                      <p className="setup-mode-copy">
                        {t('setup.mtaDesc')}
                      </p>
                    </div>
                  </div>
                  <div className="setup-mode-chip-row">
                    <span className="setup-chip setup-chip--warn">{t('setup.mtaChip1')}</span>
                    <span className="setup-chip setup-chip--warn">{t('setup.mtaChip2')}</span>
                    <span className="setup-chip setup-chip--warn">{t('setup.mtaChip3')}</span>
                  </div>
                </button>
              </div>

              {deployModeLocked && (
                <p className="setup-warning" role="status">
                  {t('setup.modeLocked', { mode: deployMode === 'mta' ? t('setup.mtaTitle') : t('setup.mirrorTitle') })}
                </p>
              )}
              <p className="setup-security-note">{t('setup.modeRequiresRedeploy')}</p>
            </div>
          )}

          {currentStep.id === 'network' && deployMode === 'mta' && (
            <div className="setup-fields">
              <div className="setup-flow-shell">
                <div className="setup-flow-header">
                  <div>
                    <div className="setup-flow-kicker">{t('setup.flowTopologyDemo')}</div>
                    <div className="setup-flow-title">{t('setup.flowMtaInlinePath')}</div>
                  </div>
                  <div className="setup-flow-budget">
                    <span>{t('setup.flowInlineBudget')}</span>
                    <strong>{t('setup.flowInlineBudgetValue')}</strong>
                  </div>
                </div>

                <div className="setup-flow-legend">
                  <span className="setup-flow-legend-item">{t('setup.flowLegendRealtime')}</span>
                  <span className="setup-flow-legend-item">{t('setup.flowLegendForward')}</span>
                  <span className="setup-flow-legend-item">{t('setup.flowLegendQuarantine')}</span>
                  <span className="setup-flow-legend-item">{t('setup.flowLegendDlp')}</span>
                </div>

                <div className="setup-flow-grid">
                  <div className="setup-flow-row">
                    <div className="setup-flow-label">
                      <span className="setup-flow-tag setup-flow-tag--inbound">{t('setup.flowInbound')}</span>
                    </div>
                    <div className="setup-flow-node">
                      <strong>{t('setup.flowExternalSender')}</strong>
                      <span>{t('setup.flowExternalSenderDesc')}</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--gateway">
                      <strong>Vigilyx MTA</strong>
                      <span>{t('setup.flowTlsSession')}</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--inspection">
                      <strong>{t('setup.flowInlineInspection')}</strong>
                      <span>{t('setup.flowInlineInspectionDesc')}</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--delivery">
                      <strong>{t('setup.flowDownstreamMta')}</strong>
                      <span>{t('setup.flowDownstreamMtaDesc')}</span>
                    </div>
                  </div>

                  <div className="setup-flow-row">
                    <div className="setup-flow-label">
                      <span className="setup-flow-tag setup-flow-tag--risk">{t('setup.flowThresholdHit')}</span>
                    </div>
                    <div className="setup-flow-node">
                      <strong>{t('setup.flowEmailSession')}</strong>
                      <span>{t('setup.flowEmailSessionDesc')}</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--gateway">
                      <strong>{t('setup.flowPolicyVerdict')}</strong>
                      <span>{t('setup.flowInlineVerdict')}</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--quarantine">
                      <strong>{t('setup.flowQuarantine')}</strong>
                      <span>{t('setup.flowQuarantineDesc')}</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--quarantine">
                      <strong>{t('setup.flowReview')}</strong>
                      <span>{t('setup.flowReviewDesc')}</span>
                    </div>
                  </div>

                  <div className="setup-flow-row">
                    <div className="setup-flow-label">
                      <span className="setup-flow-tag setup-flow-tag--outbound">{t('setup.flowOutbound')}</span>
                    </div>
                    <div className="setup-flow-node">
                      <strong>{t('setup.flowInternalUser')}</strong>
                      <span>{t('setup.flowInternalUserDesc')}</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--gateway">
                      <strong>Vigilyx MTA</strong>
                      <span>{t('setup.flowSendChain')}</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node setup-flow-node--inspection">
                      <strong>{t('setup.flowDlpAudit')}</strong>
                      <span>{t('setup.flowDlpAuditDesc')}</span>
                    </div>
                    <div className="setup-flow-arrow" aria-hidden="true" />
                    <div className="setup-flow-node">
                      <strong>{t('setup.flowExternalRecipient')}</strong>
                      <span>{t('setup.flowExternalRecipientDesc')}</span>
                    </div>
                  </div>
                </div>

                <div className="setup-flow-footer">
                  <div className="setup-flow-metric">
                    <strong>{t('setup.flowMetricModulesValue')}</strong>
                    <span>{t('setup.flowMetricModules')}</span>
                  </div>
                  <div className="setup-flow-metric">
                    <strong>{t('setup.flowMetricDirectionValue')}</strong>
                    <span>{t('setup.flowMetricBidirectional')}</span>
                  </div>
                  <div className="setup-flow-metric">
                    <strong>{t('setup.flowMetricQuarantineValue')}</strong>
                    <span>{t('setup.flowMetricQuarantine')}</span>
                  </div>
                </div>
              </div>

              <p className="setup-step-note">
                {t('setup.networkMtaNote')}
              </p>

              <p className="setup-security-note">{t('setup.mtaListenDeployManaged')}</p>

              {/* Downstream relay */}
              <label className="setup-label" htmlFor="setup-mta-downstream-host">
                {t('setup.downstreamMta')}
                <span className="setup-hint">{t('setup.downstreamMtaHint')}</span>
              </label>
              <div className="setup-row">
                <input id="setup-mta-downstream-host" className="grok-input" style={{ flex: 1 }}
                  value={mtaDownstreamHost} onChange={e => setMtaDownstreamHost(e.target.value)}
                  placeholder="10.1.246.33" required />
                <input className="grok-input" style={{ width: 88, textAlign: 'center' }}
                  type="number" min="1" max="65535" inputMode="numeric"
                  aria-label={t('setup.downstreamPort')}
                  value={mtaDownstreamPort} onChange={e => setMtaDownstreamPort(e.target.value)}
                  placeholder="25" required />
              </div>
              <p className="setup-tip">{t('setup.mtaConfigRestartNote')}</p>

            </div>
          )}

          {currentStep.id === 'network' && deployMode !== 'mta' && (
            <div className="setup-fields">
              <p className="setup-security-note">{t('setup.networkEnvNote')}</p>
              <label className="setup-label">
                {t('setup.detectedInterfaces')}
                <span className="setup-hint">{t('setup.detectedInterfacesHint')}</span>
              </label>
              {ifaceLoading ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 0', color: 'rgba(255,255,255,0.4)', fontSize: 13 }}>
                  <span className="grok-spinner" /> {t('setup.detectingInterfaces')}
                </div>
              ) : interfaces.length > 0 ? (
                <div className="setup-iface-list">
                  {interfaces.map(iface => (
                    <div
                      key={iface.name}
                      className={`setup-iface-card ${interfaces[0]?.name === iface.name ? 'active' : ''}`}
                    >
                      <div className="setup-iface-name">
                        {iface.name}
                        {iface.status === 'up' && <span className="setup-iface-up">{t('setup.interfaceUp')}</span>}
                        {interfaces[0]?.name === iface.name && <span className="setup-iface-rec">{t('setup.recommended')}</span>}
                      </div>
                      <div className="setup-iface-stats">
                        <span>RX {formatBytes(iface.rx_bytes)}</span>
                        <span>TX {formatBytes(iface.tx_bytes)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : interfaceLoadFailed ? (
                <p className="setup-warning" role="status">{t('setup.interfacesLoadFailed')}</p>
              ) : null}
              {!ifaceLoading && !interfaceLoadFailed && interfaces.length === 0 && (
                <p className="setup-tip">{t('setup.noInterfacesDetected')}</p>
              )}
            </div>
          )}

          {currentStep.id === 'domains' && (
            <div className="setup-fields">
              <label className="setup-label" htmlFor="setup-mta-domains">
                {t('setup.internalDomains')}
                <span className="setup-hint">{t('setup.internalDomainsHint')}</span>
              </label>
              <textarea
                id="setup-mta-domains"
                className="grok-input setup-textarea"
                placeholder="example.com&#10;company.cn&#10;mail.corp.local"
                value={domains}
                onChange={e => setDomains(e.target.value)}
                rows={4}
                required
              />
              <p className="setup-tip">
                {t('setup.internalDomainsTip')}
              </p>
            </div>
          )}

          {currentStep.id === 'sniffer' && (
            <div className="setup-fields">
              <label className="setup-label">
                {t('setup.webmailServers')}
                <span className="setup-hint">{t('setup.webmailServersHint')}</span>
              </label>
              <input
                type="text"
                className="grok-input"
                placeholder="192.168.1.10, 10.0.0.20"
                value={webmailServers}
                onChange={e => setWebmailServers(e.target.value)}
              />
              <label className="setup-label" style={{ marginTop: 16 }}>
                {t('setup.httpPorts')}
                <span className="setup-hint">{t('setup.httpPortsHint')}</span>
              </label>
              <input
                type="text"
                className="grok-input"
                placeholder="80,443,8080"
                value={httpPorts}
                onChange={e => setHttpPorts(e.target.value)}
              />
              <p className="setup-tip">
                {t('setup.snifferSkipTip')}
              </p>
            </div>
          )}

          {currentStep.id === 'alerts' && (
            <div className="setup-fields">
              <label className="setup-toggle-row">
                <span>{t('setup.enableEmailAlerts')}</span>
                <button
                  type="button"
                  className={`setup-toggle ${alertEnabled ? 'on' : ''}`}
                  role="switch"
                  aria-checked={alertEnabled}
                  aria-label={t('setup.enableEmailAlerts')}
                  onClick={() => setAlertEnabled(!alertEnabled)}
                >
                  <span className="setup-toggle-knob" />
                </button>
              </label>
              {alertEnabled && (
                <>
                  <div className="setup-row">
                    <div className="setup-field">
                      <label className="setup-label">{t('setup.smtpServer')}</label>
                      <input type="text" className="grok-input" placeholder="smtp.example.com" value={smtpHost} onChange={e => setSmtpHost(e.target.value)} required={alertEnabled} />
                    </div>
                    <div className="setup-field setup-field--sm">
                      <label className="setup-label">{t('setup.port')}</label>
                      <input type="number" min="1" max="65535" inputMode="numeric" className="grok-input" placeholder="465" value={smtpPort} onChange={e => setSmtpPort(e.target.value)} required={alertEnabled} />
                    </div>
                    <div className="setup-field setup-field--sm">
                      <label className="setup-label">{t('setup.encryption')}</label>
                      <div className="setup-segmented" role="group" aria-label={t('setup.smtpEncryption')}>
                        <button
                          type="button"
                          className={`setup-seg-btn ${smtpTls === 'tls' ? 'active' : ''}`}
                          onClick={() => setSmtpTls('tls')}
                        >
                          TLS
                        </button>
                        <button
                          type="button"
                          className={`setup-seg-btn ${smtpTls === 'starttls' ? 'active' : ''}`}
                          onClick={() => setSmtpTls('starttls')}
                        >
                          STARTTLS
                        </button>
                        <button
                          type="button"
                          className={`setup-seg-btn setup-seg-btn--blocked ${smtpTls === 'none' ? 'active' : ''}`}
                          onClick={() => setSmtpTls('none')}
                          title={t('setup.noEncryptionHint')}
                        >
                          {t('setup.noEncryption')}
                        </button>
                      </div>
                    </div>
                  </div>
                  <p className="setup-security-note">
                    {t('setup.noEncryptionWarning')}
                  </p>
                  <label className="setup-label" style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12 }}>
                    <input
                      type="checkbox"
                      checked={allowPlaintextSmtp}
                      onChange={e => setAllowPlaintextSmtp(e.target.checked)}
                    />
                    <span>{t('setup.allowPlaintextSmtp')}</span>
                  </label>
                  <div className="setup-row">
                    <div className="setup-field">
                      <label className="setup-label">{t('setup.smtpUsername')}</label>
                      <input type="text" className="grok-input" placeholder="alert@example.com" value={smtpUser} onChange={e => setSmtpUser(e.target.value)} />
                    </div>
                    <div className="setup-field">
                      <label className="setup-label">{t('setup.smtpPassword')}</label>
                      <input
                        type="password"
                        className="grok-input"
                        placeholder={smtpPasswordSet ? t('setup.smtpPasswordConfigured') : t('setup.smtpPasswordPlaceholder')}
                        value={smtpPass}
                        onChange={e => {
                          setSmtpPass(e.target.value)
                          if (e.target.value) setSmtpPasswordSet(false)
                        }}
                      />
                    </div>
                  </div>
                  <p className="setup-security-note">
                    {t('setup.smtpNoAuthNote')}
                  </p>
                  <div className="setup-row">
                    <div className="setup-field">
                      <label className="setup-label">{t('setup.fromAddress')}</label>
                      <input type="email" className="grok-input" placeholder="vigilyx-alert@example.com" value={alertFrom} onChange={e => setAlertFrom(e.target.value)} required={alertEnabled} />
                    </div>
                    <div className="setup-field">
                      <label className="setup-label">{t('setup.alertRecipient')}</label>
                      <input type="email" className="grok-input" placeholder="admin@example.com" value={alertTo} onChange={e => setAlertTo(e.target.value)} required={alertEnabled} />
                    </div>
                  </div>
                  <label className="setup-label">{t('setup.minAlertLevel')}</label>
                  <div className="setup-level-pills">
                    {(['low', 'medium', 'high', 'critical'] as const).map(lv => (
                      <button
                        key={lv}
                        type="button"
                        className={`setup-pill ${alertLevel === lv ? 'active' : ''} setup-pill--${lv}`}
                        aria-pressed={alertLevel === lv}
                        onClick={() => setAlertLevel(lv)}
                      >
                        {{ low: t('setup.levelLow'), medium: t('setup.levelMedium'), high: t('setup.levelHigh'), critical: t('setup.levelCritical') }[lv]}
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
                <span>{t('setup.enableAi')}</span>
                <button
                  type="button"
                  className={`setup-toggle ${aiEnabled ? 'on' : ''}`}
                  role="switch"
                  aria-checked={aiEnabled}
                  aria-label={t('setup.enableAi')}
                  onClick={() => setAiEnabled(!aiEnabled)}
                >
                  <span className="setup-toggle-knob" />
                </button>
              </label>
              {aiEnabled && (
                <>
                  <label className="setup-label" style={{ marginTop: 12 }}>
                    {t('setup.aiServiceUrl')}
                    <span className="setup-hint">{t('setup.aiServiceUrlHint')}</span>
                  </label>
                  <input
                    type="text"
                    className="grok-input"
                    placeholder="http://vigilyx-ai:8900"
                    value={aiUrl}
                    onChange={e => setAiUrl(e.target.value)}
                    required={aiEnabled}
                  />
                  <p className="setup-tip">
                    {t('setup.aiModelNote')}
                  </p>
                </>
              )}
              {!aiEnabled && (
                <p className="setup-tip">
                  {t('setup.aiDisabledTip')}
                </p>
              )}
            </div>
          )}

          {/* Footer buttons - step 0 buttons were moved to the title row */}
          {step > 0 && (
            <div className="setup-footer">
              <button type="button" className="setup-btn setup-btn--ghost" onClick={handleBack} disabled={saving}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M19 12H5m7 7-7-7 7-7"/></svg>
                {t('setup.prevStep')}
              </button>
              <div className="setup-footer-right">
                {canSkipCurrentStep && (
                  <button type="button" className="setup-btn setup-btn--ghost" onClick={handleSkip} disabled={saving}>
                    {t('setup.skip')}
                  </button>
                )}
                <button type="submit" className="setup-btn setup-btn--primary" disabled={saving}>
                  {saving && <span className="grok-spinner" />}
                  {isLastStep ? t('setup.finish') : t('setup.nextStep')}
                  {!saving && !isLastStep && (
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
