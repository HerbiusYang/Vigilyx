import { useState, useEffect, useRef, FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
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
  const glowVars = useWizardGlows()

  // Build STEPS with translated titles/subtitles
  const STEPS = [
    { id: 'welcome' as const, title: t('setup.welcomeTitle'), subtitle: t('setup.welcomeSubtitle') },
    { id: 'deploy_mode' as const, title: t('setup.deployModeTitle'), subtitle: t('setup.deployModeSubtitle') },
    { id: 'network' as const, title: t('setup.networkTitle'), subtitle: t('setup.networkSubtitle') },
    { id: 'domains' as const, title: t('setup.domainsTitle'), subtitle: t('setup.domainsSubtitle') },
    { id: 'sniffer' as const, title: t('setup.snifferTitle'), subtitle: t('setup.snifferSubtitle') },
    { id: 'alerts' as const, title: t('setup.alertsTitle'), subtitle: t('setup.alertsSubtitle') },
    { id: 'ai' as const, title: t('setup.aiTitle'), subtitle: t('setup.aiSubtitle') },
  ]

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
  const [allowPlaintextSmtp, setAllowPlaintextSmtp] = useState(false)
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
        title: deployMode === 'mta' ? t('setup.networkMtaTitle') : t('setup.networkSnifferTitle'),
        subtitle: deployMode === 'mta' ? t('setup.networkMtaSubtitle') : t('setup.networkSnifferSubtitle'),
      }
    : rawStep

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
        if (!data.success) throw new Error(data.error || t('setup.saveFailed'))
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
            if (!data.success) throw new Error(data.error || t('setup.saveDomainsFailed'))
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
          if (!data.success) throw new Error(data.error || t('setup.saveDomainsFailed'))
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
          if (smtpTls === 'none' && !allowPlaintextSmtp) {
            throw new Error(getPlaintextSmtpLockMessage())
          }
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
              allow_plaintext_smtp: allowPlaintextSmtp,
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
      const msg = e instanceof Error ? e.message : t('setup.saveFailed')
      setError(normalizeSmtpUiError(msg))
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
            <span className="setup-step-chip">{t('setup.securityGuide')}</span>
            <span className="setup-step-count">
              {String(step + 1).padStart(2, '0')} / {String(STEPS.length).padStart(2, '0')}
            </span>
          </div>
          <div className="setup-title-row">
            <h2 className="setup-title">{currentStep.title}</h2>
            {step === 0 && (
              <button type="button" className="setup-btn setup-btn--primary" disabled={saving} onClick={() => handleNext()}>
                {saving && <span className="grok-spinner" />}
                {t('setup.startConfig')}
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
                  {t('setup.welcomeText')}
                </p>
              </div>

              <div className="setup-feature-grid">
                {FEATURE_KEYS.map(f => (
                  <div key={f.titleKey} className="setup-feature-card">
                    <div className="setup-feature-icon" style={{ color: f.accent, borderColor: f.accent + '33', background: f.accent + '14' }}>
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
                {t('setup.welcomeHint')}
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
                    <strong>8s</strong>
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
                      <span>Inline verdict</span>
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
                    <strong>20+</strong>
                    <span>{t('setup.flowMetricModules')}</span>
                  </div>
                  <div className="setup-flow-metric">
                    <strong>Inbound / Outbound</strong>
                    <span>{t('setup.flowMetricBidirectional')}</span>
                  </div>
                  <div className="setup-flow-metric">
                    <strong>Quarantine Ready</strong>
                    <span>{t('setup.flowMetricQuarantine')}</span>
                  </div>
                </div>
              </div>

              <p className="setup-step-note">
                {t('setup.networkMtaNote')}
              </p>

              {/* Listen address */}
              <label className="setup-label">
                {t('setup.listenAddress')}
                <span className="setup-hint">{t('setup.listenAddressHint')}</span>
              </label>
              <div className="setup-row">
                <select className="grok-input" defaultValue="0.0.0.0" style={{ flex: 1 }}>
                  <option value="0.0.0.0">{t('setup.allInterfaces')}</option>
                  <option value="127.0.0.1">{t('setup.localhostOnly')}</option>
                  {interfaces.map(iface => (
                    <option key={iface.name} value={iface.name}>{iface.name} — {formatBytes(iface.total_bytes)} {t('setup.traffic')}</option>
                  ))}
                </select>
                <div className="setup-inline-port">:25 / :465</div>
              </div>

              {/* Downstream relay */}
              <label className="setup-label">
                {t('setup.downstreamMta')}
                <span className="setup-hint">{t('setup.downstreamMtaHint')}</span>
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
              <p className="setup-tip" style={{ marginBottom: 12, opacity: 0.7 }}>{t('setup.networkEnvNote')}</p>
              <label className="setup-label">
                {t('setup.snifferInterface')}
                <span className="setup-hint">{t('setup.snifferInterfaceHint')}</span>
              </label>
              {ifaceLoading ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 0', color: 'rgba(255,255,255,0.4)', fontSize: 13 }}>
                  <span className="grok-spinner" /> {t('setup.detectingInterfaces')}
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
                        {interfaces[0]?.name === iface.name && <span className="setup-iface-rec">{t('setup.recommended')}</span>}
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
                <p className="setup-tip">{t('setup.noInterfacesDetected')}</p>
              )}
              <div className="setup-row" style={{ marginTop: 16 }}>
                <div className="setup-field">
                  <label className="setup-label">
                    {t('setup.smtpPorts')}
                    <span className="setup-hint">{t('setup.smtpPortsHint')}</span>
                  </label>
                  <input type="text" className="grok-input" placeholder="25,465,587" value={smtpPorts} onChange={e => setSmtpPorts(e.target.value)} />
                </div>
                <div className="setup-field">
                  <label className="setup-label">
                    {t('setup.pop3Ports')}
                    <span className="setup-hint">{t('setup.pop3PortsHint')}</span>
                  </label>
                  <input type="text" className="grok-input" placeholder="110,995" value={pop3Ports} onChange={e => setPop3Ports(e.target.value)} />
                </div>
                <div className="setup-field">
                  <label className="setup-label">
                    {t('setup.imapPorts')}
                    <span className="setup-hint">{t('setup.imapPortsHint')}</span>
                  </label>
                  <input type="text" className="grok-input" placeholder="143,993" value={imapPorts} onChange={e => setImapPorts(e.target.value)} />
                </div>
              </div>
            </div>
          )}

          {currentStep.id === 'domains' && (
            <div className="setup-fields">
              <label className="setup-label">
                {t('setup.internalDomains')}
                <span className="setup-hint">{t('setup.internalDomainsHint')}</span>
              </label>
              <textarea
                className="grok-input setup-textarea"
                placeholder="example.com&#10;company.cn&#10;mail.corp.local"
                value={domains}
                onChange={e => setDomains(e.target.value)}
                rows={4}
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
                      <input type="text" className="grok-input" placeholder="smtp.example.com" value={smtpHost} onChange={e => setSmtpHost(e.target.value)} />
                    </div>
                    <div className="setup-field setup-field--sm">
                      <label className="setup-label">{t('setup.port')}</label>
                      <input type="text" className="grok-input" placeholder="465" value={smtpPort} onChange={e => setSmtpPort(e.target.value)} />
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
                      <input type="password" className="grok-input" placeholder={t('setup.smtpPasswordPlaceholder')} value={smtpPass} onChange={e => setSmtpPass(e.target.value)} />
                    </div>
                  </div>
                  <p className="setup-security-note">
                    {t('setup.smtpNoAuthNote')}
                  </p>
                  <div className="setup-row">
                    <div className="setup-field">
                      <label className="setup-label">{t('setup.fromAddress')}</label>
                      <input type="email" className="grok-input" placeholder="vigilyx-alert@example.com" value={alertFrom} onChange={e => setAlertFrom(e.target.value)} />
                    </div>
                    <div className="setup-field">
                      <label className="setup-label">{t('setup.alertRecipient')}</label>
                      <input type="email" className="grok-input" placeholder="admin@example.com" value={alertTo} onChange={e => setAlertTo(e.target.value)} />
                    </div>
                  </div>
                  <label className="setup-label">{t('setup.minAlertLevel')}</label>
                  <div className="setup-level-pills">
                    {(['low', 'medium', 'high', 'critical'] as const).map(lv => (
                      <button
                        key={lv}
                        type="button"
                        className={`setup-pill ${alertLevel === lv ? 'active' : ''} setup-pill--${lv}`}
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
                <button type="button" className="setup-btn setup-btn--ghost" onClick={handleSkip} disabled={saving}>
                  {t('setup.skip')}
                </button>
                <button type="submit" className="setup-btn setup-btn--primary" disabled={saving}>
                  {saving && <span className="grok-spinner" />}
                  {step === STEPS.length - 1 ? t('setup.finish') : t('setup.nextStep')}
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
