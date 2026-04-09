import { useState, useEffect, useCallback, useRef } from 'react'
import { apiFetch } from '../../utils/api'

type DeployMode = 'mirror' | 'mta'

export default function DeploymentSettings() {
  const [deployMode, setDeployMode] = useState<DeployMode>(
    () => (localStorage.getItem('vigilyx-deploy-mode') as DeployMode) || 'mirror'
  )
  const [snifferInterface] = useState(
    () => localStorage.getItem('vigilyx-sniffer-iface') || 'eth0'
  )
  const [deploySaving, setDeploySaving] = useState(false)
  const [deploySaved, setDeploySaved] = useState(false)
  const [mtaDownstreamHost, setMtaDownstreamHost] = useState(
    () => localStorage.getItem('vigilyx-mta-downstream-host') || ''
  )
  const [mtaDownstreamPort, setMtaDownstreamPort] = useState(
    () => localStorage.getItem('vigilyx-mta-downstream-port') || '25'
  )
  const [mtaTimeout, setMtaTimeout] = useState(
    () => localStorage.getItem('vigilyx-mta-timeout') || '8'
  )
  const [deployModeSource, setDeployModeSource] = useState<string>('default')
  const [deployModeLocked, setDeployModeLocked] = useState(false)
  const [mtaLocalDomains, setMtaLocalDomains] = useState(() => localStorage.getItem('vigilyx-mta-local-domains') || '')
  const [mtaStarttls, setMtaStarttls] = useState(() => localStorage.getItem('vigilyx-mta-starttls') !== 'false')
  const [mtaFailOpen, setMtaFailOpen] = useState(false)
  const [mtaHostname, setMtaHostname] = useState(() => localStorage.getItem('vigilyx-mta-hostname') || 'vigilyx-mta')
  const [mtaMaxConn, setMtaMaxConn] = useState(() => localStorage.getItem('vigilyx-mta-max-conn') || '100')
  const [mtaDlpEnabled, setMtaDlpEnabled] = useState(() => localStorage.getItem('vigilyx-mta-dlp-enabled') !== 'false')
  const [mtaDlpAction, setMtaDlpAction] = useState(() => localStorage.getItem('vigilyx-mta-dlp-action') || 'quarantine')

  // Detected services status
  const [detectedServices, setDetectedServices] = useState<{ sniffer_online: boolean; mta_online: boolean }>({ sniffer_online: false, mta_online: false })
  const deployModeInitDone = useRef(false)

  // Mode-switch notice
  const [switchMsg, setSwitchMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const deployAutoSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const deployInitLoaded = useRef(false)
  const deploySkipNextAutoSave = useRef(false)

  // Load the deployment mode from the API (initial load + periodic service-status refresh)
  useEffect(() => {
    const load = () => {
      apiFetch('/api/config/deployment-mode')
        .then(res => res.json())
        .then(data => {
          if (data.success && data.data) {
            // Set the mode only on first load; later polling only updates the service-status indicators
            if (!deployModeInitDone.current) {
              deployModeInitDone.current = true
              deploySkipNextAutoSave.current = true
              localStorage.removeItem('vigilyx-mta-fail-open')
              const m = data.data.mode as DeployMode
              if (m === 'mirror' || m === 'mta') setDeployMode(m)
              setDeployModeSource(data.data.source || 'default')
              setDeployModeLocked(!!data.data.locked)
              const mc = data.data.mta_config || {}
              if (data.data.mta_config) {
                if (mc.mta_downstream_host) setMtaDownstreamHost(mc.mta_downstream_host)
                if (mc.mta_downstream_port) setMtaDownstreamPort(String(mc.mta_downstream_port))
                if (mc.mta_inline_timeout_secs) setMtaTimeout(String(mc.mta_inline_timeout_secs))
                if (mc.mta_hostname) setMtaHostname(mc.mta_hostname)
                if (mc.mta_max_connections) setMtaMaxConn(String(mc.mta_max_connections))
                if (mc.mta_starttls !== undefined) setMtaStarttls(mc.mta_starttls)
                if (mc.mta_local_domains) setMtaLocalDomains(mc.mta_local_domains)
                if (mc.mta_dlp_enabled !== undefined) setMtaDlpEnabled(mc.mta_dlp_enabled)
                if (mc.mta_dlp_action) setMtaDlpAction(mc.mta_dlp_action)
              }
              setMtaFailOpen(mc.mta_fail_open === true)
            }
            // Always keep service online/offline state updated
            if (data.data.detected_services) setDetectedServices(data.data.detected_services)
          }
        })
        .catch(() => {})
    }
    load()
    const timer = setInterval(load, 15000)
    return () => clearInterval(timer)
  }, [])

  // Switch modes immediately and show a notice
  const switchDeployMode = useCallback(async (mode: DeployMode) => {
    setDeployMode(mode)
    localStorage.setItem('vigilyx-deploy-mode', mode)
    setDeploySaving(true)
    setSwitchMsg(null)
    // Optimistic update: reflect the switch result immediately
    setDetectedServices({
      sniffer_online: mode === 'mirror',
      mta_online: mode === 'mta',
    })
    try {
      const res = await apiFetch('/api/config/deployment-mode', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      })
      const data = await res.json()
      if (data.success) {
        if (data.data?.detected_services) setDetectedServices(data.data.detected_services)
        window.dispatchEvent(new CustomEvent('vigilyx:deploy-mode-changed', { detail: mode }))
        setSwitchMsg({ type: 'success', text: mode === 'mta' ? '已切换到 MTA 网关模式，Sniffer 已停止' : '已切换到镜像监听模式，MTA 已停止' })
      } else {
        setSwitchMsg({ type: 'error', text: data.error || '切换失败' })
        // Roll back
        const prev: DeployMode = mode === 'mta' ? 'mirror' : 'mta'
        setDeployMode(prev)
        setDetectedServices({ sniffer_online: prev === 'mirror', mta_online: prev === 'mta' })
      }
    } catch {
      setSwitchMsg({ type: 'error', text: '网络错误，请重试' })
    } finally {
      setDeploySaving(false)
      setTimeout(() => setSwitchMsg(null), 6000)
    }
  }, [])

  // Auto-save all MTA parameters (1.5s debounce)
  useEffect(() => {
    if (!deployInitLoaded.current) { deployInitLoaded.current = true; return }
    if (deploySkipNextAutoSave.current) { deploySkipNextAutoSave.current = false; return }
    if (deployAutoSaveTimer.current) clearTimeout(deployAutoSaveTimer.current)
    deployAutoSaveTimer.current = setTimeout(async () => {
      try {
        const res = await apiFetch('/api/config/deployment-mode', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mta_downstream_host: mtaDownstreamHost || undefined,
            mta_downstream_port: mtaDownstreamPort ? Number(mtaDownstreamPort) : undefined,
            mta_inline_timeout_secs: mtaTimeout ? Number(mtaTimeout) : undefined,
            mta_hostname: mtaHostname || undefined,
            mta_max_connections: mtaMaxConn ? Number(mtaMaxConn) : undefined,
            mta_starttls: mtaStarttls,
            mta_fail_open: mtaFailOpen,
            mta_local_domains: mtaLocalDomains || undefined,
            mta_dlp_enabled: mtaDlpEnabled,
            mta_dlp_action: mtaDlpAction || undefined,
          }),
        })
        const data = await res.json()
        if (data.success) { setDeploySaved(true); setTimeout(() => setDeploySaved(false), 3000) }
      } catch { /* silent */ }
    }, 1500)
    return () => { if (deployAutoSaveTimer.current) clearTimeout(deployAutoSaveTimer.current) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mtaDownstreamHost, mtaDownstreamPort, mtaTimeout, mtaHostname, mtaMaxConn, mtaStarttls, mtaFailOpen, mtaLocalDomains, mtaDlpEnabled, mtaDlpAction])

  // Suppress unused variable warning — state is used for display logic
  void deployModeSource

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>
            </svg>
          </span>
          部署模式
        </h2>
        <p className="s-section-subtitle">系统运行模式与网卡配置</p>
      </div>

      {/* Operating mode */}
      <div className="s-setting-group">
        <div className="s-setting-group-header">运行模式</div>
        {deployModeLocked && (
          <div style={{ margin: '0 12px 8px', padding: '8px 12px', borderRadius: 8, fontSize: 12, background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.2)', color: '#eab308' }}>
            模式已被环境变量 VIGILYX_MODE 锁定为 <strong>{deployMode}</strong>，如需切换请修改 .env 并重新部署
          </div>
        )}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, padding: '0 12px 12px' }}>
          {([
            { mode: 'mirror' as DeployMode, title: '网络镜像监听', desc: '旁路监听 \u00B7 零侵入', online: detectedServices.sniffer_online, color: '#3b82f6' },
            { mode: 'mta' as DeployMode, title: 'MTA 邮件网关', desc: '串联部署 \u00B7 实时拦截', online: detectedServices.mta_online, color: '#f97316' },
          ]).map(card => {
            const active = deployMode === card.mode
            return (
              <div
                key={card.mode}
                onClick={() => !deploySaving && !deployModeLocked && switchDeployMode(card.mode)}
                style={{
                  padding: '14px 16px', borderRadius: 12, cursor: active ? 'default' : 'pointer',
                  border: `1.5px solid ${active ? card.color + '60' : 'var(--border-muted)'}`,
                  background: active ? card.color + '08' : 'transparent',
                  transition: 'all 0.2s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{card.title}</span>
                  <span style={{
                    fontSize: 9, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
                    background: card.online ? 'rgba(34,197,94,0.12)' : 'rgba(255,255,255,0.04)',
                    color: card.online ? '#22c55e' : 'var(--text-tertiary)',
                  }}>{card.online ? '运行中' : '未运行'}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>{card.desc}</div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Status mismatch notice */}
      {!deploySaving && !switchMsg && ((deployMode === 'mta' && !detectedServices.mta_online) || (deployMode === 'mirror' && !detectedServices.sniffer_online)) && (
        <div style={{ padding: '10px 16px', borderRadius: 10, fontSize: 12, background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.2)', color: '#eab308', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>当前选择的模式与实际运行的服务不一致</span>
          <button onClick={() => switchDeployMode(deployMode)} disabled={deploySaving} style={{ fontSize: 12, padding: '4px 12px', borderRadius: 6, border: '1px solid rgba(234,179,8,0.3)', background: 'rgba(234,179,8,0.1)', color: '#eab308', cursor: 'pointer' }}>
            立即同步
          </button>
        </div>
      )}

      {/* Switch-result notice */}
      {deploySaving && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 16px', borderRadius: 10, background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.2)', fontSize: 13, color: '#67e8f9' }}>
          <span className="grok-spinner" /> 正在切换模式...
        </div>
      )}
      {switchMsg && (
        <div style={{ padding: '12px 16px', borderRadius: 10, fontSize: 13, background: switchMsg.type === 'success' ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)', border: '1px solid ' + (switchMsg.type === 'success' ? 'rgba(34,197,94,0.25)' : 'rgba(239,68,68,0.25)'), color: switchMsg.type === 'success' ? '#22c55e' : '#ef4444' }}>
          {switchMsg.type === 'success' ? '\u2713 ' : '\u2717 '}{switchMsg.text}
        </div>
      )}

      {/* Sniffer NIC configuration (shown only in mirror mode) */}
      {deployMode === 'mirror' && (
      <div className="s-setting-group">
        <div className="s-setting-group-header" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>Sniffer 网卡配置</span>
          {detectedServices.sniffer_online && <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, background: 'rgba(59,130,246,0.12)', color: '#3b82f6', fontWeight: 700 }}>运行中</span>}
        </div>
        {!detectedServices.sniffer_online && (
          <div style={{ padding: '0 16px 8px', fontSize: 11, color: 'var(--text-tertiary)' }}>Sniffer 未运行，以下配置将在启动后生效</div>
        )}

          <div style={{ padding: '0 16px 8px', fontSize: 11, color: 'var(--text-tertiary)', opacity: 0.8 }}>以下参数由容器环境变量控制（SNIFFER_INTERFACE, SMTP_PORTS 等），修改需重新部署容器</div>

          <div className="s-setting-row">
            <div className="s-setting-info">
              <span className="s-setting-label">监听网卡</span>
              <span className="s-setting-desc">由环境变量 SNIFFER_INTERFACE 控制，此处仅供参考</span>
            </div>
            <input
              className="s-input"
              style={{ width: 160, textAlign: 'center', fontFamily: 'var(--font-mono)', opacity: 0.6 }}
              value={snifferInterface}
              readOnly
              title="由容器环境变量 SNIFFER_INTERFACE 控制"
              placeholder="eth0"
            />
          </div>

          <div className="s-setting-row">
            <div className="s-setting-info">
              <span className="s-setting-label">捕获模式</span>
              <span className="s-setting-desc">使用 libpcap 混杂模式捕获所有经过该网卡的数据包</span>
            </div>
            <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)', padding: '6px 12px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border-muted)' }}>promiscuous</span>
          </div>

          <div className="s-setting-row">
            <div className="s-setting-info">
              <span className="s-setting-label">协议端口</span>
              <span className="s-setting-desc">由环境变量 SMTP_PORTS / POP3_PORTS / IMAP_PORTS 控制</span>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {[
                { proto: 'SMTP', ports: '25,465,587' },
                { proto: 'POP3', ports: '110,995' },
                { proto: 'IMAP', ports: '143,993' },
              ].map(p => (
                <span key={p.proto} style={{ fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 600, padding: '3px 8px', borderRadius: 5, background: 'rgba(59,130,246,0.08)', color: '#3b82f6', border: '1px solid rgba(59,130,246,0.12)' }}>
                  {p.proto} {p.ports}
                </span>
              ))}
            </div>
          </div>

      </div>
      )}

      {/* MTA gateway configuration (shown only in MTA mode) */}
      {deployMode === 'mta' && (<>
      <div className="s-setting-group">
        <div className="s-setting-group-header" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>MTA 网关配置</span>
          {detectedServices.mta_online && <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, background: 'rgba(249,115,22,0.12)', color: '#f97316', fontWeight: 700 }}>运行中</span>}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0', padding: '0' }}>
          <div className="s-setting-row">
            <div className="s-setting-info"><span className="s-setting-label">下游 MTA</span></div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <input className="s-input" style={{ width: 140, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 12 }}
                value={mtaDownstreamHost} onChange={e => { setMtaDownstreamHost(e.target.value); localStorage.setItem('vigilyx-mta-downstream-host', e.target.value) }}
                placeholder="10.1.246.33" />
              <span style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>:</span>
              <input className="s-input" style={{ width: 55, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 12 }}
                type="number" value={mtaDownstreamPort} onChange={e => { setMtaDownstreamPort(e.target.value); localStorage.setItem('vigilyx-mta-downstream-port', e.target.value) }} />
            </div>
          </div>
          <div className="s-setting-row">
            <div className="s-setting-info"><span className="s-setting-label">本地域名</span></div>
            <input className="s-input" style={{ width: 200, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 11 }}
              value={mtaLocalDomains} onChange={e => { setMtaLocalDomains(e.target.value); localStorage.setItem('vigilyx-mta-local-domains', e.target.value) }}
              placeholder="example.com" />
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0' }}>
          <div className="s-setting-row">
            <div className="s-setting-info"><span className="s-setting-label">检测超时</span></div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <input className="s-input" style={{ width: 55, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 12 }}
                type="number" value={mtaTimeout} onChange={e => { setMtaTimeout(e.target.value); localStorage.setItem('vigilyx-mta-timeout', e.target.value) }} />
              <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>秒</span>
            </div>
          </div>
          <div className="s-setting-row">
            <div className="s-setting-info"><span className="s-setting-label">故障策略</span></div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
              <input type="checkbox" checked={mtaFailOpen}
                onChange={e => { setMtaFailOpen(e.target.checked) }} />
              <span style={{ fontSize: 11, color: mtaFailOpen ? '#f97316' : 'var(--accent-emerald)' }}>
                {mtaFailOpen ? 'Fail-Open' : 'Fail-Closed'}
              </span>
            </label>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0' }}>
          <div className="s-setting-row">
            <div className="s-setting-info"><span className="s-setting-label">STARTTLS</span></div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
              <input type="checkbox" checked={mtaStarttls}
                onChange={e => { setMtaStarttls(e.target.checked); localStorage.setItem('vigilyx-mta-starttls', String(e.target.checked)) }} />
              <span style={{ fontSize: 11, color: mtaStarttls ? 'var(--accent-emerald)' : 'var(--text-tertiary)' }}>
                {mtaStarttls ? '已启用' : '已关闭'}
              </span>
            </label>
          </div>
          <div className="s-setting-row">
            <div className="s-setting-info"><span className="s-setting-label">出站 DLP</span></div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
              <input type="checkbox" checked={mtaDlpEnabled}
                onChange={e => { setMtaDlpEnabled(e.target.checked); localStorage.setItem('vigilyx-mta-dlp-enabled', String(e.target.checked)) }} />
              <span style={{ fontSize: 11, color: mtaDlpEnabled ? 'var(--accent-emerald)' : 'var(--text-tertiary)' }}>
                {mtaDlpEnabled ? '已启用' : '已关闭'}
              </span>
            </label>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0' }}>
          <div className="s-setting-row">
            <div className="s-setting-info"><span className="s-setting-label">最大连接</span></div>
            <input className="s-input" style={{ width: 70, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 12 }}
              type="number" value={mtaMaxConn} onChange={e => { setMtaMaxConn(e.target.value); localStorage.setItem('vigilyx-mta-max-conn', e.target.value) }} />
          </div>
          <div className="s-setting-row">
            <div className="s-setting-info"><span className="s-setting-label">主机名</span></div>
            <input className="s-input" style={{ width: 140, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 12 }}
              value={mtaHostname} onChange={e => { setMtaHostname(e.target.value); localStorage.setItem('vigilyx-mta-hostname', e.target.value) }}
              placeholder="vigilyx-mta" />
          </div>
        </div>
      </div>
      </>)}

      {/* Auto-save status notice */}
      {deploySaved && (
        <div className="s-deploy-success" style={{ marginTop: 12 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          配置已保存，需重启 MTA 容器生效
        </div>
      )}
    </div>
  )
}
