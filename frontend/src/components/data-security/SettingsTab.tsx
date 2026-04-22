import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'
import type { SyslogConfig } from './types'
import { expandIpInput } from './helpers'
import { SyslogCard } from './SyslogCard'

export function SettingsTab() {
  const { t } = useTranslation()
  // -- Sniffer configuration (webmail_servers / http_ports) --
  const [servers, setServers] = useState<string[]>([])
  const [ports, setPorts] = useState<number[]>([80, 443, 8080])
  const [newServer, setNewServer] = useState('')
  const [newPort, setNewPort] = useState('')
  const [snifferSaving, setSnifferSaving] = useState(false)
  const [snifferMsg, setSnifferMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // -- Time policy configuration --
  const [tp, setTp] = useState({ enabled: true, work_hour_start: 8, work_hour_end: 18, utc_offset_hours: 8, weekend_is_off_hours: true })
  const [tpSaving, setTpSaving] = useState(false)
  const [tpMsg, setTpMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // -- Syslog forwarding configuration --
  const [sl, setSl] = useState<SyslogConfig>({ enabled: false, server_address: '', port: 514, protocol: 'udp', facility: 4, format: 'rfc5424', min_severity: 'medium' })
  const [slSaving, setSlSaving] = useState(false)
  const [slMsg, setSlMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [slTesting, setSlTesting] = useState(false)

  // Load configuration
  useEffect(() => {
    apiFetch('/api/config/sniffer').then(r => r.json()).then(d => {
      if (d.success && d.data) {
        setServers(d.data.webmail_servers || [])
        setPorts(d.data.http_ports || [80, 443, 8080])
      }
    }).catch(() => {})
    apiFetch('/api/config/time-policy').then(r => r.json()).then(d => {
      if (d.success && d.data) setTp(d.data)
    }).catch(() => {})
    apiFetch('/api/config/syslog').then(r => r.json()).then(d => {
      if (d.success && d.data) setSl(d.data)
    }).catch(() => {})
  }, [])

  const addServer = useCallback(() => {
    const ips = expandIpInput(newServer)
    const valid = ips.filter(ip => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip))
    if (valid.length > 0) { setServers(prev => [...new Set([...prev, ...valid])]); setNewServer('') }
  }, [newServer])

  const addPort = useCallback(() => {
    const p = parseInt(newPort)
    if (p > 0 && p <= 65535 && !ports.includes(p)) { setPorts(prev => [...prev, p].sort((a, b) => a - b)); setNewPort('') }
  }, [newPort, ports])

  const saveSniffer = useCallback(async () => {
    setSnifferSaving(true); setSnifferMsg(null)
    try {
      const r = await apiFetch('/api/config/sniffer', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ webmail_servers: servers, http_ports: ports }) })
      const d = await r.json()
      if (d.success) { setSnifferMsg({ ok: true, text: t('dataSecurity.snifferSavedRestarting') }); setTimeout(() => setSnifferMsg(null), 8000) }
      else setSnifferMsg({ ok: false, text: d.error || t('dataSecurity.saveFailed') })
    } catch { setSnifferMsg({ ok: false, text: t('dataSecurity.networkError') }) }
    finally { setSnifferSaving(false) }
  }, [servers, ports])

  const saveTp = useCallback(async () => {
    if (tp.work_hour_start >= tp.work_hour_end) { setTpMsg({ ok: false, text: t('dataSecurity.startBeforeEnd') }); return }
    setTpSaving(true); setTpMsg(null)
    try {
      const r = await apiFetch('/api/config/time-policy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(tp) })
      const d = await r.json()
      if (d.success) { setTpMsg({ ok: true, text: t('dataSecurity.timePolicySaved') }); setTimeout(() => setTpMsg(null), 5000) }
      else setTpMsg({ ok: false, text: d.error || t('dataSecurity.saveFailed') })
    } catch { setTpMsg({ ok: false, text: t('dataSecurity.networkError') }) }
    finally { setTpSaving(false) }
  }, [tp])

  return (
    <div className="ds3-settings-page">
      {/* -- Section 1: HTTP traffic capture -- */}
      <div className="ds3-settings-card">
        <div className="ds3-settings-card-head">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span>{t('dataSecurity.httpTrafficCapture')}</span>
        </div>
        <p className="ds3-settings-card-desc">{t('dataSecurity.httpTrafficCaptureDesc')}</p>

        {/* Webmail servers */}
        <div className="ds3-settings-field">
          <div className="ds3-settings-field-label">{t('dataSecurity.webmailServerIp')}</div>
          {servers.length > 0 && (
            <div className="ds3-chip-row">
              {servers.map((ip, i) => (
                <span key={i} className="ds3-chip ds3-chip--cyan">
                  {ip}
                  <button className="ds3-chip-x" onClick={() => setServers(prev => prev.filter((_, idx) => idx !== i))}>&times;</button>
                </span>
              ))}
            </div>
          )}
          <div className="ds3-input-row">
            <input className="ds3-settings-input ds3-mono" value={newServer} onChange={e => setNewServer(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') addServer() }}
              placeholder={t('dataSecurity.enterIpPlaceholder')} />
            <button className="ds3-settings-add ds3-settings-add--cyan" onClick={addServer}>{t('dataSecurity.add')}</button>
          </div>
        </div>

        {/* HTTP ports */}
        <div className="ds3-settings-field">
          <div className="ds3-settings-field-label">{t('dataSecurity.httpListenPorts')}</div>
          <div className="ds3-chip-row">
            {ports.map((port, i) => (
              <span key={i} className="ds3-chip ds3-chip--blue">
                {port}
                <button className="ds3-chip-x" onClick={() => setPorts(prev => prev.filter((_, idx) => idx !== i))}>&times;</button>
              </span>
            ))}
          </div>
          <div className="ds3-input-row">
            <input className="ds3-settings-input ds3-mono" type="number" min={1} max={65535} style={{ width: 120, textAlign: 'center' }}
              value={newPort} onChange={e => setNewPort(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') addPort() }}
              placeholder={t('dataSecurity.portNumber')} />
            <button className="ds3-settings-add ds3-settings-add--blue" onClick={addPort}>{t('dataSecurity.add')}</button>
          </div>
        </div>

        {snifferMsg && <div className={`ds3-settings-msg ${snifferMsg.ok ? 'ds3-settings-msg--ok' : 'ds3-settings-msg--err'}`}>{snifferMsg.text}</div>}
        <div className="ds3-settings-save-row">
          <span className="ds3-settings-warn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            {t('dataSecurity.saveWillRestartSniffer')}
          </span>
          <button className="ds3-settings-save-btn" onClick={saveSniffer} disabled={snifferSaving}>
            {snifferSaving ? t('dataSecurity.saving') : t('dataSecurity.saveAndRestartSniffer')}
          </button>
        </div>
      </div>

      {/* -- Section 2: after-hours weighting -- */}
      <div className="ds3-settings-card">
        <div className="ds3-settings-card-head">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#a855f7" strokeWidth="2"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
          <span>{t('dataSecurity.offHoursWeighting')}</span>
        </div>
        <p className="ds3-settings-card-desc">{t('dataSecurity.offHoursWeightingDescData')}</p>

        <label className="ds3-settings-toggle-row">
          <span>{t('dataSecurity.enableSeverityBoost')}</span>
          <input type="checkbox" checked={tp.enabled} onChange={e => setTp({ ...tp, enabled: e.target.checked })} className="ds3-settings-checkbox" />
        </label>

        <div className="ds3-settings-row">
          <span className="ds3-settings-label">{t('dataSecurity.workTime')}</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <select value={tp.work_hour_start} onChange={e => setTp({ ...tp, work_hour_start: Number(e.target.value) })} className="ds3-settings-select" disabled={!tp.enabled}>
              {Array.from({ length: 24 }, (_, i) => <option key={i} value={i}>{String(i).padStart(2, '0')}:00</option>)}
            </select>
            <span style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>{t('dataSecurity.to')}</span>
            <select value={tp.work_hour_end} onChange={e => setTp({ ...tp, work_hour_end: Number(e.target.value) })} className="ds3-settings-select" disabled={!tp.enabled}>
              {Array.from({ length: 24 }, (_, i) => i + 1).map(h => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}
            </select>
          </div>
        </div>

        <div className="ds3-settings-row">
          <span className="ds3-settings-label">{t('dataSecurity.timezone')}</span>
          <select value={tp.utc_offset_hours} onChange={e => setTp({ ...tp, utc_offset_hours: Number(e.target.value) })} className="ds3-settings-select" disabled={!tp.enabled}>
            {[[-12,'UTC-12'],[-11,'UTC-11'],[-10,'UTC-10'],[-9,'UTC-9'],[-8,'UTC-8'],[-7,'UTC-7'],[-6,'UTC-6'],[-5,'UTC-5'],[-4,'UTC-4'],[-3,'UTC-3'],[-2,'UTC-2'],[-1,'UTC-1'],[0,'UTC'],[1,'UTC+1'],[2,'UTC+2'],[3,'UTC+3'],[4,'UTC+4'],[5,'UTC+5'],[5.5,'UTC+5:30'],[6,'UTC+6'],[7,'UTC+7'],[8,t('dataSecurity.utc8China')],[9,'UTC+9'],[10,'UTC+10'],[11,'UTC+11'],[12,'UTC+12'],[13,'UTC+13'],[14,'UTC+14']].map(([v, l]) => (
              <option key={v} value={v}>{l as string}</option>
            ))}
          </select>
        </div>

        <label className="ds3-settings-toggle-row">
          <span>{t('dataSecurity.weekendAsOffHours')}</span>
          <input type="checkbox" checked={tp.weekend_is_off_hours} onChange={e => setTp({ ...tp, weekend_is_off_hours: e.target.checked })} className="ds3-settings-checkbox" disabled={!tp.enabled} />
        </label>

        {tpMsg && <div className={`ds3-settings-msg ${tpMsg.ok ? 'ds3-settings-msg--ok' : 'ds3-settings-msg--err'}`}>{tpMsg.text}</div>}
        <div className="ds3-settings-save-row">
          <button className="ds3-settings-save-btn" onClick={saveTp} disabled={tpSaving}>
            {tpSaving ? t('dataSecurity.saving') : t('dataSecurity.saveTimePolicy')}
          </button>
        </div>
      </div>

      {/* -- Section 3: syslog forwarding -- */}
      <SyslogCard sl={sl} setSl={setSl} slSaving={slSaving} setSlSaving={setSlSaving} slMsg={slMsg} setSlMsg={setSlMsg} slTesting={slTesting} setSlTesting={setSlTesting} />
    </div>
  )
}
