import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'
import type { SyslogConfig } from './types'

export function SyslogCard({ sl, setSl, slSaving, setSlSaving, slMsg, setSlMsg, slTesting, setSlTesting }: {
  sl: SyslogConfig
  setSl: (v: SyslogConfig) => void
  slSaving: boolean; setSlSaving: (v: boolean) => void
  slMsg: { ok: boolean; text: string } | null; setSlMsg: (v: { ok: boolean; text: string } | null) => void
  slTesting: boolean; setSlTesting: (v: boolean) => void
}) {
  const { t } = useTranslation()
  const saveSl = useCallback(async () => {
    if (sl.enabled && !sl.server_address) { setSlMsg({ ok: false, text: t('dataSecurity.enterServerAddress') }); return }
    setSlSaving(true); setSlMsg(null)
    try {
      const r = await apiFetch('/api/config/syslog', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sl) })
      const d = await r.json()
      if (d.success) { setSlMsg({ ok: true, text: t('dataSecurity.syslogSavedRestart') }); setTimeout(() => setSlMsg(null), 8000) }
      else setSlMsg({ ok: false, text: d.error || t('dataSecurity.saveFailed') })
    } catch { setSlMsg({ ok: false, text: t('dataSecurity.networkError') }) }
    finally { setSlSaving(false) }
  }, [sl, setSlSaving, setSlMsg])

  const testSl = useCallback(async () => {
    setSlTesting(true); setSlMsg(null)
    try {
      const r = await apiFetch('/api/config/syslog/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sl) })
      const d = await r.json()
      setSlMsg({ ok: d.success, text: d.success ? d.data : (d.error || t('dataSecurity.testFailed')) })
    } catch { setSlMsg({ ok: false, text: t('dataSecurity.networkError') }) }
    finally { setSlTesting(false) }
    setTimeout(() => setSlMsg(null), 8000)
  }, [sl, setSlTesting, setSlMsg])

  return (
    <div className="ds3-settings-card">
      <div className="ds3-settings-card-head">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
        <span>{t('dataSecurity.syslogForwarding')}</span>
      </div>
      <p className="ds3-settings-card-desc">{t('dataSecurity.syslogForwardingDescRestart')}</p>

      <div className="ds3-settings-row" style={{ marginBottom: 16 }}>
        <span className="ds3-settings-label">{t('dataSecurity.enableForwarding')}</span>
        <label className="tp-switch">
          <input type="checkbox" checked={sl.enabled} onChange={e => setSl({ ...sl, enabled: e.target.checked })} />
          <span className="tp-switch-track" />
        </label>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px', gap: 12, marginBottom: 12 }}>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">{t('dataSecurity.serverAddress')}</div>
          <input className="ds3-settings-input ds3-mono" value={sl.server_address} onChange={e => setSl({ ...sl, server_address: e.target.value })} placeholder={t('dataSecurity.ipOrHostname')} disabled={!sl.enabled} />
        </div>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">{t('dataSecurity.port')}</div>
          <input className="ds3-settings-input ds3-mono" type="number" min={1} max={65535} value={sl.port} onChange={e => setSl({ ...sl, port: Number(e.target.value) })} disabled={!sl.enabled} style={{ textAlign: 'center' }} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">{t('dataSecurity.protocol')}</div>
          <select className="ds3-settings-select" value={sl.protocol} onChange={e => setSl({ ...sl, protocol: e.target.value })} disabled={!sl.enabled} style={{ width: '100%' }}>
            <option value="udp">UDP</option>
            <option value="tcp">TCP</option>
          </select>
        </div>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">{t('dataSecurity.messageFormat')}</div>
          <select className="ds3-settings-select" value={sl.format} onChange={e => setSl({ ...sl, format: e.target.value })} disabled={!sl.enabled} style={{ width: '100%' }}>
            <option value="rfc5424">RFC 5424</option>
            <option value="rfc3164">RFC 3164</option>
          </select>
        </div>
        <div className="ds3-settings-field" style={{ margin: 0 }}>
          <div className="ds3-settings-field-label">{t('dataSecurity.minSeverity')}</div>
          <select className="ds3-settings-select" value={sl.min_severity} onChange={e => setSl({ ...sl, min_severity: e.target.value })} disabled={!sl.enabled} style={{ width: '100%' }}>
            <option value="info">Info</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>

      <div className="ds3-settings-field" style={{ margin: '0 0 16px 0' }}>
        <div className="ds3-settings-field-label">Facility</div>
        <select className="ds3-settings-select" value={sl.facility} onChange={e => setSl({ ...sl, facility: Number(e.target.value) })} disabled={!sl.enabled} style={{ width: 200 }}>
          {[[0,'kern'],[1,'user'],[4,'auth'],[10,'authpriv'],[13,'audit'],[16,'local0'],[17,'local1'],[18,'local2'],[19,'local3'],[20,'local4'],[21,'local5'],[22,'local6'],[23,'local7']].map(([v, l]) => (
            <option key={v} value={v}>{v} — {l as string}</option>
          ))}
        </select>
      </div>

      {slMsg && <div className={`ds3-settings-msg ${slMsg.ok ? 'ds3-settings-msg--ok' : 'ds3-settings-msg--err'}`}>{slMsg.text}</div>}
      <div className="ds3-settings-save-row">
        <button className="ds3-settings-add ds3-settings-add--blue" onClick={testSl} disabled={!sl.enabled || !sl.server_address || slTesting}>
          {slTesting ? t('dataSecurity.testing') : t('dataSecurity.testConnection')}
        </button>
        <button className="ds3-settings-save-btn" onClick={saveSl} disabled={slSaving}>
          {slSaving ? t('dataSecurity.saving') : t('dataSecurity.saveSyslogConfig')}
        </button>
      </div>
    </div>
  )
}
