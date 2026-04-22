import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'
import type { SyslogConfig } from './types'

export function TimePolicyTab() {
  const { t } = useTranslation()
  const [tp, setTp] = useState({ enabled: true, work_hour_start: 8, work_hour_end: 18, utc_offset_hours: 8, weekend_is_off_hours: true })
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // Syslog
  const [sl, setSl] = useState<SyslogConfig>({ enabled: false, server_address: '', port: 514, protocol: 'udp', facility: 4, format: 'rfc5424', min_severity: 'medium' })
  const [slSaving, setSlSaving] = useState(false)
  const [slMsg, setSlMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [slTesting, setSlTesting] = useState(false)

  useEffect(() => {
    apiFetch('/api/config/time-policy').then(r => r.json()).then(d => {
      if (d.success && d.data) setTp(d.data)
    }).catch(() => {})
    apiFetch('/api/config/syslog').then(r => r.json()).then(d => {
      if (d.success && d.data) setSl(d.data)
    }).catch(() => {})
  }, [])

  const save = useCallback(async () => {
    if (tp.work_hour_start >= tp.work_hour_end) { setMsg({ ok: false, text: t('dataSecurity.startBeforeEnd') }); return }
    setSaving(true); setMsg(null)
    try {
      const r = await apiFetch('/api/config/time-policy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(tp) })
      const d = await r.json()
      if (d.success) { setMsg({ ok: true, text: t('dataSecurity.timePolicySaved') }); setTimeout(() => setMsg(null), 5000) }
      else setMsg({ ok: false, text: d.error || t('dataSecurity.saveFailed') })
    } catch { setMsg({ ok: false, text: t('dataSecurity.networkError') }) }
    finally { setSaving(false) }
  }, [tp])

  return (
    <div className="tp-center">
      {/* -- Time policies -- */}
      <div className="tp-card">
        <div className="tp-header">
          <div className="tp-icon-wrap">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#a855f7" strokeWidth="2"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
          </div>
          <div>
            <h3 className="tp-title">{t('dataSecurity.offHoursWeighting')}</h3>
            <p className="tp-subtitle">{t('dataSecurity.offHoursWeightingDesc')}</p>
          </div>
        </div>

        <div className="tp-body">
          <div className="tp-field">
            <div className="tp-field-row">
              <span className="tp-field-label">{t('dataSecurity.enableSeverityBoost')}</span>
              <label className="tp-switch">
                <input type="checkbox" checked={tp.enabled} onChange={e => setTp({ ...tp, enabled: e.target.checked })} />
                <span className="tp-switch-track" />
              </label>
            </div>
            <p className="tp-field-hint">{t('dataSecurity.severityBoostHint')}</p>
          </div>

          <div className="tp-divider" />

          <div className="tp-field">
            <span className="tp-field-label">{t('dataSecurity.workHours')}</span>
            <div className="tp-time-row">
              <select value={tp.work_hour_start} onChange={e => setTp({ ...tp, work_hour_start: Number(e.target.value) })} className="tp-select" disabled={!tp.enabled}>
                {Array.from({ length: 24 }, (_, i) => <option key={i} value={i}>{String(i).padStart(2, '0')}:00</option>)}
              </select>
              <span className="tp-time-sep">—</span>
              <select value={tp.work_hour_end} onChange={e => setTp({ ...tp, work_hour_end: Number(e.target.value) })} className="tp-select" disabled={!tp.enabled}>
                {Array.from({ length: 24 }, (_, i) => i + 1).map(h => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}
              </select>
            </div>
          </div>

          <div className="tp-field">
            <span className="tp-field-label">{t('dataSecurity.timezone')}</span>
            <select value={tp.utc_offset_hours} onChange={e => setTp({ ...tp, utc_offset_hours: Number(e.target.value) })} className="tp-select tp-select--wide" disabled={!tp.enabled}>
              {[[-12,'UTC-12'],[-11,'UTC-11'],[-10,'UTC-10'],[-9,'UTC-9'],[-8,'UTC-8'],[-7,'UTC-7'],[-6,'UTC-6'],[-5,'UTC-5'],[-4,'UTC-4'],[-3,'UTC-3'],[-2,'UTC-2'],[-1,'UTC-1'],[0,'UTC'],[1,'UTC+1'],[2,'UTC+2'],[3,'UTC+3'],[4,'UTC+4'],[5,'UTC+5'],[5.5,'UTC+5:30'],[6,'UTC+6'],[7,'UTC+7'],[8,t('dataSecurity.utc8China')],[9,'UTC+9'],[10,'UTC+10'],[11,'UTC+11'],[12,'UTC+12'],[13,'UTC+13'],[14,'UTC+14']].map(([v, l]) => (
                <option key={v} value={v}>{l as string}</option>
              ))}
            </select>
          </div>

          <div className="tp-field">
            <div className="tp-field-row">
              <span className="tp-field-label">{t('dataSecurity.weekendAsOffHours')}</span>
              <label className="tp-switch">
                <input type="checkbox" checked={tp.weekend_is_off_hours} onChange={e => setTp({ ...tp, weekend_is_off_hours: e.target.checked })} disabled={!tp.enabled} />
                <span className="tp-switch-track" />
              </label>
            </div>
          </div>
        </div>

        {msg && <div className={`tp-msg ${msg.ok ? 'tp-msg--ok' : 'tp-msg--err'}`}>{msg.text}</div>}
        <div className="tp-footer">
          <button className="tp-save" onClick={save} disabled={saving}>
            {saving ? t('dataSecurity.saving') : t('dataSecurity.save')}
          </button>
        </div>
      </div>

      {/* -- Syslog -- */}
      <div className="tp-card tp-card--blue">
        <div className="tp-header">
          <div className="tp-icon-wrap tp-icon-wrap--blue">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
          </div>
          <div>
            <h3 className="tp-title">{t('dataSecurity.syslogForwarding')}</h3>
            <p className="tp-subtitle">{t('dataSecurity.syslogForwardingDesc')}</p>
          </div>
        </div>

        <div className="tp-body">
          <div className="tp-field">
            <div className="tp-field-row">
              <span className="tp-field-label">{t('dataSecurity.enableForwarding')}</span>
              <label className="tp-switch tp-switch--blue">
                <input type="checkbox" checked={sl.enabled} onChange={e => setSl({ ...sl, enabled: e.target.checked })} />
                <span className="tp-switch-track" />
              </label>
            </div>
          </div>

          <div className="tp-divider" />

          <div className="tp-grid tp-grid--2">
            <div className="tp-field">
              <span className="tp-field-label">{t('dataSecurity.serverAddress')}</span>
              <input className="tp-input" value={sl.server_address} onChange={e => setSl({ ...sl, server_address: e.target.value })} placeholder={t('dataSecurity.ipOrHostname')} disabled={!sl.enabled} />
            </div>
            <div className="tp-field">
              <span className="tp-field-label">{t('dataSecurity.port')}</span>
              <input className="tp-input tp-input--center" type="number" min={1} max={65535} value={sl.port} onChange={e => setSl({ ...sl, port: Number(e.target.value) })} disabled={!sl.enabled} />
            </div>
          </div>

          <div className="tp-grid tp-grid--3">
            <div className="tp-field">
              <span className="tp-field-label">{t('dataSecurity.protocol')}</span>
              <select className="tp-select tp-select--wide" value={sl.protocol} onChange={e => setSl({ ...sl, protocol: e.target.value })} disabled={!sl.enabled}>
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
              </select>
            </div>
            <div className="tp-field">
              <span className="tp-field-label">{t('dataSecurity.messageFormat')}</span>
              <select className="tp-select tp-select--wide" value={sl.format} onChange={e => setSl({ ...sl, format: e.target.value })} disabled={!sl.enabled}>
                <option value="rfc5424">RFC 5424</option>
                <option value="rfc3164">RFC 3164</option>
              </select>
            </div>
            <div className="tp-field">
              <span className="tp-field-label">{t('dataSecurity.minSeverity')}</span>
              <select className="tp-select tp-select--wide" value={sl.min_severity} onChange={e => setSl({ ...sl, min_severity: e.target.value })} disabled={!sl.enabled}>
                <option value="info">Info</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          <div className="tp-field">
            <span className="tp-field-label">Facility</span>
            <select className="tp-select" value={sl.facility} onChange={e => setSl({ ...sl, facility: Number(e.target.value) })} disabled={!sl.enabled} style={{ width: 200 }}>
              {[[0,'kern'],[1,'user'],[4,'auth'],[10,'authpriv'],[13,'audit'],[16,'local0'],[17,'local1'],[18,'local2'],[19,'local3'],[20,'local4'],[21,'local5'],[22,'local6'],[23,'local7']].map(([v, l]) => (
                <option key={v} value={v}>{v} — {l as string}</option>
              ))}
            </select>
          </div>
        </div>

        {slMsg && <div className={`tp-msg ${slMsg.ok ? 'tp-msg--ok' : 'tp-msg--err'}`}>{slMsg.text}</div>}
        <div className="tp-footer">
          <button className="tp-btn-outline" onClick={async () => {
            setSlTesting(true); setSlMsg(null)
            try {
              const r = await apiFetch('/api/config/syslog/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sl) })
              const d = await r.json()
              setSlMsg({ ok: d.success, text: d.success ? d.data : (d.error || t('dataSecurity.testFailed')) })
            } catch { setSlMsg({ ok: false, text: t('dataSecurity.networkError') }) }
            finally { setSlTesting(false) }
            setTimeout(() => setSlMsg(null), 8000)
          }} disabled={!sl.enabled || !sl.server_address || slTesting}>
            {slTesting ? t('dataSecurity.testing') : t('dataSecurity.testConnection')}
          </button>
          <button className="tp-save tp-save--blue" onClick={async () => {
            if (sl.enabled && !sl.server_address) { setSlMsg({ ok: false, text: t('dataSecurity.enterServerAddress') }); return }
            setSlSaving(true); setSlMsg(null)
            try {
              const r = await apiFetch('/api/config/syslog', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sl) })
              const d = await r.json()
              if (d.success) { setSlMsg({ ok: true, text: t('dataSecurity.syslogSaved') }); setTimeout(() => setSlMsg(null), 5000) }
              else setSlMsg({ ok: false, text: d.error || t('dataSecurity.saveFailed') })
            } catch { setSlMsg({ ok: false, text: t('dataSecurity.networkError') }) }
            finally { setSlSaving(false) }
          }} disabled={slSaving}>
            {slSaving ? t('dataSecurity.saving') : t('dataSecurity.save')}
          </button>
        </div>
      </div>
    </div>
  )
}
