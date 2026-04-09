import { useState, useEffect } from 'react'
import { apiFetch } from '../../utils/api'

export default function SyslogSettings() {
  const [syslog, setSyslog] = useState({ enabled: false, server_address: '', port: 514, protocol: 'udp', facility: 4, format: 'rfc5424', min_severity: 'medium' })
  const [syslogSaving, setSyslogSaving] = useState(false)
  const [syslogMsg, setSyslogMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [syslogTesting, setSyslogTesting] = useState(false)

  // Load syslog configuration on mount
  useEffect(() => {
    apiFetch('/api/config/syslog').then(r => r.json()).then(d => {
      if (d.success && d.data) setSyslog(d.data)
    }).catch(() => {})
  }, [])

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon" style={{ background: 'rgba(59,130,246,0.08)', color: '#3b82f6' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>
            </svg>
          </span>
          Syslog 事件转发
        </h2>
        <p className="s-section-subtitle">将安全事件通过 Syslog 协议（TCP/UDP）转发到外部 SIEM / 日志平台。当前已支持数据安全事件，邮件安全事件后续扩展。</p>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">基本配置</div>

        <div className="s-setting-row" style={{ borderBottom: 'none', paddingBottom: 8 }}>
          <div className="s-setting-info">
            <span className="s-setting-label">启用 Syslog 转发</span>
            <span className="s-setting-desc">开启后安全事件将实时转发到指定 Syslog 服务器</span>
          </div>
          <label className="s-toggle">
            <input type="checkbox" checked={syslog.enabled} onChange={e => setSyslog({ ...syslog, enabled: e.target.checked })} />
            <span className="s-toggle-slider" />
          </label>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px', gap: 12, marginBottom: 16 }}>
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 4 }}>服务器地址</div>
            <input className="s-input" value={syslog.server_address} onChange={e => setSyslog({ ...syslog, server_address: e.target.value })} placeholder="IP 或主机名" disabled={!syslog.enabled} style={{ fontFamily: 'var(--font-mono)', width: '100%' }} />
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 4 }}>端口</div>
            <input className="s-input" type="number" min={1} max={65535} value={syslog.port} onChange={e => setSyslog({ ...syslog, port: Number(e.target.value) })} disabled={!syslog.enabled} style={{ fontFamily: 'var(--font-mono)', width: '100%', textAlign: 'center' }} />
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 4 }}>传输协议</div>
            <select className="s-input" value={syslog.protocol} onChange={e => setSyslog({ ...syslog, protocol: e.target.value })} disabled={!syslog.enabled} style={{ width: '100%' }}>
              <option value="udp">UDP（无连接，轻量）</option>
              <option value="tcp">TCP（可靠传输）</option>
            </select>
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 4 }}>消息格式</div>
            <select className="s-input" value={syslog.format} onChange={e => setSyslog({ ...syslog, format: e.target.value })} disabled={!syslog.enabled} style={{ width: '100%' }}>
              <option value="rfc5424">RFC 5424（推荐）</option>
              <option value="rfc3164">RFC 3164（兼容旧设备）</option>
            </select>
          </div>
        </div>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">过滤与分类</div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 4 }}>最低转发严重度</div>
            <select className="s-input" value={syslog.min_severity} onChange={e => setSyslog({ ...syslog, min_severity: e.target.value })} disabled={!syslog.enabled} style={{ width: '100%' }}>
              <option value="info">Info — 全部转发</option>
              <option value="low">Low 及以上</option>
              <option value="medium">Medium 及以上</option>
              <option value="high">High 及以上</option>
              <option value="critical">仅 Critical</option>
            </select>
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 4 }}>Syslog Facility</div>
            <select className="s-input" value={syslog.facility} onChange={e => setSyslog({ ...syslog, facility: Number(e.target.value) })} disabled={!syslog.enabled} style={{ width: '100%' }}>
              {[[0,'kern'],[1,'user'],[4,'auth'],[10,'authpriv'],[13,'audit'],[16,'local0'],[17,'local1'],[18,'local2'],[19,'local3'],[20,'local4'],[21,'local5'],[22,'local6'],[23,'local7']].map(([v, l]) => (
                <option key={v} value={v}>{v} — {l as string}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <div className="s-deploy-action">
        {syslogMsg && <div className={syslogMsg.ok ? 's-deploy-success' : ''} style={syslogMsg.ok ? {} : { color: '#ef4444', fontSize: 12, marginBottom: 8 }}>
          {syslogMsg.ok && <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>}
          {syslogMsg.text}
        </div>}
        <div className="s-deploy-action-row">
          <div className="s-deploy-action-hint">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2" style={{ flexShrink: 0 }}><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <span>保存后需重启服务才能生效</span>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="s-btn-sm" style={{ padding: '7px 16px', fontSize: 12, borderRadius: 6, background: 'rgba(59,130,246,0.08)', color: '#3b82f6', border: '1px solid rgba(59,130,246,0.15)', cursor: 'pointer' }}
              disabled={!syslog.enabled || !syslog.server_address || syslogTesting}
              onClick={async () => {
                setSyslogTesting(true); setSyslogMsg(null)
                try {
                  const r = await apiFetch('/api/config/syslog/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(syslog) })
                  const d = await r.json()
                  setSyslogMsg({ ok: d.success, text: d.success ? d.data : (d.error || '测试失败') })
                } catch { setSyslogMsg({ ok: false, text: '网络错误' }) }
                finally { setSyslogTesting(false) }
                setTimeout(() => setSyslogMsg(null), 8000)
              }}>{syslogTesting ? '测试中...' : '测试连接'}</button>
            <button className="s-deploy-apply-btn"
              disabled={syslogSaving}
              onClick={async () => {
                setSyslogSaving(true); setSyslogMsg(null)
                try {
                  const r = await apiFetch('/api/config/syslog', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(syslog) })
                  const d = await r.json()
                  if (d.success) { setSyslogMsg({ ok: true, text: 'Syslog 配置已保存，重启服务后生效' }) }
                  else setSyslogMsg({ ok: false, text: d.error || '保存失败' })
                } catch { setSyslogMsg({ ok: false, text: '网络错误' }) }
                finally { setSyslogSaving(false) }
                setTimeout(() => setSyslogMsg(null), 8000)
              }}>
              {syslogSaving ? (
                <><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="s-deploy-spin"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> 保存中...</>
              ) : (
                <><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> 保存 Syslog 配置</>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
