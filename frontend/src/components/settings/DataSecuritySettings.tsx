import { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'

/**
 * Expand compact IP notation: "192.168.1.10/11" -> ["192.168.1.10", "192.168.1.11"]
 * Also supports multiple suffixes: "192.168.1.10/11/12"
 */
function expandIpInput(raw: string): string[] {
  const trimmed = raw.trim()
  if (!trimmed) return []
  const match = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3}(?:\/\d{1,3})+)$/.exec(trimmed)
  if (match) {
    const prefix = match[1]
    const parts = match[2].split('/')
    return parts.map(p => prefix + p)
  }
  return [trimmed]
}

export default function DataSecuritySettings() {
  const { t } = useTranslation()
  const [dsWebmailServers, setDsWebmailServers] = useState<string[]>([])
  const [dsHttpPorts, setDsHttpPorts] = useState<number[]>([80, 443, 8080])
  const [dsNewServer, setDsNewServer] = useState('')
  const [dsNewPort, setDsNewPort] = useState('')
  const [dsSaving, setDsSaving] = useState(false)
  const [dsSaved, setDsSaved] = useState(false)
  const [dsError, setDsError] = useState<string | null>(null)
  const [dsLoaded, setDsLoaded] = useState(false)

  // Load sniffer settings on mount
  useEffect(() => {
    if (!dsLoaded) {
      (async () => {
        try {
          const res = await apiFetch('/api/config/sniffer')
          const data = await res.json()
          if (data.success && data.data) {
            setDsWebmailServers(data.data.webmail_servers || [])
            setDsHttpPorts(data.data.http_ports || [80, 443, 8080])
          }
          setDsLoaded(true)
        } catch (e) {
          console.error('Failed to fetch sniffer config:', e)
        }
      })()
    }
  }, [dsLoaded])

  // Auto-save data security settings (1.5s debounce)
  const dsAutoSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => {
    if (!dsLoaded) return // Skip the initial load
    if (dsAutoSaveTimer.current) clearTimeout(dsAutoSaveTimer.current)
    dsAutoSaveTimer.current = setTimeout(async () => {
      setDsSaving(true)
      setDsError(null)
      try {
        const res = await apiFetch('/api/config/sniffer', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ webmail_servers: dsWebmailServers, http_ports: dsHttpPorts }),
        })
        const data = await res.json()
        if (data.success) {
          setDsSaved(true)
          setTimeout(() => setDsSaved(false), 3000)
        } else {
          setDsError(data.error || t('settings.dataSecurity.saveFailed'))
        }
      } catch (e: unknown) {
        setDsError(e instanceof Error ? e.message : t('settings.dataSecurity.requestFailed'))
      } finally { setDsSaving(false) }
    }, 1500)
    return () => { if (dsAutoSaveTimer.current) clearTimeout(dsAutoSaveTimer.current) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dsWebmailServers, dsHttpPorts])

  // Suppress unused variable warnings — state is used for UI feedback
  void dsSaving

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>
            </svg>
          </span>
          {t('settings.dataSecurity.title')}
        </h2>
        <p className="s-section-subtitle">{t('settings.dataSecurity.subtitle')}</p>
      </div>

      {/* Webmail servers */}
      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.dataSecurity.webmailServers')}</div>
        <p style={{ fontSize: 12, color: 'var(--text-tertiary)', margin: '0 0 12px 0', lineHeight: 1.5 }}>
          {t('settings.dataSecurity.webmailServersDesc')}
        </p>

        {dsWebmailServers.length > 0 && (
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
            {dsWebmailServers.map((ip, i) => (
              <span key={i} style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                fontSize: 12, fontFamily: 'var(--font-mono)', fontWeight: 500,
                padding: '4px 10px', borderRadius: 6,
                background: 'rgba(34,211,238,0.08)', color: '#22d3ee',
                border: '1px solid rgba(34,211,238,0.15)',
              }}>
                {ip}
                <button
                  onClick={() => setDsWebmailServers(prev => prev.filter((_, idx) => idx !== i))}
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--text-tertiary)', padding: 0, lineHeight: 1,
                    fontSize: 14, fontWeight: 700,
                  }}
                  title={t('settings.dataSecurity.remove')}
                >
                  &times;
                </button>
              </span>
            ))}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            className="s-input"
            style={{ flex: 1, fontFamily: 'var(--font-mono)' }}
            value={dsNewServer}
            onChange={e => setDsNewServer(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && dsNewServer.trim()) {
                const ips = expandIpInput(dsNewServer)
                const valid = ips.filter(ip => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip))
                if (valid.length > 0) {
                  setDsWebmailServers(prev => [...new Set([...prev, ...valid])])
                  setDsNewServer('')
                }
              }
            }}
            placeholder={t('settings.dataSecurity.ipPlaceholder')}
          />
          <button
            className="s-btn-sm"
            style={{
              padding: '6px 14px', fontSize: 12, borderRadius: 6,
              background: 'rgba(34,211,238,0.1)', color: '#22d3ee',
              border: '1px solid rgba(34,211,238,0.2)', cursor: 'pointer',
            }}
            onClick={() => {
              const ips = expandIpInput(dsNewServer)
              const valid = ips.filter(ip => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip))
              if (valid.length > 0) {
                setDsWebmailServers(prev => [...new Set([...prev, ...valid])])
                setDsNewServer('')
              }
            }}
          >
            {t('settings.dataSecurity.add')}
          </button>
        </div>
      </div>

      {/* HTTP ports */}
      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.dataSecurity.httpPorts')}</div>
        <p style={{ fontSize: 12, color: 'var(--text-tertiary)', margin: '0 0 12px 0', lineHeight: 1.5 }}>
          {t('settings.dataSecurity.httpPortsDesc')}
        </p>

        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
          {dsHttpPorts.map((port, i) => (
            <span key={i} style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              fontSize: 12, fontFamily: 'var(--font-mono)', fontWeight: 500,
              padding: '4px 10px', borderRadius: 6,
              background: 'rgba(59,130,246,0.08)', color: '#3b82f6',
              border: '1px solid rgba(59,130,246,0.12)',
            }}>
              {port}
              <button
                onClick={() => setDsHttpPorts(prev => prev.filter((_, idx) => idx !== i))}
                style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--text-tertiary)', padding: 0, lineHeight: 1,
                  fontSize: 14, fontWeight: 700,
                }}
                title={t('settings.dataSecurity.remove')}
              >
                &times;
              </button>
            </span>
          ))}
        </div>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            className="s-input"
            style={{ width: 120, fontFamily: 'var(--font-mono)', textAlign: 'center' }}
            type="number"
            min={1}
            max={65535}
            value={dsNewPort}
            onChange={e => setDsNewPort(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && dsNewPort) {
                const p = parseInt(dsNewPort)
                if (p > 0 && p <= 65535 && !dsHttpPorts.includes(p)) {
                  setDsHttpPorts(prev => [...prev, p].sort((a, b) => a - b))
                  setDsNewPort('')
                }
              }
            }}
            placeholder={t('settings.dataSecurity.portPlaceholder')}
          />
          <button
            className="s-btn-sm"
            style={{
              padding: '6px 14px', fontSize: 12, borderRadius: 6,
              background: 'rgba(59,130,246,0.08)', color: '#3b82f6',
              border: '1px solid rgba(59,130,246,0.15)', cursor: 'pointer',
            }}
            onClick={() => {
              const p = parseInt(dsNewPort)
              if (p > 0 && p <= 65535 && !dsHttpPorts.includes(p)) {
                setDsHttpPorts(prev => [...prev, p].sort((a, b) => a - b))
                setDsNewPort('')
              }
            }}
          >
            {t('settings.dataSecurity.add')}
          </button>
        </div>
      </div>

      {/* Auto-save status */}
      {dsError && (
        <div style={{ color: '#ef4444', fontSize: 12, marginTop: 12 }}>{dsError}</div>
      )}
      {dsSaved && (
        <div className="s-deploy-success" style={{ marginTop: 12 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          {t('settings.dataSecurity.autoSaved')}
        </div>
      )}

    </div>
  )
}
