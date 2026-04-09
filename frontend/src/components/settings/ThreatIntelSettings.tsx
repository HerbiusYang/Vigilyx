import { useState, useEffect } from 'react'
import { apiFetch } from '../../utils/api'

export default function ThreatIntelSettings() {
  const [intelConfig, setIntelConfig] = useState({
    otx_enabled: true,
    vt_scrape_enabled: true,
    virustotal_api_key: '',
    virustotal_api_key_set: false,
    abuseipdb_enabled: false,
    abuseipdb_api_key: '',
    abuseipdb_api_key_set: false,
  })
  const [intelSaving, setIntelSaving] = useState(false)
  const [intelMsg, setIntelMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [intelLoaded, setIntelLoaded] = useState(false)

  // Load intel config on mount
  useEffect(() => {
    if (!intelLoaded) {
      apiFetch('/api/security/intel-config').then(r => r.json()).then(d => {
        if (d.success && d.data) {
          setIntelConfig(prev => ({
            ...prev,
            otx_enabled: d.data.otx_enabled ?? true,
            vt_scrape_enabled: d.data.vt_scrape_enabled ?? true,
            virustotal_api_key: d.data.virustotal_api_key || '',
            virustotal_api_key_set: d.data.virustotal_api_key_set ?? false,
            abuseipdb_enabled: d.data.abuseipdb_enabled ?? false,
            abuseipdb_api_key: d.data.abuseipdb_api_key || '',
            abuseipdb_api_key_set: d.data.abuseipdb_api_key_set ?? false,
          }))
          setIntelLoaded(true)
        }
      }).catch(() => {})
    }
  }, [intelLoaded])

  const handleSaveIntel = async () => {
    setIntelSaving(true)
    setIntelMsg(null)
    try {
      const payload: Record<string, unknown> = {
        otx_enabled: intelConfig.otx_enabled,
        vt_scrape_enabled: intelConfig.vt_scrape_enabled,
        abuseipdb_enabled: intelConfig.abuseipdb_enabled,
      }
      // Only send key if user typed a new one (not masked placeholder)
      if (intelConfig.virustotal_api_key && !intelConfig.virustotal_api_key.includes('...') && intelConfig.virustotal_api_key !== '****') {
        payload.virustotal_api_key = intelConfig.virustotal_api_key
      }
      if (intelConfig.abuseipdb_api_key && !intelConfig.abuseipdb_api_key.includes('...') && intelConfig.abuseipdb_api_key !== '****') {
        payload.abuseipdb_api_key = intelConfig.abuseipdb_api_key
      }
      const res = await apiFetch('/api/security/intel-config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data = await res.json()
      if (data.success) {
        setIntelMsg({ ok: true, text: '配置已保存，引擎重启后生效' })
        setIntelLoaded(false) // reload on next visit
      } else {
        setIntelMsg({ ok: false, text: data.error || '保存失败' })
      }
    } catch {
      setIntelMsg({ ok: false, text: '请求失败，请检查网络' })
    } finally {
      setIntelSaving(false)
    }
  }

  const IntelSourceCard = ({
    title, description, quota, icon, enabled, onToggle,
    apiKeyLabel, apiKeyPlaceholder, apiKeySet, apiKeyValue, onKeyChange,
    children,
  }: {
    title: string; description: string; quota: string; icon: React.ReactNode
    enabled: boolean; onToggle: (v: boolean) => void
    apiKeyLabel?: string; apiKeyPlaceholder?: string; apiKeySet?: boolean
    apiKeyValue?: string; onKeyChange?: (v: string) => void
    children?: React.ReactNode
  }) => (
    <div style={{
      border: '1px solid var(--border-primary)',
      borderRadius: 10,
      padding: '18px 20px',
      marginBottom: 12,
      background: 'var(--bg-secondary)',
      position: 'relative',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
        <div style={{
          width: 40, height: 40, borderRadius: 10,
          background: enabled ? 'rgba(99,102,241,0.12)' : 'rgba(148,163,184,0.08)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: enabled ? '#6366f1' : 'var(--text-tertiary)', flexShrink: 0,
        }}>
          {icon}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>{title}</span>
              <span style={{
                fontSize: 11, padding: '2px 7px', borderRadius: 4, fontWeight: 500,
                background: (apiKeySet || !apiKeyLabel) && enabled
                  ? 'rgba(34,197,94,0.12)' : 'rgba(148,163,184,0.1)',
                color: (apiKeySet || !apiKeyLabel) && enabled
                  ? '#22c55e' : 'var(--text-tertiary)',
              }}>
                {!apiKeyLabel ? (enabled ? '已启用' : '已禁用') : (apiKeySet ? '已配置' : '未配置')}
              </span>
            </div>
            <label className="s-toggle">
              <input type="checkbox" checked={enabled} onChange={e => onToggle(e.target.checked)} />
              <span className="s-toggle-slider" />
            </label>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-tertiary)', margin: '0 0 6px 0', lineHeight: 1.5 }}>{description}</p>
          <p style={{ fontSize: 11, color: 'var(--text-tertiary)', margin: 0, opacity: 0.7 }}>{quota}</p>
        </div>
      </div>
      {apiKeyLabel && enabled && (
        <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--border-primary)' }}>
          <div style={{ fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 6 }}>{apiKeyLabel}</div>
          <input
            type="password"
            className="s-input"
            style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: 12 }}
            placeholder={apiKeySet ? '已配置（输入新值以更换）' : (apiKeyPlaceholder || '输入 API Key')}
            value={apiKeyValue || ''}
            onChange={e => onKeyChange?.(e.target.value)}
            autoComplete="new-password"
          />
        </div>
      )}
      {children}
    </div>
  )

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon" style={{ background: 'rgba(99,102,241,0.08)', color: '#6366f1' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
              <line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/>
            </svg>
          </span>
          威胁情报源
        </h2>
        <p className="s-section-subtitle">接入外部威胁情报以增强邮件安全检测能力，情报数据用于 IP / 域名 / URL / 哈希信誉查询。</p>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">免费情报源（无需 API Key）</div>

        <IntelSourceCard
          title="OTX AlienVault"
          description="开源威胁交换平台，覆盖 IP、域名、文件哈希等 IOC，基于全球安全社区共享。无需注册即可使用。"
          quota="无需 API Key · 10 次/分钟 · 免费"
          enabled={intelConfig.otx_enabled}
          onToggle={v => setIntelConfig(prev => ({ ...prev, otx_enabled: v }))}
          icon={
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
            </svg>
          }
        />
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">商业情报源（需要 API Key）</div>

        <IntelSourceCard
          title="VirusTotal"
          description="文件 / URL / 域名 / IP 多引擎扫描，聚合 70+ 安全厂商检测结果，查询 URL / 域名 / IP / 文件哈希的恶意评判。"
          quota="免费版：4 次/分钟 · 500 次/天 · 超额后自动降级使用 VT Scrape"
          enabled={intelConfig.virustotal_api_key_set || intelConfig.virustotal_api_key.length > 0}
          onToggle={v => {
            if (!v) setIntelConfig(prev => ({ ...prev, virustotal_api_key: '', virustotal_api_key_set: false }))
          }}
          apiKeyLabel="API Key"
          apiKeyPlaceholder="输入 VirusTotal API Key"
          apiKeySet={intelConfig.virustotal_api_key_set}
          apiKeyValue={intelConfig.virustotal_api_key}
          onKeyChange={v => setIntelConfig(prev => ({ ...prev, virustotal_api_key: v }))}
          icon={
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
          }
        />

        <IntelSourceCard
          title="AbuseIPDB"
          description="基于社区举报的 IP 信誉数据库，返回 0-100 滥用置信度评分和历史举报详情。"
          quota="免费版：每日 1000 次 · 超额后自动跳过该源、继续使用其他情报"
          enabled={intelConfig.abuseipdb_enabled}
          onToggle={v => setIntelConfig(prev => ({ ...prev, abuseipdb_enabled: v }))}
          apiKeyLabel="API Key"
          apiKeyPlaceholder="输入 AbuseIPDB API Key"
          apiKeySet={intelConfig.abuseipdb_api_key_set}
          apiKeyValue={intelConfig.abuseipdb_api_key}
          onKeyChange={v => setIntelConfig(prev => ({ ...prev, abuseipdb_api_key: v }))}
          icon={
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          }
        />
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">降级策略</div>
        <div style={{ padding: '12px 16px', background: 'rgba(99,102,241,0.05)', borderRadius: 8, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          <div style={{ fontWeight: 500, marginBottom: 6, color: 'var(--text-primary)' }}>当情报源不可用时，系统自动降级：</div>
          <div>· <strong>VirusTotal 超出配额</strong>：自动回落到 VT Scrape（Playwright 抓取），重置窗口 24 小时</div>
          <div>· <strong>VT Scrape 不可用</strong>：跳过 VT，继续使用 OTX + AbuseIPDB</div>
          <div>· <strong>AbuseIPDB 超出配额</strong>：停止查询 AbuseIPDB，使用 OTX + VT，次日零点重置</div>
          <div>· <strong>429 响应</strong>：立即标记该源已耗尽，不再重试直到下次重置</div>
          <div>· <strong>全部不可用</strong>：引擎仅依赖本地 YARA / 启发式规则，不影响检测正常运行</div>
        </div>
      </div>

      <div className="s-deploy-action">
        {intelMsg && (
          <div className={intelMsg.ok ? 's-deploy-success' : ''} style={intelMsg.ok ? {} : { color: '#ef4444', fontSize: 12, marginBottom: 8 }}>
            {intelMsg.ok && <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>}
            {intelMsg.text}
          </div>
        )}
        <div className="s-deploy-action-row">
          <div className="s-deploy-action-hint">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2" style={{ flexShrink: 0 }}><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <span>API Key 经 AES-256-GCM 加密存储，引擎重启后生效</span>
          </div>
          <button
            className="s-btn-primary"
            disabled={intelSaving}
            onClick={handleSaveIntel}
          >
            {intelSaving ? '保存中...' : '保存配置'}
          </button>
        </div>
      </div>
    </div>
  )
}
