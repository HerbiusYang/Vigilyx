import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'

type KwCategory =
  | 'phishing_keywords'
  | 'weak_phishing_keywords'
  | 'bec_phrases'
  | 'internal_authority_phrases'
  | 'gateway_banner_patterns'
  | 'notice_banner_patterns'
  | 'dsn_patterns'
  | 'auto_reply_patterns'
interface KwCatOverride { added: string[]; removed: string[] }
interface KwOverrides {
  phishing_keywords: KwCatOverride
  weak_phishing_keywords: KwCatOverride
  bec_phrases: KwCatOverride
  internal_authority_phrases: KwCatOverride
  gateway_banner_patterns: KwCatOverride
  notice_banner_patterns: KwCatOverride
  dsn_patterns: KwCatOverride
  auto_reply_patterns: KwCatOverride
}

const KW_CATEGORY_KEYS: KwCategory[] = [
  'phishing_keywords',
  'weak_phishing_keywords',
  'bec_phrases',
  'internal_authority_phrases',
  'gateway_banner_patterns',
  'notice_banner_patterns',
  'dsn_patterns',
  'auto_reply_patterns',
]

export default function KeywordsTab() {
  const { t } = useTranslation()
  const [kwBuiltin, setKwBuiltin] = useState<Record<string, string[]>>({})
  const [kwOverrides, setKwOverrides] = useState<KwOverrides | null>(null)
  const [kwLoaded, setKwLoaded] = useState(false)
  const [kwSaving, setKwSaving] = useState(false)
  const [kwNewKeyword, setKwNewKeyword] = useState('')
  const [kwActiveCategory, setKwActiveCategory] = useState<KwCategory>('phishing_keywords')
  const [kwMsg, setKwMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const KW_CATEGORY_LABELS: Record<KwCategory, string> = {
    phishing_keywords: t('emailSecurity.kwPhishingKeywords'),
    weak_phishing_keywords: t('emailSecurity.kwWeakPhishingKeywords'),
    bec_phrases: t('emailSecurity.kwBecPhrases'),
    internal_authority_phrases: t('emailSecurity.kwInternalAuthorityPhrases'),
    gateway_banner_patterns: t('emailSecurity.kwGatewayBannerPatterns'),
    notice_banner_patterns: t('emailSecurity.kwNoticeBannerPatterns'),
    dsn_patterns: t('emailSecurity.kwDsnPatterns'),
    auto_reply_patterns: t('emailSecurity.kwAutoReplyPatterns'),
  }

  useEffect(() => {
    if (!kwLoaded) {
      apiFetch('/api/security/keyword-overrides')
        .then(r => r.json())
        .then(data => {
          if (data.success && data.data) {
            setKwBuiltin(data.data.builtin || {})
            setKwOverrides(data.data.overrides || null)
          }
          setKwLoaded(true)
        })
        .catch(() => setKwLoaded(true))
    }
  }, [kwLoaded])

  const handleKwAdd = () => {
    if (!kwOverrides || !kwNewKeyword.trim()) return
    const kw = kwNewKeyword.trim().toLowerCase()
    const cat = kwActiveCategory
    const ov = { ...kwOverrides }
    const catOv = { ...ov[cat] }
    if (catOv.removed.includes(kw)) {
      catOv.removed = catOv.removed.filter(r => r !== kw)
    } else if (!catOv.added.includes(kw)) {
      const builtinList = kwBuiltin[cat] || []
      if (!builtinList.includes(kw)) {
        catOv.added = [...catOv.added, kw]
      }
    }
    ov[cat] = catOv
    setKwOverrides(ov)
    setKwNewKeyword('')
  }

  const handleKwRemove = (kw: string) => {
    if (!kwOverrides) return
    const cat = kwActiveCategory
    const ov = { ...kwOverrides }
    const catOv = { ...ov[cat] }
    const builtinList = kwBuiltin[cat] || []
    if (builtinList.includes(kw)) {
      if (!catOv.removed.includes(kw)) catOv.removed = [...catOv.removed, kw]
    } else {
      catOv.added = catOv.added.filter(a => a !== kw)
    }
    ov[cat] = catOv
    setKwOverrides(ov)
  }

  const handleKwRestore = (kw: string) => {
    if (!kwOverrides) return
    const cat = kwActiveCategory
    const ov = { ...kwOverrides }
    const catOv = { ...ov[cat] }
    catOv.removed = catOv.removed.filter(r => r !== kw)
    ov[cat] = catOv
    setKwOverrides(ov)
  }

  const handleKwSave = async () => {
    if (!kwOverrides) return
    setKwSaving(true); setKwMsg(null)
    try {
      const res = await apiFetch('/api/security/keyword-overrides', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(kwOverrides),
      })
      const data = await res.json()
      if (data.success) {
        setKwMsg({ type: 'success', text: t('emailSecurity.kwSaveSuccess') })
        setKwLoaded(false)
      } else {
        setKwMsg({ type: 'error', text: data.error || t('emailSecurity.saveFailed') })
      }
    } catch { setKwMsg({ type: 'error', text: t('emailSecurity.networkError') }) }
    finally { setKwSaving(false) }
  }

  return (
    <div className="sec-panel">
      <div className="sec-panel-header">
        <h3>{t('emailSecurity.kwManageTitle')}</h3>
        <p style={{ fontSize: 13, color: 'var(--text-tertiary)', margin: '4px 0 0' }}>{t('emailSecurity.kwManageDesc')}</p>
      </div>
      <div className="sec-panel-body" style={{ padding: '1.25rem' }}>
        {!kwLoaded ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
            <div className="page-loading" style={{ minHeight: 200 }} />
          </div>
        ) : !kwOverrides ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>{t('emailSecurity.kwLoadFailed')}</div>
        ) : (() => {
          const cat = kwActiveCategory
          const builtinList: string[] = kwBuiltin[cat] || []
          const catOv = kwOverrides[cat]
          const removedSet = new Set(catOv.removed)
          const activeBuiltin = builtinList.filter(kw => !removedSet.has(kw))
          const removedBuiltin = builtinList.filter(kw => removedSet.has(kw))
          const customAdded = catOv.added
          const totalEffective = builtinList.length - removedSet.size + catOv.added.length
          const searchLower = kwNewKeyword.trim().toLowerCase()
          const hl = (text: string) => {
            if (!searchLower || searchLower.length < 2) return <>{text}</>
            const idx = text.toLowerCase().indexOf(searchLower)
            if (idx < 0) return <>{text}</>
            return <>{text.slice(0, idx)}<span className="kw-hl">{text.slice(idx, idx + searchLower.length)}</span>{text.slice(idx + searchLower.length)}</>
          }
          const matchesSearch = (kw: string) => !searchLower || searchLower.length < 2 || kw.toLowerCase().includes(searchLower)

          return <div className="kw-grid">
            {/* Left-side category navigation */}
            <div className="kw-cats">
              {KW_CATEGORY_KEYS.map(k => {
                const bl = kwBuiltin[k] || []
                const ov = kwOverrides[k]
                const eff = bl.length - ov.removed.length + ov.added.length
                return (
                  <button key={k} className={`kw-cat ${kwActiveCategory === k ? 'active' : ''}`}
                    onClick={() => setKwActiveCategory(k)}>
                    <span>{KW_CATEGORY_LABELS[k]}</span>
                    <span className="kw-cat-count">{eff}</span>
                  </button>
                )
              })}
            </div>

            {/* Right-side content area */}
            <div>
              {/* Search + add + save */}
              <div className="kw-toolbar">
                <div className="kw-search-wrap">
                  <svg className="kw-search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
                  <input className="kw-search" value={kwNewKeyword} onChange={e => setKwNewKeyword(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleKwAdd()} placeholder={t('emailSecurity.kwSearchPlaceholder')} />
                </div>
                <button className="kw-add-btn" onClick={handleKwAdd} disabled={!kwNewKeyword.trim()}>{t('emailSecurity.add')}</button>
                <button className="kw-save-btn" onClick={handleKwSave} disabled={kwSaving}>{kwSaving ? t('emailSecurity.saving') : t('emailSecurity.saveConfig')}</button>
                {kwMsg && <span className={`kw-save-msg ${kwMsg.type === 'success' ? 'ok' : 'err'}`}>{kwMsg.text}</span>}
              </div>

              {/* Statistics */}
              <div className="kw-stats">
                <span>{t('emailSecurity.kwSystem')} <strong className="n-sys">{builtinList.length}</strong></span>
                <span>{t('emailSecurity.kwDisabled')} <strong className="n-off">{removedSet.size}</strong></span>
                <span>{t('emailSecurity.kwCustom')} <strong className="n-add">{customAdded.length}</strong></span>
                <span>{t('emailSecurity.kwEffective')} <strong className="n-eff">{totalEffective}</strong></span>
              </div>

              {/* Custom additions */}
              {customAdded.length > 0 && (
                <div className="kw-section">
                  <div className="kw-section-hd">{t('emailSecurity.kwCustomAdded')}</div>
                  <div className="kw-tags">
                    {customAdded.filter(matchesSearch).map(kw => (
                      <span key={`c-${kw}`} className="kw-tag kw-tag--add" onClick={() => handleKwRemove(kw)} title={t('emailSecurity.kwClickToDelete')}>
                        {hl(kw)}<span className="kw-tag-x">×</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Hidden items */}
              {removedBuiltin.length > 0 && (
                <div className="kw-section">
                  <div className="kw-section-hd">{t('emailSecurity.kwDisabledClickRestore')}</div>
                  <div className="kw-tags">
                    {removedBuiltin.filter(matchesSearch).map(kw => (
                      <span key={`r-${kw}`} className="kw-tag kw-tag--off" onClick={() => handleKwRestore(kw)} title={t('emailSecurity.kwClickToRestore')}>
                        {hl(kw)}<span className="kw-tag-x">↩</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Built-in presets */}
              <div className="kw-section">
                <div className="kw-section-hd">{t('emailSecurity.kwBuiltinClickDisable')}</div>
                <div className="kw-tags-scroll">
                  <div className="kw-tags">
                    {activeBuiltin.filter(matchesSearch).map(kw => (
                      <span key={`b-${kw}`} className="kw-tag kw-tag--sys" onClick={() => handleKwRemove(kw)} title={t('emailSecurity.kwClickToDisable')}>
                        {hl(kw)}
                      </span>
                    ))}
                    {activeBuiltin.filter(matchesSearch).length === 0 && searchLower.length >= 2 && (
                      <span style={{ fontSize: 13, color: 'var(--text-tertiary)', padding: '8px 0' }}>
                        {t('emailSecurity.kwNoMatch', { keyword: kwNewKeyword.trim() })}
                      </span>
                    )}
                  </div>
                </div>
              </div>

            </div>
          </div>
        })()}
      </div>
    </div>
  )
}
