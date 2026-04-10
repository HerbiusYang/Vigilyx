import { useState, useEffect } from 'react'
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

const KW_CATEGORY_LABELS: Record<KwCategory, string> = {
  phishing_keywords: '钓鱼关键词',
  weak_phishing_keywords: '弱钓鱼关键词',
  bec_phrases: 'BEC 短语',
  internal_authority_phrases: '内部冒充短语',
  gateway_banner_patterns: '网关提示短语',
  notice_banner_patterns: '通知横幅短语',
  dsn_patterns: '退信系统短语',
  auto_reply_patterns: '自动回复短语',
}

export default function KeywordsTab() {
  const [kwBuiltin, setKwBuiltin] = useState<Record<string, string[]>>({})
  const [kwOverrides, setKwOverrides] = useState<KwOverrides | null>(null)
  const [kwLoaded, setKwLoaded] = useState(false)
  const [kwSaving, setKwSaving] = useState(false)
  const [kwNewKeyword, setKwNewKeyword] = useState('')
  const [kwActiveCategory, setKwActiveCategory] = useState<KwCategory>('phishing_keywords')
  const [kwMsg, setKwMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

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
        setKwMsg({ type: 'success', text: '关键词配置已保存，需重启引擎生效' })
        setKwLoaded(false)
      } else {
        setKwMsg({ type: 'error', text: data.error || '保存失败' })
      }
    } catch { setKwMsg({ type: 'error', text: '网络错误' }) }
    finally { setKwSaving(false) }
  }

  return (
    <div className="sec-panel">
      <div className="sec-panel-header">
        <h3>关键词管理</h3>
        <p style={{ fontSize: 13, color: 'var(--text-tertiary)', margin: '4px 0 0' }}>管理邮件安全检测引擎使用的关键词库。系统预置已包含平台种子词库，点击标签可屏蔽或恢复，支持搜索过滤。</p>
      </div>
      <div className="sec-panel-body" style={{ padding: '1.25rem' }}>
        {!kwLoaded ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-tertiary)' }}>
            <div className="page-loading" style={{ minHeight: 200 }} />
          </div>
        ) : !kwOverrides ? (
          <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>加载关键词配置失败</div>
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
              {(Object.keys(KW_CATEGORY_LABELS) as KwCategory[]).map(k => {
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
                    onKeyDown={e => e.key === 'Enter' && handleKwAdd()} placeholder="搜索或输入新关键词，回车添加..." />
                </div>
                <button className="kw-add-btn" onClick={handleKwAdd} disabled={!kwNewKeyword.trim()}>添加</button>
                <button className="kw-save-btn" onClick={handleKwSave} disabled={kwSaving}>{kwSaving ? '保存中...' : '保存配置'}</button>
                {kwMsg && <span className={`kw-save-msg ${kwMsg.type === 'success' ? 'ok' : 'err'}`}>{kwMsg.text}</span>}
              </div>

              {/* Statistics */}
              <div className="kw-stats">
                <span>系统 <strong className="n-sys">{builtinList.length}</strong></span>
                <span>已屏蔽 <strong className="n-off">{removedSet.size}</strong></span>
                <span>自定义 <strong className="n-add">{customAdded.length}</strong></span>
                <span>生效 <strong className="n-eff">{totalEffective}</strong></span>
              </div>

              {/* Custom additions */}
              {customAdded.length > 0 && (
                <div className="kw-section">
                  <div className="kw-section-hd">自定义添加</div>
                  <div className="kw-tags">
                    {customAdded.filter(matchesSearch).map(kw => (
                      <span key={`c-${kw}`} className="kw-tag kw-tag--add" onClick={() => handleKwRemove(kw)} title="点击删除">
                        {hl(kw)}<span className="kw-tag-x">×</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Hidden items */}
              {removedBuiltin.length > 0 && (
                <div className="kw-section">
                  <div className="kw-section-hd">已屏蔽（点击恢复）</div>
                  <div className="kw-tags">
                    {removedBuiltin.filter(matchesSearch).map(kw => (
                      <span key={`r-${kw}`} className="kw-tag kw-tag--off" onClick={() => handleKwRestore(kw)} title="点击恢复">
                        {hl(kw)}<span className="kw-tag-x">↩</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Built-in presets */}
              <div className="kw-section">
                <div className="kw-section-hd">系统预置（点击屏蔽）</div>
                <div className="kw-tags-scroll">
                  <div className="kw-tags">
                    {activeBuiltin.filter(matchesSearch).map(kw => (
                      <span key={`b-${kw}`} className="kw-tag kw-tag--sys" onClick={() => handleKwRemove(kw)} title="点击屏蔽">
                        {hl(kw)}
                      </span>
                    ))}
                    {activeBuiltin.filter(matchesSearch).length === 0 && searchLower.length >= 2 && (
                      <span style={{ fontSize: 13, color: 'var(--text-tertiary)', padding: '8px 0' }}>
                        没有匹配「{kwNewKeyword.trim()}」的关键词 — 按回车可添加为自定义词
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
