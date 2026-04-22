import { useState, useEffect, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../../utils/api'
import { formatDateOnly, getServerDateStamp, isPastServerNow } from '../../utils/format'
import type { ApiResponse, IocEntry } from '../../types'

const PAGE_SIZE = 30

export default function IocTab() {
  const { t } = useTranslation()
  const [iocList, setIocList] = useState<IocEntry[]>([])
  const [iocTotal, setIocTotal] = useState(0)
  const [iocSearch, setIocSearch] = useState('')
  const [iocTypeFilter, setIocTypeFilter] = useState('')
  const [showAddIoc, setShowAddIoc] = useState(false)
  const [addingIoc, setAddingIoc] = useState(false)
  const [iocForm, setIocForm] = useState({ indicator: '', ioc_type: 'ip', verdict: 'suspicious', confidence: 0.8, attack_type: 'unknown', description: '' })
  const [iocPage, setIocPage] = useState(0)
  const [showExportMenu, setShowExportMenu] = useState(false)
  const exportMenuRef = useRef<HTMLDivElement>(null)

  // Close export dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setShowExportMenu(false)
      }
    }
    if (showExportMenu) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [showExportMenu])

  const fetchIoc = useCallback(async () => {
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(iocPage * PAGE_SIZE),
      })
      if (iocSearch) params.set('search', iocSearch)
      if (iocTypeFilter) params.set('ioc_type', iocTypeFilter)
      const res = await apiFetch(`/api/security/ioc?${params}`)
      const data: ApiResponse<{ items: IocEntry[]; total: number }> = await res.json()
      if (data.success && data.data) {
        setIocList(data.data.items)
        setIocTotal(data.data.total)
      }
    } catch (e) {
      console.error('Failed to fetch IOC:', e)
    }
  }, [iocSearch, iocTypeFilter, iocPage])

  useEffect(() => {
    fetchIoc()
  }, [fetchIoc])

  const handleAddIoc = async () => {
    if (!iocForm.indicator.trim()) return
    setAddingIoc(true)
    try {
      const res = await apiFetch('/api/security/ioc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator: iocForm.indicator.trim(),
          ioc_type: iocForm.ioc_type,
          verdict: iocForm.verdict,
          confidence: iocForm.confidence,
          attack_type: iocForm.attack_type,
          description: iocForm.description || undefined,
        }),
      })
      const data: ApiResponse<any> = await res.json()
      if (data.success) {
        setIocForm({ indicator: '', ioc_type: 'ip', verdict: 'suspicious', confidence: 0.8, attack_type: 'unknown', description: '' })
        setShowAddIoc(false)
        fetchIoc()
      }
    } catch (e) {
      console.error('Failed to add IOC:', e)
    } finally {
      setAddingIoc(false)
    }
  }

  const handleDeleteIoc = async (id: string) => {
    try {
      const res = await apiFetch(`/api/security/ioc/${id}`, { method: 'DELETE' })
      const data = await res.json()
      if (!data.success) {
        alert(data.error || t('emailSecurity.deleteFailed'))
        return
      }
      fetchIoc()
    } catch (e) {
      console.error('Failed to delete IOC:', e)
    }
  }

  const handleExtendIoc = async (id: string, days: number = 30) => {
    try {
      const res = await apiFetch(`/api/security/ioc/${id}/extend`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ days }),
      })
      if (!res.ok) { console.error('Failed to extend IOC:', res.status); return }
      fetchIoc()
    } catch (e) {
      console.error('Failed to extend IOC:', e)
    }
  }

  const exportIoc = (verdictFilter?: string) => {
    const params = verdictFilter ? `?verdict=${verdictFilter}` : ''
    const url = `/api/security/ioc/export${params}`
    const verdictSlug = verdictFilter
      ? verdictFilter
          .split(',')
          .map(part => part.trim())
          .filter(Boolean)
          .join('-')
      : 'all'
    fetch(url, { credentials: 'same-origin' })
      .then(res => res.blob())
      .then(blob => {
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `vigilyx-ioc-${verdictSlug}-${getServerDateStamp()}.csv`
        a.click()
        URL.revokeObjectURL(a.href)
      })
      .catch(e => console.error('Export failed:', e))
  }

  const importIocFile = async (file: File) => {
    try {
      const text = await file.text()
      const res = await apiFetch('/api/security/ioc/import', {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: text,
      })
      const data: ApiResponse<{ imported: number; skipped: number }> = await res.json()
      if (data.success && data.data) {
        alert(t('emailSecurity.importComplete', { imported: data.data.imported, skipped: data.data.skipped }))
        fetchIoc()
      } else {
        alert(t('emailSecurity.importFailed', { error: data.error || t('emailSecurity.unknownError') }))
      }
    } catch (e) {
      console.error('Import failed:', e)
      alert(t('emailSecurity.importFailedGeneric'))
    }
  }

  return (
    <div className="sec-ioc">
      <div className="sec-ioc-toolbar">
        <div className="sec-ioc-search">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input
            type="text"
            placeholder={t('emailSecurity.searchIocPlaceholder')}
            value={iocSearch}
            onChange={e => { setIocSearch(e.target.value); setIocPage(0) }}
          />
        </div>
        <select
          className="sec-ioc-select"
          value={iocTypeFilter}
          onChange={e => { setIocTypeFilter(e.target.value); setIocPage(0) }}
        >
          <option value="">{t('emailSecurity.allTypes')}</option>
          <option value="ip">{t('emailSecurity.iocTypeIp')}</option>
          <option value="domain">{t('emailSecurity.iocTypeDomain')}</option>
          <option value="url">{t('emailSecurity.iocTypeUrl')}</option>
          <option value="hash">{t('emailSecurity.iocTypeHash')}</option>
          <option value="email">{t('emailSecurity.iocTypeEmail')}</option>
          <option value="subject">{t('emailSecurity.iocTypeSubject')}</option>
        </select>
        <div className="sec-ioc-actions">
          <span className="sec-ioc-total">{t('emailSecurity.totalItems', { count: iocTotal })}</span>
          <div className="sec-export-dropdown" ref={exportMenuRef}>
            <button className="sec-btn sec-btn--sm sec-btn--ghost" onClick={() => setShowExportMenu(!showExportMenu)} title={t('emailSecurity.exportIocTitle')}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              {t('emailSecurity.export')}
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
            </button>
            {showExportMenu && (
              <div className="sec-export-menu">
                <button className="sec-export-menu-item" onClick={() => { exportIoc('malicious,suspicious'); setShowExportMenu(false) }}>
                  <span className="sec-export-dot sec-export-dot--danger" />
                  {t('emailSecurity.exportMalicious')}
                </button>
                <button className="sec-export-menu-item" onClick={() => { exportIoc('clean'); setShowExportMenu(false) }}>
                  <span className="sec-export-dot sec-export-dot--safe" />
                  {t('emailSecurity.exportSafe')}
                </button>
                <div className="sec-export-menu-divider" />
                <button className="sec-export-menu-item" onClick={() => { exportIoc(); setShowExportMenu(false) }}>
                  <span className="sec-export-dot sec-export-dot--all" />
                  {t('emailSecurity.exportAll')}
                </button>
              </div>
            )}
          </div>
          <label className="sec-btn sec-btn--sm sec-btn--ghost sec-btn-upload" title={t('emailSecurity.importIocTitle')}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            {t('emailSecurity.import')}
            <input type="file" accept=".csv" style={{ display: 'none' }} onChange={e => {
              const file = e.target.files?.[0]
              if (file) { importIocFile(file); e.target.value = '' }
            }} />
          </label>
          <button className="sec-btn sec-btn--primary sec-btn--sm" onClick={() => setShowAddIoc(!showAddIoc)}>
            {showAddIoc ? t('emailSecurity.cancel') : t('emailSecurity.addIoc')}
          </button>
        </div>
      </div>

      {showAddIoc && (
        <div className="sec-ioc-add-form">
          <div className="sec-form-row">
            <div className="sec-form-group" style={{ flex: 2 }}>
              <label className="sec-form-label">{t('emailSecurity.indicatorValue')}</label>
              <input
                type="text"
                className="sec-form-input"
                value={iocForm.indicator}
                onChange={e => setIocForm({ ...iocForm, indicator: e.target.value })}
                placeholder={t('emailSecurity.indicatorPlaceholder')}
              />
            </div>
            <div className="sec-form-group">
              <label className="sec-form-label">{t('emailSecurity.type')}</label>
              <select className="sec-form-select" value={iocForm.ioc_type} onChange={e => setIocForm({ ...iocForm, ioc_type: e.target.value })}>
                <option value="ip">{t('emailSecurity.iocTypeIp')}</option>
                <option value="domain">{t('emailSecurity.iocTypeDomain')}</option>
                <option value="url">{t('emailSecurity.iocTypeUrl')}</option>
                <option value="hash">{t('emailSecurity.iocTypeHash')}</option>
                <option value="email">{t('emailSecurity.iocTypeEmail')}</option>
                <option value="subject">{t('emailSecurity.iocTypeSubject')}</option>
              </select>
            </div>
            <div className="sec-form-group">
              <label className="sec-form-label">{t('emailSecurity.verdict')}</label>
              <select className="sec-form-select" value={iocForm.verdict} onChange={e => setIocForm({ ...iocForm, verdict: e.target.value })}>
                <option value="malicious">{t('emailSecurity.verdictMalicious')}</option>
                <option value="suspicious">{t('emailSecurity.verdictSuspicious')}</option>
                <option value="safe">{t('emailSecurity.verdictSafe')}</option>
              </select>
            </div>
          </div>
          <div className="sec-form-row">
            <div className="sec-form-group">
              <label className="sec-form-label">{t('emailSecurity.attackType')}</label>
              <select className="sec-form-select" value={iocForm.attack_type} onChange={e => setIocForm({ ...iocForm, attack_type: e.target.value })}>
                <option value="phishing">{t('emailSecurity.attackPhishing')}</option>
                <option value="spoofing">{t('emailSecurity.attackSpoofing')}</option>
                <option value="malware">{t('emailSecurity.attackMalware')}</option>
                <option value="bec">{t('emailSecurity.attackBec')}</option>
                <option value="spam">{t('emailSecurity.attackSpam')}</option>
                <option value="unknown">{t('emailSecurity.attackUnknown')}</option>
              </select>
            </div>
            <div className="sec-form-group">
              <label className="sec-form-label">{t('emailSecurity.confidence')}</label>
              <input
                type="number"
                className="sec-form-input"
                value={iocForm.confidence}
                onChange={e => setIocForm({ ...iocForm, confidence: Math.min(1, Math.max(0, parseFloat(e.target.value) || 0)) })}
                min={0} max={1} step={0.1}
              />
            </div>
            <div className="sec-form-group" style={{ flex: 2 }}>
              <label className="sec-form-label">{t('emailSecurity.descriptionOptional')}</label>
              <input
                type="text"
                className="sec-form-input"
                value={iocForm.description}
                onChange={e => setIocForm({ ...iocForm, description: e.target.value })}
                placeholder={t('emailSecurity.notePlaceholder')}
              />
            </div>
            <div className="sec-form-group" style={{ alignSelf: 'flex-end' }}>
              <button className="sec-btn sec-btn--primary" onClick={handleAddIoc} disabled={addingIoc || !iocForm.indicator.trim()}>
                {addingIoc ? t('emailSecurity.adding') : t('emailSecurity.confirmAdd')}
              </button>
            </div>
          </div>
        </div>
      )}

      {iocList.length === 0 ? (
        <div className="sec-empty">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
          <p>{t('emailSecurity.noIocData')}</p>
        </div>
      ) : (
        <div className="sec-table-wrap">
          <table className="sec-table">
            <thead>
              <tr>
                <th>{t('emailSecurity.indicatorValue')}</th>
                <th>{t('emailSecurity.type')}</th>
                <th>{t('emailSecurity.source')}</th>
                <th>{t('emailSecurity.verdict')}</th>
                <th className="sec-th-r">{t('emailSecurity.confidence')}</th>
                <th className="sec-th-r">{t('emailSecurity.hits')}</th>
                <th>{t('emailSecurity.expiresAt')}</th>
                <th className="sec-th-r">{t('emailSecurity.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {iocList.map(ioc => {
                const isExpired = !!ioc.expires_at && isPastServerNow(ioc.expires_at)
                const expiresLabel = !ioc.expires_at ? t('emailSecurity.neverExpires')
                  : isExpired ? t('emailSecurity.expired')
                  : formatDateOnly(ioc.expires_at)
                return (
                  <tr key={ioc.id} style={isExpired ? { opacity: 0.5 } : undefined}>
                    <td className="sec-ioc-indicator" title={ioc.indicator}>
                      <span className="sec-mono">{ioc.indicator}</span>
                    </td>
                    <td><span className="sec-badge sec-badge--type">{ioc.ioc_type}</span></td>
                    <td>
                      {ioc.source === 'system' ? (
                        <span className="sec-badge sec-badge--system">{t('emailSecurity.sourceSystem')}</span>
                      ) : ioc.source === 'admin_clean' ? (
                        <span className="sec-badge sec-badge--admin">{t('emailSecurity.sourceAdmin')}</span>
                      ) : ioc.source === 'admin' ? (
                        <span className="sec-badge sec-badge--admin">{t('emailSecurity.sourceAdmin')}</span>
                      ) : (
                        <span className="sec-badge sec-badge--auto">{ioc.source}</span>
                      )}
                    </td>
                    <td>
                      <span className={`sec-verdict-tag sec-verdict--${ioc.verdict}`}>
                        {ioc.verdict === 'malicious' ? t('emailSecurity.verdictMalicious') : ioc.verdict === 'suspicious' ? t('emailSecurity.verdictSuspicious') : t('emailSecurity.verdictSafe')}
                      </span>
                    </td>
                    <td className="sec-td-r sec-mono">{(ioc.confidence * 100).toFixed(0)}%</td>
                    <td className="sec-td-r sec-mono">{ioc.hit_count}</td>
                    <td className={isExpired ? 'sec-text-warn' : ''}>
                      {expiresLabel}
                    </td>
                    <td className="sec-td-r" style={{ whiteSpace: 'nowrap' }}>
                      {ioc.source !== 'system' && ioc.expires_at && (
                        <button className="sec-btn-extend" onClick={() => handleExtendIoc(ioc.id, 30)} title={t('emailSecurity.extend30d')}>+30d</button>
                      )}
                      <button className="sec-btn-del" onClick={() => handleDeleteIoc(ioc.id)}>{t('emailSecurity.delete')}</button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {iocTotal > PAGE_SIZE && (
        <div className="sec-pagination">
          <button
            className="sec-page-btn"
            disabled={iocPage === 0}
            onClick={() => setIocPage(p => p - 1)}
          >
            {t('emailSecurity.prevPage')}
          </button>
          <span className="sec-page-info">
            {t('emailSecurity.pageInfo', { current: iocPage + 1, total: Math.ceil(iocTotal / PAGE_SIZE) })}
          </span>
          <button
            className="sec-page-btn"
            disabled={(iocPage + 1) * PAGE_SIZE >= iocTotal}
            onClick={() => setIocPage(p => p + 1)}
          >
            {t('emailSecurity.nextPage')}
          </button>
        </div>
      )}
    </div>
  )
}
