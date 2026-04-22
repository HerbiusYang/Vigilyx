import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { loadCachedUiPreferences, saveUiPreferencesPatch, syncUiPreferencesFromServer } from '../../utils/uiPreferences'

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

export default function CaptureSettings() {
  const { t } = useTranslation()
  const cached = loadCachedUiPreferences()
  // Protocol display toggles
  const [captureSmtp, setCaptureSmtp] = useState(
    cached.capture.smtp
  )
  const [capturePop3, setCapturePop3] = useState(
    cached.capture.pop3
  )
  const [captureImap, setCaptureImap] = useState(
    cached.capture.imap
  )
  const [autoRestore, setAutoRestore] = useState(
    cached.capture.auto_restore
  )
  const [maxPacketSize, setMaxPacketSize] = useState(
    cached.capture.max_packet_size
  )

  // Traffic rules: inbound
  const [inboundSrc, setInboundSrc] = useState<string[]>(
    cached.capture.inbound_src
  )
  const [inboundDst, setInboundDst] = useState<string[]>(
    cached.capture.inbound_dst
  )
  // Traffic rules: outbound
  const [outboundSrc, setOutboundSrc] = useState<string[]>(
    cached.capture.outbound_src
  )
  const [outboundDst, setOutboundDst] = useState<string[]>(
    cached.capture.outbound_dst
  )

  // Input fields for IP entry
  const [inSrcInput, setInSrcInput] = useState('')
  const [inDstInput, setInDstInput] = useState('')
  const [outSrcInput, setOutSrcInput] = useState('')
  const [outDstInput, setOutDstInput] = useState('')

  const [rulesSaved, setRulesSaved] = useState(false)
  const [rulesError, setRulesError] = useState<string | null>(null)
  const [rulesResetMsg, setRulesResetMsg] = useState(false)
  const hydratedRef = useRef(false)

  useEffect(() => {
    syncUiPreferencesFromServer()
      .then(prefs => {
        setCaptureSmtp(prefs.capture.smtp)
        setCapturePop3(prefs.capture.pop3)
        setCaptureImap(prefs.capture.imap)
        setAutoRestore(prefs.capture.auto_restore)
        setMaxPacketSize(prefs.capture.max_packet_size)
        setInboundSrc(prefs.capture.inbound_src)
        setInboundDst(prefs.capture.inbound_dst)
        setOutboundSrc(prefs.capture.outbound_src)
        setOutboundDst(prefs.capture.outbound_dst)
      })
      .catch(() => {})
      .finally(() => {
        hydratedRef.current = true
      })
  }, [])

  useEffect(() => {
    if (!hydratedRef.current) return
    const timer = window.setTimeout(() => {
      void saveUiPreferencesPatch({
        capture: {
          smtp: captureSmtp,
          pop3: capturePop3,
          imap: captureImap,
          auto_restore: autoRestore,
          max_packet_size: maxPacketSize,
        },
      }).catch(() => {})
    }, 250)
    return () => window.clearTimeout(timer)
  }, [captureSmtp, capturePop3, captureImap, autoRestore, maxPacketSize])

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon capture">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </span>
          {t('settings.capture.title')}
        </h2>
        <p className="s-section-subtitle">{t('settings.capture.subtitle')}</p>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.capture.protocolFilter')}</div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">
              <span className="s-protocol-dot smtp" />
              {t('settings.capture.showSmtp')}
            </span>
            <span className="s-setting-desc">{t('settings.capture.showSmtpDesc')}</span>
          </div>
          <label className="s-toggle">
            <input type="checkbox" checked={captureSmtp} onChange={e => setCaptureSmtp(e.target.checked)} />
            <span className="s-toggle-slider" />
          </label>
        </div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">
              <span className="s-protocol-dot pop3" />
              {t('settings.capture.showPop3')}
            </span>
            <span className="s-setting-desc">{t('settings.capture.showPop3Desc')}</span>
          </div>
          <label className="s-toggle">
            <input type="checkbox" checked={capturePop3} onChange={e => setCapturePop3(e.target.checked)} />
            <span className="s-toggle-slider" />
          </label>
        </div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">
              <span className="s-protocol-dot imap" />
              {t('settings.capture.showImap')}
            </span>
            <span className="s-setting-desc">{t('settings.capture.showImapDesc')}</span>
          </div>
          <label className="s-toggle">
            <input type="checkbox" checked={captureImap} onChange={e => setCaptureImap(e.target.checked)} />
            <span className="s-toggle-slider" />
          </label>
        </div>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.capture.trafficRules')}</div>

        <div className="s-setting-info s-group-hint">
          <span className="s-setting-desc">
            {t('settings.capture.trafficRulesDesc')}
          </span>
        </div>

        {/* Inbound rules */}
        <div className="s-rule-row">
          <span className="s-rule-badge inbound">{t('settings.capture.inbound')}</span>
          <div className="s-rule-flow">
            <div className="s-ip-tags">
              {inboundSrc.map((ip, i) => (
                <span key={i} className="s-ip-tag">
                  {ip}
                  <button className="s-ip-tag-remove" onClick={() => setInboundSrc(prev => prev.filter((_, j) => j !== i))}>&times;</button>
                </span>
              ))}
              <input
                type="text"
                className="s-ip-input"
                value={inSrcInput}
                onChange={e => setInSrcInput(e.target.value)}
                onKeyDown={e => {
                  if ((e.key === 'Enter' || e.key === ',') && inSrcInput.trim()) {
                    e.preventDefault()
                    const expanded = expandIpInput(inSrcInput.trim().replace(/,$/, ''))
                    const newIps = expanded.filter(ip => ip && !inboundSrc.includes(ip))
                    if (newIps.length) setInboundSrc(prev => [...prev, ...newIps])
                    setInSrcInput('')
                  }
                  if (e.key === 'Backspace' && !inSrcInput && inboundSrc.length > 0) setInboundSrc(prev => prev.slice(0, -1))
                }}
                placeholder={inboundSrc.length === 0 ? t('settings.capture.srcIpPlaceholder') : t('settings.capture.addMore')}
              />
            </div>
            <span className="s-rule-arrow">&rarr;</span>
            <div className="s-ip-tags">
              {inboundDst.map((ip, i) => (
                <span key={i} className="s-ip-tag dest">
                  {ip}
                  <button className="s-ip-tag-remove" onClick={() => setInboundDst(prev => prev.filter((_, j) => j !== i))}>&times;</button>
                </span>
              ))}
              <input
                type="text"
                className="s-ip-input"
                value={inDstInput}
                onChange={e => setInDstInput(e.target.value)}
                onKeyDown={e => {
                  if ((e.key === 'Enter' || e.key === ',') && inDstInput.trim()) {
                    e.preventDefault()
                    const expanded = expandIpInput(inDstInput.trim().replace(/,$/, ''))
                    const newIps = expanded.filter(ip => ip && !inboundDst.includes(ip))
                    if (newIps.length) setInboundDst(prev => [...prev, ...newIps])
                    setInDstInput('')
                  }
                  if (e.key === 'Backspace' && !inDstInput && inboundDst.length > 0) setInboundDst(prev => prev.slice(0, -1))
                }}
                placeholder={inboundDst.length === 0 ? t('settings.capture.dstIpPlaceholder') : t('settings.capture.addMore')}
              />
            </div>
          </div>
        </div>

        {/* Outbound rules */}
        <div className="s-rule-row">
          <span className="s-rule-badge outbound">{t('settings.capture.outbound')}</span>
          <div className="s-rule-flow">
            <div className="s-ip-tags">
              {outboundSrc.map((ip, i) => (
                <span key={i} className="s-ip-tag">
                  {ip}
                  <button className="s-ip-tag-remove" onClick={() => setOutboundSrc(prev => prev.filter((_, j) => j !== i))}>&times;</button>
                </span>
              ))}
              <input
                type="text"
                className="s-ip-input"
                value={outSrcInput}
                onChange={e => setOutSrcInput(e.target.value)}
                onKeyDown={e => {
                  if ((e.key === 'Enter' || e.key === ',') && outSrcInput.trim()) {
                    e.preventDefault()
                    const expanded = expandIpInput(outSrcInput.trim().replace(/,$/, ''))
                    const newIps = expanded.filter(ip => ip && !outboundSrc.includes(ip))
                    if (newIps.length) setOutboundSrc(prev => [...prev, ...newIps])
                    setOutSrcInput('')
                  }
                  if (e.key === 'Backspace' && !outSrcInput && outboundSrc.length > 0) setOutboundSrc(prev => prev.slice(0, -1))
                }}
                placeholder={outboundSrc.length === 0 ? t('settings.capture.srcIpPlaceholder') : t('settings.capture.addMore')}
              />
            </div>
            <span className="s-rule-arrow">&rarr;</span>
            <div className="s-ip-tags">
              {outboundDst.map((ip, i) => (
                <span key={i} className="s-ip-tag dest">
                  {ip}
                  <button className="s-ip-tag-remove" onClick={() => setOutboundDst(prev => prev.filter((_, j) => j !== i))}>&times;</button>
                </span>
              ))}
              <input
                type="text"
                className="s-ip-input"
                value={outDstInput}
                onChange={e => setOutDstInput(e.target.value)}
                onKeyDown={e => {
                  if ((e.key === 'Enter' || e.key === ',') && outDstInput.trim()) {
                    e.preventDefault()
                    const expanded = expandIpInput(outDstInput.trim().replace(/,$/, ''))
                    const newIps = expanded.filter(ip => ip && !outboundDst.includes(ip))
                    if (newIps.length) setOutboundDst(prev => [...prev, ...newIps])
                    setOutDstInput('')
                  }
                  if (e.key === 'Backspace' && !outDstInput && outboundDst.length > 0) setOutboundDst(prev => prev.slice(0, -1))
                }}
                placeholder={outboundDst.length === 0 ? t('settings.capture.dstIpAllExternal') : t('settings.capture.addMore')}
              />
            </div>
          </div>
        </div>

        {rulesResetMsg && (
          <div className="s-alert success in-group">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <span>{t('settings.capture.rulesResetSuccess')}</span>
          </div>
        )}

        {rulesError && (
          <div className="s-alert error in-group">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
            <span>{rulesError}</span>
          </div>
        )}

        {/* Summary of the currently effective rules */}
        {(inboundSrc.length > 0 || inboundDst.length > 0 || outboundSrc.length > 0 || outboundDst.length > 0) && (
          <div className="s-rules-saved-summary">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <span>
              {t('settings.capture.currentRules')}
              {(inboundSrc.length > 0 || inboundDst.length > 0) && (
                <> {t('settings.capture.inbound')} {inboundSrc.length > 0 ? inboundSrc.join(', ') : t('settings.capture.all')}
                  {inboundDst.length > 0 ? ` \u2192 ${inboundDst.join(', ')}` : ` \u2192 ${t('settings.capture.all')}`}
                </>
              )}
              {(inboundSrc.length > 0 || inboundDst.length > 0) && (outboundSrc.length > 0 || outboundDst.length > 0) && '\uff1b'}
              {(outboundSrc.length > 0 || outboundDst.length > 0) && (
                <> {t('settings.capture.outbound')} {outboundSrc.length > 0 ? outboundSrc.join(', ') : t('settings.capture.all')}
                  {outboundDst.length > 0 ? ` \u2192 ${outboundDst.join(', ')}` : ` \u2192 ${t('settings.capture.allExternal')}`}
                </>
              )}
            </span>
          </div>
        )}

        <div className="s-rule-actions">
          <button
            className="s-btn-ghost"
            disabled={rulesSaved}
            onClick={async () => {
              setInboundSrc([])
              setInboundDst([])
              setOutboundSrc([])
              setOutboundDst([])
              setInSrcInput('')
              setInDstInput('')
              setOutSrcInput('')
              setOutDstInput('')
              setRulesError(null)
              try {
                await saveUiPreferencesPatch({
                  capture: {
                    inbound_src: [],
                    inbound_dst: [],
                    outbound_src: [],
                    outbound_dst: [],
                  },
                })
                setRulesSaved(true)
                setRulesResetMsg(true)
                setTimeout(() => { setRulesSaved(false); setRulesResetMsg(false) }, 3000)
              } catch (e) {
                setRulesError(e instanceof Error ? e.message : t('settings.capture.rulesResetFailed'))
              }
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
            {t('settings.capture.resetRules')}
          </button>
          <button
            className={`s-btn-primary ${rulesSaved ? 's-btn-saved' : ''}`}
            disabled={rulesSaved}
            onClick={async () => {
              // First move any unsubmitted IPs from the input field into the array
              const flush = (input: string, setter: React.Dispatch<React.SetStateAction<string[]>>, existing: string[]) => {
                const trimmed = input.trim().replace(/,$/, '')
                if (trimmed) {
                  const expanded = expandIpInput(trimmed)
                  const newIps = expanded.filter(ip => ip && !existing.includes(ip))
                  if (newIps.length) setter(prev => [...prev, ...newIps])
                  return [...existing, ...newIps]
                }
                return existing
              }
              const finalInSrc = flush(inSrcInput, setInboundSrc, inboundSrc); setInSrcInput('')
              const finalInDst = flush(inDstInput, setInboundDst, inboundDst); setInDstInput('')
              const finalOutSrc = flush(outSrcInput, setOutboundSrc, outboundSrc); setOutSrcInput('')
              const finalOutDst = flush(outDstInput, setOutboundDst, outboundDst); setOutDstInput('')

              // Validate all IP formats
              const ipv4Re = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
              const validateIp = (ip: string): boolean => {
                const m = ipv4Re.exec(ip)
                if (!m) return false
                return [m[1], m[2], m[3], m[4]].every(o => {
                  const n = parseInt(o)
                  return n >= 0 && n <= 255
                })
              }

              const allIps = [
                ...finalInSrc.map(ip => ({ ip, label: t('settings.capture.inboundSrc') })),
                ...finalInDst.map(ip => ({ ip, label: t('settings.capture.inboundDst') })),
                ...finalOutSrc.map(ip => ({ ip, label: t('settings.capture.outboundSrc') })),
                ...finalOutDst.map(ip => ({ ip, label: t('settings.capture.outboundDst') })),
              ]

              const invalid = allIps.filter(({ ip }) => !validateIp(ip))
              if (invalid.length > 0) {
                const detail = invalid.map(({ ip, label }) => `${label}: ${ip}`).join('\u3001')
                setRulesError(t('settings.capture.invalidIp', { detail }))
                return
              }

              const hasInbound = finalInSrc.length > 0 || finalInDst.length > 0
              const hasOutbound = finalOutSrc.length > 0 || finalOutDst.length > 0
              if (!hasInbound && !hasOutbound) {
                setRulesError(t('settings.capture.atLeastOneRule'))
                return
              }

              setRulesError(null)
              try {
                await saveUiPreferencesPatch({
                  capture: {
                    inbound_src: finalInSrc,
                    inbound_dst: finalInDst,
                    outbound_src: finalOutSrc,
                    outbound_dst: finalOutDst,
                  },
                })
                setRulesSaved(true)
                setTimeout(() => setRulesSaved(false), 2000)
              } catch (e) {
                setRulesError(e instanceof Error ? e.message : t('settings.capture.rulesSaveFailed'))
              }
            }}
          >
            {rulesSaved ? (
              <>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                {t('settings.capture.applied')}
              </>
            ) : t('settings.capture.applyRules')}
          </button>
        </div>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.capture.advancedOptions')}</div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">{t('settings.capture.autoRestore')}</span>
            <span className="s-setting-desc">{t('settings.capture.autoRestoreDesc')}</span>
          </div>
          <label className="s-toggle">
            <input type="checkbox" checked={autoRestore} onChange={e => setAutoRestore(e.target.checked)} />
            <span className="s-toggle-slider" />
          </label>
        </div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">{t('settings.capture.maxPacketSize')}</span>
            <span className="s-setting-desc">{t('settings.capture.maxPacketSizeDesc')}</span>
          </div>
          <select
            className="s-select"
            value={maxPacketSize}
            onChange={e => setMaxPacketSize(Number(e.target.value))}
          >
            <option value={16384}>16 KB</option>
            <option value={32768}>32 KB</option>
            <option value={65535}>64 KB</option>
            <option value={131072}>128 KB</option>
            <option value={262144}>256 KB</option>
          </select>
        </div>
      </div>
    </div>
  )
}
