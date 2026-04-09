import React, { useState, useEffect, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import type { EmailSession, ApiResponse, PaginatedResponse, Protocol } from '../../types'
import { decodeMimeWord } from '../../utils/mime'
import { formatDate, getRelativeTime, isEncryptedPort } from '../../utils/format'
import { apiFetch } from '../../utils/api'

type TimeFilter = 'ALL' | '30m' | '1h' | '6h' | '24h'
type ProtocolFilter = Protocol | 'ALL'
type LogStatusFilter = 'finished' | 'ALL'

const statusLabels: Record<string, string> = {
  active: '活跃',
  completed: '完成',
  timeout: '超时',
  error: '错误',
}

/** Build link-trace nodes by ordering the current session and related sessions over time into a full transmission path. */
function buildChainNodes(current: EmailSession, related: EmailSession[]) {
  const all = [current, ...related].sort(
    (a, b) => new Date(a.started_at).getTime() - new Date(b.started_at).getTime()
  )
  // Each session is one hop: client_ip -> server_ip
  const nodes: {
    id: string
    clientIp: string
    clientPort: number
    serverIp: string
    serverPort: number
    encrypted: boolean
    protocol: string
    isCurrent: boolean
    hasContent: boolean
    time: string
  }[] = []

  for (const s of all) {
    const enc = s.content?.is_encrypted || isEncryptedPort(s.server_port)
    const hasContent = !!(s.content?.body_text || s.content?.body_html)
    nodes.push({
      id: s.id,
      clientIp: s.client_ip,
      clientPort: s.client_port,
      serverIp: s.server_ip,
      serverPort: s.server_port,
      encrypted: enc,
      protocol: s.protocol,
      isCurrent: s.id === current.id,
      hasContent,
      time: s.started_at,
    })
  }
  return nodes
}

export default function EncryptedLogs() {
  const [sessions, setSessions] = useState<EmailSession[]>([])
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [timeFilter, setTimeFilter] = useState<TimeFilter>('ALL')
  const [protocolFilter, setProtocolFilter] = useState<ProtocolFilter>('ALL')
  const [statusFilter, setStatusFilter] = useState<LogStatusFilter>('finished')
  const [searchInput, setSearchInput] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const pageSize = 20

  // Link tracing
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())
  const [relatedCache, setRelatedCache] = useState<Record<string, EmailSession[]>>({})
  const [relatedLoading, setRelatedLoading] = useState<Set<string>>(new Set())

  const [fetchError, setFetchError] = useState(false)
  const abortRef = useRef<AbortController | null>(null)
  const isInitialLoad = useRef(true)
  const debounceRef = useRef(0)

  // Search debounce
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = window.setTimeout(() => {
      setSearchTerm(searchInput.trim())
    }, 400)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [searchInput])

  const buildQueryString = useCallback((pageNum: number) => {
    const params = new URLSearchParams({
      page: String(pageNum),
      limit: String(pageSize),
    })
    if (protocolFilter !== 'ALL') params.set('protocol', protocolFilter)
    if (statusFilter === 'finished') params.set('status', 'completed')
    if (timeFilter !== 'ALL') {
      const ms: Record<string, number> = {
        '30m': 30 * 60_000, '1h': 60 * 60_000,
        '6h': 6 * 60 * 60_000, '24h': 24 * 60 * 60_000,
      }
      params.set('since', new Date(Date.now() - ms[timeFilter]).toISOString())
    }
    if (searchTerm) params.set('search', searchTerm)
    return params.toString()
  }, [timeFilter, protocolFilter, statusFilter, searchTerm])

  const fetchPage = useCallback(async (pageNum: number) => {
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    if (isInitialLoad.current) setLoading(true)
    try {
      const qs = buildQueryString(pageNum)
      const res = await apiFetch(`/api/sessions?${qs}`, { signal: controller.signal })
      const data: ApiResponse<PaginatedResponse<EmailSession>> = await res.json()
      if (data.success && data.data) {
        setSessions(data.data.items)
        setTotal(data.data.total)
        setTotalPages(data.data.total_pages)
        setPage(pageNum)
        setFetchError(false)
      }
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === 'AbortError') return
      setFetchError(true)
    } finally {
      if (!controller.signal.aborted) { setLoading(false); isInitialLoad.current = false }
    }
  }, [buildQueryString])

  useEffect(() => { fetchPage(1) }, [fetchPage])

  // 30s polling (only while the page is visible)
  useEffect(() => {
    const timer = setInterval(() => {
      if (document.hidden) return
      apiFetch(`/api/sessions?${buildQueryString(page)}`)
        .then(r => r.json())
        .then((data: ApiResponse<PaginatedResponse<EmailSession>>) => {
          if (data.success && data.data) {
            setSessions(data.data.items)
            setTotal(data.data.total)
            setTotalPages(data.data.total_pages)
          }
        }).catch(() => {})
    }, 30000)
    return () => clearInterval(timer)
  }, [buildQueryString, page])

  useEffect(() => { return () => { abortRef.current?.abort() } }, [])

  // Load related sessions for link tracing
  const toggleChain = useCallback(async (sessionId: string) => {
    setExpandedRows(prev => {
      const next = new Set(prev)
      if (next.has(sessionId)) { next.delete(sessionId); return next }
      next.add(sessionId)
      return next
    })
    // If cached, do not fetch again
    if (relatedCache[sessionId]) return
    setRelatedLoading(prev => new Set(prev).add(sessionId))
    try {
      const res = await apiFetch(`/api/sessions/${sessionId}/related`)
      const data: ApiResponse<EmailSession[]> = await res.json()
      if (data.success && data.data) {
        setRelatedCache(prev => ({ ...prev, [sessionId]: data.data! }))
      } else {
        setRelatedCache(prev => ({ ...prev, [sessionId]: [] }))
      }
    } catch {
      setRelatedCache(prev => ({ ...prev, [sessionId]: [] }))
    } finally {
      setRelatedLoading(prev => { const n = new Set(prev); n.delete(sessionId); return n })
    }
  }, [relatedCache])

  // Search highlighting
  const highlight = (text: string | null | undefined): React.ReactNode => {
    if (!text) return text
    if (!searchTerm) return text
    const idx = text.toLowerCase().indexOf(searchTerm.toLowerCase())
    if (idx === -1) return text
    return <>{text.slice(0, idx)}<mark className="search-highlight">{text.slice(idx, idx + searchTerm.length)}</mark>{text.slice(idx + searchTerm.length)}</>
  }

  const colCount = 10

  return (
    <div className="traffic-list">
      <div className="traffic-list-header">
        <div className="header-left">
          <h1>日志</h1>
          <div className="email-stats">
            <span className="email-count">
              共 {total} 条
            </span>
          </div>
        </div>
        <div className="header-right">
          <div className="log-search-box">
            <input
              type="text"
              className="log-search-input"
              placeholder="搜索 IP、发件人、收件人、主题..."
              value={searchInput}
              onChange={e => setSearchInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') {
                  if (debounceRef.current) clearTimeout(debounceRef.current)
                  setSearchTerm(searchInput.trim())
                }
              }}
            />
            {searchInput && (
              <button className="log-search-clear" onClick={() => { setSearchInput(''); setSearchTerm('') }} title="清除搜索">x</button>
            )}
          </div>
          <div className="filters">
            <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value as LogStatusFilter)}>
              <option value="finished">已完成</option>
              <option value="ALL">全部状态</option>
            </select>
            <select className="filter-select" value={protocolFilter} onChange={e => setProtocolFilter(e.target.value as ProtocolFilter)}>
              <option value="ALL">全部协议</option>
              <option value="SMTP">SMTP</option>
              <option value="POP3">POP3</option>
              <option value="IMAP">IMAP</option>
            </select>
            <select className="filter-select" value={timeFilter} onChange={e => setTimeFilter(e.target.value as TimeFilter)}>
              <option value="ALL">全部时间</option>
              <option value="30m">最近 30 分钟</option>
              <option value="1h">最近 1 小时</option>
              <option value="6h">最近 6 小时</option>
              <option value="24h">最近 24 小时</option>
            </select>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="table-container">
          <table><thead><tr>
            <th></th><th>时间</th><th>协议</th><th>状态</th><th>源地址</th><th>目的地址</th><th>发件人</th><th>收件人</th><th>主题</th><th>操作</th>
          </tr></thead><tbody>
            {[1,2,3,4].map(i => <tr key={i} className="skeleton-row">{Array.from({length: colCount}, (_,j) => <td key={j}><div className="skeleton-line narrow"/></td>)}</tr>)}
          </tbody></table>
        </div>
      ) : sessions.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{color:'#6e7681'}}>
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
          </div>
          {fetchError ? (
            <><h3>数据加载失败</h3><p>请检查网络连接或稍后重试</p></>
          ) : searchTerm ? (
            <><h3>未找到匹配的日志</h3><p>没有匹配 "{searchTerm}" 的记录</p>
              <button className="view-all-btn" onClick={() => {setSearchInput('');setSearchTerm('')}}>清除搜索</button></>
          ) : (
            <><h3>暂无日志记录</h3><p>等待邮件传输完成后自动记录</p></>
          )}
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead><tr>
              <th className="chain-col"></th>
              <th>时间</th>
              <th>协议</th>
              <th>状态</th>
              <th>源地址</th>
              <th>目的地址</th>
              <th>发件人</th>
              <th>收件人</th>
              <th>主题</th>
              <th>操作</th>
            </tr></thead>
            <tbody>
              {sessions.map(s => {
                const isEncrypted = s.content?.is_encrypted || isEncryptedPort(s.server_port)
                const hasContent = !!(s.content?.body_text || s.content?.body_html)
                const isExpanded = expandedRows.has(s.id)
                const related = relatedCache[s.id]
                const isLoadingRelated = relatedLoading.has(s.id)
                return (
                  <React.Fragment key={s.id}>
                    <tr className={isExpanded ? 'expanded-parent' : ''}>
                      <td className="chain-col">
                        <button
                          className={`chain-toggle-btn ${isExpanded ? 'expanded' : ''}`}
                          onClick={() => toggleChain(s.id)}
                          title="链路追踪 (Message-ID 关联)"
                        >
                          {isExpanded ? '▼' : '▶'}
                        </button>
                      </td>
                      <td title={formatDate(s.started_at)}>{getRelativeTime(s.started_at)}</td>
                      <td>
                        <span className={`protocol-badge ${s.protocol.toLowerCase()}`}>{s.protocol}</span>
                        {isEncrypted && <span className="encrypted-badge small" style={{marginLeft:4}}>TLS</span>}
                      </td>
                      <td><span className={`status-badge ${s.status}`}>{statusLabels[s.status] || s.status}</span></td>
                      <td className="mono-cell">{highlight(`${s.client_ip}:${s.client_port}`)}</td>
                      <td className="mono-cell">{highlight(`${s.server_ip}:${s.server_port}`)}</td>
                      <td className="ellipsis-cell">{highlight(s.mail_from) || '-'}</td>
                      <td className="ellipsis-cell">
                        {s.rcpt_to.length > 0
                          ? s.rcpt_to.length > 1
                            ? <>{highlight(s.rcpt_to[0])} <span className="extra-count">+{s.rcpt_to.length-1}</span></>
                            : highlight(s.rcpt_to[0])
                          : '-'}
                      </td>
                      <td className="subject-cell">
                        {highlight(decodeMimeWord(s.subject)) || (isEncrypted ? '(已加密)' : '(无主题)')}
                      </td>
                      <td>
                        {hasContent || !isEncrypted ? (
                          <Link to={`/emails/${s.id}`} className="table-action">详情</Link>
                        ) : (
                          <span className="table-action disabled">已加密</span>
                        )}
                      </td>
                    </tr>

                    {/* Expanded row for link tracing */}
                    {isExpanded && (
                      <tr className="chain-detail-row">
                        <td colSpan={colCount}>
                          {isLoadingRelated ? (
                            <div className="chain-loading">加载链路信息...</div>
                          ) : !related || related.length === 0 ? (
                            <div className="chain-empty">
                              {s.message_id
                                ? <span className="chain-msg-id" title={s.message_id}>Message-ID: {s.message_id}</span>
                                : <span className="chain-msg-id">无 Message-ID (加密会话)</span>
                              }
                              <span className="chain-no-related">未找到关联会话</span>
                            </div>
                          ) : (
                            <div className="chain-trace">
                              <div className="chain-msg-id" title={s.message_id || ''}>
                                {s.message_id
                                  ? <>Message-ID: {s.message_id}</>
                                  : <>无 Message-ID (加密会话)</>

                                }
                              </div>
                              <div className="chain-path">
                                {buildChainNodes(s, related).map((node, idx, arr) => (
                                  <React.Fragment key={node.id}>
                                    <div className={`chain-hop ${node.isCurrent ? 'current' : ''}`}>
                                      <div className="chain-hop-header">
                                        <span className={`protocol-badge small ${node.protocol.toLowerCase()}`}>{node.protocol}</span>
                                        {node.encrypted
                                          ? <span className="chain-tls-badge">TLS</span>
                                          : <span className="chain-plain-badge">明文</span>
                                        }
                                        {node.hasContent && <span className="chain-content-badge">有内容</span>}
                                        {node.isCurrent && <span className="chain-current-badge">当前</span>}
                                      </div>
                                      <div className="chain-hop-endpoints">
                                        <span className="chain-ip">{node.clientIp}:{node.clientPort}</span>
                                        <span className={`chain-arrow ${node.encrypted ? 'encrypted' : 'plain'}`}>
                                          {node.encrypted ? '---TLS--->' : '----------->'}
                                        </span>
                                        <span className="chain-ip">{node.serverIp}:{node.serverPort}</span>
                                      </div>
                                      <div className="chain-hop-time">{formatDate(node.time)}</div>
                                      {!node.isCurrent && (
                                        <Link to={`/emails/${node.id}`} className="chain-hop-link">查看此段</Link>
                                      )}
                                    </div>
                                    {idx < arr.length - 1 && (
                                      <div className="chain-connector">
                                        <div className="chain-connector-line" />
                                      </div>
                                    )}
                                  </React.Fragment>
                                ))}
                              </div>
                              {/* One-line summary of the full path */}
                              <div className="chain-summary">
                                {(() => {
                                  const nodes = buildChainNodes(s, related)
                                  const parts: string[] = []
                                  for (let i = 0; i < nodes.length; i++) {
                                    if (i === 0) parts.push(nodes[i].clientIp)
                                    parts.push(nodes[i].encrypted ? '--TLS-->' : '--明文-->')
                                    parts.push(nodes[i].serverIp)
                                  }
                                  return <code className="chain-summary-path">{parts.join(' ')}</code>
                                })()}
                              </div>
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {!loading && total > 0 && (
        <div className="pagination-controls">
          <div className="pagination-info">
            <span className="pagination-text">
              第 <b>{page}</b> / {totalPages} 页，共 {total} 条
            </span>
          </div>
          {totalPages > 1 && (
            <div className="pagination-buttons">
              <button className="pagination-btn" disabled={page<=1} onClick={() => fetchPage(1)} title="首页">&laquo;</button>
              <button className="pagination-btn" disabled={page<=1} onClick={() => fetchPage(page-1)} title="上一页">&lsaquo;</button>
              {(() => {
                const items: (number | '...')[] = []
                if (totalPages <= 7) {
                  for (let i = 1; i <= totalPages; i++) items.push(i)
                } else {
                  items.push(1)
                  if (page > 3) items.push('...')
                  const start = Math.max(2, page - 1)
                  const end = Math.min(totalPages - 1, page + 1)
                  for (let i = start; i <= end; i++) items.push(i)
                  if (page < totalPages - 2) items.push('...')
                  items.push(totalPages)
                }
                return items.map((item, idx) =>
                  item === '...' ? (
                    <span key={`e${idx}`} className="pagination-ellipsis">...</span>
                  ) : (
                    <button key={item} className={`pagination-btn ${item===page?'active':''}`} onClick={() => item!==page && fetchPage(item)}>{item}</button>
                  )
                )
              })()}
              <button className="pagination-btn" disabled={page>=totalPages} onClick={() => fetchPage(page+1)} title="下一页">&rsaquo;</button>
              <button className="pagination-btn" disabled={page>=totalPages} onClick={() => fetchPage(totalPages)} title="末页">&raquo;</button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
