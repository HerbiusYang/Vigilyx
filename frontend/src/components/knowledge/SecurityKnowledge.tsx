import { useState, useEffect, useRef, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { type TopicId, type CategoryFilter, topicEntries, getTopicEntry, categoryFilters } from './knowledgeData'
import { searchTopics, type SearchResult, type SearchSnippet } from './knowledgeSearch'
import { TopicMTA, TopicOpportunisticTLS, TopicMandatoryTLS, TopicSTARTTLS, TopicSPF, TopicDSFusion, TopicTemporalEVT, TopicModulePipeline, TopicPhishingDetection, TopicIocIntel, TopicAiNlp, TopicSoarAlerts, TopicDataSecurity } from './knowledgeArticles'

type ViewMode = 'browse' | 'read'

/* ====== Icon Components ====== */
function TopicIcon({ type, size = 24 }: { type: string; size?: number }) {
  const props = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const }
  switch (type) {
    case 'mail':
      return <svg {...props}><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><polyline points="2,5 12,13 22,5"/></svg>
    case 'lock-open':
      return <svg {...props}><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>
    case 'lock-closed':
      return <svg {...props}><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    case 'code':
      return <svg {...props}><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
    case 'shield':
      return <svg {...props}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    case 'analytics':
      return <svg {...props}><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>
    default:
      return null
  }
}

/* ====== Highlight Component ====== */
function HighlightText({ text, highlights }: { text: string; highlights: [number, number][] }) {
  if (!highlights.length) return <>{text}</>
  const parts: React.ReactNode[] = []
  let lastEnd = 0
  const sorted = [...highlights].sort((a, b) => a[0] - b[0])
  for (const [start, end] of sorted) {
    if (start > lastEnd) parts.push(text.slice(lastEnd, start))
    parts.push(<mark className="sk-highlight" key={start}>{text.slice(start, end)}</mark>)
    lastEnd = end
  }
  if (lastEnd < text.length) parts.push(text.slice(lastEnd))
  return <>{parts}</>
}

/* ====== Article Renderer ====== */
function ArticleRenderer({ topicId }: { topicId: TopicId }) {
  switch (topicId) {
    case 'mta': return <TopicMTA />
    case 'opportunistic-tls': return <TopicOpportunisticTLS />
    case 'mandatory-tls': return <TopicMandatoryTLS />
    case 'starttls': return <TopicSTARTTLS />
    case 'spf-dkim-dmarc': return <TopicSPF />
    case 'ds-fusion': return <TopicDSFusion />
    case 'temporal-evt': return <TopicTemporalEVT />
    case 'module-pipeline': return <TopicModulePipeline />
    case 'phishing-detection': return <TopicPhishingDetection />
    case 'ioc-intel': return <TopicIocIntel />
    case 'ai-nlp': return <TopicAiNlp />
    case 'soar-alerts': return <TopicSoarAlerts />
    case 'data-security': return <TopicDataSecurity />
  }
}

/* ====== Table of Contents ====== */
interface TocItem {
  id: string
  text: string
}

function TableOfContents({ articleRef, topicId }: { articleRef: React.RefObject<HTMLDivElement | null>; topicId: TopicId | null }) {
  const [items, setItems] = useState<TocItem[]>([])
  const [activeId, setActiveId] = useState('')

  useEffect(() => {
    if (!articleRef.current) return
    // Small delay to ensure article DOM is rendered
    const timer = setTimeout(() => {
      if (!articleRef.current) return
      const headings = articleRef.current.querySelectorAll('.sk-section h2')
      const tocItems: TocItem[] = Array.from(headings).map((h, i) => {
        const id = `sk-h-${i}`
        h.id = id
        return { id, text: h.textContent || '' }
      })
      setItems(tocItems)
      if (tocItems.length > 0) setActiveId(tocItems[0].id)
    }, 50)
    return () => clearTimeout(timer)
  }, [topicId, articleRef])

  useEffect(() => {
    if (!items.length || !articleRef.current) return
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id)
          }
        }
      },
      { rootMargin: '-80px 0px -60% 0px', threshold: 0 }
    )
    items.forEach(item => {
      const el = document.getElementById(item.id)
      if (el) observer.observe(el)
    })
    return () => observer.disconnect()
  }, [items, articleRef])

  const handleClick = (id: string) => {
    const el = document.getElementById(id)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  if (items.length === 0) return null

  return (
    <aside className="sk-reader-toc">
      <div className="sk-toc-title">目录</div>
      <nav className="sk-toc">
        {items.map(item => (
          <button
            key={item.id}
            className={`sk-toc-item ${activeId === item.id ? 'active' : ''}`}
            onClick={() => handleClick(item.id)}
          >
            {item.text}
          </button>
        ))}
      </nav>
    </aside>
  )
}

/* ====== Main Component ====== */
function SecurityKnowledge() {
  const [searchParams] = useSearchParams()
  const exportTopicId = searchParams.get('export') as TopicId | null

  const [viewMode, setViewMode] = useState<ViewMode>('browse')
  const [activeTopic, setActiveTopic] = useState<TopicId | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<SearchResult[]>([])
  const [readingProgress, setReadingProgress] = useState(0)
  const [activeCategory, setActiveCategory] = useState<CategoryFilter>('全部')

  const searchInputRef = useRef<HTMLInputElement>(null)
  const searchDebounceRef = useRef<number>(0)
  const articleRef = useRef<HTMLDivElement>(null)

  // Export mode: hide app shell via body class
  useEffect(() => {
    if (!exportTopicId) return
    document.body.classList.add('sk-export-mode')
    return () => { document.body.classList.remove('sk-export-mode') }
  }, [exportTopicId])

  // Debounced search
  useEffect(() => {
    if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current)
    if (!searchQuery.trim()) {
      setSearchResults([])
      return
    }
    searchDebounceRef.current = window.setTimeout(() => {
      const results = searchTopics(searchQuery, topicEntries)
      setSearchResults(results)
    }, 200)
    return () => {
      if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current)
    }
  }, [searchQuery])

  // Keyboard shortcut: "/" to focus search
  useEffect(() => {
    const handleKeydown = (e: KeyboardEvent) => {
      if (e.key === '/' && viewMode === 'browse') {
        const tag = (e.target as HTMLElement)?.tagName
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
        e.preventDefault()
        searchInputRef.current?.focus()
      }
      if (e.key === 'Escape') {
        if (viewMode === 'read') {
          handleBackToBrowse()
        } else if (searchQuery) {
          setSearchQuery('')
          searchInputRef.current?.blur()
        }
      }
    }
    window.addEventListener('keydown', handleKeydown)
    return () => window.removeEventListener('keydown', handleKeydown)
  }, [viewMode, searchQuery])

  // Reading progress
  useEffect(() => {
    if (viewMode !== 'read' || !articleRef.current) {
      setReadingProgress(0)
      return
    }
    const handleScroll = () => {
      const el = articleRef.current
      if (!el) return
      const rect = el.getBoundingClientRect()
      const scrolled = -rect.top
      const total = el.scrollHeight - window.innerHeight
      if (total <= 0) { setReadingProgress(1); return }
      setReadingProgress(Math.max(0, Math.min(1, scrolled / total)))
    }
    window.addEventListener('scroll', handleScroll, { passive: true })
    handleScroll()
    return () => window.removeEventListener('scroll', handleScroll)
  }, [viewMode, activeTopic])

  const handleSelectTopic = useCallback((topicId: TopicId) => {
    setActiveTopic(topicId)
    setViewMode('read')
    setSearchQuery('')
    setSearchResults([])
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }, [])

  const handleBackToBrowse = useCallback(() => {
    setViewMode('browse')
    setActiveTopic(null)
    setReadingProgress(0)
  }, [])

  const activeEntry = activeTopic ? getTopicEntry(activeTopic) : null

  const handleExportPdf = useCallback(() => {
    if (!activeTopic) return
    window.open(`/knowledge?export=${activeTopic}`, '_blank', 'noopener,noreferrer')
  }, [activeTopic])

  const showSearchResults = searchQuery.trim().length > 0
  const filteredEntries = activeCategory === '全部'
    ? topicEntries
    : topicEntries.filter(e => e.category === activeCategory)

  /* ====== EXPORT MODE ====== */
  if (exportTopicId) {
    const exportEntry = getTopicEntry(exportTopicId)
    if (!exportEntry) return <div>文章不存在</div>
    return (
      <div className="sk-export-wrap">
        <div className="sk-export-banner">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <div className="sk-export-banner-text">
            <span className="sk-export-banner-title">Vigilyx 安全知识库</span>
            <span className="sk-export-banner-sep">|</span>
            <span className="sk-export-banner-article">{exportEntry.title}</span>
          </div>
          <span className="sk-export-banner-date">{new Date().toLocaleDateString('zh-CN')}</span>
        </div>
        <ArticleRenderer topicId={exportTopicId} />
      </div>
    )
  }

  /* ====== BROWSE MODE ====== */
  if (viewMode === 'browse') {
    return (
      <div className="sk-browse">
        {/* Hero */}
        <div className="sk-hero">
          <div className="sk-hero-glow" />
          <div className="sk-hero-content">
            <h1 className="sk-hero-title">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
              Vigilyx 安全知识库
            </h1>
            <p className="sk-hero-desc">深入理解邮件安全协议与威胁分析</p>
          </div>

          {/* Search bar */}
          <div className="sk-search-container">
            <div className="sk-search-bar">
              <svg className="sk-search-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <input
                ref={searchInputRef}
                type="text"
                placeholder="搜索文章标题、内容或关键词..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="sk-search-input"
              />
              {searchQuery ? (
                <button className="sk-search-clear" onClick={() => { setSearchQuery(''); searchInputRef.current?.focus() }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
              ) : (
                <kbd className="sk-search-kbd">/</kbd>
              )}
            </div>
          </div>

          {/* Category filter tags */}
          <div className="sk-filter-tags">
            {categoryFilters.map(cat => (
              <button
                key={cat}
                className={`sk-filter-tag ${activeCategory === cat ? 'active' : ''}`}
                onClick={() => setActiveCategory(cat)}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Search results or card grid */}
        {showSearchResults ? (
          <div className="sk-search-results">
            {searchResults.length > 0 ? (
              <>
                <div className="sk-search-count">
                  找到 <strong>{searchResults.length}</strong> 篇相关文章
                </div>
                {searchResults.map((result, idx) => (
                  <button
                    key={result.topicId}
                    className="sk-search-result"
                    style={{ animationDelay: `${idx * 40}ms` }}
                    onClick={() => handleSelectTopic(result.topicId)}
                  >
                    <div className="sk-search-result-icon">
                      <TopicIcon type={result.iconType} size={20} />
                    </div>
                    <div className="sk-search-result-body">
                      <div className="sk-search-result-header">
                        <span className="sk-search-result-title">{result.title}</span>
                        <span className={`sk-tag ${result.tagClass}`}>{result.tag}</span>
                      </div>
                      <div className="sk-search-result-subtitle">{result.subtitle}</div>
                      {result.snippets.map((snippet: SearchSnippet, si: number) => (
                        <div key={si} className="sk-search-snippet">
                          {snippet.sectionHeading && (
                            <span className="sk-snippet-section">{snippet.sectionHeading}</span>
                          )}
                          <span className="sk-snippet-text">
                            <HighlightText text={snippet.text} highlights={snippet.highlights} />
                          </span>
                        </div>
                      ))}
                    </div>
                    <svg className="sk-search-result-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                  </button>
                ))}
              </>
            ) : (
              <div className="sk-empty-state">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <div className="sk-empty-title">未找到相关内容</div>
                <div className="sk-empty-desc">尝试不同的关键词，或浏览下方的全部文章</div>
                <button className="sk-empty-browse" onClick={() => setSearchQuery('')}>浏览全部文章</button>
              </div>
            )}
          </div>
        ) : (
          <>
            <div className="sk-grid-header">
              <span className="sk-grid-count">{filteredEntries.length} 篇文章</span>
            </div>
            <div className="sk-card-grid">
              {filteredEntries.map((entry, idx) => (
                <button
                  key={entry.id}
                  className="sk-topic-card"
                  style={{ animationDelay: `${idx * 60}ms` }}
                  onClick={() => handleSelectTopic(entry.id)}
                >
                  <div className="sk-card-top">
                    <div className={`sk-card-icon ${entry.tagClass.replace('sk-tag-', 'sk-icon-')}`}>
                      <TopicIcon type={entry.iconType} size={22} />
                    </div>
                    <span className={`sk-tag ${entry.tagClass}`}>{entry.tag}</span>
                  </div>
                  <div className="sk-card-title">{entry.title}</div>
                  <div className="sk-card-subtitle">{entry.subtitle}</div>
                  <div className="sk-card-bottom">
                    <span className="sk-card-time">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                      {entry.readingTime} 分钟
                    </span>
                    <span className="sk-card-sections">{entry.sections.length} 个章节</span>
                    <svg className="sk-card-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                  </div>
                </button>
              ))}
            </div>
          </>
        )}
      </div>
    )
  }

  /* ====== READ MODE ====== */
  return (
    <div className="sk-reader">
      {/* Progress bar */}
      <div className="sk-progress-bar" style={{ width: `${readingProgress * 100}%` }} />

      <div className="sk-reader-layout">
        <div className="sk-reader-main" ref={articleRef}>
          {/* Navigation */}
          <div className="sk-reader-nav">
            <button className="sk-back-btn" onClick={handleBackToBrowse}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
              返回知识库
            </button>
            <div className="sk-breadcrumb">
              <span className="sk-breadcrumb-root" onClick={handleBackToBrowse}>知识库</span>
              <span className="sk-breadcrumb-sep">/</span>
              {activeEntry && <span className={`sk-tag ${activeEntry.tagClass}`}>{activeEntry.tag}</span>}
              <span className="sk-breadcrumb-sep">/</span>
              <span className="sk-breadcrumb-current">{activeEntry?.title}</span>
            </div>
            {activeEntry?.referenceUrl && (
              <a
                className="sk-export-btn"
                href={activeEntry.referenceUrl}
                target="_blank"
                rel="noopener noreferrer"
                title="查看外部参考资料"
                style={{ textDecoration: 'none' }}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                参考资料
              </a>
            )}
            <button className="sk-export-btn" onClick={handleExportPdf} title="导出为 PDF">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              导出 PDF
            </button>
          </div>

          {/* Article content */}
          {activeTopic && <ArticleRenderer topicId={activeTopic} />}
        </div>

        {/* Table of Contents */}
        <TableOfContents articleRef={articleRef} topicId={activeTopic} />
      </div>
    </div>
  )
}

export default SecurityKnowledge
