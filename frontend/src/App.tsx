import { useState, useEffect, useCallback, useMemo, useRef, lazy, Suspense, Component } from 'react'
import type { ReactNode, ErrorInfo } from 'react'
import { BrowserRouter, Routes, Route, Link, useLocation, Navigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import i18n from './i18n'
import { EVENTS } from './utils/events'

/** Track previous value of a state variable */
function usePrevious<T>(value: T): T | undefined {
  const ref = useRef<T | undefined>(undefined)
  useEffect(() => { ref.current = value })
  return ref.current
}

/** Lazy import with auto-reload on chunk load failure (deployment cache mismatch) */
function lazyRetry<T extends { default: React.ComponentType }>(
  factory: () => Promise<T>,
): React.LazyExoticComponent<T['default']> {
  return lazy(() =>
    factory().catch((err) => {
      // If a chunk fails to load (filenames changed after deployment), refresh the page to fetch the new HTML
      const reloaded = sessionStorage.getItem('vigilyx-chunk-reload')
      if (!reloaded) {
        sessionStorage.setItem('vigilyx-chunk-reload', '1')
        window.location.reload()
      }
      throw err
    }),
  )
}

/** Error boundary - catches child render crashes so the whole page does not go blank. */
class ChunkErrorBoundary extends Component<
  { children: ReactNode },
  { hasError: boolean; error: Error | null }
> {
  state = { hasError: false, error: null as Error | null }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error }
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Page render error:', error, info)
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary)' }}>
          <p style={{ fontSize: 15, marginBottom: 16 }}>{i18n.t('app.pageError')}</p>
          <button
            onClick={() => window.location.reload()}
            style={{
              padding: '8px 20px', borderRadius: 8, border: '1px solid var(--border-default)',
              background: 'var(--bg-elevated)', color: 'var(--text-primary)', cursor: 'pointer',
            }}
          >
            {i18n.t('app.refresh')}
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// Clear the chunk-reload marker after the page loads successfully
sessionStorage.removeItem('vigilyx-chunk-reload')

import Login from './components/auth/Login'
import SetupWizard from './components/auth/SetupWizard'
import SystemStatusBar from './components/settings/SystemStatusBar'
import ThemeToggle from './components/settings/ThemeToggle'
import LanguageToggle from './components/settings/LanguageToggle'

const Dashboard = lazyRetry(() => import('./components/dashboard/Dashboard'))
const TrafficList = lazyRetry(() => import('./components/email-security/TrafficList'))
const EmailDetail = lazyRetry(() => import('./components/email-security/EmailDetail'))
const Settings = lazyRetry(() => import('./components/settings/Settings'))
const EmailSecurity = lazyRetry(() => import('./components/email-security/EmailSecurity'))
const EncryptedLogs = lazyRetry(() => import('./components/network/EncryptedLogs'))
const SecurityKnowledge = lazyRetry(() => import('./components/knowledge/SecurityKnowledge'))
const DataSecurity = lazyRetry(() => import('./components/data-security/DataSecurity'))
const AutomationDisposition = lazyRetry(() => import('./components/automation/AutomationDisposition'))
const OpenSourceCommunity = lazyRetry(() => import('./components/community/OpenSourceCommunity'))
const Quarantine = lazyRetry(() => import('./components/quarantine/Quarantine'))
import { useWebSocket } from './hooks/useWebSocket'
import { useTheme } from './hooks/useTheme'
import { apiFetch, resetLogoutFlag } from './utils/api'
import { syncServerClock } from './utils/format'
import { notifySecurityVerdict, notifyNewSession, notifyDataSecurityAlert } from './utils/notify'
import { resolveSetupStatus } from './utils/setupStatus'
import { syncUiPreferencesFromServer } from './utils/uiPreferences'
import './App.css'

function NavLink({ to, icon, children, activeMatch }: { to: string; icon: React.ReactNode; children: React.ReactNode; activeMatch?: (path: string) => boolean }) {
  const location = useLocation()
  const isActive = activeMatch ? activeMatch(location.pathname) : to === '/' ? location.pathname === '/' : location.pathname.startsWith(to)

  return (
    <Link
      to={to}
      className={`nav-link ${isActive ? 'active' : ''}`}
    >
      <span className="nav-icon">{icon}</span>
      <span className="nav-label">{children}</span>
      {isActive && <span className="nav-indicator" />}
    </Link>
  )
}

interface AppContentProps {
  onLogout: () => void
}

function RealtimeBridge({
  mode,
  onConnectedChange,
  refreshStats,
}: {
  mode: 'app' | 'portal'
  onConnectedChange: (connected: boolean) => void
  refreshStats?: () => void
}) {
  const wsUrl = useMemo(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${window.location.host}/ws`
  }, [])
  const { lastMessage, readyState } = useWebSocket(wsUrl)
  const prevReadyState = usePrevious(readyState)

  useEffect(() => {
    const wasDisconnected = prevReadyState !== undefined && prevReadyState !== WebSocket.OPEN
    const nowConnected = readyState === WebSocket.OPEN

    onConnectedChange(nowConnected)
    window.dispatchEvent(new CustomEvent(EVENTS.CONNECTION_CHANGE, { detail: { connected: nowConnected } }))

    if (wasDisconnected && nowConnected) {
      refreshStats?.()
      window.dispatchEvent(new Event(EVENTS.WS_RECONNECTED))
    }
  }, [onConnectedChange, prevReadyState, readyState, refreshStats])

  useEffect(() => {
    if (!lastMessage) return

    try {
      const parsed = JSON.parse(lastMessage.data) as Record<string, unknown>

      if (parsed.type === 'StatsUpdate') {
        window.dispatchEvent(new CustomEvent(EVENTS.STATS_UPDATE, { detail: { stats: parsed.data, connected: true } }))
        return
      }

      if (parsed.type === 'RefreshNeeded') {
        refreshStats?.()
        window.dispatchEvent(new Event(EVENTS.WS_RECONNECTED))
        return
      }

      if (parsed.type === 'DataSecurityAlert') {
        notifyDataSecurityAlert(parsed)
        window.dispatchEvent(new Event(EVENTS.DASHBOARD_REFRESH))
        return
      }

      if (mode === 'portal') return

      if (parsed.type === 'SecurityVerdict') {
        notifySecurityVerdict(parsed)
        window.dispatchEvent(new Event(EVENTS.DASHBOARD_REFRESH))
      } else if (parsed.type === 'NewSession') {
        notifyNewSession()
        window.dispatchEvent(new Event(EVENTS.DASHBOARD_REFRESH))
      } else if (parsed.type === 'SessionUpdate') {
        window.dispatchEvent(new Event(EVENTS.DASHBOARD_REFRESH))
      }
    } catch (e) {
      console.error('Failed to parse WebSocket message:', e)
    }
  }, [lastMessage, mode, refreshStats])

  return null
}

function AppContent({ onLogout }: AppContentProps) {
  const { t } = useTranslation()
  const { theme, toggleTheme } = useTheme()
  const [connected, setConnected] = useState(false)
  const [deployMode, setDeployMode] = useState<string>(
    () => localStorage.getItem('vigilyx-deploy-mode') || 'mirror'
  )

  // Load the deployment mode from the API to decide which navigation items are visible
  useEffect(() => {
    void syncUiPreferencesFromServer()
  }, [])

  useEffect(() => {
    let cancelled = false

    const syncClock = async () => {
      try {
        const res = await apiFetch('/api/system/status')
        const data = await res.json()
        if (!cancelled && data.success && data.data) {
          syncServerClock(data.data)
        }
      } catch {
        /* ignore */
      }
    }

    void syncClock()
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    apiFetch('/api/config/deployment-mode')
      .then(res => res.json())
      .then(data => {
        if (data.success && data.data?.mode) {
          setDeployMode(data.data.mode)
          localStorage.setItem('vigilyx-deploy-mode', data.data.mode)
        }
      })
      .catch(() => {})
    // Listen for mode-switch events from the settings page
    const handler = (e: Event) => {
      const mode = (e as CustomEvent).detail
      if (mode === 'mirror' || mode === 'mta') setDeployMode(mode)
    }
    window.addEventListener(EVENTS.DEPLOY_MODE_CHANGED, handler)
    return () => window.removeEventListener(EVENTS.DEPLOY_MODE_CHANGED, handler)
  }, [])

  // Load initial stats
  const loadStats = useCallback(() => {
    apiFetch('/api/stats')
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          window.dispatchEvent(new CustomEvent(EVENTS.STATS_UPDATE, { detail: { stats: data.data } }))
        }
      })
      .catch(console.error)
  }, [])

  useEffect(() => {
    loadStats()
  }, [loadStats])

  // Listen for database-clear events and reload statistics
  useEffect(() => {
    const handler = () => loadStats()
    window.addEventListener(EVENTS.STATS_CLEARED, handler)
    return () => window.removeEventListener(EVENTS.STATS_CLEARED, handler)
  }, [loadStats])

  return (
    <div className="app">
      <RealtimeBridge mode="app" onConnectedChange={setConnected} refreshStats={loadStats} />
      <header className="hd">
        <div className="hd-inner">
          {/* ── Brand ── */}
          <Link to="/" className="hd-brand">
            <span className="hd-brand-name">Vigilyx</span>
            <span className="hd-brand-sep" />
            <span className="hd-brand-sub">{t('app.brand')}</span>
          </Link>

          {/* ── Nav ── */}
          <nav className="hd-nav">
            {/* Core features */}
            <NavLink to="/" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>}>{t('nav.dashboard')}</NavLink>
            <NavLink to="/emails" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>}>{t('nav.emails')}</NavLink>
            <NavLink to="/security" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>}>{t('nav.emailSecurity')}</NavLink>
            <NavLink to="/data-security" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>}>{t('nav.dataSecurity')}</NavLink>
            <NavLink to="/automation" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>}>{t('nav.automation')}</NavLink>
            <span className="hd-nav-sep" />
            {/* Supporting features */}
            <NavLink to="/knowledge" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>}>{t('nav.knowledge')}</NavLink>
            <NavLink to="/community" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>}>{t('nav.community')}</NavLink>
            <NavLink to="/logs" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>}>{t('nav.logs')}</NavLink>
            <NavLink to="/settings" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>}>{t('nav.settings')}</NavLink>
          </nav>

          {/* ── Right Controls ── */}
          <div className="hd-actions">
            <Link to="/settings" className="hd-deploy-badge" title={t('app.deployBadgeTitle')} onClick={() => window.dispatchEvent(new CustomEvent(EVENTS.NAVIGATE_SETTINGS, { detail: 'deployment' }))}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 12h4l3-9 4 18 3-9h6"/></svg>
              <span>{deployMode === 'mta' ? t('app.deployMta') : t('app.deployMirror')}</span>
            </Link>
            <SystemStatusBar />
            <div className={`hd-ws ${connected ? 'hd-ws--on' : 'hd-ws--off'}`} title={connected ? t('app.wsConnected') : t('app.wsOffline')}>
              <span className="hd-ws-dot" />
            </div>
            <ThemeToggle theme={theme} onToggle={toggleTheme} />
            <LanguageToggle />
            <button className="hd-logout" onClick={onLogout} title={t('app.logout')}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            </button>
          </div>
        </div>
      </header>

      <main className="main">
        <ChunkErrorBoundary><Suspense fallback={<div className="page-loading">{t('app.loading')}</div>}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/emails" element={<TrafficList />} />
            <Route path="/emails/:id" element={<EmailDetail />} />
            <Route path="/security" element={<Navigate to="/security/overview" replace />} />
            <Route path="/security/:tab" element={<EmailSecurity />} />
            <Route path="/data-security/*" element={<DataSecurity />} />
            <Route path="/automation" element={<AutomationDisposition />} />
            <Route path="/quarantine" element={<Quarantine />} />
            <Route path="/knowledge" element={<SecurityKnowledge />} />
            <Route path="/knowledge/:topicId" element={<SecurityKnowledge />} />
            <Route path="/community" element={<OpenSourceCommunity />} />
            <Route path="/logs" element={<EncryptedLogs />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense></ChunkErrorBoundary>
      </main>

      <footer className="footer">
        <p>{t('app.footer')}</p>
      </footer>
    </div>
  )
}

// ═══════════════════════════════════════════
// Portal simplified layout - data security + system settings only
// ═══════════════════════════════════════════
function PortalContent({ onLogout }: AppContentProps) {
  const { t } = useTranslation()
  const { theme, toggleTheme } = useTheme()
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    void syncUiPreferencesFromServer()
  }, [])

  useEffect(() => {
    let cancelled = false

    const syncClock = async () => {
      try {
        const res = await apiFetch('/api/system/status')
        const data = await res.json()
        if (!cancelled && data.success && data.data) {
          syncServerClock(data.data)
        }
      } catch {
        /* ignore */
      }
    }

    void syncClock()
    return () => { cancelled = true }
  }, [])

  return (
    <div className="app">
      <RealtimeBridge mode="portal" onConnectedChange={setConnected} />
      <header className="hd">
        <div className="hd-inner">
          <Link to="/portal" className="hd-brand">
            <span className="hd-brand-name">Vigilyx</span>
            <span className="hd-brand-sep" />
            <span className="hd-brand-sub">{t('app.brandPortal')}</span>
          </Link>

          <nav className="hd-nav">
            <NavLink to="/portal" activeMatch={p => p.startsWith('/portal') && !p.startsWith('/portal/settings')} icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>}>{t('nav.dataSecurity')}</NavLink>
            <NavLink to="/portal/settings" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>}>{t('nav.settings')}</NavLink>
          </nav>

          <div className="hd-actions">
            <SystemStatusBar />
            <div className={`hd-ws ${connected ? 'hd-ws--on' : 'hd-ws--off'}`} title={connected ? t('app.wsConnected') : t('app.wsOffline')}>
              <span className="hd-ws-dot" />
            </div>
            <ThemeToggle theme={theme} onToggle={toggleTheme} />
            <LanguageToggle />
            <button className="hd-logout" onClick={onLogout} title={t('app.logout')}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            </button>
          </div>
        </div>
      </header>

      <main className="main">
        <ChunkErrorBoundary><Suspense fallback={<div className="page-loading">{t('app.loading')}</div>}>
          <Routes>
            <Route path="/portal/settings" element={<Settings />} />
            <Route path="/portal/*" element={<DataSecurity />} />
          </Routes>
        </Suspense></ChunkErrorBoundary>
      </main>

      <footer className="footer">
        <p>{t('app.footerPortal')}</p>
      </footer>
    </div>
  )
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [needsSetup, setNeedsSetup] = useState(false)
  const [authReady, setAuthReady] = useState(false)
  const [portalMode, setPortalMode] = useState(false)

  // Validate the cookie session through /api/auth/me on page load instead of checking a localStorage token
  useEffect(() => {
    let cancelled = false

    const restoreSession = async () => {
      try {
        const res = await fetch('/api/auth/me', { credentials: 'same-origin' })
        if (!res.ok) {
          if (!cancelled) setAuthReady(true)
          return
        }

        resetLogoutFlag()
        if (!cancelled) setIsAuthenticated(true)

        const completed = await resolveSetupStatus()
        if (!cancelled) setNeedsSetup(!completed)
      } catch {
        // Network error or missing cookie -> treat as logged out
      } finally {
        if (!cancelled) setAuthReady(true)
      }
    }

    void restoreSession()
    return () => { cancelled = true }
  }, [])

  // Periodically validate cookie-session freshness instead of decoding JWT expiry in the frontend
  useEffect(() => {
    if (!isAuthenticated) return
    const interval = setInterval(async () => {
      try {
        const res = await fetch('/api/auth/me', { credentials: 'same-origin' })
        if (!res.ok) {
          setIsAuthenticated(false)
          setNeedsSetup(false)
        }
      } catch {
        // Do not log out on network errors; wait for the next retry
      }
    }, 300_000) // Check every 5 minutes (cookie expiration is controlled by the server)
    return () => clearInterval(interval)
  }, [isAuthenticated])

  useEffect(() => {
    const onAuthLogout = () => {
      // Server-side cookie clearing is handled by /api/auth/logout; only update frontend state here
      setIsAuthenticated(false)
      setNeedsSetup(false)
      setAuthReady(true)
    }
    window.addEventListener('auth:logout', onAuthLogout)
    return () => window.removeEventListener('auth:logout', onAuthLogout)
  }, [])

  // After login, fetch the portal_mode flag from the deployment-mode endpoint
  useEffect(() => {
    if (!isAuthenticated) return
    apiFetch('/api/config/deployment-mode')
      .then(res => res.json())
      .then(data => {
        if (data.success && data.data) {
          setPortalMode(!!data.data.portal_mode)
        }
      })
      .catch(() => {})
  }, [isAuthenticated])

  const handleLogin = async () => {
    resetLogoutFlag()
    setIsAuthenticated(true)
    setNeedsSetup(false)
    setAuthReady(false)

    try {
      const completed = await resolveSetupStatus()
      setNeedsSetup(!completed)
    } catch (error) {
      console.error('Failed to load setup status after login:', error)
      setNeedsSetup(false)
    } finally {
      setAuthReady(true)
    }
  }

  const handleLogout = async () => {
    // Ask the backend to clear the HttpOnly cookie
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
    } catch {
      // Continue logging out on the frontend even if the request fails
    }
    setIsAuthenticated(false)
    setNeedsSetup(false)
    setAuthReady(true)
  }

  if (!authReady) {
    return <div className="page-loading">{i18n.t('app.checkingInit')}</div>
  }

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />
  }

  if (needsSetup) {
    return <SetupWizard onComplete={() => setNeedsSetup(false)} />
  }

  return (
    <BrowserRouter>
      <PortalOrApp onLogout={handleLogout} portalMode={portalMode} />
    </BrowserRouter>
  )
}

// Choose the layout from the backend portal_mode flag or the URL prefix
// When portal_mode=true, redirect every non-/portal route to /portal
function PortalOrApp({ onLogout, portalMode }: AppContentProps & { portalMode: boolean }) {
  const location = useLocation()
  if (portalMode && !location.pathname.startsWith('/portal')) {
    return <Navigate to="/portal" replace />
  }
  if (location.pathname.startsWith('/portal')) {
    return <PortalContent onLogout={onLogout} />
  }
  return <AppContent onLogout={onLogout} />
}

export default App
