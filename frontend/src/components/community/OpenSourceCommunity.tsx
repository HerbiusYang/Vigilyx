import { useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'

type TabKey = 'mission' | 'roadmap' | 'finance' | 'intel'

export default function OpenSourceCommunity() {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState<TabKey>('mission')

  const TABS: { key: TabKey; label: string; icon: JSX.Element }[] = useMemo(() => [
    { key: 'mission', label: t('community.tabMission'), icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg> },
    { key: 'roadmap', label: t('community.tabRoadmap'), icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> },
    { key: 'finance', label: t('community.tabFinance'), icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg> },
    { key: 'intel', label: t('community.tabIntel'), icon: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> },
  ], [t])

  const OPEN_SOURCE_ROADMAP: { phase: string; title: string; status: 'done' | 'current' | 'planned'; date: string; items: string[] }[] = useMemo(() => [
    { phase: 'v0.9.0', title: t('community.ossRoadmapCoreEngineTitle'), status: 'current' as const, date: '2026 Q1',
      items: [t('community.ossRoadmapCoreItem1'), t('community.ossRoadmapCoreItem2'), t('community.ossRoadmapCoreItem3'), t('community.ossRoadmapCoreItem4'), t('community.ossRoadmapCoreItem5')] },
    { phase: 'v1.0.0', title: t('community.ossRoadmapReleaseTitle'), status: 'planned' as const, date: '2026 Q2',
      items: [t('community.ossRoadmapReleaseItem1'), t('community.ossRoadmapReleaseItem2'), t('community.ossRoadmapReleaseItem3'), t('community.ossRoadmapReleaseItem4')] },
    { phase: 'v1.x.x', title: t('community.ossRoadmapIntelTitle'), status: 'planned' as const, date: '2026 Q3',
      items: [t('community.ossRoadmapIntelItem1'), t('community.ossRoadmapIntelItem2'), t('community.ossRoadmapIntelItem3'), t('community.ossRoadmapIntelItem4')] },
  ], [t])

  const COMMERCIAL_ROADMAP = useMemo(() => [
    { phase: 'Pro', title: t('community.bizRoadmapAiTitle'), status: 'planned' as const, date: t('community.bizRoadmapDateTbd'),
      items: [t('community.bizRoadmapAiItem1'), t('community.bizRoadmapAiItem2'), t('community.bizRoadmapAiItem3'), t('community.bizRoadmapAiItem4')] },
    { phase: 'Enterprise', title: t('community.bizRoadmapEnterpriseTitle'), status: 'planned' as const, date: t('community.bizRoadmapDateTbd'),
      items: [t('community.bizRoadmapEnterpriseItem1'), t('community.bizRoadmapEnterpriseItem2'), t('community.bizRoadmapEnterpriseItem3'), t('community.bizRoadmapEnterpriseItem4')] },
    { phase: 'Cloud', title: t('community.bizRoadmapCloudTitle'), status: 'planned' as const, date: t('community.bizRoadmapDateTbd'),
      items: [t('community.bizRoadmapCloudItem1'), t('community.bizRoadmapCloudItem2'), t('community.bizRoadmapCloudItem3'), t('community.bizRoadmapCloudItem4')] },
  ], [t])

  const FINANCE_ITEMS = useMemo(() => [
    { category: t('community.finCategoryCharity'), pct: 80, items: [t('community.finCharityItem1'), t('community.finCharityItem2'), t('community.finCharityItem3'), t('community.finCharityItem4')], color: '#10b981', icon: '💚' },
    { category: t('community.finCategoryDev'), pct: 10, items: [t('community.finDevItem1'), t('community.finDevItem2'), t('community.finDevItem3'), t('community.finDevItem4')], color: '#3b82f6', icon: '⚡' },
    { category: t('community.finCategoryTeam'), pct: 10, items: [t('community.finTeamItem1'), t('community.finTeamItem2'), t('community.finTeamItem3')], color: '#a855f7', icon: '🤝' },
  ], [t])

  const INTEL_FEEDS = useMemo(() => [
    { name: t('community.intelFeedIocName'), type: 'STIX/TAXII', desc: t('community.intelFeedIocDesc'), status: 'planned', subscribers: 0 },
    { name: t('community.intelFeedYaraName'), type: 'YARA Rules', desc: t('community.intelFeedYaraDesc'), status: 'planned', subscribers: 0 },
    { name: t('community.intelFeedSamplesName'), type: 'Samples', desc: t('community.intelFeedSamplesDesc'), status: 'planned', subscribers: 0 },
    { name: t('community.intelFeedReportsName'), type: 'Reports', desc: t('community.intelFeedReportsDesc'), status: 'planned', subscribers: 0 },
  ], [t])

  return (
    <div className="osc-page">
      {/* -- Page header -- */}
      <div className="osc-hero">
        <div className="osc-hero-content">
          <div className="osc-hero-badge">OPEN SOURCE</div>
          <h1 className="osc-hero-title">{t('community.heroTitle')}</h1>
          <p className="osc-hero-desc">
            {t('community.heroDesc1')}
            <br />
            {t('community.heroDesc2')}
          </p>
          <div className="osc-hero-stats">
            <div className="osc-hero-stat">
              <span className="osc-hero-stat-val">20</span>
              <span className="osc-hero-stat-lbl">{t('community.heroStatModules')}</span>
            </div>
            <div className="osc-hero-stat-sep" />
            <div className="osc-hero-stat">
              <span className="osc-hero-stat-val">58</span>
              <span className="osc-hero-stat-lbl">{t('community.heroStatYara')}</span>
            </div>
            <div className="osc-hero-stat-sep" />
            <div className="osc-hero-stat">
              <span className="osc-hero-stat-val">AGPL-3.0</span>
              <span className="osc-hero-stat-lbl">{t('community.heroStatLicense')}</span>
            </div>
          </div>
        </div>
      </div>

      {/* -- Tab navigation -- */}
      <div className="osc-tabs">
        {TABS.map(tab => (
          <button key={tab.key} className={`osc-tab ${activeTab === tab.key ? 'osc-tab--active' : ''}`} onClick={() => setActiveTab(tab.key)}>
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* -- Open-source mission -- */}
      {activeTab === 'mission' && (
        <div className="osc-section osc-fade-in">
          <div className="osc-mission-grid">
            {[
              { title: t('community.missionEquityTitle'), desc: t('community.missionEquityDesc'), icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>, color: '#3b82f6' },
              { title: t('community.missionCollabTitle'), desc: t('community.missionCollabDesc'), icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>, color: '#10b981' },
              { title: t('community.missionTransTitle'), desc: t('community.missionTransDesc'), icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>, color: '#f59e0b' },
              { title: t('community.missionEvolveTitle'), desc: t('community.missionEvolveDesc'), icon: <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>, color: '#a855f7' },
            ].map((item, i) => (
              <div key={i} className="osc-mission-card" style={{ '--osc-color': item.color } as React.CSSProperties}>
                <div className="osc-mission-icon" style={{ color: item.color }}>{item.icon}</div>
                <h3 className="osc-mission-title">{item.title}</h3>
                <p className="osc-mission-desc">{item.desc}</p>
              </div>
            ))}
          </div>

          <div className="osc-cta-row">
            <a className="osc-cta-card" href="https://github.com/HerbiusYang/Vigilyx" target="_blank" rel="noopener noreferrer">
              <div className="osc-cta-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
              </div>
              <div>
                <div className="osc-cta-title">{t('community.ctaGithubTitle')}</div>
                <div className="osc-cta-desc">{t('community.ctaGithubDesc')}</div>
              </div>
              <span className="osc-cta-badge osc-cta-badge--live">{t('community.ctaBadgeLive')}</span>
            </a>
            <a className="osc-cta-card" href="https://gitee.com/DoHeras/vigilyx" target="_blank" rel="noopener noreferrer">
              <div className="osc-cta-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 2C6.48 2 2 6.48 2 12c0 4.42 2.87 8.17 6.84 9.5.5.08.66-.23.66-.5v-1.69C6.73 19.91 6.14 18 6.14 18c-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.87 1.52 2.34 1.07 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.93 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02A9.56 9.56 0 0 1 12 6.8c.85.004 1.7.115 2.5.337 1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.75c0 .27.16.59.67.5A10.003 10.003 0 0 0 22 12c0-5.52-4.48-10-10-10z"/></svg>
              </div>
              <div>
                <div className="osc-cta-title">{t('community.ctaGiteeTitle')}</div>
                <div className="osc-cta-desc">{t('community.ctaGiteeDesc')}</div>
              </div>
              <span className="osc-cta-badge osc-cta-badge--live">{t('community.ctaBadgeLive')}</span>
            </a>
          </div>
        </div>
      )}

      {/* -- Roadmap -- */}
      {activeTab === 'roadmap' && (
        <div className="osc-section osc-fade-in">
          <div className="osc-roadmap-dual">
            {/* Open-source track */}
            <div className="osc-track">
              <div className="osc-track-header osc-track-header--oss">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                <span className="osc-track-label">{t('community.trackOss')}</span>
                <span className="osc-track-badge osc-track-badge--oss">FREE & OPEN</span>
              </div>
              <div className="osc-track-body">
                {OPEN_SOURCE_ROADMAP.map((m, i) => (
                  <div key={i} className={`osc-rm-card osc-rm-card--${m.status}`} style={{ '--rm-color': m.status === 'done' ? '#10b981' : m.status === 'current' ? '#3b82f6' : 'var(--text-tertiary)' } as React.CSSProperties}>
                    <div className="osc-rm-card-top">
                      <span className="osc-rm-phase">{m.phase}</span>
                      <span className="osc-rm-date">{m.date}</span>
                      <span className={`osc-rm-status osc-rm-status--${m.status}`}>
                        {m.status === 'done' ? t('community.statusDone') : m.status === 'current' ? t('community.statusCurrent') : t('community.statusPlanned')}
                      </span>
                    </div>
                    <h4 className="osc-rm-title">{m.title}</h4>
                    <ul className="osc-rm-list">
                      {m.items.map((item, j) => (
                        <li key={j}>
                          {m.status === 'done' ? (
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                          ) : m.status === 'current' ? (
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2"><circle cx="12" cy="12" r="5" fill="#3b82f6" fillOpacity="0.15"/></svg>
                          ) : (
                            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2"><circle cx="12" cy="12" r="4"/></svg>
                          )}
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>

            {/* Commercial track */}
            <div className="osc-track">
              <div className="osc-track-header osc-track-header--biz">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
                <span className="osc-track-label">{t('community.trackBiz')}</span>
                <span className="osc-track-badge osc-track-badge--biz">PRO / ENTERPRISE</span>
              </div>
              <div className="osc-track-body">
                {COMMERCIAL_ROADMAP.map((m, i) => (
                  <div key={i} className={`osc-rm-card osc-rm-card--planned`} style={{ '--rm-color': 'var(--text-tertiary)' } as React.CSSProperties}>
                    <div className="osc-rm-card-top">
                      <span className="osc-rm-phase">{m.phase}</span>
                      <span className="osc-rm-date">{m.date}</span>
                      <span className="osc-rm-status osc-rm-status--planned">{t('community.statusPlanning')}</span>
                    </div>
                    <h4 className="osc-rm-title">{m.title}</h4>
                    <ul className="osc-rm-list">
                      {m.items.map((item, j) => (
                        <li key={j}>
                          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="2"><circle cx="12" cy="12" r="4"/></svg>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* -- Funding breakdown -- */}
      {activeTab === 'finance' && (
        <div className="osc-section osc-fade-in">
          <div className="osc-finance-notice">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
            <span>{t('community.finNotice')}</span>
          </div>

          {/* Allocation-ratio visualization */}
          <div className="osc-finance-bar">
            {FINANCE_ITEMS.map((item, i) => (
              <div key={i} className="osc-finance-bar-seg" style={{ flex: item.pct, background: item.color }} title={`${item.category} ${item.pct}%`} />
            ))}
          </div>
          <div className="osc-finance-bar-labels">
            {FINANCE_ITEMS.map((item, i) => (
              <span key={i} style={{ flex: item.pct, color: item.color, textAlign: 'center', fontSize: 10, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{item.pct}%</span>
            ))}
          </div>

          <div className="osc-finance-cards">
            {FINANCE_ITEMS.map((item, i) => (
              <div key={i} className="osc-finance-card" style={{ '--osc-color': item.color } as React.CSSProperties}>
                <div className="osc-finance-card-head">
                  <span className="osc-finance-emoji">{item.icon}</span>
                  <div className="osc-finance-card-title">
                    <span className="osc-finance-cat">{item.category}</span>
                    <span className="osc-finance-pct" style={{ color: item.color }}>{item.pct}%</span>
                  </div>
                </div>
                <ul className="osc-finance-list">
                  {item.items.map((sub, j) => (
                    <li key={j} className="osc-finance-list-item">
                      <span className="osc-finance-bullet" style={{ background: item.color }} />
                      {sub}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <div className="osc-finance-footer">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-tertiary)" strokeWidth="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>{t('community.finFooter')}</span>
          </div>
        </div>
      )}

      {/* -- Shared intel -- */}
      {activeTab === 'intel' && (
        <div className="osc-section osc-fade-in">
          <div className="osc-intel-intro">
            <h3>{t('community.intelIntroTitle')}</h3>
            <p>{t('community.intelIntroDesc')}</p>
          </div>

          <div className="osc-intel-grid">
            {INTEL_FEEDS.map((feed, i) => (
              <div key={i} className="osc-intel-card">
                <div className="osc-intel-card-head">
                  <span className="osc-intel-name">{feed.name}</span>
                  <span className={`osc-intel-status osc-intel-status--${feed.status}`}>
                    {feed.status === 'active' ? t('community.intelStatusActive') : feed.status === 'beta' ? t('community.intelStatusBeta') : t('community.statusPlanned')}
                  </span>
                </div>
                <span className="osc-intel-type">{feed.type}</span>
                <p className="osc-intel-desc">{feed.desc}</p>
                <div className="osc-intel-footer">
                  <span className="osc-intel-sub">
                    {feed.status === 'planned' ? t('community.intelComingSoon') : t('community.intelSubscribers', { count: feed.subscribers })}
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className="osc-intel-tlp">
            <h4 className="osc-intel-tlp-title">{t('community.tlpTitle')}</h4>
            <div className="osc-intel-tlp-grid">
              {[
                { color: '#dc2626', label: 'TLP:RED', desc: t('community.tlpRedDesc') },
                { color: '#f59e0b', label: 'TLP:AMBER', desc: t('community.tlpAmberDesc') },
                { color: '#10b981', label: 'TLP:GREEN', desc: t('community.tlpGreenDesc') },
                { color: '#e2e8f0', label: 'TLP:CLEAR', desc: t('community.tlpClearDesc') },
              ].map((tlp, i) => (
                <div key={i} className="osc-intel-tlp-item">
                  <span className="osc-intel-tlp-dot" style={{ background: tlp.color }} />
                  <span className="osc-intel-tlp-label">{tlp.label}</span>
                  <span className="osc-intel-tlp-desc">{tlp.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
