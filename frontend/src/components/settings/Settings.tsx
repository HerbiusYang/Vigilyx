import { useState, useEffect, useCallback } from 'react'
import { apiFetch } from '../../utils/api'

import AppearanceSettings from './AppearanceSettings'
import NotificationSettings from './NotificationSettings'
import SyslogSettings from './SyslogSettings'
import ThreatIntelSettings from './ThreatIntelSettings'
import CaptureSettings from './CaptureSettings'
import DatabaseSettings from './DatabaseSettings'
import DataSecuritySettings from './DataSecuritySettings'
import DeploymentSettings from './DeploymentSettings'
import AccountSettings from './AccountSettings'
import TrainingSettings from './TrainingSettings'
import AboutSettings from './AboutSettings'

type SettingsTab = 'appearance' | 'notification' | 'capture' | 'data_security' | 'syslog' | 'threat_intel' | 'deployment' | 'database' | 'training' | 'account' | 'about'

const TABS: { key: SettingsTab; label: string; desc: string; icon: JSX.Element }[] = [
  {
    key: 'appearance',
    label: '外观设置',
    desc: '主题与强调色',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
      </svg>
    ),
  },
  {
    key: 'notification',
    label: '通知提醒',
    desc: '告警与推送',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>
      </svg>
    ),
  },
  {
    key: 'capture',
    label: '显示设置',
    desc: '协议与流量规则',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
      </svg>
    ),
  },
  {
    key: 'data_security' as SettingsTab,
    label: '数据安全',
    desc: 'HTTP 流量监控',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>
      </svg>
    ),
  },
  {
    key: 'syslog' as SettingsTab,
    label: 'Syslog',
    desc: '事件外发转发',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>
      </svg>
    ),
  },
  {
    key: 'threat_intel' as SettingsTab,
    label: '威胁情报',
    desc: 'IP / 域名 / 哈希查询',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
        <line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/>
      </svg>
    ),
  },
  {
    key: 'deployment',
    label: '部署模式',
    desc: '运行模式与网卡',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>
      </svg>
    ),
  },
  {
    key: 'database',
    label: '数据库管理',
    desc: '清理与轮转',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
      </svg>
    ),
  },
  {
    key: 'training',
    label: '模型训练',
    desc: 'NLP 五分类训练',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>
      </svg>
    ),
  },
  {
    key: 'account',
    label: '账户安全',
    desc: '密码与会话',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    ),
  },
  {
    key: 'about',
    label: '关于系统',
    desc: '版本与状态',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
      </svg>
    ),
  },
]

const VALID_TABS = new Set<string>(['appearance','notification','capture','data_security','syslog','threat_intel','deployment','database','training','account','about'])

function Settings() {
  const [activeTab, setActiveTab] = useState<SettingsTab>(() => {
    const h = window.location.hash.replace('#', '')
    return VALID_TABS.has(h) ? h as SettingsTab : 'appearance'
  })

  const [apiVersion, setApiVersion] = useState('0.9.0')

  const changeTab = useCallback((tab: SettingsTab) => {
    setActiveTab(tab)
    window.history.replaceState(null, '', `${window.location.pathname}#${tab}`)
  }, [])

  useEffect(() => {
    const handler = (e: Event) => {
      const tab = (e as CustomEvent).detail as SettingsTab
      if (tab) changeTab(tab)
    }
    window.addEventListener('vigilyx:navigate-settings', handler)
    return () => window.removeEventListener('vigilyx:navigate-settings', handler)
  }, [changeTab])

  useEffect(() => {
    const handler = () => {
      const h = window.location.hash.replace('#', '')
      if (VALID_TABS.has(h)) setActiveTab(h as SettingsTab)
    }
    window.addEventListener('popstate', handler)
    return () => window.removeEventListener('popstate', handler)
  }, [])

  // Fetch API version for sidebar footer
  useEffect(() => {
    apiFetch('/api/system/info')
      .then(r => r.json())
      .then(d => { if (d.success && d.data?.api_version) setApiVersion(d.data.api_version) })
      .catch(() => {})
  }, [])

  const renderContent = () => {
    switch (activeTab) {
      case 'appearance': return <AppearanceSettings />
      case 'notification': return <NotificationSettings />
      case 'capture': return <CaptureSettings />
      case 'data_security': return <DataSecuritySettings />
      case 'syslog': return <SyslogSettings />
      case 'threat_intel': return <ThreatIntelSettings />
      case 'deployment': return <DeploymentSettings />
      case 'database': return <DatabaseSettings />
      case 'training': return <TrainingSettings />
      case 'account': return <AccountSettings />
      case 'about': return <AboutSettings />
    }
  }

  return (
    <div className="s-page">
      <aside className="s-sidebar">
        <div className="s-sidebar-header">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
          </svg>
          <span>设置</span>
        </div>
        <nav className="s-sidebar-nav">
          {TABS.map(tab => (
            <button
              key={tab.key}
              className={`s-sidebar-item ${activeTab === tab.key ? 'active' : ''}`}
              onClick={() => changeTab(tab.key)}
            >
              <div className="s-sidebar-icon">{tab.icon}</div>
              <div className="s-sidebar-text">
                <span className="s-sidebar-label">{tab.label}</span>
                <span className="s-sidebar-desc">{tab.desc}</span>
              </div>
            </button>
          ))}
        </nav>
        <div className="s-sidebar-footer">
          <span>Vigilyx v{apiVersion}</span>
        </div>
      </aside>

      <main className="s-main">
        {renderContent()}
      </main>
    </div>
  )
}

export default Settings
