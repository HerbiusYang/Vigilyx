import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { loadCachedUiPreferences, saveUiPreferencesPatch, syncUiPreferencesFromServer } from '../../utils/uiPreferences'

export default function NotificationSettings() {
  const { t } = useTranslation()
  const cached = loadCachedUiPreferences()
  const [soundEnabled, setSoundEnabled] = useState(cached.notifications.sound_enabled)
  const [desktopNotify, setDesktopNotify] = useState(cached.notifications.desktop_notify)
  const [emailAlertThreshold, setEmailAlertThreshold] = useState(cached.notifications.alert_threshold)
  const hydratedRef = useRef(false)

  useEffect(() => {
    syncUiPreferencesFromServer()
      .then(prefs => {
        setSoundEnabled(prefs.notifications.sound_enabled)
        setDesktopNotify(prefs.notifications.desktop_notify)
        setEmailAlertThreshold(prefs.notifications.alert_threshold)
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
        notifications: {
          sound_enabled: soundEnabled,
          desktop_notify: desktopNotify,
          alert_threshold: emailAlertThreshold,
        },
      }).catch(() => {})
    }, 250)
    return () => window.clearTimeout(timer)
  }, [soundEnabled, desktopNotify, emailAlertThreshold])

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon notification">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
          </span>
          {t('settings.notifications')}
        </h2>
        <p className="s-section-subtitle">{t('settings.notificationsSubtitle')}</p>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.notificationMethods')}</div>
        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="s-setting-label-icon"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"/></svg>
              {t('settings.soundEffect')}
            </span>
            <span className="s-setting-desc">{t('settings.soundEffectDesc')}</span>
          </div>
          <label className="s-toggle">
            <input type="checkbox" checked={soundEnabled} onChange={e => setSoundEnabled(e.target.checked)} />
            <span className="s-toggle-slider" />
          </label>
        </div>

        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="s-setting-label-icon"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
              {t('settings.desktopNotify')}
            </span>
            <span className="s-setting-desc">{t('settings.desktopNotifyDesc')}</span>
          </div>
          <label className="s-toggle">
            <input type="checkbox" checked={desktopNotify} onChange={e => {
              if (e.target.checked && 'Notification' in window) {
                Notification.requestPermission().then(p => {
                  setDesktopNotify(p === 'granted')
                })
              } else {
                setDesktopNotify(e.target.checked)
              }
            }} />
            <span className="s-toggle-slider" />
          </label>
        </div>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.alertRules')}</div>
        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="s-setting-label-icon"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              {t('settings.trafficAlertThreshold')}
            </span>
            <span className="s-setting-desc">{t('settings.trafficAlertThresholdDesc')}</span>
          </div>
          <div className="s-number-input">
            <button onClick={() => setEmailAlertThreshold(v => Math.max(10, v - 10))}>-</button>
            <span>{emailAlertThreshold}</span>
            <button onClick={() => setEmailAlertThreshold(v => Math.min(10000, v + 10))}>+</button>
          </div>
        </div>
      </div>

    </div>
  )
}
