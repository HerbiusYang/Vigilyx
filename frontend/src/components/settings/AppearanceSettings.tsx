import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { loadCachedUiPreferences, saveUiPreferencesPatch, syncUiPreferencesFromServer, type AccentColor } from '../../utils/uiPreferences'

const ACCENT_COLORS = [
  { key: 'cyan', color: '#22d3ee', labelKey: 'settings.accentCyan' },
  { key: 'blue', color: '#3b82f6', labelKey: 'settings.accentBlue' },
  { key: 'purple', color: '#a855f7', labelKey: 'settings.accentPurple' },
  { key: 'green', color: '#22c55e', labelKey: 'settings.accentGreen' },
  { key: 'amber', color: '#f59e0b', labelKey: 'settings.accentAmber' },
  { key: 'rose', color: '#f43f5e', labelKey: 'settings.accentRose' },
]

export default function AppearanceSettings() {
  const { t } = useTranslation()
  const cached = loadCachedUiPreferences()
  const [theme, setTheme] = useState<'dark' | 'light'>(cached.appearance.theme)
  const [accentColor, setAccentColor] = useState<AccentColor>(cached.appearance.accent)

  useEffect(() => {
    syncUiPreferencesFromServer()
      .then(prefs => {
        setTheme(prefs.appearance.theme)
        setAccentColor(prefs.appearance.accent)
      })
      .catch(() => {})
  }, [])

  const handleThemeChange = (newTheme: 'dark' | 'light') => {
    setTheme(newTheme)
    void saveUiPreferencesPatch({ appearance: { theme: newTheme } }).catch(() => {})
  }

  const handleAccentChange = (key: AccentColor) => {
    setAccentColor(key)
    void saveUiPreferencesPatch({ appearance: { accent: key } }).catch(() => {})
  }

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon appearance">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
          </span>
          {t('settings.appearance')}
        </h2>
        <p className="s-section-subtitle">{t('settings.appearanceSubtitle')}</p>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.themeMode')}</div>
        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">{t('settings.interfaceTheme')}</span>
            <span className="s-setting-desc">{t('settings.interfaceThemeDesc')}</span>
          </div>
          <div className="s-theme-switcher">
            <button
              className={`s-theme-btn ${theme === 'dark' ? 'active' : ''}`}
              onClick={() => handleThemeChange('dark')}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
              {t('settings.dark')}
            </button>
            <button
              className={`s-theme-btn ${theme === 'light' ? 'active' : ''}`}
              onClick={() => handleThemeChange('light')}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/></svg>
              {t('settings.light')}
            </button>
          </div>
        </div>
      </div>

      <div className="s-setting-group">
        <div className="s-setting-group-header">{t('settings.personalization')}</div>
        <div className="s-setting-row">
          <div className="s-setting-info">
            <span className="s-setting-label">{t('settings.accentColor')}</span>
            <span className="s-setting-desc">{t('settings.accentColorDesc')}</span>
          </div>
          <div className="s-color-picker">
            {ACCENT_COLORS.map(c => (
              <button
                key={c.key}
                className={`s-color-dot ${accentColor === c.key ? 'active' : ''}`}
                style={{ '--dot-color': c.color } as React.CSSProperties}
                onClick={() => handleAccentChange(c.key as AccentColor)}
                title={t(c.labelKey)}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
