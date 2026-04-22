import { useState, useEffect, useCallback } from 'react'
import { loadCachedUiPreferences, saveUiPreferencesPatch } from '../utils/uiPreferences'
import { EVENTS } from '../utils/events'

type Theme = 'dark' | 'light'

// Apply the theme immediately on module load to avoid page flicker
const savedTheme = loadCachedUiPreferences().appearance.theme as Theme
document.documentElement.setAttribute('data-theme', savedTheme)

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(savedTheme)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  useEffect(() => {
    const onPreferencesChanged = (event: Event) => {
      const nextTheme = (event as CustomEvent).detail?.appearance?.theme
      if (nextTheme === 'dark' || nextTheme === 'light') {
        setThemeState(nextTheme)
      }
    }
    window.addEventListener(EVENTS.UI_PREFERENCES_CHANGED, onPreferencesChanged)
    return () => window.removeEventListener(EVENTS.UI_PREFERENCES_CHANGED, onPreferencesChanged)
  }, [])

  const toggleTheme = useCallback(() => {
    setThemeState(prev => {
      const next = prev === 'dark' ? 'light' : 'dark'
      void saveUiPreferencesPatch({ appearance: { theme: next } }).catch(() => {})
      return next
    })
  }, [])

  return { theme, toggleTheme } as const
}
