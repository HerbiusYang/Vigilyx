import { useState, useEffect, useCallback } from 'react'
import { loadCachedUiPreferences, saveUiPreferencesPatch } from '../utils/uiPreferences'

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
    window.addEventListener('vigilyx:ui-preferences-changed', onPreferencesChanged)
    return () => window.removeEventListener('vigilyx:ui-preferences-changed', onPreferencesChanged)
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
