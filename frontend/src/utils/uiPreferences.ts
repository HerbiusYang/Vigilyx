import { apiFetch } from './api'

export type ThemeMode = 'dark' | 'light'
export type AccentColor = 'cyan' | 'blue' | 'purple' | 'green' | 'amber' | 'rose'

export interface UiPreferences {
  appearance: {
    theme: ThemeMode
    accent: AccentColor
  }
  notifications: {
    sound_enabled: boolean
    desktop_notify: boolean
    alert_threshold: number
  }
  capture: {
    smtp: boolean
    pop3: boolean
    imap: boolean
    auto_restore: boolean
    max_packet_size: number
    inbound_src: string[]
    inbound_dst: string[]
    outbound_src: string[]
    outbound_dst: string[]
  }
  about: {
    ntp_servers: string
    ntp_interval_minutes: number
  }
}

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends (infer U)[]
    ? U[]
    : T[K] extends object
      ? DeepPartial<T[K]>
      : T[K]
}

const UI_PREFERENCES_CACHE_KEY = 'vigilyx-ui-preferences-cache'

const ACCENT_COLORS: Record<AccentColor, string> = {
  cyan: '#22d3ee',
  blue: '#3b82f6',
  purple: '#a855f7',
  green: '#22c55e',
  amber: '#f59e0b',
  rose: '#f43f5e',
}

const DEFAULT_UI_PREFERENCES: UiPreferences = {
  appearance: {
    theme: 'dark',
    accent: 'cyan',
  },
  notifications: {
    sound_enabled: true,
    desktop_notify: false,
    alert_threshold: 100,
  },
  capture: {
    smtp: true,
    pop3: true,
    imap: true,
    auto_restore: true,
    max_packet_size: 65535,
    inbound_src: [],
    inbound_dst: [],
    outbound_src: [],
    outbound_dst: [],
  },
  about: {
    ntp_servers: 'ntp.aliyun.com',
    ntp_interval_minutes: 60,
  },
}

function cloneDefaults(): UiPreferences {
  return JSON.parse(JSON.stringify(DEFAULT_UI_PREFERENCES)) as UiPreferences
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function normalizeBool(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback
}

function normalizeNumber(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || Number.isNaN(value)) return fallback
  return Math.min(max, Math.max(min, Math.round(value)))
}

function normalizeIpList(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  const seen = new Set<string>()
  const ips: string[] = []
  value.forEach(item => {
    if (typeof item !== 'string') return
    const trimmed = item.trim()
    if (!trimmed) return
    if (!seen.has(trimmed)) {
      seen.add(trimmed)
      ips.push(trimmed)
    }
  })
  return ips
}

export function normalizeUiPreferences(input: unknown): UiPreferences {
  const defaults = cloneDefaults()
  if (!isObject(input)) return defaults

  const appearance = isObject(input.appearance) ? input.appearance : {}
  const notifications = isObject(input.notifications) ? input.notifications : {}
  const capture = isObject(input.capture) ? input.capture : {}
  const about = isObject(input.about) ? input.about : {}

  const theme = appearance.theme === 'light' ? 'light' : 'dark'
  const accent = typeof appearance.accent === 'string' && appearance.accent in ACCENT_COLORS
    ? appearance.accent as AccentColor
    : defaults.appearance.accent

  return {
    appearance: {
      theme,
      accent,
    },
    notifications: {
      sound_enabled: normalizeBool(notifications.sound_enabled, defaults.notifications.sound_enabled),
      desktop_notify: normalizeBool(notifications.desktop_notify, defaults.notifications.desktop_notify),
      alert_threshold: normalizeNumber(notifications.alert_threshold, defaults.notifications.alert_threshold, 10, 10000),
    },
    capture: {
      smtp: normalizeBool(capture.smtp, defaults.capture.smtp),
      pop3: normalizeBool(capture.pop3, defaults.capture.pop3),
      imap: normalizeBool(capture.imap, defaults.capture.imap),
      auto_restore: normalizeBool(capture.auto_restore, defaults.capture.auto_restore),
      max_packet_size: normalizeNumber(capture.max_packet_size, defaults.capture.max_packet_size, 512, 262144),
      inbound_src: normalizeIpList(capture.inbound_src),
      inbound_dst: normalizeIpList(capture.inbound_dst),
      outbound_src: normalizeIpList(capture.outbound_src),
      outbound_dst: normalizeIpList(capture.outbound_dst),
    },
    about: {
      ntp_servers: typeof about.ntp_servers === 'string' && about.ntp_servers.trim()
        ? about.ntp_servers.trim()
        : defaults.about.ntp_servers,
      ntp_interval_minutes: normalizeNumber(
        about.ntp_interval_minutes,
        defaults.about.ntp_interval_minutes,
        1,
        1440,
      ),
    },
  }
}

function readLegacyUiPreferences(): UiPreferences {
  return normalizeUiPreferences({
    appearance: {
      theme: localStorage.getItem('vigilyx-theme') || DEFAULT_UI_PREFERENCES.appearance.theme,
      accent: localStorage.getItem('vigilyx-accent') || DEFAULT_UI_PREFERENCES.appearance.accent,
    },
    notifications: {
      sound_enabled: localStorage.getItem('vigilyx-sound') !== 'false',
      desktop_notify: localStorage.getItem('vigilyx-desktop-notify') === 'true',
      alert_threshold: Number(localStorage.getItem('vigilyx-alert-threshold') || DEFAULT_UI_PREFERENCES.notifications.alert_threshold),
    },
    capture: {
      smtp: localStorage.getItem('vigilyx-capture-smtp') !== 'false',
      pop3: localStorage.getItem('vigilyx-capture-pop3') !== 'false',
      imap: localStorage.getItem('vigilyx-capture-imap') !== 'false',
      auto_restore: localStorage.getItem('vigilyx-auto-restore') !== 'false',
      max_packet_size: Number(localStorage.getItem('vigilyx-max-packet') || DEFAULT_UI_PREFERENCES.capture.max_packet_size),
      inbound_src: (localStorage.getItem('vigilyx-inbound-src') || '').split(',').filter(Boolean),
      inbound_dst: (localStorage.getItem('vigilyx-inbound-dst') || '').split(',').filter(Boolean),
      outbound_src: (localStorage.getItem('vigilyx-outbound-src') || '').split(',').filter(Boolean),
      outbound_dst: (localStorage.getItem('vigilyx-outbound-dst') || '').split(',').filter(Boolean),
    },
    about: {
      ntp_servers: localStorage.getItem('vigilyx-ntp-servers') || DEFAULT_UI_PREFERENCES.about.ntp_servers,
      ntp_interval_minutes: Number(localStorage.getItem('vigilyx-ntp-interval') || DEFAULT_UI_PREFERENCES.about.ntp_interval_minutes),
    },
  })
}

export function loadCachedUiPreferences(): UiPreferences {
  try {
    const cached = localStorage.getItem(UI_PREFERENCES_CACHE_KEY)
    if (cached) return normalizeUiPreferences(JSON.parse(cached))
  } catch {
    // Ignore broken cache and fall back to legacy keys
  }
  return readLegacyUiPreferences()
}

function writeLegacyKeys(prefs: UiPreferences) {
  localStorage.setItem('vigilyx-theme', prefs.appearance.theme)
  localStorage.setItem('vigilyx-accent', prefs.appearance.accent)
  localStorage.setItem('vigilyx-sound', String(prefs.notifications.sound_enabled))
  localStorage.setItem('vigilyx-desktop-notify', String(prefs.notifications.desktop_notify))
  localStorage.setItem('vigilyx-alert-threshold', String(prefs.notifications.alert_threshold))
  localStorage.setItem('vigilyx-capture-smtp', String(prefs.capture.smtp))
  localStorage.setItem('vigilyx-capture-pop3', String(prefs.capture.pop3))
  localStorage.setItem('vigilyx-capture-imap', String(prefs.capture.imap))
  localStorage.setItem('vigilyx-auto-restore', String(prefs.capture.auto_restore))
  localStorage.setItem('vigilyx-max-packet', String(prefs.capture.max_packet_size))
  localStorage.setItem('vigilyx-inbound-src', prefs.capture.inbound_src.join(','))
  localStorage.setItem('vigilyx-inbound-dst', prefs.capture.inbound_dst.join(','))
  localStorage.setItem('vigilyx-outbound-src', prefs.capture.outbound_src.join(','))
  localStorage.setItem('vigilyx-outbound-dst', prefs.capture.outbound_dst.join(','))
  localStorage.setItem('vigilyx-ntp-servers', prefs.about.ntp_servers)
  localStorage.setItem('vigilyx-ntp-interval', String(prefs.about.ntp_interval_minutes))
  localStorage.setItem(UI_PREFERENCES_CACHE_KEY, JSON.stringify(prefs))
}

export function applyUiPreferencesToClient(prefs: UiPreferences, emit = true) {
  writeLegacyKeys(prefs)
  document.documentElement.setAttribute('data-theme', prefs.appearance.theme)
  document.documentElement.style.setProperty('--accent-primary', ACCENT_COLORS[prefs.appearance.accent])

  if (emit) {
    window.dispatchEvent(new Event('vigilyx:display-settings-changed'))
    window.dispatchEvent(new CustomEvent('vigilyx:ui-preferences-changed', { detail: prefs }))
  }
}

export async function fetchUiPreferencesFromServer(): Promise<UiPreferences> {
  const res = await apiFetch('/api/config/ui-preferences')
  const data = await res.json()
  if (!data.success || !data.data) {
    throw new Error(data.error || 'Failed to load ui preferences')
  }
  const prefs = normalizeUiPreferences(data.data)
  applyUiPreferencesToClient(prefs)
  return prefs
}

export async function syncUiPreferencesFromServer(): Promise<UiPreferences> {
  try {
    return await fetchUiPreferencesFromServer()
  } catch {
    const cached = loadCachedUiPreferences()
    applyUiPreferencesToClient(cached, false)
    return cached
  }
}

export async function saveUiPreferencesPatch(patch: DeepPartial<UiPreferences>): Promise<UiPreferences> {
  const res = await apiFetch('/api/config/ui-preferences', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  })
  const data = await res.json()
  if (!data.success || !data.data) {
    throw new Error(data.error || 'Failed to save ui preferences')
  }
  const prefs = normalizeUiPreferences(data.data)
  applyUiPreferencesToClient(prefs)
  return prefs
}
