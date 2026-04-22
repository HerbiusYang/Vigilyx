import i18n from '../i18n'

const SERVER_CLOCK_STORAGE_KEY = 'vigilyx-server-clock'

type ServerClockSnapshot = {
  server_time?: string
  server_timezone?: string | null
  server_utc_offset_minutes?: number | null
}

type ServerClockState = {
  serverNowMs: number | null
  syncedClientNowMs: number | null
  timeZone: string | null
  offsetMinutes: number | null
}

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null
  try {
    return window.localStorage
  } catch {
    return null
  }
}

function coerceFiniteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function isValidTimeZone(timeZone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone }).format(0)
    return true
  } catch {
    return false
  }
}

export function normalizeTimestamp(value: string): string {
  const trimmed = value.trim()
  if (!trimmed) return trimmed
  if (trimmed.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(trimmed)) return trimmed
  return `${trimmed}Z`
}

function parseTimestamp(value: string | number | Date): Date {
  if (value instanceof Date) return new Date(value.getTime())
  if (typeof value === 'number') return new Date(value)
  return new Date(normalizeTimestamp(value))
}

function extractOffsetMinutesFromIso(value: string): number | null {
  const normalized = normalizeTimestamp(value)
  if (normalized.endsWith('Z')) return 0
  const match = normalized.match(/([+-])(\d{2}):?(\d{2})$/)
  if (!match) return null
  const sign = match[1] === '+' ? 1 : -1
  const hours = Number(match[2])
  const minutes = Number(match[3])
  return sign * (hours * 60 + minutes)
}

function loadServerClockState(): ServerClockState {
  const fallback: ServerClockState = {
    serverNowMs: null,
    syncedClientNowMs: null,
    timeZone: null,
    offsetMinutes: null,
  }
  const storage = getStorage()
  if (!storage) return fallback

  try {
    const raw = storage.getItem(SERVER_CLOCK_STORAGE_KEY)
    if (!raw) return fallback
    const parsed = JSON.parse(raw) as Partial<ServerClockState>
    return {
      serverNowMs: coerceFiniteNumber(parsed.serverNowMs),
      syncedClientNowMs: coerceFiniteNumber(parsed.syncedClientNowMs),
      timeZone:
        typeof parsed.timeZone === 'string' && isValidTimeZone(parsed.timeZone)
          ? parsed.timeZone
          : null,
      offsetMinutes: coerceFiniteNumber(parsed.offsetMinutes),
    }
  } catch {
    return fallback
  }
}

const serverClock = loadServerClockState()

function persistServerClock(): void {
  const storage = getStorage()
  if (!storage) return
  storage.setItem(SERVER_CLOCK_STORAGE_KEY, JSON.stringify(serverClock))
}

export function syncServerClock(snapshot: ServerClockSnapshot): void {
  const serverTime = typeof snapshot.server_time === 'string' ? snapshot.server_time.trim() : ''
  if (serverTime) {
    const serverNowMs = parseTimestamp(serverTime).getTime()
    if (Number.isFinite(serverNowMs)) {
      serverClock.serverNowMs = serverNowMs
      serverClock.syncedClientNowMs = Date.now()
    }
  }

  const serverTimeZone =
    typeof snapshot.server_timezone === 'string' ? snapshot.server_timezone.trim() : ''
  if (serverTimeZone && isValidTimeZone(serverTimeZone)) {
    serverClock.timeZone = serverTimeZone
  }

  const offsetMinutes =
    coerceFiniteNumber(snapshot.server_utc_offset_minutes) ??
    (serverTime ? extractOffsetMinutesFromIso(serverTime) : null)
  if (offsetMinutes !== null) {
    serverClock.offsetMinutes = offsetMinutes
  }

  persistServerClock()
}

export function resetServerClockForTests(): void {
  serverClock.serverNowMs = null
  serverClock.syncedClientNowMs = null
  serverClock.timeZone = null
  serverClock.offsetMinutes = null
  const storage = getStorage()
  storage?.removeItem(SERVER_CLOCK_STORAGE_KEY)
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function getDateLocale(): string {
  return i18n.language === 'en' ? 'en-US' : 'zh-CN'
}

export function getServerNowMs(): number {
  if (serverClock.serverNowMs === null || serverClock.syncedClientNowMs === null) {
    return Date.now()
  }
  return serverClock.serverNowMs + (Date.now() - serverClock.syncedClientNowMs)
}

function getServerNowDate(): Date {
  return new Date(getServerNowMs())
}

function formatInServerTime(date: Date, options: Intl.DateTimeFormatOptions): string {
  const locale = getDateLocale()
  if (serverClock.timeZone) {
    return new Intl.DateTimeFormat(locale, {
      ...options,
      timeZone: serverClock.timeZone,
    }).format(date)
  }

  if (serverClock.offsetMinutes !== null) {
    const shifted = new Date(date.getTime() + serverClock.offsetMinutes * 60_000)
    return new Intl.DateTimeFormat(locale, {
      ...options,
      timeZone: 'UTC',
    }).format(shifted)
  }

  return new Intl.DateTimeFormat(locale, options).format(date)
}

type TimeParts = {
  year: string
  month: string
  day: string
  hour: string
  minute: string
  second: string
}

function getServerTimeParts(date: Date): TimeParts {
  if (serverClock.timeZone) {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: serverClock.timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      hourCycle: 'h23',
    }).formatToParts(date)

    const byType = new Map(parts.map(part => [part.type, part.value]))
    return {
      year: byType.get('year') ?? '0000',
      month: byType.get('month') ?? '00',
      day: byType.get('day') ?? '00',
      hour: byType.get('hour') ?? '00',
      minute: byType.get('minute') ?? '00',
      second: byType.get('second') ?? '00',
    }
  }

  const shifted =
    serverClock.offsetMinutes !== null
      ? new Date(date.getTime() + serverClock.offsetMinutes * 60_000)
      : date
  const useUtc = serverClock.offsetMinutes !== null
  const year = useUtc ? shifted.getUTCFullYear() : shifted.getFullYear()
  const month = (useUtc ? shifted.getUTCMonth() : shifted.getMonth()) + 1
  const day = useUtc ? shifted.getUTCDate() : shifted.getDate()
  const hour = useUtc ? shifted.getUTCHours() : shifted.getHours()
  const minute = useUtc ? shifted.getUTCMinutes() : shifted.getMinutes()
  const second = useUtc ? shifted.getUTCSeconds() : shifted.getSeconds()
  const pad = (value: number) => String(value).padStart(2, '0')

  return {
    year: String(year).padStart(4, '0'),
    month: pad(month),
    day: pad(day),
    hour: pad(hour),
    minute: pad(minute),
    second: pad(second),
  }
}

export function formatDate(dateStr: string): string {
  return formatInServerTime(parseTimestamp(dateStr), {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatDateFull(dateStr: string): string {
  return formatInServerTime(parseTimestamp(dateStr), {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function formatDateOnly(dateStr: string): string {
  return formatInServerTime(parseTimestamp(dateStr), {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  })
}

export function formatCurrentServerDateTime(): string {
  return formatInServerTime(getServerNowDate(), {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function formatCurrentServerTime(): string {
  return formatInServerTime(getServerNowDate(), {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function getServerDateStamp(): string {
  const parts = getServerTimeParts(getServerNowDate())
  return `${parts.year}-${parts.month}-${parts.day}`
}

export function formatHourLabel(dateStr: string): string {
  const { hour } = getServerTimeParts(parseTimestamp(dateStr))
  return `${hour}:00`
}

export function isPastServerNow(dateStr: string): boolean {
  return parseTimestamp(dateStr).getTime() < getServerNowMs()
}

export function getRelativeTime(dateStr: string): string {
  const diffMs = getServerNowMs() - parseTimestamp(dateStr).getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return i18n.t('format.justNow')
  if (diffMins < 60) return i18n.t('format.minutesAgo', { count: diffMins })
  if (diffHours < 24) return i18n.t('format.hoursAgo', { count: diffHours })
  return i18n.t('format.daysAgo', { count: diffDays })
}

export function isEncryptedPort(port: number): boolean {
  return [465, 993, 995].includes(port)
}

/**
 * Format ISO timestamp → "MM-DD HH:mm" (no seconds).
 * Used by whitelist / intel / verdict tables.
 */
export function formatTime(iso: string): string {
  const { month, day, hour, minute } = getServerTimeParts(parseTimestamp(iso))
  return `${month}-${day} ${hour}:${minute}`
}

/**
 * Format ISO timestamp → full zh-CN locale string (hour12: false).
 * Used by quarantine table.
 */
export function formatTimeFull(iso: string): string {
  return formatInServerTime(parseTimestamp(iso), {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

/**
 * Format ISO timestamp → "MM-DD HH:mm:ss" with TZ normalization.
 * Appends 'Z' to naive timestamps so they're treated as UTC.
 */
export function formatTimeWithSeconds(ts: string): string {
  const { month, day, hour, minute, second } = getServerTimeParts(parseTimestamp(ts))
  return `${month}-${day} ${hour}:${minute}:${second}`
}

export function formatClockTime(ts: string): string {
  const { hour, minute, second } = getServerTimeParts(parseTimestamp(ts))
  return `${hour}:${minute}:${second}`
}

/**
 * Format byte count → human-readable size with max unit MB.
 * Uses toFixed(1). For TB-capable formatting, use `formatBytes`.
 */
export function formatSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(1)} MB`
}

/**
 * Relative time with TZ normalization + 7-day fallback to formatTimeWithSeconds.
 */
export function formatRelativeTime(ts: string): string {
  const diffMs = getServerNowMs() - parseTimestamp(ts).getTime()
  if (diffMs < 0) return formatTimeWithSeconds(ts)
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return i18n.t('format.justNow')
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return i18n.t('format.minutesAgo', { count: diffMin })
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return i18n.t('format.hoursAgo', { count: diffHr })
  const diffDay = Math.floor(diffHr / 24)
  if (diffDay < 7) return i18n.t('format.daysAgo', { count: diffDay })
  return formatTimeWithSeconds(ts)
}

/** Return the matching icon for a MIME type. */
export function getFileIcon(contentType: string): string {
  if (contentType.startsWith('image/')) return '🖼️'
  if (contentType.startsWith('video/')) return '🎬'
  if (contentType.startsWith('audio/')) return '🎵'
  if (contentType.includes('pdf')) return '📕'
  if (contentType.includes('word') || contentType.includes('document')) return '📘'
  if (contentType.includes('excel') || contentType.includes('spreadsheet')) return '📗'
  if (contentType.includes('powerpoint') || contentType.includes('presentation')) return '📙'
  if (contentType.includes('zip') || contentType.includes('archive') || contentType.includes('compressed')) return '📦'
  if (contentType.includes('text')) return '📄'
  return '📎'
}
