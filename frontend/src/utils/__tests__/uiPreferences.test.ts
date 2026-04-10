import { describe, it, expect } from 'vitest'
import { normalizeUiPreferences } from '../uiPreferences'
import type { UiPreferences } from '../uiPreferences'

describe('normalizeUiPreferences', () => {
  // ---------- null / undefined / non-object → all defaults ----------
  it('returns defaults for undefined input', () => {
    const result = normalizeUiPreferences(undefined)
    expect(result.appearance.theme).toBe('dark')
    expect(result.appearance.accent).toBe('cyan')
    expect(result.notifications.sound_enabled).toBe(true)
    expect(result.notifications.desktop_notify).toBe(false)
    expect(result.notifications.alert_threshold).toBe(100)
    expect(result.capture.smtp).toBe(true)
    expect(result.capture.max_packet_size).toBe(65535)
    expect(result.about.ntp_servers).toBe('ntp.aliyun.com')
    expect(result.about.ntp_interval_minutes).toBe(60)
  })

  it('returns defaults for null input', () => {
    const result = normalizeUiPreferences(null)
    expect(result.appearance.theme).toBe('dark')
    expect(result.capture.inbound_src).toEqual([])
  })

  it('returns defaults for non-object input (string)', () => {
    const result = normalizeUiPreferences('not an object')
    expect(result.appearance.theme).toBe('dark')
  })

  it('returns defaults for non-object input (number)', () => {
    const result = normalizeUiPreferences(42)
    expect(result.appearance.theme).toBe('dark')
  })

  it('returns defaults for array input', () => {
    const result = normalizeUiPreferences([1, 2, 3])
    expect(result.appearance.theme).toBe('dark')
  })

  // ---------- Partial fields → fills missing with defaults ----------
  it('fills missing sections with defaults', () => {
    const result = normalizeUiPreferences({ appearance: { theme: 'light' } })
    expect(result.appearance.theme).toBe('light')
    expect(result.appearance.accent).toBe('cyan')
    expect(result.notifications.sound_enabled).toBe(true)
    expect(result.capture.smtp).toBe(true)
    expect(result.about.ntp_servers).toBe('ntp.aliyun.com')
  })

  it('fills missing fields within a section', () => {
    const result = normalizeUiPreferences({
      notifications: { sound_enabled: false },
    })
    expect(result.notifications.sound_enabled).toBe(false)
    expect(result.notifications.desktop_notify).toBe(false)
    expect(result.notifications.alert_threshold).toBe(100)
  })

  // ---------- Invalid theme/accent → fallback ----------
  it('falls back invalid theme to dark', () => {
    const result = normalizeUiPreferences({ appearance: { theme: 'neon' } })
    expect(result.appearance.theme).toBe('dark')
  })

  it('accepts "light" theme', () => {
    const result = normalizeUiPreferences({ appearance: { theme: 'light' } })
    expect(result.appearance.theme).toBe('light')
  })

  it('falls back invalid accent to cyan', () => {
    const result = normalizeUiPreferences({ appearance: { accent: 'rainbow' } })
    expect(result.appearance.accent).toBe('cyan')
  })

  it('accepts valid accent "purple"', () => {
    const result = normalizeUiPreferences({ appearance: { accent: 'purple' } })
    expect(result.appearance.accent).toBe('purple')
  })

  it('accepts valid accent "rose"', () => {
    const result = normalizeUiPreferences({ appearance: { accent: 'rose' } })
    expect(result.appearance.accent).toBe('rose')
  })

  it('falls back numeric accent to cyan', () => {
    const result = normalizeUiPreferences({ appearance: { accent: 123 } })
    expect(result.appearance.accent).toBe('cyan')
  })

  // ---------- Number clamping ----------
  it('clamps alert_threshold below minimum to 10', () => {
    const result = normalizeUiPreferences({ notifications: { alert_threshold: 5 } })
    expect(result.notifications.alert_threshold).toBe(10)
  })

  it('clamps alert_threshold above maximum to 10000', () => {
    const result = normalizeUiPreferences({ notifications: { alert_threshold: 99999 } })
    expect(result.notifications.alert_threshold).toBe(10000)
  })

  it('clamps negative alert_threshold to 10', () => {
    const result = normalizeUiPreferences({ notifications: { alert_threshold: -50 } })
    expect(result.notifications.alert_threshold).toBe(10)
  })

  it('uses fallback for NaN alert_threshold', () => {
    const result = normalizeUiPreferences({ notifications: { alert_threshold: NaN } })
    expect(result.notifications.alert_threshold).toBe(100)
  })

  it('uses fallback for string alert_threshold', () => {
    const result = normalizeUiPreferences({ notifications: { alert_threshold: 'abc' as any } })
    expect(result.notifications.alert_threshold).toBe(100)
  })

  it('clamps max_packet_size below 512 to 512', () => {
    const result = normalizeUiPreferences({ capture: { max_packet_size: 100 } })
    expect(result.capture.max_packet_size).toBe(512)
  })

  it('clamps max_packet_size above 262144 to 262144', () => {
    const result = normalizeUiPreferences({ capture: { max_packet_size: 500000 } })
    expect(result.capture.max_packet_size).toBe(262144)
  })

  it('rounds fractional numbers', () => {
    const result = normalizeUiPreferences({ notifications: { alert_threshold: 55.7 } })
    expect(result.notifications.alert_threshold).toBe(56)
  })

  it('clamps ntp_interval_minutes between 1 and 1440', () => {
    expect(normalizeUiPreferences({ about: { ntp_interval_minutes: 0 } }).about.ntp_interval_minutes).toBe(1)
    expect(normalizeUiPreferences({ about: { ntp_interval_minutes: 5000 } }).about.ntp_interval_minutes).toBe(1440)
  })

  // ---------- IP list normalization ----------
  it('deduplicates IP list', () => {
    const result = normalizeUiPreferences({
      capture: { inbound_src: ['192.168.1.1', '10.0.0.1', '192.168.1.1'] },
    })
    expect(result.capture.inbound_src).toEqual(['192.168.1.1', '10.0.0.1'])
  })

  it('filters empty strings from IP list', () => {
    const result = normalizeUiPreferences({
      capture: { inbound_src: ['192.168.1.1', '', '  ', '10.0.0.1'] },
    })
    expect(result.capture.inbound_src).toEqual(['192.168.1.1', '10.0.0.1'])
  })

  it('returns empty array for non-array IP list', () => {
    const result = normalizeUiPreferences({
      capture: { inbound_src: 'not-an-array' as any },
    })
    expect(result.capture.inbound_src).toEqual([])
  })

  it('filters non-string items from IP list', () => {
    const result = normalizeUiPreferences({
      capture: { inbound_dst: ['192.168.1.1', 42 as any, null as any, '10.0.0.1'] },
    })
    expect(result.capture.inbound_dst).toEqual(['192.168.1.1', '10.0.0.1'])
  })

  // ---------- Boolean normalization ----------
  it('uses fallback for non-boolean value', () => {
    const result = normalizeUiPreferences({ capture: { smtp: 'yes' as any } })
    expect(result.capture.smtp).toBe(true) // default is true
  })

  it('uses fallback for null boolean', () => {
    const result = normalizeUiPreferences({ notifications: { sound_enabled: null as any } })
    expect(result.notifications.sound_enabled).toBe(true) // default
  })

  it('accepts false boolean values', () => {
    const result = normalizeUiPreferences({
      capture: { smtp: false, pop3: false, imap: false },
    })
    expect(result.capture.smtp).toBe(false)
    expect(result.capture.pop3).toBe(false)
    expect(result.capture.imap).toBe(false)
  })

  // ---------- ntp_servers string normalization ----------
  it('trims ntp_servers string', () => {
    const result = normalizeUiPreferences({ about: { ntp_servers: '  pool.ntp.org  ' } })
    expect(result.about.ntp_servers).toBe('pool.ntp.org')
  })

  it('uses default for empty ntp_servers', () => {
    const result = normalizeUiPreferences({ about: { ntp_servers: '   ' } })
    expect(result.about.ntp_servers).toBe('ntp.aliyun.com')
  })

  it('uses default for non-string ntp_servers', () => {
    const result = normalizeUiPreferences({ about: { ntp_servers: 123 as any } })
    expect(result.about.ntp_servers).toBe('ntp.aliyun.com')
  })

  // ---------- Complete valid input ----------
  it('preserves all valid fields from a complete input', () => {
    const input: UiPreferences = {
      appearance: { theme: 'light', accent: 'amber' },
      notifications: { sound_enabled: false, desktop_notify: true, alert_threshold: 500 },
      capture: {
        smtp: false, pop3: true, imap: false, auto_restore: false,
        max_packet_size: 32768,
        inbound_src: ['10.0.0.1'], inbound_dst: ['10.0.0.2'],
        outbound_src: [], outbound_dst: ['192.168.1.1'],
      },
      about: { ntp_servers: 'time.google.com', ntp_interval_minutes: 30 },
    }
    const result = normalizeUiPreferences(input)
    expect(result).toEqual(input)
  })
})
