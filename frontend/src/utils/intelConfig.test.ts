import { describe, expect, it } from 'vitest'
import { buildIntelConfigPayload, normalizeIntelSourceConfig } from './intelConfig'

describe('intel config contract', () => {
  it('keeps VT scrape opt-in when the backend omits the field', () => {
    expect(normalizeIntelSourceConfig(undefined).vt_scrape_enabled).toBe(false)
    expect(normalizeIntelSourceConfig({ otx_enabled: true }).vt_scrape_enabled).toBe(false)
    expect(normalizeIntelSourceConfig({ vt_scrape_enabled: true }).vt_scrape_enabled).toBe(true)
  })

  it('preserves nullable API keys as an unchanged value', () => {
    const config = normalizeIntelSourceConfig({
      virustotal_api_key: null,
      abuseipdb_api_key: null,
    })

    const payload = buildIntelConfigPayload(config)
    expect(payload).not.toHaveProperty('vt_scrape_url')
    expect(payload).not.toHaveProperty('virustotal_api_key')
    expect(payload).not.toHaveProperty('abuseipdb_api_key')
  })

  it('uses an explicit empty string to clear a configured API key', () => {
    const config = normalizeIntelSourceConfig({
      virustotal_api_key: '',
      virustotal_api_key_set: true,
    })

    expect(buildIntelConfigPayload(config).virustotal_api_key).toBeNull()
  })

  it('preserves the configured VT scrape URL and omits masked secrets', () => {
    const config = normalizeIntelSourceConfig({
      vt_scrape_url: 'http://vigilyx-ai:8900',
      virustotal_api_key: '****',
      virustotal_api_key_set: true,
    })
    const payload = buildIntelConfigPayload(config)

    expect(payload.vt_scrape_url).toBe('http://vigilyx-ai:8900')
    expect(payload).not.toHaveProperty('virustotal_api_key')
  })
})
