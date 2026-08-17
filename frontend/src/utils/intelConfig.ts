import type { IntelSourceConfig } from '../types'

export function normalizeIntelSourceConfig(value: Partial<IntelSourceConfig> | null | undefined): IntelSourceConfig {
  return {
    otx_enabled: value?.otx_enabled ?? true,
    vt_scrape_enabled: value?.vt_scrape_enabled ?? false,
    vt_scrape_url: value?.vt_scrape_url ?? null,
    virustotal_api_key: value?.virustotal_api_key ?? null,
    virustotal_api_key_set: value?.virustotal_api_key_set ?? false,
    abuseipdb_enabled: value?.abuseipdb_enabled ?? false,
    abuseipdb_api_key: value?.abuseipdb_api_key ?? null,
    abuseipdb_api_key_set: value?.abuseipdb_api_key_set ?? false,
  }
}

export function isMaskedSecretValue(value: string | null | undefined): boolean {
  return typeof value === 'string' && (value.includes('...') || value === '****')
}

export function buildIntelConfigPayload(config: IntelSourceConfig): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    otx_enabled: config.otx_enabled,
    vt_scrape_enabled: config.vt_scrape_enabled,
    abuseipdb_enabled: config.abuseipdb_enabled,
  }

  if (config.vt_scrape_url !== null) payload.vt_scrape_url = config.vt_scrape_url

  for (const key of ['virustotal_api_key', 'abuseipdb_api_key'] as const) {
    const value = config[key]
    if (value === '') payload[key] = null
    else if (value === null) continue
    else if (!isMaskedSecretValue(value)) payload[key] = value
  }

  return payload
}
