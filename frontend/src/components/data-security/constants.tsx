import financialPolicy from '../../../../shared/schemas/data_security_policy.json'
import i18n from '../../i18n'
import type { JSX } from 'react'

export const INCIDENT_TYPE_CN: Record<string, string> = new Proxy({} as Record<string, string>, { get: (_, key: string) => i18n.t(`dataSecurity.incidentType_${key}`, { defaultValue: key }) })
export const INCIDENT_TYPE_DESC: Record<string, string> = new Proxy({} as Record<string, string>, { get: (_, key: string) => i18n.t(`dataSecurity.incidentTypeDesc_${key}`) })
export const INCIDENT_TYPE_COLOR: Record<string, string> = { draft_box_abuse: '#a855f7', file_transit_abuse: '#3b82f6', self_sending: '#f97316', sensitive_data_transfer: '#f97316', bulk_sensitive_transfer: '#ef4444', volume_anomaly: '#eab308', jrt_compliance_violation: '#ef4444' }
export const INCIDENT_TYPE_ICON: Record<string, JSX.Element> = {
  draft_box_abuse: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>,
  file_transit_abuse: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>,
  self_sending: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>,
  volume_anomaly: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 12 7 12 10 4 14 20 17 12 21 12"/></svg>,
  jrt_compliance_violation: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
}
INCIDENT_TYPE_ICON.sensitive_data_transfer = INCIDENT_TYPE_ICON.self_sending
INCIDENT_TYPE_ICON.bulk_sensitive_transfer = INCIDENT_TYPE_ICON.jrt_compliance_violation
export const SEVERITY_COLOR: Record<string, string> = { info: '#6b7280', low: '#3b82f6', medium: '#eab308', high: '#f97316', critical: '#ef4444' }
export const SEVERITY_BG: Record<string, string> = { info: 'rgba(107,114,128,.12)', low: 'rgba(59,130,246,.12)', medium: 'rgba(234,179,8,.12)', high: 'rgba(249,115,22,.12)', critical: 'rgba(239,68,68,.12)' }
export const SEVERITY_CN: Record<string, string> = new Proxy({} as Record<string, string>, { get: (_, key: string) => i18n.t(`dataSecurity.severity_${key}`) })
export const DLP_MATCH_CN: Record<string, string> = new Proxy({} as Record<string, string>, { get: (_, key: string) => i18n.t(`dataSecurity.dlpMatch_${key}`, { defaultValue: key }) })
export const FINANCIAL_POLICY = financialPolicy
export const DATA_SECURITY_LEVEL_COLOR: Record<number, string> = { 5: '#b91c1c', 4: '#ef4444', 3: '#f97316', 2: '#eab308', 1: '#22c55e' }
export const DATA_SECURITY_LEVEL_LABEL: Record<number, string> = new Proxy({} as Record<number, string>, { get: (_, key: string) => i18n.t('dataSecurity.levelNumber', { level: key }) })
export function getSecurityLevel(name: string, matches: string[]): number {
  if (name === 'otp_verification' && matches.some(item => ['credit_card', 'bank_card', 'iban', 'bank_account', 'bank_account_context'].includes(item))) return 4
  if (name === 'bank_account_context') name = 'bank_account'
  return (FINANCIAL_POLICY.field_levels as Record<string, number>)[name] || 0
}
export const METHOD_COLOR: Record<string, string> = { GET: '#22d3ee', POST: '#f97316', PUT: '#eab308', DELETE: '#ef4444', PATCH: '#a855f7' }

const MASKED_BODY_KEY = 'dataSecurity.maskedBody'
const MASKED_SNIPPET_KEY = 'dataSecurity.maskedSnippet'
export const getMaskedBody = () => i18n.t(MASKED_BODY_KEY)
export const getMaskedSnippet = () => i18n.t(MASKED_SNIPPET_KEY)
