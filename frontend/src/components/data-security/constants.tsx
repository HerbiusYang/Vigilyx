import i18n from '../../i18n'

export const INCIDENT_TYPE_CN: Record<string, string> = new Proxy({} as Record<string, string>, { get: (_, key: string) => i18n.t(`dataSecurity.incidentType_${key}`) })
export const INCIDENT_TYPE_DESC: Record<string, string> = new Proxy({} as Record<string, string>, { get: (_, key: string) => i18n.t(`dataSecurity.incidentTypeDesc_${key}`) })
export const INCIDENT_TYPE_COLOR: Record<string, string> = { draft_box_abuse: '#a855f7', file_transit_abuse: '#3b82f6', self_sending: '#f97316', jrt_compliance_violation: '#ef4444' }
export const INCIDENT_TYPE_ICON: Record<string, JSX.Element> = {
  draft_box_abuse: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>,
  file_transit_abuse: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>,
  self_sending: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>,
  jrt_compliance_violation: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
}
export const SEVERITY_COLOR: Record<string, string> = { info: '#6b7280', low: '#3b82f6', medium: '#eab308', high: '#f97316', critical: '#ef4444' }
export const SEVERITY_BG: Record<string, string> = { info: 'rgba(107,114,128,.12)', low: 'rgba(59,130,246,.12)', medium: 'rgba(234,179,8,.12)', high: 'rgba(249,115,22,.12)', critical: 'rgba(239,68,68,.12)' }
export const SEVERITY_CN: Record<string, string> = new Proxy({} as Record<string, string>, { get: (_, key: string) => i18n.t(`dataSecurity.severity_${key}`) })
export const DLP_MATCH_CN: Record<string, string> = new Proxy({} as Record<string, string>, { get: (_, key: string) => i18n.t(`dataSecurity.dlpMatch_${key}`) })
export const DLP_JRT_LEVEL: Record<string, number> = { credential_leak: 4, cvv_code: 4, credit_card: 4, biometric_data: 4, medical_health: 4, id_number: 3, phone_number: 3, bank_card: 3, customer_address: 3, email_address: 3, passport_number: 3, iban: 3, large_amount: 3, bank_account_context: 3, contract_number: 3, vehicle_info: 3, property_info: 3, income_info: 3, geo_location: 3, otp_verification: 3, loan_credit_info: 3, insurance_policy: 3, family_relation: 3, swift_code: 2, tax_id: 2, employee_info: 2, judicial_record: 2, education_info: 2, business_license: 2, social_credit_code: 1 }
export const JRT_LEVEL_COLOR: Record<number, string> = { 4: '#ef4444', 3: '#f97316', 2: '#eab308', 1: '#22c55e' }
export const JRT_LEVEL_LABEL: Record<number, string> = { 4: 'C4', 3: 'C3', 2: 'C2', 1: 'C1' }
export const METHOD_COLOR: Record<string, string> = { GET: '#22d3ee', POST: '#f97316', PUT: '#eab308', DELETE: '#ef4444', PATCH: '#a855f7' }

export const PRIVACY_KEY = 'vigilyx_ds_privacy_mode'
export const MASKED_BODY_KEY = 'dataSecurity.maskedBody'
export const MASKED_SNIPPET_KEY = 'dataSecurity.maskedSnippet'
export const getMaskedBody = () => i18n.t(MASKED_BODY_KEY)
export const getMaskedSnippet = () => i18n.t(MASKED_SNIPPET_KEY)
