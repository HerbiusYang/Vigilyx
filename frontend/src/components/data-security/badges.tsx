import { memo } from 'react'
import { SEVERITY_COLOR, SEVERITY_BG, SEVERITY_CN, INCIDENT_TYPE_COLOR, INCIDENT_TYPE_ICON, INCIDENT_TYPE_CN, METHOD_COLOR } from './constants'

export const SeverityBadge = memo(function SeverityBadge({ severity }: { severity: string }) {
  const c = SEVERITY_COLOR[severity] || SEVERITY_COLOR.info
  const bg = SEVERITY_BG[severity] || SEVERITY_BG.info
  return <span className="ds3-sev-badge" style={{ background: bg, color: c }}><span className="ds3-sev-badge-dot" style={{ background: c }} />{SEVERITY_CN[severity] || severity}</span>
})

export const IncidentTypeBadge = memo(function IncidentTypeBadge({ type: t }: { type: string }) {
  const c = INCIDENT_TYPE_COLOR[t] || '#8b949e'
  return <span className="ds3-type-badge" style={{ background: c + '12', color: c }}>{INCIDENT_TYPE_ICON[t]}{INCIDENT_TYPE_CN[t] || t}</span>
})

export const MethodBadge = memo(function MethodBadge({ method }: { method: string }) {
  const c = METHOD_COLOR[method] || 'var(--text-secondary)'
  return <span className="ds3-method-badge" style={{ background: c + '15', color: c }}>{method}</span>
})
