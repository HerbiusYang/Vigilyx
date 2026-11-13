import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { PrivacyResourceRef, PrivacyScope } from '../../types'
import { usePrivacyAccess } from '../../hooks/usePrivacyAccess'

const EMAIL_SCOPES: PrivacyScope[] = ['body', 'html', 'headers', 'verdict', 'attachment_download', 'eml_download']
const HTTP_SCOPES: PrivacyScope[] = ['http_body']

function scopeOptions(resource: PrivacyResourceRef): PrivacyScope[] {
  if (resource.resource_type === 'http_session') return HTTP_SCOPES
  if (resource.resource_type === 'attachment') return ['attachment_download']
  return EMAIL_SCOPES
}

function remainingSeconds(expiresAt: string): number {
  return Math.max(0, Math.ceil((Date.parse(expiresAt) - Date.now()) / 1000))
}

function formatRemaining(seconds: number): string {
  const minutes = Math.floor(seconds / 60)
  const rest = seconds % 60
  return `${String(minutes).padStart(2, '0')}:${String(rest).padStart(2, '0')}`
}

export function PrivacyAccessPanel({ resource, defaultScopes, onLeaseReady }: {
  resource: PrivacyResourceRef
  defaultScopes?: PrivacyScope[]
  onLeaseReady?: () => void
}) {
  const { t } = useTranslation()
  const access = usePrivacyAccess(resource)
  const options = useMemo(() => scopeOptions(resource), [resource.resource_type])
  const [scopes, setScopes] = useState<PrivacyScope[]>(defaultScopes?.filter(scope => options.includes(scope)) ?? [options[0]])
  const [purpose, setPurpose] = useState('')
  const [adminKey, setAdminKey] = useState('')
  const [ttlSeconds, setTtlSeconds] = useState(300)
  const [submitting, setSubmitting] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [clock, setClock] = useState(Date.now())

  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  const latestRequest = access.requests[0]
  const activeLease = access.lease
  const secondsLeft = activeLease ? remainingSeconds(activeLease.expires_at) : 0
  const canRequest = access.isAdmin && purpose.trim().length >= 4 && adminKey.length >= 12 && scopes.length > 0 && !submitting

  const toggleScope = (scope: PrivacyScope) => {
    setScopes(current => current.includes(scope) ? current.filter(item => item !== scope) : [...current, scope])
    setActionError(null)
  }

  const submitRequest = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!canRequest) return
    setSubmitting(true)
    setActionError(null)
    setActionMessage(null)
    try {
      await access.request({ scopes, purpose: purpose.trim(), ttl_seconds: ttlSeconds, admin_key: adminKey })
      setPurpose('')
      setAdminKey('')
      setActionMessage(t('privacy.requestCreated'))
    } catch {
      setActionError(t('privacy.requestFailed'))
    } finally {
      setSubmitting(false)
    }
  }

  const acquire = async () => {
    if (!latestRequest || latestRequest.status !== 'approved') return
    setActionError(null)
    try {
      await access.acquire(latestRequest.request_id)
      setActionMessage(t('privacy.leaseReady'))
      onLeaseReady?.()
    } catch {
      setActionError(t('privacy.leaseFailed'))
    }
  }

  // Keep the visible countdown fresh even when the API is quiet.
  void clock

  return (
    <section className="privacy-access-panel" aria-labelledby="privacy-access-panel-title">
      <div className="privacy-access-panel__header">
        <div>
          <div className="privacy-access-kicker">{t('privacy.kicker')}</div>
          <h3 id="privacy-access-panel-title">{t('privacy.resourceAccess')}</h3>
          <p>{t('privacy.resourceBoundHint', { id: resource.resource_id })}</p>
        </div>
        <span className="privacy-access-lock" aria-hidden="true">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <rect x="5" y="10" width="14" height="10" rx="2" />
            <path d="M8 10V7a4 4 0 0 1 8 0v3" />
            <path d="M12 14v2" />
          </svg>
        </span>
      </div>

      {access.error && <div className="privacy-access-message privacy-access-message--error" role="alert">{t('privacy.serviceUnavailable')}</div>}
      {actionError && <div className="privacy-access-message privacy-access-message--error" role="alert">{actionError}</div>}
      {actionMessage && <div className="privacy-access-message privacy-access-message--success" role="status">{actionMessage}</div>}

      {activeLease && secondsLeft > 0 ? (
        <div className="privacy-lease-card" role="status" aria-live="polite">
          <div>
            <strong>{t('privacy.leaseActive')}</strong>
            <span>{t('privacy.leaseScope', { scopes: activeLease.scopes.map(scope => t(`privacy.scope.${scope}`)).join('、') })}</span>
          </div>
          <div className="privacy-lease-card__actions">
            <span className="privacy-lease-countdown">{formatRemaining(secondsLeft)}</span>
            <button type="button" className="privacy-access-button privacy-access-button--danger" onClick={() => void access.lock()}>
              {t('privacy.lockNow')}
            </button>
          </div>
        </div>
      ) : latestRequest?.status === 'approved' ? (
        <div className="privacy-access-message privacy-access-message--success" role="status">
          <span>{t('privacy.approvedAwaitingLease')}</span>
          <button type="button" className="privacy-access-button" onClick={() => void acquire()}>{t('privacy.activateLease')}</button>
        </div>
      ) : latestRequest ? (
        <div className="privacy-request-status" role="status">
          <span className={`privacy-request-status__dot privacy-request-status__dot--${latestRequest.status}`} />
          <div>
            <strong>{t(`privacy.requestStatus.${latestRequest.status}`)}</strong>
            <span>{t('privacy.requestScopeSummary', { scopes: latestRequest.scopes.map(scope => t(`privacy.scope.${scope}`)).join('、') })}</span>
          </div>
        </div>
      ) : null}

      {access.isAdmin ? (
        <form className="privacy-request-form" onSubmit={submitRequest}>
          <div className="privacy-request-form__title-row">
            <div className="privacy-request-form__title">{t('privacy.adminRequestTitle')}</div>
            <span className="privacy-request-form__required">{t('privacy.requiredFields')}</span>
          </div>
          <fieldset className="privacy-request-form__scopes">
            <legend>{t('privacy.scopeLabel')}</legend>
            <div className="privacy-scope-grid">
              {options.map(scope => (
                <label key={scope} className="privacy-scope-option">
                  <input type="checkbox" checked={scopes.includes(scope)} onChange={() => toggleScope(scope)} />
                  <span>{t(`privacy.scope.${scope}`)}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="privacy-request-form__grid">
            <label className="privacy-form-field privacy-form-field--wide">
              <span>{t('privacy.purposeLabel')}</span>
              <textarea value={purpose} onChange={event => setPurpose(event.target.value)} minLength={4} maxLength={500} rows={3} placeholder={t('privacy.purposePlaceholder')} required />
            </label>
            <label className="privacy-form-field">
              <span>{t('privacy.adminFactorLabel')}</span>
              <input type="password" value={adminKey} onChange={event => setAdminKey(event.target.value)} autoComplete="new-password" spellCheck={false} minLength={12} required />
            </label>
            <label className="privacy-form-field">
              <span>{t('privacy.validityLabel')}</span>
              <select value={ttlSeconds} onChange={event => setTtlSeconds(Number(event.target.value))}>
                <option value={60}>{t('privacy.validityOption', { minutes: 1 })}</option>
                <option value={300}>{t('privacy.validityOption', { minutes: 5 })}</option>
              </select>
            </label>
          </div>
          <div className="privacy-request-form__footer">
            <span>{t('privacy.auditMustApprove')}</span>
            <button type="submit" className="privacy-access-button" disabled={!canRequest}>
              {submitting ? t('privacy.submitting') : t('privacy.requestView')}
            </button>
          </div>
        </form>
      ) : access.isAudit ? (
        <div className="privacy-access-message" role="note">{t('privacy.auditUseCenter')}</div>
      ) : (
        <div className="privacy-access-message" role="note">{t('privacy.noPrivacyPermission')}</div>
      )}
    </section>
  )
}
