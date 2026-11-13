import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { PrivacyResourceType } from '../../types'
import { approvePrivacyRequest, rejectPrivacyRequest, setPrivacyFactor, usePrivacyAccess } from '../../hooks/usePrivacyAccess'
import { usePrivacyPolicy } from '../../hooks/usePrivacyPolicy'
import { PrivacyAccessPanel } from './PrivacyAccessPanel'

function requestTime(value: string): string {
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString()
}

export default function PrivacyAccessCenter() {
  const { t } = useTranslation()
  const access = usePrivacyAccess()
  const policy = usePrivacyPolicy()
  const [resourceType, setResourceType] = useState<PrivacyResourceType>('session')
  const [resourceId, setResourceId] = useState('')
  const [selectedRequest, setSelectedRequest] = useState<string | null>(null)
  const [factor, setFactor] = useState('')
  const [currentOperatorFactor, setCurrentOperatorFactor] = useState('')
  const [operatorFactor, setOperatorFactor] = useState('')
  const [operatorFactorConfirmation, setOperatorFactorConfirmation] = useState('')
  const [factorBusy, setFactorBusy] = useState(false)
  const [busyAction, setBusyAction] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [actionMessage, setActionMessage] = useState<string | null>(null)

  const pendingRequests = useMemo(
    () => access.requests.filter(request => request.status === 'requested'),
    [access.requests],
  )

  const approve = async (requestId: string) => {
    if (!factor || busyAction) return
    // Clear the input before the network request so the factor cannot remain
    // in the admin/audit page after a timeout or a rejected response.
    const submittedFactor = factor
    setFactor('')
    setBusyAction(requestId)
    setActionError(null)
    setActionMessage(null)
    try {
      const updated = await approvePrivacyRequest(requestId, submittedFactor)
      access.setRequests(current => current.map(item => item.request_id === requestId ? updated : item))
      setSelectedRequest(null)
      await access.refresh()
    } catch {
      setActionError(t('privacy.approveFailed'))
    } finally {
      setBusyAction(null)
    }
  }

  const reject = async (requestId: string) => {
    if (busyAction) return
    setBusyAction(requestId)
    setActionError(null)
    setActionMessage(null)
    try {
      const updated = await rejectPrivacyRequest(requestId)
      access.setRequests(current => current.map(item => item.request_id === requestId ? updated : item))
    } catch {
      setActionError(t('privacy.rejectFailed'))
    } finally {
      setBusyAction(null)
    }
  }

  const saveOperatorFactor = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (factorBusy || operatorFactor.length < 12 || operatorFactor !== operatorFactorConfirmation) return
    const factorConfigured = access.context?.current_user.factor_configured ?? false
    if (factorConfigured && currentOperatorFactor.length < 12) return
    setFactorBusy(true)
    setActionError(null)
    setActionMessage(null)
    try {
      await setPrivacyFactor(operatorFactor, currentOperatorFactor)
      setCurrentOperatorFactor('')
      setOperatorFactor('')
      setOperatorFactorConfirmation('')
      setActionMessage(t('privacy.factorSaved'))
    } catch {
      setActionError(t('privacy.factorSetupFailed'))
    } finally {
      setFactorBusy(false)
    }
  }

  if (access.loading && !access.context) {
    return <div className="privacy-center"><div className="privacy-center__loading" role="status">{t('privacy.loading')}</div></div>
  }

  if (access.error && !access.context) {
    return <div className="privacy-center"><div className="privacy-access-message privacy-access-message--error" role="alert">{t('privacy.serviceUnavailable')}</div></div>
  }

  return (
    <div className="privacy-center">
      <div className="privacy-center__hero">
        <div className="privacy-center__hero-main">
          <span className="privacy-center__hero-icon" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3 5 6v5c0 4.5 2.8 7.9 7 10 4.2-2.1 7-5.5 7-10V6l-7-3Z" />
              <path d="m9.5 12 1.7 1.7 3.5-3.6" />
            </svg>
          </span>
          <div>
            <div className="privacy-access-kicker">{t('privacy.kicker')}</div>
            <h2>{t('privacy.centerTitle')}</h2>
            <p>{t('privacy.centerDescription')}</p>
          </div>
        </div>
        <div className="privacy-center__hero-side">
          <div className="privacy-center__pair" aria-label={t('privacy.twoPersonControl')}>
            <span>admin</span><b>+</b><span>audit</span>
          </div>
          <div className="privacy-center__secure-status">
            <span className="privacy-center__secure-dot" />
            <span>{policy.enabled ? t('privacy.defaultRedaction') : t('privacy.globalPolicyDisabled')}</span>
          </div>
        </div>
      </div>

      <div className="privacy-center__summary" aria-label={t('privacy.summaryLabel')}>
        <div className="privacy-center__summary-card">
          <span className="privacy-center__summary-icon privacy-center__summary-icon--cyan" aria-hidden="true">◌</span>
          <div>
            <span>{policy.enabled ? t('privacy.defaultRedaction') : t('privacy.globalPolicyDisabled')}</span>
            <strong>{policy.enabled ? t('privacy.defaultRedactionValue') : t('privacy.globalPolicyDisabledValue')}</strong>
            <small>{policy.enabled ? t('privacy.defaultRedactionHint') : t('privacy.globalPolicyDisabledHint')}</small>
          </div>
        </div>
        <div className="privacy-center__summary-card">
          <span className="privacy-center__summary-icon privacy-center__summary-icon--violet" aria-hidden="true">⇄</span>
          <div>
            <span>{t('privacy.approvalFlow')}</span>
            <strong>admin <i>→</i> audit</strong>
            <small>{t('privacy.approvalFlowHint')}</small>
          </div>
        </div>
        <div className="privacy-center__summary-card">
          <span className="privacy-center__summary-icon privacy-center__summary-icon--green" aria-hidden="true">◷</span>
          <div>
            <span>{t('privacy.leaseWindow')}</span>
            <strong>{t('privacy.leaseWindowValue')}</strong>
            <small>{t('privacy.leaseWindowHint')}</small>
          </div>
        </div>
      </div>

      {actionError && <div className="privacy-access-message privacy-access-message--error" role="alert">{actionError}</div>}
      {actionMessage && <div className="privacy-access-message privacy-access-message--success" role="status">{actionMessage}</div>}

      <section className="privacy-factor-setup privacy-surface" aria-labelledby="privacy-global-policy-title">
        <div className="privacy-section-heading">
          <span className="privacy-section-icon privacy-section-icon--cyan" aria-hidden="true">00</span>
          <div>
            <span className="privacy-section-kicker">{t('privacy.globalPolicyStep')}</span>
            <h3 id="privacy-global-policy-title">{t('privacy.globalPolicyTitle')}</h3>
            <p>{t('privacy.globalPolicyDescription')}</p>
          </div>
        </div>
        <div className="privacy-factor-setup__form">
          <div className="privacy-form-field">
            <span>{t('privacy.globalPolicyStatus')}</span>
            <strong>{policy.enabled ? t('privacy.globalPolicyEnabled') : t('privacy.globalPolicyDisabled')}</strong>
            <small>{policy.error ? t('privacy.globalPolicyUnavailable') : (policy.enabled ? t('privacy.globalPolicyEnabledHint') : t('privacy.globalPolicyDisabledHint'))}</small>
          </div>
          <span className="privacy-access-message" role="note">{t('privacy.globalPolicyEnforced')}</span>
        </div>
      </section>

      {(access.isAdmin || access.isAudit) && (
        <section className="privacy-factor-setup privacy-surface" aria-labelledby="privacy-factor-setup-title">
          <div className="privacy-section-heading">
            <span className="privacy-section-icon privacy-section-icon--amber" aria-hidden="true">01</span>
            <div>
              <span className="privacy-section-kicker">{t('privacy.factorSetupStep')}</span>
              <h3 id="privacy-factor-setup-title">{t('privacy.factorSetupTitle')}</h3>
              <p>{t(access.context?.current_user.factor_configured ? 'privacy.factorRotationDescription' : 'privacy.factorSetupDescription')}</p>
            </div>
          </div>
          <form className="privacy-factor-setup__form" onSubmit={saveOperatorFactor}>
            {access.context?.current_user.factor_configured && (
              <label className="privacy-form-field">
                <span>{t('privacy.currentFactorLabel')}</span>
                <input type="password" value={currentOperatorFactor} onChange={event => setCurrentOperatorFactor(event.target.value)} autoComplete="current-password" spellCheck={false} minLength={12} maxLength={4096} required />
              </label>
            )}
            <label className="privacy-form-field">
              <span>{t('privacy.factorLabel')}</span>
              <input type="password" value={operatorFactor} onChange={event => setOperatorFactor(event.target.value)} autoComplete="new-password" spellCheck={false} minLength={12} maxLength={4096} required />
            </label>
            <label className="privacy-form-field">
              <span>{t('privacy.factorConfirmLabel')}</span>
              <input type="password" value={operatorFactorConfirmation} onChange={event => setOperatorFactorConfirmation(event.target.value)} autoComplete="new-password" spellCheck={false} minLength={12} maxLength={4096} required />
            </label>
            <button type="submit" className="privacy-access-button privacy-access-button--quiet" disabled={factorBusy || operatorFactor.length < 12 || operatorFactor !== operatorFactorConfirmation || (Boolean(access.context?.current_user.factor_configured) && currentOperatorFactor.length < 12)}>
              {factorBusy ? t('privacy.factorSaving') : t(access.context?.current_user.factor_configured ? 'privacy.factorRotate' : 'privacy.factorSave')}
            </button>
          </form>
        </section>
      )}

      {access.isAudit && (
        <section className="privacy-approval-queue privacy-surface" aria-labelledby="privacy-approval-queue-title">
          <div className="privacy-approval-queue__header">
            <div className="privacy-section-heading">
              <span className="privacy-section-icon privacy-section-icon--violet" aria-hidden="true">02</span>
              <div>
                <span className="privacy-section-kicker">{t('privacy.approvalQueueStep')}</span>
                <h3 id="privacy-approval-queue-title">{t('privacy.approvalQueueTitle')}</h3>
                <p>{t('privacy.approvalQueueDescription')}</p>
              </div>
            </div>
            <div className="privacy-approval-queue__tools">
              <span className="privacy-queue-count">{pendingRequests.length}</span>
              <button type="button" className="privacy-access-button privacy-access-button--quiet" onClick={() => void access.refresh()}>{t('privacy.refresh')}</button>
            </div>
          </div>

          {pendingRequests.length === 0 ? (
            <div className="privacy-queue-empty" role="status">
              <span className="privacy-queue-empty__icon" aria-hidden="true">✓</span>
              <strong>{t('privacy.noPendingRequests')}</strong>
              <span>{t('privacy.noPendingHint')}</span>
            </div>
          ) : (
            <div className="privacy-queue-list">
              {pendingRequests.map(request => {
                const isSelected = selectedRequest === request.request_id
                return (
                  <article className="privacy-queue-item" key={request.request_id}>
                    <div className="privacy-queue-item__topline">
                      <div className="privacy-queue-item__identity">
                        <span className="privacy-queue-item__type">{request.resource_type}</span>
                        <span className="privacy-request-status__dot privacy-request-status__dot--requested" />
                        <span>{t('privacy.requestStatus.requested')}</span>
                      </div>
                      <span className="privacy-queue-item__age">{requestTime(request.created_at)}</span>
                    </div>
                    <div className="privacy-queue-item__resource">
                      <span>{t('privacy.resourceIdLabel')}</span>
                      <code>{request.resource_id}</code>
                    </div>
                    <div className="privacy-queue-item__meta">
                      <span>{t('privacy.requester')}: {request.requester_id}</span>
                      <span>{t('privacy.expiresAt')}: {requestTime(request.expires_at)}</span>
                    </div>
                    <div className="privacy-queue-item__scopes">
                      {request.scopes.map(scope => <span key={scope}>{t(`privacy.scope.${scope}`)}</span>)}
                    </div>
                    <p className="privacy-queue-item__purpose">{request.purpose}</p>
                    {isSelected ? (
                      <form className="privacy-approval-form" onSubmit={event => { event.preventDefault(); void approve(request.request_id) }}>
                        <label className="privacy-form-field">
                          <span>{t('privacy.auditFactorLabel')}</span>
                          <input
                            type="password"
                            value={factor}
                            onChange={event => setFactor(event.target.value)}
                            autoComplete="new-password"
                            spellCheck={false}
                            autoFocus
                          />
                        </label>
                        <div className="privacy-approval-form__actions">
                          <button type="button" className="privacy-access-button privacy-access-button--quiet" onClick={() => { setSelectedRequest(null); setFactor('') }}>{t('privacy.cancel')}</button>
                          <button type="submit" className="privacy-access-button" disabled={!factor || busyAction === request.request_id}>{busyAction === request.request_id ? t('privacy.approving') : t('privacy.approve')}</button>
                        </div>
                      </form>
                    ) : (
                      <div className="privacy-queue-item__actions">
                        <button type="button" className="privacy-access-button" onClick={() => setSelectedRequest(request.request_id)}>{t('privacy.approve')}</button>
                        <button type="button" className="privacy-access-button privacy-access-button--quiet" disabled={busyAction === request.request_id} onClick={() => void reject(request.request_id)}>{t('privacy.reject')}</button>
                      </div>
                    )}
                  </article>
                )
              })}
            </div>
          )}
        </section>
      )}

      {access.isAdmin && (
        <section className="privacy-admin-request privacy-surface" aria-labelledby="privacy-admin-request-title">
          <div className="privacy-approval-queue__header">
            <div className="privacy-section-heading">
              <span className="privacy-section-icon privacy-section-icon--cyan" aria-hidden="true">02</span>
              <div>
                <span className="privacy-section-kicker">{t('privacy.adminRequestStep')}</span>
                <h3 id="privacy-admin-request-title">{t('privacy.adminResourceTitle')}</h3>
                <p>{t('privacy.adminResourceDescription')}</p>
              </div>
            </div>
          </div>
          <div className="privacy-request-steps" aria-hidden="true">
            <span className="is-active"><b>01</b>{t('privacy.resourceTypeLabel')}</span>
            <i />
            <span><b>02</b>{t('privacy.scopeLabel')}</span>
            <i />
            <span><b>03</b>{t('privacy.purposeLabel')}</span>
          </div>
          <div className="privacy-resource-picker">
            <label className="privacy-form-field">
              <span>{t('privacy.resourceTypeLabel')}</span>
              <select value={resourceType} onChange={event => setResourceType(event.target.value as PrivacyResourceType)}>
                <option value="session">{t('privacy.resourceType.session')}</option>
                <option value="http_session">{t('privacy.resourceType.http_session')}</option>
                <option value="attachment">{t('privacy.resourceType.attachment')}</option>
              </select>
            </label>
            <label className="privacy-form-field privacy-resource-picker__id">
              <span>{t('privacy.resourceIdLabel')}</span>
              <input value={resourceId} onChange={event => setResourceId(event.target.value)} placeholder={t('privacy.resourceIdPlaceholder')} />
            </label>
          </div>
          {resourceId.trim() ? <PrivacyAccessPanel resource={{ resource_type: resourceType, resource_id: resourceId.trim() }} /> : (
            <div className="privacy-resource-empty">
              <span className="privacy-resource-empty__icon" aria-hidden="true">⌕</span>
              <div>
                <strong>{t('privacy.resourceIdRequired')}</strong>
                <span>{t('privacy.resourceIdHint')}</span>
              </div>
            </div>
          )}
        </section>
      )}

      {!access.isAudit && !access.isAdmin && <div className="privacy-access-message" role="note">{t('privacy.noPrivacyPermission')}</div>}
    </div>
  )
}
