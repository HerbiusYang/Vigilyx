import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { ApiResponse } from '../../types'
import type { DsLearningState } from '../../types/feedback'

import { apiFetch } from '../../utils/api'

const VALIDATION_KEYS: Record<string, string> = {
  candidate_unvalidated: 'emailSecurity.dsLearningValidationRequired',
  awaiting_feedback: 'emailSecurity.dsLearningAwaitingFeedback',
  insufficient_evidence: 'emailSecurity.dsLearningInsufficientEvidence',
}
const GATE_KEYS: Record<string, string> = {
  both_classes: 'emailSecurity.dsLearningGateBothClasses',
  independent_calibration: 'emailSecurity.dsLearningGateCalibration',
  sealed_holdout: 'emailSecurity.dsLearningGateHoldout',
  capability_preservation: 'emailSecurity.dsLearningGateCapabilities',
}

export default function DsLearningStatus({ refreshToken }: { refreshToken: unknown }) {
  const { t } = useTranslation()
  const [state, setState] = useState<DsLearningState | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(false)
  const runRef = useRef(0)
  const refresh = useCallback(async () => {
    const run = ++runRef.current
    setLoading(true)
    setError(false)
    try {
      const response = await apiFetch('/api/security/ds-learning')
      const body: ApiResponse<DsLearningState> = await response.json()
      if (!body.success || !body.data || body.data.schema_version !== 1) throw new Error('Invalid learning state')
      if (run === runRef.current) setState(body.data)
    } catch {
      if (run === runRef.current) setError(true)
    } finally {
      if (run === runRef.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
    return () => { runRef.current += 1 }
  }, [refresh, refreshToken])

  const sources = Object.entries(state?.candidate?.sources ?? {}).sort(([left], [right]) => left.localeCompare(right))
  const number = (value: number) => Number.isFinite(value) ? value.toFixed(4) : '—'
  return (
    <section className="email-feedback-learning" aria-label={t('emailSecurity.dsLearningTitle')}>
      <div className="email-feedback-heading">
        <h4>{t('emailSecurity.dsLearningTitle')}</h4>
        <button type="button" onClick={() => void refresh()} disabled={loading}>
          {t(loading ? 'emailSecurity.dsLearningLoading' : 'emailSecurity.dsLearningRefresh')}
        </button>
      </div>
      {error && <p role="alert">{t('emailSecurity.dsLearningError')}</p>}
      {state && <>
        <p>{t('emailSecurity.dsLearningCounts', { limit: state.sample_window_limit, recorded: state.feedback_count, eligible: state.eligible_count, excluded: state.excluded_count })}</p>
        <p>{t('emailSecurity.dsLearningCandidate')}: {state.candidate?.parameter_version ?? t('emailSecurity.dsLearningNoCandidate')}</p>
        <p>{t('emailSecurity.dsLearningActive')}: {state.active?.parameter_version ?? t('emailSecurity.dsLearningInitial')}</p>
        <p>{t('emailSecurity.dsLearningValidation')}: {t(VALIDATION_KEYS[state.validation_status] ?? 'emailSecurity.dsLearningValidationRequired')}</p>
        {state.pending_gates?.length > 0 && <p>{t('emailSecurity.dsLearningPendingGates')}: {Array.from(new Set(
          state.pending_gates.map(gate => t(GATE_KEYS[gate] ?? 'emailSecurity.dsLearningValidationRequired')),
        )).join(' · ')}</p>}
        <p>{t('emailSecurity.dsLearningCandidateHint')}</p>
        {sources.length > 0 && <details>
          <summary>{t('emailSecurity.dsLearningParameters', { count: Math.min(sources.length, 12), total: sources.length })}</summary>
          <div className="email-feedback-history"><table>
            <thead><tr><th>{t('emailSecurity.dsLearningSource')}</th><th>{t('emailSecurity.dsLearningSlope')}</th>
              <th>{t('emailSecurity.dsLearningIntercept')}</th><th>{t('emailSecurity.dsLearningReliability')}</th></tr></thead>
            <tbody>{sources.slice(0, 12).map(([source, parameters]) => <tr key={source}>
              <td>{source}</td><td>{number(parameters.slope)}</td><td>{number(parameters.intercept)}</td><td>{number(parameters.reliability)}</td>
            </tr>)}</tbody>
          </table></div>
        </details>}
      </>}
    </section>
  )
}
