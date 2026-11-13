import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { ApiResponse, SecurityVerdict } from '../../types'
import type { FeedbackSubmission, FeedbackSubmissionResult, FeedbackThreatLevel, FeedbackType, SessionFeedbackHistory } from '../../types/feedback'
import { apiFetch } from '../../utils/api'
import { formatDateFull } from '../../utils/format'
import { classificationLabel, threatTypeLabel } from './categoryLabels'
import DsLearningStatus from './DsLearningStatus'
import './FeedbackPanel.css'

const TYPE_KEYS: Record<FeedbackType, string> = {
  legitimate: 'emailSecurity.feedbackLegitimate',
  phishing: 'emailSecurity.feedbackPhishing',
  spoofing: 'emailSecurity.feedbackSpoofing',
  social_engineering: 'emailSecurity.feedbackSocialEng',
  other_threat: 'emailSecurity.feedbackOther',
}
const THREAT_LEVELS: FeedbackThreatLevel[] = ['safe', 'low', 'medium', 'high', 'critical']
const REASON_KEYS: Record<string, string> = {
  training_permission_missing: 'emailSecurity.feedbackReasonPermission',
  item_level_learning_evidence_missing: 'emailSecurity.feedbackReasonItemEvidence',
  corrected_severity_missing: 'emailSecurity.feedbackReasonSeverity',
  reviewed_verdict_missing: 'emailSecurity.feedbackReasonVerdict',
  immutable_learning_evidence_missing: 'emailSecurity.feedbackReasonSnapshot',
  retained_raw_mime_missing: 'emailSecurity.feedbackReasonOriginal',
  learning_evidence_exceeds_snapshot_limit: 'emailSecurity.feedbackReasonLimit',
  legacy_missing_snapshot: 'emailSecurity.feedbackReasonSnapshot',
  verdict_content_changed: 'emailSecurity.feedbackReasonContentChanged',
}

interface Props {
  sessionId: string
  verdict: SecurityVerdict | null
  open: boolean
  onClose: () => void
  onRefreshVerdict: () => Promise<unknown>
}

export default function FeedbackPanel({ sessionId, verdict, open, onClose, onRefreshVerdict }: Props) {
  const { t } = useTranslation()
  const formId = useId()
  const [feedbackType, setFeedbackType] = useState<FeedbackType | null>(null)
  const [level, setLevel] = useState<FeedbackThreatLevel | null>(null)
  const [comment, setComment] = useState('')
  const [reviewVerdict, setReviewVerdict] = useState<SecurityVerdict | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<FeedbackSubmissionResult | null>(null)
  const [history, setHistory] = useState<SessionFeedbackHistory | null>(null)
  const [historyLoading, setHistoryLoading] = useState(false)
  const [historyError, setHistoryError] = useState(false)
  const inFlight = useRef(false)
  const historyRun = useRef(0)
  const mounted = useRef(true)
  const panelRef = useRef<HTMLElement>(null)

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false; historyRun.current += 1 }
  }, [])

  const loadHistory = useCallback(async () => {
    const run = ++historyRun.current
    setHistoryLoading(true)
    setHistoryError(false)
    try {
      const response = await apiFetch(`/api/sessions/${sessionId}/feedback`)
      const body: ApiResponse<SessionFeedbackHistory> = await response.json()
      if (!body.success || !body.data || !Array.isArray(body.data.feedbacks)) throw new Error('Invalid feedback history')
      if (mounted.current && run === historyRun.current) setHistory(body.data)
    } catch {
      if (mounted.current && run === historyRun.current) setHistoryError(true)
    } finally {
      if (mounted.current && run === historyRun.current) setHistoryLoading(false)
    }
  }, [sessionId])

  useEffect(() => { if (open) void loadHistory() }, [open, loadHistory])
  useEffect(() => { if (open) panelRef.current?.scrollIntoView?.({ block: 'nearest' }) }, [open])

  const stale = Boolean(feedbackType && reviewVerdict?.id !== verdict?.id)
  const validLevel = feedbackType === 'legitimate' ? level === 'safe' : Boolean(level && level !== 'safe')
  const canSubmit = Boolean(feedbackType && validLevel && reviewVerdict && !stale && !submitting && !result)
  const original = reviewVerdict ?? verdict

  const selectType = (type: FeedbackType) => {
    setFeedbackType(type)
    // Every submitted label must be an explicit analyst choice, including confirmations.
    setLevel(null)
    setReviewVerdict(verdict)
    setError(null)
    setResult(null)
  }

  const submit = async () => {
    if (inFlight.current || !canSubmit || !feedbackType || !reviewVerdict) return
    inFlight.current = true
    setSubmitting(true)
    setError(null)
    const payload: FeedbackSubmission = {
      feedback_type: feedbackType,
      corrected_threat_level: level,
      expected_verdict_id: reviewVerdict.id,
      comment: comment.trim() || null,
    }
    try {
      const response = await apiFetch(`/api/sessions/${sessionId}/feedback`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
      })
      const body: ApiResponse<FeedbackSubmissionResult> = await response.json()
      if (!body.success || !body.data || !['recorded', 'insufficient_evidence'].includes(body.data.learning_status)) {
        throw new Error(body.error || t('emailSecurity.feedbackSaveError'))
      }
      if (!mounted.current) return
      setResult(body.data)
      await loadHistory()
    } catch (failure) {
      if (!mounted.current) return
      setError(failure instanceof Error ? failure.message : t('emailSecurity.feedbackSaveError'))
      // Refresh the reference verdict after a rejected write; never silently rebase an analyst label.
      await onRefreshVerdict().catch(() => undefined)
    } finally {
      inFlight.current = false
      if (mounted.current) setSubmitting(false)
    }
  }

  if (!open) return null

  const learningStatus = result?.learning_status ?? history?.learning_status
  const learningReason = result ? result.learning_reason : history?.learning_reason
  return (
    <section ref={panelRef} className="email-feedback" aria-label={t('emailSecurity.feedbackReviewTitle')}>
      <div className="email-feedback-heading">
        <h3>{t('emailSecurity.feedbackReviewTitle')}</h3>
        <button type="button" onClick={onClose} disabled={submitting}>{t('emailSecurity.feedbackClose')}</button>
      </div>
      <p>{t('emailSecurity.feedbackReviewHint')}</p>
      <p className="email-feedback-original">
        {t('emailSecurity.feedbackOriginalVerdict')}: {original
          ? `${t(`emailSecurity.threat_${original.threat_level}`)} · ${(original.threat_type ? threatTypeLabel(original.threat_type) : classificationLabel(original.classification)) ?? t('emailSecurity.feedbackTypeUnknown')}`
          : t('emailSecurity.feedbackNoVerdict')}
      </p>
      <p>{t('emailSecurity.feedbackTrainingHint')}</p>
      {learningStatus && (
        <p role="status">{t(learningStatus === 'insufficient_evidence'
          ? 'emailSecurity.feedbackInsufficientEvidence' : 'emailSecurity.feedbackRecorded')}</p>
      )}
      {learningReason && <p>{t('emailSecurity.feedbackLearningReason')}: {t(REASON_KEYS[learningReason] ?? 'emailSecurity.feedbackReasonUnknown')}</p>}
      {error && <p role="alert">{t('emailSecurity.feedbackSaveError')}: {error}</p>}
      {stale && <p role="alert">{t('emailSecurity.feedbackStaleVerdict')}</p>}
      <div className="email-feedback-types" role="group" aria-label={t('emailSecurity.feedbackCorrectedType')}>
        {(Object.entries(TYPE_KEYS) as [FeedbackType, string][]).map(([type, key]) => (
          <button type="button" key={type} disabled={submitting || !verdict} aria-pressed={feedbackType === type}
            onClick={() => selectType(type)}>{t(key)}</button>
        ))}
      </div>
      {feedbackType && (
        <form onSubmit={event => { event.preventDefault(); void submit() }}>
          <label htmlFor={`${formId}-level`}>{t('emailSecurity.feedbackCorrectedLevel')}</label>
          <select id={`${formId}-level`} value={level ?? ''} required disabled={submitting || Boolean(result)}
            onChange={event => setLevel(event.target.value ? event.target.value as FeedbackThreatLevel : null)}>
            <option value="">{t('emailSecurity.feedbackChooseLevel')}</option>
            {THREAT_LEVELS.filter(item => feedbackType === 'legitimate' ? item === 'safe' : item !== 'safe').map(item => (
              <option key={item} value={item}>{t(`emailSecurity.threat_${item}`)}</option>
            ))}
          </select>
          <label htmlFor={`${formId}-comment`}>{t('emailSecurity.feedbackAddNote')}</label>
          <textarea id={`${formId}-comment`} value={comment} rows={2} disabled={submitting || Boolean(result)}
            placeholder={t('emailSecurity.feedbackPlaceholder')} onChange={event => setComment(event.target.value)} />
          <button type="submit" disabled={!canSubmit}>
            {submitting ? t('emailSecurity.feedbackSubmitting') : t('emailSecurity.feedbackSubmit')}
          </button>
        </form>
      )}
      <div className="email-feedback-history">
        <h4>{t('emailSecurity.feedbackHistoryTitle')}</h4>
        {historyLoading && <p>{t('emailSecurity.feedbackHistoryLoading')}</p>}
        {historyError && <p role="alert">{t('emailSecurity.feedbackHistoryError')} <button type="button" onClick={() => void loadHistory()}>{t('emailSecurity.feedbackRetry')}</button></p>}
        {!historyLoading && !historyError && history?.feedbacks.length === 0 && <p>{t('emailSecurity.feedbackHistoryEmpty')}</p>}
        {Boolean(history?.feedbacks.length) && <table>
          <thead><tr>
            <th>{t('emailSecurity.feedbackHistoryTime')}</th><th>{t('emailSecurity.feedbackCorrectedType')}</th>
            <th>{t('emailSecurity.feedbackOriginalLevel')}</th><th>{t('emailSecurity.feedbackCorrectedLevel')}</th>
            <th>{t('emailSecurity.feedbackHistoryStatus')}</th>
          </tr></thead>
          <tbody>{history!.feedbacks.map(item => <tr key={item.id}>
            <td>{formatDateFull(item.created_at)}</td><td>{t(TYPE_KEYS[item.feedback_type] ?? 'emailSecurity.feedbackOther')}</td>
            <td>{item.original_threat_level ? t(`emailSecurity.threat_${item.original_threat_level}`) : t('emailSecurity.feedbackLevelUnknown')}</td>
            <td>{item.corrected_threat_level ? t(`emailSecurity.threat_${item.corrected_threat_level}`) : t('emailSecurity.feedbackLevelUnknown')}</td>
            <td>{t(`emailSecurity.feedbackStatus_${item.status}`, { defaultValue: t('emailSecurity.feedbackStatus_recorded') })}</td>
          </tr>)}</tbody>
        </table>}
      </div>
      <DsLearningStatus refreshToken={result} />
    </section>
  )
}
