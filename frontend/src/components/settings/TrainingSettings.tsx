import { useState, useEffect, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import i18n from '../../i18n'
import { apiFetch } from '../../utils/api'
import { formatDateFull } from '../../utils/format'

interface TrainingStats {
  total_samples: number
  label_counts: Record<string, number>
  model_version?: string
  has_finetuned?: boolean
  is_training?: boolean
  last_trained?: string | null
  min_samples_required: number
  can_train: boolean
}

interface TrainingSampleItem {
  id: string
  session_id: string
  label: number
  label_name: string
  subject: string | null
  mail_from: string | null
  analyst_comment: string | null
  created_at: string
}

const getLabelCnMap = (): Record<string, string> => ({
  legitimate: i18n.t('settings.training.labelLegitimate'),
  phishing: i18n.t('settings.training.labelPhishing'),
  spoofing: i18n.t('settings.training.labelSpoofing'),
  social_engineering: i18n.t('settings.training.labelSocialEngineering'),
  other_threat: i18n.t('settings.training.labelOtherThreat'),
})

const LABEL_COLOR_MAP: Record<string, string> = {
  legitimate: '#16a34a',
  phishing: '#dc2626',
  spoofing: '#be123c',
  social_engineering: '#b91c1c',
  other_threat: '#ea580c',
}

export default function TrainingSettings() {
  const { t } = useTranslation()
  const LABEL_CN_MAP = getLabelCnMap()

  const [trainingStats, setTrainingStats] = useState<TrainingStats | null>(null)
  const [trainingSamples, setTrainingSamples] = useState<TrainingSampleItem[]>([])
  const [trainingLoading, setTrainingLoading] = useState(false)
  const [trainingInProgress, setTrainingInProgress] = useState(false)
  const [trainingResult, setTrainingResult] = useState<string | null>(null)
  const [trainingSucceeded, setTrainingSucceeded] = useState(false)
  const [trainingProgress, setTrainingProgress] = useState<{
    active?: boolean
    phase?: string
    epoch?: number
    total_epochs?: number
    step?: number
    total_steps?: number
    loss?: number | null
    eval_loss?: number | null
    message?: string
    accuracy?: number
    macro_f1?: number
    total_samples?: number
    fold?: number
    total_folds?: number
  } | null>(null)
  const [editingSampleId, setEditingSampleId] = useState<string | null>(null)
  const [editingLabel, setEditingLabel] = useState<string>('')
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const lastProgressJson = useRef<string>('')
  const labelUpdateInFlight = useRef(false)

  const fetchTrainingData = useCallback(async () => {
    setTrainingLoading(true)
    try {
      const [statsResp, samplesResp] = await Promise.all([
        apiFetch('/api/admin/nlp/stats'),
        apiFetch('/api/admin/nlp/samples?limit=50&page=1'),
      ])
      if (statsResp.ok) {
        const data = await statsResp.json()
        setTrainingStats(data.success ? data.data : data)
      }
      if (samplesResp.ok) {
        const data = await samplesResp.json()
        setTrainingSamples(data.success ? (data.data || []) : (data || []))
      }
    } catch (e) {
      console.error('Failed to fetch training data:', e)
    } finally {
      setTrainingLoading(false)
    }
  }, [])

  // Fetch training data on mount
  useEffect(() => {
    fetchTrainingData()
  }, [fetchTrainingData])

  // Cleanup polling interval on unmount
  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
    }
  }, [])

  const handleDeleteSample = async (sampleId: string) => {
    try {
      const resp = await apiFetch(`/api/admin/nlp/samples/${sampleId}`, { method: 'DELETE' })
      if (resp.ok) {
        setTrainingSamples(prev => prev.filter(s => s.id !== sampleId))
        // Only refresh stats (label_counts changed), skip re-fetching the full sample list
        try {
          const statsResp = await apiFetch('/api/admin/nlp/stats')
          if (statsResp.ok) {
            const d = await statsResp.json()
            setTrainingStats(d.success ? d.data : d)
          }
        } catch { /* ignore */ }
      }
    } catch (e) {
      console.error('Failed to delete sample:', e)
    }
  }

  const handleTriggerTraining = async () => {
    setTrainingInProgress(true)
    setTrainingResult(null)
    setTrainingSucceeded(false)
    setTrainingProgress(null)
    lastProgressJson.current = ''

    // Clear any previous polling interval
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current)
    }

    // Start progress polling (every 2 seconds); skip re-render if the data is unchanged
    pollIntervalRef.current = setInterval(async () => {
      try {
        const resp = await apiFetch('/api/admin/nlp/progress')
        if (resp.ok) {
          const data = await resp.json()
          const progress = data.success ? data.data : data
          if (progress?.active) {
            const json = JSON.stringify(progress)
            if (json !== lastProgressJson.current) {
              lastProgressJson.current = json
              setTrainingProgress(progress)
            }
          }
        }
      } catch {
        /* ignore polling errors */
      }
    }, 2000)

    try {
      const resp = await apiFetch('/api/admin/nlp/train', { method: 'POST' })
      const data = await resp.json()
      const result = data.success ? data.data : data
      if (result?.ok) {
        setTrainingSucceeded(true)
        setTrainingResult(t('settings.training.trainComplete', { version: result.version, accuracy: (result.accuracy * 100).toFixed(1), f1: (result.macro_f1 * 100).toFixed(1), duration: result.train_duration_s }))
      } else {
        setTrainingSucceeded(false)
        setTrainingResult(t('settings.training.trainFailed', { error: result?.error || t('settings.training.unknownError') }))
      }
      fetchTrainingData()
    } catch (e) {
      setTrainingResult(t('settings.training.trainFailed', { error: e }))
    } finally {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
      setTrainingInProgress(false)
      setTrainingProgress(null)
    }
  }

  const handleUpdateSampleLabel = async (sampleId: string, newLabelName: string) => {
    labelUpdateInFlight.current = true
    try {
      const resp = await apiFetch(`/api/admin/nlp/samples/${sampleId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label_name: newLabelName }),
      })
      if (resp.ok) {
        const data = await resp.json()
        const result = data.success ? data.data : data
        if (result?.updated) {
          // Update only the labels in local state; stats refresh on the next tab switch
          setTrainingSamples(prev =>
            prev.map(s =>
              s.id === sampleId
                ? { ...s, label: result.label, label_name: result.label_name }
                : s
            )
          )
          // Refresh only the statistic counters (label_counts changed) without reloading the sample list
          try {
            const statsResp = await apiFetch('/api/admin/nlp/stats')
            if (statsResp.ok) {
              const d = await statsResp.json()
              setTrainingStats(d.success ? d.data : d)
            }
          } catch { /* ignore */ }
        }
      }
    } catch (e) {
      console.error('Failed to update sample label:', e)
    } finally {
      labelUpdateInFlight.current = false
      setEditingSampleId(null)
      setEditingLabel('')
    }
  }

  return (
    <div className="s-section-content">
      <div className="s-section-title-block">
        <h2 className="s-section-title-row">
          <span className="s-section-icon training">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
          </span>
          {t('settings.training.title')}
        </h2>
        <p className="s-section-subtitle">{t('settings.training.subtitle')}</p>
      </div>

      {trainingLoading && !trainingStats ? (
        <p className="s-loading-hint">{t('settings.training.loading')}</p>
      ) : trainingStats ? (
        <>
          {/* Model status */}
          <div className="s-train-card">
            <h3 className="s-train-card-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
              {t('settings.training.modelStatus')}
            </h3>
            <div className="s-model-grid">
              <div className="s-model-stat">
                <span className="s-model-stat-label">{t('settings.training.currentVersion')}</span>
                <span className="s-model-stat-value">{trainingStats.model_version || 'base'}</span>
              </div>
              <div className="s-model-stat">
                <span className="s-model-stat-label">{t('settings.training.finetuned')}</span>
                <span className="s-model-stat-value">{trainingStats.has_finetuned ? t('settings.training.yes') : t('settings.training.no')}</span>
              </div>
              <div className="s-model-stat">
                <span className="s-model-stat-label">{t('settings.training.lastTrained')}</span>
                <span className="s-model-stat-value">{trainingStats.last_trained ? formatDateFull(trainingStats.last_trained) : t('settings.training.none')}</span>
              </div>
            </div>
          </div>

          {/* Training-data statistics */}
          <div className="s-train-card">
            <h3 className="s-train-card-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
              {t('settings.training.trainingData')} ({trainingStats.total_samples} / {trainingStats.min_samples_required} {t('settings.training.samples')})
            </h3>
            <div className="s-label-badges">
              {Object.entries(LABEL_CN_MAP).map(([key, cn]) => {
                const count = trainingStats.label_counts?.[key] || 0
                return (
                  <span key={key} className="s-label-badge" style={{
                    background: LABEL_COLOR_MAP[key] + '18',
                    color: LABEL_COLOR_MAP[key],
                  }}>
                    {cn}: {count}
                  </span>
                )
              })}
            </div>
            <div className="s-progress-track">
              <div className="s-progress-fill" style={{
                width: `${Math.min(100, (trainingStats.total_samples / trainingStats.min_samples_required) * 100)}%`,
                background: trainingStats.can_train ? '#16a34a' : '#f59e0b',
              }} />
            </div>
          </div>

          {/* Training controls */}
          <div className="s-train-card">
            <h3 className="s-train-card-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
              {t('settings.training.trainingControl')}
            </h3>
            <button
              className={`s-train-btn ${trainingStats.can_train && !trainingInProgress ? 'ready' : 'disabled'}`}
              disabled={!trainingStats.can_train || trainingInProgress || trainingStats.is_training}
              onClick={handleTriggerTraining}
            >
              {trainingInProgress || trainingStats.is_training ? (
                <>
                  <svg className="s-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
                  {t('settings.training.trainingInProgress')}
                </>
              ) : trainingStats.can_train ? (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                  {t('settings.training.startTraining')}
                </>
              ) : t('settings.training.insufficientSamples', { count: trainingStats.min_samples_required })}
            </button>

            {/* Training progress */}
            {(trainingInProgress || trainingStats.is_training) && trainingProgress?.active && (
              <div className="s-train-progress">
                <div className="s-train-progress-header">
                  <span className="s-train-progress-phase">
                    {trainingProgress.phase === 'preprocessing' && t('settings.training.phasePreprocessing')}
                    {trainingProgress.phase === 'cross_validation' && (
                      trainingProgress.fold != null
                        ? t('settings.training.phaseCrossValidationFold', { fold: trainingProgress.fold, total: trainingProgress.total_folds || '?' })
                        : t('settings.training.phaseCrossValidationStart')
                    )}
                    {trainingProgress.phase === 'training' && trainingProgress.epoch != null &&
                      t('settings.training.phaseTrainingEpoch', { epoch: trainingProgress.epoch, totalEpochs: trainingProgress.total_epochs || '?', foldInfo: trainingProgress.fold != null ? ` (Fold ${trainingProgress.fold}/${trainingProgress.total_folds})` : '' })}
                    {trainingProgress.phase === 'quality_check' && t('settings.training.phaseQualityCheck')}
                    {trainingProgress.phase === 'final_training' && t('settings.training.phaseFinalTraining')}
                    {trainingProgress.phase === 'saving' && t('settings.training.phaseSaving')}
                    {trainingProgress.phase === 'initializing' && t('settings.training.phaseInitializing')}
                    {!trainingProgress.phase && t('settings.training.trainingInProgress')}
                  </span>
                  {trainingProgress.total_samples != null && (
                    <span className="s-train-progress-meta">{trainingProgress.total_samples} {t('settings.training.samples')}</span>
                  )}
                </div>

                {trainingProgress.phase === 'training' && trainingProgress.total_steps != null && trainingProgress.total_steps > 0 && (
                  <div>
                    <div className="s-progress-track">
                      <div className="s-progress-fill" style={{
                        width: `${Math.min(100, ((trainingProgress.step || 0) / trainingProgress.total_steps) * 100)}%`,
                        background: '#3b82f6',
                        transition: 'width 0.5s ease',
                      }} />
                    </div>
                    <div className="s-train-progress-stats">
                      <span>Step {trainingProgress.step || 0}/{trainingProgress.total_steps}</span>
                      {trainingProgress.loss != null && <span>Loss: {trainingProgress.loss.toFixed(4)}</span>}
                      {trainingProgress.eval_loss != null && <span>Val Loss: {trainingProgress.eval_loss.toFixed(4)}</span>}
                    </div>
                  </div>
                )}

                {trainingProgress.phase !== 'training' && (
                  <div className="s-progress-track">
                    <div className="s-pulse-bar" />
                  </div>
                )}

                {trainingProgress.message && (
                  <p className="s-train-progress-msg">{trainingProgress.message}</p>
                )}
              </div>
            )}

            {trainingResult && (
              <p className={`s-train-result ${trainingSucceeded ? 'success' : 'error'}`}>
                {trainingResult}
              </p>
            )}
          </div>

          {/* Recent samples */}
          <div className="s-train-card">
            <h3 className="s-train-card-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              {t('settings.training.recentSamples')}
            </h3>
            {trainingSamples.length === 0 ? (
              <div className="s-empty-state">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                <span>{t('settings.training.noSamples')}</span>
                <span className="s-empty-state-sub">{t('settings.training.noSamplesHint')}</span>
              </div>
            ) : (
              <div className="s-sample-table-wrap">
                <table className="s-sample-table">
                  <thead>
                    <tr>
                      <th>{t('settings.training.colTime')}</th>
                      <th>{t('settings.training.colCategory')}</th>
                      <th>{t('settings.training.colSubject')}</th>
                      <th>{t('settings.training.colFrom')}</th>
                      <th>{t('settings.training.colAction')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trainingSamples.map(sample => (
                      <tr key={sample.id}>
                        <td className="s-td-time">
                          {formatDateFull(sample.created_at)}
                        </td>
                        <td>
                          {editingSampleId === sample.id ? (
                            <select
                              className="s-sample-label-select"
                              value={editingLabel}
                              onChange={e => {
                                handleUpdateSampleLabel(sample.id, e.target.value)
                              }}
                              onBlur={() => {
                                setTimeout(() => {
                                  if (!labelUpdateInFlight.current) {
                                    setEditingSampleId(null)
                                    setEditingLabel('')
                                  }
                                }, 150)
                              }}
                              autoFocus
                            >
                              {Object.entries(LABEL_CN_MAP).map(([key, cn]) => (
                                <option key={key} value={key}>{cn}</option>
                              ))}
                            </select>
                          ) : (
                            <span
                              className="s-sample-label-tag"
                              style={{
                                background: (LABEL_COLOR_MAP[sample.label_name] || '#6b7280') + '18',
                                color: LABEL_COLOR_MAP[sample.label_name] || '#6b7280',
                              }}
                              title={t('settings.training.clickToChangeLabel')}
                              onClick={() => { setEditingSampleId(sample.id); setEditingLabel(sample.label_name) }}
                            >
                              {LABEL_CN_MAP[sample.label_name] || sample.label_name}
                            </span>
                          )}
                        </td>
                        <td className="s-td-subject">
                          {sample.subject || '-'}
                        </td>
                        <td className="s-td-from">
                          {sample.mail_from || '-'}
                        </td>
                        <td className="s-td-actions">
                          <button
                            className="s-sample-delete-btn"
                            onClick={() => handleDeleteSample(sample.id)}
                          >
                            {t('settings.training.delete')}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      ) : (
        <p className="s-empty-hint">{t('settings.training.loadFailed')}</p>
      )}
    </div>
  )
}
