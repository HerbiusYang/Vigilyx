import { useState, useEffect, useCallback, useRef } from 'react'
import { apiFetch } from '../../utils/api'

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

const LABEL_CN_MAP: Record<string, string> = {
  legitimate: '正常邮件',
  phishing: '钓鱼邮件',
  spoofing: '仿冒邮件',
  social_engineering: '社会工程学',
  other_threat: '其他威胁',
}

const LABEL_COLOR_MAP: Record<string, string> = {
  legitimate: '#16a34a',
  phishing: '#dc2626',
  spoofing: '#be123c',
  social_engineering: '#b91c1c',
  other_threat: '#ea580c',
}

export default function TrainingSettings() {
  const [trainingStats, setTrainingStats] = useState<TrainingStats | null>(null)
  const [trainingSamples, setTrainingSamples] = useState<TrainingSampleItem[]>([])
  const [trainingLoading, setTrainingLoading] = useState(false)
  const [trainingInProgress, setTrainingInProgress] = useState(false)
  const [trainingResult, setTrainingResult] = useState<string | null>(null)
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
        setTrainingResult(`训练完成! 模型 ${result.version}, 准确率 ${(result.accuracy * 100).toFixed(1)}%, F1 ${(result.macro_f1 * 100).toFixed(1)}%, 耗时 ${result.train_duration_s}s`)
      } else {
        setTrainingResult(`训练失败: ${result?.error || '未知错误'}`)
      }
      fetchTrainingData()
    } catch (e) {
      setTrainingResult(`训练失败: ${e}`)
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
          NLP 模型训练
        </h2>
        <p className="s-section-subtitle">管理训练样本和触发五分类 fine-tuning，持续提升检测能力</p>
      </div>

      {trainingLoading && !trainingStats ? (
        <p className="s-loading-hint">加载中...</p>
      ) : trainingStats ? (
        <>
          {/* Model status */}
          <div className="s-train-card">
            <h3 className="s-train-card-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
              模型状态
            </h3>
            <div className="s-model-grid">
              <div className="s-model-stat">
                <span className="s-model-stat-label">当前版本</span>
                <span className="s-model-stat-value">{trainingStats.model_version || 'base'}</span>
              </div>
              <div className="s-model-stat">
                <span className="s-model-stat-label">已 Fine-tuned</span>
                <span className="s-model-stat-value">{trainingStats.has_finetuned ? '是' : '否'}</span>
              </div>
              <div className="s-model-stat">
                <span className="s-model-stat-label">上次训练</span>
                <span className="s-model-stat-value">{trainingStats.last_trained ? new Date(trainingStats.last_trained).toLocaleString() : '无'}</span>
              </div>
            </div>
          </div>

          {/* Training-data statistics */}
          <div className="s-train-card">
            <h3 className="s-train-card-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
              训练数据 ({trainingStats.total_samples} / {trainingStats.min_samples_required} 样本)
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
              训练控制
            </h3>
            <button
              className={`s-train-btn ${trainingStats.can_train && !trainingInProgress ? 'ready' : 'disabled'}`}
              disabled={!trainingStats.can_train || trainingInProgress || trainingStats.is_training}
              onClick={handleTriggerTraining}
            >
              {trainingInProgress || trainingStats.is_training ? (
                <>
                  <svg className="s-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
                  训练中...
                </>
              ) : trainingStats.can_train ? (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                  开始训练
                </>
              ) : `样本不足 (需 ${trainingStats.min_samples_required} 条)`}
            </button>

            {/* Training progress */}
            {(trainingInProgress || trainingStats.is_training) && trainingProgress?.active && (
              <div className="s-train-progress">
                <div className="s-train-progress-header">
                  <span className="s-train-progress-phase">
                    {trainingProgress.phase === 'preprocessing' && '正在预处理邮件数据...'}
                    {trainingProgress.phase === 'cross_validation' && (
                      trainingProgress.fold != null
                        ? `交叉验证 — Fold ${trainingProgress.fold}/${trainingProgress.total_folds || '?'}`
                        : '正在启动交叉验证...'
                    )}
                    {trainingProgress.phase === 'training' && trainingProgress.epoch != null &&
                      `训练中 — Epoch ${trainingProgress.epoch}/${trainingProgress.total_epochs || '?'}${trainingProgress.fold != null ? ` (Fold ${trainingProgress.fold}/${trainingProgress.total_folds})` : ''}`}
                    {trainingProgress.phase === 'quality_check' && '正在评估模型质量...'}
                    {trainingProgress.phase === 'final_training' && '质量达标，正在训练最终模型...'}
                    {trainingProgress.phase === 'saving' && '正在保存模型...'}
                    {trainingProgress.phase === 'initializing' && '正在初始化...'}
                    {!trainingProgress.phase && '训练中...'}
                  </span>
                  {trainingProgress.total_samples != null && (
                    <span className="s-train-progress-meta">{trainingProgress.total_samples} 样本</span>
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
              <p className={`s-train-result ${trainingResult.includes('完成') ? 'success' : 'error'}`}>
                {trainingResult}
              </p>
            )}
          </div>

          {/* Recent samples */}
          <div className="s-train-card">
            <h3 className="s-train-card-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
              最近训练样本
            </h3>
            {trainingSamples.length === 0 ? (
              <div className="s-empty-state">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                <span>暂无训练样本</span>
                <span className="s-empty-state-sub">在邮件详情页标注后，样本将自动出现在这里</span>
              </div>
            ) : (
              <div className="s-sample-table-wrap">
                <table className="s-sample-table">
                  <thead>
                    <tr>
                      <th>时间</th>
                      <th>分类</th>
                      <th>主题</th>
                      <th>发件人</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trainingSamples.map(sample => (
                      <tr key={sample.id}>
                        <td className="s-td-time">
                          {new Date(sample.created_at).toLocaleString()}
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
                              title="点击修改分类"
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
                            删除
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
        <p className="s-empty-hint">无法加载训练数据</p>
      )}
    </div>
  )
}
