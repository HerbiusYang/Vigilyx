import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { ModuleMetadata, PipelineConfig, ModuleConfig, ContentRules, EngineStatus, VerdictConfig } from '../../types'
import PipelineGraph from './PipelineGraph'

interface PipelineTabProps {
  modules: ModuleMetadata[]
  engineStatus: EngineStatus | null
  pipelineConfig: PipelineConfig | null
  contentRules: ContentRules | null
  notice: string | null
  onToggleModule: (moduleId: string) => void
  onChangeMode: (moduleId: string, mode: ModuleConfig['mode']) => void
  onSaveThresholds: (patch: Partial<VerdictConfig>) => Promise<{ ok: boolean; error?: string }>
}

type ThresholdKey =
  | 'alert_floor_factor'
  | 'convergence_base_floor'
  | 'convergence_belief_threshold'
  | 'alert_belief_threshold'
  | 'default_epsilon'

interface ThresholdField {
  key: ThresholdKey
  labelKey: string
  hintKey: string
  min: number
  max: number
  /** When true, the lower bound is exclusive (value must be > min). */
  minExclusive?: boolean
  step: number
  /** Human-readable range for validation error messages. */
  rangeLabel: string
}

// Ranges mirror VerdictConfig::validate() in crates/vigilyx-engine/src/pipeline/config.rs
// (AGENTS.md rules: alert_floor_factor >= 1.0, convergence_base_floor >= 0.40,
// convergence_belief_threshold <= 0.10).
const THRESHOLD_FIELDS: ThresholdField[] = [
  {
    key: 'alert_floor_factor',
    labelKey: 'pipeline.alertFloorFactor',
    hintKey: 'pipeline.alertFloorFactorHint',
    min: 1.0,
    max: 3.0,
    step: 0.01,
    rangeLabel: '1.00 – 3.00',
  },
  {
    key: 'convergence_base_floor',
    labelKey: 'pipeline.convergenceBaseFloor',
    hintKey: 'pipeline.convergenceBaseFloorHint',
    min: 0.4,
    max: 0.85,
    step: 0.01,
    rangeLabel: '0.40 – 0.85',
  },
  {
    key: 'convergence_belief_threshold',
    labelKey: 'pipeline.convergenceBeliefThreshold',
    hintKey: 'pipeline.convergenceBeliefThresholdHint',
    min: 0.0,
    max: 0.1,
    minExclusive: true,
    step: 0.01,
    rangeLabel: '(0, 0.10]',
  },
  {
    key: 'alert_belief_threshold',
    labelKey: 'pipeline.alertBeliefThreshold',
    hintKey: 'pipeline.alertBeliefThresholdHint',
    min: 0.0,
    max: 0.6,
    step: 0.01,
    rangeLabel: '0.00 – 0.60',
  },
  {
    key: 'default_epsilon',
    labelKey: 'pipeline.epsilon',
    hintKey: 'pipeline.epsilonHint',
    min: 0.0,
    max: 0.5,
    minExclusive: true,
    step: 0.01,
    rangeLabel: '(0, 0.50]',
  },
]

type ThresholdDraft = Record<ThresholdKey, string>

function draftFromConfig(config: PipelineConfig): ThresholdDraft {
  const vc = config.verdict_config
  return {
    alert_floor_factor: String(vc.alert_floor_factor),
    convergence_base_floor: String(vc.convergence_base_floor),
    convergence_belief_threshold: String(vc.convergence_belief_threshold),
    alert_belief_threshold: String(vc.alert_belief_threshold),
    default_epsilon: String(vc.default_epsilon),
  }
}

export default function PipelineTab({
  modules,
  engineStatus,
  pipelineConfig,
  contentRules,
  notice,
  onToggleModule,
  onChangeMode,
  onSaveThresholds,
}: PipelineTabProps) {
  const { t } = useTranslation()
  const [thresholdDraft, setThresholdDraft] = useState<ThresholdDraft | null>(null)
  const [savingThresholds, setSavingThresholds] = useState(false)
  const [thresholdMsg, setThresholdMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // Sync the draft whenever the parent config changes (initial load, save revert).
  useEffect(() => {
    if (pipelineConfig) setThresholdDraft(draftFromConfig(pipelineConfig))
  }, [pipelineConfig])

  const saveThresholds = async () => {
    if (!thresholdDraft) return
    const patch: Partial<VerdictConfig> = {}
    for (const field of THRESHOLD_FIELDS) {
      const raw = thresholdDraft[field.key].trim()
      const value = Number(raw)
      if (raw === '' || !Number.isFinite(value)) {
        setThresholdMsg({ ok: false, text: t('pipeline.invalidNumber', { name: t(field.labelKey) }) })
        return
      }
      const belowMin = field.minExclusive ? value <= field.min : value < field.min
      if (belowMin || value > field.max) {
        setThresholdMsg({
          ok: false,
          text: t('pipeline.rangeError', { name: t(field.labelKey), range: field.rangeLabel }),
        })
        return
      }
      patch[field.key] = value
    }

    setSavingThresholds(true)
    setThresholdMsg(null)
    try {
      const result = await onSaveThresholds(patch)
      if (result.ok) {
        setThresholdMsg({ ok: true, text: t('saveSuccess') })
      } else {
        setThresholdMsg({ ok: false, text: result.error || t('saveFailed') })
      }
    } catch (e) {
      console.error('Failed to save verdict thresholds:', e)
      setThresholdMsg({ ok: false, text: t('networkError') })
    } finally {
      setSavingThresholds(false)
    }
  }

  return (
    <>
      {notice && (
        <div
          role="status"
          aria-live="polite"
          style={{
            marginBottom: '12px',
            padding: '10px 14px',
            border: '1px solid var(--status-warning)',
            borderRadius: '8px',
            color: 'var(--status-warning)',
          }}
        >
          {notice}
        </div>
      )}
      <PipelineGraph
        modules={modules}
        engineStatus={engineStatus}
        pipelineConfig={pipelineConfig}
        contentRules={contentRules}
        onToggleModule={onToggleModule}
        onChangeMode={onChangeMode}
      />

      {/* Verdict thresholds */}
      {thresholdDraft && (
        <div className="sec-ai-config" style={{ marginTop: 16 }}>
          <div className="sec-ai-section">
            <div className="sec-ai-section-header">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/>
                <line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/>
                <line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/>
                <line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>
              </svg>
              <span>{t('pipeline.thresholdsTitle')}</span>
            </div>
            <div className="sec-ai-section-body">
              <p className="sec-form-hint" style={{ marginTop: 0 }}>{t('pipeline.thresholdsHint')}</p>
              <div className="sec-form-row sec-form-row--3">
                {THRESHOLD_FIELDS.map(field => (
                  <div className="sec-form-group" key={field.key}>
                    <label className="sec-form-label">{t(field.labelKey)}</label>
                    <input
                      type="number"
                      className="sec-form-input"
                      min={field.min}
                      max={field.max}
                      step={field.step}
                      value={thresholdDraft[field.key]}
                      onChange={e => {
                        setThresholdMsg(null)
                        setThresholdDraft({ ...thresholdDraft, [field.key]: e.target.value })
                      }}
                    />
                    <span className="sec-form-hint">{t(field.hintKey)}</span>
                  </div>
                ))}
              </div>
              {thresholdMsg && (
                <div
                  className={thresholdMsg.ok ? 's-deploy-success' : ''}
                  style={thresholdMsg.ok ? { marginTop: 16 } : { color: '#ef4444', fontSize: 12, marginTop: 16, marginBottom: 8 }}
                >
                  {thresholdMsg.text}
                </div>
              )}
              <div className="intel-save-bar">
                <button
                  className="sec-btn sec-btn--primary"
                  onClick={saveThresholds}
                  disabled={savingThresholds}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>
                  </svg>
                  {savingThresholds ? t('emailSecurity.saving') : t('pipeline.saveThresholds')}
                </button>
                <span className="intel-save-hint">{t('pipeline.saveThresholdsHint')}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
