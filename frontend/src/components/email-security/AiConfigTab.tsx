import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { AiServiceConfig, EngineStatus, ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'

interface AiConfigTabProps {
  engineStatus: EngineStatus | null
  onStatsRefresh: () => void
}

export default function AiConfigTab({ engineStatus, onStatsRefresh }: AiConfigTabProps) {
  const { t } = useTranslation()
  const [aiConfig, setAiConfig] = useState<AiServiceConfig | null>(null)
  const [aiConfigDraft, setAiConfigDraft] = useState<AiServiceConfig | null>(null)
  const [savingAi, setSavingAi] = useState(false)
  const [testingAi, setTestingAi] = useState(false)
  const [aiTestResult, setAiTestResult] = useState<{ reachable: boolean; tested: boolean } | null>(null)

  const fetchAiConfig = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/ai-config')
      const data: ApiResponse<AiServiceConfig> = await res.json()
      if (data.success && data.data) {
        setAiConfig(data.data)
        setAiConfigDraft(data.data)
      }
    } catch (e) {
      console.error('Failed to fetch AI config:', e)
    }
  }, [])

  useEffect(() => {
    fetchAiConfig().then(() => setAiTestResult(null))
  }, [fetchAiConfig])

  const saveAiConfig = async () => {
    if (!aiConfigDraft) return
    setSavingAi(true)
    try {
      const res = await apiFetch('/api/security/ai-config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiConfigDraft),
      })
      const data: ApiResponse<{ saved: boolean; ai_service_available: boolean }> = await res.json()
      if (data.success) {
        fetchAiConfig()
        onStatsRefresh()
      }
    } catch (e) {
      console.error('Failed to save AI config:', e)
    } finally {
      setSavingAi(false)
    }
  }

  const testAiConnection = async () => {
    if (!aiConfigDraft) return
    setTestingAi(true)
    setAiTestResult(null)
    try {
      const res = await apiFetch('/api/security/ai-config/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiConfigDraft),
      })
      const data: ApiResponse<{ reachable: boolean }> = await res.json()
      if (data.success && data.data) {
        setAiTestResult({ reachable: data.data.reachable, tested: true })
        onStatsRefresh()
      } else {
        setAiTestResult({ reachable: false, tested: true })
      }
    } catch {
      setAiTestResult({ reachable: false, tested: true })
    } finally {
      setTestingAi(false)
    }
  }

  return (
    <div className="sec-ai-config">
      {/* Status overview */}
      <div className="sec-ai-status-bar">
        <div className="sec-ai-status-item">
          <span className={`sec-ai-status-dot ${engineStatus?.ai_service_available ? 'online' : 'offline'}`} />
          <span className="sec-ai-status-label">
            {engineStatus?.ai_service_available ? t('emailSecurity.aiServiceOnline') : t('emailSecurity.aiServiceOffline')}
          </span>
        </div>
        {aiConfig?.provider && (
          <div className="sec-ai-status-item">
            <span className="sec-ai-status-provider">
              {aiConfig.provider === 'claude' ? 'Claude' : aiConfig.provider === 'openai' ? 'OpenAI' : t('emailSecurity.localModel')}
            </span>
          </div>
        )}
        {aiConfig?.model && (
          <div className="sec-ai-status-item">
            <span className="sec-ai-status-model">{aiConfig.model}</span>
          </div>
        )}
      </div>

      {aiConfigDraft && (
        <>
          {/* Service connection */}
          <div className="sec-ai-section">
            <div className="sec-ai-section-header">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
              </svg>
              <span>{t('emailSecurity.serviceConnection')}</span>
            </div>
            <div className="sec-ai-section-body">
              <div className="sec-form-row sec-form-row--2">
                <div className="sec-form-group">
                  <label className="sec-form-label">{t('emailSecurity.aiServiceUrl')}</label>
                  <input
                    type="text"
                    className="sec-form-input"
                    value={aiConfigDraft.service_url}
                    onChange={e => setAiConfigDraft({ ...aiConfigDraft, service_url: e.target.value })}
                    placeholder="http://127.0.0.1:8900"
                  />
                  <span className="sec-form-hint">{t('emailSecurity.aiServiceUrlHint')}</span>
                </div>
                <div className="sec-form-group">
                  <label className="sec-form-label">{t('emailSecurity.llmProvider')}</label>
                  <select
                    className="sec-form-select"
                    value={aiConfigDraft.provider}
                    onChange={e => setAiConfigDraft({ ...aiConfigDraft, provider: e.target.value })}
                  >
                    <option value="claude">Claude (Anthropic)</option>
                    <option value="openai">OpenAI</option>
                    <option value="local">{t('emailSecurity.localModel')}</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          {/* Authentication and models - shown only in LLM mode */}
          {aiConfigDraft.provider !== 'local' && (
            <div className="sec-ai-section">
              <div className="sec-ai-section-header">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
                <span>{t('emailSecurity.authAndModel')}</span>
              </div>
              <div className="sec-ai-section-body">
                <div className="sec-form-row sec-form-row--2">
                  <div className="sec-form-group">
                    <label className="sec-form-label">API Key</label>
                    <input
                      type="password"
                      className="sec-form-input"
                      value={aiConfigDraft.api_key}
                      onChange={e => setAiConfigDraft({ ...aiConfigDraft, api_key: e.target.value })}
                      placeholder={aiConfig?.api_key_set ? t('emailSecurity.apiKeySetPlaceholder') : t('emailSecurity.enterApiKey')}
                    />
                    {aiConfig?.api_key_set && (
                      <span className="sec-form-hint sec-form-hint--ok">
                        {t('emailSecurity.apiKeyClearHint')}
                      </span>
                    )}
                  </div>
                  <div className="sec-form-group">
                    <label className="sec-form-label">{t('emailSecurity.modelName')}</label>
                    <input
                      type="text"
                      className="sec-form-input"
                      value={aiConfigDraft.model}
                      onChange={e => setAiConfigDraft({ ...aiConfigDraft, model: e.target.value })}
                      placeholder={aiConfigDraft.provider === 'claude' ? 'claude-sonnet-4-20250514' : 'gpt-4o'}
                    />
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Inference parameters */}
          <div className="sec-ai-section">
            <div className="sec-ai-section-header">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>
              </svg>
              <span>{t('emailSecurity.inferenceParams')}</span>
            </div>
            <div className="sec-ai-section-body">
              <div className="sec-form-row sec-form-row--3">
                {aiConfigDraft.provider !== 'local' && (
                  <>
                    <div className="sec-form-group">
                      <label className="sec-form-label">Temperature</label>
                      <input
                        type="number"
                        className="sec-form-input"
                        value={aiConfigDraft.temperature}
                        onChange={e => setAiConfigDraft({ ...aiConfigDraft, temperature: parseFloat(e.target.value) || 0 })}
                        min={0} max={1} step={0.1}
                      />
                      <span className="sec-form-hint">{t('emailSecurity.temperatureHint')}</span>
                    </div>
                    <div className="sec-form-group">
                      <label className="sec-form-label">{t('emailSecurity.maxTokens')}</label>
                      <input
                        type="number"
                        className="sec-form-input"
                        value={aiConfigDraft.max_tokens}
                        onChange={e => setAiConfigDraft({ ...aiConfigDraft, max_tokens: parseInt(e.target.value) || 4096 })}
                        min={256} max={32768} step={256}
                      />
                      <span className="sec-form-hint">{t('emailSecurity.maxTokensHint')}</span>
                    </div>
                  </>
                )}
                <div className="sec-form-group">
                  <label className="sec-form-label">{t('emailSecurity.timeout')}</label>
                  <input
                    type="number"
                    className="sec-form-input"
                    value={aiConfigDraft.timeout_secs}
                    onChange={e => setAiConfigDraft({ ...aiConfigDraft, timeout_secs: parseInt(e.target.value) || 60 })}
                    min={5} max={300} step={5}
                  />
                  <span className="sec-form-hint">{t('emailSecurity.timeoutHint')}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Action bar */}
          <div className="sec-ai-footer">
            {aiTestResult?.tested && (
              <div className={`sec-ai-test-result ${aiTestResult.reachable ? 'sec-ai-test--ok' : 'sec-ai-test--fail'}`}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  {aiTestResult.reachable
                    ? <polyline points="20 6 9 17 4 12"/>
                    : <><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></>
                  }
                </svg>
                {aiTestResult.reachable
                  ? t('emailSecurity.aiTestSuccess')
                  : t('emailSecurity.aiTestFailed')}
              </div>
            )}
            <div className="sec-ai-actions">
              <button
                className="sec-btn sec-btn--secondary"
                onClick={testAiConnection}
                disabled={testingAi}
              >
                {testingAi ? t('emailSecurity.testing') : t('emailSecurity.testConnection')}
              </button>
              <button
                className="sec-btn sec-btn--primary"
                onClick={saveAiConfig}
                disabled={savingAi}
              >
                {savingAi ? t('emailSecurity.saving') : t('emailSecurity.saveConfig')}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
