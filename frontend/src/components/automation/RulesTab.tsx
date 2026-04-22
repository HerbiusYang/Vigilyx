import { useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { DispositionRule, ApiResponse } from '../../types'
import { apiFetch } from '../../utils/api'
import type { UiMessage, RuleForm } from './types'
import { getCommonThreatLevels, getMailDirectionOptions } from './types'
import {
  createEmptyRuleForm,
  buildRuleFormFromRule,
  buildRulePreviewJson,
  buildRuleRequestPayload,
  buildRuleUpdatePayload,
  describeRuleConditions,
  describeRuleActions,
  getQuickRulePresets,
  truncate,
} from './ruleFormHelpers'

interface RulesTabProps {
  rules: DispositionRule[]
  rulesLoadError: boolean
  onRulesChanged: () => void
}

export default function RulesTab({ rules, rulesLoadError, onRulesChanged }: RulesTabProps) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState<RuleForm>(createEmptyRuleForm())
  const [saving, setSaving] = useState(false)
  const [ruleMsg, setRuleMsg] = useState<UiMessage | null>(null)

  const openNewRule = useCallback((nextForm?: RuleForm) => {
    const targetForm = nextForm ? { ...nextForm } : createEmptyRuleForm()
    if (!targetForm.advancedMode) {
      const preview = buildRulePreviewJson(targetForm)
      targetForm.rawConditions = preview.conditions
      targetForm.rawActions = preview.actions
    }

    setForm(targetForm)
    setEditing(null)
    setShowCreate(true)
    setRuleMsg(null)
  }, [])

  const startEdit = useCallback((rule: DispositionRule) => {
    const nextForm = buildRuleFormFromRule(rule)
    setForm(nextForm)
    setEditing(rule.id)
    setShowCreate(true)
    setRuleMsg(nextForm.unsupportedReason ? { type: 'err', text: nextForm.unsupportedReason } : null)
  }, [])

  const toggleAdvancedMode = useCallback(() => {
    if (!form.advancedMode) {
      const preview = buildRulePreviewJson(form)
      setForm({
        ...form,
        advancedMode: true,
        rawConditions: preview.conditions,
        rawActions: preview.actions,
        unsupportedReason: null,
      })
      setRuleMsg(null)
      return
    }

    const converted = buildRuleFormFromRule({
      id: editing || 'draft',
      name: form.name,
      description: form.description,
      enabled: form.enabled,
      priority: form.priority,
      conditions: form.rawConditions,
      actions: form.rawActions,
      created_at: '',
      updated_at: '',
    })

    if (converted.advancedMode && converted.unsupportedReason) {
      setRuleMsg({ type: 'err', text: converted.unsupportedReason })
      return
    }

    setForm(converted)
    setRuleMsg(null)
  }, [form, editing])

  const handleRuleSave = async () => {
    setSaving(true)
    setRuleMsg(null)

    if (!form.name.trim()) {
      setSaving(false)
      setRuleMsg({ type: 'err', text: t('automation.error.ruleNameRequired') })
      return
    }

    const request = buildRuleRequestPayload(form)
    if (request.error || !request.payload) {
      setSaving(false)
      setRuleMsg({ type: 'err', text: request.error || t('automation.error.ruleIncomplete') })
      return
    }

    try {
      const url = editing ? `/api/security/rules/${editing}` : '/api/security/rules'
      const res = await apiFetch(url, {
        method: editing ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request.payload),
      })
      const data: ApiResponse<DispositionRule> = await res.json()
      if (!res.ok || !data.success) {
        setRuleMsg({ type: 'err', text: data.error || t('automation.error.saveRuleFailed') })
        return
      }

      setShowCreate(false)
      setEditing(null)
      setForm(createEmptyRuleForm())
      setRuleMsg({ type: 'ok', text: editing ? t('automation.ruleUpdated') : t('automation.ruleCreated') })
      onRulesChanged()
    } catch (e) {
      console.error('Failed to save rule:', e)
      setRuleMsg({ type: 'err', text: t('automation.error.networkError') })
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm(t('automation.confirmDeleteRule'))) return
    try {
      const res = await apiFetch(`/api/security/rules/${id}`, { method: 'DELETE' })
      const data: ApiResponse<{ deleted: boolean }> = await res.json()
      if (!res.ok || !data.success) {
        setRuleMsg({ type: 'err', text: data.error || t('automation.error.deleteRuleFailed') })
        return
      }
      setRuleMsg({ type: 'ok', text: t('automation.ruleDeleted') })
      onRulesChanged()
    } catch (e) {
      console.error('Failed to delete rule:', e)
      setRuleMsg({ type: 'err', text: t('automation.error.networkError') })
    }
  }

  const handleToggle = async (rule: DispositionRule) => {
    const request = buildRuleUpdatePayload({ ...rule, enabled: !rule.enabled })
    if (request.error || !request.payload) {
      setRuleMsg({ type: 'err', text: request.error || t('automation.error.updateRuleFailed') })
      return
    }

    try {
      const res = await apiFetch(`/api/security/rules/${rule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request.payload),
      })
      const data: ApiResponse<DispositionRule> = await res.json()
      if (!res.ok || !data.success) {
        setRuleMsg({ type: 'err', text: data.error || t('automation.error.updateRuleFailed') })
        return
      }
      setRuleMsg({ type: 'ok', text: rule.enabled ? t('automation.ruleDisabled') : t('automation.ruleEnabled') })
      onRulesChanged()
    } catch (e) {
      console.error('Failed to toggle rule:', e)
      setRuleMsg({ type: 'err', text: t('automation.error.networkError') })
    }
  }

  const visualPreview = buildRulePreviewJson(form)

  return (
    <>
      <div className="auto-rule-intro">
        <div className="auto-rule-intro-copy">
          <p className="auto-rule-intro-title">{t('automation.rules.introTitle')}</p>
          <p className="auto-rule-intro-text">{t('automation.rules.introText')}</p>
        </div>
        <div className="auto-rule-template-row">
          {getQuickRulePresets().map(preset => (
            <button
              key={preset.id}
              className="auto-rule-template"
              onClick={() => openNewRule(preset.build())}
            >
              <span className="auto-rule-template-name">{preset.label}</span>
              <span className="auto-rule-template-desc">{preset.description}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="auto-rules-header">
        <h3>
          {t('automation.tabRules')}
          <span className="auto-rules-count">{rules.length}</span>
        </h3>
        {!showCreate && (
          <button className="sec-btn sec-btn--primary" onClick={() => openNewRule()}>
            + {t('automation.rules.newRule')}
          </button>
        )}
      </div>

      {ruleMsg && (
        <div className={`auto-msg ${ruleMsg.type === 'ok' ? 'auto-msg--ok' : 'auto-msg--err'}`} style={{ marginBottom: 'var(--space-3)' }}>
          {ruleMsg.text}
        </div>
      )}

      {showCreate && (
        <div className="auto-rule-form">
          <div className="auto-rule-form-head">
            <div>
              <h4>{editing ? t('automation.rules.editRule') : t('automation.rules.newRule')}</h4>
              <p className="auto-form-hint">
                {t('automation.rules.priorityHint')}
              </p>
            </div>
            <button className="auto-rule-link" onClick={toggleAdvancedMode}>
              {form.advancedMode ? t('automation.rules.switchToVisual') : t('automation.rules.switchToJson')}
            </button>
          </div>

          <div className="auto-form-grid auto-form-grid--2-narrow">
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.form.ruleName')}</label>
              <input
                className="auto-form-input"
                type="text"
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder={t('automation.form.ruleNamePlaceholder')}
              />
            </div>
            <div className="auto-form-group">
              <label className="auto-form-label">{t('automation.form.priority')}</label>
              <input
                className="auto-form-input"
                type="number"
                value={form.priority}
                onChange={e => setForm({ ...form, priority: parseInt(e.target.value, 10) || 100 })}
              />
            </div>
          </div>

          <div className="auto-form-group" style={{ marginTop: 'var(--space-3)' }}>
            <label className="auto-form-label">{t('automation.form.description')}</label>
            <input
              className="auto-form-input"
              type="text"
              value={form.description}
              onChange={e => setForm({ ...form, description: e.target.value })}
              placeholder={t('automation.form.descriptionPlaceholder')}
            />
          </div>

          <div className="auto-check-row" style={{ marginTop: 'var(--space-3)' }}>
            <label className="auto-check-label">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={e => setForm({ ...form, enabled: e.target.checked })}
              />
              {t('automation.form.enableRule')}
            </label>
          </div>

          {form.advancedMode ? (
            <>
              <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-4)' }}>
                <div className="auto-form-group">
                  <label className="auto-form-label">{t('automation.form.conditionsJson')}</label>
                  <textarea
                    className="auto-form-textarea"
                    rows={8}
                    value={form.rawConditions}
                    onChange={e => setForm({ ...form, rawConditions: e.target.value })}
                    placeholder='{"min_threat_level":"medium","categories":["phishing"]}'
                  />
                </div>
                <div className="auto-form-group">
                  <label className="auto-form-label">{t('automation.form.actionsJson')}</label>
                  <textarea
                    className="auto-form-textarea"
                    rows={8}
                    value={form.rawActions}
                    onChange={e => setForm({ ...form, rawActions: e.target.value })}
                    placeholder='[{"action_type":"email_alert"}]'
                  />
                </div>
              </div>
              <div className="auto-form-hint" style={{ marginTop: 'var(--space-3)' }}>
                {t('automation.rules.advancedHint')}
              </div>
            </>
          ) : (
            <>
              <div className="auto-rule-builder-grid" style={{ marginTop: 'var(--space-4)' }}>
                <div className="auto-builder-card">
                  <div className="auto-section-label">{t('automation.rules.whenToTrigger')}</div>
                  <div className="auto-form-grid auto-form-grid--2-narrow">
                    <div className="auto-form-group">
                      <label className="auto-form-label">{t('automation.form.minThreatLevel')}</label>
                      <select
                        className="auto-form-select"
                        value={form.minThreatLevel}
                        onChange={e => setForm({ ...form, minThreatLevel: e.target.value })}
                      >
                        <option value="">{t('automation.anyLevel')}</option>
                        {getCommonThreatLevels().map(option => (
                          <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                    </div>
                    <div className="auto-form-group">
                      <label className="auto-form-label">{t('automation.form.mailDirection')}</label>
                      <select
                        className="auto-form-select"
                        value={form.mailDirection}
                        onChange={e => setForm({ ...form, mailDirection: e.target.value })}
                      >
                        {getMailDirectionOptions().map(option => (
                          <option key={option.value || 'any'} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                      <span className="auto-form-hint">{t('automation.rules.directionHint')}</span>
                    </div>
                  </div>
                  <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-3)' }}>
                    <div className="auto-form-group">
                      <label className="auto-form-label">{t('automation.form.categories')}</label>
                      <textarea
                        className="auto-form-textarea"
                        rows={4}
                        value={form.categoriesText}
                        onChange={e => setForm({ ...form, categoriesText: e.target.value })}
                        placeholder={t('automation.form.categoriesPlaceholder')}
                      />
                      <span className="auto-form-hint">{t('automation.rules.categoriesHint')}</span>
                    </div>
                    <div className="auto-form-group">
                      <label className="auto-form-label">{t('automation.form.flaggedModules')}</label>
                      <textarea
                        className="auto-form-textarea"
                        rows={4}
                        value={form.flaggedModulesText}
                        onChange={e => setForm({ ...form, flaggedModulesText: e.target.value })}
                        placeholder={t('automation.form.modulesPlaceholder')}
                      />
                      <span className="auto-form-hint">{t('automation.rules.modulesHint')}</span>
                    </div>
                  </div>
                </div>

                <div className="auto-builder-card">
                  <div className="auto-section-label">{t('automation.rules.whatToExecute')}</div>
                  <div className="auto-action-grid">
                    <label className={`auto-action-tile ${form.sendEmail ? 'auto-action-tile--active' : ''}`}>
                      <input
                        type="checkbox"
                        checked={form.sendEmail}
                        onChange={e => setForm({ ...form, sendEmail: e.target.checked })}
                      />
                      <span className="auto-action-tile-title">{t('automation.action.emailAlert')}</span>
                      <span className="auto-action-tile-desc">{t('automation.action.emailAlertDesc')}</span>
                    </label>
                    <label className={`auto-action-tile ${form.sendWechat ? 'auto-action-tile--active' : ''}`}>
                      <input
                        type="checkbox"
                        checked={form.sendWechat}
                        onChange={e => setForm({ ...form, sendWechat: e.target.checked })}
                      />
                      <span className="auto-action-tile-title">{t('automation.action.wechatAlert')}</span>
                      <span className="auto-action-tile-desc">{t('automation.action.wechatAlertDesc')}</span>
                    </label>
                    <label className={`auto-action-tile ${form.sendWebhook ? 'auto-action-tile--active' : ''}`}>
                      <input
                        type="checkbox"
                        checked={form.sendWebhook}
                        onChange={e => setForm({ ...form, sendWebhook: e.target.checked })}
                      />
                      <span className="auto-action-tile-title">Webhook</span>
                      <span className="auto-action-tile-desc">{t('automation.action.webhookDesc')}</span>
                    </label>
                    <label className={`auto-action-tile ${form.sendLog ? 'auto-action-tile--active' : ''}`}>
                      <input
                        type="checkbox"
                        checked={form.sendLog}
                        onChange={e => setForm({ ...form, sendLog: e.target.checked })}
                      />
                      <span className="auto-action-tile-title">{t('automation.action.log')}</span>
                      <span className="auto-action-tile-desc">{t('automation.action.logDesc')}</span>
                    </label>
                  </div>

                  {(form.sendEmail || form.sendWechat) && (
                    <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-3)' }}>
                      {form.sendEmail && (
                        <div className="auto-form-group">
                          <label className="auto-form-label">{t('automation.form.emailTemplate')}</label>
                          <textarea
                            className="auto-form-textarea"
                            rows={4}
                            value={form.emailMessageTemplate}
                            onChange={e => setForm({ ...form, emailMessageTemplate: e.target.value })}
                            placeholder={t('automation.form.emailTemplatePlaceholder')}
                          />
                        </div>
                      )}
                      {form.sendWechat && (
                        <div className="auto-form-group">
                          <label className="auto-form-label">{t('automation.form.wechatTemplate')}</label>
                          <textarea
                            className="auto-form-textarea"
                            rows={4}
                            value={form.wechatMessageTemplate}
                            onChange={e => setForm({ ...form, wechatMessageTemplate: e.target.value })}
                            placeholder={t('automation.form.wechatTemplatePlaceholder')}
                          />
                        </div>
                      )}
                    </div>
                  )}

                  {(form.sendEmail || form.sendWechat) && (
                    <div className="auto-form-hint" style={{ marginTop: '8px' }}>
                      {t('automation.rules.templateVarsHint')}
                      {' {{threat_level}} '}
                      {'{{mail_from}} '}
                      {'{{rcpt_to}} '}
                      {'{{subject}} '}
                      {'{{client_ip}} '}
                      {'{{server_ip}} '}
                      {'{{external_ip}} '}
                      {'{{mail_direction}} '}
                      {'{{summary}} '}
                      {'{{timestamp}}'}
                    </div>
                  )}

                  {form.sendWechat && (
                    <div className="auto-form-group" style={{ marginTop: 'var(--space-3)' }}>
                      <label className="auto-form-label">{t('automation.form.wechatRuleMobiles')}</label>
                      <textarea
                        className="auto-form-textarea"
                        rows={4}
                        value={form.wechatMentionedMobileText}
                        onChange={e => setForm({ ...form, wechatMentionedMobileText: e.target.value })}
                        placeholder={t('automation.form.wechatRuleMobilesPlaceholder')}
                      />
                      <span className="auto-form-hint">{t('automation.rules.ruleMobilesHint')}</span>
                    </div>
                  )}

                  {form.sendWebhook && (
                    <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-3)' }}>
                      <div className="auto-form-group">
                        <label className="auto-form-label">{t('automation.form.webhookUrl')}</label>
                        <input
                          className="auto-form-input"
                          type="text"
                          value={form.webhookUrl}
                          onChange={e => setForm({ ...form, webhookUrl: e.target.value })}
                          placeholder="https://hooks.example.com/security"
                        />
                      </div>
                      <div className="auto-form-group">
                        <label className="auto-form-label">{t('automation.form.webhookHeaders')}</label>
                        <textarea
                          className="auto-form-textarea"
                          rows={4}
                          value={form.webhookHeadersText}
                          onChange={e => setForm({ ...form, webhookHeadersText: e.target.value })}
                          placeholder={t('automation.form.webhookHeadersPlaceholder')}
                        />
                        <span className="auto-form-hint">{t('automation.rules.headersHint')}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="auto-preview-grid">
                <div className="auto-preview-card">
                  <div className="auto-preview-title">{t('automation.rules.generatedConditions')}</div>
                  <pre>{visualPreview.conditions}</pre>
                </div>
                <div className="auto-preview-card">
                  <div className="auto-preview-title">{t('automation.rules.generatedActions')}</div>
                  <pre>{visualPreview.actions}</pre>
                </div>
              </div>
            </>
          )}

          <div className="auto-rule-form-actions">
            <button
              className="sec-btn sec-btn--secondary"
              onClick={() => {
                setShowCreate(false)
                setEditing(null)
                setForm(createEmptyRuleForm())
                setRuleMsg(null)
              }}
            >
              {t('automation.cancel')}
            </button>
            <button
              className="sec-btn sec-btn--primary"
              onClick={handleRuleSave}
              disabled={saving || !form.name.trim()}
            >
              {saving ? t('automation.saving') : editing ? t('automation.rules.updateRule') : t('automation.rules.createRule')}
            </button>
          </div>
        </div>
      )}

      {rules.length === 0 ? (
        <div className="sec-empty">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.3 }}>
            <polyline points="9 11 12 14 22 4"/>
            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
          </svg>
          <p>{rulesLoadError ? t('automation.error.rulesLoadFailed') : t('automation.rules.noRules')}</p>
          <p className="sec-empty-hint">{rulesLoadError ? t('automation.error.checkNetwork') : t('automation.rules.noRulesHint')}</p>
        </div>
      ) : (
        <div>
          {rules
            .slice()
            .sort((a, b) => a.priority - b.priority)
            .map(rule => (
              <div key={rule.id} className={`auto-rule ${!rule.enabled ? 'auto-rule--off' : ''}`}>
                <div className="auto-rule-priority">{rule.priority}</div>
                <div className="auto-rule-body">
                  <div className="auto-rule-top">
                    <span className="auto-rule-name">{rule.name}</span>
                    <span className={`auto-rule-badge ${rule.enabled ? 'auto-rule-badge--on' : 'auto-rule-badge--off'}`}>
                      {rule.enabled ? 'ON' : 'OFF'}
                    </span>
                  </div>
                  {rule.description && <div className="auto-rule-desc">{rule.description}</div>}

                  <div className="auto-rule-chip-row">
                    {describeRuleConditions(rule).map(entry => (
                      <span
                        key={`${rule.id}-condition-${entry}`}
                        className={`auto-chip ${entry.includes(t('automation.chip.abnormal')) ? 'auto-chip--danger' : 'auto-chip--condition'}`}
                      >
                        {truncate(entry, 120)}
                      </span>
                    ))}
                  </div>

                  <div className="auto-rule-chip-row">
                    {describeRuleActions(rule).map(entry => (
                      <span
                        key={`${rule.id}-action-${entry}`}
                        className={`auto-chip ${entry.includes(t('automation.chip.abnormal')) || entry.includes(t('automation.chip.unknown')) ? 'auto-chip--danger' : 'auto-chip--action'}`}
                      >
                        {entry}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="auto-rule-actions">
                  <button className="auto-rule-btn" onClick={() => handleToggle(rule)}>
                    {rule.enabled ? t('automation.disable') : t('automation.enable')}
                  </button>
                  <button className="auto-rule-btn" onClick={() => startEdit(rule)}>
                    {t('automation.edit')}
                  </button>
                  <button className="auto-rule-btn auto-rule-btn--danger" onClick={() => handleDelete(rule.id)}>
                    {t('automation.delete')}
                  </button>
                </div>
              </div>
            ))}
        </div>
      )}
    </>
  )
}
