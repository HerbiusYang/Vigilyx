import { useState, useEffect, useCallback } from 'react'
import type { DispositionRule, ApiResponse, EmailAlertConfig } from '../../types'
import { apiFetch } from '../../utils/api'

const defaultAlertConfig: EmailAlertConfig = {
  enabled: false,
  smtp_host: '',
  smtp_port: 587,
  smtp_username: '',
  smtp_password: '',
  smtp_password_set: false,
  smtp_tls: 'starttls',
  from_address: '',
  admin_email: '',
  min_threat_level: 'medium',
  notify_recipient: false,
  notify_admin: true,
}

interface RuleForm {
  name: string
  description: string
  enabled: boolean
  priority: number
  conditions: string
  actions: string
}

const emptyForm: RuleForm = {
  name: '',
  description: '',
  enabled: true,
  priority: 100,
  conditions: '{"min_threat_level":"high"}',
  actions: '[{"action_type":"log"}]',
}

function AutomationDisposition() {
  const [tab, setTab] = useState<'alert' | 'rules'>('alert')

  // Email alert state
  const [alertConfig, setAlertConfig] = useState<EmailAlertConfig>({ ...defaultAlertConfig })
  const [alertSaving, setAlertSaving] = useState(false)
  const [alertTesting, setAlertTesting] = useState(false)
  const [alertMsg, setAlertMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null)

  // Disposition rules state
  const [rules, setRules] = useState<DispositionRule[]>([])
  const [rulesLoadError, setRulesLoadError] = useState(false)
  const [editing, setEditing] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState<RuleForm>({ ...emptyForm })
  const [saving, setSaving] = useState(false)

  // ── Data loading ──
  const fetchAlertConfig = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/email-alert')
      const data: ApiResponse<EmailAlertConfig> = await res.json()
      if (data.success && data.data) setAlertConfig(data.data)
    } catch (e) {
      console.error('Failed to fetch email alert config:', e)
    }
  }, [])

  const fetchRules = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/rules')
      const data: ApiResponse<DispositionRule[]> = await res.json()
      if (data.success && data.data) {
        setRules(data.data)
        setRulesLoadError(false)
      }
    } catch (e) {
      console.error('Failed to fetch disposition rules:', e)
      setRulesLoadError(true)
    }
  }, [])

  const [pageLoading, setPageLoading] = useState(true)

  useEffect(() => {
    setPageLoading(true)
    Promise.all([fetchAlertConfig(), fetchRules()]).finally(() => setPageLoading(false))
  }, [fetchAlertConfig, fetchRules])

  // ── Email alert actions ──
  const handleAlertSave = async () => {
    setAlertSaving(true)
    setAlertMsg(null)
    try {
      const res = await apiFetch('/api/security/email-alert', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alertConfig),
      })
      const data: ApiResponse<{ saved: boolean }> = await res.json()
      if (data.success) {
        setAlertMsg({ type: 'ok', text: '配置已保存' })
        fetchAlertConfig()
      } else {
        setAlertMsg({ type: 'err', text: data.error || '保存失败' })
      }
    } catch {
      setAlertMsg({ type: 'err', text: '网络错误' })
    } finally {
      setAlertSaving(false)
    }
  }

  const handleAlertTest = async () => {
    setAlertTesting(true)
    setAlertMsg(null)
    try {
      const res = await apiFetch('/api/security/email-alert/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alertConfig),
      })
      const data: ApiResponse<{ success: boolean; message: string }> = await res.json()
      if (data.success && data.data?.success) {
        setAlertMsg({ type: 'ok', text: '测试邮件已发送至管理员邮箱' })
      } else {
        setAlertMsg({ type: 'err', text: data.error || data.data?.message || '发送失败' })
      }
    } catch {
      setAlertMsg({ type: 'err', text: '网络错误' })
    } finally {
      setAlertTesting(false)
    }
  }

  // ── Rule actions ──
  const handleRuleSave = async () => {
    setSaving(true)
    try {
      JSON.parse(form.conditions)
      JSON.parse(form.actions)
    } catch {
      setAlertMsg({ type: 'err', text: '条件或动作 JSON 格式不正确' })
      setSaving(false)
      return
    }
    try {
      const url = editing ? `/api/security/rules/${editing}` : '/api/security/rules'
      const res = await apiFetch(url, {
        method: editing ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      if (!res.ok) {
        setAlertMsg({ type: 'err', text: '保存规则失败' })
        return
      }
      setShowCreate(false)
      setEditing(null)
      setForm({ ...emptyForm })
      fetchRules()
    } catch (e) {
      console.error('Failed to save rule:', e)
      setAlertMsg({ type: 'err', text: '网络错误' })
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('确定要删除此规则?')) return
    try {
      const res = await apiFetch(`/api/security/rules/${id}`, { method: 'DELETE' })
      if (!res.ok) { console.error('Failed to delete rule:', res.status); return }
      fetchRules()
    } catch (e) {
      console.error('Failed to delete rule:', e)
    }
  }

  const handleToggle = async (rule: DispositionRule) => {
    try {
      const res = await apiFetch(`/api/security/rules/${rule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: rule.name,
          description: rule.description || '',
          enabled: !rule.enabled,
          priority: rule.priority,
          conditions: rule.conditions,
          actions: rule.actions,
        }),
      })
      if (!res.ok) { console.error('Failed to toggle rule:', res.status); return }
      fetchRules()
    } catch (e) {
      console.error('Failed to toggle rule:', e)
    }
  }

  const startEdit = (rule: DispositionRule) => {
    setForm({
      name: rule.name,
      description: rule.description || '',
      enabled: rule.enabled,
      priority: rule.priority,
      conditions: rule.conditions,
      actions: rule.actions,
    })
    setEditing(rule.id)
    setShowCreate(true)
    setTab('rules')
  }

  const activeRules = rules.filter(r => r.enabled).length

  if (pageLoading) {
    return (
      <div className="auto-page">
        <div className="sec-loading"><div className="sec-spinner" />加载配置...</div>
      </div>
    )
  }

  return (
    <div className="auto-page">
      {/* Header */}
      <div className="auto-header">
        <div>
          <h2>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            自动化处置
          </h2>
          <p className="auto-header-sub">邮件告警通知与自动响应规则配置</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="sec-tabs">
        <button
          className={`sec-tab ${tab === 'alert' ? 'sec-tab--active' : ''}`}
          onClick={() => setTab('alert')}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
            <polyline points="22,6 12,13 2,6"/>
          </svg>
          邮件告警
          {alertConfig.enabled && <span className="sec-tab-badge">ON</span>}
        </button>
        <button
          className={`sec-tab ${tab === 'rules' ? 'sec-tab--active' : ''}`}
          onClick={() => setTab('rules')}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="9 11 12 14 22 4"/>
            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
          </svg>
          处置规则
          {rules.length > 0 && <span className="sec-tab-badge">{activeRules}/{rules.length}</span>}
        </button>
      </div>

      {/* ═══════════════════════════════════════════ */}
      {/* TAB: mail alerts */}
      {/* ═══════════════════════════════════════════ */}
      {tab === 'alert' && (
        <div className="auto-alert-card">
          {/* Card header */}
          <div className="auto-alert-head">
            <div className="auto-alert-head-left">
              <div className="auto-alert-icon">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                  <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
                </svg>
              </div>
              <div>
                <p className="auto-alert-head-title">邮件告警通知</p>
                <p className="auto-alert-head-desc">检测到安全威胁时自动发送告警邮件</p>
              </div>
            </div>
            <label className="s-toggle">
              <input
                type="checkbox"
                checked={alertConfig.enabled}
                onChange={e => setAlertConfig({ ...alertConfig, enabled: e.target.checked })}
              />
              <span className="s-toggle-slider" />
            </label>
          </div>

          {/* Card body */}
          <div className="auto-alert-body">
            {/* SMTP Section */}
            <div className="auto-section">
              <div className="auto-section-label">SMTP 服务器</div>
              <div className="auto-form-grid auto-form-grid--3">
                <div className="auto-form-group">
                  <label className="auto-form-label">服务器地址</label>
                  <input
                    className="auto-form-input"
                    type="text"
                    value={alertConfig.smtp_host}
                    onChange={e => setAlertConfig({ ...alertConfig, smtp_host: e.target.value })}
                    placeholder="smtp.example.com"
                  />
                </div>
                <div className="auto-form-group">
                  <label className="auto-form-label">端口</label>
                  <input
                    className="auto-form-input"
                    type="number"
                    value={alertConfig.smtp_port}
                    onChange={e => setAlertConfig({ ...alertConfig, smtp_port: parseInt(e.target.value) || 587 })}
                  />
                </div>
                <div className="auto-form-group">
                  <label className="auto-form-label">加密方式</label>
                  <select
                    className="auto-form-select"
                    value={alertConfig.smtp_tls}
                    onChange={e => setAlertConfig({ ...alertConfig, smtp_tls: e.target.value })}
                  >
                    <option value="starttls">STARTTLS</option>
                    <option value="tls">TLS/SSL</option>
                    <option value="none">无加密</option>
                  </select>
                </div>
              </div>
              <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-3)' }}>
                <div className="auto-form-group">
                  <label className="auto-form-label">用户名</label>
                  <input
                    className="auto-form-input"
                    type="text"
                    value={alertConfig.smtp_username}
                    onChange={e => setAlertConfig({ ...alertConfig, smtp_username: e.target.value })}
                    placeholder="user@example.com"
                  />
                </div>
                <div className="auto-form-group">
                  <label className="auto-form-label">
                    密码
                    {alertConfig.smtp_password_set && (
                      <span className="auto-form-label-hint">(已设置)</span>
                    )}
                  </label>
                  <input
                    className="auto-form-input"
                    type="password"
                    value={alertConfig.smtp_password}
                    onChange={e => setAlertConfig({ ...alertConfig, smtp_password: e.target.value })}
                    placeholder={alertConfig.smtp_password_set ? '留空保持不变' : '请输入密码'}
                  />
                </div>
              </div>
              <div className="auto-form-grid" style={{ marginTop: 'var(--space-3)' }}>
                <div className="auto-form-group">
                  <label className="auto-form-label">发件地址</label>
                  <input
                    className="auto-form-input"
                    type="email"
                    value={alertConfig.from_address}
                    onChange={e => setAlertConfig({ ...alertConfig, from_address: e.target.value })}
                    placeholder="vigilyx-alert@example.com"
                  />
                </div>
              </div>
            </div>

            {/* Alert config section */}
            <div className="auto-section">
              <div className="auto-section-label">告警规则</div>
              <div className="auto-form-grid auto-form-grid--2-narrow">
                <div className="auto-form-group">
                  <label className="auto-form-label">管理员邮箱</label>
                  <input
                    className="auto-form-input"
                    type="email"
                    value={alertConfig.admin_email}
                    onChange={e => setAlertConfig({ ...alertConfig, admin_email: e.target.value })}
                    placeholder="admin@company.com"
                  />
                </div>
                <div className="auto-form-group">
                  <label className="auto-form-label">最低告警等级</label>
                  <select
                    className="auto-form-select"
                    value={alertConfig.min_threat_level}
                    onChange={e => setAlertConfig({ ...alertConfig, min_threat_level: e.target.value })}
                  >
                    <option value="medium">Medium (中危)</option>
                    <option value="high">High (高危)</option>
                    <option value="critical">Critical (严重)</option>
                  </select>
                </div>
              </div>
              <div className="auto-check-row">
                <label className="auto-check-label">
                  <input
                    type="checkbox"
                    checked={alertConfig.notify_admin}
                    onChange={e => setAlertConfig({ ...alertConfig, notify_admin: e.target.checked })}
                  />
                  通知管理员
                </label>
                <label className="auto-check-label">
                  <input
                    type="checkbox"
                    checked={alertConfig.notify_recipient}
                    onChange={e => setAlertConfig({ ...alertConfig, notify_recipient: e.target.checked })}
                  />
                  通知原始收信人
                </label>
              </div>
            </div>
          </div>

          {/* Footer with actions */}
          <div className="auto-alert-footer">
            {alertMsg && (
              <div className={`auto-msg ${alertMsg.type === 'ok' ? 'auto-msg--ok' : 'auto-msg--err'}`}>
                {alertMsg.text}
              </div>
            )}
            <div style={{ flex: 1 }} />
            <button
              className="sec-btn sec-btn--secondary"
              onClick={handleAlertTest}
              disabled={alertTesting || !alertConfig.smtp_host || !alertConfig.admin_email}
            >
              {alertTesting ? '发送中...' : '测试连接'}
            </button>
            <button
              className="sec-btn sec-btn--primary"
              onClick={handleAlertSave}
              disabled={alertSaving}
            >
              {alertSaving ? '保存中...' : '保存配置'}
            </button>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════ */}
      {/* TAB: disposition rules */}
      {/* ═══════════════════════════════════════════ */}
      {tab === 'rules' && (
        <>
          <div className="auto-rules-header">
            <h3>
              处置规则
              <span className="auto-rules-count">{rules.length}</span>
            </h3>
            {!showCreate && (
              <button
                className="sec-btn sec-btn--primary"
                onClick={() => { setForm({ ...emptyForm }); setEditing(null); setShowCreate(true) }}
              >
                + 新建规则
              </button>
            )}
          </div>

          {/* Create / edit form */}
          {showCreate && (
            <div className="auto-rule-form">
              <h4>{editing ? '编辑规则' : '新建规则'}</h4>
              <div className="auto-form-grid auto-form-grid--2-narrow">
                <div className="auto-form-group">
                  <label className="auto-form-label">规则名称</label>
                  <input
                    className="auto-form-input"
                    type="text"
                    value={form.name}
                    onChange={e => setForm({ ...form, name: e.target.value })}
                    placeholder="例: 高危邮件 Webhook 通知"
                  />
                </div>
                <div className="auto-form-group">
                  <label className="auto-form-label">优先级 (数字越小越优先)</label>
                  <input
                    className="auto-form-input"
                    type="number"
                    value={form.priority}
                    onChange={e => setForm({ ...form, priority: parseInt(e.target.value) || 100 })}
                  />
                </div>
              </div>
              <div className="auto-form-group" style={{ marginTop: 'var(--space-3)' }}>
                <label className="auto-form-label">描述</label>
                <input
                  className="auto-form-input"
                  type="text"
                  value={form.description}
                  onChange={e => setForm({ ...form, description: e.target.value })}
                  placeholder="规则用途说明 (可选)"
                />
              </div>
              <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-3)' }}>
                <div className="auto-form-group">
                  <label className="auto-form-label">触发条件 (JSON)</label>
                  <textarea
                    className="auto-form-textarea"
                    value={form.conditions}
                    onChange={e => setForm({ ...form, conditions: e.target.value })}
                    rows={4}
                    placeholder='{"min_threat_level":"high","categories":["phishing"]}'
                  />
                  <span className="auto-form-hint">支持: min_threat_level, categories</span>
                </div>
                <div className="auto-form-group">
                  <label className="auto-form-label">执行动作 (JSON)</label>
                  <textarea
                    className="auto-form-textarea"
                    value={form.actions}
                    onChange={e => setForm({ ...form, actions: e.target.value })}
                    rows={4}
                    placeholder='[{"action_type":"webhook","webhook_url":"https://..."}]'
                  />
                  <span className="auto-form-hint">类型: log, alert, webhook</span>
                </div>
              </div>
              <div className="auto-check-row" style={{ marginTop: 'var(--space-3)' }}>
                <label className="auto-check-label">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={e => setForm({ ...form, enabled: e.target.checked })}
                  />
                  启用此规则
                </label>
              </div>
              <div className="auto-rule-form-actions">
                <button
                  className="sec-btn sec-btn--secondary"
                  onClick={() => { setShowCreate(false); setEditing(null) }}
                >
                  取消
                </button>
                <button
                  className="sec-btn sec-btn--primary"
                  onClick={handleRuleSave}
                  disabled={saving || !form.name.trim()}
                >
                  {saving ? '保存中...' : editing ? '更新规则' : '创建规则'}
                </button>
              </div>
            </div>
          )}

          {/* Rule list */}
          {rules.length === 0 ? (
            <div className="sec-empty">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.3 }}>
                <polyline points="9 11 12 14 22 4"/>
                <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
              </svg>
              <p>{rulesLoadError ? '规则加载失败' : '暂无处置规则'}</p>
              <p className="sec-empty-hint">{rulesLoadError ? '请检查网络连接或稍后重试' : '点击「新建规则」添加自动响应策略'}</p>
            </div>
          ) : (
            <div>
              {rules
                .sort((a, b) => a.priority - b.priority)
                .map(rule => (
                  <div
                    key={rule.id}
                    className={`auto-rule ${!rule.enabled ? 'auto-rule--off' : ''}`}
                  >
                    <div className="auto-rule-priority">{rule.priority}</div>
                    <div className="auto-rule-body">
                      <div className="auto-rule-top">
                        <span className="auto-rule-name">{rule.name}</span>
                        <span className={`auto-rule-badge ${rule.enabled ? 'auto-rule-badge--on' : 'auto-rule-badge--off'}`}>
                          {rule.enabled ? 'ON' : 'OFF'}
                        </span>
                      </div>
                      {rule.description && (
                        <div className="auto-rule-desc">{rule.description}</div>
                      )}
                      <div className="auto-rule-meta">
                        <span>条件 <code>{truncate(rule.conditions, 50)}</code></span>
                        <span>动作 <code>{truncate(rule.actions, 50)}</code></span>
                      </div>
                    </div>
                    <div className="auto-rule-actions">
                      <button className="auto-rule-btn" onClick={() => handleToggle(rule)}>
                        {rule.enabled ? '禁用' : '启用'}
                      </button>
                      <button className="auto-rule-btn" onClick={() => startEdit(rule)}>
                        编辑
                      </button>
                      <button className="auto-rule-btn auto-rule-btn--danger" onClick={() => handleDelete(rule.id)}>
                        删除
                      </button>
                    </div>
                  </div>
                ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.substring(0, max) + '...' : s
}

export default AutomationDisposition
