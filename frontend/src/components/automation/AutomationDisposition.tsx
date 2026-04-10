import { useState, useEffect, useCallback } from 'react'
import type { DispositionRule, ApiResponse, EmailAlertConfig, WechatAlertConfig } from '../../types'
import { apiFetch } from '../../utils/api'

const defaultAlertConfig: EmailAlertConfig = {
  enabled: false,
  smtp_host: '',
  smtp_port: 587,
  smtp_username: '',
  smtp_password: '',
  smtp_password_set: false,
  smtp_tls: 'starttls',
  allow_plaintext_smtp: false,
  from_address: '',
  admin_email: '',
  min_threat_level: 'medium',
  notify_recipient: false,
  notify_admin: true,
}

const defaultWechatConfig: WechatAlertConfig = {
  enabled: false,
  webhook_url: '',
  webhook_url_set: false,
  min_threat_level: 'medium',
  mentioned_mobile_list: [],
}

type UiMessage = { type: 'ok' | 'err'; text: string }
type RuleActionType = 'email_alert' | 'wechat_alert' | 'webhook' | 'log' | 'alert'

interface DispositionConditionValue {
  min_threat_level?: string
  mail_direction?: string
  categories?: string[]
  flagged_modules?: string[]
}

interface DispositionActionValue {
  action_type: string
  webhook_url?: string
  mentioned_mobile_list?: string[]
  headers?: Record<string, string>
  message_template?: string
}

interface RuleForm {
  name: string
  description: string
  enabled: boolean
  priority: number
  minThreatLevel: string
  mailDirection: string
  categoriesText: string
  flaggedModulesText: string
  sendEmail: boolean
  sendWechat: boolean
  sendWebhook: boolean
  sendLog: boolean
  emailMessageTemplate: string
  webhookUrl: string
  webhookHeadersText: string
  wechatMentionedMobileText: string
  wechatMessageTemplate: string
  advancedMode: boolean
  rawConditions: string
  rawActions: string
  unsupportedReason: string | null
}

interface QuickRulePreset {
  id: string
  label: string
  description: string
  build: () => RuleForm
}

const PLAINTEXT_SMTP_LOCK_MESSAGE =
  '当前选择了无加密 SMTP。若确需使用，请先开启“允许明文 SMTP（管理员开关）”；该设置会持久化保存。'

const commonThreatLevels = [
  { value: 'medium', label: 'Medium (中危)' },
  { value: 'high', label: 'High (高危)' },
  { value: 'critical', label: 'Critical (严重)' },
]

const mailDirectionOptions = [
  { value: '', label: '任意方向' },
  { value: 'inbound', label: '入站' },
  { value: 'outbound', label: '出站' },
  { value: 'internal', label: '内部' },
]

function normalizeSmtpUiError(message?: string): string {
  if (!message) return '保存失败'
  if (message.includes('SMTP plaintext mode blocked')) {
    return PLAINTEXT_SMTP_LOCK_MESSAGE
  }
  if (message.includes('No compatible authentication mechanism')) {
    return '当前 SMTP 服务器未提供可用的 AUTH 认证能力。若该服务器允许内网免认证发送，请将用户名和密码留空后重试。'
  }
  if (message.includes('must either both be filled or both be left empty')) {
    return 'SMTP 用户名和密码要么同时填写，要么同时留空。'
  }
  return message
}

function normalizeWechatUiError(message?: string): string {
  if (!message) return '保存失败'
  return message
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseLineList(value: string): string[] {
  const normalized: string[] = []
  for (const item of value.split(/[\n,，]/)) {
    const trimmed = item.trim()
    if (trimmed && !normalized.includes(trimmed)) normalized.push(trimmed)
  }
  return normalized
}

function formatLineList(values: string[] | undefined): string {
  return (values || []).join('\n')
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  const normalized: string[] = []
  for (const item of value) {
    if (typeof item !== 'string') continue
    const trimmed = item.trim()
    if (trimmed && !normalized.includes(trimmed)) normalized.push(trimmed)
  }
  return normalized
}

function parseStoredJsonText(raw: string): unknown | null {
  try {
    let parsed: unknown = JSON.parse(raw)
    if (typeof parsed === 'string') {
      try {
        parsed = JSON.parse(parsed)
      } catch {
        return parsed
      }
    }
    return parsed
  } catch {
    return null
  }
}

function parseHeaderLines(text: string): { headers: Record<string, string>; error?: string } {
  const headers: Record<string, string> = {}
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line) continue
    const separatorIndex = line.indexOf(':')
    if (separatorIndex <= 0) {
      return { headers: {}, error: `请求头格式不正确：${line}` }
    }
    const key = line.slice(0, separatorIndex).trim()
    const value = line.slice(separatorIndex + 1).trim()
    if (!key || !value) {
      return { headers: {}, error: `请求头格式不正确：${line}` }
    }
    headers[key] = value
  }
  return { headers }
}

function formatHeaderLines(headers: Record<string, string> | undefined): string {
  if (!headers) return ''
  return Object.entries(headers)
    .filter(([key, value]) => key.trim() && value.trim())
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n')
}

function normalizeActionType(actionType: string): RuleActionType | string {
  const normalized = actionType.trim().toLowerCase()
  if (normalized === 'email') return 'email_alert'
  if (normalized === 'wechat') return 'wechat_alert'
  return normalized
}

function formatThreatLevelLabel(level: string): string {
  switch (level) {
    case 'medium':
      return 'Medium'
    case 'high':
      return 'High'
    case 'critical':
      return 'Critical'
    case 'low':
      return 'Low'
    case 'safe':
      return 'Safe'
    default:
      return level || '任意等级'
  }
}

function formatMailDirectionLabel(direction: string): string {
  switch (direction) {
    case 'inbound':
      return '入站'
    case 'outbound':
      return '出站'
    case 'internal':
      return '内部'
    default:
      return direction || '任意方向'
  }
}

function createEmptyRuleForm(): RuleForm {
  return {
    name: '',
    description: '',
    enabled: true,
    priority: 100,
    minThreatLevel: 'medium',
    mailDirection: '',
    categoriesText: '',
    flaggedModulesText: '',
    sendEmail: true,
    sendWechat: false,
    sendWebhook: false,
    sendLog: false,
    emailMessageTemplate: '',
    webhookUrl: '',
    webhookHeadersText: '',
    wechatMentionedMobileText: '',
    wechatMessageTemplate: '',
    advancedMode: false,
    rawConditions: JSON.stringify({ min_threat_level: 'medium' }, null, 2),
    rawActions: JSON.stringify([{ action_type: 'email_alert' }], null, 2),
    unsupportedReason: null,
  }
}

function buildConditionValueFromForm(form: RuleForm): DispositionConditionValue {
  const value: DispositionConditionValue = {}
  if (form.minThreatLevel) value.min_threat_level = form.minThreatLevel
  if (form.mailDirection) value.mail_direction = form.mailDirection

  const categories = parseLineList(form.categoriesText)
  if (categories.length > 0) value.categories = categories

  const flaggedModules = parseLineList(form.flaggedModulesText)
  if (flaggedModules.length > 0) value.flagged_modules = flaggedModules

  return value
}

function buildActionsValueFromForm(form: RuleForm): { actions: DispositionActionValue[]; error?: string } {
  const actions: DispositionActionValue[] = []

  if (form.sendEmail) {
    const action: DispositionActionValue = { action_type: 'email_alert' }
    if (form.emailMessageTemplate.trim()) action.message_template = form.emailMessageTemplate.trim()
    actions.push(action)
  }

  if (form.sendWechat) {
    const action: DispositionActionValue = { action_type: 'wechat_alert' }
    const mentionedMobileList = parseLineList(form.wechatMentionedMobileText)
    if (mentionedMobileList.length > 0) action.mentioned_mobile_list = mentionedMobileList
    if (form.wechatMessageTemplate.trim()) action.message_template = form.wechatMessageTemplate.trim()
    actions.push(action)
  }

  if (form.sendWebhook) {
    if (!form.webhookUrl.trim()) {
      return { actions: [], error: '已勾选 Webhook 动作，请填写回调地址。' }
    }
    const headerResult = parseHeaderLines(form.webhookHeadersText)
    if (headerResult.error) return { actions: [], error: headerResult.error }

    const action: DispositionActionValue = {
      action_type: 'webhook',
      webhook_url: form.webhookUrl.trim(),
    }
    if (Object.keys(headerResult.headers).length > 0) action.headers = headerResult.headers
    actions.push(action)
  }

  if (form.sendLog) {
    actions.push({ action_type: 'log' })
  }

  if (actions.length === 0) {
    return { actions: [], error: '请至少选择一个执行动作。' }
  }

  return { actions }
}

function buildRulePreviewJson(form: RuleForm): { conditions: string; actions: string } {
  const conditions = buildConditionValueFromForm(form)
  const actionsResult = buildActionsValueFromForm(form)

  return {
    conditions: JSON.stringify(conditions, null, 2),
    actions: JSON.stringify(actionsResult.actions, null, 2),
  }
}

function buildRuleFormFromRule(rule: DispositionRule): RuleForm {
  const form = createEmptyRuleForm()
  form.name = rule.name
  form.description = rule.description || ''
  form.enabled = rule.enabled
  form.priority = rule.priority
  form.rawConditions = rule.conditions
  form.rawActions = rule.actions
  form.sendEmail = false

  let unsupportedReason: string | null = null
  const parsedConditions = parseStoredJsonText(rule.conditions)
  const parsedActions = parseStoredJsonText(rule.actions)

  if (isRecord(parsedConditions)) {
    form.minThreatLevel = typeof parsedConditions.min_threat_level === 'string'
      ? parsedConditions.min_threat_level
      : ''
    form.mailDirection = typeof parsedConditions.mail_direction === 'string'
      ? parsedConditions.mail_direction
      : ''
    form.categoriesText = formatLineList(asStringArray(parsedConditions.categories))
    form.flaggedModulesText = formatLineList(asStringArray(parsedConditions.flagged_modules))
  } else if (rule.conditions.trim()) {
    unsupportedReason = '当前规则条件无法转换为可视化表单，已切换到高级 JSON 模式。'
  }

  if (Array.isArray(parsedActions)) {
    for (const rawAction of parsedActions) {
      if (!isRecord(rawAction)) {
        unsupportedReason = '当前规则动作格式异常，已切换到高级 JSON 模式。'
        continue
      }

      const actionType = normalizeActionType(typeof rawAction.action_type === 'string' ? rawAction.action_type : '')

      switch (actionType) {
        case 'email_alert':
          form.sendEmail = true
          if (typeof rawAction.message_template === 'string') {
            if (form.emailMessageTemplate && form.emailMessageTemplate !== rawAction.message_template) {
              unsupportedReason = '当前规则包含多个不同的邮件告警模板，已切换到高级 JSON 模式。'
            } else {
              form.emailMessageTemplate = rawAction.message_template
            }
          }
          break
        case 'wechat_alert': {
          form.sendWechat = true
          if (typeof rawAction.webhook_url === 'string' && rawAction.webhook_url.trim()) {
            unsupportedReason = '当前规则使用了单独的微信 Webhook 覆盖，已切换到高级 JSON 模式。'
          }
          if (typeof rawAction.message_template === 'string') {
            if (form.wechatMessageTemplate && form.wechatMessageTemplate !== rawAction.message_template) {
              unsupportedReason = '当前规则包含多个不同的微信消息模板，已切换到高级 JSON 模式。'
            } else {
              form.wechatMessageTemplate = rawAction.message_template
            }
          }
          const mobileText = formatLineList(asStringArray(rawAction.mentioned_mobile_list))
          if (mobileText) {
            if (form.wechatMentionedMobileText && form.wechatMentionedMobileText !== mobileText) {
              unsupportedReason = '当前规则包含多个不同的微信 @ 手机号配置，已切换到高级 JSON 模式。'
            } else {
              form.wechatMentionedMobileText = mobileText
            }
          }
          break
        }
        case 'webhook': {
          form.sendWebhook = true
          if (typeof rawAction.webhook_url !== 'string' || !rawAction.webhook_url.trim()) {
            unsupportedReason = '当前规则的 Webhook 动作缺少地址，已切换到高级 JSON 模式。'
            break
          }
          if (form.webhookUrl && form.webhookUrl !== rawAction.webhook_url) {
            unsupportedReason = '当前规则包含多个不同的 Webhook 地址，已切换到高级 JSON 模式。'
          } else {
            form.webhookUrl = rawAction.webhook_url
          }

          const headersText = formatHeaderLines(
            isRecord(rawAction.headers)
              ? Object.fromEntries(
                  Object.entries(rawAction.headers)
                    .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
                )
              : undefined
          )
          if (headersText) {
            if (form.webhookHeadersText && form.webhookHeadersText !== headersText) {
              unsupportedReason = '当前规则包含多组不同的 Webhook 请求头，已切换到高级 JSON 模式。'
            } else {
              form.webhookHeadersText = headersText
            }
          }
          break
        }
        case 'log':
          form.sendLog = true
          break
        default:
          unsupportedReason = `当前规则包含暂不支持的动作类型「${actionType || 'unknown'}」，已切换到高级 JSON 模式。`
      }
    }
  } else if (rule.actions.trim()) {
    unsupportedReason = '当前规则动作无法转换为可视化表单，已切换到高级 JSON 模式。'
  }

  form.unsupportedReason = unsupportedReason
  form.advancedMode = Boolean(unsupportedReason)

  if (!form.advancedMode) {
    const preview = buildRulePreviewJson(form)
    form.rawConditions = preview.conditions
    form.rawActions = preview.actions
  }

  return form
}

function buildRuleRequestPayload(form: RuleForm): { payload?: Record<string, unknown>; error?: string } {
  if (form.advancedMode) {
    try {
      const conditions = JSON.parse(form.rawConditions)
      const actions = JSON.parse(form.rawActions)

      if (!isRecord(conditions)) {
        return { error: '高级模式下，条件必须是 JSON 对象。' }
      }
      if (!Array.isArray(actions)) {
        return { error: '高级模式下，动作必须是 JSON 数组。' }
      }

      return {
        payload: {
          name: form.name.trim(),
          description: form.description.trim() || undefined,
          enabled: form.enabled,
          priority: form.priority,
          conditions,
          actions,
        },
      }
    } catch {
      return { error: '高级模式 JSON 格式不正确。' }
    }
  }

  const actionResult = buildActionsValueFromForm(form)
  if (actionResult.error) return { error: actionResult.error }

  return {
    payload: {
      name: form.name.trim(),
      description: form.description.trim() || undefined,
      enabled: form.enabled,
      priority: form.priority,
      conditions: buildConditionValueFromForm(form),
      actions: actionResult.actions,
    },
  }
}

function buildRuleUpdatePayload(rule: DispositionRule): { payload?: Record<string, unknown>; error?: string } {
  const conditions = parseStoredJsonText(rule.conditions)
  const actions = parseStoredJsonText(rule.actions)

  if (!isRecord(conditions)) {
    return { error: `规则「${rule.name}」的条件格式异常，无法更新。请先进入编辑页修正。` }
  }
  if (!Array.isArray(actions)) {
    return { error: `规则「${rule.name}」的动作格式异常，无法更新。请先进入编辑页修正。` }
  }

  return {
    payload: {
      name: rule.name,
      description: rule.description || undefined,
      enabled: rule.enabled,
      priority: rule.priority,
      conditions,
      actions,
    },
  }
}

function describeRuleConditions(rule: DispositionRule): string[] {
  const parsed = parseStoredJsonText(rule.conditions)
  if (!isRecord(parsed)) return ['条件格式异常']

  const items: string[] = []
  if (typeof parsed.min_threat_level === 'string' && parsed.min_threat_level.trim()) {
    items.push(`等级 >= ${formatThreatLevelLabel(parsed.min_threat_level)}`)
  }
  if (typeof parsed.mail_direction === 'string' && parsed.mail_direction.trim()) {
    items.push(`方向: ${formatMailDirectionLabel(parsed.mail_direction)}`)
  }

  const categories = asStringArray(parsed.categories)
  if (categories.length > 0) items.push(`分类: ${categories.join(' / ')}`)

  const modules = asStringArray(parsed.flagged_modules)
  if (modules.length > 0) items.push(`模块: ${modules.join(' / ')}`)

  if (items.length === 0) items.push('任意告警均匹配')
  return items
}

function describeRuleActions(rule: DispositionRule): string[] {
  const parsed = parseStoredJsonText(rule.actions)
  if (!Array.isArray(parsed)) return ['动作格式异常']

  const labels = new Set<string>()
  for (const item of parsed) {
    if (!isRecord(item)) {
      labels.add('动作格式异常')
      continue
    }

    switch (normalizeActionType(typeof item.action_type === 'string' ? item.action_type : '')) {
      case 'email_alert':
        labels.add('邮件告警')
        if (typeof item.message_template === 'string' && item.message_template.trim()) labels.add('邮件定制内容')
        break
      case 'wechat_alert':
        labels.add('微信告警')
        if (typeof item.message_template === 'string' && item.message_template.trim()) labels.add('微信定制内容')
        break
      case 'webhook':
        labels.add('Webhook')
        break
      case 'log':
        labels.add('记录日志')
        break
      case 'alert':
        labels.add('文本告警')
        break
      default:
        labels.add('未知动作')
    }
  }

  return Array.from(labels)
}

function createPresetForm(kind: 'medium-email' | 'high-wechat' | 'inbound-high-wechat' | 'critical-dual'): RuleForm {
  const form = createEmptyRuleForm()

  if (kind === 'medium-email') {
    form.name = '中危及以上邮件告警'
    form.description = '匹配 Medium 及以上威胁，发送邮件告警。'
    form.minThreatLevel = 'medium'
    form.sendEmail = true
    form.sendWechat = false
    form.sendWebhook = false
    form.sendLog = false
  }

  if (kind === 'high-wechat') {
    form.name = '高危及以上微信告警'
    form.description = '匹配 High 及以上威胁，发送企业微信告警。'
    form.minThreatLevel = 'high'
    form.sendEmail = false
    form.sendWechat = true
    form.sendWebhook = false
    form.sendLog = false
  }

  if (kind === 'inbound-high-wechat') {
    form.name = '入站高危微信告警'
    form.description = '仅对入站 High 及以上威胁发送企业微信告警。'
    form.minThreatLevel = 'high'
    form.mailDirection = 'inbound'
    form.sendEmail = false
    form.sendWechat = true
    form.sendWebhook = false
    form.sendLog = false
  }

  if (kind === 'critical-dual') {
    form.name = '严重告警双通道通知'
    form.description = '匹配 Critical 威胁，同时发送邮件和企业微信告警。'
    form.minThreatLevel = 'critical'
    form.sendEmail = true
    form.sendWechat = true
    form.sendWebhook = false
    form.sendLog = true
  }

  const preview = buildRulePreviewJson(form)
  form.rawConditions = preview.conditions
  form.rawActions = preview.actions
  return form
}

const quickRulePresets: QuickRulePreset[] = [
  {
    id: 'medium-email',
    label: '中危邮件告警',
    description: 'Medium 及以上触发邮件告警',
    build: () => createPresetForm('medium-email'),
  },
  {
    id: 'high-wechat',
    label: '高危微信告警',
    description: 'High 及以上触发微信告警',
    build: () => createPresetForm('high-wechat'),
  },
  {
    id: 'inbound-high-wechat',
    label: '入站高危微信',
    description: '仅入站 High 及以上触发微信',
    build: () => createPresetForm('inbound-high-wechat'),
  },
  {
    id: 'critical-dual',
    label: '严重双通道',
    description: 'Critical 同时走邮件和微信',
    build: () => createPresetForm('critical-dual'),
  },
]

function truncate(s: string, max: number): string {
  return s.length > max ? s.substring(0, max) + '...' : s
}

function AutomationDisposition() {
  const [tab, setTab] = useState<'alert' | 'wechat' | 'rules'>('rules')

  const [alertConfig, setAlertConfig] = useState<EmailAlertConfig>({ ...defaultAlertConfig })
  const [alertSaving, setAlertSaving] = useState(false)
  const [alertTesting, setAlertTesting] = useState(false)
  const [alertMsg, setAlertMsg] = useState<UiMessage | null>(null)

  const [wechatConfig, setWechatConfig] = useState<WechatAlertConfig>({ ...defaultWechatConfig })
  const [wechatSaving, setWechatSaving] = useState(false)
  const [wechatTesting, setWechatTesting] = useState(false)
  const [wechatMsg, setWechatMsg] = useState<UiMessage | null>(null)

  const [rules, setRules] = useState<DispositionRule[]>([])
  const [rulesLoadError, setRulesLoadError] = useState(false)
  const [editing, setEditing] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState<RuleForm>(createEmptyRuleForm())
  const [saving, setSaving] = useState(false)
  const [ruleMsg, setRuleMsg] = useState<UiMessage | null>(null)
  const [pageLoading, setPageLoading] = useState(true)

  const fetchAlertConfig = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/email-alert')
      const data: ApiResponse<EmailAlertConfig> = await res.json()
      if (data.success && data.data) setAlertConfig({ ...defaultAlertConfig, ...data.data })
    } catch (e) {
      console.error('Failed to fetch email alert config:', e)
    }
  }, [])

  const fetchWechatConfig = useCallback(async () => {
    try {
      const res = await apiFetch('/api/security/wechat-alert')
      const data: ApiResponse<WechatAlertConfig> = await res.json()
      if (data.success && data.data) setWechatConfig({ ...defaultWechatConfig, ...data.data })
    } catch (e) {
      console.error('Failed to fetch WeChat alert config:', e)
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

  useEffect(() => {
    setPageLoading(true)
    Promise.all([fetchAlertConfig(), fetchWechatConfig(), fetchRules()]).finally(() => setPageLoading(false))
  }, [fetchAlertConfig, fetchWechatConfig, fetchRules])

  const handleAlertSave = async () => {
    if (alertConfig.smtp_tls === 'none' && !alertConfig.allow_plaintext_smtp) {
      setAlertMsg({ type: 'err', text: PLAINTEXT_SMTP_LOCK_MESSAGE })
      return
    }
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
        setAlertMsg({ type: 'err', text: normalizeSmtpUiError(data.error || '保存失败') })
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '网络错误'
      setAlertMsg({ type: 'err', text: normalizeSmtpUiError(msg) })
    } finally {
      setAlertSaving(false)
    }
  }

  const handleAlertTest = async () => {
    if (alertConfig.smtp_tls === 'none' && !alertConfig.allow_plaintext_smtp) {
      setAlertMsg({ type: 'err', text: PLAINTEXT_SMTP_LOCK_MESSAGE })
      return
    }
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
        setAlertMsg({ type: 'err', text: normalizeSmtpUiError(data.error || data.data?.message || '发送失败') })
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '网络错误'
      setAlertMsg({ type: 'err', text: normalizeSmtpUiError(msg) })
    } finally {
      setAlertTesting(false)
    }
  }

  const handleWechatSave = async () => {
    setWechatSaving(true)
    setWechatMsg(null)
    try {
      const res = await apiFetch('/api/security/wechat-alert', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(wechatConfig),
      })
      const data: ApiResponse<{ saved: boolean }> = await res.json()
      if (data.success) {
        setWechatMsg({ type: 'ok', text: '配置已保存' })
        fetchWechatConfig()
      } else {
        setWechatMsg({ type: 'err', text: normalizeWechatUiError(data.error || '保存失败') })
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '网络错误'
      setWechatMsg({ type: 'err', text: normalizeWechatUiError(msg) })
    } finally {
      setWechatSaving(false)
    }
  }

  const handleWechatTest = async () => {
    setWechatTesting(true)
    setWechatMsg(null)
    try {
      const res = await apiFetch('/api/security/wechat-alert/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(wechatConfig),
      })
      const data: ApiResponse<{ success: boolean; message: string }> = await res.json()
      if (data.success && data.data?.success) {
        setWechatMsg({ type: 'ok', text: '测试微信消息已发送' })
      } else {
        setWechatMsg({ type: 'err', text: normalizeWechatUiError(data.error || data.data?.message || '发送失败') })
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : '网络错误'
      setWechatMsg({ type: 'err', text: normalizeWechatUiError(msg) })
    } finally {
      setWechatTesting(false)
    }
  }

  const openNewRule = (nextForm?: RuleForm) => {
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
    setTab('rules')
  }

  const startEdit = (rule: DispositionRule) => {
    const nextForm = buildRuleFormFromRule(rule)
    setForm(nextForm)
    setEditing(rule.id)
    setShowCreate(true)
    setRuleMsg(nextForm.unsupportedReason ? { type: 'err', text: nextForm.unsupportedReason } : null)
    setTab('rules')
  }

  const toggleAdvancedMode = () => {
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
  }

  const handleRuleSave = async () => {
    setSaving(true)
    setRuleMsg(null)

    if (!form.name.trim()) {
      setSaving(false)
      setRuleMsg({ type: 'err', text: '请填写规则名称。' })
      return
    }

    const request = buildRuleRequestPayload(form)
    if (request.error || !request.payload) {
      setSaving(false)
      setRuleMsg({ type: 'err', text: request.error || '规则配置不完整。' })
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
        setRuleMsg({ type: 'err', text: data.error || '保存规则失败' })
        return
      }

      setShowCreate(false)
      setEditing(null)
      setForm(createEmptyRuleForm())
      setRuleMsg({ type: 'ok', text: editing ? '规则已更新' : '规则已创建' })
      fetchRules()
    } catch (e) {
      console.error('Failed to save rule:', e)
      setRuleMsg({ type: 'err', text: '网络错误' })
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('确定要删除此规则?')) return
    try {
      const res = await apiFetch(`/api/security/rules/${id}`, { method: 'DELETE' })
      const data: ApiResponse<{ deleted: boolean }> = await res.json()
      if (!res.ok || !data.success) {
        setRuleMsg({ type: 'err', text: data.error || '删除规则失败' })
        return
      }
      setRuleMsg({ type: 'ok', text: '规则已删除' })
      fetchRules()
    } catch (e) {
      console.error('Failed to delete rule:', e)
      setRuleMsg({ type: 'err', text: '网络错误' })
    }
  }

  const handleToggle = async (rule: DispositionRule) => {
    const request = buildRuleUpdatePayload({ ...rule, enabled: !rule.enabled })
    if (request.error || !request.payload) {
      setRuleMsg({ type: 'err', text: request.error || '规则更新失败' })
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
        setRuleMsg({ type: 'err', text: data.error || '更新规则失败' })
        return
      }
      setRuleMsg({ type: 'ok', text: rule.enabled ? '规则已禁用' : '规则已启用' })
      fetchRules()
    } catch (e) {
      console.error('Failed to toggle rule:', e)
      setRuleMsg({ type: 'err', text: '网络错误' })
    }
  }

  const activeRules = rules.filter(rule => rule.enabled).length
  const visualPreview = buildRulePreviewJson(form)

  if (pageLoading) {
    return (
      <div className="auto-page">
        <div className="sec-loading"><div className="sec-spinner" />加载配置...</div>
      </div>
    )
  }

  return (
    <div className="auto-page">
      <div className="auto-header">
        <div>
          <h2>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            自动化处置
          </h2>
          <p className="auto-header-sub">先配置处置规则，再配置邮件与微信告警通道</p>
        </div>
      </div>

      <div className="sec-tabs">
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
          className={`sec-tab ${tab === 'wechat' ? 'sec-tab--active' : ''}`}
          onClick={() => setTab('wechat')}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          </svg>
          微信告警
          {wechatConfig.enabled && <span className="sec-tab-badge">ON</span>}
        </button>
      </div>

      {tab === 'rules' && (
        <>
          <div className="auto-rule-intro">
            <div className="auto-rule-intro-copy">
              <p className="auto-rule-intro-title">处置规则决定“什么情况下触发什么动作”</p>
              <p className="auto-rule-intro-text">邮件告警和微信告警页签只负责通道配置。这里才决定是否真正发送，以及发到哪些动作。</p>
            </div>
            <div className="auto-rule-template-row">
              {quickRulePresets.map(preset => (
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
              处置规则
              <span className="auto-rules-count">{rules.length}</span>
            </h3>
            {!showCreate && (
              <button className="sec-btn sec-btn--primary" onClick={() => openNewRule()}>
                + 新建规则
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
                  <h4>{editing ? '编辑规则' : '新建规则'}</h4>
                  <p className="auto-form-hint">
                    优先级数字越小越先执行。通常先从最低告警等级和动作类型开始配置。
                  </p>
                </div>
                <button className="auto-rule-link" onClick={toggleAdvancedMode}>
                  {form.advancedMode ? '切换为可视化' : '切换为高级 JSON'}
                </button>
              </div>

              <div className="auto-form-grid auto-form-grid--2-narrow">
                <div className="auto-form-group">
                  <label className="auto-form-label">规则名称</label>
                  <input
                    className="auto-form-input"
                    type="text"
                    value={form.name}
                    onChange={e => setForm({ ...form, name: e.target.value })}
                    placeholder="例: 中危及以上邮件告警"
                  />
                </div>
                <div className="auto-form-group">
                  <label className="auto-form-label">优先级</label>
                  <input
                    className="auto-form-input"
                    type="number"
                    value={form.priority}
                    onChange={e => setForm({ ...form, priority: parseInt(e.target.value, 10) || 100 })}
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
                  placeholder="说明这个规则的用途，便于后续维护"
                />
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

              {form.advancedMode ? (
                <>
                  <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-4)' }}>
                    <div className="auto-form-group">
                      <label className="auto-form-label">触发条件 (JSON 对象)</label>
                      <textarea
                        className="auto-form-textarea"
                        rows={8}
                        value={form.rawConditions}
                        onChange={e => setForm({ ...form, rawConditions: e.target.value })}
                        placeholder='{"min_threat_level":"medium","categories":["phishing"]}'
                      />
                    </div>
                    <div className="auto-form-group">
                      <label className="auto-form-label">执行动作 (JSON 数组)</label>
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
                    高级模式适合处理复杂规则或历史规则兼容。条件支持 <code>mail_direction</code>，动作支持 <code>message_template</code>。
                  </div>
                </>
              ) : (
                <>
                  <div className="auto-rule-builder-grid" style={{ marginTop: 'var(--space-4)' }}>
                    <div className="auto-builder-card">
                      <div className="auto-section-label">何时触发</div>
                      <div className="auto-form-grid auto-form-grid--2-narrow">
                        <div className="auto-form-group">
                          <label className="auto-form-label">最低告警等级</label>
                          <select
                            className="auto-form-select"
                            value={form.minThreatLevel}
                            onChange={e => setForm({ ...form, minThreatLevel: e.target.value })}
                          >
                            <option value="">任意等级</option>
                            {commonThreatLevels.map(option => (
                              <option key={option.value} value={option.value}>{option.label}</option>
                            ))}
                          </select>
                        </div>
                        <div className="auto-form-group">
                          <label className="auto-form-label">邮件方向</label>
                          <select
                            className="auto-form-select"
                            value={form.mailDirection}
                            onChange={e => setForm({ ...form, mailDirection: e.target.value })}
                          >
                            {mailDirectionOptions.map(option => (
                              <option key={option.value || 'any'} value={option.value}>{option.label}</option>
                            ))}
                          </select>
                          <span className="auto-form-hint">入站适合做外部邮件告警，出站和内部适合区分外发场景。</span>
                        </div>
                      </div>
                      <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-3)' }}>
                        <div className="auto-form-group">
                          <label className="auto-form-label">命中分类</label>
                          <textarea
                            className="auto-form-textarea"
                            rows={4}
                            value={form.categoriesText}
                            onChange={e => setForm({ ...form, categoriesText: e.target.value })}
                            placeholder={'每行一个分类\nphishing\nspoofing'}
                          />
                          <span className="auto-form-hint">留空表示不按分类过滤。</span>
                        </div>
                        <div className="auto-form-group">
                          <label className="auto-form-label">命中模块</label>
                          <textarea
                            className="auto-form-textarea"
                            rows={4}
                            value={form.flaggedModulesText}
                            onChange={e => setForm({ ...form, flaggedModulesText: e.target.value })}
                            placeholder={'每行一个模块 ID\ncontent_scan\nlink_analysis'}
                          />
                          <span className="auto-form-hint">留空表示不按模块过滤。适合做更精细的自动化策略。</span>
                        </div>
                      </div>
                    </div>

                    <div className="auto-builder-card">
                      <div className="auto-section-label">执行什么</div>
                      <div className="auto-action-grid">
                        <label className={`auto-action-tile ${form.sendEmail ? 'auto-action-tile--active' : ''}`}>
                          <input
                            type="checkbox"
                            checked={form.sendEmail}
                            onChange={e => setForm({ ...form, sendEmail: e.target.checked })}
                          />
                          <span className="auto-action-tile-title">邮件告警</span>
                          <span className="auto-action-tile-desc">使用邮件告警配置发送</span>
                        </label>
                        <label className={`auto-action-tile ${form.sendWechat ? 'auto-action-tile--active' : ''}`}>
                          <input
                            type="checkbox"
                            checked={form.sendWechat}
                            onChange={e => setForm({ ...form, sendWechat: e.target.checked })}
                          />
                          <span className="auto-action-tile-title">微信告警</span>
                          <span className="auto-action-tile-desc">使用企业微信通道发送</span>
                        </label>
                        <label className={`auto-action-tile ${form.sendWebhook ? 'auto-action-tile--active' : ''}`}>
                          <input
                            type="checkbox"
                            checked={form.sendWebhook}
                            onChange={e => setForm({ ...form, sendWebhook: e.target.checked })}
                          />
                          <span className="auto-action-tile-title">Webhook</span>
                          <span className="auto-action-tile-desc">调用外部接口接收告警</span>
                        </label>
                        <label className={`auto-action-tile ${form.sendLog ? 'auto-action-tile--active' : ''}`}>
                          <input
                            type="checkbox"
                            checked={form.sendLog}
                            onChange={e => setForm({ ...form, sendLog: e.target.checked })}
                          />
                          <span className="auto-action-tile-title">记录日志</span>
                          <span className="auto-action-tile-desc">在服务端保留动作痕迹</span>
                        </label>
                      </div>

                      {(form.sendEmail || form.sendWechat) && (
                        <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-3)' }}>
                          {form.sendEmail && (
                            <div className="auto-form-group">
                              <label className="auto-form-label">邮件自定义内容模板</label>
                              <textarea
                                className="auto-form-textarea"
                                rows={4}
                                value={form.emailMessageTemplate}
                                onChange={e => setForm({ ...form, emailMessageTemplate: e.target.value })}
                                placeholder="可选。会作为邮件顶部的自定义告警内容显示。"
                              />
                            </div>
                          )}
                          {form.sendWechat && (
                            <div className="auto-form-group">
                              <label className="auto-form-label">微信自定义内容模板</label>
                              <textarea
                                className="auto-form-textarea"
                                rows={4}
                                value={form.wechatMessageTemplate}
                                onChange={e => setForm({ ...form, wechatMessageTemplate: e.target.value })}
                                placeholder="可选。会加在自动生成的微信告警摘要前面。"
                              />
                            </div>
                          )}
                        </div>
                      )}

                      {(form.sendEmail || form.sendWechat) && (
                        <div className="auto-form-hint" style={{ marginTop: '8px' }}>
                          模板支持：
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
                          <label className="auto-form-label">微信规则内 @ 手机号</label>
                          <textarea
                            className="auto-form-textarea"
                            rows={4}
                            value={form.wechatMentionedMobileText}
                            onChange={e => setForm({ ...form, wechatMentionedMobileText: e.target.value })}
                            placeholder={'可选，留空则沿用微信通道配置\n13800000000'}
                          />
                          <span className="auto-form-hint">规则内配置会覆盖微信告警页签里的默认手机号列表。</span>
                        </div>
                      )}

                      {form.sendWebhook && (
                        <div className="auto-form-grid auto-form-grid--2" style={{ marginTop: 'var(--space-3)' }}>
                          <div className="auto-form-group">
                            <label className="auto-form-label">Webhook 地址</label>
                            <input
                              className="auto-form-input"
                              type="text"
                              value={form.webhookUrl}
                              onChange={e => setForm({ ...form, webhookUrl: e.target.value })}
                              placeholder="https://hooks.example.com/security"
                            />
                          </div>
                          <div className="auto-form-group">
                            <label className="auto-form-label">请求头</label>
                            <textarea
                              className="auto-form-textarea"
                              rows={4}
                              value={form.webhookHeadersText}
                              onChange={e => setForm({ ...form, webhookHeadersText: e.target.value })}
                              placeholder={'每行一个请求头\nAuthorization: Bearer token'}
                            />
                            <span className="auto-form-hint">可选。按“Header-Name: value”格式填写。</span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="auto-preview-grid">
                    <div className="auto-preview-card">
                      <div className="auto-preview-title">生成的条件</div>
                      <pre>{visualPreview.conditions}</pre>
                    </div>
                    <div className="auto-preview-card">
                      <div className="auto-preview-title">生成的动作</div>
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

          {rules.length === 0 ? (
            <div className="sec-empty">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.3 }}>
                <polyline points="9 11 12 14 22 4"/>
                <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
              </svg>
              <p>{rulesLoadError ? '规则加载失败' : '暂无处置规则'}</p>
              <p className="sec-empty-hint">{rulesLoadError ? '请检查网络连接或稍后重试' : '可以直接点击上面的模板，先生成一条常用规则。'}</p>
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
                        {describeRuleConditions(rule).map(item => (
                          <span
                            key={`${rule.id}-condition-${item}`}
                            className={`auto-chip ${item.includes('异常') ? 'auto-chip--danger' : 'auto-chip--condition'}`}
                          >
                            {truncate(item, 120)}
                          </span>
                        ))}
                      </div>

                      <div className="auto-rule-chip-row">
                        {describeRuleActions(rule).map(item => (
                          <span
                            key={`${rule.id}-action-${item}`}
                            className={`auto-chip ${item.includes('异常') || item.includes('未知') ? 'auto-chip--danger' : 'auto-chip--action'}`}
                          >
                            {item}
                          </span>
                        ))}
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

      {tab === 'alert' && (
        <div className="auto-alert-card">
          <div className="auto-alert-head">
            <div className="auto-alert-head-left">
              <div className="auto-alert-icon">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                  <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
                </svg>
              </div>
              <div>
                <p className="auto-alert-head-title">邮件告警配置</p>
                <p className="auto-alert-head-desc">配置邮件告警通道，供处置规则中的 email_alert 动作调用</p>
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

          <div className="auto-alert-body">
            <div className="auto-form-hint" style={{ marginBottom: 'var(--space-3)' }}>
              这里只配置邮件告警通道。实际是否发送，由“处置规则”中的 <code>email_alert</code> 动作决定。
            </div>
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
                    onChange={e => setAlertConfig({ ...alertConfig, smtp_port: parseInt(e.target.value, 10) || 587 })}
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
              <div className="auto-check-row">
                <label className="auto-check-label">
                  <input
                    type="checkbox"
                    checked={Boolean(alertConfig.allow_plaintext_smtp)}
                    onChange={e => setAlertConfig({ ...alertConfig, allow_plaintext_smtp: e.target.checked })}
                  />
                  允许明文 SMTP（管理员开关）
                </label>
              </div>
              <div className="auto-form-hint" style={{ marginTop: '8px' }}>
                仅当加密方式选择“无加密”时生效。开启后配置会持久化保存，SMTP 凭据与邮件内容都可能以明文方式传输。
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
                    {alertConfig.smtp_password_set && <span className="auto-form-label-hint">(已设置)</span>}
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
              <div className="auto-form-hint" style={{ marginTop: '8px' }}>
                用户名和密码同时留空表示不启用 SMTP 认证，适用于受信内网中继或无需 AUTH 的服务器。
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
                    {commonThreatLevels.map(option => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
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

      {tab === 'wechat' && (
        <div className="auto-alert-card">
          <div className="auto-alert-head">
            <div className="auto-alert-head-left">
              <div className="auto-alert-icon">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                </svg>
              </div>
              <div>
                <p className="auto-alert-head-title">微信告警配置</p>
                <p className="auto-alert-head-desc">配置企业微信告警通道，供处置规则中的 wechat_alert 动作调用</p>
              </div>
            </div>
            <label className="s-toggle">
              <input
                type="checkbox"
                checked={wechatConfig.enabled}
                onChange={e => setWechatConfig({ ...wechatConfig, enabled: e.target.checked })}
              />
              <span className="s-toggle-slider" />
            </label>
          </div>

          <div className="auto-alert-body">
            <div className="auto-form-hint" style={{ marginBottom: 'var(--space-3)' }}>
              这里只配置微信告警通道。实际是否发送，由“处置规则”中的 <code>wechat_alert</code> 动作决定。
            </div>
            <div className="auto-section">
              <div className="auto-section-label">Webhook</div>
              <div className="auto-form-grid">
                <div className="auto-form-group">
                  <label className="auto-form-label">
                    企业微信机器人地址
                    {wechatConfig.webhook_url_set && <span className="auto-form-label-hint">(已设置)</span>}
                  </label>
                  <input
                    className="auto-form-input"
                    type="password"
                    value={wechatConfig.webhook_url}
                    onChange={e => setWechatConfig({ ...wechatConfig, webhook_url: e.target.value })}
                    placeholder={wechatConfig.webhook_url_set ? '留空保持不变' : 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...'}
                  />
                </div>
              </div>
              <div className="auto-form-hint" style={{ marginTop: '8px' }}>
                保存时会加密存储。仅接受企业微信机器人官方 Webhook 地址。
              </div>
            </div>

            <div className="auto-section">
              <div className="auto-section-label">告警规则</div>
              <div className="auto-form-grid auto-form-grid--2">
                <div className="auto-form-group">
                  <label className="auto-form-label">最低告警等级</label>
                  <select
                    className="auto-form-select"
                    value={wechatConfig.min_threat_level}
                    onChange={e => setWechatConfig({ ...wechatConfig, min_threat_level: e.target.value })}
                  >
                    {commonThreatLevels.map(option => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </div>
                <div className="auto-form-group">
                  <label className="auto-form-label">被@手机号列表</label>
                  <textarea
                    className="auto-form-textarea"
                    rows={4}
                    value={formatLineList(wechatConfig.mentioned_mobile_list)}
                    onChange={e => setWechatConfig({
                      ...wechatConfig,
                      mentioned_mobile_list: parseLineList(e.target.value),
                    })}
                    placeholder={'每行一个手机号\n13800000000'}
                  />
                </div>
              </div>
              <div className="auto-form-hint" style={{ marginTop: '8px' }}>
                仅对企业微信机器人 `text` 消息生效。手机号需对应企业微信通讯录成员。
              </div>
            </div>
          </div>

          <div className="auto-alert-footer">
            {wechatMsg && (
              <div className={`auto-msg ${wechatMsg.type === 'ok' ? 'auto-msg--ok' : 'auto-msg--err'}`}>
                {wechatMsg.text}
              </div>
            )}
            <div style={{ flex: 1 }} />
            <button
              className="sec-btn sec-btn--secondary"
              onClick={handleWechatTest}
              disabled={wechatTesting || (!wechatConfig.webhook_url && !wechatConfig.webhook_url_set)}
            >
              {wechatTesting ? '发送中...' : '测试发送'}
            </button>
            <button
              className="sec-btn sec-btn--primary"
              onClick={handleWechatSave}
              disabled={wechatSaving}
            >
              {wechatSaving ? '保存中...' : '保存配置'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default AutomationDisposition
