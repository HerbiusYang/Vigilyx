/**
 * Pure helper functions for disposition rule forms:
 * parsing, validation, serialization, presets, and display labels.
 */

import i18n from '../../i18n'
import type { DispositionRule } from '../../types'
import type {
  RuleForm,
  DispositionConditionValue,
  DispositionActionValue,
  RuleActionType,
  QuickRulePreset,
} from './types'

// ---------------------------------------------------------------------------
// Generic utilities
// ---------------------------------------------------------------------------

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function parseLineList(value: string): string[] {
  const normalized: string[] = []
  for (const item of value.split(/[\n,，]/)) {
    const trimmed = item.trim()
    if (trimmed && !normalized.includes(trimmed)) normalized.push(trimmed)
  }
  return normalized
}

export function formatLineList(values: string[] | undefined): string {
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
      return { headers: {}, error: i18n.t('automation.error.headerFormatInvalid', { line }) }
    }
    const key = line.slice(0, separatorIndex).trim()
    const value = line.slice(separatorIndex + 1).trim()
    if (!key || !value) {
      return { headers: {}, error: i18n.t('automation.error.headerFormatInvalid', { line }) }
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

export function normalizeActionType(actionType: string): RuleActionType | string {
  const normalized = actionType.trim().toLowerCase()
  if (normalized === 'email') return 'email_alert'
  if (normalized === 'wechat') return 'wechat_alert'
  return normalized
}

// ---------------------------------------------------------------------------
// Display labels
// ---------------------------------------------------------------------------

export function formatThreatLevelLabel(level: string): string {
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
      return level || i18n.t('automation.anyLevel')
  }
}

export function formatMailDirectionLabel(direction: string): string {
  switch (direction) {
    case 'inbound':
      return i18n.t('automation.directionInbound')
    case 'outbound':
      return i18n.t('automation.directionOutbound')
    case 'internal':
      return i18n.t('automation.directionInternal')
    default:
      return direction || i18n.t('automation.directionAny')
  }
}

export function truncate(s: string, max: number): string {
  return s.length > max ? s.substring(0, max) + '...' : s
}

// ---------------------------------------------------------------------------
// Empty / default form
// ---------------------------------------------------------------------------

export function createEmptyRuleForm(): RuleForm {
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

// ---------------------------------------------------------------------------
// Form ↔ JSON conversion
// ---------------------------------------------------------------------------

export function buildConditionValueFromForm(form: RuleForm): DispositionConditionValue {
  const value: DispositionConditionValue = {}
  if (form.minThreatLevel) value.min_threat_level = form.minThreatLevel
  if (form.mailDirection) value.mail_direction = form.mailDirection

  const categories = parseLineList(form.categoriesText)
  if (categories.length > 0) value.categories = categories

  const flaggedModules = parseLineList(form.flaggedModulesText)
  if (flaggedModules.length > 0) value.flagged_modules = flaggedModules

  return value
}

export function buildActionsValueFromForm(form: RuleForm): { actions: DispositionActionValue[]; error?: string } {
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
      return { actions: [], error: i18n.t('automation.error.webhookUrlRequired') }
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
    return { actions: [], error: i18n.t('automation.error.noActionSelected') }
  }

  return { actions }
}

export function buildRulePreviewJson(form: RuleForm): { conditions: string; actions: string } {
  const conditions = buildConditionValueFromForm(form)
  const actionsResult = buildActionsValueFromForm(form)

  return {
    conditions: JSON.stringify(conditions, null, 2),
    actions: JSON.stringify(actionsResult.actions, null, 2),
  }
}

export function buildRuleFormFromRule(rule: DispositionRule): RuleForm {
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
    unsupportedReason = i18n.t('automation.unsupported.conditionNotVisual')
  }

  if (Array.isArray(parsedActions)) {
    for (const rawAction of parsedActions) {
      if (!isRecord(rawAction)) {
        unsupportedReason = i18n.t('automation.unsupported.actionFormatError')
        continue
      }

      const actionType = normalizeActionType(typeof rawAction.action_type === 'string' ? rawAction.action_type : '')

      switch (actionType) {
        case 'email_alert':
          form.sendEmail = true
          if (typeof rawAction.message_template === 'string') {
            if (form.emailMessageTemplate && form.emailMessageTemplate !== rawAction.message_template) {
              unsupportedReason = i18n.t('automation.unsupported.multipleEmailTemplates')
            } else {
              form.emailMessageTemplate = rawAction.message_template
            }
          }
          break
        case 'wechat_alert': {
          form.sendWechat = true
          if (typeof rawAction.webhook_url === 'string' && rawAction.webhook_url.trim()) {
            unsupportedReason = i18n.t('automation.unsupported.wechatWebhookOverride')
          }
          if (typeof rawAction.message_template === 'string') {
            if (form.wechatMessageTemplate && form.wechatMessageTemplate !== rawAction.message_template) {
              unsupportedReason = i18n.t('automation.unsupported.multipleWechatTemplates')
            } else {
              form.wechatMessageTemplate = rawAction.message_template
            }
          }
          const mobileText = formatLineList(asStringArray(rawAction.mentioned_mobile_list))
          if (mobileText) {
            if (form.wechatMentionedMobileText && form.wechatMentionedMobileText !== mobileText) {
              unsupportedReason = i18n.t('automation.unsupported.multipleWechatMobiles')
            } else {
              form.wechatMentionedMobileText = mobileText
            }
          }
          break
        }
        case 'webhook': {
          form.sendWebhook = true
          if (typeof rawAction.webhook_url !== 'string' || !rawAction.webhook_url.trim()) {
            unsupportedReason = i18n.t('automation.unsupported.webhookMissingUrl')
            break
          }
          if (form.webhookUrl && form.webhookUrl !== rawAction.webhook_url) {
            unsupportedReason = i18n.t('automation.unsupported.multipleWebhookUrls')
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
              unsupportedReason = i18n.t('automation.unsupported.multipleWebhookHeaders')
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
          unsupportedReason = i18n.t('automation.unsupported.unknownActionType', { actionType: actionType || 'unknown' })
      }
    }
  } else if (rule.actions.trim()) {
    unsupportedReason = i18n.t('automation.unsupported.actionNotVisual')
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

export function buildRuleRequestPayload(form: RuleForm): { payload?: Record<string, unknown>; error?: string } {
  if (form.advancedMode) {
    try {
      const conditions = JSON.parse(form.rawConditions)
      const actions = JSON.parse(form.rawActions)

      if (!isRecord(conditions)) {
        return { error: i18n.t('automation.error.advancedConditionMustBeObject') }
      }
      if (!Array.isArray(actions)) {
        return { error: i18n.t('automation.error.advancedActionMustBeArray') }
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
      return { error: i18n.t('automation.error.advancedJsonInvalid') }
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

export function buildRuleUpdatePayload(rule: DispositionRule): { payload?: Record<string, unknown>; error?: string } {
  const conditions = parseStoredJsonText(rule.conditions)
  const actions = parseStoredJsonText(rule.actions)

  if (!isRecord(conditions)) {
    return { error: i18n.t('automation.error.ruleConditionAbnormal', { name: rule.name }) }
  }
  if (!Array.isArray(actions)) {
    return { error: i18n.t('automation.error.ruleActionAbnormal', { name: rule.name }) }
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

// ---------------------------------------------------------------------------
// Rule card display helpers
// ---------------------------------------------------------------------------

export function describeRuleConditions(rule: DispositionRule): string[] {
  const parsed = parseStoredJsonText(rule.conditions)
  if (!isRecord(parsed)) return [i18n.t('automation.chip.conditionAbnormal')]

  const items: string[] = []
  if (typeof parsed.min_threat_level === 'string' && parsed.min_threat_level.trim()) {
    items.push(i18n.t('automation.chip.levelGte', { level: formatThreatLevelLabel(parsed.min_threat_level) }))
  }
  if (typeof parsed.mail_direction === 'string' && parsed.mail_direction.trim()) {
    items.push(i18n.t('automation.chip.direction', { direction: formatMailDirectionLabel(parsed.mail_direction) }))
  }

  const categories = asStringArray(parsed.categories)
  if (categories.length > 0) items.push(i18n.t('automation.chip.categories', { list: categories.join(' / ') }))

  const modules = asStringArray(parsed.flagged_modules)
  if (modules.length > 0) items.push(i18n.t('automation.chip.modules', { list: modules.join(' / ') }))

  if (items.length === 0) items.push(i18n.t('automation.chip.matchAny'))
  return items
}

export function describeRuleActions(rule: DispositionRule): string[] {
  const parsed = parseStoredJsonText(rule.actions)
  if (!Array.isArray(parsed)) return [i18n.t('automation.chip.actionAbnormal')]

  const labels = new Set<string>()
  for (const item of parsed) {
    if (!isRecord(item)) {
      labels.add(i18n.t('automation.chip.actionAbnormal'))
      continue
    }

    switch (normalizeActionType(typeof item.action_type === 'string' ? item.action_type : '')) {
      case 'email_alert':
        labels.add(i18n.t('automation.action.emailAlert'))
        if (typeof item.message_template === 'string' && item.message_template.trim()) labels.add(i18n.t('automation.chip.emailCustomContent'))
        break
      case 'wechat_alert':
        labels.add(i18n.t('automation.action.wechatAlert'))
        if (typeof item.message_template === 'string' && item.message_template.trim()) labels.add(i18n.t('automation.chip.wechatCustomContent'))
        break
      case 'webhook':
        labels.add('Webhook')
        break
      case 'log':
        labels.add(i18n.t('automation.action.log'))
        break
      case 'alert':
        labels.add(i18n.t('automation.chip.textAlert'))
        break
      default:
        labels.add(i18n.t('automation.chip.unknownAction'))
    }
  }

  return Array.from(labels)
}

// ---------------------------------------------------------------------------
// Quick-create presets
// ---------------------------------------------------------------------------

function createPresetForm(kind: 'medium-email' | 'high-wechat' | 'inbound-high-wechat' | 'critical-dual'): RuleForm {
  const form = createEmptyRuleForm()

  if (kind === 'medium-email') {
    form.name = i18n.t('automation.preset.mediumEmailName')
    form.description = i18n.t('automation.preset.mediumEmailDesc')
    form.minThreatLevel = 'medium'
    form.sendEmail = true
    form.sendWechat = false
    form.sendWebhook = false
    form.sendLog = false
  }

  if (kind === 'high-wechat') {
    form.name = i18n.t('automation.preset.highWechatName')
    form.description = i18n.t('automation.preset.highWechatDesc')
    form.minThreatLevel = 'high'
    form.sendEmail = false
    form.sendWechat = true
    form.sendWebhook = false
    form.sendLog = false
  }

  if (kind === 'inbound-high-wechat') {
    form.name = i18n.t('automation.preset.inboundHighWechatName')
    form.description = i18n.t('automation.preset.inboundHighWechatDesc')
    form.minThreatLevel = 'high'
    form.mailDirection = 'inbound'
    form.sendEmail = false
    form.sendWechat = true
    form.sendWebhook = false
    form.sendLog = false
  }

  if (kind === 'critical-dual') {
    form.name = i18n.t('automation.preset.criticalDualName')
    form.description = i18n.t('automation.preset.criticalDualDesc')
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

export function getQuickRulePresets(): QuickRulePreset[] {
  return [
    {
      id: 'medium-email',
      label: i18n.t('automation.preset.mediumEmailLabel'),
      description: i18n.t('automation.preset.mediumEmailBrief'),
      build: () => createPresetForm('medium-email'),
    },
    {
      id: 'high-wechat',
      label: i18n.t('automation.preset.highWechatLabel'),
      description: i18n.t('automation.preset.highWechatBrief'),
      build: () => createPresetForm('high-wechat'),
    },
    {
      id: 'inbound-high-wechat',
      label: i18n.t('automation.preset.inboundHighWechatLabel'),
      description: i18n.t('automation.preset.inboundHighWechatBrief'),
      build: () => createPresetForm('inbound-high-wechat'),
    },
    {
      id: 'critical-dual',
      label: i18n.t('automation.preset.criticalDualLabel'),
      description: i18n.t('automation.preset.criticalDualBrief'),
      build: () => createPresetForm('critical-dual'),
    },
  ]
}
