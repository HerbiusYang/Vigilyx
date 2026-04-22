/** Shared types for automation disposition components. */

import i18n from '../../i18n'

export type UiMessage = { type: 'ok' | 'err'; text: string }

export type RuleActionType = 'email_alert' | 'wechat_alert' | 'webhook' | 'log' | 'alert'

export interface DispositionConditionValue {
  min_threat_level?: string
  mail_direction?: string
  categories?: string[]
  flagged_modules?: string[]
}

export interface DispositionActionValue {
  action_type: string
  webhook_url?: string
  mentioned_mobile_list?: string[]
  headers?: Record<string, string>
  message_template?: string
}

export interface RuleForm {
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

export interface QuickRulePreset {
  id: string
  label: string
  description: string
  build: () => RuleForm
}

export const getCommonThreatLevels = () => [
  { value: 'medium', label: i18n.t('automation.threatLevelMedium') },
  { value: 'high', label: i18n.t('automation.threatLevelHigh') },
  { value: 'critical', label: i18n.t('automation.threatLevelCritical') },
]

export const getMailDirectionOptions = () => [
  { value: '', label: i18n.t('automation.directionAny') },
  { value: 'inbound', label: i18n.t('automation.directionInbound') },
  { value: 'outbound', label: i18n.t('automation.directionOutbound') },
  { value: 'internal', label: i18n.t('automation.directionInternal') },
]
