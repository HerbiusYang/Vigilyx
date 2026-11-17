import { afterEach, beforeEach, expect, it } from 'vitest'
import i18n from '../../i18n'
import { DLP_MATCH_CN, FINANCIAL_POLICY, INCIDENT_TYPE_CN } from './constants'
import { localizeIncidentText, localizeIncidentLocation } from './incidentText'

beforeEach(async () => { await i18n.changeLanguage('zh') })
afterEach(async () => { await i18n.changeLanguage('zh') })

it('localizes persisted mail summaries and field evidence without claiming authorization or delivery', () => {
  expect(localizeIncidentText('Sensitive mail transfer risk: customer@example.com from 192.0.2.1 submitted large_amount, loan_credit_info; authorization unverified'))
    .toBe('敏感邮件发送风险：customer@example.com 从 192.0.2.1 提交了含大额金额、贷款征信信息的邮件；授权状态待核实')
  expect(localizeIncidentText('Email content contains Large Amount (2 field matches)')).toBe('邮件内容含大额金额（2 处字段匹配）')
  expect(localizeIncidentText('Email content contains Loan/Credit Information (6 field matches)')).toBe('邮件内容含贷款征信信息（6 处字段匹配）')
  expect(localizeIncidentText('email_address: 1 field matches')).toBe('邮件内容含电子邮箱（1 处字段匹配）')
  expect(localizeIncidentLocation('HTTP delivery request')).toBe('网页邮箱发送请求')
  expect(localizeIncidentLocation('email content')).toBe('邮件正文')
})

it('keeps incomplete coverage visible and preserves filenames and paths verbatim', () => {
  expect(localizeIncidentText('Document inspection incomplete: 192.0.2.1 uploaded "预算<&>.pdf"'))
    .toBe('文档检查不完整：192.0.2.1 上传了“预算<&>.pdf”')
  expect(localizeIncidentText('Document inspection exceeded a work or extraction budget; retained text does not certify complete coverage'))
    .toContain('不能证明检查覆盖完整')
  expect(localizeIncidentText('Draft save contains sensitive data (URI: /draft?token=redacted)'))
    .toBe('保存的草稿含敏感数据（请求路径：/draft?token=redacted）')
  const original = 'Unrecognized observation; customer text stays unchanged'
  expect(localizeIncidentText(original)).toBe(original)
})

it('switches existing summaries and labels between Chinese and English without changing stored data', async () => {
  const summary = 'Sensitive mail transfer risk: customer@example.com from 192.0.2.1 submitted phone_number; authorization unverified'
  expect(localizeIncidentText(summary)).toContain('手机号码')
  expect(INCIDENT_TYPE_CN.sensitive_data_transfer).toBe('敏感数据发送风险')
  expect(DLP_MATCH_CN.scan_incomplete).toBe('检查不完整')
  await i18n.changeLanguage('en')
  expect(localizeIncidentText(summary)).toContain('Phone Number; authorization unverified')
  expect(INCIDENT_TYPE_CN.sensitive_data_transfer).toBe('Sensitive transfer risk')
  expect(localizeIncidentLocation('DocumentationContent')).toBe('File content')
  await i18n.changeLanguage('zh')
  expect(localizeIncidentText(summary)).toContain('手机号码')
  expect(summary).toContain('submitted phone_number')
})

it('has both language labels for every current incident type and policy field', () => {
  const types = ['sensitive_data_transfer', 'bulk_sensitive_transfer', 'draft_box_abuse', 'file_transit_abuse', 'self_sending', 'volume_anomaly', 'jrt_compliance_violation']
  const fields = [...Object.keys(FINANCIAL_POLICY.field_levels), 'scan_incomplete', 'email_address', 'bulk_sensitive_level3', 'bulk_sensitive_level4']
  for (const lng of ['zh', 'en']) {
    for (const type of types) expect(i18n.exists(`dataSecurity.incidentType_${type}`, { lng }), type).toBe(true)
    for (const field of fields) expect(i18n.exists(`dataSecurity.dlpMatch_${field}`, { lng }), field).toBe(true)
  }
  expect(DLP_MATCH_CN.future_field).toBe('future_field')
})
