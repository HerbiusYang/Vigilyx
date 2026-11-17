import i18n from '../../i18n'

// Compatibility with descriptions already persisted by the detectors. Translate
// only known generated templates; filenames, URLs and evidence snippets stay data.
const legacyDlpNames: Record<string, string> = {
  id_number: 'ID Card Number', sensitive_extension: 'High-Risk File Type',
  email_address: 'Email Address', credential_leak: 'Credential Leak',
  cvv_code: 'CVV Security Code', executable_upload: 'Executable File',
  file_type_mismatch: 'File Type Disguise', medical_health: 'Medical Health Data',
  vehicle_info: 'Vehicle Information', property_info: 'Real Estate Information',
  income_info: 'Income/Salary Data', geo_location: 'Geographic Location',
  otp_verification: 'Verification Code/OTP', loan_credit_info: 'Loan/Credit Information',
  family_relation: 'Family Relations', employee_info: 'Employee Information',
  education_info: 'Education Information', bank_account_context: 'Bank Account',
  iban: 'IBAN Account Number', social_credit_code: 'Social Credit Code',
}

function fieldName(value: string): string {
  const name = value.trim()
  const labels = i18n.getResource('en', 'translation', 'dataSecurity') as Record<string, unknown>
  const key = Object.keys(labels).find(key => key.startsWith('dlpMatch_') &&
    (key === `dlpMatch_${name}` || labels[key] === name || legacyDlpNames[key.slice(9)] === name))
  return key ? i18n.t(`dataSecurity.${key}`) : name
}

function fieldNames(value: string): string {
  return value.split(',').map(fieldName).join(i18n.t('dataSecurity.incidentText.listSeparator'))
}

function actor(value: string): string {
  return /^(unknown|unknown user|Unknownuser)$/.test(value)
    ? i18n.t('dataSecurity.incidentText.unknownUser') : value
}

type Values = Record<string, string | number>
type Template = [RegExp, string, (match: RegExpMatchArray) => Values]
const templates: Template[] = [
  [/^Sensitive mail transfer risk: (.+) from (\S+) submitted (.+); authorization unverified$/, 'mailSummary', m => ({ user: actor(m[1]), ip: m[2], fields: fieldNames(m[3]) })],
  [/^Document inspection incomplete: (\S+) uploaded "(.*)"$/, 'incompleteSummary', m => ({ ip: m[1], filename: m[2] })],
  [/^File transit risk: (.+) from (\S+) submitted file "(.*)"; authorization unverified$/, 'fileSummary', m => ({ user: actor(m[1]), ip: m[2], filename: m[3] })],
  [/^Sensitive draft content: (.+) from (\S+) saved a draft containing (.+)$/, 'draftSummary', m => ({ user: actor(m[1]), ip: m[2], fields: fieldNames(m[3]) })],
  [/^Bulk transfer risk: (.+) submitted (\d+) level-(3\+|4) field matches within 24h \(product threshold (\d+)\); authorization unverified$/, 'bulkSummary', m => ({ user: actor(m[1]), count: m[2], level: m[3], threshold: m[4] })],
  [/^Observed level-(3\+|4) field matches: (\d+) within 24h \(product threshold: (\d+); not a statutory limit\)$/, 'bulkEvidence', m => ({ level: m[1], count: m[2], threshold: m[3] })],
  [/^Draft save contains sensitive data \(URI: (.*)\)$/, 'draftEvidence', m => ({ uri: m[1] })],
  [/^(Email content contains|File content contains|Detected) (.+) \((\d+) field matches\)$/, 'fieldEvidence', m => ({ scope: i18n.t(`dataSecurity.incidentText.${m[1] === 'Email content contains' ? 'emailScope' : m[1] === 'File content contains' ? 'fileScope' : 'draftScope'}`), field: fieldName(m[2]), count: m[3] })],
  [/^([a-z_]+): (\d+) field matches$/, 'smtpFieldEvidence', m => ({ field: fieldName(m[1]), count: m[2] })],
  [/^UploadFile: (.*) \(largesmall: (\d+) Byte\)$/, 'fileUpload', m => ({ filename: m[1], size: m[2] })],
  [/^UploadExecutable file: (.+) \(largesmall: (\d+) Byte\)$/, 'executableUpload', m => ({ type: m[1], size: m[2] })],
  [/^UploadFileType: (.+) \(largesmall: (\d+) Byte\)$/, 'fileType', m => ({ type: m[1], size: m[2] })],
  [/^HighRiskFileType: (.+)$/, 'sensitiveExtension', m => ({ extension: m[1] })],
  [/^File type disguise: (.+)$/, 'typeMismatch', m => ({ reason: m[1] })],
  [/^Uploaded encrypted\/compressed archive \(may bypass DLP content scan\): (.+) \(size: (\d+) bytes\)$/, 'encryptedArchive', m => ({ type: m[1], size: m[2] })],
  [/^Uploaded password-protected PDF \(content cannot be scanned\): size (\d+) bytes$/, 'encryptedPdf', m => ({ size: m[1] })],
  [/^Stream量Abnormal: (.+) 在 (\d+) minute内产生 (\d+) Time\/CountSensitiveOperations$/, 'volumeSummary', m => ({ user: m[1], minutes: m[2], count: m[3] })],
  [/^(\d+) minute窗口内Detected (\d+) countAccording toSecurity事件 \(Threshold: (\d+)\)$/, 'volumeEvidence', m => ({ minutes: m[1], count: m[2], threshold: m[3] })],
]

const fixedText: Record<string, string> = {
  'Sensitive outbound email submission; authorization unverified, transport outcome recorded separately': 'smtpSummary',
  'Sensitive content in a Webmail delivery submission; authorization and completed delivery require verification': 'mailEvidence',
  'Document inspection exceeded a work or extraction budget; retained text does not certify complete coverage': 'incompleteEvidence',
}

export function localizeIncidentText(text: string): string {
  if (fixedText[text]) return i18n.t(`dataSecurity.incidentText.${fixedText[text]}`)
  for (const [pattern, key, values] of templates) {
    const match = text.match(pattern)
    if (match) return i18n.t(`dataSecurity.incidentText.${key}`, values(match))
  }
  return text
}

const locations: Record<string, string> = {
  'HTTP delivery request': 'httpDelivery', 'HTTP request body': 'httpBody',
  'email body': 'emailBody', 'email content': 'emailBody', 'draft content': 'draftContent',
  DocumentationContent: 'fileContent', FileContent: 'fileContent',
  'magic bytes': 'magicBytes', 'extension mismatch': 'extensionMismatch',
  'archive header': 'archiveHeader', 'PDF header': 'pdfHeader',
  filename: 'filename', 'file upload': 'fileUpload', volume_anomaly: 'volume',
  bulk_sensitive_level3: 'bulk3', bulk_sensitive_level4: 'bulk4',
}

export function localizeIncidentLocation(location: string): string {
  return locations[location] ? i18n.t(`dataSecurity.incidentLocation.${locations[location]}`) : location
}
