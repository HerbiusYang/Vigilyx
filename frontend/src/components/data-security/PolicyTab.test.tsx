import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import i18n from '../../i18n'
import { PolicyTab } from './PolicyTab'
import { DLP_MATCH_CN, getSecurityLevel } from './constants'
afterEach(cleanup)
it('explains first-item alerts, product bulk limits and the classification boundary in both languages', async () => {
  for (const lang of ['zh', 'en']) {
    await i18n.changeLanguage(lang)
    const { unmount } = render(<PolicyTab />)
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent(i18n.t('dataSecurity.financialPolicyTitle'))
    expect(screen.getByText(i18n.t('dataSecurity.classificationBoundary'))).toBeInTheDocument()
    expect(screen.getByText(i18n.t('dataSecurity.bulkEscalationDesc', { hours:24, high:50, sensitive:500, cooldown:60 }))).toBeInTheDocument()
    expect(screen.queryByText(/^C4/)).not.toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/dataSecurity\./)
    for (const marker of ['bank_account', 'scan_incomplete', 'executable_upload', 'file_type_mismatch', 'encrypted_archive', 'encrypted_pdf', 'sensitive_extension', 'encoded_sensitive_data', 'volume_anomaly']) {
      expect(DLP_MATCH_CN[marker]).not.toMatch(/dataSecurity\./)
    }
    expect(getSecurityLevel('bank_account', ['bank_account'])).toBe(3)
    expect(getSecurityLevel('otp_verification', ['otp_verification', 'bank_account'])).toBe(4)
    unmount()
  }
  await i18n.changeLanguage('zh')
})
