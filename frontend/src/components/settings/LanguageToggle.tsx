import React from 'react'
import { useTranslation } from 'react-i18next'
import { changeLanguage } from '../../i18n'

function LanguageToggle() {
  const { i18n, t } = useTranslation()
  const isZh = i18n.language === 'zh'
  const switchLabel = isZh ? t('language.switchToEnglish') : t('language.switchToChinese')

  return (
    <button
      type="button"
      className="lang-toggle"
      onClick={() => changeLanguage(isZh ? 'en' : 'zh')}
      title={switchLabel}
      aria-label={switchLabel}
    >
      {isZh ? 'EN' : '中'}
    </button>
  )
}

export default React.memo(LanguageToggle)
