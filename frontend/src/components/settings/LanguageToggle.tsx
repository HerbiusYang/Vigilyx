import React from 'react'
import { useTranslation } from 'react-i18next'
import { changeLanguage } from '../../i18n'

function LanguageToggle() {
  const { i18n } = useTranslation()
  const isZh = i18n.language === 'zh'

  return (
    <button
      className="lang-toggle"
      onClick={() => changeLanguage(isZh ? 'en' : 'zh')}
      title={isZh ? 'Switch to English' : '切换到中文'}
      aria-label="Toggle language"
    >
      {isZh ? 'EN' : '中'}
    </button>
  )
}

export default React.memo(LanguageToggle)
