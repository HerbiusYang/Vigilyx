import React from 'react'
import { useTranslation } from 'react-i18next'
import { changeLanguage } from '../../i18n'

interface LanguageToggleProps {
  variant?: 'compact' | 'segmented'
}

function LanguageToggle({ variant = 'compact' }: LanguageToggleProps) {
  const { i18n, t } = useTranslation()
  const isZh = i18n.language === 'zh'
  const switchLabel = isZh ? t('language.switchToEnglish') : t('language.switchToChinese')

  if (variant === 'segmented') {
    return (
      <div className="lang-segmented" role="group" aria-label={t('language.selectorLabel')}>
        <svg className="lang-segmented-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
          <circle cx="12" cy="12" r="9" />
          <path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18" />
        </svg>
        <button
          type="button"
          className={`lang-segmented-option ${isZh ? 'active' : ''}`}
          aria-label={t('language.chinese')}
          aria-pressed={isZh}
          onClick={() => changeLanguage('zh')}
        >
          中文
        </button>
        <button
          type="button"
          className={`lang-segmented-option ${!isZh ? 'active' : ''}`}
          aria-label={t('language.english')}
          aria-pressed={!isZh}
          onClick={() => changeLanguage('en')}
        >
          EN
        </button>
      </div>
    )
  }

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
