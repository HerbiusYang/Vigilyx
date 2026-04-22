import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import zh from './locales/zh.json'
import en from './locales/en.json'

const STORAGE_KEY = 'vigilyx-lang'

const savedLang = localStorage.getItem(STORAGE_KEY) || 'zh'

i18n
  .use(initReactI18next)
  .init({
    resources: {
      zh: { translation: zh },
      en: { translation: en },
    },
    lng: savedLang,
    fallbackLng: 'zh',
    interpolation: {
      escapeValue: false, // React already escapes
    },
  })

// Sync <html lang> on init
document.documentElement.lang = savedLang

/** Persist language choice and switch */
export function changeLanguage(lang: 'zh' | 'en') {
  localStorage.setItem(STORAGE_KEY, lang)
  document.documentElement.lang = lang
  void i18n.changeLanguage(lang)
}

export default i18n
