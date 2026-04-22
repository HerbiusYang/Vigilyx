import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import zh from './locales/zh.json'
import en from './locales/en.json'

const STORAGE_KEY = 'vigilyx-lang'

type SupportedLang = 'zh' | 'en'

function getStorage() {
  if (typeof window === 'undefined') {
    return null
  }

  const storage = window.localStorage
  if (!storage || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function') {
    return null
  }

  return storage
}

function getSavedLang(): SupportedLang {
  const storage = getStorage()
  const savedLang = storage?.getItem(STORAGE_KEY)
  return savedLang === 'en' ? 'en' : 'zh'
}

const savedLang = getSavedLang()

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

// Sync <html lang> on init when a DOM exists.
if (typeof document !== 'undefined') {
  document.documentElement.lang = savedLang
}

/** Persist language choice and switch */
export function changeLanguage(lang: SupportedLang) {
  getStorage()?.setItem(STORAGE_KEY, lang)
  if (typeof document !== 'undefined') {
    document.documentElement.lang = lang
  }
  void i18n.changeLanguage(lang)
}

export default i18n
