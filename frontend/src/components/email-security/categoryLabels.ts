import i18n from '../../i18n'

/**
 * Localized labels for engine detection categories (ModuleResult.categories,
 * SOAR rule conditions, verdict category lists). Categories not yet present
 * in the locale files fall back to the raw snake_case id so new backend
 * categories stay visible instead of leaking an i18n key.
 */
export function categoryLabel(category: string): string {
  const key = `emailSecurity.detectionCategory.${category}`
  return i18n.exists(key) ? i18n.t(key) : category
}

/** Join localized category labels the same way rule chips join raw ids. */
export function formatCategoryList(categories: string[]): string {
  return categories.map(categoryLabel).join(' / ')
}

/** Localized primary malicious-email classification label. */
export function threatTypeLabel(threatType: string | null | undefined): string | null {
  if (!threatType) return null
  const key = `emailSecurity.threatType.${threatType}`
  return i18n.exists(key) ? i18n.t(key) : threatType
}

/** Localized mail classification, separate from malicious threat family. */
export function classificationLabel(classification: string | null | undefined): string | null {
  if (!classification) return null
  const key = `emailSecurity.classification.${classification}`
  return i18n.exists(key) ? i18n.t(key) : classification
}
