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
