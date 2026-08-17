/**
 * Session-scoped storage for internal topology values.
 *
 * Topology must not persist indefinitely in localStorage where any future XSS
 * can recover it. Reads also delete legacy persistent copies as a migration.
 */
export function getSensitiveSetting(key: string): string | null {
  localStorage.removeItem(key)
  return sessionStorage.getItem(key)
}

export function setSensitiveSetting(key: string, value: string): void {
  localStorage.removeItem(key)
  sessionStorage.setItem(key, value)
}

export function removeSensitiveSetting(key: string): void {
  localStorage.removeItem(key)
  sessionStorage.removeItem(key)
}
