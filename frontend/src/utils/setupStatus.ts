import { apiFetch } from './api'

const SETUP_STATUS_PATH = '/api/config/setup-status'
const LEGACY_SETUP_STORAGE_KEY = 'vigilyx-setup-completed'

interface SetupStatusPayload {
  completed: boolean
}

interface SetupStatusResponse {
  success?: boolean
  data?: SetupStatusPayload | null
}

function isCompletedPayload(value: unknown): value is SetupStatusPayload {
  return typeof value === 'object'
    && value !== null
    && 'completed' in value
    && typeof (value as { completed?: unknown }).completed === 'boolean'
}

function getLegacySetupFlag(): boolean {
  return localStorage.getItem(LEGACY_SETUP_STORAGE_KEY) === 'true'
}

function clearLegacySetupFlag() {
  localStorage.removeItem(LEGACY_SETUP_STORAGE_KEY)
}

async function readSetupStatusFromServer(): Promise<boolean | null> {
  const response = await apiFetch(SETUP_STATUS_PATH)
  if (!response.ok) {
    return null
  }

  const payload = await response.json() as SetupStatusResponse
  if (!payload.success || !isCompletedPayload(payload.data)) {
    return null
  }

  return payload.data.completed
}

export async function persistSetupStatus(completed: boolean): Promise<boolean> {
  const response = await apiFetch(SETUP_STATUS_PATH, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ completed }),
  })

  if (!response.ok) {
    return false
  }

  const payload = await response.json() as SetupStatusResponse
  if (!payload.success || !isCompletedPayload(payload.data)) {
    return false
  }

  clearLegacySetupFlag()
  return payload.data.completed === completed
}

export async function resolveSetupStatus(): Promise<boolean> {
  const legacyCompleted = getLegacySetupFlag()

  try {
    const serverCompleted = await readSetupStatusFromServer()
    if (serverCompleted === true) {
      clearLegacySetupFlag()
      return true
    }

    if (serverCompleted === false && legacyCompleted) {
      const migrated = await persistSetupStatus(true)
      return migrated || legacyCompleted
    }

    if (serverCompleted !== null) {
      clearLegacySetupFlag()
      return serverCompleted
    }
  } catch (error) {
    console.error('Failed to resolve setup status:', error)
  }

  return legacyCompleted
}
