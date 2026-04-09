/**
 * HttpOnly cookie authenticated fetch wrapper
 *
 * The browser automatically sends the HttpOnly cookie with same-origin /api/* requests.
 * When the token expires (401), notify App via an event so it can switch back to the login screen.
 */

let logoutTriggered = false

export async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const response = await fetch(input, {
    ...init,
    credentials: 'same-origin', // Ensure the HttpOnly cookie is sent with requests
  })

  // If the token is expired or invalid, notify App once to avoid duplicate triggers from concurrent requests
  if (response.status === 401 && !logoutTriggered) {
    logoutTriggered = true
    window.dispatchEvent(new Event('auth:logout'))
  }

  // Throw on non-2xx responses so callers can handle failures correctly (401 is handled above, but we still throw so callers can observe it)
  if (!response.ok) {
    const text = await response.text().catch(() => '')
    let msg = `HTTP ${response.status}`
    try {
      const json = JSON.parse(text)
      if (json.error) msg = json.error
    } catch { if (text) msg = text }
    throw new Error(msg)
  }

  return response
}

/** Reset the 401 debounce flag after re-login so future 401s can trigger logout normally. */
export function resetLogoutFlag() {
  logoutTriggered = false
}
