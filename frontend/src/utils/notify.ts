/**
 * Notification system: alert sounds + desktop notifications + traffic alerts
 *
 * Reads user settings from localStorage and triggers notifications when security events occur.
 * Called by the WebSocket message handler in App.tsx.
 */

import i18n from '../i18n'

// -- Settings loading --

function isSoundEnabled(): boolean {
  return localStorage.getItem('vigilyx-sound') !== 'false'
}

function isDesktopNotifyEnabled(): boolean {
  return localStorage.getItem('vigilyx-desktop-notify') === 'true'
}

function getAlertThreshold(): number {
  return parseInt(localStorage.getItem('vigilyx-alert-threshold') || '100', 10)
}

// -- Alert sounds (Web Audio API, no external files needed) --

let audioCtx: AudioContext | null = null

function playBeep(frequency = 660, durationMs = 150, volume = 0.3) {
  try {
    if (!audioCtx) audioCtx = new AudioContext()
    // The browser may suspend AudioContext until the user interacts with the page
    if (audioCtx.state === 'suspended') audioCtx.resume()

    const osc = audioCtx.createOscillator()
    const gain = audioCtx.createGain()
    osc.connect(gain)
    gain.connect(audioCtx.destination)

    osc.type = 'sine'
    osc.frequency.value = frequency
    gain.gain.value = volume

    // Fade out to avoid audible clicks/pops
    const now = audioCtx.currentTime
    gain.gain.setValueAtTime(volume, now)
    gain.gain.exponentialRampToValueAtTime(0.001, now + durationMs / 1000)

    osc.start(now)
    osc.stop(now + durationMs / 1000)
  } catch {
    // Fail silently if the Web Audio API is unavailable
  }
}

/** Threat alert sound: dual tone. */
function playThreatSound(level: 'medium' | 'high' | 'critical') {
  if (!isSoundEnabled()) return
  if (level === 'critical') {
    playBeep(880, 120, 0.4)
    setTimeout(() => playBeep(880, 120, 0.4), 180)
    setTimeout(() => playBeep(1100, 200, 0.4), 400)
  } else if (level === 'high') {
    playBeep(780, 120, 0.35)
    setTimeout(() => playBeep(780, 150, 0.35), 180)
  } else {
    playBeep(660, 150, 0.25)
  }
}

/** New-mail alert sound: single short tone. */
function playNewMailSound() {
  if (!isSoundEnabled()) return
  playBeep(520, 100, 0.15)
}

// -- Desktop notifications --

/** Throttle: do not repeat the same notification type within 30 seconds. */
const notifyTimestamps: Record<string, number> = {}
const NOTIFY_COOLDOWN = 30_000

function sendDesktopNotification(title: string, body: string, tag: string) {
  if (!isDesktopNotifyEnabled()) return
  if (!('Notification' in window) || Notification.permission !== 'granted') return

  const now = Date.now()
  if (notifyTimestamps[tag] && now - notifyTimestamps[tag] < NOTIFY_COOLDOWN) return
  notifyTimestamps[tag] = now

  try {
    const n = new Notification(title, {
      body,
      icon: '/favicon.ico',
      tag, // Reuse the same tag to replace older notifications
      silent: true, // Do not play the system sound; sound playback is handled manually
    })
    // Focus the window when the notification is clicked
    n.onclick = () => {
      window.focus()
      n.close()
    }
    // Auto-close after 10 seconds
    setTimeout(() => n.close(), 10_000)
  } catch {
    // Desktop notifications are unavailable
  }
}

// -- Traffic alerts (sliding-window counting) --

const sessionTimestamps: number[] = []
let lastThresholdAlert = 0

function trackSessionRate() {
  const now = Date.now()
  sessionTimestamps.push(now)
  // Keep only the last 60 seconds of records
  const cutoff = now - 60_000
  while (sessionTimestamps.length > 0 && sessionTimestamps[0] < cutoff) {
    sessionTimestamps.shift()
  }

  const threshold = getAlertThreshold()
  const rate = sessionTimestamps.length // Number of sessions in the last minute

  if (rate >= threshold && now - lastThresholdAlert > 60_000) {
    lastThresholdAlert = now
    playThreatSound('medium')
    sendDesktopNotification(
      i18n.t('notify.trafficAlert'),
      i18n.t('notify.trafficAlertBody', { rate, threshold }),
      'traffic-alert'
    )
  }
}

// -- Public API --

const THREAT_LEVEL_KEYS: Record<string, string> = {
  safe: 'notify.threatSafe', low: 'notify.threatLow', medium: 'notify.threatMedium', high: 'notify.threatHigh', critical: 'notify.threatCritical',
}

/**
 * Security event notification - triggered by SecurityVerdict WebSocket messages
 */
export function notifySecurityVerdict(parsed: Record<string, unknown>) {
  const data = parsed.data as Record<string, unknown> | undefined
  if (!data) return

  const threatLevel = (data.threat_level as string) || 'safe'
  if (threatLevel === 'safe' || threatLevel === 'low') return

  const subject = (data.subject as string) || i18n.t('notify.noSubject')
  const from = (data.mail_from as string) || i18n.t('notify.unknownSender')
  const levelCn = i18n.t(THREAT_LEVEL_KEYS[threatLevel] || 'notify.threatSafe')

  // Alert sound
  playThreatSound(threatLevel as 'medium' | 'high' | 'critical')

  // Desktop notification
  sendDesktopNotification(
    i18n.t('notify.threatTitle', { level: levelCn }),
    `${from}\n${subject}`,
    `verdict-${threatLevel}`
  )
}

/**
 * New-session notification - triggered by NewSession WebSocket messages
 */
export function notifyNewSession() {
  playNewMailSound()
  trackSessionRate()
}

/**
 * Data security alert notification
 */
export function notifyDataSecurityAlert(parsed: Record<string, unknown>) {
  const data = parsed.data as Record<string, unknown> | undefined
  if (!data) return

  playThreatSound('high')
  sendDesktopNotification(
    i18n.t('notify.dataSecurityAlert'),
    (data.description as string) || i18n.t('notify.dataSecurityEventDetected'),
    'data-security'
  )
}
