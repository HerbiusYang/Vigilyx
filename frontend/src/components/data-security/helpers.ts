// -- IP input expansion helpers --
export function expandIpInput(raw: string): string[] {
  const trimmed = raw.trim()
  if (!trimmed) return []
  const match = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3}(?:\/\d{1,3})+)$/.exec(trimmed)
  if (match) {
    const prefix = match[1]
    const parts = match[2].split('/')
    return parts.map(p => prefix + p)
  }
  return [trimmed]
}

// -- Privacy masking --
/** IP: 192.168.1.100 → 192.168.*.* */
export function maskIp(ip: string): string {
  if (!ip) return ip
  const parts = ip.split('.')
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`
  return ip.replace(/:[\da-f]+:[\da-f]+$/i, ':*:*') // IPv6
}
/** User: user@domain.com -> us***@domain.com */
export function maskUser(u: string): string {
  if (!u) return u
  const at = u.indexOf('@')
  if (at > 0) {
    const local = u.slice(0, at)
    const domain = u.slice(at)
    return (local.length <= 2 ? local[0] + '***' : local.slice(0, 2) + '***') + domain
  }
  return u.length <= 2 ? u[0] + '***' : u.slice(0, 2) + '***'
}
/** URL: /path?token=abc123&key=xxx → /path?token=***&key=*** */
export function maskUrl(url: string): string {
  if (!url) return url
  const qi = url.indexOf('?')
  if (qi < 0) return url
  const path = url.slice(0, qi)
  const qs = url.slice(qi + 1)
  const masked = qs.replace(/=([^&]*)/g, '=***')
  return path + '?' + masked
}

// -- Utilities --
export function sanitizeDownloadName(name: string): string {
  const cleaned = name.replace(/[\\/\u0000-\u001f\u007f"]/g, '').trim()
  return cleaned || 'http-request-body.redacted.txt'
}

export function getDownloadName(headers: Headers, fallback: string): string {
  const disposition = headers.get('content-disposition')
  if (!disposition) return sanitizeDownloadName(fallback)

  const encodedMatch = disposition.match(/filename\*\s*=\s*([^;]+)/i)
  if (encodedMatch) {
    const encoded = encodedMatch[1].trim().replace(/^UTF-8''/i, '').replace(/^"(.*)"$/, '$1')
    try {
      return sanitizeDownloadName(decodeURIComponent(encoded))
    } catch {
      return sanitizeDownloadName(encoded)
    }
  }

  const plainMatch = disposition.match(/filename\s*=\s*("?)([^";]+)\1/i)
  if (plainMatch) {
    return sanitizeDownloadName(plainMatch[2])
  }

  return sanitizeDownloadName(fallback)
}
