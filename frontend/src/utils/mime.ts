/** Decode a MIME encoded-word (RFC 2047), for example =?UTF-8?B?base64...?=. */
export function decodeMimeWord(text: string | null): string | null {
  if (!text) return text
  return text.replace(
    /=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g,
    (_match, charset, encoding, data) => {
      try {
        if (encoding.toUpperCase() === 'B') {
          const bytes = atob(data)
          const arr = new Uint8Array(bytes.length)
          for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i)
          return new TextDecoder(charset).decode(arr)
        } else {
          const decoded = data
            .replace(/_/g, ' ')
            .replace(/=([0-9A-Fa-f]{2})/g, (_: string, hex: string) =>
              String.fromCharCode(parseInt(hex, 16))
            )
          const arr = new Uint8Array(decoded.length)
          for (let i = 0; i < decoded.length; i++) arr[i] = decoded.charCodeAt(i)
          return new TextDecoder(charset).decode(arr)
        }
      } catch {
        return data
      }
    }
  )
}
