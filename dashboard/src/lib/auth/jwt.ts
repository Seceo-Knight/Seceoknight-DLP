// Minimal JWT payload decoder.
//
// This is NOT a verifier — never trust decoded claims for authorization
// decisions. Use it only for optimistic UI hints (e.g., show a role badge
// immediately after login). The authoritative source for what a user can
// do is GET /auth/me, which the server computes from the DB.

export interface JwtPayload {
  sub?: string
  email?: string
  role?: string
  exp?: number
  iat?: number
  [key: string]: unknown
}

function base64UrlDecode(segment: string): string {
  // Pad to multiple of 4, convert URL-safe alphabet, then atob.
  const padded = segment + '='.repeat((4 - (segment.length % 4)) % 4)
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  try {
    // decodeURIComponent(escape(...)) handles non-ASCII safely in browsers
    // that don't support TextDecoder on the atob output directly.
    return decodeURIComponent(
      atob(b64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
  } catch {
    return ''
  }
}

export function decodeJwt(token: string | null | undefined): JwtPayload | null {
  if (!token) return null
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const raw = base64UrlDecode(parts[1])
  if (!raw) return null
  try {
    return JSON.parse(raw) as JwtPayload
  } catch {
    return null
  }
}

export function isJwtExpired(payload: JwtPayload | null): boolean {
  if (!payload || typeof payload.exp !== 'number') return false
  // exp is seconds since epoch; Date.now() is ms.
  return payload.exp * 1000 <= Date.now()
}
