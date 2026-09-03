import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuthStore } from '@/lib/store/auth'
import { API_URL } from '@/lib/config'

/**
 * SSO Callback page — mounted at /auth/sso.
 *
 * The SIEM redirects here with the exchange token. On mount we POST it to
 * the backend /auth/sso/exchange endpoint, which verifies the signature
 * (RS256 via JWKS, or DLP_SSO_SECRET as the HS256 fallback — see
 * server/app/core/sso_verify.py), looks up the user, and returns standard
 * DLP access+refresh tokens. We then decode the access token client-side
 * (base64 parse — no library needed) to populate the auth store and
 * redirect to /dashboard.
 *
 * WHERE THE TOKEN IS READ FROM, AND WHY THE FRAGMENT IS PREFERRED
 * -----------------------------------------------------------------
 * Ported from CyberSentinel-DLP (commit 074266b, gap-scan of August 26
 * 2026). A URL fragment (#token=...) is never transmitted to a server. A
 * query string (?token=...) is, and so it is written verbatim into the
 * dashboard's nginx access log by the default log format — which is a
 * live credential sitting in a log file that gets rotated, shipped and
 * retained long after the token's short life. It also lands in browser
 * history and in the Referer header of anything the page loads afterwards.
 *
 * So the fragment is read first and the query string is accepted as a
 * fallback, which keeps a SIEM that already redirects with ?token= working
 * unchanged while giving it a strictly better option to move to.
 *
 * Either way the token is stripped from the address bar before the
 * exchange is attempted: it is single-use, so what is left behind is only
 * useful to someone reading over a shoulder or a synced history, never to
 * the user.
 */

/** Decode a JWT payload WITHOUT verifying the signature (client-side only). */
function decodeJwtPayload(token: string): Record<string, unknown> {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) throw new Error('Malformed JWT')
    // Base64url → base64 → decode
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const json = atob(base64)
    return JSON.parse(json)
  } catch {
    return {}
  }
}

export default function SSOCallback() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { setTokens } = useAuthStore()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // Fragment first (never leaves the browser), query string as the fallback.
    const fragment = new URLSearchParams(
      window.location.hash.replace(/^#/, '')
    ).get('token')
    const exchangeToken = fragment || searchParams.get('token')
    if (!exchangeToken) {
      setError('Missing SSO token in URL')
      return
    }

    // Scrub it from the address bar before doing anything with it, so it
    // is not left in history or handed to a Referer on the next navigation.
    window.history.replaceState(null, '', window.location.pathname)

    let cancelled = false

    async function performExchange(token: string) {
      try {
        const res = await fetch(`${API_URL}/auth/sso/exchange`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token }),
        })

        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(
            body.detail || `SSO exchange failed (HTTP ${res.status})`
          )
        }

        const data = await res.json()
        const { access_token, refresh_token } = data

        if (!access_token || !refresh_token) {
          throw new Error('SSO exchange returned incomplete tokens')
        }

        if (cancelled) return

        // Decode access token to extract user info (sub, email, role).
        const claims = decodeJwtPayload(access_token)

        // Populate auth store — same shape as the normal login flow.
        useAuthStore.setState({
          isAuthenticated: true,
          accessToken: access_token,
          refreshToken: refresh_token,
          user: {
            email: (claims.email as string) || '',
            role: (claims.role as string) || 'VIEWER',
            id: (claims.sub as string) || '',
            // Same placeholder as the normal login flow's JWT-decode path
            // (lib/store/auth.ts) — the access token doesn't carry a
            // permissions claim, so this list is populated lazily by the
            // first authenticated /me fetch.
            permissions: [],
          },
        })

        navigate('/dashboard', { replace: true })
      } catch (err: unknown) {
        if (cancelled) return
        setError(
          err instanceof Error ? err.message : 'SSO login failed'
        )
      }
    }

    performExchange(exchangeToken)

    return () => {
      cancelled = true
    }
  }, [searchParams, navigate, setTokens])

  if (error) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
        <div className="bg-white border border-red-200 rounded-xl p-8 max-w-md w-full text-center shadow-xl shadow-slate-200/60">
          <div className="text-red-500 text-5xl mb-4">!</div>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">
            SSO Login Failed
          </h2>
          <p className="text-muted-foreground mb-6">{error}</p>
          <a
            href="/login"
            className="inline-block px-6 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors"
          >
            Go to Login Page
          </a>
        </div>
      </div>
    )
  }

  // Loading state while exchange is in progress
  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
      <div className="bg-white border border-gray-200 rounded-xl p-8 max-w-md w-full text-center shadow-xl shadow-slate-200/60">
        <div className="inline-block w-10 h-10 border-4 border-primary border-t-transparent rounded-full animate-spin mb-4" />
        <h2 className="text-lg font-semibold text-gray-900 mb-1">
          Signing you in...
        </h2>
        <p className="text-muted-foreground text-sm">
          Verifying SSO credentials with the server
        </p>
      </div>
    </div>
  )
}
