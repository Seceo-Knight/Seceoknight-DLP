import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuthStore } from '@/lib/store/auth'
import { API_URL } from '@/lib/config'

/**
 * SSO Callback page — mounted at /auth/sso.
 *
 * The SIEM redirects here with ?token=<exchange-token>. On mount we POST the
 * token to the backend /auth/sso/exchange endpoint which verifies it against
 * DLP_SSO_SECRET, looks up the user, and returns standard DLP access+refresh
 * tokens. We then decode the access token client-side (base64 parse — no
 * library needed) to populate the auth store and redirect to /dashboard.
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
    const exchangeToken = searchParams.get('token')
    if (!exchangeToken) {
      setError('Missing SSO token in URL')
      return
    }

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
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-slate-900 to-black flex items-center justify-center p-4">
        <div className="bg-gray-800/80 backdrop-blur-sm border border-red-500/30 rounded-xl p-8 max-w-md w-full text-center">
          <div className="text-red-400 text-5xl mb-4">!</div>
          <h2 className="text-xl font-semibold text-white mb-2">
            SSO Login Failed
          </h2>
          <p className="text-gray-400 mb-6">{error}</p>
          <a
            href="/login"
            className="inline-block px-6 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors"
          >
            Go to Login Page
          </a>
        </div>
      </div>
    )
  }

  // Loading state while exchange is in progress
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-slate-900 to-black flex items-center justify-center p-4">
      <div className="bg-gray-800/80 backdrop-blur-sm border border-gray-700/50 rounded-xl p-8 max-w-md w-full text-center">
        <div className="inline-block w-10 h-10 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin mb-4" />
        <h2 className="text-lg font-semibold text-white mb-1">
          Signing you in...
        </h2>
        <p className="text-gray-400 text-sm">
          Verifying SSO credentials with the server
        </p>
      </div>
    </div>
  )
}
