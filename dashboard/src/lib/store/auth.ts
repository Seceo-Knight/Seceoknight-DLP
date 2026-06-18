import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import axios from 'axios'
import { API_URL } from '../config'
import { decodeJwt } from '../auth/jwt'

export interface AuthUser {
  id: string
  email: string
  full_name?: string
  role: string
  role_id?: string | null
  department?: string | null
  organization?: string | null
  is_active?: boolean
  permissions: string[]
}

interface AuthState {
  isAuthenticated: boolean
  user: AuthUser | null
  accessToken: string | null
  refreshToken: string | null
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  setTokens: (accessToken: string, refreshToken: string) => void
  refreshMe: () => Promise<void>
  hasPermission: (perm: string) => boolean
  hasAnyPermission: (perms: string[]) => boolean
}

async function fetchMe(accessToken: string): Promise<AuthUser> {
  const resp = await axios.get(`${API_URL}/auth/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  const d = resp.data || {}
  return {
    id: String(d.id ?? ''),
    email: String(d.email ?? ''),
    full_name: d.full_name,
    role: String(d.role ?? 'VIEWER'),
    role_id: d.role_id ?? null,
    department: d.department ?? null,
    organization: d.organization ?? null,
    is_active: d.is_active !== false,
    permissions: Array.isArray(d.permissions) ? d.permissions.map(String) : [],
  }
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      isAuthenticated: false,
      user: null,
      accessToken: null,
      refreshToken: null,

      login: async (email: string, password: string) => {
        const cleanEmail = email.trim()
        const cleanPassword = password.trim()

        try {
          const formData = new URLSearchParams()
          formData.append('username', cleanEmail)
          formData.append('password', cleanPassword)

          const response = await axios.post(
            `${API_URL}/auth/login`,
            formData,
            {
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
              },
            }
          )

          const { access_token, refresh_token } = response.data

          // Resolve real identity from /auth/me. The JWT's `role` claim is
          // only used as an instant-UI hint while the /me request is in flight.
          let user: AuthUser
          try {
            user = await fetchMe(access_token)
          } catch {
            // If /me is temporarily unavailable, fall back to a minimal
            // user record built from the JWT so the session still works.
            // Permissions default to [] — UI will hide privileged actions
            // until /me succeeds (enforced server-side regardless).
            const claims = decodeJwt(access_token)
            user = {
              id: String(claims?.sub ?? ''),
              email: String(claims?.email ?? cleanEmail),
              role: String(claims?.role ?? 'VIEWER'),
              permissions: [],
            }
          }

          set({
            isAuthenticated: true,
            accessToken: access_token,
            refreshToken: refresh_token,
            user,
          })
        } catch (error: any) {
          const errorMessage =
            error.response?.data?.detail || 'Invalid email or password'
          throw new Error(errorMessage)
        }
      },

      logout: () => {
        set({
          isAuthenticated: false,
          user: null,
          accessToken: null,
          refreshToken: null,
        })
      },

      setTokens: (accessToken: string, refreshToken: string) => {
        set({ accessToken, refreshToken })
      },

      refreshMe: async () => {
        const token = get().accessToken
        if (!token) return
        try {
          const user = await fetchMe(token)
          set({ user })
        } catch {
          // Don't nuke the session on a transient /me failure; caller can
          // log out explicitly if the token is truly invalid.
        }
      },

      hasPermission: (perm: string) => {
        const u = get().user
        if (!u) return false
        // ADMIN is treated as a global wildcard to avoid any divergence
        // between enum role and the permission list the server resolved.
        if (String(u.role).toUpperCase() === 'ADMIN') return true
        return u.permissions.includes(perm)
      },

      hasAnyPermission: (perms: string[]) => {
        const u = get().user
        if (!u) return false
        if (String(u.role).toUpperCase() === 'ADMIN') return true
        return perms.some((p) => u.permissions.includes(p))
      },
    }),
    {
      // Bumped storage key so stale "role: 'admin'" sessions from the previous
      // hardcoded-admin code don't leak into the new permission-aware store.
      name: 'dlp-auth-v3',
    }
  )
)
