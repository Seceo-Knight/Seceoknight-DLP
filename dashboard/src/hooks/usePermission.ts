import { useAuthStore } from '@/lib/store/auth'

/**
 * Hook for permission-driven UI gating.
 *
 * IMPORTANT: this is for hiding buttons / nav items only. The backend
 * is the source of truth and re-checks every request via require_permission.
 * Never rely on this hook to "enforce" anything.
 *
 * Example:
 *   const { has, hasAny, role } = usePermission()
 *   if (!has('manage_users')) return null
 */
export function usePermission() {
  const user = useAuthStore((s) => s.user)
  const hasPermission = useAuthStore((s) => s.hasPermission)
  const hasAnyPermission = useAuthStore((s) => s.hasAnyPermission)

  return {
    role: user?.role ?? null,
    permissions: user?.permissions ?? [],
    has: hasPermission,
    hasAny: hasAnyPermission,
    isAdmin: String(user?.role ?? '').toUpperCase() === 'ADMIN',
  }
}
