import { Navigate, Outlet } from 'react-router-dom'
import { useAuthStore } from '../../lib/store/auth'

export default function ProtectedRoute() {
  const { isAuthenticated } = useAuthStore()

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <Outlet />
}
