import { Navigate } from 'react-router-dom'
import { useAuthStore } from '@/lib/store/auth'
import LoginForm from '@/components/auth/LoginForm'

export default function Login() {
  const { isAuthenticated } = useAuthStore()

  // Redirect to dashboard if already authenticated
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4 relative overflow-hidden">
      {/* Faint corner washes -- quiet enough to read as "enterprise", not "marketing site" */}
      <div className="absolute -top-32 -right-32 w-96 h-96 bg-blue-100/60 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-32 -left-32 w-96 h-96 bg-slate-100/80 rounded-full blur-3xl pointer-events-none" />

      {/* Content */}
      <div className="relative z-10">
        <LoginForm />
      </div>
    </div>
  )
}


