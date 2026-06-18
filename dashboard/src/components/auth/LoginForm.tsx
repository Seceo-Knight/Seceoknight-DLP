import { useState } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/lib/store/auth'
import { changePassword } from '@/lib/api'
import { Shield, Mail, Lock, AlertCircle, CheckCircle, KeyRound, Eye, EyeOff } from 'lucide-react'

export default function LoginForm() {
  const navigate = useNavigate()
  const { login } = useAuthStore()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [mode, setMode] = useState<'login' | 'changePassword'>('login')
  const [showPassword, setShowPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  const resetForm = () => {
    setPassword('')
    setNewPassword('')
    setConfirmPassword('')
    setError('')
    setSuccess('')
    setShowPassword(false)
    setShowNewPassword(false)
    setShowConfirmPassword(false)
  }

  const switchMode = (newMode: 'login' | 'changePassword') => {
    resetForm()
    setMode(newMode)
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      await login(email, password)
      navigate('/dashboard')
    } catch (err: any) {
      const errorMessage = extractErrorDetail(err, 'Invalid credentials')
      setError(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match')
      return
    }

    setLoading(true)
    try {
      await changePassword(email, password, newPassword, confirmPassword)
      setSuccess('Password changed successfully! You can now sign in with your new password.')
      resetForm()
      setTimeout(() => setMode('login'), 2000)
    } catch (err: any) {
      const errorMessage = extractErrorDetail(err, 'Failed to change password')
      setError(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const isChangePassword = mode === 'changePassword'

  const eyeButtonClass = "absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer text-gray-400 hover:text-gray-200 transition-colors"

  return (
    <div className="w-full max-w-md">
      <div className="bg-gray-800/50 backdrop-blur-xl rounded-3xl shadow-2xl p-8 border border-gray-700/50">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-indigo-500 via-purple-500 to-pink-500 rounded-2xl mb-4 shadow-lg transform hover:scale-105 transition-transform">
            {isChangePassword ? (
              <KeyRound className="w-10 h-10 text-white" />
            ) : (
              <Shield className="w-10 h-10 text-white" />
            )}
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-indigo-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">CyberSentinel DLP</h1>
          <p className="text-gray-200 mt-3 font-medium">
            {isChangePassword ? 'Change Your Password' : 'Enterprise Data Loss Prevention'}
          </p>
        </div>

        {/* Success Alert */}
        {success && (
          <div className="mb-6 p-4 bg-green-900/30 border border-green-500/50 rounded-lg flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-medium text-green-300">Success</h3>
              <p className="text-sm text-green-200 mt-1">{success}</p>
            </div>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mb-6 p-4 bg-red-900/30 border border-red-500/50 rounded-lg flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-medium text-red-300">
                {isChangePassword ? 'Password Change Failed' : 'Authentication Failed'}
              </h3>
              <p className="text-sm text-red-200 mt-1">{error}</p>
            </div>
          </div>
        )}

        {/* Form */}
        <form onSubmit={isChangePassword ? handleChangePassword : handleLogin} className="space-y-6">
          {/* Username Field */}
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-200 mb-2">
              Username
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Mail className="h-5 w-5 text-gray-400" />
              </div>
              <input
                id="email"
                type="text"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="block w-full pl-10 pr-3 py-3 border-2 border-gray-600 rounded-xl focus:ring-4 focus:ring-purple-500/50 focus:border-purple-500 transition-all bg-gray-900/50 text-white placeholder-gray-400"
                placeholder="admin"
                disabled={loading}
              />
            </div>
          </div>

          {/* Current Password Field */}
          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-200 mb-2">
              {isChangePassword ? 'Current Password' : 'Password'}
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Lock className="h-5 w-5 text-gray-400" />
              </div>
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="block w-full pl-10 pr-10 py-3 border-2 border-gray-600 rounded-xl focus:ring-4 focus:ring-purple-500/50 focus:border-purple-500 transition-all bg-gray-900/50 text-white placeholder-gray-400"
                placeholder={isChangePassword ? 'Enter current password' : 'Enter your password'}
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className={eyeButtonClass}
                tabIndex={-1}
              >
                {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
              </button>
            </div>
          </div>

          {/* New Password Fields (only in change password mode) */}
          {isChangePassword && (
            <>
              <div>
                <label htmlFor="newPassword" className="block text-sm font-medium text-gray-200 mb-2">
                  New Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <KeyRound className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="newPassword"
                    type={showNewPassword ? 'text' : 'password'}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    className="block w-full pl-10 pr-10 py-3 border-2 border-gray-600 rounded-xl focus:ring-4 focus:ring-purple-500/50 focus:border-purple-500 transition-all bg-gray-900/50 text-white placeholder-gray-400"
                    placeholder="Enter new password"
                    disabled={loading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className={eyeButtonClass}
                    tabIndex={-1}
                  >
                    {showNewPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                  </button>
                </div>
              </div>

              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-200 mb-2">
                  Confirm New Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <KeyRound className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="confirmPassword"
                    type={showConfirmPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                    className="block w-full pl-10 pr-10 py-3 border-2 border-gray-600 rounded-xl focus:ring-4 focus:ring-purple-500/50 focus:border-purple-500 transition-all bg-gray-900/50 text-white placeholder-gray-400"
                    placeholder="Confirm new password"
                    disabled={loading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className={eyeButtonClass}
                    tabIndex={-1}
                  >
                    {showConfirmPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                  </button>
                </div>
              </div>

              <p className="text-xs text-gray-400">
                Password must be at least 7 characters with uppercase, lowercase, digit, and special character.
              </p>
            </>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 text-white font-bold py-3.5 px-4 rounded-xl hover:from-indigo-700 hover:via-purple-700 hover:to-pink-700 focus:outline-none focus:ring-4 focus:ring-purple-300 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-xl transform hover:scale-[1.02]"
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                {isChangePassword ? 'Changing Password...' : 'Signing in...'}
              </span>
            ) : (
              isChangePassword ? 'Change Password' : 'Sign In'
            )}
          </button>
        </form>

        {/* Toggle Link */}
        <div className="mt-6 text-center">
          {isChangePassword ? (
            <button
              onClick={() => switchMode('login')}
              className="text-sm text-purple-400 hover:text-purple-300 transition-colors"
            >
              Back to Sign In
            </button>
          ) : (
            <button
              onClick={() => switchMode('changePassword')}
              className="text-sm text-purple-400 hover:text-purple-300 transition-colors"
            >
              Change Password
            </button>
          )}
        </div>

        {/* Footer */}
        <div className="mt-4 text-center text-sm text-gray-300">
          <p>Secure access to your organization's DLP platform</p>
        </div>
      </div>

      {/* Version Info */}
      <div className="mt-4 text-center text-sm text-gray-400">
        <p>Version 1.0.0 | Enterprise Edition</p>
      </div>
    </div>
  )
}
