import { useState } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useNavigate } from 'react-router-dom'
import { useAuthStore, MfaRequiredError } from '@/lib/store/auth'
import { changePassword, mfaValidate } from '@/lib/api'
import { Shield, Mail, Lock, AlertCircle, CheckCircle, KeyRound, Eye, EyeOff, ShieldCheck } from 'lucide-react'

export default function LoginForm() {
  const navigate = useNavigate()
  const { login, loginWithTokens } = useAuthStore()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [mode, setMode] = useState<'login' | 'changePassword' | 'mfa'>('login')
  const [showPassword, setShowPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  // MFA state
  const [mfaToken, setMfaToken] = useState('')
  const [totpCode, setTotpCode] = useState('')

  const resetForm = () => {
    setPassword('')
    setNewPassword('')
    setConfirmPassword('')
    setError('')
    setSuccess('')
    setShowPassword(false)
    setShowNewPassword(false)
    setShowConfirmPassword(false)
    setTotpCode('')
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
      if (err instanceof MfaRequiredError) {
        // Server says MFA is required — save the bridge token and show TOTP step
        setMfaToken(err.mfaToken)
        setError('')
        setMode('mfa')
      } else {
        const errorMessage = extractErrorDetail(err, 'Invalid credentials')
        setError(errorMessage)
      }
    } finally {
      setLoading(false)
    }
  }

  const handleMfaValidate = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const { access_token, refresh_token } = await mfaValidate(mfaToken, totpCode)
      await loginWithTokens(access_token, refresh_token)
      navigate('/dashboard')
    } catch (err: any) {
      setError(extractErrorDetail(err, 'Invalid or expired code'))
      setTotpCode('')
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
  const isMfa = mode === 'mfa'

  const eyeButtonClass = "absolute inset-y-0 right-0 pr-3 flex items-center cursor-pointer text-gray-400 hover:text-gray-600 transition-colors"

  return (
    <div className="w-full max-w-md">
      <div className="bg-white rounded-2xl shadow-xl shadow-slate-200/60 p-8 border border-gray-200">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary rounded-2xl mb-4 shadow-sm">
            {isChangePassword ? (
              <KeyRound className="w-8 h-8 text-white" />
            ) : isMfa ? (
              <ShieldCheck className="w-8 h-8 text-white" />
            ) : (
              <Shield className="w-8 h-8 text-white" />
            )}
          </div>
          <h1 className="text-2xl font-bold text-gray-900">SeceoKnight DLP</h1>
          <p className="text-gray-500 mt-2 text-sm">
            {isChangePassword
              ? 'Change Your Password'
              : isMfa
              ? 'Two-Factor Authentication'
              : 'Enterprise Data Loss Prevention'}
          </p>
        </div>

        {/* Success Alert */}
        {success && (
          <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-medium text-green-800">Success</h3>
              <p className="text-sm text-green-700 mt-1">{success}</p>
            </div>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-sm font-medium text-red-800">
                {isChangePassword ? 'Password Change Failed' : isMfa ? 'Verification Failed' : 'Authentication Failed'}
              </h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>
        )}

        {/* ── MFA Step ── */}
        {isMfa && (
          <form onSubmit={handleMfaValidate} className="space-y-6">
            <div className="p-4 bg-blue-50 border border-blue-200 rounded-xl text-center">
              <p className="text-sm text-blue-700">
                Open your authenticator app and enter the 6-digit code for{' '}
                <span className="font-semibold text-blue-900">SeceoKnight DLP</span>.
              </p>
            </div>

            <div>
              <label htmlFor="totpCode" className="block text-sm font-medium text-gray-700 mb-2">
                Verification Code
              </label>
              <input
                id="totpCode"
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                required
                autoFocus
                className="block w-full px-4 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-primary/30 focus:border-primary transition-all bg-white text-gray-900 placeholder-gray-400 text-center text-2xl tracking-[0.5em] font-mono"
                placeholder="000000"
                disabled={loading}
              />
            </div>

            <button
              type="submit"
              disabled={loading || totpCode.length !== 6}
              className="w-full bg-primary hover:bg-primary/90 text-white font-semibold py-3 px-4 rounded-xl focus:outline-none focus:ring-2 focus:ring-primary/40 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Verifying...
                </span>
              ) : (
                'Verify Code'
              )}
            </button>

            <div className="text-center">
              <button
                type="button"
                onClick={() => { resetForm(); setMode('login') }}
                className="text-sm text-primary hover:text-primary/80 transition-colors"
              >
                ← Back to Sign In
              </button>
            </div>
          </form>
        )}

        {/* ── Login / Change Password Step ── */}
        {!isMfa && (
          <form onSubmit={isChangePassword ? handleChangePassword : handleLogin} className="space-y-6">
            {/* Username Field */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
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
                  className="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-primary/30 focus:border-primary transition-all bg-white text-gray-900 placeholder-gray-400"
                  placeholder="admin"
                  disabled={loading}
                />
              </div>
            </div>

            {/* Current Password Field */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
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
                  className="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-primary/30 focus:border-primary transition-all bg-white text-gray-900 placeholder-gray-400"
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
                  <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700 mb-2">
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
                      className="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-primary/30 focus:border-primary transition-all bg-white text-gray-900 placeholder-gray-400"
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
                  <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-2">
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
                      className="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-xl focus:ring-2 focus:ring-primary/30 focus:border-primary transition-all bg-white text-gray-900 placeholder-gray-400"
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

                <p className="text-xs text-gray-500">
                  Password must be at least 7 characters with uppercase, lowercase, digit, and special character.
                </p>
              </>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-primary hover:bg-primary/90 text-white font-semibold py-3 px-4 rounded-xl focus:outline-none focus:ring-2 focus:ring-primary/40 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-sm hover:shadow-md"
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
        )}

        {/* Toggle Link */}
        {!isMfa && (
          <div className="mt-6 text-center">
            {isChangePassword ? (
              <button
                onClick={() => switchMode('login')}
                className="text-sm text-primary hover:text-primary/80 transition-colors"
              >
                Back to Sign In
              </button>
            ) : (
              <button
                onClick={() => switchMode('changePassword')}
                className="text-sm text-primary hover:text-primary/80 transition-colors"
              >
                Change Password
              </button>
            )}
          </div>
        )}

        {/* Footer */}
        {!isMfa && (
          <div className="mt-4 text-center text-sm text-gray-500">
            <p>Secure access to your organization's DLP platform</p>
          </div>
        )}
      </div>

      {/* Version Info */}
      <div className="mt-4 text-center text-sm text-gray-400">
        <p>Version 1.0.0 | Enterprise Edition</p>
      </div>
    </div>
  )
}
