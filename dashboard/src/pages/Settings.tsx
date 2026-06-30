import { useState } from 'react'
import { Settings as SettingsIcon, Server, Database, Bell, Globe, Lock, ShieldCheck, ShieldOff, Eye, EyeOff } from 'lucide-react'
import toast from 'react-hot-toast'
import { initiateGoogleDriveConnection, initiateOneDriveConnection, changePassword, mfaSetup, mfaVerifySetup, mfaDisable } from '@/lib/api'
import { useAuthStore } from '@/lib/store/auth'
import { API_URL } from '@/lib/config'

type MfaStep = 'idle' | 'setup_qr' | 'setup_verify' | 'disable_confirm'

const defaultOpenSearchUrl = import.meta.env.VITE_OPENSEARCH_URL ?? 'https://localhost:9200'

export default function Settings() {
  const { user, refreshMe } = useAuthStore()
  const [isConnectingDrive, setIsConnectingDrive] = useState(false)
  const [isConnectingOneDrive, setIsConnectingOneDrive] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [changingPassword, setChangingPassword] = useState(false)

  // MFA state — seeded from the auth store so the badge is correct on load
  const [mfaEnabled, setMfaEnabled] = useState(() => user?.mfa_enabled ?? false)
  const [mfaStep, setMfaStep] = useState<MfaStep>('idle')
  const [mfaLoading, setMfaLoading] = useState(false)
  const [mfaQrCode, setMfaQrCode] = useState('')
  const [mfaSecret, setMfaSecret] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [mfaPassword, setMfaPassword] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const [showMfaPassword, setShowMfaPassword] = useState(false)

  const handleMfaEnable = async () => {
    setMfaLoading(true)
    try {
      const { qr_code, secret } = await mfaSetup()
      setMfaQrCode(qr_code)
      setMfaSecret(secret)
      setMfaCode('')
      setMfaStep('setup_qr')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to start MFA setup')
    } finally {
      setMfaLoading(false)
    }
  }

  const handleMfaVerifySetup = async () => {
    if (mfaCode.length !== 6) return
    setMfaLoading(true)
    try {
      await mfaVerifySetup(mfaCode)
      setMfaEnabled(true)
      setMfaStep('idle')
      setMfaCode('')
      setMfaQrCode('')
      setMfaSecret('')
      await refreshMe()
      toast.success('MFA enabled! Your account is now protected with two-factor authentication.')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Invalid code — please try again')
      setMfaCode('')
    } finally {
      setMfaLoading(false)
    }
  }

  const handleMfaDisable = async () => {
    if (!mfaPassword || mfaCode.length !== 6) return
    setMfaLoading(true)
    try {
      await mfaDisable(mfaPassword, mfaCode)
      setMfaEnabled(false)
      setMfaStep('idle')
      setMfaCode('')
      setMfaPassword('')
      await refreshMe()
      toast.success('MFA has been disabled.')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to disable MFA')
      setMfaCode('')
    } finally {
      setMfaLoading(false)
    }
  }

  const cancelMfa = () => {
    setMfaStep('idle')
    setMfaCode('')
    setMfaPassword('')
    setMfaQrCode('')
    setMfaSecret('')
  }

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()

    if (newPassword !== confirmPassword) {
      toast.error('New passwords do not match')
      return
    }

    setChangingPassword(true)
    try {
      await changePassword(user?.email || '', currentPassword, newPassword, confirmPassword)
      toast.success('Password changed successfully')
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || err.message || 'Failed to change password')
    } finally {
      setChangingPassword(false)
    }
  }

  const handleDriveConnect = async () => {
    try {
      setIsConnectingDrive(true)
      const { auth_url } = await initiateGoogleDriveConnection()
      window.open(auth_url, '_blank', 'noopener,noreferrer')
      toast.success('Opened Google consent screen')
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || 'Failed to start Google Drive auth')
    } finally {
      setIsConnectingDrive(false)
    }
  }

  const handleOneDriveConnect = async () => {
    try {
      setIsConnectingOneDrive(true)
      const { auth_url } = await initiateOneDriveConnection()
      window.open(auth_url, '_blank', 'noopener,noreferrer')
      toast.success('Opened OneDrive consent screen')
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || 'Failed to start OneDrive auth')
    } finally {
      setIsConnectingOneDrive(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="mt-1 text-sm text-gray-600">
          Configure system settings and preferences
        </p>
      </div>

      {/* Settings Sections */}
      <div className="space-y-6">
        {/* Account Security */}
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Lock className="h-5 w-5 text-purple-600" />
            </div>
            <h3 className="font-semibold text-gray-900">Account Security</h3>
          </div>

          <form onSubmit={handleChangePassword} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Username
              </label>
              <input
                type="text"
                className="input bg-gray-50"
                value={user?.email || ''}
                readOnly
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Current Password
              </label>
              <input
                type="password"
                className="input"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter current password"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                New Password
              </label>
              <input
                type="password"
                className="input"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Confirm New Password
              </label>
              <input
                type="password"
                className="input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
                required
              />
              <p className="mt-1 text-xs text-gray-500">
                Must be at least 7 characters with uppercase, lowercase, digit, and special character.
              </p>
            </div>

            <button
              type="submit"
              disabled={changingPassword}
              className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {changingPassword ? 'Updating...' : 'Update Password'}
            </button>
          </form>
        </div>

        {/* Two-Factor Authentication */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${mfaEnabled ? 'bg-green-100' : 'bg-gray-100'}`}>
                <ShieldCheck className={`h-5 w-5 ${mfaEnabled ? 'text-green-600' : 'text-gray-500'}`} />
              </div>
              <div>
                <h3 className="font-semibold text-gray-900">Two-Factor Authentication</h3>
                <p className="text-xs text-gray-500 mt-0.5">
                  {mfaEnabled ? 'Your account is protected with TOTP.' : 'Add a second layer of security to your account.'}
                </p>
              </div>
            </div>
            <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${mfaEnabled ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-600'}`}>
              {mfaEnabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>

          {/* Idle */}
          {mfaStep === 'idle' && (
            !mfaEnabled ? (
              <button
                onClick={handleMfaEnable}
                disabled={mfaLoading}
                className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                <ShieldCheck className="w-4 h-4" />
                {mfaLoading ? 'Setting up...' : 'Enable MFA'}
              </button>
            ) : (
              <button
                onClick={() => { setMfaStep('disable_confirm'); setMfaCode(''); setMfaPassword('') }}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-semibold rounded-lg transition-colors text-sm"
              >
                <ShieldOff className="w-4 h-4" />
                Disable MFA
              </button>
            )
          )}

          {/* Step 1: QR Code */}
          {mfaStep === 'setup_qr' && (
            <div className="space-y-4">
              <p className="text-sm text-gray-600">
                Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.):
              </p>
              {mfaQrCode && (
                <div className="inline-block p-3 bg-white border border-gray-200 rounded-xl shadow-sm">
                  <img src={`data:image/png;base64,${mfaQrCode}`} alt="MFA QR Code" className="w-48 h-48" />
                </div>
              )}
              <div>
                <p className="text-xs text-gray-500 mb-1">Can't scan? Enter this code manually:</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-sm font-mono tracking-widest text-gray-800"
                    style={{ filter: showSecret ? 'none' : 'blur(5px)', userSelect: showSecret ? 'auto' : 'none' }}>
                    {mfaSecret}
                  </code>
                  <button type="button" onClick={() => setShowSecret(!showSecret)} className="p-2 text-gray-400 hover:text-gray-600">
                    {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <div className="flex gap-3">
                <button onClick={() => { setMfaStep('setup_verify'); setMfaCode('') }} className="btn-primary">
                  I've scanned it →
                </button>
                <button onClick={cancelMfa} className="btn-secondary">Cancel</button>
              </div>
            </div>
          )}

          {/* Step 2: Verify */}
          {mfaStep === 'setup_verify' && (
            <div className="space-y-4 max-w-xs">
              <p className="text-sm text-gray-600">Enter the 6-digit code from your authenticator app to confirm:</p>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                autoFocus
                className="input text-center text-2xl tracking-[0.5em] font-mono"
                placeholder="000000"
              />
              <div className="flex gap-3">
                <button
                  onClick={handleMfaVerifySetup}
                  disabled={mfaLoading || mfaCode.length !== 6}
                  className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {mfaLoading ? 'Activating...' : 'Activate MFA'}
                </button>
                <button onClick={cancelMfa} className="btn-secondary">Cancel</button>
              </div>
            </div>
          )}

          {/* Disable confirm */}
          {mfaStep === 'disable_confirm' && (
            <div className="space-y-4 max-w-xs">
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
                Enter your current password and a TOTP code to disable MFA.
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Current Password</label>
                <div className="relative">
                  <input
                    type={showMfaPassword ? 'text' : 'password'}
                    value={mfaPassword}
                    onChange={(e) => setMfaPassword(e.target.value)}
                    className="input pr-10"
                    placeholder="Enter your password"
                  />
                  <button type="button" onClick={() => setShowMfaPassword(!showMfaPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600">
                    {showMfaPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Authenticator Code</label>
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                  className="input text-center text-xl tracking-[0.4em] font-mono"
                  placeholder="000000"
                />
              </div>
              <div className="flex gap-3">
                <button
                  onClick={handleMfaDisable}
                  disabled={mfaLoading || !mfaPassword || mfaCode.length !== 6}
                  className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-semibold rounded-lg transition-colors text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {mfaLoading ? 'Disabling...' : 'Confirm Disable'}
                </button>
                <button onClick={cancelMfa} className="btn-secondary">Cancel</button>
              </div>
            </div>
          )}
        </div>

        {/* System Settings */}
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Server className="h-5 w-5 text-blue-600" />
            </div>
            <h3 className="font-semibold text-gray-900">System Settings</h3>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Manager URL
              </label>
              <input
                type="text"
                className="input"
                defaultValue={API_URL}
                readOnly
              />
              <p className="mt-1 text-xs text-gray-500">
                The manager API endpoint
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Refresh Interval
              </label>
              <select className="input">
                <option>5 seconds</option>
                <option selected>10 seconds</option>
                <option>30 seconds</option>
                <option>60 seconds</option>
              </select>
              <p className="mt-1 text-xs text-gray-500">
                How often to refresh data automatically
              </p>
            </div>
          </div>
        </div>

        {/* Database Settings */}
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-green-100 rounded-lg">
              <Database className="h-5 w-5 text-green-600" />
            </div>
            <h3 className="font-semibold text-gray-900">OpenSearch Settings</h3>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                OpenSearch Host
              </label>
              <input
                type="text"
                className="input"
                defaultValue={defaultOpenSearchUrl}
                readOnly
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Index Prefix
              </label>
              <input
                type="text"
                className="input"
                defaultValue="seceoknight"
                readOnly
              />
              <p className="mt-1 text-xs text-gray-500">
                Prefix for all indices (e.g., seceoknight-events-2025.01.12)
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Retention Days
              </label>
              <input
                type="number"
                className="input"
                defaultValue="90"
                readOnly
              />
              <p className="mt-1 text-xs text-gray-500">
                Number of days to retain event data
              </p>
            </div>
          </div>
        </div>

        {/* Notification Settings */}
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Bell className="h-5 w-5 text-yellow-600" />
            </div>
            <h3 className="font-semibold text-gray-900">Notifications</h3>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">Email Notifications</p>
                <p className="text-sm text-gray-600">
                  Send email alerts for critical events
                </p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" defaultChecked />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
              </label>
            </div>

            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">Desktop Notifications</p>
                <p className="text-sm text-gray-600">
                  Show browser notifications for new alerts
                </p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" className="sr-only peer" />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
              </label>
            </div>
          </div>
        </div>

        {/* Cloud Connectors */}
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-emerald-100 rounded-lg">
              <Globe className="h-5 w-5 text-emerald-600" />
            </div>
            <h3 className="font-semibold text-gray-900">Cloud Connectors</h3>
          </div>
          <p className="text-sm text-gray-600 mb-4">
            Use these temporary actions to open OAuth flows for testing. We&apos;ll relocate them once the full UI ships.
          </p>
          <div className="flex flex-col sm:flex-row gap-3">
            <button
              onClick={handleDriveConnect}
              disabled={isConnectingDrive}
              className="px-4 py-2 rounded-lg font-semibold text-white bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
            >
              {isConnectingDrive ? 'Opening...' : 'Connect Google Drive'}
            </button>
            <button
              onClick={handleOneDriveConnect}
              disabled={isConnectingOneDrive}
              className="px-4 py-2 rounded-lg font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
            >
              {isConnectingOneDrive ? 'Opening...' : 'Connect OneDrive'}
            </button>
          </div>
        </div>

        {/* About */}
        <div className="card">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-gray-100 rounded-lg">
              <SettingsIcon className="h-5 w-5 text-gray-600" />
            </div>
            <h3 className="font-semibold text-gray-900">About</h3>
          </div>

          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-600">Version</span>
              <span className="font-medium">2.0.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Backend API</span>
              <span className="font-medium">FastAPI 0.109.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">OpenSearch</span>
              <span className="font-medium">2.11.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">License</span>
              <span className="font-medium">Apache 2.0</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
