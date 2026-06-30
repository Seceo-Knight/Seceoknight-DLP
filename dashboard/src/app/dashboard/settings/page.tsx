'use client'
import { extractErrorDetail } from '@/utils/errorUtils'

import { useState } from 'react'
import DashboardLayout from '@/components/layout/DashboardLayout'
import { Settings as SettingsIcon, Bell, Shield, Database, Globe, ShieldCheck, ShieldOff, Eye, EyeOff } from 'lucide-react'
import toast from 'react-hot-toast'
import { initiateGoogleDriveConnection, initiateOneDriveConnection, mfaSetup, mfaVerifySetup, mfaDisable } from '@/lib/api'
import { useAuthStore } from '@/lib/store/auth'

type MfaStep = 'idle' | 'setup_qr' | 'setup_verify' | 'disable_confirm'

export default function SettingsPage() {
  const { user, refreshMe } = useAuthStore()
  const [isConnectingDrive, setIsConnectingDrive] = useState(false)
  const [isConnectingOneDrive, setIsConnectingOneDrive] = useState(false)

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
      toast.error(extractErrorDetail(err, 'Failed to start MFA setup'))
    } finally {
      setMfaLoading(false)
    }
  }

  const handleMfaNext = () => {
    setMfaStep('setup_verify')
    setMfaCode('')
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
      toast.error(extractErrorDetail(err, 'Invalid code — please try again'))
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
      toast.error(extractErrorDetail(err, 'Failed to disable MFA — check your password and code'))
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

  const handleDriveConnect = async () => {
    try {
      setIsConnectingDrive(true)
      const { auth_url } = await initiateGoogleDriveConnection()
      window.open(auth_url, '_blank', 'noopener,noreferrer')
      toast.success('Opened Google consent screen in a new tab')
    } catch (error: any) {
      toast.error(extractErrorDetail(error, 'Failed to start Google Drive auth'))
    } finally {
      setIsConnectingDrive(false)
    }
  }

  const handleOneDriveConnect = async () => {
    try {
      setIsConnectingOneDrive(true)
      const { auth_url } = await initiateOneDriveConnection()
      window.open(auth_url, '_blank', 'noopener,noreferrer')
      toast.success('Opened OneDrive consent screen in a new tab')
    } catch (error: any) {
      toast.error(extractErrorDetail(error, 'Failed to start OneDrive auth'))
    } finally {
      setIsConnectingOneDrive(false)
    }
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Settings</h1>
          <p className="text-gray-400 mt-2">Configure DLP system settings and preferences</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* General Settings */}
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 p-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 bg-indigo-900/30 border border-indigo-500/50 rounded-lg">
                <SettingsIcon className="w-6 h-6 text-indigo-400" />
              </div>
              <h2 className="text-xl font-semibold text-white">General</h2>
            </div>
            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-400">Organization Name</label>
                <input type="text" value="SeceoKnight" className="w-full mt-2 px-4 py-2 bg-gray-900/50 border border-gray-600 rounded-lg text-white" />
              </div>
              <div>
                <label className="text-sm text-gray-400">Server IP Address</label>
                <input type="text" defaultValue="Set in .env (SERVER_IP)" className="w-full mt-2 px-4 py-2 bg-gray-900/50 border border-gray-600 rounded-lg text-white font-mono" readOnly />
              </div>
              <div>
                <label className="text-sm text-gray-400">Timezone</label>
                <select className="w-full mt-2 px-4 py-2 bg-gray-900/50 border border-gray-600 rounded-lg text-white">
                  <option>UTC</option>
                  <option>America/New_York</option>
                  <option>Europe/London</option>
                  <option>Asia/Tokyo</option>
                </select>
              </div>
            </div>
          </div>

          {/* Notifications */}
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 p-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 bg-yellow-900/30 border border-yellow-500/50 rounded-lg">
                <Bell className="w-6 h-6 text-yellow-400" />
              </div>
              <h2 className="text-xl font-semibold text-white">Notifications</h2>
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white font-medium">Email Alerts</p>
                  <p className="text-sm text-gray-400">Receive email notifications for critical events</p>
                </div>
                <input type="checkbox" className="w-12 h-6" defaultChecked />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white font-medium">Slack Integration</p>
                  <p className="text-sm text-gray-400">Send alerts to Slack channel</p>
                </div>
                <input type="checkbox" className="w-12 h-6" />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white font-medium">SIEM Forward</p>
                  <p className="text-sm text-gray-400">Forward events to Wazuh SIEM</p>
                </div>
                <input type="checkbox" className="w-12 h-6" defaultChecked />
              </div>
            </div>
          </div>

          {/* ── MFA / Two-Factor Authentication ── */}
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 p-6 lg:col-span-2">
            <div className="flex items-center gap-3 mb-6">
              <div className={`p-2 rounded-lg border ${mfaEnabled ? 'bg-green-900/30 border-green-500/50' : 'bg-red-900/30 border-red-500/50'}`}>
                <Shield className={`w-6 h-6 ${mfaEnabled ? 'text-green-400' : 'text-red-400'}`} />
              </div>
              <div>
                <h2 className="text-xl font-semibold text-white">Two-Factor Authentication (MFA)</h2>
                <p className="text-sm text-gray-400 mt-0.5">
                  {mfaEnabled
                    ? 'Your account is protected with TOTP two-factor authentication.'
                    : 'Add an extra layer of security to your account with an authenticator app.'}
                </p>
              </div>
              <div className="ml-auto">
                <span className={`px-3 py-1 rounded-full text-xs font-semibold ${mfaEnabled ? 'bg-green-900/40 text-green-300 border border-green-500/40' : 'bg-red-900/40 text-red-300 border border-red-500/40'}`}>
                  {mfaEnabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            </div>

            {/* ── Idle: show enable / disable button ── */}
            {mfaStep === 'idle' && (
              <div>
                {!mfaEnabled ? (
                  <button
                    onClick={handleMfaEnable}
                    disabled={mfaLoading}
                    className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:from-indigo-700 hover:to-purple-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    {mfaLoading ? 'Setting up...' : 'Enable MFA'}
                  </button>
                ) : (
                  <button
                    onClick={() => { setMfaStep('disable_confirm'); setMfaCode(''); setMfaPassword('') }}
                    className="flex items-center gap-2 px-5 py-2.5 bg-red-700 hover:bg-red-600 text-white font-semibold rounded-xl transition-colors"
                  >
                    <ShieldOff className="w-4 h-4" />
                    Disable MFA
                  </button>
                )}
              </div>
            )}

            {/* ── Step 1: QR Code ── */}
            {mfaStep === 'setup_qr' && (
              <div className="space-y-5">
                <p className="text-gray-300 text-sm">
                  Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.):
                </p>
                {mfaQrCode && (
                  <div className="inline-block p-3 bg-white rounded-xl">
                    <img
                      src={`data:image/png;base64,${mfaQrCode}`}
                      alt="MFA QR Code"
                      className="w-48 h-48"
                    />
                  </div>
                )}
                <div>
                  <p className="text-sm text-gray-400 mb-1">
                    Can't scan? Enter this code manually in your app:
                  </p>
                  <div className="flex items-center gap-2">
                    <code className={`flex-1 px-3 py-2 bg-gray-900/50 border border-gray-600 rounded-lg text-sm font-mono tracking-widest ${showSecret ? 'text-white' : 'text-transparent select-none'} blur-sm`}
                      style={{ filter: showSecret ? 'none' : 'blur(4px)' }}>
                      {mfaSecret}
                    </code>
                    <code className={`flex-1 px-3 py-2 bg-gray-900/50 border border-gray-600 rounded-lg text-sm font-mono tracking-widest text-white ${!showSecret ? 'hidden' : ''}`}>
                      {mfaSecret}
                    </code>
                    <button
                      type="button"
                      onClick={() => setShowSecret(!showSecret)}
                      className="p-2 text-gray-400 hover:text-gray-200 transition-colors"
                    >
                      {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={handleMfaNext}
                    className="px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:from-indigo-700 hover:to-purple-700 transition-all"
                  >
                    I've scanned it →
                  </button>
                  <button onClick={cancelMfa} className="px-5 py-2.5 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-xl transition-colors">
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {/* ── Step 2: Verify first code ── */}
            {mfaStep === 'setup_verify' && (
              <div className="space-y-5 max-w-sm">
                <p className="text-gray-300 text-sm">
                  Enter the 6-digit code from your authenticator app to confirm setup:
                </p>
                <div>
                  <label className="text-sm text-gray-400 mb-2 block">Verification Code</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    autoFocus
                    className="w-full px-4 py-3 border-2 border-gray-600 rounded-xl focus:ring-4 focus:ring-purple-500/50 focus:border-purple-500 transition-all bg-gray-900/50 text-white text-center text-2xl tracking-[0.5em] font-mono"
                    placeholder="000000"
                  />
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={handleMfaVerifySetup}
                    disabled={mfaLoading || mfaCode.length !== 6}
                    className="px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:from-indigo-700 hover:to-purple-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {mfaLoading ? 'Verifying...' : 'Activate MFA'}
                  </button>
                  <button onClick={cancelMfa} className="px-5 py-2.5 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-xl transition-colors">
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {/* ── Disable confirm ── */}
            {mfaStep === 'disable_confirm' && (
              <div className="space-y-5 max-w-sm">
                <div className="p-4 bg-red-900/20 border border-red-500/40 rounded-xl">
                  <p className="text-sm text-red-200">
                    To disable MFA, enter your current password and a TOTP code from your authenticator app.
                  </p>
                </div>
                <div>
                  <label className="text-sm text-gray-400 mb-2 block">Current Password</label>
                  <div className="relative">
                    <input
                      type={showMfaPassword ? 'text' : 'password'}
                      value={mfaPassword}
                      onChange={(e) => setMfaPassword(e.target.value)}
                      className="w-full pr-10 px-4 py-3 border-2 border-gray-600 rounded-xl focus:ring-4 focus:ring-purple-500/50 focus:border-purple-500 transition-all bg-gray-900/50 text-white"
                      placeholder="Enter your password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowMfaPassword(!showMfaPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-200"
                    >
                      {showMfaPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                    </button>
                  </div>
                </div>
                <div>
                  <label className="text-sm text-gray-400 mb-2 block">Authenticator Code</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    className="w-full px-4 py-3 border-2 border-gray-600 rounded-xl focus:ring-4 focus:ring-red-500/50 focus:border-red-500 transition-all bg-gray-900/50 text-white text-center text-2xl tracking-[0.5em] font-mono"
                    placeholder="000000"
                  />
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={handleMfaDisable}
                    disabled={mfaLoading || !mfaPassword || mfaCode.length !== 6}
                    className="px-5 py-2.5 bg-red-700 hover:bg-red-600 text-white font-semibold rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {mfaLoading ? 'Disabling...' : 'Confirm Disable'}
                  </button>
                  <button onClick={cancelMfa} className="px-5 py-2.5 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-xl transition-colors">
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Security (other settings) */}
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 p-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 bg-red-900/30 border border-red-500/50 rounded-lg">
                <Shield className="w-6 h-6 text-red-400" />
              </div>
              <h2 className="text-xl font-semibold text-white">Security Policy</h2>
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white font-medium">Auto-block on violation</p>
                  <p className="text-sm text-gray-400">Automatically block suspicious activity</p>
                </div>
                <input type="checkbox" className="w-12 h-6" defaultChecked />
              </div>
              <div className="flex items-center justify-between opacity-60">
                <div>
                  <p className="text-white font-medium">
                    Quarantine Files (coming soon)
                  </p>
                  <p className="text-sm text-gray-400">
                    Move sensitive files to a secure quarantine location
                  </p>
                </div>
                <input type="checkbox" className="w-12 h-6" disabled />
              </div>
            </div>
          </div>

          {/* Database */}
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 p-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 bg-green-900/30 border border-green-500/50 rounded-lg">
                <Database className="w-6 h-6 text-green-400" />
              </div>
              <h2 className="text-xl font-semibold text-white">Database</h2>
            </div>
            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-400">PostgreSQL Status</label>
                <div className="flex items-center gap-2 mt-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-green-400 font-medium">Connected</span>
                </div>
              </div>
              <div>
                <label className="text-sm text-gray-400">MongoDB Status</label>
                <div className="flex items-center gap-2 mt-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-green-400 font-medium">Connected</span>
                </div>
              </div>
              <div>
                <label className="text-sm text-gray-400">Redis Status</label>
                <div className="flex items-center gap-2 mt-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-green-400 font-medium">Connected</span>
                </div>
              </div>
            </div>
          </div>

          {/* Cloud Connectors */}
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 p-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 bg-emerald-900/30 border border-emerald-500/50 rounded-lg">
                <Globe className="w-6 h-6 text-emerald-400" />
              </div>
              <h2 className="text-xl font-semibold text-white">Cloud Connectors</h2>
            </div>
            <p className="text-gray-300 mb-4">
              Link cloud storage accounts to ingest activity events. Temporary actions until the full UI ships.
            </p>
            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={handleDriveConnect}
                disabled={isConnectingDrive}
                className="px-4 py-2 rounded-lg font-semibold transition-colors bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {isConnectingDrive ? 'Opening...' : 'Connect Google Drive'}
              </button>
              <button
                onClick={handleOneDriveConnect}
                disabled={isConnectingOneDrive}
                className="px-4 py-2 rounded-lg font-semibold transition-colors bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {isConnectingOneDrive ? 'Opening...' : 'Connect OneDrive'}
              </button>
            </div>
          </div>
        </div>

        <div className="flex gap-3">
          <button className="px-6 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:from-indigo-700 hover:to-purple-700 transition-all">
            Save Changes
          </button>
          <button className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-xl transition-colors">
            Cancel
          </button>
        </div>
      </div>
    </DashboardLayout>
  )
}
