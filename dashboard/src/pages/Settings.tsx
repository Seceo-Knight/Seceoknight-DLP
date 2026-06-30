import { useState } from 'react'
import {
  Lock, ShieldCheck, Eye, EyeOff, Server, Database,
  Bell, Globe, Info, ChevronRight, CheckCircle2, AlertCircle,
  Cloud, HardDrive,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { initiateGoogleDriveConnection, initiateOneDriveConnection, changePassword, mfaSetup, mfaVerifySetup } from '@/lib/api'
import { useAuthStore } from '@/lib/store/auth'
import { API_URL } from '@/lib/config'

type MfaStep = 'idle' | 'setup_qr' | 'setup_verify'
type Tab = 'security' | 'mfa' | 'system' | 'notifications' | 'integrations' | 'about'

const defaultOpenSearchUrl = import.meta.env.VITE_OPENSEARCH_URL ?? 'https://localhost:9200'

const tabs: { id: Tab; label: string; icon: typeof Lock; description: string }[] = [
  { id: 'security',      label: 'Account Security',  icon: Lock,         description: 'Password & credentials' },
  { id: 'mfa',           label: 'Two-Factor Auth',   icon: ShieldCheck,  description: 'TOTP authentication' },
  { id: 'system',        label: 'System',            icon: Server,       description: 'API & refresh settings' },
  { id: 'notifications', label: 'Notifications',     icon: Bell,         description: 'Alerts & emails' },
  { id: 'integrations',  label: 'Integrations',      icon: Cloud,        description: 'Cloud connectors' },
  { id: 'about',         label: 'About',             icon: Info,         description: 'Version & license' },
]

export default function Settings() {
  const { user, refreshMe } = useAuthStore()
  const [activeTab, setActiveTab] = useState<Tab>('security')

  // Password state
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [changingPassword, setChangingPassword] = useState(false)
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)

  // MFA state
  const [mfaEnabled, setMfaEnabled] = useState(() => user?.mfa_enabled ?? false)
  const [mfaStep, setMfaStep] = useState<MfaStep>('idle')
  const [mfaLoading, setMfaLoading] = useState(false)
  const [mfaQrCode, setMfaQrCode] = useState('')
  const [mfaSecret, setMfaSecret] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [showSecret, setShowSecret] = useState(false)

  // Integrations state
  const [isConnectingDrive, setIsConnectingDrive] = useState(false)
  const [isConnectingOneDrive, setIsConnectingOneDrive] = useState(false)

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
      toast.success('MFA enabled successfully.')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Invalid code — please try again')
      setMfaCode('')
    } finally {
      setMfaLoading(false)
    }
  }

  const cancelMfa = () => {
    setMfaStep('idle')
    setMfaCode('')
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
      toast.success('Password updated successfully')
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

  const PasswordInput = ({
    label, value, onChange, placeholder, show, onToggle, hint
  }: {
    label: string; value: string; onChange: (v: string) => void
    placeholder: string; show: boolean; onToggle: () => void; hint?: string
  }) => (
    <div>
      <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">{label}</label>
      <div className="relative">
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className="input pr-10"
          required
        />
        <button type="button" onClick={onToggle}
          className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600">
          {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
        </button>
      </div>
      {hint && <p className="mt-1 text-xs text-gray-400">{hint}</p>}
    </div>
  )

  const ReadonlyField = ({ label, value, hint }: { label: string; value: string; hint?: string }) => (
    <div>
      <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">{label}</label>
      <div className="flex items-center gap-2 px-3 py-2.5 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-700 font-mono">
        {value}
      </div>
      {hint && <p className="mt-1 text-xs text-gray-400">{hint}</p>}
    </div>
  )

  return (
    <div className="h-full">
      {/* Page Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="mt-1 text-sm text-gray-500">
          Manage your account, security, and system preferences
        </p>
      </div>

      <div className="flex gap-6 min-h-[600px]">
        {/* Left Nav */}
        <div className="w-56 shrink-0">
          <nav className="space-y-0.5">
            {tabs.map((tab) => {
              const Icon = tab.icon
              const isActive = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all group ${
                    isActive
                      ? 'bg-primary-50 text-primary-700 font-medium'
                      : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
                  }`}
                >
                  <Icon className={`h-4 w-4 shrink-0 ${isActive ? 'text-primary-600' : 'text-gray-400 group-hover:text-gray-600'}`} />
                  <div className="min-w-0">
                    <p className="text-sm truncate">{tab.label}</p>
                    <p className={`text-[10px] truncate ${isActive ? 'text-primary-500' : 'text-gray-400'}`}>{tab.description}</p>
                  </div>
                  {isActive && <ChevronRight className="h-3.5 w-3.5 ml-auto text-primary-400" />}
                </button>
              )
            })}
          </nav>
        </div>

        {/* Right Content */}
        <div className="flex-1 min-w-0">

          {/* ── Account Security ── */}
          {activeTab === 'security' && (
            <div className="card max-w-lg">
              <div className="flex items-center gap-3 mb-6 pb-4 border-b border-gray-100">
                <div className="p-2 bg-purple-50 rounded-lg border border-purple-100">
                  <Lock className="h-5 w-5 text-purple-600" />
                </div>
                <div>
                  <h2 className="font-semibold text-gray-900">Account Security</h2>
                  <p className="text-xs text-gray-500 mt-0.5">Update your login credentials</p>
                </div>
              </div>

              {/* Identity */}
              <div className="mb-6 p-3 bg-gray-50 rounded-lg border border-gray-200 flex items-center gap-3">
                <div className="h-9 w-9 rounded-full bg-primary-100 flex items-center justify-center text-primary-700 font-bold text-sm shrink-0">
                  {(user?.full_name || user?.email || 'A').charAt(0).toUpperCase()}
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">{user?.full_name || '—'}</p>
                  <p className="text-xs text-gray-500 truncate">{user?.email}</p>
                </div>
                <span className="ml-auto shrink-0 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-indigo-100 text-indigo-700 uppercase tracking-wide">
                  {user?.role}
                </span>
              </div>

              <form onSubmit={handleChangePassword} className="space-y-4">
                <PasswordInput
                  label="Current Password" value={currentPassword}
                  onChange={setCurrentPassword} placeholder="Enter current password"
                  show={showCurrent} onToggle={() => setShowCurrent(!showCurrent)}
                />
                <PasswordInput
                  label="New Password" value={newPassword}
                  onChange={setNewPassword} placeholder="Enter new password"
                  show={showNew} onToggle={() => setShowNew(!showNew)}
                  hint="Min. 7 characters with uppercase, lowercase, digit and special character"
                />
                <PasswordInput
                  label="Confirm New Password" value={confirmPassword}
                  onChange={setConfirmPassword} placeholder="Confirm new password"
                  show={showConfirm} onToggle={() => setShowConfirm(!showConfirm)}
                />
                <div className="pt-2">
                  <button type="submit" disabled={changingPassword}
                    className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed w-full sm:w-auto">
                    {changingPassword ? 'Updating...' : 'Update Password'}
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* ── Two-Factor Auth ── */}
          {activeTab === 'mfa' && (
            <div className="card max-w-lg">
              <div className="flex items-center gap-3 mb-6 pb-4 border-b border-gray-100">
                <div className={`p-2 rounded-lg border ${mfaEnabled ? 'bg-green-50 border-green-100' : 'bg-gray-50 border-gray-200'}`}>
                  <ShieldCheck className={`h-5 w-5 ${mfaEnabled ? 'text-green-600' : 'text-gray-400'}`} />
                </div>
                <div className="flex-1">
                  <h2 className="font-semibold text-gray-900">Two-Factor Authentication</h2>
                  <p className="text-xs text-gray-500 mt-0.5">TOTP-based second factor via authenticator app</p>
                </div>
                <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${mfaEnabled ? 'bg-green-100 text-green-700' : 'bg-red-50 text-red-600 border border-red-100'}`}>
                  {mfaEnabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>

              {mfaStep === 'idle' && (
                <>
                  {mfaEnabled ? (
                    <div className="space-y-4">
                      <div className="flex items-start gap-3 p-4 bg-green-50 border border-green-200 rounded-lg">
                        <CheckCircle2 className="h-5 w-5 text-green-600 mt-0.5 shrink-0" />
                        <div>
                          <p className="text-sm font-medium text-green-800">MFA is active</p>
                          <p className="text-xs text-green-700 mt-0.5">Your account requires a TOTP code on every login. This cannot be self-disabled — contact your administrator if you lose access to your authenticator app.</p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="flex items-start gap-3 p-4 bg-amber-50 border border-amber-200 rounded-lg">
                        <AlertCircle className="h-5 w-5 text-amber-600 mt-0.5 shrink-0" />
                        <div>
                          <p className="text-sm font-medium text-amber-800">MFA not enabled</p>
                          <p className="text-xs text-amber-700 mt-0.5">Your account is protected by password only. Enable MFA to add a second layer of security.</p>
                        </div>
                      </div>
                      <button onClick={handleMfaEnable} disabled={mfaLoading}
                        className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2">
                        <ShieldCheck className="w-4 h-4" />
                        {mfaLoading ? 'Setting up...' : 'Enable Two-Factor Authentication'}
                      </button>
                    </div>
                  )}
                </>
              )}

              {mfaStep === 'setup_qr' && (
                <div className="space-y-5">
                  <div className="text-sm text-gray-600 space-y-1">
                    <p className="font-medium text-gray-800">Step 1 — Scan the QR code</p>
                    <p className="text-xs text-gray-500">Open Google Authenticator, Authy, or 1Password and scan the code below.</p>
                  </div>
                  {mfaQrCode && (
                    <div className="inline-block p-4 bg-white border-2 border-gray-200 rounded-xl shadow-sm">
                      <img src={`data:image/png;base64,${mfaQrCode}`} alt="MFA QR Code" className="w-44 h-44" />
                    </div>
                  )}
                  <div>
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Manual entry key</p>
                    <div className="flex items-center gap-2 p-2.5 bg-gray-50 border border-gray-200 rounded-lg">
                      <code className="flex-1 text-xs font-mono tracking-widest text-gray-800"
                        style={{ filter: showSecret ? 'none' : 'blur(4px)', userSelect: showSecret ? 'auto' : 'none' }}>
                        {mfaSecret}
                      </code>
                      <button type="button" onClick={() => setShowSecret(!showSecret)}
                        className="p-1 text-gray-400 hover:text-gray-600 shrink-0">
                        {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                  <div className="flex gap-3 pt-1">
                    <button onClick={() => { setMfaStep('setup_verify'); setMfaCode('') }} className="btn-primary">
                      I've scanned it →
                    </button>
                    <button onClick={cancelMfa} className="btn-secondary">Cancel</button>
                  </div>
                </div>
              )}

              {mfaStep === 'setup_verify' && (
                <div className="space-y-5">
                  <div className="text-sm text-gray-600 space-y-1">
                    <p className="font-medium text-gray-800">Step 2 — Verify the code</p>
                    <p className="text-xs text-gray-500">Enter the 6-digit code shown in your authenticator app to confirm setup.</p>
                  </div>
                  <input
                    type="text" inputMode="numeric" maxLength={6}
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    autoFocus
                    className="input text-center text-3xl tracking-[0.6em] font-mono w-full max-w-[240px]"
                    placeholder="000000"
                  />
                  <div className="flex gap-3">
                    <button onClick={handleMfaVerifySetup}
                      disabled={mfaLoading || mfaCode.length !== 6}
                      className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed">
                      {mfaLoading ? 'Activating...' : 'Activate MFA'}
                    </button>
                    <button onClick={cancelMfa} className="btn-secondary">Cancel</button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── System ── */}
          {activeTab === 'system' && (
            <div className="space-y-5 max-w-lg">
              <div className="card">
                <div className="flex items-center gap-3 mb-5 pb-4 border-b border-gray-100">
                  <div className="p-2 bg-blue-50 rounded-lg border border-blue-100">
                    <Server className="h-5 w-5 text-blue-600" />
                  </div>
                  <div>
                    <h2 className="font-semibold text-gray-900">API Configuration</h2>
                    <p className="text-xs text-gray-500 mt-0.5">Manager endpoint and data refresh settings</p>
                  </div>
                </div>
                <div className="space-y-4">
                  <ReadonlyField label="Manager API URL" value={API_URL} hint="The backend API endpoint for this deployment" />
                  <div>
                    <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Data Refresh Interval</label>
                    <select className="input">
                      <option>5 seconds</option>
                      <option>10 seconds</option>
                      <option>30 seconds</option>
                      <option>60 seconds</option>
                    </select>
                    <p className="mt-1 text-xs text-gray-400">How often the dashboard polls for new events and alerts</p>
                  </div>
                </div>
              </div>

              <div className="card">
                <div className="flex items-center gap-3 mb-5 pb-4 border-b border-gray-100">
                  <div className="p-2 bg-green-50 rounded-lg border border-green-100">
                    <Database className="h-5 w-5 text-green-600" />
                  </div>
                  <div>
                    <h2 className="font-semibold text-gray-900">OpenSearch</h2>
                    <p className="text-xs text-gray-500 mt-0.5">Event storage and index configuration</p>
                  </div>
                </div>
                <div className="space-y-4">
                  <ReadonlyField label="OpenSearch Host" value={defaultOpenSearchUrl} />
                  <ReadonlyField label="Index Prefix" value="seceoknight" hint="Indices follow the pattern: seceoknight-events-YYYY.MM.DD" />
                  <ReadonlyField label="Retention Period" value="90 days" hint="Events older than 90 days are automatically purged" />
                </div>
              </div>
            </div>
          )}

          {/* ── Notifications ── */}
          {activeTab === 'notifications' && (
            <div className="card max-w-lg">
              <div className="flex items-center gap-3 mb-6 pb-4 border-b border-gray-100">
                <div className="p-2 bg-yellow-50 rounded-lg border border-yellow-100">
                  <Bell className="h-5 w-5 text-yellow-600" />
                </div>
                <div>
                  <h2 className="font-semibold text-gray-900">Notifications</h2>
                  <p className="text-xs text-gray-500 mt-0.5">Configure alert delivery preferences</p>
                </div>
              </div>
              <div className="divide-y divide-gray-100">
                {[
                  { label: 'Email Notifications', desc: 'Receive email alerts for critical and high-severity events', defaultOn: true },
                  { label: 'Desktop Notifications', desc: 'Show browser push notifications for new alerts', defaultOn: false },
                  { label: 'Critical Events Only', desc: 'Limit notifications to critical severity events only', defaultOn: false },
                ].map((item) => (
                  <div key={item.label} className="flex items-center justify-between py-4">
                    <div>
                      <p className="text-sm font-medium text-gray-900">{item.label}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{item.desc}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer ml-4 shrink-0">
                      <input type="checkbox" className="sr-only peer" defaultChecked={item.defaultOn} />
                      <div className="w-10 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary-600"></div>
                    </label>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Integrations ── */}
          {activeTab === 'integrations' && (
            <div className="card max-w-lg">
              <div className="flex items-center gap-3 mb-6 pb-4 border-b border-gray-100">
                <div className="p-2 bg-emerald-50 rounded-lg border border-emerald-100">
                  <Globe className="h-5 w-5 text-emerald-600" />
                </div>
                <div>
                  <h2 className="font-semibold text-gray-900">Cloud Integrations</h2>
                  <p className="text-xs text-gray-500 mt-0.5">Connect cloud storage for DLP monitoring</p>
                </div>
              </div>
              <div className="space-y-3">
                {/* Google Drive */}
                <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:border-gray-300 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-50 rounded-lg">
                      <HardDrive className="h-5 w-5 text-blue-600" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">Google Drive</p>
                      <p className="text-xs text-gray-500">Monitor files and sharing activity</p>
                    </div>
                  </div>
                  <button onClick={handleDriveConnect} disabled={isConnectingDrive}
                    className="px-3 py-1.5 rounded-lg text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-60 disabled:cursor-not-allowed transition-colors shrink-0">
                    {isConnectingDrive ? 'Connecting...' : 'Connect'}
                  </button>
                </div>

                {/* OneDrive */}
                <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:border-gray-300 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-indigo-50 rounded-lg">
                      <Cloud className="h-5 w-5 text-indigo-600" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">Microsoft OneDrive</p>
                      <p className="text-xs text-gray-500">Monitor SharePoint and OneDrive data</p>
                    </div>
                  </div>
                  <button onClick={handleOneDriveConnect} disabled={isConnectingOneDrive}
                    className="px-3 py-1.5 rounded-lg text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-60 disabled:cursor-not-allowed transition-colors shrink-0">
                    {isConnectingOneDrive ? 'Connecting...' : 'Connect'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ── About ── */}
          {activeTab === 'about' && (
            <div className="card max-w-lg">
              <div className="flex items-center gap-3 mb-6 pb-4 border-b border-gray-100">
                <div className="p-2 bg-gray-100 rounded-lg border border-gray-200">
                  <Info className="h-5 w-5 text-gray-600" />
                </div>
                <div>
                  <h2 className="font-semibold text-gray-900">About SeceoKnight DLP</h2>
                  <p className="text-xs text-gray-500 mt-0.5">Version and platform information</p>
                </div>
              </div>
              <div className="space-y-1">
                {[
                  { label: 'Product', value: 'SeceoKnight DLP' },
                  { label: 'Version', value: '2.0.0' },
                  { label: 'Backend', value: 'FastAPI 0.109.0' },
                  { label: 'Database', value: 'PostgreSQL 15' },
                  { label: 'Search Engine', value: 'OpenSearch 2.11.0' },
                  { label: 'License', value: 'Apache 2.0' },
                ].map((row) => (
                  <div key={row.label} className="flex items-center justify-between py-2.5 border-b border-gray-50 last:border-0">
                    <span className="text-sm text-gray-500">{row.label}</span>
                    <span className="text-sm font-medium text-gray-900">{row.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  )
}
