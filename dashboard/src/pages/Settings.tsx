import { useState, useEffect } from 'react'
import {
  Lock, ShieldCheck, Eye, EyeOff, Server, Database,
  Bell, Globe, Info, ChevronRight, CheckCircle2, AlertCircle,
  Cloud, HardDrive, User, Wifi, WifiOff, Mail, Plus, X, Send, Archive,
} from 'lucide-react'
import toast from 'react-hot-toast'
import {
  initiateGoogleDriveConnection, initiateOneDriveConnection, changePassword, mfaSetup, mfaVerifySetup,
  getRetentionConfig, updateRetentionConfig, type RetentionConfig,
} from '@/lib/api'
import { useAuthStore } from '@/lib/store/auth'
import { API_URL } from '@/lib/config'
import IpAllowlistSection from '@/components/settings/IpAllowlistSection'

type MfaStep = 'idle' | 'setup_qr' | 'setup_verify'
type Tab = 'security' | 'mfa' | 'system' | 'notifications' | 'integrations' | 'about'

const defaultOpenSearchUrl = import.meta.env.VITE_OPENSEARCH_URL ?? 'https://localhost:9200'

const tabs: { id: Tab; label: string; icon: typeof Lock; description: string }[] = [
  { id: 'security',      label: 'Account Security',  icon: Lock,        description: 'Password & credentials' },
  { id: 'mfa',           label: 'Two-Factor Auth',   icon: ShieldCheck, description: 'TOTP authentication' },
  { id: 'system',        label: 'System',            icon: Server,      description: 'API & data settings' },
  { id: 'notifications', label: 'Notifications',     icon: Bell,        description: 'Alerts & delivery' },
  { id: 'integrations',  label: 'Integrations',      icon: Cloud,       description: 'Cloud connectors' },
  { id: 'about',         label: 'About',             icon: Info,        description: 'Version & license' },
]

export default function Settings() {
  const { user, refreshMe } = useAuthStore()
  const [activeTab, setActiveTab] = useState<Tab>('security')

  // Always fetch fresh MFA status on mount so admin-reset is reflected immediately
  useEffect(() => { refreshMe() }, [])

  // Derive MFA status reactively from store — never stale
  const mfaEnabled = user?.mfa_enabled ?? false
  const isSuperAdmin = String(user?.role ?? '').toUpperCase() === 'ADMIN'

  // ── Log retention state (Super Admin only) ───────────────────────────────
  const [retention, setRetention] = useState<RetentionConfig | null>(null)
  const [retForm, setRetForm] = useState({ event_retention_days: 180, opensearch_retention_days: 90 })
  const [savingRetention, setSavingRetention] = useState(false)

  useEffect(() => {
    if (activeTab !== 'system' || !isSuperAdmin) return
    getRetentionConfig()
      .then((r) => {
        setRetention(r)
        setRetForm({ event_retention_days: r.event_retention_days, opensearch_retention_days: r.opensearch_retention_days })
      })
      .catch(() => {})
  }, [activeTab, isSuperAdmin])

  const handleSaveRetention = async (e: React.FormEvent) => {
    e.preventDefault()
    const min = retention?.minimum_days ?? 90
    if (retForm.event_retention_days < min || retForm.opensearch_retention_days < min) {
      toast.error(`Retention must be at least ${min} days`)
      return
    }
    setSavingRetention(true)
    try {
      const r = await updateRetentionConfig(retForm)
      setRetention(r)
      setRetForm({ event_retention_days: r.event_retention_days, opensearch_retention_days: r.opensearch_retention_days })
      toast.success('Log retention updated')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to update retention')
    } finally {
      setSavingRetention(false)
    }
  }

  // Password state
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [changingPassword, setChangingPassword] = useState(false)
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)

  // MFA flow state
  const [mfaStep, setMfaStep] = useState<MfaStep>('idle')
  const [mfaLoading, setMfaLoading] = useState(false)
  const [mfaQrCode, setMfaQrCode] = useState('')
  const [mfaSecret, setMfaSecret] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [showSecret, setShowSecret] = useState(false)

  // Integration state
  const [isConnectingDrive, setIsConnectingDrive] = useState(false)
  const [isConnectingOneDrive, setIsConnectingOneDrive] = useState(false)

  // ── Email alert settings state ───────────────────────────────────────────
  const [emailSettings, setEmailSettings] = useState({
    smtp_host: 'smtp.gmail.com',
    smtp_port: 587,
    smtp_tls: true,
    smtp_user: '',
    smtp_password: '',
    smtp_from_name: 'SeceoKnight DLP',
    smtp_from_email: 'noreply@seceoknight.com',
    alert_recipients: [] as string[],
    min_severity: 'high',
    enabled: true,
  })
  const [emailSettingsLoading, setEmailSettingsLoading] = useState(false)
  const [emailSettingsSaving, setEmailSettingsSaving] = useState(false)
  const [testEmailAddress, setTestEmailAddress] = useState('')
  const [testEmailSending, setTestEmailSending] = useState(false)
  const [newRecipient, setNewRecipient] = useState('')

  useEffect(() => {
    if (activeTab !== 'notifications') return
    const token = localStorage.getItem('token') || sessionStorage.getItem('token') || ''
    setEmailSettingsLoading(true)
    fetch(`${API_URL}/api/v1/settings/email`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => r.ok ? r.json() : Promise.reject(r))
      .then(data => setEmailSettings(s => ({
        ...s,
        smtp_host: data.smtp_host ?? s.smtp_host,
        smtp_port: data.smtp_port ?? s.smtp_port,
        smtp_tls: data.smtp_tls ?? s.smtp_tls,
        smtp_user: data.smtp_user ?? s.smtp_user,
        smtp_from_name: data.smtp_from_name ?? s.smtp_from_name,
        smtp_from_email: data.smtp_from_email ?? s.smtp_from_email,
        alert_recipients: data.alert_recipients ?? s.alert_recipients,
        min_severity: data.min_severity ?? s.min_severity,
        enabled: data.enabled ?? s.enabled,
      })))
      .catch(() => {})
      .finally(() => setEmailSettingsLoading(false))
  }, [activeTab])

  const handleSaveEmailSettings = async () => {
    const token = localStorage.getItem('token') || sessionStorage.getItem('token') || ''
    setEmailSettingsSaving(true)
    try {
      const res = await fetch(`${API_URL}/api/v1/settings/email`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ ...emailSettings, smtp_password: emailSettings.smtp_password || null }),
      })
      if (!res.ok) throw new Error((await res.json()).detail || 'Failed to save')
      toast.success('Email settings saved')
      setEmailSettings(s => ({ ...s, smtp_password: '' }))
    } catch (e: any) {
      toast.error(e.message || 'Failed to save email settings')
    } finally {
      setEmailSettingsSaving(false)
    }
  }

  const handleTestEmail = async () => {
    if (!testEmailAddress) { toast.error('Enter a recipient address first'); return }
    const token = localStorage.getItem('token') || sessionStorage.getItem('token') || ''
    setTestEmailSending(true)
    try {
      const res = await fetch(`${API_URL}/api/v1/settings/email/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ recipient: testEmailAddress }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Test failed')
      toast.success(data.message || 'Test email sent!')
    } catch (e: any) {
      toast.error(e.message || 'Failed to send test email')
    } finally {
      setTestEmailSending(false)
    }
  }

  const addRecipient = () => {
    const email = newRecipient.trim()
    if (!email || emailSettings.alert_recipients.includes(email)) return
    setEmailSettings(s => ({ ...s, alert_recipients: [...s.alert_recipients, email] }))
    setNewRecipient('')
  }

  const removeRecipient = (email: string) => {
    setEmailSettings(s => ({ ...s, alert_recipients: s.alert_recipients.filter(r => r !== email) }))
  }

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
    if (newPassword !== confirmPassword) { toast.error('New passwords do not match'); return }
    setChangingPassword(true)
    try {
      await changePassword(user?.email || '', currentPassword, newPassword, confirmPassword)
      toast.success('Password updated successfully')
      setCurrentPassword(''); setNewPassword(''); setConfirmPassword('')
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
    } finally { setIsConnectingDrive(false) }
  }

  const handleOneDriveConnect = async () => {
    try {
      setIsConnectingOneDrive(true)
      const { auth_url } = await initiateOneDriveConnection()
      window.open(auth_url, '_blank', 'noopener,noreferrer')
      toast.success('Opened OneDrive consent screen')
    } catch (error: any) {
      toast.error(error?.response?.data?.detail || 'Failed to start OneDrive auth')
    } finally { setIsConnectingOneDrive(false) }
  }

  return (
    <div className="flex flex-col h-full">
      {/* Page Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="mt-1 text-sm text-gray-500">Manage your account, security, and platform preferences</p>
      </div>

      <div className="flex gap-8 flex-1 min-h-0">

        {/* ── Left Nav ── */}
        <div className="w-60 shrink-0">
          <div className="sticky top-0">
            <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2 px-3">Configuration</p>
            <nav className="space-y-0.5">
              {tabs.map((tab) => {
                const Icon = tab.icon
                const isActive = activeTab === tab.id
                return (
                  <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                    className={`w-full flex items-center gap-3 px-3 py-3 rounded-xl text-left transition-all group ${
                      isActive ? 'bg-blue-50 text-blue-700' : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                    }`}
                  >
                    <div className={`p-1.5 rounded-lg shrink-0 ${isActive ? 'bg-blue-100' : 'bg-gray-100 group-hover:bg-gray-200'}`}>
                      <Icon className={`h-4 w-4 ${isActive ? 'text-blue-600' : 'text-gray-500'}`} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className={`text-sm font-medium truncate ${isActive ? 'text-blue-700' : ''}`}>{tab.label}</p>
                      <p className="text-[11px] text-gray-400 truncate">{tab.description}</p>
                    </div>
                    {isActive && <ChevronRight className="h-3.5 w-3.5 text-blue-400 shrink-0" />}
                  </button>
                )
              })}
            </nav>
          </div>
        </div>

        {/* ── Right Content ── */}
        <div className="flex-1 min-w-0 pb-8">

          {/* ── ACCOUNT SECURITY ── */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              {/* Identity Card */}
              <div className="card flex items-center gap-5 p-5">
                <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white font-bold text-xl shrink-0 shadow-md">
                  {(user?.full_name || user?.email || 'A').charAt(0).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-base font-semibold text-gray-900 truncate">{user?.full_name || '—'}</p>
                  <p className="text-sm text-gray-500 truncate">{user?.email}</p>
                </div>
                <div className="shrink-0 flex flex-col items-end gap-1.5">
                  <span className="px-3 py-1 rounded-full text-xs font-bold bg-indigo-100 text-indigo-700 uppercase tracking-wide">
                    {user?.role}
                  </span>
                  <span className="text-xs text-gray-400">
                    {user?.organization || 'SeceoKnight'}
                  </span>
                </div>
              </div>

              {/* Change Password */}
              <div className="card">
                <div className="flex items-center gap-3 mb-6 pb-5 border-b border-gray-100">
                  <div className="p-2.5 bg-purple-50 rounded-xl border border-purple-100">
                    <Lock className="h-5 w-5 text-purple-600" />
                  </div>
                  <div>
                    <h2 className="font-semibold text-gray-900">Change Password</h2>
                    <p className="text-xs text-gray-500 mt-0.5">Update your login credentials</p>
                  </div>
                </div>

                <form onSubmit={handleChangePassword}>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                    <div className="md:col-span-2">
                      <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Current Password</label>
                      <div className="relative">
                        <input type={showCurrent ? 'text' : 'password'} value={currentPassword}
                          onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Enter current password"
                          className="input pr-10" required />
                        <button type="button" onClick={() => setShowCurrent(!showCurrent)}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600">
                          {showCurrent ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">New Password</label>
                      <div className="relative">
                        <input type={showNew ? 'text' : 'password'} value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)} placeholder="Enter new password"
                          className="input pr-10" required />
                        <button type="button" onClick={() => setShowNew(!showNew)}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600">
                          {showNew ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Confirm New Password</label>
                      <div className="relative">
                        <input type={showConfirm ? 'text' : 'password'} value={confirmPassword}
                          onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Confirm new password"
                          className="input pr-10" required />
                        <button type="button" onClick={() => setShowConfirm(!showConfirm)}
                          className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600">
                          {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                  </div>
                  <p className="mt-3 text-xs text-gray-400">Min. 7 characters — must include uppercase, lowercase, digit and special character.</p>
                  <div className="mt-5 pt-4 border-t border-gray-100">
                    <button type="submit" disabled={changingPassword}
                      className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed px-6">
                      {changingPassword ? 'Updating...' : 'Update Password'}
                    </button>
                  </div>
                </form>
              </div>

              {isSuperAdmin && <IpAllowlistSection />}
            </div>
          )}

          {/* ── TWO-FACTOR AUTH ── */}
          {activeTab === 'mfa' && (
            <div className="card">
              <div className="flex items-center justify-between mb-6 pb-5 border-b border-gray-100">
                <div className="flex items-center gap-3">
                  <div className={`p-2.5 rounded-xl border ${mfaEnabled ? 'bg-green-50 border-green-100' : 'bg-gray-50 border-gray-200'}`}>
                    <ShieldCheck className={`h-5 w-5 ${mfaEnabled ? 'text-green-600' : 'text-gray-400'}`} />
                  </div>
                  <div>
                    <h2 className="font-semibold text-gray-900">Two-Factor Authentication</h2>
                    <p className="text-xs text-gray-500 mt-0.5">TOTP via Google Authenticator, Authy or 1Password</p>
                  </div>
                </div>
                <span className={`px-3 py-1 rounded-full text-xs font-bold tracking-wide ${
                  mfaEnabled ? 'bg-green-100 text-green-700' : 'bg-red-50 text-red-600 border border-red-100'
                }`}>
                  {mfaEnabled ? '● Enabled' : '○ Disabled'}
                </span>
              </div>

              {mfaStep === 'idle' && (
                <div className="space-y-5">
                  {mfaEnabled ? (
                    <div className="flex items-start gap-4 p-5 bg-green-50 border border-green-200 rounded-xl">
                      <CheckCircle2 className="h-6 w-6 text-green-600 mt-0.5 shrink-0" />
                      <div>
                        <p className="font-semibold text-green-800">Your account is protected</p>
                        <p className="text-sm text-green-700 mt-1 leading-relaxed">
                          MFA is active. Every login requires a TOTP code from your authenticator app in addition to your password.
                          Only your administrator can disable MFA — contact them if you lose access to your authenticator.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="flex items-start gap-4 p-5 bg-amber-50 border border-amber-200 rounded-xl">
                        <AlertCircle className="h-6 w-6 text-amber-600 mt-0.5 shrink-0" />
                        <div>
                          <p className="font-semibold text-amber-800">MFA is not enabled</p>
                          <p className="text-sm text-amber-700 mt-1 leading-relaxed">
                            Your account is currently protected by password only. Enable two-factor authentication to significantly increase your account security.
                          </p>
                        </div>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 py-2">
                        {[
                          { step: '1', title: 'Install an app', desc: 'Google Authenticator, Authy, or 1Password' },
                          { step: '2', title: 'Scan QR code', desc: 'Link the app to your account' },
                          { step: '3', title: 'Verify code', desc: 'Confirm with a one-time code' },
                        ].map((s) => (
                          <div key={s.step} className="flex gap-3 p-4 bg-gray-50 rounded-xl border border-gray-200">
                            <span className="h-7 w-7 rounded-full bg-blue-100 text-blue-700 font-bold text-sm flex items-center justify-center shrink-0">{s.step}</span>
                            <div>
                              <p className="text-sm font-semibold text-gray-900">{s.title}</p>
                              <p className="text-xs text-gray-500 mt-0.5">{s.desc}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                      <button onClick={handleMfaEnable} disabled={mfaLoading}
                        className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 px-6 py-2.5">
                        <ShieldCheck className="w-4 h-4" />
                        {mfaLoading ? 'Setting up...' : 'Enable Two-Factor Authentication'}
                      </button>
                    </>
                  )}
                </div>
              )}

              {mfaStep === 'setup_qr' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                  <div className="space-y-4">
                    <div>
                      <p className="font-semibold text-gray-900 mb-1">Step 1 — Scan the QR code</p>
                      <p className="text-sm text-gray-500">Open your authenticator app and scan the QR code to link it to your account.</p>
                    </div>
                    {mfaQrCode && (
                      <div className="inline-block p-4 bg-white border-2 border-gray-200 rounded-2xl shadow-sm">
                        <img src={`data:image/png;base64,${mfaQrCode}`} alt="MFA QR Code" className="w-52 h-52" />
                      </div>
                    )}
                    <div className="flex gap-3 pt-2">
                      <button onClick={() => { setMfaStep('setup_verify'); setMfaCode('') }} className="btn-primary px-5">
                        I've scanned it →
                      </button>
                      <button onClick={cancelMfa} className="btn-secondary">Cancel</button>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div>
                      <p className="font-semibold text-gray-900 mb-1">Can't scan?</p>
                      <p className="text-sm text-gray-500">Enter this key manually in your authenticator app.</p>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Secret Key</label>
                      <div className="flex items-center gap-2 p-3 bg-gray-50 border border-gray-200 rounded-xl">
                        <code className="flex-1 text-sm font-mono tracking-widest text-gray-800 break-all"
                          style={{ filter: showSecret ? 'none' : 'blur(4px)', userSelect: showSecret ? 'auto' : 'none' }}>
                          {mfaSecret}
                        </code>
                        <button type="button" onClick={() => setShowSecret(!showSecret)}
                          className="p-1.5 text-gray-400 hover:text-gray-600 shrink-0 rounded-lg hover:bg-gray-200 transition-colors">
                          {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                    <div className="p-4 bg-blue-50 border border-blue-100 rounded-xl text-xs text-blue-700 space-y-1">
                      <p className="font-semibold">Supported apps</p>
                      <p>Google Authenticator · Authy · Microsoft Authenticator · 1Password · Bitwarden</p>
                    </div>
                  </div>
                </div>
              )}

              {mfaStep === 'setup_verify' && (
                <div className="max-w-md space-y-5">
                  <div>
                    <p className="font-semibold text-gray-900 mb-1">Step 2 — Verify the code</p>
                    <p className="text-sm text-gray-500">Enter the 6-digit code currently shown in your authenticator app to confirm setup.</p>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Verification Code</label>
                    <input type="text" inputMode="numeric" maxLength={6}
                      value={mfaCode} onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                      autoFocus placeholder="000000"
                      className="input text-center text-3xl tracking-[0.6em] font-mono w-full" />
                  </div>
                  <div className="flex gap-3">
                    <button onClick={handleMfaVerifySetup} disabled={mfaLoading || mfaCode.length !== 6}
                      className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed px-6">
                      {mfaLoading ? 'Activating...' : 'Activate MFA'}
                    </button>
                    <button onClick={cancelMfa} className="btn-secondary">Back</button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── SYSTEM ── */}
          {activeTab === 'system' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="card">
                <div className="flex items-center gap-3 mb-6 pb-5 border-b border-gray-100">
                  <div className="p-2.5 bg-blue-50 rounded-xl border border-blue-100">
                    <Server className="h-5 w-5 text-blue-600" />
                  </div>
                  <div>
                    <h2 className="font-semibold text-gray-900">API Configuration</h2>
                    <p className="text-xs text-gray-500 mt-0.5">Manager endpoint settings</p>
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Manager API URL</label>
                    <div className="px-3 py-2.5 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-700 font-mono break-all">{API_URL}</div>
                    <p className="mt-1 text-xs text-gray-400">Backend API for this deployment</p>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Data Refresh Interval</label>
                    <select className="input">
                      <option>5 seconds</option>
                      <option>10 seconds</option>
                      <option>30 seconds</option>
                      <option>60 seconds</option>
                    </select>
                    <p className="mt-1 text-xs text-gray-400">Dashboard polling frequency for live data</p>
                  </div>
                </div>
              </div>

              <div className="card">
                <div className="flex items-center gap-3 mb-6 pb-5 border-b border-gray-100">
                  <div className="p-2.5 bg-green-50 rounded-xl border border-green-100">
                    <Database className="h-5 w-5 text-green-600" />
                  </div>
                  <div>
                    <h2 className="font-semibold text-gray-900">OpenSearch</h2>
                    <p className="text-xs text-gray-500 mt-0.5">Event storage and search engine</p>
                  </div>
                </div>
                <div className="space-y-4">
                  {[
                    { label: 'Host', value: defaultOpenSearchUrl },
                    { label: 'Index Prefix', value: 'seceoknight', hint: 'Pattern: seceoknight-events-YYYY.MM.DD' },
                    { label: 'Retention Period', value: '90 days', hint: 'Events older than 90 days are auto-purged' },
                  ].map((f) => (
                    <div key={f.label}>
                      <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">{f.label}</label>
                      <div className="px-3 py-2.5 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-700 font-mono">{f.value}</div>
                      {f.hint && <p className="mt-1 text-xs text-gray-400">{f.hint}</p>}
                    </div>
                  ))}
                </div>

                {/* Log retention — DB-backed, admin-editable, 90-day compliance floor */}
                {isSuperAdmin && (
                  <form onSubmit={handleSaveRetention} className="space-y-4 pt-4 mt-4 border-t border-gray-100">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-semibold text-gray-900">Log Retention</span>
                      {retention && (
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-gray-100 text-gray-500">
                          source: {retention.source}
                        </span>
                      )}
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Event log retention (days)</label>
                        <input type="number" min={retention?.minimum_days ?? 90} className="input"
                          value={retForm.event_retention_days}
                          onChange={(e) => setRetForm({ ...retForm, event_retention_days: Number(e.target.value) })} />
                      </div>
                      <div>
                        <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Index log retention (days)</label>
                        <input type="number" min={retention?.minimum_days ?? 90} className="input"
                          value={retForm.opensearch_retention_days}
                          onChange={(e) => setRetForm({ ...retForm, opensearch_retention_days: Number(e.target.value) })} />
                      </div>
                    </div>
                    <p className="text-xs text-gray-400">
                      Minimum {retention?.minimum_days ?? 90} days — enforced server-side. Applied daily by the cleanup task; logs newer than the window are always retained.
                    </p>
                    <button type="submit" disabled={savingRetention}
                      className="flex items-center gap-2 px-5 py-2 bg-blue-600 text-white text-sm font-semibold rounded-xl hover:bg-blue-700 disabled:opacity-60 transition-colors">
                      <Archive className="h-4 w-4" />{savingRetention ? 'Saving…' : 'Save retention'}
                    </button>
                  </form>
                )}
              </div>
            </div>
          )}

          {/* ── NOTIFICATIONS ── */}
          {activeTab === 'notifications' && (
            <div className="space-y-6">
              {emailSettingsLoading && (
                <div className="flex items-center gap-2 text-sm text-gray-500 py-4">
                  <div className="h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                  Loading settings…
                </div>
              )}

              {/* ── Enable toggle ── */}
              <div className="card">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 bg-yellow-50 rounded-xl border border-yellow-100">
                      <Bell className="h-5 w-5 text-yellow-600" />
                    </div>
                    <div>
                      <h2 className="font-semibold text-gray-900">Email Alerts</h2>
                      <p className="text-xs text-gray-500 mt-0.5">Send email when a policy violation is detected</p>
                    </div>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer shrink-0">
                    <input type="checkbox" className="sr-only peer"
                      checked={emailSettings.enabled}
                      onChange={e => setEmailSettings(s => ({ ...s, enabled: e.target.checked }))} />
                    <div className="w-10 h-5 bg-gray-200 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600" />
                  </label>
                </div>
              </div>

              {/* ── SMTP Configuration ── */}
              <div className="card">
                <div className="flex items-center gap-3 mb-6 pb-5 border-b border-gray-100">
                  <div className="p-2.5 bg-blue-50 rounded-xl border border-blue-100">
                    <Mail className="h-5 w-5 text-blue-600" />
                  </div>
                  <div>
                    <h2 className="font-semibold text-gray-900">SMTP Configuration</h2>
                    <p className="text-xs text-gray-500 mt-0.5">Outgoing mail server settings</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">SMTP Host</label>
                    <input type="text" value={emailSettings.smtp_host}
                      onChange={e => setEmailSettings(s => ({ ...s, smtp_host: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="smtp.gmail.com" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">SMTP Port</label>
                    <input type="number" value={emailSettings.smtp_port}
                      onChange={e => setEmailSettings(s => ({ ...s, smtp_port: parseInt(e.target.value) || 587 }))}
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="587" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">Username / Email</label>
                    <input type="text" value={emailSettings.smtp_user}
                      onChange={e => setEmailSettings(s => ({ ...s, smtp_user: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="alerts@yourcompany.com" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">Password / App Password</label>
                    <input type="password" value={emailSettings.smtp_password}
                      onChange={e => setEmailSettings(s => ({ ...s, smtp_password: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Leave blank to keep existing" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">From Name</label>
                    <input type="text" value={emailSettings.smtp_from_name}
                      onChange={e => setEmailSettings(s => ({ ...s, smtp_from_name: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="SeceoKnight DLP" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">From Email</label>
                    <input type="email" value={emailSettings.smtp_from_email}
                      onChange={e => setEmailSettings(s => ({ ...s, smtp_from_email: e.target.value }))}
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="noreply@yourcompany.com" />
                  </div>
                </div>

                <div className="flex items-center gap-3 mt-4">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input type="checkbox" checked={emailSettings.smtp_tls}
                      onChange={e => setEmailSettings(s => ({ ...s, smtp_tls: e.target.checked }))}
                      className="rounded" />
                    <span className="text-sm text-gray-700">Use STARTTLS</span>
                  </label>
                  <span className="text-xs text-gray-400">(recommended for port 587)</span>
                </div>
              </div>

              {/* ── Alert Recipients ── */}
              <div className="card">
                <div className="flex items-center gap-3 mb-6 pb-5 border-b border-gray-100">
                  <div className="p-2.5 bg-orange-50 rounded-xl border border-orange-100">
                    <AlertCircle className="h-5 w-5 text-orange-600" />
                  </div>
                  <div>
                    <h2 className="font-semibold text-gray-900">Alert Recipients</h2>
                    <p className="text-xs text-gray-500 mt-0.5">Who receives automatic violation alerts</p>
                  </div>
                </div>

                <div className="mb-4">
                  <label className="block text-xs font-medium text-gray-700 mb-1">Minimum Severity to Trigger Email</label>
                  <select value={emailSettings.min_severity}
                    onChange={e => setEmailSettings(s => ({ ...s, min_severity: e.target.value }))}
                    className="px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white">
                    <option value="critical">Critical only</option>
                    <option value="high">High and above</option>
                    <option value="medium">Medium and above</option>
                    <option value="low">All (Low and above)</option>
                  </select>
                </div>

                <div className="flex gap-2 mb-3">
                  <input type="email" value={newRecipient}
                    onChange={e => setNewRecipient(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addRecipient() }}}
                    className="flex-1 px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="admin@yourcompany.com" />
                  <button onClick={addRecipient}
                    className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors">
                    <Plus className="h-4 w-4" /> Add
                  </button>
                </div>

                {emailSettings.alert_recipients.length === 0 ? (
                  <p className="text-sm text-gray-400 py-3">No recipients added. Emails will not be sent.</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {emailSettings.alert_recipients.map(r => (
                      <span key={r} className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-50 border border-blue-200 text-blue-800 text-xs font-medium rounded-full">
                        {r}
                        <button onClick={() => removeRecipient(r)} className="text-blue-400 hover:text-blue-700">
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* ── Save + Test ── */}
              <div className="card">
                <div className="flex flex-col sm:flex-row gap-4">
                  <button onClick={handleSaveEmailSettings} disabled={emailSettingsSaving}
                    className="flex items-center justify-center gap-2 px-5 py-2.5 bg-blue-600 text-white text-sm font-semibold rounded-xl hover:bg-blue-700 disabled:opacity-60 transition-colors">
                    {emailSettingsSaving
                      ? <><div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> Saving…</>
                      : <><CheckCircle2 className="h-4 w-4" /> Save Settings</>}
                  </button>

                  <div className="flex gap-2 flex-1">
                    <input type="email" value={testEmailAddress}
                      onChange={e => setTestEmailAddress(e.target.value)}
                      className="flex-1 px-3 py-2 border border-gray-200 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Send test email to…" />
                    <button onClick={handleTestEmail} disabled={testEmailSending || !testEmailAddress}
                      className="flex items-center gap-1.5 px-4 py-2 bg-gray-700 text-white text-sm font-medium rounded-lg hover:bg-gray-800 disabled:opacity-50 transition-colors shrink-0">
                      {testEmailSending
                        ? <div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        : <Send className="h-4 w-4" />}
                      Test
                    </button>
                  </div>
                </div>
                <p className="text-xs text-gray-400 mt-3">
                  Save settings before sending a test. For Gmail, use an App Password (not your login password).
                </p>
              </div>
            </div>
          )}

          {/* ── INTEGRATIONS ── */}
          {activeTab === 'integrations' && (
            <div className="space-y-6">
              <div className="card">
                <div className="flex items-center gap-3 mb-6 pb-5 border-b border-gray-100">
                  <div className="p-2.5 bg-emerald-50 rounded-xl border border-emerald-100">
                    <Globe className="h-5 w-5 text-emerald-600" />
                  </div>
                  <div>
                    <h2 className="font-semibold text-gray-900">Cloud Storage Connectors</h2>
                    <p className="text-xs text-gray-500 mt-0.5">Connect cloud storage providers for DLP monitoring</p>
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {[
                    {
                      name: 'Google Drive',
                      desc: 'Monitor file access, sharing, and data exfiltration across Google Workspace',
                      icon: HardDrive,
                      color: 'bg-blue-50 border-blue-100',
                      iconColor: 'text-blue-600',
                      btnColor: 'bg-blue-600 hover:bg-blue-700',
                      loading: isConnectingDrive,
                      onClick: handleDriveConnect,
                    },
                    {
                      name: 'Microsoft OneDrive',
                      desc: 'Monitor SharePoint and OneDrive activity across Microsoft 365',
                      icon: Cloud,
                      color: 'bg-indigo-50 border-indigo-100',
                      iconColor: 'text-indigo-600',
                      btnColor: 'bg-indigo-600 hover:bg-indigo-700',
                      loading: isConnectingOneDrive,
                      onClick: handleOneDriveConnect,
                    },
                  ].map((conn) => {
                    const Icon = conn.icon
                    return (
                      <div key={conn.name} className="p-5 border border-gray-200 rounded-xl hover:border-gray-300 hover:shadow-sm transition-all">
                        <div className="flex items-start gap-4">
                          <div className={`p-3 rounded-xl border ${conn.color} shrink-0`}>
                            <Icon className={`h-6 w-6 ${conn.iconColor}`} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="font-semibold text-gray-900">{conn.name}</p>
                            <p className="text-xs text-gray-500 mt-1 leading-relaxed">{conn.desc}</p>
                            <div className="flex items-center gap-1.5 mt-2">
                              <WifiOff className="h-3 w-3 text-gray-400" />
                              <span className="text-xs text-gray-400">Not connected</span>
                            </div>
                          </div>
                        </div>
                        <button onClick={conn.onClick} disabled={conn.loading}
                          className={`mt-4 w-full py-2 rounded-lg text-sm font-semibold text-white transition-colors disabled:opacity-60 disabled:cursor-not-allowed ${conn.btnColor}`}>
                          {conn.loading ? 'Opening OAuth...' : 'Connect'}
                        </button>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          {/* ── ABOUT ── */}
          {activeTab === 'about' && (
            <div className="card">
              <div className="flex items-center gap-3 mb-6 pb-5 border-b border-gray-100">
                <div className="p-2.5 bg-gray-100 rounded-xl border border-gray-200">
                  <Info className="h-5 w-5 text-gray-600" />
                </div>
                <div>
                  <h2 className="font-semibold text-gray-900">About SeceoKnight DLP</h2>
                  <p className="text-xs text-gray-500 mt-0.5">Platform version and technology stack</p>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { label: 'Product', value: 'SeceoKnight DLP' },
                  { label: 'Version', value: '2.0.0' },
                  { label: 'Backend', value: 'FastAPI 0.109.0' },
                  { label: 'Database', value: 'PostgreSQL 15' },
                  { label: 'Search Engine', value: 'OpenSearch 2.11.0' },
                  { label: 'Cache', value: 'Redis 7' },
                  { label: 'License', value: 'Apache 2.0' },
                  { label: 'Support', value: 'support@seceoknight.com' },
                ].map((row) => (
                  <div key={row.label} className="flex items-center justify-between p-4 bg-gray-50 rounded-xl border border-gray-100">
                    <span className="text-sm text-gray-500">{row.label}</span>
                    <span className="text-sm font-semibold text-gray-900">{row.value}</span>
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
