'use client'
import { extractErrorDetail } from '@/utils/errorUtils'

import { useState } from 'react'
import DashboardLayout from '@/components/layout/DashboardLayout'
import { Settings as SettingsIcon, Bell, Shield, Database, Globe } from 'lucide-react'
import toast from 'react-hot-toast'
import { initiateGoogleDriveConnection, initiateOneDriveConnection } from '@/lib/api'

export default function SettingsPage() {
  const [isConnectingDrive, setIsConnectingDrive] = useState(false)
  const [isConnectingOneDrive, setIsConnectingOneDrive] = useState(false)

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
                <input type="text" value="CyberSentinel Corp" className="w-full mt-2 px-4 py-2 bg-gray-900/50 border border-gray-600 rounded-lg text-white" />
              </div>
              <div>
                <label className="text-sm text-gray-400">Server IP Address</label>
                <input type="text" value="10.220.143.130" className="w-full mt-2 px-4 py-2 bg-gray-900/50 border border-gray-600 rounded-lg text-white font-mono" />
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

          {/* Security */}
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 p-6">
            <div className="flex items-center gap-3 mb-6">
              <div className="p-2 bg-red-900/30 border border-red-500/50 rounded-lg">
                <Shield className="w-6 h-6 text-red-400" />
              </div>
              <h2 className="text-xl font-semibold text-white">Security</h2>
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white font-medium">Enable 2FA</p>
                  <p className="text-sm text-gray-400">Two-factor authentication for admins</p>
                </div>
                <input type="checkbox" className="w-12 h-6" />
              </div>
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
                    Planned feature to move sensitive files to a secure quarantine location
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
