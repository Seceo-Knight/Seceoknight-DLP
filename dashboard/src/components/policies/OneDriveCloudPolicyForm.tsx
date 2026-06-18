import React, { useState, useEffect } from 'react'
import { OneDriveCloudConfig } from '@/types/policy'
import {
  getOneDriveConnections,
  getOneDriveProtectedFolders,
  initiateOneDriveConnection,
  updateOneDriveBaseline,
  type OneDriveProtectedFolderStatus,
} from '@/lib/api'
import { Loader2, Plus, Cloud, RefreshCcw, Check } from 'lucide-react'
import ProtectedFolderSelector from '../onedrive/ProtectedFolderSelector'
import { toast } from 'react-hot-toast'
import { formatDate } from '@/lib/utils'

interface OneDriveCloudPolicyFormProps {
  config: OneDriveCloudConfig
  onChange: (config: OneDriveCloudConfig) => void
}

interface Connection {
  id: string
  connection_name: string
  microsoft_user_email: string
  status: string
  monitoring_since?: string | null
}

const POLLING_PRESETS = [5, 10, 15, 30, 60]

export default function OneDriveCloudPolicyForm({
  config,
  onChange,
}: OneDriveCloudPolicyFormProps) {
  const [connections, setConnections] = useState<Connection[]>([])
  const [loading, setLoading] = useState(true)
  const [connecting, setConnecting] = useState(false)
  const [customPolling, setCustomPolling] = useState(false)
  const [folderStatuses, setFolderStatuses] = useState<Record<string, OneDriveProtectedFolderStatus>>({})
  const [baselineLoading, setBaselineLoading] = useState(false)
  const [resettingBaseline, setResettingBaseline] = useState(false)
  const selectedFolders = config.protectedFolders || []
  const activeConnection = connections.find((conn) => conn.id === config.connectionId)
  const monitoringSince = activeConnection?.monitoring_since
  const selectedFolderBaselines = selectedFolders.map((folder) => {
    const status = folderStatuses[folder.id]
    return {
      ...folder,
      baseline: status?.last_seen_timestamp || null,
    }
  })

  useEffect(() => {
    loadConnections()
  }, [])

  useEffect(() => {
    if (config.connectionId) {
      loadFolderStatuses(config.connectionId)
    } else {
      setFolderStatuses({})
    }
  }, [config.connectionId])

  const loadConnections = async () => {
    try {
      setLoading(true)
      const data = await getOneDriveConnections()
      setConnections(data)
      // Auto-select first connection if none selected
      if (!config.connectionId && data.length > 0) {
        updateConfig('connectionId', data[0].id)
      }
    } catch (error) {
      console.error('Failed to load connections', error)
      toast.error('Failed to load OneDrive connections')
    } finally {
      setLoading(false)
    }
  }

  const loadFolderStatuses = async (connectionId: string) => {
    try {
      setBaselineLoading(true)
      const data: OneDriveProtectedFolderStatus[] = await getOneDriveProtectedFolders(connectionId)
      const map: Record<string, OneDriveProtectedFolderStatus> = {}
      data.forEach((folder) => {
        map[folder.folder_id] = folder
      })
      setFolderStatuses(map)
    } catch (error) {
      console.error('Failed to load folder baselines', error)
      toast.error('Failed to load folder baselines')
    } finally {
      setBaselineLoading(false)
    }
  }

  const handleConnect = async () => {
    try {
      setConnecting(true)
      const { auth_url } = await initiateOneDriveConnection()
      window.open(auth_url, '_blank', 'width=600,height=700')
      toast.success('Please complete authentication in the popup window')
    } catch (error) {
      console.error(error)
      toast.error('Failed to initiate connection')
    } finally {
      setConnecting(false)
    }
  }

  const handleResetBaseline = async (scope: 'connection' | 'selected') => {
    if (!config.connectionId) return
    if (scope === 'selected' && (!config.protectedFolders || config.protectedFolders.length === 0)) {
      toast.error('Select at least one folder to reset')
      return
    }

    try {
      setResettingBaseline(true)
      const payload =
        scope === 'selected'
          ? { folderIds: config.protectedFolders?.map((folder) => folder.id) }
          : undefined
      await updateOneDriveBaseline(config.connectionId, payload)
      toast.success('Baseline updated')
      await loadFolderStatuses(config.connectionId)
      await loadConnections()
    } catch (error) {
      console.error('Failed to reset baseline', error)
      toast.error('Failed to reset baseline')
    } finally {
      setResettingBaseline(false)
    }
  }

  const updateConfig = (key: keyof OneDriveCloudConfig, value: any) => {
    // IMPORTANT: Spread the existing config first to avoid losing other fields
    onChange({ ...config, [key]: value })
  }

  // Handle folder selection specifically to ensure it updates correctly
  const handleFoldersChange = (folders: Array<{ id: string; name: string; path?: string }>) => {
    // Create a new config object explicitly
    const newConfig = {
      ...config,
      protectedFolders: folders
    }
    onChange(newConfig)
  }

  return (
    <div className="space-y-6">
      {/* Connection Selection */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <label className="block text-sm font-medium text-gray-200">
            OneDrive Account
          </label>
          <button
            onClick={loadConnections}
            className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors"
          >
            <RefreshCcw className="h-3 w-3" />
            Refresh List
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center p-8 bg-gray-900/30 rounded-lg border border-dashed border-gray-700">
            <Loader2 className="h-5 w-5 animate-spin text-gray-500" />
          </div>
        ) : connections.length === 0 ? (
          <div className="text-center p-8 bg-gray-900/30 rounded-lg border border-dashed border-gray-700 space-y-3">
            <div className="inline-flex p-3 rounded-full bg-gray-800 text-gray-400">
              <Cloud className="h-6 w-6" />
            </div>
            <div>
              <p className="font-medium text-gray-300">No accounts connected</p>
              <p className="text-sm text-gray-500">Connect a OneDrive account to start monitoring</p>
            </div>
            <button
              onClick={handleConnect}
              disabled={connecting}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-lg shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-60 transition-colors"
            >
              {connecting ? (
                <>
                  <Loader2 className="animate-spin -ml-1 mr-2 h-4 w-4" />
                  Connecting...
                </>
              ) : (
                <>
                  <Plus className="-ml-1 mr-2 h-4 w-4" />
                  Connect Account
                </>
              )}
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {connections.map((conn) => (
              <div
                key={conn.id}
                onClick={() => updateConfig('connectionId', conn.id)}
                className={`
                  relative rounded-lg border p-4 cursor-pointer flex items-center space-x-3 transition-all
                  ${config.connectionId === conn.id 
                    ? 'ring-2 ring-indigo-500 border-indigo-500 bg-indigo-900/20' 
                    : 'border-gray-700 bg-gray-800 hover:border-gray-600 hover:bg-gray-700'}
                `}
              >
                <div className="flex-shrink-0">
                  <div className={`h-10 w-10 rounded-full flex items-center justify-center font-bold text-lg ${
                    config.connectionId === conn.id
                      ? 'bg-indigo-600 text-white'
                      : 'bg-gray-700 text-gray-400'
                  }`}>
                    {conn.connection_name?.[0] || conn.microsoft_user_email?.[0] || 'O'}
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium truncate ${
                    config.connectionId === conn.id ? 'text-white' : 'text-gray-300'
                  }`}>
                    {conn.connection_name || 'OneDrive'}
                  </p>
                  <p className="text-sm text-gray-500 truncate">
                    {conn.microsoft_user_email}
                  </p>
                  {conn.monitoring_since && (
                    <p className="text-xs text-gray-500 truncate">
                      Monitoring since {formatDate(conn.monitoring_since)}
                    </p>
                  )}
                </div>
                {config.connectionId === conn.id && (
                  <div className="flex-shrink-0 text-indigo-500">
                    <Check className="h-5 w-5" />
                  </div>
                )}
              </div>
            ))}
            
            {/* Add Another Account Button */}
            <button
              onClick={handleConnect}
              disabled={connecting}
              className="relative rounded-lg border border-dashed border-gray-600 p-4 flex items-center justify-center space-x-2 hover:border-gray-500 hover:bg-gray-800 transition-all text-gray-400 hover:text-gray-300"
            >
              <Plus className="h-5 w-5" />
              <span className="text-sm font-medium">Add Another</span>
            </button>
          </div>
        )}
      </div>

      {/* Protected Folders Selection */}
      {config.connectionId && (
        <div className="space-y-3">
          <label className="block text-sm font-medium text-gray-200">
            Protected Folders
          </label>
          <p className="text-sm text-gray-400">
            Select the folders you want to monitor for activity.
          </p>
          
          <ProtectedFolderSelector
            connectionId={config.connectionId}
            selectedFolders={config.protectedFolders || []} // Ensure array
            onChange={handleFoldersChange}
          />

          <div className="mt-4 rounded-lg border border-gray-700 bg-gray-900/40 p-4 space-y-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-sm text-gray-300">
                  Monitoring since{' '}
                  <span className="font-medium text-white">
                    {monitoringSince ? formatDate(monitoringSince) : 'Not initialized yet'}
                  </span>
                </p>
                <p className="text-xs text-gray-500">
                  Only OneDrive activity after this timestamp will appear in the dashboard.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => handleResetBaseline('selected')}
                  disabled={resettingBaseline || selectedFolders.length === 0}
                  className="px-3 py-1.5 text-xs rounded-md border border-indigo-500/50 text-indigo-300 hover:bg-indigo-900/30 disabled:opacity-50 transition-colors"
                >
                  {resettingBaseline ? 'Updating...' : 'Reset Selected Baseline'}
                </button>
                <button
                  onClick={() => handleResetBaseline('connection')}
                  disabled={resettingBaseline}
                  className="px-3 py-1.5 text-xs rounded-md border border-gray-600 text-gray-200 hover:bg-gray-800 disabled:opacity-50 transition-colors"
                >
                  {resettingBaseline ? 'Updating...' : 'Reset Connection Baseline'}
                </button>
              </div>
            </div>

            <div className="border border-gray-800 rounded-md overflow-hidden">
              <div className="bg-gray-800/60 px-3 py-2 text-xs text-gray-400 flex items-center justify-between">
                <span>Selected Folders</span>
                {baselineLoading && (
                  <span className="flex items-center gap-1 text-indigo-300">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    Refreshing...
                  </span>
                )}
              </div>
              {selectedFolderBaselines.length === 0 ? (
                <div className="p-4 text-xs text-gray-500">No folders selected yet.</div>
              ) : (
                <div className="divide-y divide-gray-800 text-xs">
                  {selectedFolderBaselines.map((folder) => (
                    <div key={folder.id} className="flex flex-col sm:flex-row sm:items-center sm:justify-between px-3 py-2">
                      <div className="text-gray-300 font-medium truncate">{folder.name}</div>
                      <div className="text-gray-500 mt-1 sm:mt-0">
                        {folder.baseline ? formatDate(folder.baseline) : 'Pending baseline'}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Polling Interval */}
      <div className="space-y-3">
        <label className="block text-sm font-medium text-gray-200">
          Polling Interval
        </label>
        <div className="flex flex-wrap gap-2">
          {POLLING_PRESETS.map((interval) => (
            <button
              key={interval}
              onClick={() => {
                setCustomPolling(false)
                updateConfig('pollingInterval', interval)
              }}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all border ${
                !customPolling && config.pollingInterval === interval
                  ? 'bg-indigo-600 border-indigo-600 text-white'
                  : 'bg-gray-800 border-gray-700 text-gray-300 hover:bg-gray-700'
              }`}
            >
              {interval} min
            </button>
          ))}
          <button
            onClick={() => setCustomPolling(true)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all border ${
              customPolling
                ? 'bg-indigo-600 border-indigo-600 text-white'
                : 'bg-gray-800 border-gray-700 text-gray-300 hover:bg-gray-700'
            }`}
          >
            Custom
          </button>
        </div>
        
        {customPolling && (
          <div className="mt-3 flex items-center gap-3">
            <input
              type="number"
              min="1"
              max="1440"
              value={config.pollingInterval}
              onChange={(e) => updateConfig('pollingInterval', Math.max(1, parseInt(e.target.value) || 1))}
              className="w-24 px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
            />
            <span className="text-sm text-gray-400">minutes</span>
          </div>
        )}
        
        <p className="text-xs text-gray-500 mt-1">
          How frequently the system checks OneDrive for new activity.
        </p>
      </div>

      {/* Action (Read-only for now) */}
      <div className="rounded-lg bg-indigo-900/30 border border-indigo-500/30 p-4">
        <div className="flex">
          <div className="flex-shrink-0">
            <Cloud className="h-5 w-5 text-indigo-400" aria-hidden="true" />
          </div>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-indigo-300">Log-Only Mode</h3>
            <div className="mt-2 text-sm text-indigo-200/80">
              <p>
                Cloud monitoring currently supports logging activities only. Blocking capabilities require endpoint agent integration.
              </p>
              <p className="mt-2 text-xs text-indigo-300/70">
                Note: File downloads cannot be detected without a Microsoft 365 subscription.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}


