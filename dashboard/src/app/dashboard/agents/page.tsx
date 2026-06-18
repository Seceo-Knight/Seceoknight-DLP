'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import DashboardLayout from '@/components/layout/DashboardLayout'
import { Monitor, Circle, Download, Plus, X, Copy, Check, Activity, AlertCircle, CheckCircle, Loader2 } from 'lucide-react'
import toast from 'react-hot-toast'
import { getAgents, getAgentsStats } from '@/lib/api'
import { formatDateTimeIST } from '@/lib/utils'

export default function AgentsPage() {
  const [showDeployModal, setShowDeployModal] = useState(false)
  const [deployConfig, setDeployConfig] = useState({
    os: 'windows',
    name: '',
    serverIp: '10.220.143.130'
  })
  const [generatedScript, setGeneratedScript] = useState('')
  const [copied, setCopied] = useState(false)

  // Fetch agents from API
  const { data: agents = [], isLoading, refetch } = useQuery({
    queryKey: ['agents'],
    queryFn: () => getAgents(),
    refetchInterval: 5000, // Refresh every 5 seconds
  })

  // Fetch agent stats
  const { data: agentStats, refetch: refetchStats } = useQuery({
    queryKey: ['agent-stats'],
    queryFn: () => getAgentsStats(),
    refetchInterval: 5000,
  })

  const stats = {
    total: agentStats?.total || 0,
    online: agentStats?.online || 0,
    offline: agentStats?.offline || 0,
    warning: agentStats?.warning || 0,
  }

  const generateDeployScript = () => {
    const { os, name, serverIp } = deployConfig

    if (!name.trim()) {
      toast.error('Please enter an agent name')
      return
    }

    let script = ''

    if (os === 'windows') {
      script = `# CyberSentinel DLP Agent - Windows Installer
# Run this script as Administrator

$AgentName = "${name}"
$ServerIP = "${serverIp}"
$DownloadURL = "http://${serverIp}:8000/api/v1/agents/download/windows"

Write-Host "Installing CyberSentinel DLP Agent..." -ForegroundColor Green
Write-Host "Agent Name: $AgentName"
Write-Host "Server: $ServerIP"

# Download installer
Invoke-WebRequest -Uri $DownloadURL -OutFile "C:\\Temp\\dlp-agent-setup.exe"

# Install agent
Start-Process -FilePath "C:\\Temp\\dlp-agent-setup.exe" -ArgumentList "/S","/NAME=$AgentName","/SERVER=$ServerIP" -Wait

Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "Agent will start automatically and connect to $ServerIP"`
    } else {
      script = `#!/bin/bash
# CyberSentinel DLP Agent - Linux Installer
# Run this script with sudo

AGENT_NAME="${name}"
SERVER_IP="${serverIp}"
DOWNLOAD_URL="http://${serverIp}:8000/api/v1/agents/download/linux"

echo "Installing CyberSentinel DLP Agent..."
echo "Agent Name: $AGENT_NAME"
echo "Server: $SERVER_IP"

# Download installer
curl -o /tmp/dlp-agent-installer.sh "$DOWNLOAD_URL"

# Make executable
chmod +x /tmp/dlp-agent-installer.sh

# Install agent
sudo /tmp/dlp-agent-installer.sh --name="$AGENT_NAME" --server="$SERVER_IP"

echo "Installation complete!"
echo "Agent will start automatically and connect to $SERVER_IP"`
    }

    setGeneratedScript(script)
    toast.success('Installation script generated!')
  }

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedScript)
    setCopied(true)
    toast.success('Script copied to clipboard!')
    setTimeout(() => setCopied(false), 2000)
  }

  const downloadScript = () => {
    const filename = deployConfig.os === 'windows' ? 'install-agent.ps1' : 'install-agent.sh'
    const blob = new Blob([generatedScript], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
    toast.success(`Script downloaded as ${filename}`)
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'text-green-400 bg-green-900/30 border-green-500/50'
      case 'offline': return 'text-red-400 bg-red-900/30 border-red-500/50'
      case 'warning': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/50'
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500/50'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online': return <CheckCircle className="w-4 h-4" />
      case 'offline': return <AlertCircle className="w-4 h-4" />
      case 'warning': return <Activity className="w-4 h-4" />
      default: return <Circle className="w-4 h-4" />
    }
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-3xl font-bold text-white">Endpoint Agents</h1>
            <p className="text-gray-400 mt-2">Manage and monitor DLP agents deployed across your organization</p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                refetch()
                refetchStats()
              }}
              className="flex items-center gap-2 px-4 py-2 rounded-xl border border-gray-600 text-gray-200 hover:border-indigo-500 hover:text-white transition-colors"
            >
              <Activity className="w-4 h-4" />
              Refresh
            </button>
            <button
              onClick={() => setShowDeployModal(true)}
              className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white px-6 py-3 rounded-xl hover:from-indigo-700 hover:to-purple-700 shadow-lg hover:shadow-xl transition-all"
            >
              <Plus className="w-5 h-5" />
              Deploy Agent
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Agents</p>
                <p className="text-3xl font-bold text-white mt-2">{stats.total}</p>
              </div>
              <Monitor className="w-12 h-12 text-indigo-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Online</p>
                <p className="text-3xl font-bold text-green-400 mt-2">{stats.online}</p>
              </div>
              <CheckCircle className="w-12 h-12 text-green-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Offline</p>
                <p className="text-3xl font-bold text-red-400 mt-2">{stats.offline}</p>
              </div>
              <AlertCircle className="w-12 h-12 text-red-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Warnings</p>
                <p className="text-3xl font-bold text-yellow-400 mt-2">{stats.warning}</p>
              </div>
              <Activity className="w-12 h-12 text-yellow-400" />
            </div>
          </div>
        </div>

        {/* Agents List */}
        <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 overflow-hidden">
          <div className="p-6 border-b border-gray-700">
            <h2 className="text-xl font-semibold text-white">Deployed Agents</h2>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center p-12">
              <Loader2 className="w-8 h-8 text-indigo-400 animate-spin" />
            </div>
          ) : agents.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-12 text-center">
              <Monitor className="w-16 h-16 text-gray-600 mb-4" />
              <h3 className="text-lg font-semibold text-white mb-2">No Agents Found</h3>
              <p className="text-gray-400 mb-6">Deploy your first agent to start monitoring endpoints</p>
              <button
                onClick={() => setShowDeployModal(true)}
                className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white px-6 py-3 rounded-xl hover:from-indigo-700 hover:to-purple-700 transition-all"
              >
                <Plus className="w-5 h-5" />
                Deploy First Agent
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-900/50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Agent Name</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Operating System</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">IP Address</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Last Seen</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Version</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {agents.map((agent: any) => (
                    <tr key={agent.agent_id} className="hover:bg-gray-700/30 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-500 rounded-lg flex items-center justify-center">
                            <Monitor className="w-5 h-5 text-white" />
                          </div>
                          <span className="text-white font-medium">{agent.name}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-300">{agent.os}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-gray-300 font-mono text-sm">{agent.ip_address}</span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-lg border text-xs font-medium uppercase ${getStatusColor(agent.status)}`}>
                          {getStatusIcon(agent.status)}
                          {agent.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-300 text-sm">
                        {agent.last_seen ? formatDateTimeIST(agent.last_seen) : 'Never'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-gray-400 font-mono text-xs">{agent.version}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Deploy Agent Modal */}
        {showDeployModal && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={() => setShowDeployModal(false)}>
            <div className="bg-gray-800 rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto border border-gray-700" onClick={(e) => e.stopPropagation()}>
              {/* Modal Header */}
              <div className="flex items-center justify-between p-6 border-b border-gray-700 sticky top-0 bg-gray-800 z-10">
                <div>
                  <h3 className="text-2xl font-bold text-white">Deploy Agent</h3>
                  <p className="text-gray-400 mt-1">Generate installation script for endpoint deployment</p>
                </div>
                <button onClick={() => setShowDeployModal(false)} className="text-gray-400 hover:text-white transition-colors">
                  <X className="w-6 h-6" />
                </button>
              </div>

              {/* Modal Content */}
              <div className="p-6 space-y-6">
                {/* OS Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-200 mb-3">Operating System</label>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      onClick={() => setDeployConfig({ ...deployConfig, os: 'windows' })}
                      className={`p-4 rounded-xl border-2 transition-all ${
                        deployConfig.os === 'windows'
                          ? 'border-indigo-500 bg-indigo-900/30 text-white'
                          : 'border-gray-600 bg-gray-900/30 text-gray-400 hover:border-gray-500'
                      }`}
                    >
                      <div className="text-center">
                        <Monitor className="w-8 h-8 mx-auto mb-2" />
                        <div className="font-semibold">Windows</div>
                        <div className="text-xs opacity-70">PowerShell Script (.ps1)</div>
                      </div>
                    </button>
                    <button
                      onClick={() => setDeployConfig({ ...deployConfig, os: 'linux' })}
                      className={`p-4 rounded-xl border-2 transition-all ${
                        deployConfig.os === 'linux'
                          ? 'border-indigo-500 bg-indigo-900/30 text-white'
                          : 'border-gray-600 bg-gray-900/30 text-gray-400 hover:border-gray-500'
                      }`}
                    >
                      <div className="text-center">
                        <Monitor className="w-8 h-8 mx-auto mb-2" />
                        <div className="font-semibold">Linux</div>
                        <div className="text-xs opacity-70">Bash Script (.sh)</div>
                      </div>
                    </button>
                  </div>
                </div>

                {/* Agent Name */}
                <div>
                  <label className="block text-sm font-medium text-gray-200 mb-2">Agent Name</label>
                  <input
                    type="text"
                    value={deployConfig.name}
                    onChange={(e) => setDeployConfig({ ...deployConfig, name: e.target.value })}
                    placeholder="e.g., WIN-DESK-01, UBUNTU-SRV-02"
                    className="w-full px-4 py-3 bg-gray-900/50 border-2 border-gray-600 rounded-xl text-white placeholder-gray-400 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-500/20 transition-all"
                  />
                </div>

                {/* Server IP */}
                <div>
                  <label className="block text-sm font-medium text-gray-200 mb-2">Server IP Address</label>
                  <input
                    type="text"
                    value={deployConfig.serverIp}
                    onChange={(e) => setDeployConfig({ ...deployConfig, serverIp: e.target.value })}
                    className="w-full px-4 py-3 bg-gray-900/50 border-2 border-gray-600 rounded-xl text-white font-mono focus:border-indigo-500 focus:ring-4 focus:ring-indigo-500/20 transition-all"
                  />
                </div>

                {/* Generate Button */}
                <button
                  onClick={generateDeployScript}
                  className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold py-3 rounded-xl hover:from-indigo-700 hover:to-purple-700 transition-all"
                >
                  Generate Script
                </button>

                {/* Generated Script */}
                {generatedScript && (
                  <div className="bg-gray-900 rounded-xl p-4 border border-gray-700">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-sm font-medium text-gray-300">Installation Script</span>
                      <div className="flex gap-2">
                        <button
                          onClick={copyToClipboard}
                          className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-white rounded-lg transition-colors text-sm"
                        >
                          {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                          {copied ? 'Copied!' : 'Copy'}
                        </button>
                        <button
                          onClick={downloadScript}
                          className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-white rounded-lg transition-colors text-sm"
                        >
                          <Download className="w-4 h-4" />
                          Download
                        </button>
                      </div>
                    </div>
                    <pre className="bg-black/50 p-4 rounded-lg overflow-x-auto text-xs text-gray-300 font-mono max-h-64">
                      {generatedScript}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  )
}
