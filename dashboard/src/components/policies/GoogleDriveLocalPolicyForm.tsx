'use client'

import { useState } from 'react'
import { GoogleDriveLocalConfig } from '@/types/policy'
import { Plus, Trash2, Folder } from 'lucide-react'

interface GoogleDriveLocalPolicyFormProps {
  config: GoogleDriveLocalConfig
  onChange: (config: GoogleDriveLocalConfig) => void
}

const commonExtensions = ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.csv', '.pptx', '.ppt', '.txt', '.json', '.xml', '.sql', '.zip', '.rar', '.7z', '.db']

export default function GoogleDriveLocalPolicyForm({ config, onChange }: GoogleDriveLocalPolicyFormProps) {
  const [newFolder, setNewFolder] = useState('')
  const [newExtension, setNewExtension] = useState('')

  const handleAddFolder = () => {
    if (!newFolder.trim()) {
      alert('Please enter a folder path')
      return
    }

    // Normalize folder path (remove leading/trailing slashes)
    const normalizedFolder = newFolder.trim().replace(/^[\\/]+|[\\/]+$/g, '').replace(/\//g, '\\')
    
    if (config.monitoredFolders.includes(normalizedFolder)) {
      alert('Folder already added')
      return
    }

    onChange({
      ...config,
      monitoredFolders: [...config.monitoredFolders, normalizedFolder]
    })

    setNewFolder('')
  }

  const handleRemoveFolder = (index: number) => {
    onChange({
      ...config,
      monitoredFolders: config.monitoredFolders.filter((_, i) => i !== index)
    })
  }

  const handleToggleExtension = (ext: string) => {
    const currentExtensions = config.fileExtensions || []
    const newExtensions = currentExtensions.includes(ext)
      ? currentExtensions.filter(e => e !== ext)
      : [...currentExtensions, ext]

    onChange({
      ...config,
      fileExtensions: newExtensions.length > 0 ? newExtensions : undefined
    })
  }

  const handleAddCustomExtension = () => {
    if (!newExtension.trim()) {
      alert('Please enter a file extension')
      return
    }

    const ext = newExtension.startsWith('.') ? newExtension : `.${newExtension}`
    const currentExtensions = config.fileExtensions || []

    if (currentExtensions.includes(ext)) {
      alert('Extension already added')
      return
    }

    onChange({
      ...config,
      fileExtensions: [...currentExtensions, ext]
    })

    setNewExtension('')
  }

  const handleRemoveExtension = (ext: string) => {
    const currentExtensions = config.fileExtensions || []
    onChange({
      ...config,
      fileExtensions: currentExtensions.filter(e => e !== ext)
    })
  }

  const handleToggleEvent = (event: keyof GoogleDriveLocalConfig['events']) => {
    onChange({
      ...config,
      events: {
        ...config.events,
        [event]: !config.events[event]
      }
    })
  }

  const handleBasePathChange = (newBasePath: string) => {
    onChange({
      ...config,
      basePath: newBasePath
    })
  }

  return (
    <div className="space-y-6">
      {/* Base Path */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Google Drive Base Path
        </label>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={config.basePath}
            onChange={(e) => handleBasePathChange(e.target.value)}
            placeholder="G:\\My Drive\\"
            className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <span className="text-sm text-gray-400">(Default Windows Google Drive sync location)</span>
        </div>
        <p className="mt-2 text-xs text-gray-400">
          Default path is usually <code>G:\My Drive\</code>. Leave empty to monitor the entire drive if your path differs.
        </p>
      </div>

      {/* Monitored Folders */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Monitored Folders <span className="text-gray-400">(within Google Drive)</span>
        </label>
        <div className="space-y-2">
          {config.monitoredFolders.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {config.monitoredFolders.map((folder, index) => (
                <div
                  key={index}
                  className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg"
                >
                  <Folder className="w-4 h-4 text-gray-400" />
                  <span className="text-sm text-gray-200">{folder}</span>
                  <button
                    onClick={() => handleRemoveFolder(index)}
                    className="text-gray-400 hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          )}
          <div className="flex gap-2">
            <input
              type="text"
              value={newFolder}
              onChange={(e) => setNewFolder(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleAddFolder()}
              placeholder="Folder1 or Folder1/Subfolder"
              className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            <button
              onClick={handleAddFolder}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Folder
            </button>
          </div>
          <p className="text-xs text-gray-400">
            Specify folders within Google Drive to monitor. Leave empty to monitor entire drive.
          </p>
        </div>
      </div>

      {/* File Extensions */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          File Extensions <span className="text-gray-400">(optional)</span>
        </label>
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            {commonExtensions.map((ext) => {
              const isSelected = config.fileExtensions?.includes(ext) || false
              return (
                <button
                  key={ext}
                  onClick={() => handleToggleExtension(ext)}
                  className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                    isSelected
                      ? 'bg-indigo-600 text-white'
                      : 'bg-gray-800 text-gray-300 hover:bg-gray-700 border border-gray-700'
                  }`}
                >
                  {ext}
                </button>
              )
            })}
          </div>
          {config.fileExtensions && config.fileExtensions.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {config.fileExtensions
                .filter((ext) => !commonExtensions.includes(ext))
                .map((ext) => (
                  <div
                    key={ext}
                    className="flex items-center gap-2 px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg"
                  >
                    <span className="text-sm text-gray-200">{ext}</span>
                    <button
                      onClick={() => handleRemoveExtension(ext)}
                      className="text-gray-400 hover:text-red-400 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
            </div>
          )}
          <div className="flex gap-2">
            <input
              type="text"
              value={newExtension}
              onChange={(e) => setNewExtension(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleAddCustomExtension()}
              placeholder=".custom"
              className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            <button
              onClick={handleAddCustomExtension}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
            >
              Add Custom
            </button>
          </div>
        </div>
      </div>

      {/* Event Types */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Event Types to Monitor
        </label>
        <div className="space-y-2">
          {(['create', 'modify', 'delete', 'move'] as const).map((event) => (
            <label key={event} className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.events[event]}
                onChange={() => handleToggleEvent(event)}
                className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-600 rounded bg-gray-900/50"
              />
              <span className="text-sm text-gray-200 capitalize">{event}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Action */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Action
        </label>
        <select
          value={config.action}
          onChange={(e) => onChange({ ...config, action: e.target.value as GoogleDriveLocalConfig['action'] })}
          className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="log">Log Only</option>
          <option value="alert">Alert</option>
          <option value="block">Block</option>
        </select>
      </div>
    </div>
  )
}
