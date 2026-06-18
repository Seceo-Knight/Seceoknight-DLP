'use client'

import { useState } from 'react'
import { FileSystemConfig } from '@/types/policy'
import { Plus, Trash2, X } from 'lucide-react'

interface FileSystemPolicyFormProps {
  config: FileSystemConfig
  onChange: (config: FileSystemConfig) => void
}

const commonExtensions = ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.csv', '.pptx', '.ppt', '.txt', '.json', '.xml', '.sql', '.zip', '.rar', '.7z', '.db']

export default function FileSystemPolicyForm({ config, onChange }: FileSystemPolicyFormProps) {
  const [newPath, setNewPath] = useState('')
  const [newExtension, setNewExtension] = useState('')

  const handleAddPath = () => {
    if (!newPath.trim()) {
      alert('Please enter a path')
      return
    }

    if (config.monitoredPaths.includes(newPath.trim())) {
      alert('Path already added')
      return
    }

    onChange({
      ...config,
      monitoredPaths: [...config.monitoredPaths, newPath.trim()]
    })

    setNewPath('')
  }

  const handleRemovePath = (index: number) => {
    onChange({
      ...config,
      monitoredPaths: config.monitoredPaths.filter((_, i) => i !== index)
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

  const handleToggleEvent = (event: keyof FileSystemConfig['events']) => {
    onChange({
      ...config,
      events: {
        ...config.events,
        [event]: !config.events[event]
      }
    })
  }

  return (
    <div className="space-y-6">
      {/* Monitored Directories */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Monitored Directories *
        </label>
        
        {/* Existing Paths */}
        {config.monitoredPaths.length > 0 && (
          <div className="space-y-2 mb-3">
            {config.monitoredPaths.map((path, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-3 bg-gray-900/50 rounded-lg border border-gray-700"
              >
                <code className="text-sm text-indigo-300 flex-1">{path}</code>
                <button
                  onClick={() => handleRemovePath(index)}
                  className="ml-3 p-1 text-gray-400 hover:text-red-400 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Add Path */}
        <div className="flex gap-2">
          <input
            type="text"
            value={newPath}
            onChange={(e) => setNewPath(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleAddPath()}
            placeholder="e.g., C:\\Users\\%USERNAME%\\Documents or /home/$USER/Documents"
            className="flex-1 px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-gray-500 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
          />
          <button
            onClick={handleAddPath}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add
          </button>
        </div>
        <p className="text-xs text-gray-400 mt-2">
          Supports environment variables: %USERNAME%, $USER, etc.
        </p>
      </div>

      {/* File Extensions */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          File Extensions (Optional)
        </label>
        <p className="text-xs text-gray-400 mb-3">
          Leave empty to monitor all file types
        </p>

        {/* Common Extensions */}
        <div className="flex flex-wrap gap-2 mb-3">
          {commonExtensions.map((ext) => {
            const isSelected = config.fileExtensions?.includes(ext) || false
            
            return (
              <button
                key={ext}
                onClick={() => handleToggleExtension(ext)}
                className={`px-3 py-1 rounded-lg border-2 text-sm font-mono transition-all ${
                  isSelected
                    ? 'border-indigo-500 bg-indigo-900/30 text-white'
                    : 'border-gray-600 bg-gray-900/30 text-gray-400 hover:border-gray-500'
                }`}
              >
                {ext}
              </button>
            )
          })}
        </div>

        {/* Selected Extensions */}
        {config.fileExtensions && config.fileExtensions.length > 0 && (
          <div className="mb-3">
            <div className="text-xs text-gray-400 mb-2">Selected Extensions:</div>
            <div className="flex flex-wrap gap-2">
              {config.fileExtensions.map((ext) => (
                <div
                  key={ext}
                  className="flex items-center gap-2 px-3 py-1 bg-indigo-900/30 border border-indigo-500/50 rounded-lg text-sm"
                >
                  <code className="text-indigo-300">{ext}</code>
                  <button
                    onClick={() => handleRemoveExtension(ext)}
                    className="text-gray-400 hover:text-red-400 transition-colors"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Custom Extension Input */}
        <div className="flex gap-2">
          <input
            type="text"
            value={newExtension}
            onChange={(e) => setNewExtension(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleAddCustomExtension()}
            placeholder="e.g., .custom or custom"
            className="flex-1 px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-gray-500 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
          />
          <button
            onClick={handleAddCustomExtension}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add
          </button>
        </div>
      </div>

      {/* Events to Monitor */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Events to Monitor *
        </label>
        <div className="space-y-2">
          {Object.entries(config.events).map(([event, enabled]) => (
            <label
              key={event}
              className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all"
            >
              <input
                type="checkbox"
                checked={enabled}
                onChange={() => handleToggleEvent(event as keyof FileSystemConfig['events'])}
                className="w-4 h-4 text-indigo-600 rounded"
              />
              <div>
                <div className="text-white font-medium text-sm capitalize">
                  File {event}
                </div>
                <div className="text-gray-400 text-xs">{`Monitor file ${event} operations`}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      {/* Action Selection */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Action When Event Detected
        </label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="filesystem-action"
              value="alert"
              checked={config.action === 'alert'}
              onChange={() => onChange({ ...config, action: 'alert', quarantinePath: undefined })}
              className="w-4 h-4 text-indigo-600"
            />
            <div>
              <div className="text-white font-medium text-sm">Alert</div>
              <div className="text-gray-400 text-xs">Send alert notification</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="filesystem-action"
              value="log"
              checked={config.action === 'log'}
              onChange={() => onChange({ ...config, action: 'log', quarantinePath: undefined })}
              className="w-4 h-4 text-indigo-600"
            />
            <div>
              <div className="text-white font-medium text-sm">Log Only</div>
              <div className="text-gray-400 text-xs">Record events without blocking</div>
            </div>
          </label>
        </div>
      </div>
    </div>
  )
}
