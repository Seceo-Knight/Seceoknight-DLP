'use client'

import { useState } from 'react'
import { FileIdentityDenylistConfig } from '@/types/policy'
import { Plus, Trash2, X } from 'lucide-react'

interface FileIdentityDenylistPolicyFormProps {
  config: FileIdentityDenylistConfig
  onChange: (config: FileIdentityDenylistConfig) => void
}

// Common "known-bad" categories admins reach for first when denylisting by
// extension -- executables/scripts, not content-classification categories
// (that's what file_system_monitoring's content patterns are for).
const commonExtensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.msi', '.dll', '.jar', '.sh']

// A SHA-256 hex digest is always exactly 64 hex characters -- catches the
// most common mistake (pasting an MD5, or a truncated/garbled hash) before
// it silently becomes a rule that can never match anything.
const isValidSha256 = (h: string) => /^[a-f0-9]{64}$/i.test(h.trim())

export default function FileIdentityDenylistPolicyForm({ config: rawConfig, onChange }: FileIdentityDenylistPolicyFormProps) {
  const config: FileIdentityDenylistConfig = {
    extensions: rawConfig?.extensions ?? [],
    hashes: rawConfig?.hashes ?? [],
    action: rawConfig?.action ?? 'block',
    quarantinePath: rawConfig?.quarantinePath,
  }

  const [newExtension, setNewExtension] = useState('')
  const [newHash, setNewHash] = useState('')
  const [hashError, setHashError] = useState<string | null>(null)

  const handleToggleExtension = (ext: string) => {
    const current = config.extensions || []
    const next = current.includes(ext) ? current.filter((e) => e !== ext) : [...current, ext]
    onChange({ ...config, extensions: next })
  }

  const handleAddCustomExtension = () => {
    if (!newExtension.trim()) {
      alert('Please enter a file extension')
      return
    }
    const ext = (newExtension.startsWith('.') ? newExtension : `.${newExtension}`).toLowerCase()
    const current = config.extensions || []
    if (current.includes(ext)) {
      alert('Extension already added')
      return
    }
    onChange({ ...config, extensions: [...current, ext] })
    setNewExtension('')
  }

  const handleRemoveExtension = (ext: string) => {
    onChange({ ...config, extensions: (config.extensions || []).filter((e) => e !== ext) })
  }

  const handleAddHash = () => {
    const hash = newHash.trim().toLowerCase()
    if (!hash) {
      setHashError('Please enter a hash')
      return
    }
    if (!isValidSha256(hash)) {
      setHashError('Expected a 64-character SHA-256 hex hash (e.g. from an Events row\'s File Hash field)')
      return
    }
    const current = config.hashes || []
    if (current.includes(hash)) {
      setHashError('Hash already added')
      return
    }
    onChange({ ...config, hashes: [...current, hash] })
    setNewHash('')
    setHashError(null)
  }

  const handleRemoveHash = (hash: string) => {
    onChange({ ...config, hashes: (config.hashes || []).filter((h) => h !== hash) })
  }

  return (
    <div className="space-y-6">
      <div className="p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg text-sm text-amber-200/90">
        Blocks files by <strong>what they are</strong> -- extension or exact-content hash -- independent of
        DLP content classification. Matches against file system, file transfer, USB transfer, and print events.
        At least one extension or hash is required.
      </div>

      {/* Extensions */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Denied Extensions
        </label>

        <div className="flex flex-wrap gap-2 mb-3">
          {commonExtensions.map((ext) => {
            const isSelected = config.extensions?.includes(ext) || false
            return (
              <button
                key={ext}
                onClick={() => handleToggleExtension(ext)}
                className={`px-3 py-1 rounded-lg border-2 text-sm font-mono transition-all ${
                  isSelected
                    ? 'border-red-500 bg-red-900/30 text-white'
                    : 'border-gray-600 bg-gray-900/30 text-muted-foreground/70 hover:border-gray-500'
                }`}
              >
                {ext}
              </button>
            )
          })}
        </div>

        {config.extensions && config.extensions.length > 0 && (
          <div className="mb-3">
            <div className="text-xs text-muted-foreground/70 mb-2">Denied:</div>
            <div className="flex flex-wrap gap-2">
              {config.extensions.map((ext) => (
                <div
                  key={ext}
                  className="flex items-center gap-2 px-3 py-1 bg-red-900/30 border border-red-500/50 rounded-lg text-sm"
                >
                  <code className="text-red-300">{ext}</code>
                  <button
                    onClick={() => handleRemoveExtension(ext)}
                    className="text-muted-foreground/70 hover:text-red-400 transition-colors"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="flex gap-2">
          <input
            type="text"
            value={newExtension}
            onChange={(e) => setNewExtension(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleAddCustomExtension()}
            placeholder="e.g., .custom or custom"
            className="flex-1 px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-muted-foreground focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
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

      {/* Hashes */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Denied File Hashes (SHA-256)
        </label>
        <p className="text-xs text-muted-foreground/70 mb-3">
          Exact-content match -- blocks this file no matter what it&apos;s named or where it&apos;s encountered.
          Copy a hash from an Events row&apos;s File Hash field.
        </p>

        {config.hashes && config.hashes.length > 0 && (
          <div className="space-y-2 mb-3">
            {config.hashes.map((hash) => (
              <div
                key={hash}
                className="flex items-center justify-between p-3 bg-gray-900/50 rounded-lg border border-gray-700"
              >
                <code className="text-sm text-red-300 flex-1 break-all">{hash}</code>
                <button
                  onClick={() => handleRemoveHash(hash)}
                  className="ml-3 p-1 text-muted-foreground/70 hover:text-red-400 transition-colors"
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
            value={newHash}
            onChange={(e) => {
              setNewHash(e.target.value)
              setHashError(null)
            }}
            onKeyPress={(e) => e.key === 'Enter' && handleAddHash()}
            placeholder="64-character SHA-256 hex hash"
            className="flex-1 px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-muted-foreground focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
          />
          <button
            onClick={handleAddHash}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add
          </button>
        </div>
        {hashError && <p className="text-xs text-red-400 mt-2">{hashError}</p>}
      </div>

      {/* Action Selection */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Action When a Denied File Is Encountered
        </label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="file-identity-denylist-action"
              value="block"
              checked={config.action === 'block'}
              onChange={() => onChange({ ...config, action: 'block', quarantinePath: undefined })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Block</div>
              <div className="text-muted-foreground/70 text-xs">Delete/cancel the file or job immediately</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="file-identity-denylist-action"
              value="quarantine"
              checked={config.action === 'quarantine'}
              onChange={() => onChange({ ...config, action: 'quarantine' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div className="flex-1">
              <div className="text-white font-medium text-sm">Quarantine</div>
              <div className="text-muted-foreground/70 text-xs">Move the file to a quarantine folder instead of deleting it</div>
            </div>
          </label>

          {config.action === 'quarantine' && (
            <div className="ml-7">
              <input
                type="text"
                value={config.quarantinePath || ''}
                onChange={(e) => onChange({ ...config, quarantinePath: e.target.value })}
                placeholder="e.g., C:\\ProgramData\\SeceoKnight\\quarantine"
                className="w-full px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-muted-foreground focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
              />
            </div>
          )}

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="file-identity-denylist-action"
              value="alert"
              checked={config.action === 'alert'}
              onChange={() => onChange({ ...config, action: 'alert', quarantinePath: undefined })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Alert</div>
              <div className="text-muted-foreground/70 text-xs">Send alert notification, don&apos;t touch the file</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="file-identity-denylist-action"
              value="log"
              checked={config.action === 'log'}
              onChange={() => onChange({ ...config, action: 'log', quarantinePath: undefined })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Log Only</div>
              <div className="text-muted-foreground/70 text-xs">Record matches without blocking</div>
            </div>
          </label>
        </div>
      </div>
    </div>
  )
}
