'use client'

import { useState } from 'react'
import { GoogleDriveLocalConfig } from '@/types/policy'
import { predefinedPatterns, validateRegex, testRegex } from '@/utils/policyUtils'
import { Plus, Trash2, Folder, X, Check } from 'lucide-react'
import { useCustomDetectionRules, type DetectionPattern } from '@/hooks/useCustomDetectionRules'

interface GoogleDriveLocalPolicyFormProps {
  config: GoogleDriveLocalConfig
  onChange: (config: GoogleDriveLocalConfig) => void
}

const commonExtensions = ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.csv', '.pptx', '.ppt', '.txt', '.json', '.xml', '.sql', '.zip', '.rar', '.7z', '.db']

export default function GoogleDriveLocalPolicyForm({ config: rawConfig, onChange }: GoogleDriveLocalPolicyFormProps) {
  // Defensive: policies saved before content-pattern support existed (or
  // still on the default construction in PolicyCreatorModal.tsx, which
  // deliberately omits `patterns` the same way file_system_monitoring's
  // default does) have no "patterns" key at all -- normalize so the form
  // never crashes, same pattern FileSystemPolicyForm.tsx uses.
  const config: GoogleDriveLocalConfig = {
    ...rawConfig,
    patterns: {
      predefined: rawConfig?.patterns?.predefined ?? [],
      custom: rawConfig?.patterns?.custom ?? [],
    },
  }

  const [newFolder, setNewFolder] = useState('')
  const [newExtension, setNewExtension] = useState('')
  const [customRegex, setCustomRegex] = useState('')
  const [customDescription, setCustomDescription] = useState('')
  const [testText, setTestText] = useState('')
  const [testResult, setTestResult] = useState<boolean | null>(null)

  // Rules created in the Rules tab, shown as ordinary selectable tiles
  // alongside the built-in SSN/Credit Card/Phone Number/etc. patterns below
  // -- same as File System Monitoring's own pattern picker.
  const { rules: customRules } = useCustomDetectionRules()

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

  const handlePredefinedToggle = (patternId: string) => {
    const predefined = config.patterns!.predefined
    const newPredefined = predefined.includes(patternId)
      ? predefined.filter(p => p !== patternId)
      : [...predefined, patternId]

    onChange({
      ...config,
      patterns: { ...config.patterns!, predefined: newPredefined }
    })
  }

  const handleAddCustomPattern = () => {
    const validation = validateRegex(customRegex)
    if (!validation.valid) {
      alert(validation.error)
      return
    }

    onChange({
      ...config,
      patterns: {
        ...config.patterns!,
        custom: [...config.patterns!.custom, { regex: customRegex, description: customDescription || undefined }]
      }
    })

    setCustomRegex('')
    setCustomDescription('')
  }

  // Toggling a Rules-tab tile just adds/removes its derived pattern from
  // the same `patterns.custom` list a manually-typed regex would land in.
  const handleRuleToggle = (pattern: DetectionPattern) => {
    const isSelected = config.patterns!.custom.some((c) => c.regex === pattern.regex)
    const newCustom = isSelected
      ? config.patterns!.custom.filter((c) => c.regex !== pattern.regex)
      : [...config.patterns!.custom, pattern]

    onChange({
      ...config,
      patterns: { ...config.patterns!, custom: newCustom }
    })
  }

  const handleRemoveCustomPattern = (index: number) => {
    onChange({
      ...config,
      patterns: { ...config.patterns!, custom: config.patterns!.custom.filter((_, i) => i !== index) }
    })
  }

  const handleTestRegex = () => {
    if (!testText.trim()) {
      alert('Please enter sample text to test')
      return
    }
    const validation = validateRegex(customRegex)
    if (!validation.valid) {
      alert(validation.error)
      return
    }
    setTestResult(testRegex(customRegex, testText))
  }

  const regexValidation = customRegex ? validateRegex(customRegex) : null

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
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Google Drive Base Path
        </label>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={config.basePath}
            onChange={(e) => handleBasePathChange(e.target.value)}
            placeholder="G:\\My Drive\\"
            className="flex-1 px-4 py-2 bg-muted border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          />
          <span className="text-sm text-muted-foreground">(Default Windows Google Drive sync location)</span>
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          Default path is usually <code>G:\My Drive\</code>. Leave empty to monitor the entire drive if your path differs.
        </p>
      </div>

      {/* Monitored Folders */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Monitored Folders <span className="text-muted-foreground">(within Google Drive)</span>
        </label>
        <div className="space-y-2">
          {config.monitoredFolders.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {config.monitoredFolders.map((folder, index) => (
                <div
                  key={index}
                  className="flex items-center gap-2 px-3 py-1.5 bg-muted border border-border rounded-lg"
                >
                  <Folder className="w-4 h-4 text-muted-foreground" />
                  <span className="text-sm text-foreground/90">{folder}</span>
                  <button
                    onClick={() => handleRemoveFolder(index)}
                    className="text-muted-foreground hover:text-critical transition-colors"
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
              className="flex-1 px-4 py-2 bg-muted border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
            />
            <button
              onClick={handleAddFolder}
              className="px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Folder
            </button>
          </div>
          <p className="text-xs text-muted-foreground">
            Specify folders within Google Drive to monitor. Leave empty to monitor entire drive.
          </p>
        </div>
      </div>

      {/* File Extensions */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          File Extensions <span className="text-muted-foreground">(optional)</span>
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
                      ? 'bg-primary text-white'
                      : 'bg-muted text-muted-foreground hover:bg-secondary border border-border'
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
                    className="flex items-center gap-2 px-3 py-1.5 bg-muted border border-border rounded-lg"
                  >
                    <span className="text-sm text-foreground/90">{ext}</span>
                    <button
                      onClick={() => handleRemoveExtension(ext)}
                      className="text-muted-foreground hover:text-critical transition-colors"
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
              className="flex-1 px-4 py-2 bg-muted border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
            />
            <button
              onClick={handleAddCustomExtension}
              className="px-4 py-2 bg-secondary hover:bg-secondary/70 text-foreground rounded-lg transition-colors"
            >
              Add Custom
            </button>
          </div>
        </div>
      </div>

      {/* Content Detection Patterns */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Detection Patterns (Optional)
        </label>
        <p className="text-xs text-muted-foreground mb-3">
          Checks file contents (including OCR&apos;d text from images/screenshots) against these patterns
          before deciding an action -- the same content classification engine File System Monitoring
          uses. Leave empty to alert/quarantine/block on any matching file regardless of content
          (pure path/extension monitoring).
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
          {predefinedPatterns.map((pattern) => {
            const isSelected = config.patterns!.predefined.includes(pattern.id)
            return (
              <button
                key={pattern.id}
                onClick={() => handlePredefinedToggle(pattern.id)}
                className={`p-3 rounded-lg border-2 text-left transition-all ${
                  isSelected
                    ? 'border-primary bg-primary/10 text-white'
                    : 'border-border bg-muted/30 text-muted-foreground hover:border-primary/40'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium text-sm">{pattern.name}</div>
                    <div className="text-xs mt-1 opacity-70 font-mono">{pattern.example}</div>
                  </div>
                  {isSelected && <Check className="w-5 h-5 text-primary" />}
                </div>
              </button>
            )
          })}

          {/* Rules created in the Rules tab -- rendered as the exact same
              kind of tile as the built-in patterns above. */}
          {customRules.map(({ rule, pattern }) => {
            const isSelected = config.patterns!.custom.some((c) => c.regex === pattern.regex)
            const preview = rule.type === 'keyword' ? (rule.keywords || []).join(', ') : pattern.regex

            return (
              <button
                key={`rule-${rule.id}`}
                onClick={() => handleRuleToggle(pattern)}
                className={`p-3 rounded-lg border-2 text-left transition-all ${
                  isSelected
                    ? 'border-primary bg-primary/10 text-white'
                    : 'border-border bg-muted/30 text-muted-foreground hover:border-primary/40'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="min-w-0">
                    <div className="font-medium text-sm truncate">{rule.name}</div>
                    <div className="text-xs mt-1 opacity-70 font-mono truncate">{preview}</div>
                  </div>
                  {isSelected && <Check className="w-5 h-5 text-primary" />}
                </div>
              </button>
            )
          })}
        </div>

        {/* Custom Patterns */}
        {config.patterns!.custom.length > 0 && (
          <div className="space-y-2 mb-4">
            {config.patterns!.custom.map((custom, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-3 bg-muted/30 rounded-lg border border-border"
              >
                <div className="flex-1">
                  <code className="text-sm text-primary">{custom.regex}</code>
                  {custom.description && (
                    <p className="text-xs text-muted-foreground mt-1">{custom.description}</p>
                  )}
                </div>
                <button
                  onClick={() => handleRemoveCustomPattern(index)}
                  className="ml-3 p-1 text-muted-foreground hover:text-critical transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}

        <div className="space-y-3 p-4 bg-muted/30 rounded-lg border border-border">
          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-2">
              Custom Regex Pattern
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={customRegex}
                onChange={(e) => setCustomRegex(e.target.value)}
                placeholder="e.g., \\d{4}-\\d{4}-\\d{4}"
                className="flex-1 px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
              />
              {regexValidation && (
                <div className={`flex items-center px-2 ${regexValidation.valid ? 'text-success' : 'text-critical'}`}>
                  {regexValidation.valid ? <Check className="w-5 h-5" /> : <X className="w-5 h-5" />}
                </div>
              )}
            </div>
            {regexValidation && !regexValidation.valid && (
              <p className="text-xs text-critical mt-1">{regexValidation.error}</p>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-2">
              Description (Optional)
            </label>
            <input
              type="text"
              value={customDescription}
              onChange={(e) => setCustomDescription(e.target.value)}
              placeholder="e.g., Study Report Detection"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all text-sm"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-2">
              Test Pattern
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={testText}
                onChange={(e) => setTestText(e.target.value)}
                placeholder="Enter sample text to test"
                className="flex-1 px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all text-sm"
              />
              <button
                onClick={handleTestRegex}
                disabled={!customRegex.trim() || !testText.trim()}
                className="px-4 py-2 bg-primary hover:bg-primary/90 disabled:bg-secondary disabled:text-muted-foreground text-white rounded-lg transition-colors text-sm font-medium"
              >
                Test
              </button>
            </div>
            {testResult !== null && (
              <p className={`text-xs mt-2 ${testResult ? 'text-success' : 'text-critical'}`}>
                {testResult ? '✓ Pattern matches!' : '✗ Pattern does not match'}
              </p>
            )}
          </div>

          <button
            onClick={handleAddCustomPattern}
            disabled={!customRegex.trim() || (regexValidation !== null && !regexValidation.valid)}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 disabled:bg-secondary disabled:text-muted-foreground text-white rounded-lg transition-colors text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            Add Custom Pattern
          </button>
        </div>
      </div>

      {/* Event Types */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Event Types to Monitor
        </label>
        <div className="space-y-2">
          {(['create', 'modify', 'delete', 'move'] as const).map((event) => (
            <label key={event} className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.events[event]}
                onChange={() => handleToggleEvent(event)}
                className="h-4 w-4 text-primary focus:ring-primary border-border rounded bg-muted/30"
              />
              <span className="text-sm text-foreground/90 capitalize">{event}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Action */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Action
        </label>
        <select
          value={config.action}
          onChange={(e) => {
            const action = e.target.value as GoogleDriveLocalConfig['action']
            onChange({
              ...config,
              action,
              // Clear a stale quarantine path when switching away from
              // Quarantine -- same "don't leave dead config behind" pattern
              // FileSystemPolicyForm.tsx uses on its own action selector.
              quarantinePath: action === 'quarantine' ? config.quarantinePath : undefined,
            })
          }}
          className="w-full px-4 py-2 bg-muted border border-border rounded-lg text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
        >
          <option value="log">Log Only</option>
          <option value="alert">Alert</option>
          <option value="quarantine">Quarantine</option>
          <option value="block">Block</option>
        </select>
        {config.action === 'quarantine' && (
          <div className="mt-3">
            <label className="block text-xs font-medium text-muted-foreground mb-1.5">
              Quarantine Folder Path
            </label>
            <input
              type="text"
              value={config.quarantinePath || ''}
              onChange={(e) => onChange({ ...config, quarantinePath: e.target.value })}
              placeholder="e.g., C:\\ProgramData\\SeceoKnight\\quarantine"
              className="w-full px-4 py-2 bg-muted border border-border rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm"
            />
            <p className="mt-1.5 text-xs text-muted-foreground">
              Matched files are moved here instead of being deleted outright. Defaults to the agent's standard quarantine folder if left blank.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
