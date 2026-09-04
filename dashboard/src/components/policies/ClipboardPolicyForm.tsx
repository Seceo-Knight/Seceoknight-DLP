'use client'

import { useState } from 'react'
import { ClipboardConfig } from '@/types/policy'
import { predefinedPatterns, validateRegex, testRegex } from '@/utils/policyUtils'
import { Check, X, Plus, Trash2 } from 'lucide-react'

interface ClipboardPolicyFormProps {
  config: ClipboardConfig
  onChange: (config: ClipboardConfig) => void
}

export default function ClipboardPolicyForm({ config: rawConfig, onChange }: ClipboardPolicyFormProps) {
  // Defensive: some clipboard policies were saved with a different
  // config shape (monitoredEvents/contentTypes/dataTypes instead of
  // patterns.predefined/custom). Normalize so the form never crashes
  // on missing nested properties.
  const config: ClipboardConfig = {
    ...rawConfig,
    patterns: {
      predefined: rawConfig?.patterns?.predefined ?? [],
      custom: rawConfig?.patterns?.custom ?? [],
    },
    action: rawConfig?.action ?? 'alert',
  }

  const [customRegex, setCustomRegex] = useState('')
  const [customDescription, setCustomDescription] = useState('')
  const [testText, setTestText] = useState('')
  const [testResult, setTestResult] = useState<boolean | null>(null)

  const handlePredefinedToggle = (patternId: string) => {
    const newPredefined = config.patterns.predefined.includes(patternId)
      ? config.patterns.predefined.filter(p => p !== patternId)
      : [...config.patterns.predefined, patternId]
    
    onChange({
      ...config,
      patterns: {
        ...config.patterns,
        predefined: newPredefined
      }
    })
  }

  const handleAddCustomPattern = () => {
    const validation = validateRegex(customRegex)
    if (!validation.valid) {
      alert(validation.error)
      return
    }

    const newCustom = [
      ...config.patterns.custom,
      { regex: customRegex, description: customDescription || undefined }
    ]

    onChange({
      ...config,
      patterns: {
        ...config.patterns,
        custom: newCustom
      }
    })

    setCustomRegex('')
    setCustomDescription('')
  }

  const handleRemoveCustomPattern = (index: number) => {
    const newCustom = config.patterns.custom.filter((_, i) => i !== index)
    onChange({
      ...config,
      patterns: {
        ...config.patterns,
        custom: newCustom
      }
    })
  }

  const handleTestRegex = () => {
    if (!customRegex.trim()) {
      alert('Please enter a regex pattern to test')
      return
    }

    const validation = validateRegex(customRegex)
    if (!validation.valid) {
      alert(validation.error)
      return
    }

    const result = testRegex(customRegex, testText)
    setTestResult(result)
  }

  const regexValidation = customRegex ? validateRegex(customRegex) : null

  return (
    <div className="space-y-6">
      {/* Predefined Patterns */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Detection Patterns
        </label>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {predefinedPatterns.map((pattern) => {
            const isSelected = config.patterns.predefined.includes(pattern.id)

            return (
              <button
                key={pattern.id}
                onClick={() => handlePredefinedToggle(pattern.id)}
                className={`p-3 rounded-lg border-2 text-left transition-all ${
                  isSelected
                    ? 'border-primary bg-primary/10 text-foreground'
                    : 'border-border bg-card text-muted-foreground hover:border-primary/40 hover:bg-accent'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium text-sm">{pattern.name}</div>
                    <div className="text-xs mt-1 opacity-80 font-mono">{pattern.example}</div>
                  </div>
                  {isSelected && <Check className="w-5 h-5 text-primary shrink-0" />}
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Custom Patterns */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Custom Regex Patterns
        </label>

        {/* Existing Custom Patterns */}
        {config.patterns.custom.length > 0 && (
          <div className="space-y-2 mb-4">
            {config.patterns.custom.map((custom, index) => (
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

        {/* Add Custom Pattern */}
        <div className="space-y-3 p-4 bg-muted/30 rounded-lg border border-border">
          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-2">
              Regex Pattern
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={customRegex}
                onChange={(e) => setCustomRegex(e.target.value)}
                placeholder="e.g., \\d{4}-\\d{4}-\\d{4}"
                className="input flex-1 font-mono text-sm"
              />
              {regexValidation && (
                <div className={`flex items-center px-2 ${
                  regexValidation.valid ? 'text-success' : 'text-critical'
                }`}>
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
              placeholder="e.g., Custom ID Pattern"
              className="input text-sm"
            />
          </div>

          {/* Test Regex */}
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
                className="input flex-1 text-sm"
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
              <p className={`text-xs mt-2 ${
                testResult ? 'text-success' : 'text-critical'
              }`}>
                {testResult ? '✓ Pattern matches!' : '✗ Pattern does not match'}
              </p>
            )}
          </div>

          <button
            onClick={handleAddCustomPattern}
            disabled={!customRegex.trim() || (regexValidation && !regexValidation.valid)}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 disabled:bg-secondary disabled:text-muted-foreground text-white rounded-lg transition-colors text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            Add Custom Pattern
          </button>
        </div>
      </div>

      {/* Action Selection */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Action When Pattern Detected
        </label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-card cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="clipboard-action"
              value="alert"
              checked={config.action === 'alert'}
              onChange={() => onChange({ ...config, action: 'alert' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Alert</div>
              <div className="text-muted-foreground text-xs">Send alert notification when pattern is detected</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-card cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="clipboard-action"
              value="log"
              checked={config.action === 'log'}
              onChange={() => onChange({ ...config, action: 'log' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Log Only</div>
              <div className="text-muted-foreground text-xs">Log the event without sending alerts</div>
            </div>
          </label>
        </div>
      </div>
    </div>
  )
}

