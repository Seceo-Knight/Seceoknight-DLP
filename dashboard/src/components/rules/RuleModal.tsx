import { useState, useEffect } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useMutation } from '@tanstack/react-query'
import { X, Plus, Trash2 } from 'lucide-react'
import { createRule, updateRule, type Rule, type RuleCreate } from '@/lib/rules-api'
import toast from 'react-hot-toast'

interface RuleModalProps {
  rule: Rule | null
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
}

export default function RuleModal({ rule, isOpen, onClose, onSuccess }: RuleModalProps) {
  const isEdit = !!rule

  const [formData, setFormData] = useState<RuleCreate>({
    name: '',
    description: '',
    type: 'regex',
    pattern: '',
    regex_flags: [],
    keywords: [],
    case_sensitive: false,
    dictionary_path: '',
    threshold: 1,
    weight: 0.5,
    classification_labels: [],
    severity: 'medium',
    category: '',
    tags: [],
    enabled: true,
  })

  const [keywordInput, setKeywordInput] = useState('')
  const [labelInput, setLabelInput] = useState('')
  const [tagInput, setTagInput] = useState('')

  useEffect(() => {
    if (rule) {
      setFormData({
        name: rule.name,
        description: rule.description || '',
        type: rule.type,
        pattern: rule.pattern || '',
        regex_flags: rule.regex_flags || [],
        keywords: rule.keywords || [],
        case_sensitive: rule.case_sensitive || false,
        dictionary_path: rule.dictionary_path || '',
        threshold: rule.threshold,
        weight: rule.weight,
        classification_labels: rule.classification_labels || [],
        severity: rule.severity || 'medium',
        category: rule.category || '',
        tags: rule.tags || [],
        enabled: rule.enabled,
      })
    } else {
      // Reset form for new rule
      setFormData({
        name: '',
        description: '',
        type: 'regex',
        pattern: '',
        regex_flags: [],
        keywords: [],
        case_sensitive: false,
        dictionary_path: '',
        threshold: 1,
        weight: 0.5,
        classification_labels: [],
        severity: 'medium',
        category: '',
        tags: [],
        enabled: true,
      })
    }
  }, [rule, isOpen])

  const createMutation = useMutation({
    mutationFn: createRule,
    onSuccess: () => {
      toast.success('Rule created successfully')
      onSuccess()
      onClose()
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to create rule'))
    },
  })

  const updateMutation = useMutation({
    mutationFn: (data: { id: string; updates: Partial<RuleCreate> }) =>
      updateRule(data.id, data.updates),
    onSuccess: () => {
      toast.success('Rule updated successfully')
      onSuccess()
      onClose()
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to update rule'))
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    // Validation
    if (!formData.name.trim()) {
      toast.error('Rule name is required')
      return
    }

    if (formData.type === 'regex' && !formData.pattern) {
      toast.error('Pattern is required for regex rules')
      return
    }

    if (formData.type === 'keyword' && (!formData.keywords || formData.keywords.length === 0)) {
      toast.error('At least one keyword is required for keyword rules')
      return
    }

    if (formData.type === 'dictionary' && !formData.dictionary_path) {
      toast.error('Dictionary path is required for dictionary rules')
      return
    }

    if (isEdit && rule) {
      updateMutation.mutate({ id: rule.id, updates: formData })
    } else {
      createMutation.mutate(formData)
    }
  }

  const addKeyword = () => {
    if (keywordInput.trim() && !formData.keywords?.includes(keywordInput.trim())) {
      setFormData({
        ...formData,
        keywords: [...(formData.keywords || []), keywordInput.trim()],
      })
      setKeywordInput('')
    }
  }

  const removeKeyword = (keyword: string) => {
    setFormData({
      ...formData,
      keywords: formData.keywords?.filter((k) => k !== keyword) || [],
    })
  }

  const addLabel = () => {
    if (labelInput.trim() && !formData.classification_labels?.includes(labelInput.trim())) {
      setFormData({
        ...formData,
        classification_labels: [...(formData.classification_labels || []), labelInput.trim()],
      })
      setLabelInput('')
    }
  }

  const removeLabel = (label: string) => {
    setFormData({
      ...formData,
      classification_labels: formData.classification_labels?.filter((l) => l !== label) || [],
    })
  }

  const addTag = () => {
    if (tagInput.trim() && !formData.tags?.includes(tagInput.trim())) {
      setFormData({
        ...formData,
        tags: [...(formData.tags || []), tagInput.trim()],
      })
      setTagInput('')
    }
  }

  const removeTag = (tag: string) => {
    setFormData({
      ...formData,
      tags: formData.tags?.filter((t) => t !== tag) || [],
    })
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-6 z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
        <form onSubmit={handleSubmit}>
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-200">
            <h3 className="text-2xl font-bold text-gray-900">
              {isEdit ? 'Edit Rule' : 'Create Rule'}
            </h3>
            <button
              type="button"
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
            >
              <X className="w-6 h-6" />
            </button>
          </div>

          {/* Content */}
          <div className="p-6 space-y-6">
            {/* Basic Info */}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Rule Name *
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="input w-full"
                  placeholder="e.g., Credit Card Number Detection"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Description
                </label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="input w-full"
                  rows={2}
                  placeholder="Describe what this rule detects..."
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Rule Type *
                  </label>
                  <select
                    value={formData.type}
                    onChange={(e) =>
                      setFormData({ ...formData, type: e.target.value as any })
                    }
                    className="input w-full"
                  >
                    <option value="regex">Regex</option>
                    <option value="keyword">Keyword</option>
                    <option value="dictionary">Dictionary</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Category
                  </label>
                  <input
                    type="text"
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                    className="input w-full"
                    placeholder="e.g., PII, Financial"
                  />
                </div>
              </div>
            </div>

            {/* Type-specific fields */}
            {formData.type === 'regex' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Regex Pattern *
                  </label>
                  <input
                    type="text"
                    value={formData.pattern}
                    onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
                    className="input w-full font-mono text-sm"
                    placeholder="e.g., \b\d{3}-\d{2}-\d{4}\b"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Use standard regex syntax. Backslashes will be properly escaped.
                  </p>
                </div>
              </div>
            )}

            {formData.type === 'keyword' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Keywords *
                  </label>
                  <div className="flex gap-2 mb-2">
                    <input
                      type="text"
                      value={keywordInput}
                      onChange={(e) => setKeywordInput(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addKeyword())}
                      className="input flex-1"
                      placeholder="Enter keyword and press Enter"
                    />
                    <button
                      type="button"
                      onClick={addKeyword}
                      className="btn-secondary"
                    >
                      <Plus className="h-4 w-4" />
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {formData.keywords?.map((keyword) => (
                      <span
                        key={keyword}
                        className="inline-flex items-center gap-1 px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm"
                      >
                        {keyword}
                        <button
                          type="button"
                          onClick={() => removeKeyword(keyword)}
                          className="hover:text-blue-900"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex items-center">
                  <input
                    type="checkbox"
                    id="case-sensitive"
                    checked={formData.case_sensitive}
                    onChange={(e) =>
                      setFormData({ ...formData, case_sensitive: e.target.checked })
                    }
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <label htmlFor="case-sensitive" className="ml-2 text-sm text-gray-700">
                    Case sensitive matching
                  </label>
                </div>
              </div>
            )}

            {formData.type === 'dictionary' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Dictionary Path *
                </label>
                <input
                  type="text"
                  value={formData.dictionary_path}
                  onChange={(e) =>
                    setFormData({ ...formData, dictionary_path: e.target.value })
                  }
                  className="input w-full font-mono text-sm"
                  placeholder="/app/dictionaries/medical_terms.txt"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Path to dictionary file containing one word per line
                </p>
              </div>
            )}

            {/* Scoring */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Threshold (Min Matches)
                </label>
                <input
                  type="number"
                  min="1"
                  value={formData.threshold}
                  onChange={(e) =>
                    setFormData({ ...formData, threshold: parseInt(e.target.value) })
                  }
                  className="input w-full"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Minimum matches required to trigger
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Weight (0.0 - 1.0)
                </label>
                <input
                  type="number"
                  min="0"
                  max="1"
                  step="0.1"
                  value={formData.weight}
                  onChange={(e) =>
                    setFormData({ ...formData, weight: parseFloat(e.target.value) })
                  }
                  className="input w-full"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Contribution to confidence score
                </p>
              </div>
            </div>

            {/* Classification */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Severity
              </label>
              <select
                value={formData.severity}
                onChange={(e) => setFormData({ ...formData, severity: e.target.value as any })}
                className="input w-full"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Classification Labels
              </label>
              <div className="flex gap-2 mb-2">
                <input
                  type="text"
                  value={labelInput}
                  onChange={(e) => setLabelInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addLabel())}
                  className="input flex-1"
                  placeholder="e.g., PII, FINANCIAL (press Enter)"
                />
                <button type="button" onClick={addLabel} className="btn-secondary">
                  <Plus className="h-4 w-4" />
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {formData.classification_labels?.map((label) => (
                  <span
                    key={label}
                    className="inline-flex items-center gap-1 px-3 py-1 bg-purple-100 text-purple-800 rounded-full text-sm"
                  >
                    {label}
                    <button
                      type="button"
                      onClick={() => removeLabel(label)}
                      className="hover:text-purple-900"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Tags</label>
              <div className="flex gap-2 mb-2">
                <input
                  type="text"
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addTag())}
                  className="input flex-1"
                  placeholder="e.g., compliance, gdpr (press Enter)"
                />
                <button type="button" onClick={addTag} className="btn-secondary">
                  <Plus className="h-4 w-4" />
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {formData.tags?.map((tag) => (
                  <span
                    key={tag}
                    className="inline-flex items-center gap-1 px-3 py-1 bg-gray-100 text-gray-800 rounded-full text-sm"
                  >
                    {tag}
                    <button
                      type="button"
                      onClick={() => removeTag(tag)}
                      className="hover:text-gray-900"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                ))}
              </div>
            </div>

            {/* Enabled */}
            <div className="flex items-center">
              <input
                type="checkbox"
                id="enabled"
                checked={formData.enabled}
                onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
              />
              <label htmlFor="enabled" className="ml-2 text-sm text-gray-700">
                Enable this rule immediately
              </label>
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 p-6 border-t border-gray-200 bg-gray-50">
            <button type="button" onClick={onClose} className="btn-secondary">
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending || updateMutation.isPending}
              className="btn-primary"
            >
              {createMutation.isPending || updateMutation.isPending
                ? 'Saving...'
                : isEdit
                ? 'Update Rule'
                : 'Create Rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
