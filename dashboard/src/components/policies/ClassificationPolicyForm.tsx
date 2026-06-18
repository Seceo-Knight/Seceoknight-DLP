'use client'

import { useState, useEffect } from 'react'
import { Plus, X, Trash2, Info } from 'lucide-react'

export interface ClassificationPolicy {
  conditions: {
    match: 'all' | 'any'
    rules: PolicyCondition[]
  }
  actions: {
    alert?: {
      severity: 'low' | 'medium' | 'high' | 'critical'
      message?: string
    }
    block?: {}
    quarantine?: {
      location?: string
    }
    log?: {
      level?: 'info' | 'warning' | 'error'
    }
  }
}

interface PolicyCondition {
  field: string
  operator: string
  value: any
}

interface ClassificationPolicyFormProps {
  policy: ClassificationPolicy
  onChange: (policy: ClassificationPolicy) => void
}

const FIELD_OPTIONS = [
  { value: 'classification_level', label: 'Classification Level', type: 'select', options: ['Public', 'Internal', 'Confidential', 'Restricted'] },
  { value: 'confidence_score', label: 'Confidence Score', type: 'number' },
  { value: 'classification_labels', label: 'Classification Labels (contains)', type: 'text' },
  { value: 'event_type', label: 'Event Type', type: 'select', options: ['file_transfer', 'clipboard', 'file_create', 'file_modify', 'file_delete', 'usb_connect'] },
  { value: 'destination_type', label: 'Destination Type', type: 'select', options: ['removable_drive', 'email', 'cloud_storage', 'network'] },
  { value: 'file_extension', label: 'File Extension', type: 'text' },
]

const OPERATOR_OPTIONS = [
  { value: 'equals', label: '= Equals' },
  { value: 'in', label: '∈ In (array)' },
  { value: 'contains', label: '⊃ Contains' },
  { value: '>=', label: '≥ Greater or Equal' },
  { value: '<=', label: '≤ Less or Equal' },
  { value: '>', label: '> Greater than' },
  { value: '<', label: '< Less than' },
]

export default function ClassificationPolicyForm({ policy, onChange }: ClassificationPolicyFormProps) {
  const addCondition = () => {
    const newCondition: PolicyCondition = {
      field: 'classification_level',
      operator: 'equals',
      value: 'Restricted'
    }

    onChange({
      ...policy,
      conditions: {
        ...policy.conditions,
        rules: [...policy.conditions.rules, newCondition]
      }
    })
  }

  const updateCondition = (index: number, field: keyof PolicyCondition, value: any) => {
    const newRules = [...policy.conditions.rules]
    newRules[index] = { ...newRules[index], [field]: value }

    onChange({
      ...policy,
      conditions: {
        ...policy.conditions,
        rules: newRules
      }
    })
  }

  const removeCondition = (index: number) => {
    const newRules = policy.conditions.rules.filter((_, i) => i !== index)
    onChange({
      ...policy,
      conditions: {
        ...policy.conditions,
        rules: newRules
      }
    })
  }

  const updateAction = (actionType: keyof ClassificationPolicy['actions'], enabled: boolean, config?: any) => {
    const newActions = { ...policy.actions }

    if (enabled) {
      newActions[actionType] = config || {}
    } else {
      delete newActions[actionType]
    }

    onChange({
      ...policy,
      actions: newActions
    })
  }

  const getFieldConfig = (fieldValue: string) => {
    return FIELD_OPTIONS.find(f => f.value === fieldValue)
  }

  return (
    <div className="space-y-6">
      {/* Info Box */}
      <div className="bg-indigo-900/20 border border-indigo-500/50 rounded-xl p-4">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-indigo-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-indigo-200">
            <p className="font-semibold mb-1">Classification-Aware Policies</p>
            <p>Create policies based on content classification, confidence scores, and labels.
            The classification engine analyzes content using 20+ rules and assigns a level (Public/Internal/Confidential/Restricted).</p>
          </div>
        </div>
      </div>

      {/* Conditions */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h5 className="text-md font-semibold text-white">Conditions</h5>
          <select
            value={policy.conditions.match}
            onChange={(e) => onChange({
              ...policy,
              conditions: {
                ...policy.conditions,
                match: e.target.value as 'all' | 'any'
              }
            })}
            className="px-3 py-1.5 bg-gray-900/50 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
          >
            <option value="all">Match ALL conditions</option>
            <option value="any">Match ANY condition</option>
          </select>
        </div>

        <div className="space-y-3">
          {policy.conditions.rules.map((condition, index) => {
            const fieldConfig = getFieldConfig(condition.field)

            return (
              <div key={index} className="bg-gray-900/50 border border-gray-600 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <div className="flex-1 grid grid-cols-3 gap-3">
                    {/* Field */}
                    <div>
                      <label className="block text-xs font-medium text-gray-400 mb-1.5">Field</label>
                      <select
                        value={condition.field}
                        onChange={(e) => updateCondition(index, 'field', e.target.value)}
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                      >
                        {FIELD_OPTIONS.map(opt => (
                          <option key={opt.value} value={opt.value}>{opt.label}</option>
                        ))}
                      </select>
                    </div>

                    {/* Operator */}
                    <div>
                      <label className="block text-xs font-medium text-gray-400 mb-1.5">Operator</label>
                      <select
                        value={condition.operator}
                        onChange={(e) => updateCondition(index, 'operator', e.target.value)}
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                      >
                        {OPERATOR_OPTIONS.map(opt => (
                          <option key={opt.value} value={opt.value}>{opt.label}</option>
                        ))}
                      </select>
                    </div>

                    {/* Value */}
                    <div>
                      <label className="block text-xs font-medium text-gray-400 mb-1.5">Value</label>
                      {fieldConfig?.type === 'select' ? (
                        condition.operator === 'in' ? (
                          <input
                            type="text"
                            value={Array.isArray(condition.value) ? condition.value.join(', ') : condition.value}
                            onChange={(e) => {
                              const values = e.target.value.split(',').map(v => v.trim()).filter(Boolean)
                              updateCondition(index, 'value', values)
                            }}
                            placeholder="value1, value2, ..."
                            className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                          />
                        ) : (
                          <select
                            value={condition.value}
                            onChange={(e) => updateCondition(index, 'value', e.target.value)}
                            className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                          >
                            {fieldConfig.options?.map(opt => (
                              <option key={opt} value={opt}>{opt}</option>
                            ))}
                          </select>
                        )
                      ) : fieldConfig?.type === 'number' ? (
                        <input
                          type="number"
                          step="0.1"
                          min="0"
                          max="1"
                          value={condition.value}
                          onChange={(e) => updateCondition(index, 'value', parseFloat(e.target.value))}
                          placeholder="0.0 - 1.0"
                          className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                        />
                      ) : (
                        <input
                          type="text"
                          value={condition.value}
                          onChange={(e) => updateCondition(index, 'value', e.target.value)}
                          placeholder="Enter value..."
                          className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                        />
                      )}
                    </div>
                  </div>

                  {/* Remove button */}
                  <button
                    onClick={() => removeCondition(index)}
                    className="mt-6 p-2 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )
          })}

          <button
            onClick={addCondition}
            className="w-full px-4 py-3 bg-gray-900/50 border-2 border-dashed border-gray-600 hover:border-indigo-500 rounded-lg text-gray-400 hover:text-indigo-400 transition-colors flex items-center justify-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add Condition
          </button>
        </div>
      </div>

      {/* Actions */}
      <div>
        <h5 className="text-md font-semibold text-white mb-4">Actions (when conditions match)</h5>

        <div className="space-y-3">
          {/* Alert Action */}
          <div className="bg-gray-900/50 border border-gray-600 rounded-lg p-4">
            <div className="flex items-center gap-3 mb-3">
              <input
                type="checkbox"
                id="action-alert"
                checked={!!policy.actions.alert}
                onChange={(e) => updateAction('alert', e.target.checked, { severity: 'high', message: '' })}
                className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-600 rounded bg-gray-900/50"
              />
              <label htmlFor="action-alert" className="text-sm font-medium text-white flex-1">
                Create Alert
              </label>
            </div>

            {policy.actions.alert && (
              <div className="ml-7 space-y-3">
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1.5">Severity</label>
                  <select
                    value={policy.actions.alert.severity}
                    onChange={(e) => updateAction('alert', true, { ...policy.actions.alert, severity: e.target.value })}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1.5">Message</label>
                  <input
                    type="text"
                    value={policy.actions.alert.message || ''}
                    onChange={(e) => updateAction('alert', true, { ...policy.actions.alert, message: e.target.value })}
                    placeholder="Optional alert message..."
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Block Action */}
          <div className="bg-gray-900/50 border border-gray-600 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="action-block"
                checked={!!policy.actions.block}
                onChange={(e) => updateAction('block', e.target.checked, {})}
                className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-600 rounded bg-gray-900/50"
              />
              <label htmlFor="action-block" className="text-sm font-medium text-white flex-1">
                Block Action
              </label>
              <span className="text-xs text-gray-400">Prevents file transfer/clipboard copy</span>
            </div>
          </div>

          {/* Quarantine Action */}
          <div className="bg-gray-900/50 border border-gray-600 rounded-lg p-4">
            <div className="flex items-center gap-3 mb-3">
              <input
                type="checkbox"
                id="action-quarantine"
                checked={!!policy.actions.quarantine}
                onChange={(e) => updateAction('quarantine', e.target.checked, { location: '/var/quarantine/' })}
                className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-600 rounded bg-gray-900/50"
              />
              <label htmlFor="action-quarantine" className="text-sm font-medium text-white flex-1">
                Quarantine File
              </label>
            </div>

            {policy.actions.quarantine && (
              <div className="ml-7">
                <label className="block text-xs font-medium text-gray-400 mb-1.5">Location</label>
                <input
                  type="text"
                  value={policy.actions.quarantine.location || ''}
                  onChange={(e) => updateAction('quarantine', true, { location: e.target.value })}
                  placeholder="/var/quarantine/"
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>
            )}
          </div>

          {/* Log Action */}
          <div className="bg-gray-900/50 border border-gray-600 rounded-lg p-4">
            <div className="flex items-center gap-3 mb-3">
              <input
                type="checkbox"
                id="action-log"
                checked={!!policy.actions.log}
                onChange={(e) => updateAction('log', e.target.checked, { level: 'info' })}
                className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-600 rounded bg-gray-900/50"
              />
              <label htmlFor="action-log" className="text-sm font-medium text-white flex-1">
                Log Event
              </label>
            </div>

            {policy.actions.log && (
              <div className="ml-7">
                <label className="block text-xs font-medium text-gray-400 mb-1.5">Log Level</label>
                <select
                  value={policy.actions.log.level || 'info'}
                  onChange={(e) => updateAction('log', true, { level: e.target.value })}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                >
                  <option value="info">Info</option>
                  <option value="warning">Warning</option>
                  <option value="error">Error</option>
                </select>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Example Scenarios */}
      <div className="bg-gray-900/30 border border-gray-700 rounded-xl p-4">
        <h6 className="text-sm font-semibold text-gray-300 mb-2">💡 Example Scenarios</h6>
        <div className="text-xs text-gray-400 space-y-1">
          <p>• <strong>Block USB with Restricted Data:</strong> classification_level = "Restricted" AND destination_type = "removable_drive"</p>
          <p>• <strong>Alert High Confidence:</strong> confidence_score ≥ 0.8</p>
          <p>• <strong>Block Credentials in Clipboard:</strong> classification_labels contains "CREDENTIAL" AND event_type = "clipboard"</p>
        </div>
      </div>
    </div>
  )
}
