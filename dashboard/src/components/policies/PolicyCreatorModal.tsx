'use client'

import { useState, useEffect } from 'react'
import { 
  Policy, 
  PolicyType, 
  ClipboardConfig, 
  FileSystemConfig, 
  USBDeviceConfig, 
  USBTransferConfig,
  FileTransferConfig,
  GoogleDriveLocalConfig,
  GoogleDriveCloudConfig,
  OneDriveCloudConfig
} from '@/types/policy'
import { validatePolicy } from '@/utils/policyUtils'
import PolicyTypeSelector from './PolicyTypeSelector'
import ClipboardPolicyForm from './ClipboardPolicyForm'
import FileSystemPolicyForm from './FileSystemPolicyForm'
import FileTransferPolicyForm from './FileTransferPolicyForm'
import USBDevicePolicyForm from './USBDevicePolicyForm'
import USBTransferPolicyForm from './USBTransferPolicyForm'
import GoogleDriveLocalPolicyForm from './GoogleDriveLocalPolicyForm'
import GoogleDriveCloudPolicyForm from './GoogleDriveCloudPolicyForm'
import OneDriveCloudPolicyForm from './OneDriveCloudPolicyForm'
import ClassificationPolicyForm, { ClassificationPolicy } from './ClassificationPolicyForm'
import { getAgents, Agent } from '@/lib/api'
import { X, ChevronLeft, ChevronRight, Check } from 'lucide-react'
import toast from 'react-hot-toast'

interface PolicyCreatorModalProps {
  isOpen: boolean
  onClose: () => void
  onSave: (policy: Partial<Policy>) => void
  editingPolicy?: Policy | null
}

const getDefaultConfig = (type: PolicyType): ClipboardConfig | FileSystemConfig | USBDeviceConfig | USBTransferConfig | FileTransferConfig | GoogleDriveLocalConfig | GoogleDriveCloudConfig | OneDriveCloudConfig | {} => {
  switch (type) {
    case 'classification_aware_policy':
      // Classification-aware policies don't use config, they use conditions/actions
      return {}

    case 'clipboard_monitoring':
      return {
        patterns: {
          predefined: [],
          custom: []
        },
        action: 'alert'
      } as ClipboardConfig
    
    case 'file_system_monitoring':
      return {
        monitoredPaths: [],
        events: {
          create: true,
          modify: false,
          delete: false,
          move: false
        },
        action: 'alert'
      } as FileSystemConfig

    case 'file_transfer_monitoring':
      return {
        protectedPaths: [],
        monitoredDestinations: [],
        fileExtensions: [],
        events: {
          create: true,
          modify: true,
          delete: false,
          move: true
        },
        action: 'block'
      } as FileTransferConfig
    
    case 'usb_device_monitoring':
      return {
        events: {
          connect: true,
          disconnect: false,
          fileTransfer: false
        },
        action: 'alert'
      } as USBDeviceConfig
    
    case 'usb_file_transfer_monitoring':
      return {
        monitoredPaths: [],
        action: 'block'
      } as USBTransferConfig
    
    case 'google_drive_local_monitoring':
      return {
        basePath: 'G:\\My Drive\\',
        monitoredFolders: [],
        events: {
          create: true,
          modify: false,
          delete: false,
          move: false
        },
        action: 'alert'
      } as GoogleDriveLocalConfig
      
    case 'google_drive_cloud_monitoring':
      return {
        connectionId: '',
        protectedFolders: [],
        pollingInterval: 10,
        action: 'log'
      } as GoogleDriveCloudConfig
      
    case 'onedrive_cloud_monitoring':
      return {
        connectionId: '',
        protectedFolders: [],
        pollingInterval: 10,
        action: 'log'
      } as OneDriveCloudConfig
  }
}

export default function PolicyCreatorModal({ 
  isOpen, 
  onClose, 
  onSave, 
  editingPolicy 
}: PolicyCreatorModalProps) {
  // When editing, skip step 1 (type selection) and go straight to step 2
  // (configuration). The policy type can't be changed for an existing
  // policy anyway, and landing on step 1 with a visually-selected-but-
  // internally-null type confuses users into clicking the tile again.
  const [step, setStep] = useState(editingPolicy ? 2 : 1)
  const [policyType, setPolicyType] = useState<PolicyType | null>(
    editingPolicy?.type || (editingPolicy ? 'classification_aware_policy' : null)
  )
  const [policyName, setPolicyName] = useState(editingPolicy?.name || '')
  const [description, setDescription] = useState(editingPolicy?.description || '')
  const [severity, setSeverity] = useState<'low' | 'medium' | 'high' | 'critical'>(
    editingPolicy?.severity || 'medium'
  )
  const [priority, setPriority] = useState(editingPolicy?.priority || 100)
  const [enabled, setEnabled] = useState(editingPolicy?.enabled ?? true)
  const [agents, setAgents] = useState<Agent[]>([])
  const [agentId, setAgentId] = useState(editingPolicy?.agentIds?.[0] || '')
  const [config, setConfig] = useState<ClipboardConfig | FileSystemConfig | USBDeviceConfig | USBTransferConfig | FileTransferConfig | GoogleDriveLocalConfig | GoogleDriveCloudConfig>(
    editingPolicy?.config || (policyType ? getDefaultConfig(policyType) : getDefaultConfig('clipboard_monitoring'))
  )
  const [classificationPolicy, setClassificationPolicy] = useState<ClassificationPolicy>(() => {
    // DEFENSIVE: even after transformApiPolicyToFrontend there's no
    // guarantee the incoming policy has the exact {match,rules}+object
    // shape this form needs. Coerce into the expected structure rather
    // than dereferencing `.conditions.match` on a potentially-malformed
    // value (which used to blank the screen).
    const rawC: any = editingPolicy?.conditions
    const rawA: any = editingPolicy?.actions
    return {
      conditions: {
        match: (rawC && !Array.isArray(rawC) && rawC.match) || 'all',
        rules: Array.isArray(rawC?.rules)
          ? rawC.rules
          : Array.isArray(rawC)
            ? rawC
            : [],
      },
      actions:
        rawA && typeof rawA === 'object' && !Array.isArray(rawA)
          ? rawA
          : {},
    }
  })

  // Reset form when modal opens/closes or editing policy changes
  useEffect(() => {
    if (isOpen) {
      if (editingPolicy) {
        setStep(2) // skip type selection — can't change type for existing policy
        setPolicyType(editingPolicy.type || 'classification_aware_policy')
        setPolicyName(editingPolicy.name || '')
        setDescription(editingPolicy.description || '')
        setSeverity(editingPolicy.severity || 'medium')
        setPriority(editingPolicy.priority ?? 100)
        setEnabled(editingPolicy.enabled ?? true)
        setAgentId(editingPolicy.agentIds?.[0] || '')
        if (editingPolicy.config) {
          setConfig(editingPolicy.config)
        }
        // Same defensive coercion as the initial useState — never
        // trust that `conditions` is {match,rules} or that `actions`
        // is an object, because the API serializer may send a list.
        const rawC: any = editingPolicy.conditions
        const rawA: any = editingPolicy.actions
        setClassificationPolicy({
          conditions: {
            match: (rawC && !Array.isArray(rawC) && rawC.match) || 'all',
            rules: Array.isArray(rawC?.rules)
              ? rawC.rules
              : Array.isArray(rawC)
                ? rawC
                : [],
          },
          actions:
            rawA && typeof rawA === 'object' && !Array.isArray(rawA)
              ? rawA
              : {},
        })
      } else {
        // Reset for new policy
        setStep(1)
        setPolicyType(null)
        setPolicyName('')
        setDescription('')
        setSeverity('medium')
        setPriority(100)
        setEnabled(true)
        setAgentId('')
        setConfig(getDefaultConfig('clipboard_monitoring'))
        setClassificationPolicy({
          conditions: {
            match: 'all',
            rules: []
          },
          actions: {}
        })
      }
    }
  }, [isOpen, editingPolicy])

  // Update config when type changes
  useEffect(() => {
    if (policyType && !editingPolicy) {
      setConfig(getDefaultConfig(policyType))
    }
  }, [policyType])

  // Load agents for single-select
  useEffect(() => {
    if (!isOpen) return
    getAgents()
      .then((data) => setAgents(Array.isArray(data) ? data : data?.items || []))
      .catch(() => setAgents([]))
  }, [isOpen])

  const handleClose = () => {
    setStep(1)
    onClose()
  }

  const handleNext = () => {
    if (step === 1) {
      if (!policyType) {
        toast.error('Please select a policy type')
        return
      }
      setStep(2)
    } else if (step === 2) {
      setStep(3)
    }
  }

  const handleBack = () => {
    if (step > 1) {
      setStep(step - 1)
    }
  }

  const handleSave = () => {
    if (!policyName.trim()) {
      toast.error('Policy name is required')
      return
    }

    if (!policyType) {
      toast.error('Policy type is required')
      return
    }

    let policy: Partial<Policy>

    if (policyType === 'classification_aware_policy') {
      // Classification-aware policy uses conditions/actions format
      if (classificationPolicy.conditions.rules.length === 0) {
        toast.error('At least one condition is required for classification-aware policies')
        return
      }

      if (Object.keys(classificationPolicy.actions).length === 0) {
        toast.error('At least one action is required for classification-aware policies')
        return
      }

      // Convert conditions from {match, rules} to just rules array for API
      const conditionsArray = classificationPolicy.conditions.rules.map(rule => ({
        field: rule.field,
        operator: rule.operator,
        value: rule.value
      }))

      // Convert actions from {alert: {}, block: {}} to [{type: "alert", parameters: {}}, {type: "block", parameters: {}}]
      const actionsArray = Object.entries(classificationPolicy.actions).map(([actionType, actionConfig]) => ({
        type: actionType,
        parameters: actionConfig || {}
      }))

      policy = {
        name: policyName.trim(),
        description: description.trim() || undefined,
        priority,
        enabled,
        match: classificationPolicy.conditions.match,
        conditions: conditionsArray,
        actions: actionsArray,
        agentIds: agentId ? [agentId] : [],
      } as Partial<Policy> & { match: 'all' | 'any' }
    } else {
      // Traditional policy uses type/severity/config format
      policy = {
        name: policyName.trim(),
        description: description.trim() || undefined,
        type: policyType,
        severity,
        priority,
        enabled,
        config,
        agentIds: agentId ? [agentId] : [],
      }

      const validation = validatePolicy(policy)
      if (!validation.valid) {
        toast.error(validation.errors[0] || 'Invalid policy configuration')
        return
      }
    }

    onSave(policy)
    handleClose()
  }

  const canProceedFromStep1 = policyType !== null
  const canProceedFromStep2 = policyType !== null && (
    policyType === 'classification_aware_policy'
      ? classificationPolicy.conditions.rules.length > 0 && Object.keys(classificationPolicy.actions).length > 0
      : config !== null
  )
  const canSave = policyName.trim() !== '' && policyType !== null

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={handleClose}>
      <div 
        className="bg-gray-800 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto border border-gray-700" 
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700 sticky top-0 bg-gray-800 z-10">
          <div>
            <h3 className="text-2xl font-bold text-white">
              {editingPolicy ? 'Edit Policy' : 'Create New Policy'}
            </h3>
            <p className="text-gray-400 mt-1">
              {step === 1 && 'Select policy type'}
              {step === 2 && 'Configure policy settings'}
              {step === 3 && 'Review and save'}
            </p>
          </div>
          <button onClick={handleClose} className="text-gray-400 hover:text-white transition-colors">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Progress Indicator */}
        <div className="px-6 pt-6">
          <div className="flex items-center justify-between max-w-md mx-auto">
            {[1, 2, 3].map((s) => (
              <div key={s} className="flex items-center flex-1">
                <div className="flex flex-col items-center w-full">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all ${
                    step >= s
                      ? 'bg-indigo-600 border-indigo-500 text-white'
                      : 'bg-gray-700 border-gray-600 text-gray-400'
                  }`}>
                    {step > s ? <Check className="w-5 h-5" /> : s}
                  </div>
                  <span className={`text-xs mt-2 ${
                    step >= s ? 'text-white' : 'text-gray-400'
                  }`}>
                    {s === 1 ? 'Type' : s === 2 ? 'Config' : 'Review'}
                  </span>
                </div>
                {s < 3 && (
                  <div className={`h-0.5 flex-1 mx-2 ${
                    step > s ? 'bg-indigo-600' : 'bg-gray-700'
                  }`} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6">
          {step === 1 && (
            <PolicyTypeSelector
              selectedType={policyType}
              onSelectType={(type) => {
                setPolicyType(type)
                setConfig(getDefaultConfig(type))
              }}
            />
          )}

          {step === 2 && policyType && (
            <div className="space-y-6">
              {/* Basic Information */}
              <div className="bg-gray-900/50 rounded-xl p-6 border border-gray-700">
                <h4 className="text-lg font-semibold text-white mb-4">Basic Information</h4>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-200 mb-2">Policy Name *</label>
                    <input
                      type="text"
                      value={policyName}
                      onChange={(e) => setPolicyName(e.target.value)}
                      className="w-full px-4 py-3 bg-gray-900/50 border-2 border-gray-600 rounded-xl text-white placeholder-gray-400 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-500/20 transition-all"
                      placeholder="e.g., Block Sensitive Data Transfer"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-200 mb-2">Description</label>
                    <textarea
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      rows={3}
                      className="w-full px-4 py-3 bg-gray-900/50 border-2 border-gray-600 rounded-xl text-white placeholder-gray-400 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-500/20 transition-all resize-none"
                      placeholder="Describe what this policy does..."
                    />
                  </div>
                  <div className={`grid ${policyType === 'classification_aware_policy' ? 'grid-cols-1' : 'grid-cols-2'} gap-4`}>
                    {policyType !== 'classification_aware_policy' && (
                      <div>
                        <label className="block text-sm font-medium text-gray-200 mb-2">Severity Level</label>
                        <select
                          value={severity}
                          onChange={(e) => setSeverity(e.target.value as typeof severity)}
                          className="w-full px-4 py-3 bg-gray-900/50 border-2 border-gray-600 rounded-xl text-white focus:border-indigo-500 focus:ring-4 focus:ring-indigo-500/20 transition-all"
                        >
                          <option value="low">Low</option>
                          <option value="medium">Medium</option>
                          <option value="high">High</option>
                          <option value="critical">Critical</option>
                        </select>
                      </div>
                    )}
                    <div>
                      <label className="block text-sm font-medium text-gray-200 mb-2">Priority</label>
                      <input
                        type="number"
                        value={priority}
                        onChange={(e) => setPriority(parseInt(e.target.value) || 100)}
                        min="1"
                        max="1000"
                        className="w-full px-4 py-3 bg-gray-900/50 border-2 border-gray-600 rounded-xl text-white placeholder-gray-400 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-500/20 transition-all"
                        placeholder="1-1000"
                      />
                      <p className="text-xs text-gray-400 mt-1">Higher priority policies are evaluated first</p>
                    </div>
                  </div>
                {/* Agent Scope */}
                <div className="space-y-2">
                  <label className="block text-sm font-medium text-gray-200 mb-2">Target Agent (optional)</label>
                  <select
                    value={agentId}
                    onChange={(e) => setAgentId(e.target.value)}
                    className="w-full px-4 py-3 bg-gray-900/50 border-2 border-gray-600 rounded-xl text-white focus:border-indigo-500 focus:ring-4 focus:ring-indigo-500/20 transition-all text-sm"
                  >
                    <option value="">All agents</option>
                    {agents.map((agent) => (
                      <option key={agent.agent_id} value={agent.agent_id}>
                        {agent.name} ({agent.agent_id})
                      </option>
                    ))}
                  </select>
                  <p className="text-xs text-gray-400">
                    Leave empty to apply to all agents. Select one agent to scope this policy.
                  </p>
                </div>
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="policy-enabled"
                      checked={enabled}
                      onChange={(e) => setEnabled(e.target.checked)}
                      className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-600 rounded bg-gray-900/50"
                    />
                    <label htmlFor="policy-enabled" className="text-sm font-medium text-gray-200">
                      Enable Policy
                    </label>
                  </div>
                </div>
              </div>

              {/* Policy Type Specific Configuration */}
              <div className="bg-gray-900/50 rounded-xl p-6 border border-gray-700">
                <h4 className="text-lg font-semibold text-white mb-4">Policy Configuration</h4>
                {policyType === 'clipboard_monitoring' && (
                  <ClipboardPolicyForm
                    config={config as ClipboardConfig}
                    onChange={(newConfig) => setConfig(newConfig)}
                  />
                )}
                
                {policyType === 'file_system_monitoring' && (
                  <FileSystemPolicyForm
                    config={config as FileSystemConfig}
                    onChange={(newConfig) => setConfig(newConfig)}
                  />
                )}

                {policyType === 'file_transfer_monitoring' && (
                  <FileTransferPolicyForm
                    config={config as FileTransferConfig}
                    onChange={(newConfig) => setConfig(newConfig)}
                  />
                )}
                
                {policyType === 'usb_device_monitoring' && (
                  <USBDevicePolicyForm
                    config={config as USBDeviceConfig}
                    onChange={(newConfig) => setConfig(newConfig)}
                  />
                )}
                
                {policyType === 'usb_file_transfer_monitoring' && (
                  <USBTransferPolicyForm
                    config={config as USBTransferConfig}
                    onChange={(newConfig) => setConfig(newConfig)}
                  />
                )}
                
                {policyType === 'google_drive_local_monitoring' && (
                  <GoogleDriveLocalPolicyForm
                    config={config as GoogleDriveLocalConfig}
                    onChange={(newConfig) => setConfig(newConfig)}
                  />
                )}

                {policyType === 'google_drive_cloud_monitoring' && (
                  <GoogleDriveCloudPolicyForm
                    config={config as GoogleDriveCloudConfig}
                    onChange={(newConfig) => setConfig(newConfig)}
                  />
                )}

                {policyType === 'onedrive_cloud_monitoring' && (
                  <OneDriveCloudPolicyForm
                    config={config as OneDriveCloudConfig}
                    onChange={(newConfig) => setConfig(newConfig)}
                  />
                )}

                {policyType === 'classification_aware_policy' && (
                  <ClassificationPolicyForm
                    policy={classificationPolicy}
                    onChange={(newPolicy) => setClassificationPolicy(newPolicy)}
                  />
                )}
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-6">
              <div className="bg-indigo-900/20 border border-indigo-500/50 rounded-xl p-6">
                <h4 className="text-lg font-semibold text-indigo-300 mb-4">Policy Summary</h4>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Name:</span>
                    <span className="text-white font-medium">{policyName || 'Not set'}</span>
                  </div>
                  {description && (
                    <div>
                      <span className="text-gray-400">Description:</span>
                      <p className="text-white mt-1">{description}</p>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-gray-400">Type:</span>
                    <span className="text-white font-medium">{policyType ? policyType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) : 'Not set'}</span>
                  </div>
                  {policyType !== 'classification_aware_policy' && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Severity:</span>
                      <span className="text-white font-medium uppercase">{severity}</span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-gray-400">Priority:</span>
                    <span className="text-white font-medium">{priority}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Status:</span>
                    <span className="text-white font-medium">{enabled ? 'Enabled' : 'Disabled'}</span>
                  </div>
                </div>
              </div>

              {/* Configuration Preview */}
              {policyType === 'classification_aware_policy' ? (
                <div className="bg-gray-900/50 rounded-xl p-6 border border-gray-700">
                  <h4 className="text-lg font-semibold text-white mb-4">Policy Rules</h4>
                  <div className="space-y-4">
                    <div>
                      <h5 className="text-sm font-semibold text-gray-300 mb-2">Conditions ({classificationPolicy.conditions.match === 'all' ? 'Match ALL' : 'Match ANY'})</h5>
                      <div className="space-y-2">
                        {classificationPolicy.conditions.rules.map((rule, idx) => (
                          <div key={idx} className="bg-gray-800 p-3 rounded-lg text-xs text-gray-300">
                            <span className="text-indigo-400">{rule.field}</span>
                            {' '}<span className="text-gray-500">{rule.operator}</span>{' '}
                            <span className="text-green-400">{JSON.stringify(rule.value)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div>
                      <h5 className="text-sm font-semibold text-gray-300 mb-2">Actions</h5>
                      <pre className="bg-gray-800 p-4 rounded-lg text-xs overflow-x-auto text-gray-300">
                        {JSON.stringify(classificationPolicy.actions, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              ) : config && (
                <div className="bg-gray-900/50 rounded-xl p-6 border border-gray-700">
                  <h4 className="text-lg font-semibold text-white mb-4">Configuration</h4>
                  <pre className="bg-gray-800 p-4 rounded-lg text-xs overflow-x-auto text-gray-300">
                    {JSON.stringify(config, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex gap-3 p-6 border-t border-gray-700 sticky bottom-0 bg-gray-800">
          {step > 1 && (
            <button
              onClick={handleBack}
              className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-xl transition-colors flex items-center gap-2"
            >
              <ChevronLeft className="w-5 h-5" />
              Back
            </button>
          )}
          
          <div className="flex-1" />
          
          {step < 3 ? (
            <button
              onClick={handleNext}
              disabled={step === 1 ? !canProceedFromStep1 : !canProceedFromStep2}
              className="px-6 py-3 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-700 disabled:text-gray-500 text-white font-semibold rounded-xl transition-colors flex items-center gap-2"
            >
              Next
              <ChevronRight className="w-5 h-5" />
            </button>
          ) : (
            <button
              onClick={handleSave}
              disabled={!canSave}
              className="px-6 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 disabled:from-gray-700 disabled:to-gray-700 disabled:text-gray-500 text-white font-semibold rounded-xl transition-all"
            >
              {editingPolicy ? 'Update Policy' : 'Create Policy'}
            </button>
          )}
          
          <button
            onClick={handleClose}
            className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-xl transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}
