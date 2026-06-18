import { useState } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Trash2, ToggleLeft, ToggleRight, ChevronDown, ChevronUp, AlertTriangle, Ban, Bell, Eye, Loader2, RefreshCcw } from 'lucide-react'
import { getPolicies, enablePolicy, disablePolicy, deletePolicy, createPolicy } from '@/lib/api'
import toast from 'react-hot-toast'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-green-100 text-green-700 border-green-200',
}

const ACTION_ICONS: Record<string, typeof Ban> = {
  block: Ban,
  alert: Bell,
  quarantine: AlertTriangle,
}

type PolicyCondition = {
  field: string
  operator: string
  value: any
}

type PolicyAction = {
  type: string
  parameters?: Record<string, any>
  severity?: string
}

type Policy = {
  id: string
  name: string
  description: string
  enabled: boolean
  priority: number
  type?: string
  severity?: string
  config?: Record<string, any>
  conditions: PolicyCondition[]
  actions: PolicyAction[]
  compliance_tags: string[]
  agent_ids: string[]
  created_at?: string
  updated_at?: string
}

function CreatePolicyModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('high')
  const [policyType, setPolicyType] = useState('usb_file_transfer_monitoring')
  const [priority, setPriority] = useState(100)

  // Conditions
  const [conditions, setConditions] = useState<PolicyCondition[]>([
    { field: 'classification_level', operator: 'in', value: 'Confidential,Restricted' },
    { field: 'destination_type', operator: 'equals', value: 'removable_drive' },
  ])

  // Actions
  const [actions, setActions] = useState<{ type: string; severity?: string }[]>([
    { type: 'block' },
    { type: 'alert', severity: 'high' },
  ])

  const [submitting, setSubmitting] = useState(false)

  const handleAddCondition = () => {
    setConditions([...conditions, { field: '', operator: 'equals', value: '' }])
  }

  const handleRemoveCondition = (idx: number) => {
    setConditions(conditions.filter((_, i) => i !== idx))
  }

  const handleAddAction = () => {
    setActions([...actions, { type: 'alert' }])
  }

  const handleRemoveAction = (idx: number) => {
    setActions(actions.filter((_, i) => i !== idx))
  }

  const handleSubmit = async () => {
    if (!name.trim()) { toast.error('Policy name is required'); return }
    if (conditions.length === 0) { toast.error('At least one condition is required'); return }
    if (actions.length === 0) { toast.error('At least one action is required'); return }

    setSubmitting(true)
    try {
      const actionsObj: Record<string, any> = {}
      for (const a of actions) {
        if (a.type === 'alert') {
          actionsObj.alert = { severity: a.severity || severity }
        } else {
          actionsObj[a.type] = {}
        }
      }

      const conditionRules = conditions.map(c => {
        let val: any = c.value
        if (c.operator === 'in' && typeof val === 'string') {
          val = val.split(',').map((s: string) => s.trim())
        }
        if (c.operator === '>=' || c.operator === '<=' || c.operator === '>' || c.operator === '<') {
          val = parseFloat(val)
        }
        return { field: c.field, operator: c.operator, value: val }
      })

      await createPolicy({
        name,
        description: description || name,
        enabled: true,
        priority,
        type: policyType,
        severity,
        config: { description },
        conditions: conditionRules,
        actions: Object.entries(actionsObj).map(([type, params]) => ({ type, parameters: params })),
      })

      toast.success('Policy created')
      onCreated()
      onClose()
    } catch (e: any) {
      toast.error(extractErrorDetail(e, 'Failed to create policy'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6">
        <h2 className="text-xl font-bold text-gray-900 mb-6">Create New Policy</h2>

        {/* Basic Info */}
        <div className="space-y-4 mb-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Policy Name</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="e.g., Block Sensitive Data on USB" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="What does this policy do?" />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
              <select value={policyType} onChange={e => setPolicyType(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm">
                <option value="usb_file_transfer_monitoring">USB File Transfer</option>
                <option value="clipboard_monitoring">Clipboard</option>
                <option value="file_system_monitoring">File System</option>
                <option value="usb_device_monitoring">USB Device</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm">
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Priority</label>
              <input type="number" value={priority} onChange={e => setPriority(parseInt(e.target.value) || 0)}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" />
            </div>
          </div>
        </div>

        {/* Conditions */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-3">
            <label className="text-sm font-semibold text-gray-700 uppercase">Conditions (ALL must match)</label>
            <button onClick={handleAddCondition} className="text-xs text-blue-600 hover:text-blue-800 font-medium">+ Add Condition</button>
          </div>
          <div className="space-y-2">
            {conditions.map((c, idx) => (
              <div key={idx} className="flex gap-2 items-center">
                <select value={c.field} onChange={e => { const nc = [...conditions]; nc[idx].field = e.target.value; setConditions(nc) }}
                  className="border border-gray-300 rounded-lg px-2 py-1.5 text-sm flex-1">
                  <option value="">Select field...</option>
                  <option value="classification_level">Classification Level</option>
                  <option value="confidence_score">Confidence Score</option>
                  <option value="destination_type">Destination Type</option>
                  <option value="event_type">Event Type</option>
                  <option value="severity">Severity</option>
                </select>
                <select value={c.operator} onChange={e => { const nc = [...conditions]; nc[idx].operator = e.target.value; setConditions(nc) }}
                  className="border border-gray-300 rounded-lg px-2 py-1.5 text-sm w-28">
                  <option value="equals">equals</option>
                  <option value="in">in</option>
                  <option value=">=">{'>='}  </option>
                  <option value="<=">{'<='}</option>
                  <option value=">">{'>'}</option>
                  <option value="<">{'<'}</option>
                  <option value="contains">contains</option>
                </select>
                <input type="text" value={typeof c.value === 'object' ? (c.value as string[]).join(',') : c.value}
                  onChange={e => { const nc = [...conditions]; nc[idx].value = e.target.value; setConditions(nc) }}
                  className="border border-gray-300 rounded-lg px-2 py-1.5 text-sm flex-1"
                  placeholder={c.operator === 'in' ? 'val1,val2' : 'value'} />
                <button onClick={() => handleRemoveCondition(idx)} className="text-red-400 hover:text-red-600">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-3">
            <label className="text-sm font-semibold text-gray-700 uppercase">Actions</label>
            <button onClick={handleAddAction} className="text-xs text-blue-600 hover:text-blue-800 font-medium">+ Add Action</button>
          </div>
          <div className="space-y-2">
            {actions.map((a, idx) => (
              <div key={idx} className="flex gap-2 items-center">
                <select value={a.type} onChange={e => { const na = [...actions]; na[idx].type = e.target.value; setActions(na) }}
                  className="border border-gray-300 rounded-lg px-2 py-1.5 text-sm flex-1">
                  <option value="block">Block</option>
                  <option value="alert">Alert</option>
                  <option value="quarantine">Quarantine</option>
                </select>
                {a.type === 'alert' && (
                  <select value={a.severity || 'high'} onChange={e => { const na = [...actions]; na[idx].severity = e.target.value; setActions(na) }}
                    className="border border-gray-300 rounded-lg px-2 py-1.5 text-sm w-32">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                )}
                <button onClick={() => handleRemoveAction(idx)} className="text-red-400 hover:text-red-600">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Submit */}
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900">Cancel</button>
          <button onClick={handleSubmit} disabled={submitting}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2">
            {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
            Create Policy
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Policies() {
  const queryClient = useQueryClient()
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  const { data: policies = [], isLoading, error, refetch } = useQuery<Policy[]>({
    queryKey: ['policies'],
    queryFn: getPolicies,
  })

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      return enabled ? await disablePolicy(id) : await enablePolicy(id)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast.success('Policy updated')
    },
    onError: () => toast.error('Failed to update policy'),
  })

  const deleteMutation = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      toast.success('Policy deleted')
    },
    onError: () => toast.error('Failed to delete policy'),
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
        <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-2" />
        <p className="text-red-700">Failed to load policies</p>
        <button onClick={() => refetch()} className="mt-2 text-sm text-red-600 underline">Retry</button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Policies</h1>
          <p className="mt-1 text-sm text-gray-600">
            {(policies || []).length} {(policies || []).length === 1 ? 'policy' : 'policies'} configured
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => refetch()}
            className="px-3 py-2 text-sm text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 flex items-center gap-2">
            <RefreshCcw className="w-4 h-4" /> Refresh
          </button>
          <button onClick={() => setShowCreate(true)}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 flex items-center gap-2">
            <Plus className="w-4 h-4" /> Create Policy
          </button>
        </div>
      </div>

      {/* Empty State */}
      {policies.length === 0 && (
        <div className="bg-gray-50 border border-gray-200 rounded-xl p-12 text-center">
          <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900">No policies configured</h3>
          <p className="text-sm text-gray-600 mt-1">Create your first policy to start enforcing data protection rules.</p>
          <button onClick={() => setShowCreate(true)}
            className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700">
            Create Policy
          </button>
        </div>
      )}

      {/* Policy List */}
      <div className="space-y-3">
        {policies.map((policy) => {
          const isExpanded = expandedId === policy.id
          const sevClass = SEVERITY_COLORS[policy.severity || 'medium'] || SEVERITY_COLORS.medium
          const pConditions = policy.conditions || []
          const pActions = policy.actions || []
          const hasBlock = pActions.some(a => a.type === 'block')

          return (
            <div key={policy.id} className={`bg-white rounded-xl border ${policy.enabled ? 'border-gray-200' : 'border-gray-100 opacity-60'} shadow-sm overflow-hidden`}>
              {/* Policy Header */}
              <div className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-gray-50"
                onClick={() => setExpandedId(isExpanded ? null : policy.id)}>
                {/* Toggle */}
                <button
                  onClick={(e) => { e.stopPropagation(); toggleMutation.mutate({ id: policy.id, enabled: policy.enabled }) }}
                  className={`flex-shrink-0 ${policy.enabled ? 'text-green-500' : 'text-gray-300'}`}
                  title={policy.enabled ? 'Disable policy' : 'Enable policy'}
                >
                  {policy.enabled ? <ToggleRight className="w-7 h-7" /> : <ToggleLeft className="w-7 h-7" />}
                </button>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-gray-900 truncate">{policy.name}</h3>
                    {hasBlock && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-700">
                        <Ban className="w-3 h-3" /> Blocks
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-gray-500 truncate">{policy.description}</p>
                </div>

                {/* Badges */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  {policy.type && (
                    <span className="px-2 py-1 rounded-lg text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200">
                      {policy.type.replace(/_/g, ' ')}
                    </span>
                  )}
                  <span className={`px-2 py-1 rounded-lg text-xs font-medium border ${sevClass}`}>
                    {policy.severity || 'medium'}
                  </span>
                  <span className="text-xs text-gray-400">P{policy.priority}</span>
                  {isExpanded ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
                </div>
              </div>

              {/* Expanded Details */}
              {isExpanded && (
                <div className="border-t border-gray-100 px-5 py-4 bg-gray-50 space-y-4">
                  {/* Conditions */}
                  <div>
                    <label className="text-xs text-gray-500 uppercase font-semibold mb-2 block">Conditions (ALL must match)</label>
                    <div className="space-y-1">
                      {pConditions.map((c, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-sm">
                          <code className="px-2 py-0.5 bg-white rounded border text-blue-700 font-mono text-xs">{c.field}</code>
                          <span className="text-gray-500 font-medium">{c.operator}</span>
                          <code className="px-2 py-0.5 bg-white rounded border text-green-700 font-mono text-xs">
                            {Array.isArray(c.value) ? c.value.join(', ') : String(c.value)}
                          </code>
                        </div>
                      ))}
                      {pConditions.length === 0 && (
                        <p className="text-sm text-gray-400 italic">No conditions defined</p>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div>
                    <label className="text-xs text-gray-500 uppercase font-semibold mb-2 block">Actions</label>
                    <div className="flex flex-wrap gap-2">
                      {pActions.map((a, idx) => {
                        const Icon = ACTION_ICONS[a.type] || Eye
                        return (
                          <span key={idx} className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium border ${
                            a.type === 'block' ? 'bg-red-50 text-red-700 border-red-200' :
                            a.type === 'quarantine' ? 'bg-orange-50 text-orange-700 border-orange-200' :
                            'bg-blue-50 text-blue-700 border-blue-200'
                          }`}>
                            <Icon className="w-3.5 h-3.5" />
                            {a.type}
                            {a.type === 'alert' && a.parameters?.severity && (
                              <span className="text-xs opacity-75">({a.parameters.severity})</span>
                            )}
                          </span>
                        )
                      })}
                    </div>
                  </div>

                  {/* Metadata & Delete */}
                  <div className="flex items-center justify-between pt-2 border-t border-gray-200">
                    <div className="text-xs text-gray-400 space-x-4">
                      {policy.created_at && <span>Created: {new Date(policy.created_at).toLocaleDateString()}</span>}
                      {(policy.agent_ids?.length ?? 0) > 0 && (
                        <span>Scoped to {policy.agent_ids!.length} agent(s)</span>
                      )}
                    </div>
                    <button
                      onClick={() => { if (confirm(`Delete policy "${policy.name}"?`)) deleteMutation.mutate(policy.id) }}
                      className="text-red-400 hover:text-red-600 text-sm flex items-center gap-1">
                      <Trash2 className="w-4 h-4" /> Delete
                    </button>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Create Modal */}
      {showCreate && (
        <CreatePolicyModal
          onClose={() => setShowCreate(false)}
          onCreated={() => queryClient.invalidateQueries({ queryKey: ['policies'] })}
        />
      )}
    </div>
  )
}
