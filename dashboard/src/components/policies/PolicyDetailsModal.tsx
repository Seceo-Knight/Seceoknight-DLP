import { useState } from 'react'
import { X, ChevronDown, ChevronUp } from 'lucide-react'
import { Policy } from '@/types/policy'
import { getPolicyTypeIcon, getPolicyTypeLabel, getSeverityColorLight } from '@/utils/policyUtils'

interface PolicyDetailsModalProps {
  isOpen: boolean
  policy: Policy | null
  onClose: () => void
}

export default function PolicyDetailsModal({ isOpen, policy, onClose }: PolicyDetailsModalProps) {
  const [showJson, setShowJson] = useState(false)

  if (!isOpen || !policy) return null

  const Icon = getPolicyTypeIcon(policy.type)
  const severityColor = getSeverityColorLight(policy.severity)

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleString('en-US', {
      month: 'long',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  return (
    <div
      className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <div
        className="bg-card rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto border border-border shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-border sticky top-0 bg-card z-10">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${severityColor.bg}`}>
              <Icon className={`h-6 w-6 ${severityColor.icon}`} />
            </div>
            <div>
              <h3 className="text-2xl font-bold text-foreground">{policy.name}</h3>
              <p className="text-sm text-muted-foreground mt-1">{getPolicyTypeLabel(policy.type)}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-accent transition-colors"
          >
            <X className="h-5 w-5 text-muted-foreground" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Basic Information */}
          <div>
            <h4 className="text-lg font-semibold text-foreground mb-4">Basic Information</h4>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Status</label>
                <p className="mt-1">
                  {policy.enabled ? (
                    <span className="badge badge-success">Active</span>
                  ) : (
                    <span className="badge bg-secondary text-muted-foreground">Inactive</span>
                  )}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Severity</label>
                <p className="mt-1">
                  <span className={`badge ${severityColor.badge}`}>{policy.severity}</span>
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Priority</label>
                <p className="mt-1 text-foreground font-medium">{policy.priority}</p>
              </div>
              {policy.violations !== undefined && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Violations</label>
                  <p className="mt-1 text-foreground font-medium">{policy.violations}</p>
                </div>
              )}
            </div>
          </div>

          {/* Description */}
          {policy.description && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">Description</label>
              <p className="mt-1 text-foreground">{policy.description}</p>
            </div>
          )}

          {/* Scope */}
          <div>
            <label className="text-sm font-medium text-muted-foreground">Scope</label>
            <p className="mt-1 text-foreground">
              {policy.agentIds && policy.agentIds.length > 0
                ? `Selected agents (${policy.agentIds.length}): ${policy.agentIds.join(', ')}`
                : 'All agents'}
            </p>
          </div>

          {/* Configuration */}
          <div>
            <h4 className="text-lg font-semibold text-foreground mb-4">Configuration</h4>
            <div className="bg-muted/30 rounded-lg p-4 border border-border">
              <pre className="text-sm text-foreground/90 whitespace-pre-wrap">
                {JSON.stringify(policy.config, null, 2)}
              </pre>
            </div>
          </div>

          {/* Metadata */}
          <div>
            <h4 className="text-lg font-semibold text-foreground mb-4">Metadata</h4>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Created</label>
                <p className="mt-1 text-foreground">{formatDate(policy.createdAt)}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Last Updated</label>
                <p className="mt-1 text-foreground">{formatDate(policy.updatedAt)}</p>
              </div>
              {policy.createdBy && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Created By</label>
                  <p className="mt-1 text-foreground">{policy.createdBy}</p>
                </div>
              )}
              {policy.lastViolation && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Last Violation</label>
                  <p className="mt-1 text-foreground">{formatDate(policy.lastViolation)}</p>
                </div>
              )}
            </div>
          </div>

          {/* Raw JSON Data (Expandable) */}
          <div className="border-t border-border pt-4">
            <button
              onClick={() => setShowJson(!showJson)}
              className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors w-full"
            >
              {showJson ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
              <span className="text-sm font-medium">View Raw JSON Data</span>
            </button>
            {showJson && (
              <div className="mt-4 bg-muted/30 rounded-lg p-4 border border-border">
                <pre className="text-xs text-foreground/90 overflow-x-auto">
                  {JSON.stringify(policy, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end p-6 border-t border-border sticky bottom-0 bg-card">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-secondary text-foreground/90 rounded-lg hover:bg-accent transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}

