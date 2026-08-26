import { useRef, useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { Policy } from '@/types/policy'
import { getPolicyTypeIcon, getPolicyTypeLabel, getSeverityColorLight } from '@/utils/policyUtils'
import Modal, { ModalHeader, ModalFooter } from '@/components/ui/Modal'

interface PolicyDetailsModalProps {
  isOpen: boolean
  policy: Policy | null
  onClose: () => void
}

export default function PolicyDetailsModal({ isOpen, policy, onClose }: PolicyDetailsModalProps) {
  const [showJson, setShowJson] = useState(false)

  // The caller clears `policy` to null in the same click handler that sets
  // isOpen=false (see pages/Policies.tsx's onClose), so both land in the
  // same React batch. Modal.tsx plays a ~150ms exit animation driven by its
  // own `open` prop and expects to still have content to render while it
  // fades out — bailing out here on `!policy` would unmount it instantly
  // instead, skipping the animation. Remembering the last real policy keeps
  // the closing dialog showing what it was showing a moment ago.
  const lastPolicyRef = useRef<Policy | null>(null)
  if (policy) lastPolicyRef.current = policy
  const displayPolicy = policy ?? lastPolicyRef.current

  if (!displayPolicy) return null
  const policyData = displayPolicy

  const Icon = getPolicyTypeIcon(policyData.type)
  const severityColor = getSeverityColorLight(policyData.severity)

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
    <Modal
      open={isOpen}
      onClose={onClose}
      size="xl"
      label={policyData.name}
      header={
        <ModalHeader
          title={
            <span className="flex items-center gap-3">
              <span className={`p-2 rounded-lg ${severityColor.bg}`}>
                <Icon className={`h-6 w-6 ${severityColor.icon}`} />
              </span>
              {policyData.name}
            </span>
          }
          hint={getPolicyTypeLabel(policyData.type)}
          onClose={onClose}
        />
      }
      footer={
        <ModalFooter>
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
        </ModalFooter>
      }
    >
        <div className="space-y-6">
          {/* Basic Information */}
          <div>
            <h4 className="text-lg font-semibold text-foreground mb-4">Basic Information</h4>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Status</label>
                <p className="mt-1">
                  {policyData.enabled ? (
                    <span className="badge badge-success">Active</span>
                  ) : (
                    <span className="badge bg-secondary text-muted-foreground">Inactive</span>
                  )}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Severity</label>
                <p className="mt-1">
                  <span className={`badge ${severityColor.badge}`}>{policyData.severity}</span>
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Priority</label>
                <p className="mt-1 text-foreground font-medium">{policyData.priority}</p>
              </div>
              {policyData.violations !== undefined && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Violations</label>
                  <p className="mt-1 text-foreground font-medium">{policyData.violations}</p>
                </div>
              )}
            </div>
          </div>

          {/* Description */}
          {policyData.description && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">Description</label>
              <p className="mt-1 text-foreground">{policyData.description}</p>
            </div>
          )}

          {/* Scope */}
          <div>
            <label className="text-sm font-medium text-muted-foreground">Scope</label>
            <p className="mt-1 text-foreground">
              {policyData.agentIds && policyData.agentIds.length > 0
                ? `Selected agents (${policyData.agentIds.length}): ${policyData.agentIds.join(', ')}`
                : 'All agents'}
            </p>
          </div>

          {/* Configuration */}
          <div>
            <h4 className="text-lg font-semibold text-foreground mb-4">Configuration</h4>
            <div className="bg-muted/30 rounded-lg p-4 border border-border">
              <pre className="text-sm text-foreground/90 whitespace-pre-wrap">
                {JSON.stringify(policyData.config, null, 2)}
              </pre>
            </div>
          </div>

          {/* Metadata */}
          <div>
            <h4 className="text-lg font-semibold text-foreground mb-4">Metadata</h4>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Created</label>
                <p className="mt-1 text-foreground">{formatDate(policyData.createdAt)}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Last Updated</label>
                <p className="mt-1 text-foreground">{formatDate(policyData.updatedAt)}</p>
              </div>
              {policyData.createdBy && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Created By</label>
                  <p className="mt-1 text-foreground">{policyData.createdBy}</p>
                </div>
              )}
              {policyData.lastViolation && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Last Violation</label>
                  <p className="mt-1 text-foreground">{formatDate(policyData.lastViolation)}</p>
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
                  {JSON.stringify(policyData, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
    </Modal>
  )
}

