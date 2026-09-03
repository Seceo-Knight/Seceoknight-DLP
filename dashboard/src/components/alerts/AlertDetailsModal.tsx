import { useEffect, useRef, useState } from 'react'
import { getEvent } from '@/lib/api'
import LoadingSpinner from '../LoadingSpinner'
import { cn, formatAgentLabel } from '@/lib/utils'
import { tone } from '@/lib/tone'
import Modal, { ModalHeader, ModalFooter } from '@/components/ui/Modal'

interface AlertDetailsModalProps {
  alert: any
  isOpen: boolean
  onClose: () => void
}

export default function AlertDetailsModal({ alert: rawAlert, isOpen, onClose }: AlertDetailsModalProps) {
  const [eventData, setEventData] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Alerts.tsx clears its `selectedAlert` state in the same click handler
  // that flips isOpen=false, so both land in the same React batch. Modal.tsx
  // plays a ~150ms exit animation driven by its own `open` prop and expects
  // to still have content while it fades out -- remembering the last real
  // alert keeps the closing dialog showing what it was showing a moment ago
  // instead of going blank mid-animation.
  const lastAlertRef = useRef<any>(null)
  if (rawAlert) lastAlertRef.current = rawAlert
  const alert = rawAlert ?? lastAlertRef.current

  useEffect(() => {
    if (isOpen && alert) {
      fetchEventData()
    }
  }, [isOpen, alert])

  const fetchEventData = async () => {
    if (!alert?.event_id) {
      // If no event_id, use the alert data itself
      setEventData(alert)
      return
    }

    setLoading(true)
    setError(null)
    try {
      const data = await getEvent(alert.event_id)
      setEventData(data)
    } catch (err: any) {
      console.error('Failed to fetch event data:', err)
      // Fallback to showing the alert data itself
      setEventData(alert)
    } finally {
      setLoading(false)
    }
  }

  if (!alert) return null

  return (
    <Modal
      open={isOpen}
      onClose={onClose}
      size="2xl"
      label="Alert Details"
      header={
        <ModalHeader
          title="Alert Details"
          hint={
            <>
              Alert ID: <code className="bg-secondary px-2 py-0.5 rounded">{alert.id}</code>
            </>
          }
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
          {/* Content */}
          <div>
            {/* Alert Summary */}
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-foreground/90 mb-3">Alert Summary</h3>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-muted-foreground">Severity:</span>
                  <span
                    className={cn(
                      'badge',
                      alert.severity === 'critical'
                        ? 'badge-danger'
                        : alert.severity === 'high'
                        ? 'badge-warning'
                        : alert.severity === 'medium'
                        ? 'badge-info'
                        : 'badge-success'
                    )}
                  >
                    {alert.severity}
                  </span>
                </div>
                <div>
                  <span className="font-medium text-muted-foreground">Title:</span>
                  <span className="ml-2">{alert.title}</span>
                </div>
                <div>
                  <span className="font-medium text-muted-foreground">Description:</span>
                  <span className="ml-2">{alert.description}</span>
                </div>
                <div>
                  <span className="font-medium text-muted-foreground">Created:</span>
                  <span className="ml-2">{new Date(alert.created_at).toLocaleString()}</span>
                </div>
                <div>
                  <span className="font-medium text-muted-foreground">Agent:</span>
                  <span
                    className="ml-2"
                    title={eventData?.agent_id || alert.agent_id}
                  >
                    {formatAgentLabel(
                      eventData?.agent_name,
                      eventData?.agent_code,
                    )}
                  </span>
                </div>
                {(eventData?.user_email || alert.user_email) &&
                  (eventData?.user_email || alert.user_email) !== 'agent@system' && (
                  <div>
                    <span className="font-medium text-muted-foreground">User:</span>
                    <span className="ml-2">{eventData?.user_email || alert.user_email}</span>
                  </div>
                )}
                <div>
                  <span className="font-medium text-muted-foreground">Event ID:</span>
                  <span className="ml-2 font-mono text-xs">{alert.event_id}</span>
                </div>
              </div>
            </div>

            {/* Classification Details */}
            {(alert.classification_category || alert.classification_level || alert.classification_rules_matched?.length > 0) && (
              <div className="mb-6 rounded-lg border border-primary/20 bg-primary/5 p-4">
                <h3 className="mb-3 text-sm font-semibold text-foreground">Classification Details</h3>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <span className="font-medium text-muted-foreground">Category:</span>
                    <span className={cn(
                      'ml-2 rounded px-2 py-0.5 text-xs font-bold uppercase',
                      (alert.classification_category || alert.classification_level) === 'Restricted' ? 'bg-critical/15 text-critical' :
                      (alert.classification_category || alert.classification_level) === 'Confidential' ? 'bg-warning/15 text-warning' :
                      (alert.classification_category || alert.classification_level) === 'Internal' ? 'bg-warning/10 text-warning' :
                      'bg-success/15 text-success'
                    )}>
                      {alert.classification_category || alert.classification_level || 'Public'}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-muted-foreground">Confidence:</span>
                    <span className="ml-2 font-bold text-foreground">{((alert.classification_score || 0) * 100).toFixed(0)}%</span>
                  </div>
                  <div>
                    <span className="font-medium text-muted-foreground">Action:</span>
                    <span className={cn(
                      'ml-2 rounded px-2 py-0.5 text-xs font-medium uppercase',
                      alert.action_taken === 'block' ? 'bg-critical/15 text-critical' :
                      alert.action_taken === 'alert' ? 'bg-warning/10 text-warning' :
                      'bg-success/15 text-success'
                    )}>
                      {alert.action_taken || 'allowed'}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-muted-foreground">Blocked:</span>
                    <span className={cn(
                      'ml-2 rounded px-2 py-0.5 text-xs font-medium',
                      alert.blocked ? 'bg-critical/15 text-critical' : 'bg-success/15 text-success'
                    )}>
                      {alert.blocked ? 'Yes' : 'No'}
                    </span>
                  </div>
                </div>
                {alert.classification_rules_matched && alert.classification_rules_matched.length > 0 && (
                  <div className="mt-3">
                    <span className="text-sm font-medium text-muted-foreground">Matched Rules:</span>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {alert.classification_rules_matched.map((rule: string, idx: number) => (
                        <span key={idx} className={cn('rounded-full px-2 py-0.5 text-xs font-medium border', tone('purple'))}>
                          {rule}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {alert.detected_content && (
                  <div className="mt-3">
                    <span className="text-sm font-medium text-muted-foreground">Detected Content:</span>
                    <pre className="mt-1 rounded border border-border bg-card p-2 text-xs text-foreground/90 whitespace-pre-wrap">{alert.detected_content}</pre>
                  </div>
                )}
              </div>
            )}

            {/* Raw Event Log */}
            <div>
              <h3 className="text-sm font-semibold text-foreground/90 mb-3">Raw Event Log</h3>

              {loading && (
                <div className="flex justify-center py-8">
                  <LoadingSpinner size="md" />
                </div>
              )}

              {error && (
                <div className="rounded-lg border border-critical/30 bg-critical/10 p-4">
                  <p className="text-sm text-critical">{error}</p>
                </div>
              )}

              {!loading && !error && eventData && (
                <div className="bg-muted/30 rounded-lg p-4 overflow-x-auto">
                  <pre className="text-xs text-foreground font-mono whitespace-pre-wrap break-words">
                    {JSON.stringify(eventData, null, 2)}
                  </pre>
                </div>
              )}

              {!loading && !error && !eventData && (
                <div className="rounded-lg border border-warning/30 bg-warning/10 p-4">
                  <p className="text-sm text-warning">No event data available</p>
                </div>
              )}
            </div>
          </div>
    </Modal>
  )
}
