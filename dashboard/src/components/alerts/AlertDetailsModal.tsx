import { X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { getEvent } from '@/lib/api'
import LoadingSpinner from '../LoadingSpinner'
import { cn, formatAgentLabel } from '@/lib/utils'

interface AlertDetailsModalProps {
  alert: any
  isOpen: boolean
  onClose: () => void
}

export default function AlertDetailsModal({ alert, isOpen, onClose }: AlertDetailsModalProps) {
  const [eventData, setEventData] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

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

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black bg-opacity-50 transition-opacity"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="relative w-full max-w-4xl bg-card rounded-lg shadow-xl">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-border">
            <div>
              <h2 className="text-xl font-semibold text-foreground">Alert Details</h2>
              <p className="text-sm text-muted-foreground mt-1">
                Alert ID: <code className="bg-secondary px-2 py-0.5 rounded">{alert.id}</code>
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-accent rounded-lg transition-colors"
            >
              <X className="h-5 w-5 text-muted-foreground" />
            </button>
          </div>

          {/* Content */}
          <div className="px-6 py-4 max-h-[600px] overflow-y-auto">
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
                <div>
                  <span className="font-medium text-muted-foreground">Event ID:</span>
                  <span className="ml-2 font-mono text-xs">{alert.event_id}</span>
                </div>
              </div>
            </div>

            {/* Classification Details */}
            {(alert.classification_category || alert.classification_level || alert.classification_rules_matched?.length > 0) && (
              <div className="mb-6 bg-purple-500/10 border border-purple-500/30 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-purple-300 mb-3">Classification Details</h3>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <span className="font-medium text-muted-foreground">Category:</span>
                    <span className={cn(
                      'ml-2 px-2 py-0.5 rounded text-xs font-bold uppercase',
                      (alert.classification_category || alert.classification_level) === 'Restricted' ? 'bg-red-500/15 text-red-300' :
                      (alert.classification_category || alert.classification_level) === 'Confidential' ? 'bg-orange-500/15 text-orange-300' :
                      (alert.classification_category || alert.classification_level) === 'Internal' ? 'bg-yellow-500/15 text-yellow-300' :
                      'bg-green-500/15 text-green-300'
                    )}>
                      {alert.classification_category || alert.classification_level || 'Public'}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-muted-foreground">Confidence:</span>
                    <span className="ml-2 font-bold">{((alert.classification_score || 0) * 100).toFixed(0)}%</span>
                  </div>
                  <div>
                    <span className="font-medium text-muted-foreground">Action:</span>
                    <span className={cn(
                      'ml-2 px-2 py-0.5 rounded text-xs font-medium uppercase',
                      alert.action_taken === 'block' ? 'bg-red-500/15 text-red-300' :
                      alert.action_taken === 'alert' ? 'bg-yellow-500/15 text-yellow-300' :
                      'bg-green-500/15 text-green-300'
                    )}>
                      {alert.action_taken || 'allowed'}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-muted-foreground">Blocked:</span>
                    <span className={cn(
                      'ml-2 px-2 py-0.5 rounded text-xs font-medium',
                      alert.blocked ? 'bg-red-500/15 text-red-300' : 'bg-green-500/15 text-green-300'
                    )}>
                      {alert.blocked ? 'Yes' : 'No'}
                    </span>
                  </div>
                </div>
                {alert.classification_rules_matched && alert.classification_rules_matched.length > 0 && (
                  <div className="mt-3">
                    <span className="font-medium text-muted-foreground text-sm">Matched Rules:</span>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {alert.classification_rules_matched.map((rule: string, idx: number) => (
                        <span key={idx} className="px-2 py-0.5 rounded-full text-xs font-medium bg-purple-500/15 text-purple-300">
                          {rule}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {alert.detected_content && (
                  <div className="mt-3">
                    <span className="font-medium text-muted-foreground text-sm">Detected Content:</span>
                    <pre className="mt-1 text-xs text-foreground/90 bg-card rounded p-2 border border-border whitespace-pre-wrap">{alert.detected_content}</pre>
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
                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                  <p className="text-sm text-red-300">{error}</p>
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
                <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                  <p className="text-sm text-yellow-300">No event data available</p>
                </div>
              )}
            </div>
          </div>

          {/* Footer */}
          <div className="flex justify-end gap-3 px-6 py-4 border-t border-border">
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-foreground/90 bg-card border border-border rounded-lg hover:bg-accent transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
