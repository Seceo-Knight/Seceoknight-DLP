import { useState, useMemo, useEffect } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import {
  Search, Filter, FileText, Shield, AlertTriangle, Ban, ArrowRight, File, HardDrive, Usb,
  ChevronDown, ChevronUp, Trash2, Clipboard, Eye, Bell, Download, RefreshCcw, Loader2, Move, Copy,
  FilePlus, FileEdit, FileX, ArrowUpDown, ListFilter,
} from 'lucide-react'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { searchEvents, getAgents, clearAllEvents, triggerGoogleDrivePoll, triggerOneDrivePoll, getPolicies, type Event, type Agent } from '@/lib/api'
import { formatDate, cn, truncate, formatDateTimeIST, formatAgentLabel } from '@/lib/utils'
import { PageHeader } from '@/components/ui/page-header'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge, severityToVariant } from '@/components/ui/badge'
import { EmptyState } from '@/components/ui/empty-state'
import { DataPagination } from '@/components/ui/pagination'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useTableSort, usePagination } from '@/lib/hooks/useTableState'
import { tone, surfaceBox, innerBox, labelCls, type Tone } from '@/lib/tone'
import toast from 'react-hot-toast'

// Event Detail Modal Component
function EventDetailModal({
  event,
  onClose,
  isBlockedTransfer,
  formatFileSize,
  getDriveLetter,
}: {
  event: any
  onClose: () => void
  isBlockedTransfer: boolean
  formatFileSize: (bytes: number) => string
  getDriveLetter: (path: string) => string
}) {
  const [showRawData, setShowRawData] = useState(false)

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'blocked': return <Ban className="w-4 h-4" />
      case 'alerted': return <Bell className="w-4 h-4" />
      case 'quarantined': return <Download className="w-4 h-4" />
      default: return <Eye className="w-4 h-4" />
    }
  }

  const getEventSubtypeIcon = (subtype: string) => {
    const normalized = subtype?.toLowerCase() || ''
    if (normalized.includes('created')) return <FilePlus className="w-4 h-4" />
    if (normalized.includes('modified') || normalized.includes('updated')) return <FileEdit className="w-4 h-4" />
    if (normalized.includes('deleted')) return <FileX className="w-4 h-4" />
    if (normalized.includes('moved') || normalized.includes('renamed')) return <Move className="w-4 h-4" />
    if (normalized.includes('copied')) return <Copy className="w-4 h-4" />
    return <File className="w-4 h-4" />
  }

  const getEventSubtypeTone = (subtype: string): Tone => {
    const normalized = subtype?.toLowerCase() || ''
    if (normalized.includes('created')) return 'green'
    if (normalized.includes('modified') || normalized.includes('updated')) return 'blue'
    if (normalized.includes('deleted')) return 'red'
    if (normalized.includes('moved') || normalized.includes('renamed')) return 'orange'
    if (normalized.includes('copied')) return 'purple'
    return 'gray'
  }

  const getEventSubtypeLabel = (subtype: string, changeType?: string) => {
    if (!subtype) return 'File Activity'
    const normalized = subtype.toLowerCase()
    if (normalized.includes('created')) return 'File Created'
    if (normalized.includes('modified') || normalized.includes('updated')) return 'File Modified'
    if (normalized.includes('deleted')) return 'File Deleted'
    if (normalized.includes('moved')) return 'File Moved'
    if (normalized.includes('renamed')) return 'File Renamed'
    if (normalized.includes('copied')) return 'File Copied'
    if (changeType) return changeType.charAt(0).toUpperCase() + changeType.slice(1)
    return 'File Activity'
  }

  const severityTone: Tone = event.severity === 'critical' ? 'red' : event.severity === 'high' ? 'orange' : event.severity === 'medium' ? 'yellow' : 'green'

  const rawDataToggle = (
    <div className="border-t border-border pt-4">
      <button
        onClick={() => setShowRawData(!showRawData)}
        className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors w-full"
      >
        {showRawData ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        <span className="text-sm font-medium">View Raw Event Data</span>
      </button>
      {showRawData && (
        <div className={cn(surfaceBox, 'mt-4 p-4')}>
          <pre className="text-xs text-muted-foreground overflow-x-auto">{JSON.stringify(event, null, 2)}</pre>
        </div>
      )}
    </div>
  )

  if (isBlockedTransfer) {
    const blocked = event.blocked !== false
    const sourcePath = event.file_path || ''
    const destPath = event.destination || ''
    const fileName = event.file_name || sourcePath.split(/[/\\]/).pop() || 'Unknown'
    const fileSize = event.file_size ? formatFileSize(event.file_size) : 'Unknown size'
    const driveLetter = getDriveLetter(destPath)

    return (
      <Dialog open onOpenChange={(o) => !o && onClose()}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <div className="flex items-center gap-4">
              <div className={cn('p-3 rounded-xl border', blocked ? tone('red') : tone('orange'))}>
                <Shield className="w-8 h-8" />
              </div>
              <div>
                <DialogTitle className="text-2xl">
                  {blocked ? 'File Transfer Blocked' : 'Transfer Attempt Detected'}
                </DialogTitle>
                <p className="text-muted-foreground text-sm mt-1">{formatDateTimeIST(event.timestamp)}</p>
              </div>
            </div>
          </DialogHeader>

          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <span className={cn('inline-flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium', blocked ? tone('green') : tone('red'))}>
                <Ban className="w-4 h-4" />
                {blocked ? 'Successfully Blocked' : 'Block Failed'}
              </span>
              <span className={cn('inline-flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium uppercase', tone(severityTone))}>
                {event.severity}
              </span>
            </div>

            <div className={surfaceBox}>
              <div className="flex items-center justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <File className="w-5 h-5 text-info" />
                    <label className="text-sm text-muted-foreground uppercase font-medium">Source</label>
                  </div>
                  <div className={innerBox}>
                    <p className="text-foreground font-semibold text-lg mb-1">{fileName}</p>
                    <p className="text-muted-foreground text-sm font-mono truncate" title={sourcePath}>{sourcePath}</p>
                    <p className="text-muted-foreground text-xs mt-2">{fileSize}</p>
                  </div>
                </div>

                <div className="flex flex-col items-center gap-2">
                  <ArrowRight className="w-6 h-6 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground font-medium">Copied to</span>
                </div>

                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <HardDrive className="w-5 h-5 text-critical" />
                    <label className="text-sm text-muted-foreground uppercase font-medium">Destination</label>
                  </div>
                  <div className={cn(innerBox, 'border-critical/30')}>
                    <div className="flex items-center gap-2 mb-1">
                      <Usb className="w-4 h-4 text-critical" />
                      <p className="text-critical font-semibold">{driveLetter || 'Destination'}</p>
                    </div>
                    <p className="text-muted-foreground text-sm font-mono truncate" title={destPath}>{destPath}</p>
                    <p className="text-critical text-xs mt-2 font-medium">Blocked</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className={innerBox}>
                <label className={labelCls}>Agent</label>
                <p className="text-foreground font-medium" title={event.agent_id}>
                  {formatAgentLabel(event.agent_name, event.agent_code, null, event.agent_id)}
                </p>
              </div>
              <div className={innerBox}>
                <label className={labelCls}>User</label>
                <p className="text-foreground font-medium">{event.user_email}</p>
              </div>
              <div className={innerBox}>
                <label className={labelCls}>Transfer Type</label>
                <p className="text-foreground font-medium capitalize">{event.transfer_type || 'File Transfer'}</p>
              </div>
              <div className={innerBox}>
                <label className={labelCls}>Action Taken</label>
                <p className="text-foreground font-medium capitalize">{event.action_taken || event.action || 'Blocked'}</p>
              </div>
            </div>

            {event.file_hash && (
              <div className={innerBox}>
                <label className={cn(labelCls, 'mb-2')}>File Hash (SHA256)</label>
                <p className="text-muted-foreground font-mono text-xs break-all">{event.file_hash}</p>
              </div>
            )}

            {rawDataToggle}
          </div>
        </DialogContent>
      </Dialog>
    )
  }

  const eventType = event.event_type?.toLowerCase() || 'file'
  const isClipboard = eventType === 'clipboard'
  const isFile = eventType === 'file' && !isBlockedTransfer

  const displayContent = isClipboard
    ? (event.clipboard_content || event.content || '')
    : (event.content || event.content_redacted || '')

  const classificationLabels = event.classification_labels || []
  const classification = event.classification || []
  const matchedPolicies = event.matched_policies || []

  const fileName = event.file_name || (event.file_path ? event.file_path.split(/[/\\]/).pop() : 'Unknown')
  const fileSize = event.file_size ? formatFileSize(event.file_size) : null
  const fileExtension = fileName?.includes('.') ? fileName.split('.').pop()?.toUpperCase() : null

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <div className="flex items-center gap-4">
            <div className={cn('p-3 rounded-xl border', tone(severityTone))}>
              {isClipboard ? <Clipboard className="w-8 h-8" /> : <File className="w-8 h-8" />}
            </div>
            <div>
              <DialogTitle className="text-2xl">
                {isClipboard ? 'Clipboard Violation' : isFile ? (
                  event.event_subtype ? (
                    <>
                      {getEventSubtypeLabel(event.event_subtype, event.details?.change_type)}
                      {fileName && fileName !== 'Unknown' && (
                        <span className="text-muted-foreground font-normal">: {fileName}</span>
                      )}
                    </>
                  ) : event.description || (fileName ? `File Event: ${fileName}` : 'File Event')
                ) : 'Event Details'}
              </DialogTitle>
              <p className="text-muted-foreground text-sm mt-1">{formatDateTimeIST(event.timestamp)}</p>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-6">
          <div className="flex items-center gap-3 flex-wrap">
            {event.event_subtype && (event.source === 'onedrive_cloud' || event.source === 'google_drive_cloud') && (
              <span className={cn('inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border text-base font-semibold', tone(getEventSubtypeTone(event.event_subtype)))}>
                {getEventSubtypeIcon(event.event_subtype)}
                {getEventSubtypeLabel(event.event_subtype, event.details?.change_type)}
              </span>
            )}
            <span className={cn('inline-flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium uppercase', tone(severityTone))}>
              {event.severity}
            </span>
            <span className={cn(
              'inline-flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium',
              event.action_taken === 'blocked' ? tone('red') :
              event.action_taken === 'alerted' ? tone('yellow') :
              (event.action_taken === 'quarantined' || event.quarantined) ? tone('blue') : tone('gray'),
            )}>
              {getActionIcon(event.action_taken || event.action || (event.quarantined ? 'quarantined' : 'logged'))}
              {event.action_taken || (event.quarantined ? 'quarantined' : event.action) || 'Logged'}
            </span>
            {event.quarantined && (
              <span className={cn('inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-medium uppercase', tone('blue'))}>
                <Download className="w-3 h-3" />
                Quarantined
              </span>
            )}
          </div>

          {(event.source === 'onedrive_cloud' || event.source === 'google_drive_cloud') && event.event_subtype && (
            <div className={cn(surfaceBox, 'bg-primary/5 border-primary/20')}>
              <div className="flex items-center gap-3 mb-4">
                <div className={cn('p-2 rounded-lg border', tone(getEventSubtypeTone(event.event_subtype)))}>
                  {getEventSubtypeIcon(event.event_subtype)}
                </div>
                <label className="text-sm text-foreground uppercase font-semibold">Activity Details</label>
              </div>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Action Performed</label>
                    <div className={cn('inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium', tone(getEventSubtypeTone(event.event_subtype)))}>
                      {getEventSubtypeIcon(event.event_subtype)}
                      {getEventSubtypeLabel(event.event_subtype, event.details?.change_type)}
                    </div>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Timestamp</label>
                    <p className="text-foreground font-medium">{formatDateTimeIST(event.timestamp)}</p>
                  </div>
                </div>
                {event.user_email && event.user_email !== 'unknown@onedrive' && (
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Performed By</label>
                    <p className="text-foreground font-medium">{event.user_email}</p>
                  </div>
                )}
                {event.details?.change_type && (
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Change Type</label>
                    <p className="text-foreground font-mono text-sm bg-card px-3 py-1.5 rounded border border-border inline-block">
                      {event.details.change_type}
                    </p>
                  </div>
                )}
                {(event.event_subtype?.includes('moved') || event.event_subtype?.includes('renamed')) && event.details?.raw_delta_item && (
                  <div className={innerBox}>
                    <label className="text-xs text-muted-foreground mb-2 block uppercase font-medium">Additional Context</label>
                    {event.details.raw_delta_item.parentReference && (
                      <div className="space-y-2">
                        <div>
                          <span className="text-xs text-muted-foreground">Current Location: </span>
                          <span className="text-foreground font-mono text-sm">{event.details.raw_delta_item.parentReference.path || 'Root'}</span>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {isClipboard && displayContent && (
            <div className={surfaceBox}>
              <div className="flex items-center gap-2 mb-4">
                <Clipboard className="w-5 h-5 text-info" />
                <label className="text-sm text-muted-foreground uppercase font-medium">Clipboard Content</label>
              </div>
              <div className={innerBox}>
                <p className="text-foreground font-mono text-sm whitespace-pre-wrap break-words">{displayContent}</p>
              </div>
            </div>
          )}

          {isFile && (
            <>
              <div className={surfaceBox}>
                <div className="flex items-center gap-2 mb-4">
                  <File className="w-5 h-5 text-info" />
                  <label className="text-sm text-muted-foreground uppercase font-medium">File Information</label>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">File Name</label>
                    <p className="text-foreground font-semibold text-lg">{fileName}</p>
                  </div>
                  {event.file_path && (
                    <div>
                      <label className="text-xs text-muted-foreground mb-1 block">File Path</label>
                      <p className="text-foreground font-mono text-sm break-all">{event.file_path}</p>
                    </div>
                  )}
                  <div className="grid grid-cols-3 gap-4">
                    {fileSize && (
                      <div>
                        <label className="text-xs text-muted-foreground mb-1 block">Size</label>
                        <p className="text-foreground font-medium">{fileSize}</p>
                      </div>
                    )}
                    {fileExtension && (
                      <div>
                        <label className="text-xs text-muted-foreground mb-1 block">Extension</label>
                        <p className="text-foreground font-medium">.{fileExtension}</p>
                      </div>
                    )}
                    {event.file_hash && (
                      <div>
                        <label className="text-xs text-muted-foreground mb-1 block">Hash (SHA256)</label>
                        <p className="text-foreground font-mono text-xs break-all" title={event.file_hash}>
                          {event.file_hash.substring(0, 16)}...
                        </p>
                      </div>
                    )}
                    {event.quarantined && event.quarantine_path && (
                      <div className="col-span-3">
                        <label className={cn(labelCls, 'text-info')}>Quarantine Path</label>
                        <p className="text-info font-mono text-xs break-all">{event.quarantine_path}</p>
                        {event.quarantine_timestamp && (
                          <p className="text-info/80 text-xs mt-1">Quarantined at: {formatDateTimeIST(event.quarantine_timestamp)}</p>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {displayContent && (
                <div className={surfaceBox}>
                  <div className="flex items-center gap-2 mb-4">
                    <Eye className="w-5 h-5 text-violet-400" />
                    <label className="text-sm text-muted-foreground uppercase font-medium">Content That Triggered Violation</label>
                  </div>
                  <div className={cn(innerBox, 'max-h-64 overflow-y-auto')}>
                    <pre className="text-foreground font-mono text-xs whitespace-pre-wrap break-words">
                      {displayContent.length > 2000 ? displayContent.substring(0, 2000) + '\n\n... (truncated)' : displayContent}
                    </pre>
                  </div>
                </div>
              )}
            </>
          )}

          {(event.classification_level || event.classification_score) && (
            <div className={cn(surfaceBox, 'bg-primary/5 border-primary/20')}>
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-5 h-5 text-primary" />
                <label className="text-sm text-foreground uppercase font-semibold">Classification Result</label>
              </div>
              <div className="grid grid-cols-2 gap-4">
                {event.classification_level && (
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Classification Level</label>
                    <span className={cn(
                      'inline-flex items-center gap-2 px-4 py-2 rounded-lg border text-base font-bold',
                      event.classification_level === 'Restricted' ? tone('red') :
                      event.classification_level === 'Confidential' ? tone('orange') :
                      event.classification_level === 'Internal' ? tone('yellow') : tone('green'),
                    )}>
                      {event.classification_level}
                    </span>
                  </div>
                )}
                {event.classification_score != null && event.classification_score > 0 && (
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Confidence Score</label>
                    <p className="text-2xl font-bold text-foreground">{Math.round(event.classification_score * 100)}%</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {classificationLabels.length > 0 && (
            <div className={surfaceBox}>
              <div className="flex items-center gap-2 mb-4">
                <AlertTriangle className="w-5 h-5 text-warning" />
                <label className="text-sm text-muted-foreground uppercase font-medium">Detected Sensitive Data</label>
              </div>
              <div className="flex flex-wrap gap-2">
                {classificationLabels.map((label: string, idx: number) => {
                  const conf = classification[idx]?.confidence || event.classification_score || 1.0
                  return (
                    <span key={idx} className={cn('inline-flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium', tone('red'))}>
                      <Shield className="w-4 h-4" />
                      {label}
                      {conf < 1.0 && <span className="text-xs opacity-75">({Math.round(conf * 100)}%)</span>}
                    </span>
                  )
                })}
              </div>
            </div>
          )}

          {matchedPolicies.length > 0 && (
            <div className={surfaceBox}>
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-5 h-5 text-primary" />
                <label className="text-sm text-muted-foreground uppercase font-medium">Matched Policies</label>
              </div>
              <div className="space-y-3">
                {matchedPolicies.map((policy: any, idx: number) => (
                  <div key={idx} className={innerBox}>
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <p className="text-foreground font-semibold">{policy.policy_name || 'Unknown Policy'}</p>
                        {policy.matched_rules && policy.matched_rules.length > 0 && (
                          <div className="mt-2 space-y-1">
                            <p className="text-xs text-muted-foreground">Matched Rules:</p>
                            {policy.matched_rules.map((rule: any, ruleIdx: number) => (
                              <p key={ruleIdx} className="text-xs text-muted-foreground font-mono ml-2">
                                • {rule.field} {rule.operator} {Array.isArray(rule.value) ? rule.value.join(', ') : rule.value}
                              </p>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <span className={cn(
                          'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
                          policy.severity === 'critical' ? 'bg-critical/15 text-critical' :
                          policy.severity === 'high' ? 'bg-warning/15 text-warning' : 'bg-warning/10 text-warning',
                        )}>
                          {policy.severity}
                        </span>
                        {policy.priority && <span className="text-xs text-muted-foreground">Priority: {policy.priority}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div className={innerBox}>
              <label className={labelCls}>Event Type</label>
              <p className="text-foreground font-medium capitalize">
                {event.event_subtype ? event.event_subtype.replace(/_/g, ' ') : event.event_type}
              </p>
            </div>
            <div className={innerBox}>
              <label className={labelCls}>User</label>
              <p className="text-foreground font-medium">{event.user_email}</p>
            </div>
            <div className={innerBox}>
              <label className={labelCls}>Agent</label>
              <p className="text-foreground font-medium" title={event.agent_id}>
                {formatAgentLabel(event.agent_name, event.agent_code)}
              </p>
            </div>
            <div className={innerBox}>
              <label className={labelCls}>Description</label>
              <p className="text-foreground font-medium text-sm">{event.description || 'N/A'}</p>
            </div>
          </div>

          {rawDataToggle}
        </div>
      </DialogContent>
    </Dialog>
  )
}

export default function Events() {
  const [searchParams, setSearchParams] = useSearchParams()
  const agentParam = searchParams.get('agent')

  const dashboardFilters = useMemo(() => {
    const get = (k: string) => searchParams.get(k) || undefined
    return {
      module: get('module'),
      event_type: get('event_type'),
      classification: get('classification'),
      action: get('action'),
      severity: get('severity'),
      channel: get('channel'),
      start_date: get('start_date'),
      end_date: get('end_date'),
      time_range: get('time_range'),
    }
  }, [searchParams])

  const activeDashboardFilters = useMemo(
    () => Object.entries(dashboardFilters).filter(([, v]) => !!v),
    [dashboardFilters],
  )

  const [kqlQuery, setKqlQuery] = useState('')
  const [activeQuery, setActiveQuery] = useState(agentParam || '')
  const [showFilters, setShowFilters] = useState(false)
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)
  const [isRefreshing, setIsRefreshing] = useState(false)

  useEffect(() => {
    if (agentParam) {
      setActiveQuery(agentParam)
      setKqlQuery(agentParam)
    }
  }, [agentParam])

  const { data: agentsData } = useQuery({
    queryKey: ['agents'],
    queryFn: getAgents,
    refetchInterval: 30000,
  })

  const agentMap = useMemo(() => {
    const map = new Map<string, { name: string; agent_code?: number }>()
    if (agentsData && Array.isArray(agentsData)) {
      agentsData.forEach((agent: Agent) => {
        if (agent?.agent_id && agent?.name) {
          map.set(agent.agent_id, { name: agent.name, agent_code: agent.agent_code })
        }
      })
    }
    return map
  }, [agentsData])

  const getEventAgentLabel = (event: Event): string => {
    const fallback = event.agent_id ? agentMap.get(event.agent_id) : undefined
    return formatAgentLabel(event.agent_name, event.agent_code ?? fallback?.agent_code, fallback?.name, event.agent_id)
  }

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
  }

  const isBlockedTransfer = (event: any): boolean => {
    if (event.event_type !== 'file') return false
    const hasTransferSubtype = event.event_subtype === 'transfer_blocked' || event.event_subtype === 'transfer_attempt'
    const hasTransferType = event.transfer_type === 'usb_copy'
    const hasDestination = event.destination && event.destination !== null
    const hasBlockedField = event.blocked === true || event.blocked === false
    const descriptionMatches = event.description?.toLowerCase().includes('transfer blocked') ||
      event.description?.toLowerCase().includes('file transfer')
    return event.file_path && (
      (hasTransferSubtype && hasDestination) ||
      (hasTransferType && hasDestination) ||
      (hasBlockedField && hasDestination && descriptionMatches)
    )
  }

  const getDriveLetter = (path: string): string => {
    if (!path) return ''
    const match = path.match(/^([A-Z]):/)
    return match ? match[1] + ':' : ''
  }

  const getEventSubtypeIcon = (subtype: string) => {
    const normalized = subtype?.toLowerCase() || ''
    if (normalized.includes('created')) return <FilePlus className="w-4 h-4" />
    if (normalized.includes('modified') || normalized.includes('updated')) return <FileEdit className="w-4 h-4" />
    if (normalized.includes('deleted')) return <FileX className="w-4 h-4" />
    if (normalized.includes('moved') || normalized.includes('renamed')) return <Move className="w-4 h-4" />
    if (normalized.includes('copied')) return <Copy className="w-4 h-4" />
    return <File className="w-4 h-4" />
  }

  const getEventSubtypeTone = (subtype: string): Tone => {
    const normalized = subtype?.toLowerCase() || ''
    if (normalized.includes('created')) return 'green'
    if (normalized.includes('modified') || normalized.includes('updated')) return 'blue'
    if (normalized.includes('deleted')) return 'red'
    if (normalized.includes('moved') || normalized.includes('renamed')) return 'orange'
    if (normalized.includes('copied')) return 'purple'
    return 'gray'
  }

  const getEventSubtypeLabel = (subtype: string, changeType?: string) => {
    if (!subtype) return 'File Activity'
    const normalized = subtype.toLowerCase()
    if (normalized.includes('created')) return 'File Created'
    if (normalized.includes('modified') || normalized.includes('updated')) return 'File Modified'
    if (normalized.includes('deleted')) return 'File Deleted'
    if (normalized.includes('moved')) return 'File Moved'
    if (normalized.includes('renamed')) return 'File Renamed'
    if (normalized.includes('copied')) return 'File Copied'
    if (changeType) return changeType.charAt(0).toUpperCase() + changeType.slice(1)
    return 'File Activity'
  }

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['events', activeQuery, dashboardFilters],
    queryFn: () => {
      const params: Record<string, any> = { limit: 100 }
      if (activeQuery) params.search = activeQuery
      for (const [k, v] of Object.entries(dashboardFilters)) {
        if (v) params[k] = v
      }
      return searchEvents(params)
    },
    refetchInterval: 15000,
  })

  const events = data?.events || []
  const total = data?.total || 0

  // Client-side sort + pagination over the fetched page. The Events feed
  // is a rich, semi-structured record (not uniform tabular columns), so
  // it keeps its expandable row-card layout rather than a literal
  // <table> — but it gets the same sort/paginate affordances a table
  // would have, which is the gap the earlier UI audit flagged.
  const { sorted, sortKey, direction, onSort } = useTableSort<Event>(events, 'timestamp')
  const { page, pageSize, pageRows, setPage, setPageSize } = usePagination<Event>(sorted, 20)

  const handleSearch = () => setActiveQuery(kqlQuery)
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSearch()
  }

  const handleClearLogs = async () => {
    if (!confirm('Are you sure you want to clear all events? This action cannot be undone.')) return
    try {
      const result = await clearAllEvents()
      toast.success(`Successfully cleared ${result.deleted_count} events`)
      refetch()
    } catch (error: any) {
      toast.error(extractErrorDetail(error, 'Failed to clear events'))
    }
  }

  const handleManualRefresh = async () => {
    setIsRefreshing(true)
    try {
      await refetch()

      let policies: any[] = []
      try {
        const policiesResponse = await getPolicies({ enabled_only: true })
        if (Array.isArray(policiesResponse)) {
          policies = policiesResponse
        } else if (policiesResponse && typeof policiesResponse === 'object' && 'data' in policiesResponse) {
          policies = Array.isArray(policiesResponse.data) ? policiesResponse.data : []
        } else {
          policies = []
        }
      } catch (error: any) {
        toast.error(`Failed to fetch policies: ${error?.message || 'Unknown error'}`)
        setIsRefreshing(false)
        return
      }

      if (policies.length === 0) {
        toast.success('Events refreshed. No cloud monitoring policies found.')
        setIsRefreshing(false)
        return
      }

      const hasGoogleDrivePolicies = policies.some((p: any) => p && p.type === 'google_drive_cloud_monitoring' && p.enabled === true)
      const hasOneDrivePolicies = policies.some((p: any) => p && p.type === 'onedrive_cloud_monitoring' && p.enabled === true)

      const pollingResults: string[] = []

      if (hasGoogleDrivePolicies) {
        try {
          const response = await triggerGoogleDrivePoll()
          if (response?.status === 'queued') pollingResults.push('Google Drive polling queued')
          else if (response?.status === 'skipped') pollingResults.push('Google Drive: no folders configured')
        } catch (error: any) {
          pollingResults.push(`Google Drive polling failed: ${error?.message || 'Unknown error'}`)
        }
      }

      if (hasOneDrivePolicies) {
        try {
          let response
          try {
            response = await triggerOneDrivePoll()
          } catch (axiosError: any) {
            const authData = localStorage.getItem('dlp-auth-v2')
            const token = authData ? JSON.parse(authData).state?.accessToken : null
            const fetchResponse = await fetch('/api/v1/onedrive/poll', {
              method: 'POST',
              headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            })
            response = await fetchResponse.json()
          }
          if (response?.status === 'queued') pollingResults.push('OneDrive polling queued')
          else if (response?.status === 'skipped') pollingResults.push('OneDrive: no folders configured')
          else pollingResults.push(`OneDrive: ${response?.status || 'unknown status'}`)
        } catch (error: any) {
          pollingResults.push(`OneDrive polling failed: ${extractErrorDetail(error, 'Unknown error')}`)
        }
      }

      if (pollingResults.length > 0) {
        toast.success(`Events refreshed. ${pollingResults.join('. ')}.`)
      } else {
        toast.success('Events refreshed.')
      }
    } catch (error: any) {
      toast.error(extractErrorDetail(error, 'Failed to refresh events'))
    } finally {
      setIsRefreshing(false)
    }
  }

  const quickFilters = [
    { label: 'Critical Events', query: 'event.severity:critical' },
    { label: 'Blocked Events', query: 'blocked:true' },
    { label: 'File Events', query: 'event.type:file' },
    { label: 'USB Events', query: 'event.type:usb' },
    { label: 'Clipboard Events', query: 'event.type:clipboard' },
    { label: 'With Classifications', query: 'classification:*' },
  ]

  const sortOptions = [
    { key: 'timestamp', label: 'Time' },
    { key: 'severity', label: 'Severity' },
    { key: 'event_type', label: 'Event Type' },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FileText}
        title="Events"
        description="Search and analyze DLP events by keyword."
      />

      {activeDashboardFilters.length > 0 && (
        <div className="rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm text-foreground font-medium">Drill-down from dashboard:</span>
            {activeDashboardFilters.map(([k, v]) => (
              <span key={k} className="inline-flex items-center gap-1 px-2 py-1 rounded bg-card border border-border text-xs font-medium text-foreground">
                {k}=<span className="font-mono text-primary">{v}</span>
              </span>
            ))}
          </div>
          <button
            onClick={() => {
              const next = new URLSearchParams(searchParams)
              for (const [k] of activeDashboardFilters) next.delete(k)
              setSearchParams(next, { replace: true })
            }}
            className="text-xs text-primary hover:underline font-medium"
          >
            Clear filters
          </button>
        </div>
      )}

      {/* Search Bar */}
      <Card className="p-5">
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search events (e.g., usb, clipboard, google drive, block, etc.)"
              className="pl-9"
              value={kqlQuery}
              onChange={(e) => setKqlQuery(e.target.value)}
              onKeyPress={handleKeyPress}
            />
          </div>
          <Button onClick={handleSearch}>Search</Button>
          <Button variant="outline" onClick={() => setShowFilters(!showFilters)}>
            <Filter className="h-4 w-4" />
            Filters
          </Button>
        </div>

        {showFilters && (
          <div className="mt-4 pt-4 border-t border-border">
            <p className="text-sm font-medium text-foreground mb-2">Quick Filters:</p>
            <div className="flex flex-wrap gap-2">
              {quickFilters.map((filter) => (
                <button
                  key={filter.label}
                  onClick={() => {
                    setKqlQuery(filter.query)
                    setActiveQuery(filter.query)
                  }}
                  className="px-3 py-1 text-sm border border-border rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                >
                  {filter.label}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="mt-4 pt-4 border-t border-border">
          <p className="text-xs text-muted-foreground">
            <strong className="text-foreground">KQL Examples:</strong> field:value, field:"exact value",
            field:* (wildcard), field:(value1 OR value2), field &gt; 100, NOT field:value
          </p>
        </div>
      </Card>

      {/* Results */}
      <Card className="p-0 overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h3 className="font-semibold text-foreground">Search Results</h3>
            <p className="text-sm text-muted-foreground mt-1">
              {total.toLocaleString()} events found
              {activeQuery && (
                <span className="ml-2">
                  for query: <code className="text-xs bg-secondary px-1 py-0.5 rounded">{activeQuery}</code>
                </span>
              )}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex items-center gap-1.5">
              <ListFilter className="h-3.5 w-3.5 text-muted-foreground" />
              <Select value={sortKey ?? undefined} onValueChange={(v) => onSort(v)}>
                <SelectTrigger className="h-8 w-[130px] text-xs">
                  <SelectValue placeholder="Sort by" />
                </SelectTrigger>
                <SelectContent>
                  {sortOptions.map((o) => (
                    <SelectItem key={o.key} value={o.key}>{o.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                size="icon"
                className="h-8 w-8"
                onClick={() => sortKey && onSort(sortKey)}
                aria-label="Toggle sort direction"
                title={direction === 'asc' ? 'Ascending' : direction === 'desc' ? 'Descending' : 'Unsorted'}
              >
                <ArrowUpDown className={cn('h-3.5 w-3.5', direction === 'asc' && 'scale-y-[-1]')} />
              </Button>
            </div>
            <Button onClick={handleManualRefresh} disabled={isRefreshing} size="sm">
              {isRefreshing ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCcw className="w-4 h-4" />}
              Manual Refresh
            </Button>
            <Button variant="destructive" size="sm" onClick={handleClearLogs} disabled={events.length === 0}>
              <Trash2 className="w-4 h-4" />
              Clear Logs
            </Button>
          </div>
        </div>

        <div className="divide-y divide-border">
          {isLoading ? (
            <LoadingSpinner />
          ) : error ? (
            <div className="p-6">
              <ErrorMessage message="Failed to load events" retry={() => refetch()} />
            </div>
          ) : pageRows.length === 0 ? (
            <EmptyState
              icon={FileText}
              title="No events found"
              description="Try adjusting your search query or clearing active filters."
            />
          ) : (
            pageRows.map((event) => (
              <div
                key={event.id || event.event_id}
                className="p-4 hover:bg-accent cursor-pointer transition-colors"
                onClick={() => setSelectedEvent(event)}
              >
                <div className="flex items-start gap-4">
                  <div className={cn(
                    'p-2 rounded-lg border',
                    event.blocked ? tone('red') : event.quarantined ? tone('blue') : event.severity === 'critical' ? tone('red') : event.severity === 'high' ? tone('orange') : tone('blue'),
                  )}>
                    {event.event_type === 'file' ? <FileText className="h-5 w-5" /> :
                      event.event_type === 'usb' ? <Shield className="h-5 w-5" /> :
                      <AlertTriangle className="h-5 w-5" />}
                  </div>

                  <div className="flex-1 min-w-0">
                    {event.title && (
                      <h4 className="font-semibold text-foreground mb-2 text-base">{event.title}</h4>
                    )}

                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      {event.event_subtype && (event.source === 'onedrive_cloud' || event.source === 'google_drive_cloud') && (
                        <span className={cn('inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-semibold', tone(getEventSubtypeTone(event.event_subtype)))}>
                          {getEventSubtypeIcon(event.event_subtype)}
                          {getEventSubtypeLabel(event.event_subtype, event.details?.change_type)}
                        </span>
                      )}
                      <Badge variant={severityToVariant(event.severity)}>{event.severity}</Badge>
                      <Badge variant="info">
                        {event.event_type === 'usb' && event.event_subtype
                          ? (event.event_subtype === 'usb_connect' ? 'USB Connected'
                            : event.event_subtype === 'usb_disconnect' ? 'USB Disconnected'
                            : event.event_subtype === 'usb_blocked' ? 'USB Blocked'
                            : event.event_type)
                          : event.event_type}
                      </Badge>
                      {event.blocked && <Badge variant="critical">blocked</Badge>}
                      {!event.blocked && (event.quarantined || event.action_taken === 'quarantined' || event.action === 'quarantined') && (
                        <Badge variant="warning">quarantined</Badge>
                      )}
                      {event.classification_labels && event.classification_labels.length > 0 && (
                        <span className={cn('inline-flex items-center px-2 py-1 text-xs font-medium rounded-full border', tone('purple'))}>
                          {event.classification_labels[0]}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-sm text-muted-foreground flex-wrap">
                      <span>
                        <span className="text-muted-foreground/70">Agent:</span>{' '}
                        <span className="font-medium text-foreground" title={event.agent_id}>{getEventAgentLabel(event)}</span>
                      </span>
                      <span className="text-muted-foreground/40">•</span>
                      <span>{formatDate(event.timestamp, 'PPpp')}</span>
                      <span className="text-muted-foreground/40">•</span>
                      <code className="text-xs bg-secondary px-1 py-0.5 rounded">{event.id || event.event_id}</code>
                    </div>

                    {event.file_path && (
                      <p className="mt-2 text-sm text-foreground/80">
                        <strong className="text-foreground">File:</strong>{' '}
                        {(event.source === 'onedrive_cloud' || event.source === 'google_drive_cloud') && event.event_subtype ? (
                          <>
                            <span className="font-medium">{getEventSubtypeLabel(event.event_subtype, event.details?.change_type)}:</span>{' '}
                            {event.file_name || truncate(event.file_path, 60)}
                          </>
                        ) : truncate(event.file_path, 80)}
                      </p>
                    )}

                    {Array.isArray(event.matched_policies) && event.matched_policies.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-2">
                        {event.matched_policies
                          .map((policy: any) => policy?.policy_name)
                          .filter(Boolean)
                          .map((name: string) => (
                            <span key={`${event.id}-policy-${name}`} className={cn('inline-flex items-center px-2 py-1 text-xs font-medium rounded-full border', tone('indigo'))}>
                              {name}
                            </span>
                          ))}
                      </div>
                    )}

                    {event.usb && (
                      <p className="mt-2 text-sm text-foreground/80">
                        <strong className="text-foreground">USB:</strong> {event.usb.vendor} {event.usb.product}
                        {event.usb.serial && ` (${event.usb.serial})`}
                      </p>
                    )}

                    {event.policy && (
                      <p className="mt-2 text-sm text-foreground/80">
                        <strong className="text-foreground">Policy:</strong> {event.policy.policy_name} ({event.policy.action})
                      </p>
                    )}

                    {event.content_redacted && (
                      <div className="mt-2 p-2 bg-secondary rounded text-xs font-mono text-muted-foreground">
                        {truncate(event.content_redacted, 200)}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {!isLoading && !error && sorted.length > 0 && (
          <DataPagination
            page={page}
            pageSize={pageSize}
            total={sorted.length}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            pageSizeOptions={[10, 20, 50, 100]}
          />
        )}
      </Card>

      {selectedEvent && (
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          isBlockedTransfer={isBlockedTransfer(selectedEvent)}
          formatFileSize={formatFileSize}
          getDriveLetter={getDriveLetter}
        />
      )}
    </div>
  )
}
