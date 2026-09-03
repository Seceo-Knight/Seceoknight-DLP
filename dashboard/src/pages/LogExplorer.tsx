import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Search, Download, RefreshCcw, ChevronDown, ChevronUp, FileText,
  Clipboard, Usb, Ban, Clock,
} from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import StatsCard from '@/components/StatsCard'
import { PageHeader } from '@/components/ui/page-header'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { EmptyState } from '@/components/ui/empty-state'
import { DataPagination } from '@/components/ui/pagination'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { searchEvents, getEventsByType } from '@/lib/api'
import { formatDateTimeIST, cn } from '@/lib/utils'
import { tone, type Tone } from '@/lib/tone'

// Real server-side filtering, pagination, and counts -- previously this
// page fetched a flat 100-row cap with no skip, and every filter (time
// range, classification, agent, user, even the search box) ran client-side
// over just those 100 rows. The backend (/events/) already supports real
// search/severity/event_type/classification/start_time/end_time/skip/limit
// -- see server/app/api/v1/events.py -- so a search for a user or agent
// that isn't among the 100 most-recently-ingested events silently returned
// nothing, no matter how many matching events actually existed. Rebuilt to
// thread every filter into the real query params, same pattern as Events.tsx.

const TIME_PRESETS = [
  { label: '5m', minutes: 5 }, { label: '10m', minutes: 10 }, { label: '15m', minutes: 15 },
  { label: '30m', minutes: 30 }, { label: '1h', minutes: 60 }, { label: '24h', minutes: 1440 },
  { label: '7d', minutes: 10080 }, { label: '30d', minutes: 43200 }, { label: '90d', minutes: 129600 },
]

// Classification tier ladder -- matches the Restricted=red/Confidential=
// orange/Internal=yellow/Public=green scheme already used in Events.tsx's
// EventDetailModal, instead of a 3rd independently-invented scheme.
const classificationTone = (category?: string | null): Tone => {
  switch (category) {
    case 'Restricted': return 'red'
    case 'Confidential': return 'orange'
    case 'Internal': return 'yellow'
    case 'Public': return 'green'
    default: return 'gray'
  }
}

// Same 4-tone severity ladder as Events/Alerts/Risk Scoring (critical=red,
// high=orange, medium=yellow, low=blue). This page previously mapped
// low -> green, a 4th independently-invented scheme that disagreed with
// every other tab's severity colors.
const severityTone = (severity?: string | null): Tone => {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return 'red'
    case 'high': return 'orange'
    case 'medium': return 'yellow'
    case 'low': return 'blue'
    default: return 'gray'
  }
}

/** Debounce a fast-changing value (free-text inputs) before it drives a
 *  network request, so typing "vaibhav" doesn't fire 7 requests. */
function useDebounced<T>(value: T, delayMs = 350): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(t)
  }, [value, delayMs])
  return debounced
}

export default function LogExplorerPage() {
  const [searchInput, setSearchInput] = useState('')
  const [agentInput, setAgentInput] = useState('')
  const [userInput, setUserInput] = useState('')
  const searchQuery = useDebounced(searchInput)
  const agentFilter = useDebounced(agentInput)
  const userFilter = useDebounced(userInput)

  const [eventType, setEventType] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [classification, setClassification] = useState('all')
  const [timePreset, setTimePreset] = useState<number | null>(null)
  const [startTime, setStartTime] = useState('')
  const [endTime, setEndTime] = useState('')
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null)
  const [showFilters, setShowFilters] = useState(true)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [isExporting, setIsExporting] = useState(false)

  // Reset to page 1 whenever any filter narrows/widens the result set --
  // otherwise "page 5" can silently show as empty against a much smaller
  // filtered count.
  useEffect(() => {
    setPage(1)
  }, [searchQuery, eventType, severity, classification, timePreset, startTime, endTime, agentFilter, userFilter, pageSize])

  // Populate the Event Type filter from what the backend actually has,
  // instead of a hand-typed list that only covered clipboard/usb/file and
  // silently had no way to filter to web_activity, print, google_drive,
  // messaging, etc. -- event types the live deployment actually emits.
  const { data: typeStats } = useQuery({
    queryKey: ['log-explorer-event-types'],
    queryFn: () => getEventsByType(),
    staleTime: 5 * 60 * 1000,
  })
  const eventTypeOptions = useMemo(() => {
    const types = Array.isArray(typeStats) ? typeStats : []
    return types
      .filter((t: any) => t?.type && t.type !== 'unknown')
      .sort((a: any, b: any) => (b.count || 0) - (a.count || 0))
      .map((t: any) => ({ value: t.type, label: t.type.replace(/_/g, ' ') }))
  }, [typeStats])

  const buildParams = (skip: number, limit: number) => {
    const params: Record<string, any> = { skip, limit }
    if (searchQuery) params.search = searchQuery
    if (eventType !== 'all') params.event_type = eventType
    if (severity !== 'all') params.severity = severity
    if (classification !== 'all') params.classification = classification
    if (agentFilter) params.agent_id = agentFilter
    if (userFilter) params.user_email = userFilter
    if (timePreset) {
      params.start_time = new Date(Date.now() - timePreset * 60000).toISOString()
    } else {
      if (startTime) params.start_time = new Date(startTime).toISOString()
      if (endTime) params.end_time = new Date(endTime).toISOString()
    }
    return params
  }

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['log-explorer', searchQuery, eventType, severity, classification, agentFilter, userFilter, timePreset, startTime, endTime, page, pageSize],
    queryFn: () => searchEvents(buildParams((page - 1) * pageSize, pageSize)),
    staleTime: 0,
  })

  const events = data?.events || []
  const total = data?.total || 0
  const counts = data?.counts || {}

  const hasFilters = !!(searchInput || eventType !== 'all' || severity !== 'all' || classification !== 'all' || timePreset || startTime || endTime || agentInput || userInput)
  const clearFilters = () => {
    setSearchInput(''); setAgentInput(''); setUserInput('')
    setEventType('all'); setSeverity('all'); setClassification('all')
    setTimePreset(null); setStartTime(''); setEndTime('')
  }

  // Export fetches up to the backend's own max page size (1000) under the
  // current filters, independent of the on-screen page/pageSize -- not
  // just "whatever happens to be loaded right now". Honest about it when
  // the true match count exceeds that cap, rather than silently truncating.
  const EXPORT_CAP = 1000
  const runExport = async (format: 'csv' | 'json') => {
    setIsExporting(true)
    try {
      const result = await searchEvents(buildParams(0, EXPORT_CAP))
      const rows = result?.events || []
      const trueTotal = result?.total ?? rows.length
      if (rows.length === 0) {
        toast.error('No events match the current filters')
        return
      }
      if (format === 'csv') {
        const csvRows = [
          ['Timestamp', 'Type', 'Severity', 'Classification', 'Action', 'Blocked', 'Matched Policies', 'Description', 'Agent', 'User'].join(','),
          ...rows.map((e: any) => [
            e.timestamp, e.event_type, e.severity,
            e.classification_category || e.classification_level || 'Public',
            e.action_taken || 'logged', e.blocked ? 'Yes' : 'No',
            `"${(e.matched_policies || []).map((p: any) => p?.policy_name).filter(Boolean).join('; ')}"`,
            `"${(e.description || '').replace(/"/g, '""').replace(/\n/g, ' ')}"`,
            e.agent_id, e.user_email,
          ].join(',')),
        ]
        const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' })
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `dlp-logs-${new Date().toISOString().slice(0, 10)}.csv`
        a.click()
      } else {
        const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' })
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `dlp-logs-${new Date().toISOString().slice(0, 10)}.json`
        a.click()
      }
      toast.success(
        trueTotal > rows.length
          ? `Exported ${rows.length.toLocaleString()} of ${trueTotal.toLocaleString()} matching events (capped at ${EXPORT_CAP.toLocaleString()} -- narrow your filters to export the rest)`
          : `Exported ${rows.length.toLocaleString()} event(s)`,
      )
    } catch {
      toast.error('Export failed')
    } finally {
      setIsExporting(false)
    }
  }

  if (isLoading) return <LoadingSpinner size="lg" />
  if (error) return <ErrorMessage message="Failed to load events" retry={() => refetch()} />

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Search}
        title="Log Explorer"
        description="Search, filter, and investigate DLP events."
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCcw className={cn('h-4 w-4', isFetching && 'animate-spin')} />
              Refresh
            </Button>
            <Button variant="outline" size="sm" onClick={() => runExport('csv')} disabled={isExporting}>
              <Download className="h-4 w-4" />
              CSV
            </Button>
            <Button variant="outline" size="sm" onClick={() => runExport('json')} disabled={isExporting}>
              <FileText className="h-4 w-4" />
              JSON
            </Button>
          </div>
        }
      />

      {/* Stats -- server-computed counts, scoped to the active search/time/
          severity context but independent of the caller's own Event Type /
          Blocked selection, so switching Event Type to "usb" doesn't zero
          out the Clipboard tile. See events.py's `counts` field. */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatsCard title="Results" value={total.toLocaleString()} icon={Search} color="indigo" />
        <StatsCard title="Clipboard" value={(counts.clipboard ?? 0).toLocaleString()} icon={Clipboard} color="indigo" />
        <StatsCard title="USB" value={(counts.usb ?? 0).toLocaleString()} icon={Usb} color="indigo" />
        <StatsCard title="Blocked" value={(counts.blocked ?? 0).toLocaleString()} icon={Ban} color="red" />
      </div>

      {/* Search + Filters */}
      <Card className="p-0 overflow-hidden">
        <div className="p-4 border-b border-border">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search by description, agent, user, file path, classification rules..."
              className="pl-9 pr-24"
            />
            <div className="absolute right-2 top-1/2 flex -translate-y-1/2 gap-1">
              {hasFilters && (
                <button onClick={clearFilters} className="px-2 py-1 text-xs text-muted-foreground hover:text-foreground">
                  Clear
                </button>
              )}
              <Button variant={showFilters ? 'secondary' : 'ghost'} size="sm" onClick={() => setShowFilters(!showFilters)}>
                Filters
              </Button>
            </div>
          </div>
        </div>

        {showFilters && (
          <div className="space-y-4 border-b border-border bg-muted/20 p-4">
            <div>
              <label className="mb-2 block text-xs uppercase text-muted-foreground">Time Range</label>
              <div className="flex items-center gap-1 rounded-md border border-border bg-card p-0.5 w-fit flex-wrap">
                <Clock className="ml-1.5 h-3.5 w-3.5 text-muted-foreground" />
                <button
                  type="button"
                  onClick={() => { setTimePreset(null) }}
                  className={cn('rounded px-2.5 py-1 text-xs font-medium transition-colors',
                    !timePreset ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted hover:text-foreground')}
                >
                  All Time
                </button>
                {TIME_PRESETS.map((p) => (
                  <button
                    key={p.minutes}
                    type="button"
                    onClick={() => { setTimePreset(p.minutes); setStartTime(''); setEndTime('') }}
                    className={cn('rounded px-2.5 py-1 text-xs font-medium transition-colors',
                      timePreset === p.minutes ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted hover:text-foreground')}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              <div className="mt-2 flex gap-3">
                <div className="flex-1">
                  <label className="mb-1 block text-xs text-muted-foreground">Start</label>
                  <input
                    type="datetime-local" value={startTime}
                    onChange={(e) => { setStartTime(e.target.value); setTimePreset(null) }}
                    className="w-full rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground focus:border-primary focus:outline-none"
                  />
                </div>
                <div className="flex-1">
                  <label className="mb-1 block text-xs text-muted-foreground">End</label>
                  <input
                    type="datetime-local" value={endTime}
                    onChange={(e) => { setEndTime(e.target.value); setTimePreset(null) }}
                    className="w-full rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground focus:border-primary focus:outline-none"
                  />
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Event Type</label>
                <Select value={eventType} onValueChange={setEventType}>
                  <SelectTrigger className="h-9 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    {eventTypeOptions.map((t) => (
                      <SelectItem key={t.value} value={t.value} className="capitalize">{t.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Severity</label>
                <Select value={severity} onValueChange={setSeverity}>
                  <SelectTrigger className="h-9 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Classification</label>
                <Select value={classification} onValueChange={setClassification}>
                  <SelectTrigger className="h-9 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="Restricted">Restricted</SelectItem>
                    <SelectItem value="Confidential">Confidential</SelectItem>
                    <SelectItem value="Internal">Internal</SelectItem>
                    <SelectItem value="Public">Public</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">Agent</label>
                <Input value={agentInput} onChange={(e) => setAgentInput(e.target.value)} placeholder="Agent ID..." className="h-9 text-sm" />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">User</label>
                <Input value={userInput} onChange={(e) => setUserInput(e.target.value)} placeholder="Email..." className="h-9 text-sm" />
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {events.length === 0 ? (
          <EmptyState icon={Search} title="No events match your filters" description="Try widening the time range or clearing a filter." />
        ) : (
          <>
            <div className="grid grid-cols-12 gap-2 border-b border-border bg-muted/30 px-4 py-3 text-xs font-medium uppercase text-muted-foreground">
              <div className="col-span-1">Type</div>
              <div className="col-span-3">Description</div>
              <div className="col-span-2">Classification</div>
              <div className="col-span-1">Severity</div>
              <div className="col-span-1">Action</div>
              <div className="col-span-2">User</div>
              <div className="col-span-2">Time</div>
            </div>
            <div className="divide-y divide-border">
              {events.map((event: any, idx: number) => {
                const key = event.id || idx.toString()
                const isExpanded = expandedEvent === key
                const category = event.classification_category || event.classification_level || 'Public'
                return (
                  <div key={key}>
                    <div
                      onClick={() => setExpandedEvent(isExpanded ? null : key)}
                      className="grid cursor-pointer grid-cols-12 items-center gap-2 px-4 py-3 text-sm transition-colors hover:bg-accent"
                    >
                      <div className="col-span-1"><span className="text-xs capitalize text-muted-foreground">{event.event_type}</span></div>
                      <div className="col-span-3 truncate font-medium text-foreground">{event.description || `${event.event_type} event`}</div>
                      <div className="col-span-2">
                        <span className={cn('rounded border px-2 py-0.5 text-xs font-medium', tone(classificationTone(category)))}>{category}</span>
                      </div>
                      <div className="col-span-1">
                        <span className={cn('rounded border px-2 py-0.5 text-xs font-medium', tone(severityTone(event.severity)))}>{event.severity}</span>
                      </div>
                      <div className="col-span-1">
                        <span className={cn('text-xs font-medium', event.blocked ? 'text-critical' : 'text-muted-foreground')}>{event.action_taken || 'logged'}</span>
                      </div>
                      <div className="col-span-2 truncate text-xs text-muted-foreground">{event.user_email || '-'}</div>
                      <div className="col-span-2 flex items-center justify-between">
                        <span className="text-xs text-muted-foreground">{formatDateTimeIST(event.timestamp)}</span>
                        {isExpanded ? <ChevronUp className="h-3 w-3 text-muted-foreground" /> : <ChevronDown className="h-3 w-3 text-muted-foreground" />}
                      </div>
                    </div>
                    {isExpanded && (
                      <div className="space-y-3 border-t border-border bg-muted/30 px-4 pb-4">
                        <div className="grid grid-cols-2 gap-3 pt-3 md:grid-cols-4">
                          <div><label className="text-xs text-muted-foreground">Event Type</label><p className="text-sm capitalize text-foreground">{event.event_subtype || event.event_type}</p></div>
                          <div><label className="text-xs text-muted-foreground">Action</label><p className="text-sm text-foreground">{event.action_taken || 'logged'}</p></div>
                          <div><label className="text-xs text-muted-foreground">Confidence</label><p className="text-sm font-bold text-foreground">{((event.classification_score || 0) * 100).toFixed(0)}%</p></div>
                          <div><label className="text-xs text-muted-foreground">Agent</label><p className="font-mono text-xs text-foreground">{event.agent_name ? `${event.agent_name}${event.agent_code != null ? ` (${String(event.agent_code).padStart(3, '0')})` : ''}` : event.agent_id}</p></div>
                        </div>
                        {event.classification_rules_matched && event.classification_rules_matched.length > 0 && (
                          <div>
                            <label className="text-xs text-muted-foreground">Matched Rules</label>
                            <div className="mt-1 flex flex-wrap gap-1.5">
                              {event.classification_rules_matched.map((r: string, i: number) => (
                                <span key={i} className={cn('rounded-full border px-2 py-0.5 text-xs font-medium', tone('purple'))}>{r}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {event.detected_content && (
                          <div>
                            <label className="text-xs text-muted-foreground">Detected Content</label>
                            <pre className="mt-1 whitespace-pre-wrap rounded-lg border border-border bg-card p-3 text-xs text-foreground/90">{event.detected_content}</pre>
                          </div>
                        )}
                        <details>
                          <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">Raw JSON</summary>
                          <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-lg border border-border bg-card p-3 text-xs text-muted-foreground">{JSON.stringify(event, null, 2)}</pre>
                        </details>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </>
        )}

        {total > 0 && (
          <DataPagination
            page={page}
            pageSize={pageSize}
            total={total}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            pageSizeOptions={[10, 25, 50, 100]}
          />
        )}
      </Card>
    </div>
  )
}
