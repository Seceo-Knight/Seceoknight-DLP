import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

import { Shield, Clock, User, Loader2, AlertTriangle, CheckCircle, Eye, RefreshCcw, ChevronDown, ChevronUp, ArrowUpDown, Siren } from 'lucide-react'
import { getAutoIncidents, getAutoIncident, updateAutoIncident } from '@/lib/api'
import { formatDateTimeIST, cn } from '@/lib/utils'
import { PageHeader } from '@/components/ui/page-header'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { tone, innerBox, labelCls, type Tone } from '@/lib/tone'
import toast from 'react-hot-toast'

const severityMap: Record<number, { label: string; t: Tone }> = {
  0: { label: 'Info', t: 'gray' },
  1: { label: 'Low', t: 'green' },
  2: { label: 'Medium', t: 'yellow' },
  3: { label: 'High', t: 'orange' },
  4: { label: 'Critical', t: 'red' },
}

const statusConfig: Record<string, { label: string; icon: any; t: Tone }> = {
  open: { label: 'Open', icon: AlertTriangle, t: 'red' },
  investigating: { label: 'Investigating', icon: Eye, t: 'yellow' },
  resolved: { label: 'Resolved', icon: CheckCircle, t: 'green' },
}

function classificationTone(level?: string): Tone {
  if (level === 'Restricted') return 'red'
  if (level === 'Confidential') return 'orange'
  if (level === 'Internal') return 'yellow'
  return 'gray'
}

function IncidentCard({ incident, onClick }: { incident: any; onClick: () => void }) {
  const sev = severityMap[incident.severity] ?? severityMap[2]
  return (
    <div
      onClick={onClick}
      className="group rounded-xl border border-border bg-card p-4 hover:border-primary/40 hover:shadow-md hover:-translate-y-0.5 cursor-pointer transition-all"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <h4 className="text-foreground font-semibold text-sm truncate group-hover:text-primary transition-colors">{incident.title}</h4>
          <p className="text-muted-foreground text-xs mt-1 truncate">{incident.description}</p>
        </div>
        <span className={cn('px-2.5 py-1 rounded-lg border text-xs font-semibold uppercase shrink-0', tone(sev.t))}>{sev.label}</span>
      </div>
      <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground flex-wrap">
        {incident.user_email && (
          <span className="flex items-center gap-1"><User className="w-3 h-3" />{incident.user_email}</span>
        )}
        {incident.event_count > 1 && <span className="text-warning font-medium">{incident.event_count} events</span>}
        <span className="ml-auto flex items-center gap-1"><Clock className="w-3 h-3" />{formatDateTimeIST(incident.created_at)}</span>
      </div>
    </div>
  )
}

function IncidentDetail({ incidentId, onClose }: { incidentId: string; onClose: () => void }) {
  const [expandedEvent, setExpandedEvent] = useState<number | null>(null)
  const queryClient = useQueryClient()

  const { data: incident, isLoading } = useQuery({
    queryKey: ['auto-incident', incidentId],
    queryFn: () => getAutoIncident(incidentId),
  })

  const statusMutation = useMutation({
    mutationFn: (newStatus: string) => updateAutoIncident(incidentId, { status: newStatus }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auto-incidents'] })
      queryClient.invalidateQueries({ queryKey: ['auto-incident', incidentId] })
      toast.success('Status updated')
    },
    onError: () => toast.error('Failed to update'),
  })

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-4xl">
        {isLoading || !incident ? (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
          </div>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle className="text-xl">{incident.title}</DialogTitle>
              <div className="flex gap-2 mt-1 flex-wrap">
                <span className={cn('px-3 py-1 rounded-lg border text-xs font-semibold uppercase', tone((severityMap[incident.severity] ?? severityMap[2]).t))}>
                  {(severityMap[incident.severity] ?? severityMap[2]).label}
                </span>
                <span className={cn('px-3 py-1 rounded-lg border text-xs font-semibold uppercase', tone((statusConfig[incident.status] || statusConfig.open).t))}>
                  {incident.status}
                </span>
                {incident.classification_level && (
                  <span className={cn('px-3 py-1 rounded-lg border text-xs font-semibold uppercase', tone(classificationTone(incident.classification_level)))}>
                    {incident.classification_level}
                  </span>
                )}
              </div>
            </DialogHeader>

            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                  { label: 'User', value: incident.user_email || 'Unknown' },
                  { label: 'Agent', value: incident.agent_id?.slice(0, 12) || 'N/A' },
                  { label: 'Events', value: incident.event_count || 1 },
                  { label: 'Created', value: formatDateTimeIST(incident.created_at) },
                ].map((item) => (
                  <div key={item.label} className={innerBox}>
                    <label className="text-xs text-muted-foreground block">{item.label}</label>
                    <p className="text-foreground text-sm font-medium truncate">{item.value}</p>
                  </div>
                ))}
              </div>

              {incident.description && (
                <div className={innerBox}>
                  <label className={cn(labelCls, 'mb-2')}>Description</label>
                  <p className="text-foreground/90 text-sm">{incident.description}</p>
                </div>
              )}

              <div className={innerBox}>
                <label className={cn(labelCls, 'mb-3')}>Update Status</label>
                <div className="flex gap-2 flex-wrap">
                  {['open', 'investigating', 'resolved'].map((s) => {
                    const cfg = statusConfig[s]
                    const active = incident.status === s
                    return (
                      <button
                        key={s}
                        onClick={() => statusMutation.mutate(s)}
                        disabled={statusMutation.isPending}
                        className={cn(
                          'flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium transition-all disabled:opacity-50',
                          active ? tone(cfg.t) : 'border-border text-muted-foreground hover:text-foreground hover:border-primary/40',
                        )}
                      >
                        <cfg.icon className="w-4 h-4" />{cfg.label}
                      </button>
                    )
                  })}
                </div>
              </div>

              <details className={cn(innerBox, 'overflow-hidden p-0')}>
                <summary className="px-4 py-3 text-sm font-medium text-foreground cursor-pointer hover:bg-accent">View Raw Incident Data</summary>
                <pre className="px-4 pb-4 text-xs text-muted-foreground overflow-x-auto whitespace-pre-wrap">{JSON.stringify(incident, null, 2)}</pre>
              </details>

              {(incident.related_events || []).length > 0 && (
                <div>
                  <label className={cn(labelCls, 'mb-3')}>Related Events ({incident.related_events.length})</label>
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {incident.related_events.map((ev: any, idx: number) => (
                      <div key={idx} className={cn(innerBox, 'overflow-hidden p-0')}>
                        <div
                          onClick={() => setExpandedEvent(expandedEvent === idx ? null : idx)}
                          className="flex items-center justify-between p-3 cursor-pointer hover:bg-accent transition-colors"
                        >
                          <div className="flex-1 min-w-0">
                            <p className="text-foreground text-sm font-medium truncate">{ev.description || ev.event_type}</p>
                            <p className="text-muted-foreground text-xs">{ev.event_type} | {ev.action_taken || 'logged'} | {formatDateTimeIST(ev.timestamp)}</p>
                          </div>
                          <div className="flex items-center gap-2 ml-3 shrink-0">
                            {ev.classification_level && (
                              <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', tone(classificationTone(ev.classification_level)))}>
                                {ev.classification_level}
                              </span>
                            )}
                            {expandedEvent === idx ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                          </div>
                        </div>
                        {expandedEvent === idx && (
                          <div className="border-t border-border p-3 bg-muted/30">
                            {ev.detected_content && (
                              <div className="mb-3">
                                <label className="text-xs text-muted-foreground block mb-1">Detected Content</label>
                                <pre className="text-xs text-foreground/90 bg-card rounded p-2 border border-border whitespace-pre-wrap">{ev.detected_content}</pre>
                              </div>
                            )}
                            {ev.classification_rules_matched && ev.classification_rules_matched.length > 0 && (
                              <div className="mb-3">
                                <label className="text-xs text-muted-foreground block mb-1">Matched Rules</label>
                                <div className="flex gap-1.5 flex-wrap">
                                  {ev.classification_rules_matched.map((r: string, i: number) => (
                                    <span key={i} className={cn('px-2 py-0.5 rounded-full text-xs font-medium border', tone('purple'))}>{r}</span>
                                  ))}
                                </div>
                              </div>
                            )}
                            <details>
                              <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">Raw JSON</summary>
                              <pre className="mt-2 text-xs text-muted-foreground bg-card rounded p-2 border border-border overflow-x-auto whitespace-pre-wrap">{JSON.stringify(ev, null, 2)}</pre>
                            </details>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

type SortMode = 'severity' | 'newest' | 'oldest'

function sortIncidents(list: any[], mode: SortMode) {
  const copy = [...list]
  if (mode === 'severity') copy.sort((a, b) => (b.severity || 0) - (a.severity || 0))
  else if (mode === 'newest') copy.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
  else copy.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
  return copy
}

const PAGE_SIZE = 8

function IncidentColumn({
  title, icon: Icon, iconTone, incidents, emptyLabel, onSelect,
}: {
  title: string
  icon: any
  iconTone: Tone
  incidents: any[]
  emptyLabel: string
  onSelect: (id: string) => void
}) {
  const [visible, setVisible] = useState(PAGE_SIZE)
  const shown = incidents.slice(0, visible)

  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        <Icon className={cn('w-4 h-4', tone(iconTone).split(' ').find((c) => c.startsWith('text-')))} />
        <h2 className="text-sm font-semibold uppercase text-foreground">{title} ({incidents.length})</h2>
      </div>
      <div className="space-y-3">
        {incidents.length === 0 ? (
          <div className="rounded-xl border border-border bg-muted/20 p-6 text-center">
            <p className="text-muted-foreground text-sm">{emptyLabel}</p>
          </div>
        ) : (
          <>
            {shown.map((inc: any) => (
              <IncidentCard key={inc.id || inc.event_id} incident={inc} onClick={() => onSelect(inc.id || inc.event_id)} />
            ))}
            {incidents.length > visible && (
              <Button variant="outline" size="sm" className="w-full" onClick={() => setVisible((v) => v + PAGE_SIZE)}>
                Show {Math.min(PAGE_SIZE, incidents.length - visible)} more
              </Button>
            )}
          </>
        )}
      </div>
    </div>
  )
}

export default function IncidentsPage() {
  const [selectedIncident, setSelectedIncident] = useState<string | null>(null)
  const [sortMode, setSortMode] = useState<SortMode>('severity')

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['auto-incidents'],
    queryFn: () => getAutoIncidents({ limit: 200 }),
    staleTime: 0,
    refetchInterval: 15000,
    retry: false,
  })

  const incidents = data?.incidents || []
  const stats = data?.stats || { total: 0, open: 0, investigating: 0, resolved: 0 }

  const openIncidents = useMemo(() => sortIncidents(incidents.filter((i: any) => i.status === 'open'), sortMode), [incidents, sortMode])
  const investigatingIncidents = useMemo(() => sortIncidents(incidents.filter((i: any) => i.status === 'investigating'), sortMode), [incidents, sortMode])
  const resolvedIncidents = useMemo(() => sortIncidents(incidents.filter((i: any) => i.status === 'resolved'), sortMode), [incidents, sortMode])

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Siren}
        title="Incidents"
        description="Auto-generated from blocked and critical DLP events."
        actions={
          <div className="flex items-center gap-2">
            <ArrowUpDown className="h-3.5 w-3.5 text-muted-foreground" />
            <Select value={sortMode} onValueChange={(v) => setSortMode(v as SortMode)}>
              <SelectTrigger className="h-8 w-[140px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="severity">Severity</SelectItem>
                <SelectItem value="newest">Newest first</SelectItem>
                <SelectItem value="oldest">Oldest first</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
              <RefreshCcw className={cn('w-4 h-4', isFetching && 'animate-spin')} />
              Refresh
            </Button>
          </div>
        }
      />

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { label: 'Total', value: stats.total, t: 'gray' as Tone },
          { label: 'Open', value: stats.open, t: 'red' as Tone },
          { label: 'Investigating', value: stats.investigating, t: 'yellow' as Tone },
          { label: 'Resolved', value: stats.resolved, t: 'green' as Tone },
        ].map((s) => (
          <Card key={s.label} className="p-4">
            <p className="text-muted-foreground text-xs uppercase">{s.label}</p>
            <p className={cn('text-3xl font-bold mt-1', tone(s.t).split(' ').find((c) => c.startsWith('text-')) || 'text-foreground')}>
              {s.value}
            </p>
          </Card>
        ))}
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {[0, 1, 2].map((i) => (
            <div key={i} className="space-y-3">
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-24 w-full" />
              <Skeleton className="h-24 w-full" />
            </div>
          ))}
        </div>
      ) : incidents.length === 0 ? (
        <Card className="p-0">
          <EmptyState
            icon={Shield}
            title="No incidents"
            description="Blocked or critical events will auto-generate incidents here."
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <IncidentColumn
            title="Open"
            icon={AlertTriangle}
            iconTone="red"
            incidents={openIncidents}
            emptyLabel="No open incidents"
            onSelect={setSelectedIncident}
          />
          <IncidentColumn
            title="Investigating"
            icon={Eye}
            iconTone="yellow"
            incidents={investigatingIncidents}
            emptyLabel="No active investigations"
            onSelect={setSelectedIncident}
          />
          <IncidentColumn
            title="Resolved"
            icon={CheckCircle}
            iconTone="green"
            incidents={resolvedIncidents}
            emptyLabel="No resolved incidents"
            onSelect={setSelectedIncident}
          />
        </div>
      )}

      {selectedIncident && <IncidentDetail incidentId={selectedIncident} onClose={() => setSelectedIncident(null)} />}
    </div>
  )
}
