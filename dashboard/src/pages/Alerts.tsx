import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, AlertTriangle, ShieldAlert, Search } from 'lucide-react'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import AlertDetailsModal from '@/components/alerts/AlertDetailsModal'
import StatsCard from '@/components/StatsCard'
import { PageHeader } from '@/components/ui/page-header'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { EmptyState } from '@/components/ui/empty-state'
import { DataPagination } from '@/components/ui/pagination'
import { getAlerts, getAgents, type Agent } from '@/lib/api'
import { formatRelativeTime, formatAgentLabel, cn } from '@/lib/utils'
import { tone, type Tone } from '@/lib/tone'

type FilterType = 'all' | 'high' | 'critical'

// Same 4-tone severity ladder as the Events tab (critical=red, high=orange,
// medium=yellow, low=blue) so the two "list of security records" pages
// read consistently instead of each inventing its own scheme.
const severityTone = (severity?: string | null): Tone => {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return 'red'
    case 'high': return 'orange'
    case 'medium': return 'yellow'
    case 'low': return 'blue'
    default: return 'gray'
  }
}

const SEVERITY_BORDER: Record<string, string> = {
  critical: 'border-l-critical',
  high: 'border-l-warning',
  medium: 'border-l-warning/50',
  low: 'border-l-info',
}

export default function Alerts() {
  const [selectedAlert, setSelectedAlert] = useState<any>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [filter, setFilter] = useState<FilterType>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

  // Reset to page 1 whenever the severity filter, page size, or search
  // query changes -- searchQuery in particular, since it narrows the
  // current page's results and a stale page number would otherwise show
  // as e.g. "Page 3 of 1" against the smaller filtered count below.
  useEffect(() => setPage(1), [filter, pageSize, searchQuery])

  const severityParam = filter === 'all' ? undefined : filter

  const { data: alertsData, isLoading, error, refetch } = useQuery({
    queryKey: ['alerts', severityParam, page, pageSize],
    queryFn: () => getAlerts({ severity: severityParam, skip: (page - 1) * pageSize, limit: pageSize }),
    refetchInterval: 10000,
  })

  const { data: agentsData } = useQuery({
    queryKey: ['agents'],
    queryFn: getAgents,
    refetchInterval: 30000,
  })
  const agentMap = useMemo(() => {
    const map = new Map<string, { name: string; agent_code?: number }>()
    if (Array.isArray(agentsData)) {
      agentsData.forEach((agent: Agent) => {
        if (agent?.agent_id && agent?.name) map.set(agent.agent_id, { name: agent.name, agent_code: agent.agent_code })
      })
    }
    return map
  }, [agentsData])
  const getAlertAgentLabel = (alert: any): string => {
    const fallback = alert.agent_id ? agentMap.get(alert.agent_id) : undefined
    return formatAgentLabel(fallback?.name, fallback?.agent_code, null, alert.agent_id)
  }

  const handleAlertClick = (alert: any) => {
    setSelectedAlert(alert)
    setIsModalOpen(true)
  }

  // Handle both old format (array) and new format (object with alerts and counts).
  // This whole derivation has to run unconditionally on every render, before
  // the isLoading/error early returns below, since hooks can't be called
  // conditionally. alertsData is simply undefined while loading, which
  // every branch here already guards for.
  let alerts: any[] = []
  let counts: Record<string, number> = {}

  if (!alertsData) {
    alerts = []
  } else if (Array.isArray(alertsData)) {
    alerts = alertsData
  } else if (typeof alertsData === 'object' && alertsData !== null) {
    if ('alerts' in alertsData && Array.isArray(alertsData.alerts)) alerts = alertsData.alerts
    if ('counts' in alertsData && typeof alertsData.counts === 'object' && alertsData.counts !== null) counts = alertsData.counts
  }
  if (!Array.isArray(alerts)) alerts = []

  // Server-computed, filter-independent breakdown (counts.total tracks
  // whatever `severity` filter is currently applied to the query; high/
  // critical are always the true totals so the tiles stay accurate no
  // matter which one is selected). Previously these were computed by
  // counting severity matches within the capped ~100-row fetched page,
  // silently undercounting once there were more alerts than that.
  const totalAlertsCount = typeof counts.total === 'number' ? counts.total : alerts.length
  const highAlertsCount = typeof counts.high === 'number' ? counts.high : alerts.filter((a) => a?.severity === 'high').length
  const criticalAlertsCount = typeof counts.critical === 'number' ? counts.critical : alerts.filter((a) => a?.severity === 'critical').length

  // Free-text search is a client-side refinement over the currently
  // loaded page only (the backend has no keyword search for alerts) --
  // narrower in scope than the Events tab's server-side search, so
  // pagination below falls back to the local filtered count while a
  // search is active instead of claiming the server's larger total.
  const filteredAlerts = alerts.filter((alert) => {
    if (!searchQuery) return true
    const query = searchQuery.toLowerCase()
    return (
      alert.title?.toLowerCase().includes(query) ||
      alert.description?.toLowerCase().includes(query) ||
      alert.agent_id?.toLowerCase().includes(query) ||
      alert.user_email?.toLowerCase().includes(query) ||
      alert.event_id?.toLowerCase().includes(query) ||
      alert.severity?.toLowerCase().includes(query)
    )
  })

  const paginationTotal = searchQuery ? filteredAlerts.length : totalAlertsCount

  if (isLoading) {
    return <LoadingSpinner size="lg" />
  }

  if (error) {
    return <ErrorMessage message="Failed to load alerts" retry={() => refetch()} />
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={ShieldAlert}
        title="Alerts"
        description="Security alerts triggered by DLP policies."
      />

      {/* Stats — click to filter the list below */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatsCard
          title="Total Alerts"
          value={totalAlertsCount.toLocaleString()}
          icon={ShieldAlert}
          color="indigo"
          onClick={() => setFilter('all')}
          active={filter === 'all'}
        />
        <StatsCard
          title="High Alerts"
          value={highAlertsCount.toLocaleString()}
          icon={AlertTriangle}
          color="orange"
          onClick={() => setFilter('high')}
          active={filter === 'high'}
        />
        <StatsCard
          title="Critical Alerts"
          value={criticalAlertsCount.toLocaleString()}
          icon={AlertCircle}
          color="red"
          onClick={() => setFilter('critical')}
          active={filter === 'critical'}
        />
      </div>

      {/* Search Bar */}
      <Card className="p-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search alerts by title, description, agent ID, severity..."
            className="pl-9"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </Card>

      {/* Alerts List */}
      <Card className="p-0 overflow-hidden">
        <div className="border-b border-border px-5 py-4">
          <h3 className="font-semibold text-foreground">
            {filter === 'all' ? 'All Alerts' : filter === 'high' ? 'High Severity Alerts' : 'Critical Severity Alerts'}
            {searchQuery && <span className="ml-2 font-normal text-muted-foreground">— search: "{searchQuery}"</span>}
          </h3>
        </div>

        <div className="divide-y divide-border">
          {filteredAlerts.length === 0 ? (
            <EmptyState
              icon={AlertCircle}
              title={searchQuery ? 'No alerts found' : filter === 'all' ? 'No alerts' : `No ${filter} severity alerts`}
              description={
                searchQuery
                  ? 'Try adjusting your search query.'
                  : filter === 'all'
                    ? 'Alerts will appear here when policies trigger.'
                    : 'Click "Total Alerts" to see all alerts.'
              }
            />
          ) : (
            filteredAlerts.map((alert) => {
              const sevTone = severityTone(alert.severity)
              return (
                <div
                  key={alert.id}
                  className={cn(
                    'flex items-start gap-3 border-l-2 py-3.5 pl-3 pr-4 cursor-pointer transition-colors hover:bg-accent',
                    SEVERITY_BORDER[(alert.severity || '').toLowerCase()] || 'border-l-border',
                  )}
                  onClick={() => handleAlertClick(alert)}
                >
                  <div className={cn('mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md border', tone(sevTone))}>
                    <ShieldAlert className="h-4 w-4" />
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-bold uppercase tracking-wide', tone(sevTone))}>
                        {alert.severity}
                      </span>
                      {alert.status === 'new' && <Badge variant="critical">New</Badge>}
                      {alert.status === 'acknowledged' && <Badge variant="warning">Acknowledged</Badge>}
                      {alert.status === 'resolved' && <Badge variant="success">Resolved</Badge>}
                    </div>

                    <h4 className="mt-1 text-sm font-semibold text-foreground">{alert.title}</h4>
                    {alert.description && (
                      <p className="mt-0.5 text-xs text-muted-foreground line-clamp-2">{alert.description}</p>
                    )}

                    <div className="mt-1.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs text-muted-foreground">
                      <span title={alert.agent_id}>
                        <span className="text-muted-foreground/70">Agent</span>{' '}
                        <span className="font-medium text-foreground">{getAlertAgentLabel(alert)}</span>
                      </span>
                      {alert.user_email && alert.user_email !== 'agent@system' && (
                        <>
                          <span className="text-muted-foreground/30">·</span>
                          <span>
                            <span className="text-muted-foreground/70">User</span>{' '}
                            <span className="font-medium text-foreground">{alert.user_email}</span>
                          </span>
                        </>
                      )}
                      <span className="text-muted-foreground/30">·</span>
                      <span>{formatRelativeTime(alert.created_at)}</span>
                    </div>
                  </div>

                  <code
                    className="mt-0.5 hidden shrink-0 font-mono text-[10px] text-muted-foreground/40 sm:block"
                    title={alert.event_id}
                  >
                    {alert.event_id && alert.event_id.length > 10 ? `${alert.event_id.slice(0, 10)}…` : alert.event_id}
                  </code>
                </div>
              )
            })
          )}
        </div>
        {paginationTotal > 0 && (
          <DataPagination
            page={page}
            pageSize={pageSize}
            total={paginationTotal}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            pageSizeOptions={[10, 25, 50, 100]}
          />
        )}
      </Card>

      {/* Alert Details Modal */}
      <AlertDetailsModal
        alert={selectedAlert}
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false)
          setSelectedAlert(null)
        }}
      />
    </div>
  )
}
