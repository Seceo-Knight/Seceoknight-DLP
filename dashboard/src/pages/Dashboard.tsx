import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Server, AlertCircle, FileText, ShieldAlert, Shield, Activity,
  TrendingUp, LayoutDashboard,
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'

import StatsCard from '@/components/StatsCard'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { PageHeader } from '@/components/ui/page-header'
import { Card } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  getStats, getEventTimeSeries, getEventsByType, getEventsBySeverity,
} from '@/lib/api'
import { cn } from '@/lib/utils'
import { drillDownUrl, DRILL_TOOLTIP } from '@/lib/drilldown'
import { CHART_COLORS, RECHARTS_CONFIG, tickStyle } from '@/styles/charts'

// ── Time formatting (IST) ───────────────────────────────────────────────
const IST_TIMEZONE = 'Asia/Kolkata'
const formatTimeIST = (d: Date) =>
  new Intl.DateTimeFormat('en-IN', {
    timeZone: IST_TIMEZONE, hour: '2-digit', minute: '2-digit', hour12: false,
  }).format(d)
const formatDateTimeIST = (d: Date) =>
  new Intl.DateTimeFormat('en-IN', {
    timeZone: IST_TIMEZONE, dateStyle: 'long', timeStyle: 'long',
  }).format(d)

// Distinct, harmonious palette for event-type pie segments.
const TYPE_PALETTE = [
  '#5B7EFF', '#2DD4BF', '#FB923C', '#F87171', '#7B9EFF', '#34D399', '#FBBF24', '#60A5FA',
]

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#F87171',
  high:     '#FB923C',
  medium:   '#FBBF24',
  low:      '#5B7EFF',
  info:     '#A0A0B8',
}

// ── Custom tooltip ───────────────────────────────────────────────────────
function ChartTooltip({ active, payload, label, labelFormatter, drillHint }: any) {
  if (!active || !payload?.length) return null
  return (
    <div
      className="rounded-md border border-border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-lg"
    >
      {label !== undefined && (
        <div className="mb-1 font-medium text-muted-foreground">
          {labelFormatter ? labelFormatter(label) : label}
        </div>
      )}
      {payload.map((p: any, i: number) => (
        <div key={i} className="flex items-center gap-2 tabular-nums">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: p.color || p.payload?.fill || CHART_COLORS.primary }} />
          <span className="text-muted-foreground">{p.name ?? p.dataKey}:</span>
          <span className="font-semibold text-foreground">{Number(p.value).toLocaleString()}</span>
        </div>
      ))}
      {drillHint && (
        <div className="mt-1.5 border-t border-border pt-1.5 text-[10px] font-medium uppercase tracking-wider text-primary">
          ↗ Click to filter by {drillHint}
        </div>
      )}
    </div>
  )
}

// ── Page ────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const navigate = useNavigate()

  const { data: stats, isLoading: statsLoading, error: statsError, isFetching } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    refetchInterval: 5000,
  })

  const { data: timeSeries = [], isLoading: timeSeriesLoading } = useQuery({
    queryKey: ['eventTimeSeries'],
    queryFn: () => getEventTimeSeries({ interval: 'hour' }),
  })

  const { data: eventsByType = [], isLoading: typeLoading } = useQuery({
    queryKey: ['eventsByType'],
    queryFn: getEventsByType,
  })

  const { data: eventsBySeverity = [], isLoading: severityLoading } = useQuery({
    queryKey: ['eventsBySeverity'],
    queryFn: getEventsBySeverity,
  })

  const agentHealth = useMemo(() => {
    if (!stats?.total_agents) return null
    const pct = (stats.active_agents / stats.total_agents) * 100
    return Number.isFinite(pct) ? Math.round(pct) : null
  }, [stats])

  const blockRate = useMemo(() => {
    if (!stats?.total_events) return null
    const pct = ((stats.blocked_events ?? 0) / stats.total_events) * 100
    return Number.isFinite(pct) ? Math.round(pct) : null
  }, [stats])

  if (statsLoading) return <LoadingSpinner size="lg" />
  if (statsError) {
    return <ErrorMessage message="Failed to load dashboard data. Please check if the backend is running." />
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={LayoutDashboard}
        title="Security Operations"
        description="Real-time view of DLP activity across endpoints and channels."
        actions={
          <div className="flex items-center gap-2 rounded-full border border-success/30 bg-success/10 px-3 py-1.5 text-xs font-medium text-success">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-success" />
            </span>
            Live · refreshes every 5s
            {isFetching && <span className="ml-1 text-primary">syncing…</span>}
          </div>
        }
      />

      {/* Stat cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title="Total Events"
          value={(stats?.total_events ?? 0).toLocaleString()}
          icon={FileText}
          color="indigo"
          subtext="all-time recorded"
          to={drillDownUrl({})}
          drillTooltip="See all events"
        />
        <StatsCard
          title="Active Agents"
          value={stats?.active_agents ?? 0}
          icon={Server}
          color="green"
          subtext={agentHealth !== null ? `${agentHealth}% of ${stats?.total_agents ?? 0} online` : 'awaiting heartbeats'}
          to="/agents"
          drillTooltip="Open the agents view"
        />
        <StatsCard
          title="Critical Alerts"
          value={stats?.critical_alerts ?? 0}
          icon={AlertCircle}
          color="red"
          subtext="needs investigation"
          to={drillDownUrl({ severity: 'critical' })}
          drillTooltip="Investigate critical events"
        />
        <StatsCard
          title="Blocked Events"
          value={(stats?.blocked_events ?? 0).toLocaleString()}
          icon={ShieldAlert}
          color="orange"
          subtext={blockRate !== null ? `${blockRate}% block rate` : 'enforcement engaged'}
          to={drillDownUrl({ action: 'blocked' })}
          drillTooltip="Investigate blocked events"
        />
      </div>

      {/* Row 1 — events over time + by type */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ChartCard title="Events Over Time" subtitle="Hourly volume across all DLP modules" icon={Activity} accent="indigo" className="lg:col-span-2">
          {timeSeriesLoading ? (
            <ChartSkeleton />
          ) : timeSeries.length === 0 ? (
            <ChartEmpty />
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={timeSeries} margin={{ top: 10, right: 8, left: -12, bottom: 0 }}>
                <defs>
                  <linearGradient id="grad-events" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={CHART_COLORS.primary} stopOpacity={0.45} />
                    <stop offset="100%" stopColor={CHART_COLORS.primary} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={RECHARTS_CONFIG.gridStroke} vertical={false} />
                <XAxis
                  dataKey="timestamp"
                  tick={{ fontSize: 11, fill: tickStyle.fill }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v) => formatTimeIST(new Date(v))}
                  minTickGap={32}
                />
                <YAxis tick={{ fontSize: 11, fill: tickStyle.fill }} tickLine={false} axisLine={false} width={40} />
                <Tooltip
                  cursor={{ stroke: RECHARTS_CONFIG.cursorStroke, strokeWidth: 1, strokeDasharray: '3 3', opacity: RECHARTS_CONFIG.cursorOpacity }}
                  content={<ChartTooltip labelFormatter={(v: any) => formatDateTimeIST(new Date(v))} />}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  name="Events"
                  stroke={CHART_COLORS.primary}
                  strokeWidth={2.25}
                  fill="url(#grad-events)"
                  activeDot={{ r: 5, strokeWidth: 2, stroke: CHART_COLORS.backgrounds.surface }}
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard title="Events by Type" subtitle="Breakdown of channels" icon={TrendingUp} accent="indigo">
          {typeLoading ? (
            <ChartSkeleton />
          ) : eventsByType.length === 0 ? (
            <ChartEmpty />
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={eventsByType}
                  cx="50%"
                  cy="50%"
                  innerRadius={56}
                  outerRadius={92}
                  paddingAngle={3}
                  cornerRadius={4}
                  dataKey="count"
                  nameKey="type"
                  stroke={CHART_COLORS.backgrounds.surface}
                  strokeWidth={2}
                  onClick={(d: any) => {
                    const v = d?.payload?.type ?? d?.type
                    if (v) navigate(drillDownUrl({ module: String(v) }))
                  }}
                  cursor="pointer"
                >
                  {eventsByType.map((_: any, idx: number) => (
                    <Cell key={idx} fill={TYPE_PALETTE[idx % TYPE_PALETTE.length]} style={{ cursor: 'pointer', transition: 'opacity .15s' }} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip drillHint="module" />} />
              </PieChart>
            </ResponsiveContainer>
          )}
          {eventsByType.length > 0 && (
            <ul className="mt-4 grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
              {eventsByType.slice(0, 6).map((row: any, i: number) => (
                <li
                  key={i}
                  className="group -mx-1 flex min-w-0 cursor-pointer items-center gap-2 rounded px-1 py-0.5 transition-colors hover:bg-accent"
                  title={`${DRILL_TOOLTIP}: module=${row.type}`}
                  onClick={() => navigate(drillDownUrl({ module: String(row.type ?? 'unknown') }))}
                >
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: TYPE_PALETTE[i % TYPE_PALETTE.length] }} />
                  <span className="truncate text-muted-foreground group-hover:text-foreground" title={row.type}>
                    {row.type || 'unknown'}
                  </span>
                  <span className="ml-auto font-mono tabular-nums text-muted-foreground">{Number(row.count).toLocaleString()}</span>
                </li>
              ))}
            </ul>
          )}
        </ChartCard>
      </div>

      {/* Row 2 — severity bar + DLP actions */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ChartCard title="Events by Severity" subtitle="Distribution of risk levels" icon={AlertCircle} accent="red" className="lg:col-span-2">
          {severityLoading ? (
            <ChartSkeleton />
          ) : eventsBySeverity.length === 0 ? (
            <ChartEmpty />
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={eventsBySeverity} margin={{ top: 10, right: 8, left: -12, bottom: 0 }}>
                <defs>
                  {Object.entries(SEVERITY_COLORS).map(([k, c]) => (
                    <linearGradient key={k} id={`grad-sev-${k}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={c} stopOpacity={0.95} />
                      <stop offset="100%" stopColor={c} stopOpacity={0.5} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={RECHARTS_CONFIG.gridStroke} vertical={false} />
                <XAxis dataKey="severity" tick={{ fontSize: 11, fill: tickStyle.fill }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 11, fill: tickStyle.fill }} tickLine={false} axisLine={false} width={40} />
                <Tooltip cursor={{ fill: 'rgba(91, 126, 255, 0.08)' }} content={<ChartTooltip drillHint="severity" />} />
                <Bar
                  dataKey="count"
                  radius={[8, 8, 0, 0]}
                  onClick={(d: any) => {
                    const v = d?.payload?.severity ?? d?.severity
                    if (v) navigate(drillDownUrl({ severity: String(v) }))
                  }}
                  cursor="pointer"
                >
                  {eventsBySeverity.map((entry: any, idx: number) => (
                    <Cell key={idx} fill={`url(#grad-sev-${entry.severity})`} style={{ cursor: 'pointer' }} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ActionsPanel
          stats={{
            blocked:  stats?.blocked_events ?? 0,
            critical: stats?.critical_alerts ?? 0,
            total:    stats?.total_events ?? 0,
          }}
        />
      </div>
    </div>
  )
}

// ── Reusable chart card wrapper ─────────────────────────────────────────
function ChartCard({
  title, subtitle, icon: Icon, accent = 'indigo', className, children,
}: {
  title: string
  subtitle?: string
  icon?: React.ComponentType<{ className?: string }>
  accent?: 'indigo' | 'red' | 'orange' | 'green'
  className?: string
  children: React.ReactNode
}) {
  const accentMap = {
    indigo: 'from-primary to-info',
    red:    'from-critical to-destructive',
    orange: 'from-warning to-critical',
    green:  'from-success to-primary',
  }
  return (
    <Card className={cn('relative overflow-hidden p-5', className)}>
      <div className={cn('absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r', accentMap[accent])} />
      <header className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
            {Icon && <Icon className="h-4 w-4 text-muted-foreground" />}
            {title}
          </h3>
          {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
        </div>
      </header>
      {children}
    </Card>
  )
}

// ── DLP actions panel — three rich rows with hover state ────────────────
function ActionsPanel({ stats }: { stats: { blocked: number; critical: number; total: number } }) {
  const rows: Array<{
    label: string
    sub: string
    value: number
    icon: React.ComponentType<{ className?: string }>
    accent: 'critical' | 'warning' | 'primary'
    to: string
  }> = [
    { label: 'Blocked Events',  sub: 'Prevented by policy enforcement',  value: stats.blocked,  icon: ShieldAlert, accent: 'critical', to: drillDownUrl({ action: 'blocked' }) },
    { label: 'Critical Alerts', sub: 'High-severity events outstanding', value: stats.critical, icon: AlertCircle, accent: 'warning',  to: drillDownUrl({ severity: 'critical' }) },
    { label: 'Total Events',    sub: 'Across every monitored channel',   value: stats.total,    icon: FileText,    accent: 'primary',  to: drillDownUrl({}) },
  ]

  return (
    <Card className="relative overflow-hidden p-5">
      <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-primary via-warning to-critical" />
      <header className="mb-4">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
          <Shield className="h-4 w-4 text-muted-foreground" />
          DLP Enforcement
        </h3>
        <p className="mt-0.5 text-xs text-muted-foreground">Live policy outcomes — click to investigate</p>
      </header>
      <ul className="space-y-2.5">
        {rows.map((r) => (
          <ActionRow key={r.label} {...r} />
        ))}
      </ul>
    </Card>
  )
}

function ActionRow({
  label, sub, value, icon: Icon, accent, to,
}: {
  label: string
  sub: string
  value: number
  icon: React.ComponentType<{ className?: string }>
  accent: 'critical' | 'warning' | 'primary'
  to: string
}) {
  const navigate = useNavigate()
  return (
    <li
      onClick={() => navigate(to)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          navigate(to)
        }
      }}
      role="button"
      tabIndex={0}
      title={`${DRILL_TOOLTIP}: ${label}`}
      aria-label={`${label}: ${value.toLocaleString()}. ${DRILL_TOOLTIP}.`}
      className={cn(
        'group relative flex cursor-pointer items-center justify-between gap-3 rounded-lg border border-border p-3',
        `bg-${accent}/5`,
        'transition-all duration-200 hover:-translate-y-0.5 hover:bg-accent',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background'
      )}
    >
      <div className="flex min-w-0 items-center gap-3">
        <div className={cn('flex h-9 w-9 items-center justify-center rounded-lg', `bg-${accent}/15 text-${accent}`)}>
          <Icon className="h-4.5 w-4.5" />
        </div>
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold text-foreground">{label}</p>
          <p className="truncate text-xs text-muted-foreground">{sub}</p>
        </div>
      </div>
      <span className={cn('text-xl font-bold tabular-nums', `text-${accent}`)}>{value.toLocaleString()}</span>
    </li>
  )
}

// ── State stand-ins ────────────────────────────────────────────────────
function ChartSkeleton() {
  return <Skeleton className="h-[300px] w-full" />
}

function ChartEmpty() {
  return (
    <div className="flex h-[300px] items-center justify-center text-sm italic text-muted-foreground">
      No data yet — agents will populate this as events arrive.
    </div>
  )
}
