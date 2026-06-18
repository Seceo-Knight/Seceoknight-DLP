import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Server, AlertCircle, FileText, ShieldAlert, Shield, Activity,
  TrendingUp,
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'

import StatsCard from '@/components/StatsCard'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
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

// ── Color tokens ────────────────────────────────────────────────────────
// Stable severity → hex map. Critical+High lean red/orange (alarm),
// medium amber, low blue. Driven by spec PART 1.
const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#f59e0b',
  low:      '#3b82f6',
  info:     '#64748b',
}

// Distinct, harmonious palette for event-type pie segments. Avoids the
// default rainbow and keeps colours from clashing with the severity
// red/orange family.
const TYPE_PALETTE = [
  '#4f46e5', '#0ea5e9', '#10b981', '#f59e0b',
  '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6',
]

// ── Custom tooltips (PART 4 hover tooltips) ─────────────────────────────
function ChartTooltip({
  active, payload, label, labelFormatter, drillHint,
}: any) {
  if (!active || !payload?.length) return null
  return (
    <div
      className="rounded-md px-3 py-2 text-xs"
      style={{
        background: RECHARTS_CONFIG.tooltipBackground,
        border: `0.5px solid ${RECHARTS_CONFIG.tooltipBorder}`,
        color: CHART_COLORS.text.primary,
        boxShadow: 'none',
      }}
    >
      {label !== undefined && (
        <div className="font-medium mb-1" style={{ color: CHART_COLORS.text.secondary }}>
          {labelFormatter ? labelFormatter(label) : label}
        </div>
      )}
      {payload.map((p: any, i: number) => (
        <div key={i} className="flex items-center gap-2 tabular-nums" style={{ color: CHART_COLORS.text.primary }}>
          <span
            className="inline-block w-2 h-2 rounded-full"
            style={{ background: p.color || p.payload?.fill || CHART_COLORS.primary }}
          />
          <span style={{ color: CHART_COLORS.text.secondary }}>{p.name ?? p.dataKey}:</span>
          <span className="font-semibold">{Number(p.value).toLocaleString()}</span>
        </div>
      ))}
      {/* PART 5: surface "click to drill down" affordance in the tooltip
          itself so the action is discoverable without a separate hint. */}
      {drillHint && (
        <div
          className="mt-1.5 pt-1.5 text-[10px] font-medium uppercase tracking-wider"
          style={{
            borderTop: `1px solid ${CHART_COLORS.backgrounds.tertiary}`,
            color: CHART_COLORS.primary,
          }}
        >
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

  // Derived: agent health % for the green stat card subtext.
  const agentHealth = useMemo(() => {
    if (!stats?.total_agents) return null
    const pct = (stats.active_agents / stats.total_agents) * 100
    return Number.isFinite(pct) ? Math.round(pct) : null
  }, [stats])

  // Block rate for the orange stat card subtext.
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
    <div className="space-y-8">
      {/* Header */}
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-gray-900">
            Security Operations
          </h1>
          <p className="mt-1 text-sm text-gray-500">
            Real-time view of DLP activity across endpoints and channels.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <span className="live-dot" />
          <span className="font-medium text-gray-700">Live</span>
          <span aria-hidden>·</span>
          <span>Refreshes every 5s</span>
          {isFetching && (
            <span className="text-indigo-600 font-medium ml-1">syncing…</span>
          )}
        </div>
      </header>

      {/* Stat cards — every one is a drill-down anchor (PART 1) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6">
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
          subtext={
            agentHealth !== null
              ? `${agentHealth}% of ${stats?.total_agents ?? 0} online`
              : 'awaiting heartbeats'
          }
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
          subtext={
            blockRate !== null
              ? `${blockRate}% block rate`
              : 'enforcement engaged'
          }
          to={drillDownUrl({ action: 'blocked' })}
          drillTooltip="Investigate blocked events"
        />
      </div>

      {/* Row 1 — events over time + by type */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-6">
        {/* Area chart: spans 2/3 on lg */}
        <ChartCard
          title="Events Over Time"
          subtitle="Hourly volume across all DLP modules"
          icon={Activity}
          accent="indigo"
          className="lg:col-span-2"
        >
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
                <YAxis
                  tick={{ fontSize: 11, fill: tickStyle.fill }}
                  tickLine={false}
                  axisLine={false}
                  width={40}
                />
                <Tooltip
                  cursor={{ stroke: RECHARTS_CONFIG.cursorStroke, strokeWidth: 1, strokeDasharray: '3 3', opacity: RECHARTS_CONFIG.cursorOpacity }}
                  content={
                    <ChartTooltip
                      labelFormatter={(v: any) => formatDateTimeIST(new Date(v))}
                    />
                  }
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

        {/* Pie: spans 1/3 */}
        <ChartCard
          title="Events by Type"
          subtitle="Breakdown of channels"
          icon={TrendingUp}
          accent="indigo"
        >
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
                  // PART 2: clicking a segment drills into that module.
                  onClick={(d: any) => {
                    const v = d?.payload?.type ?? d?.type
                    if (v) navigate(drillDownUrl({ module: String(v) }))
                  }}
                  cursor="pointer"
                >
                  {eventsByType.map((_: any, idx: number) => (
                    <Cell
                      key={idx}
                      fill={TYPE_PALETTE[idx % TYPE_PALETTE.length]}
                      style={{ cursor: 'pointer', transition: 'opacity .15s' }}
                    />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip drillHint="module" />} />
              </PieChart>
            </ResponsiveContainer>
          )}
          {/* Custom legend — also clickable as a drill-down (PART 5
              "highlight clickable elements" applies to legend items too). */}
          {eventsByType.length > 0 && (
            <ul className="mt-4 grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
              {eventsByType.slice(0, 6).map((row: any, i: number) => (
                <li
                  key={i}
                  className="flex items-center gap-2 min-w-0 group cursor-pointer rounded px-1 py-0.5 -mx-1 hover:bg-indigo-50 transition-colors"
                  title={`${DRILL_TOOLTIP}: module=${row.type}`}
                  onClick={() =>
                    navigate(drillDownUrl({ module: String(row.type ?? 'unknown') }))
                  }
                >
                  <span
                    className="h-2 w-2 rounded-full shrink-0"
                    style={{ background: TYPE_PALETTE[i % TYPE_PALETTE.length] }}
                  />
                  <span className="text-gray-700 group-hover:text-indigo-700 truncate" title={row.type}>
                    {row.type || 'unknown'}
                  </span>
                  <span className="ml-auto font-mono text-gray-500 tabular-nums">
                    {Number(row.count).toLocaleString()}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </ChartCard>
      </div>

      {/* Row 2 — severity bar + DLP actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-6">
        <ChartCard
          title="Events by Severity"
          subtitle="Distribution of risk levels"
          icon={AlertCircle}
          accent="red"
          className="lg:col-span-2"
        >
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
                <XAxis
                  dataKey="severity"
                  tick={{ fontSize: 11, fill: tickStyle.fill }}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  tick={{ fontSize: 11, fill: tickStyle.fill }}
                  tickLine={false}
                  axisLine={false}
                  width={40}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(91, 126, 255, 0.08)' }}
                  content={<ChartTooltip drillHint="severity" />}
                />
                <Bar
                  dataKey="count"
                  radius={[8, 8, 0, 0]}
                  // PART 2: clicking a bar drills into that severity.
                  onClick={(d: any) => {
                    const v = d?.payload?.severity ?? d?.severity
                    if (v) navigate(drillDownUrl({ severity: String(v) }))
                  }}
                  cursor="pointer"
                >
                  {eventsBySeverity.map((entry: any, idx: number) => (
                    <Cell
                      key={idx}
                      fill={`url(#grad-sev-${entry.severity})`}
                      style={{ cursor: 'pointer' }}
                    />
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
    indigo: 'from-indigo-500 to-blue-500',
    red:    'from-red-500 to-rose-500',
    orange: 'from-orange-500 to-amber-500',
    green:  'from-emerald-500 to-green-500',
  }
  return (
    <section className={cn('card-static relative overflow-hidden', className)}>
      <div className={cn(
        'absolute inset-x-0 top-0 h-[2px] rounded-t-2xl bg-gradient-to-r',
        accentMap[accent],
      )} />
      <header className="flex items-start justify-between gap-3 mb-4">
        <div>
          <h3 className="section-title flex items-center gap-2">
            {Icon && <Icon className="h-4 w-4 text-gray-500" />}
            {title}
          </h3>
          {subtitle && <p className="mt-0.5 text-xs text-gray-500">{subtitle}</p>}
        </div>
      </header>
      {children}
    </section>
  )
}

// ── DLP actions panel — three rich rows with hover state ────────────────
function ActionsPanel({
  stats,
}: {
  stats: { blocked: number; critical: number; total: number }
}) {
  const rows: Array<{
    label: string
    sub: string
    value: number
    icon: React.ComponentType<{ className?: string }>
    accent: 'red' | 'orange' | 'indigo'
    to: string
  }> = [
    {
      label: 'Blocked Events',
      sub: 'Prevented by policy enforcement',
      value: stats.blocked,
      icon: ShieldAlert,
      accent: 'red',
      to: drillDownUrl({ action: 'blocked' }),
    },
    {
      label: 'Critical Alerts',
      sub: 'High-severity events outstanding',
      value: stats.critical,
      icon: AlertCircle,
      accent: 'orange',
      to: drillDownUrl({ severity: 'critical' }),
    },
    {
      label: 'Total Events',
      sub: 'Across every monitored channel',
      value: stats.total,
      icon: FileText,
      accent: 'indigo',
      to: drillDownUrl({}),
    },
  ]

  return (
    <section className="card-static relative overflow-hidden">
      <div className="absolute inset-x-0 top-0 h-[2px] rounded-t-2xl bg-gradient-to-r from-indigo-500 via-orange-500 to-red-500" />
      <header className="mb-4">
        <h3 className="section-title flex items-center gap-2">
          <Shield className="h-4 w-4 text-gray-500" />
          DLP Enforcement
        </h3>
        <p className="mt-0.5 text-xs text-gray-500">Live policy outcomes — click to investigate</p>
      </header>
      <ul className="space-y-3">
        {rows.map((r) => (
          <ActionRow key={r.label} {...r} />
        ))}
      </ul>
    </section>
  )
}

function ActionRow({
  label, sub, value, icon: Icon, accent, to,
}: {
  label: string
  sub: string
  value: number
  icon: React.ComponentType<{ className?: string }>
  accent: 'red' | 'orange' | 'indigo'
  to: string
}) {
  const navigate = useNavigate()
  const map = {
    red:    { bg: 'from-red-50 to-rose-50',         text: 'text-red-700',     iconBg: 'bg-red-100 text-red-600',         border: 'border-red-100' },
    orange: { bg: 'from-orange-50 to-amber-50',     text: 'text-orange-700',  iconBg: 'bg-orange-100 text-orange-600',   border: 'border-orange-100' },
    indigo: { bg: 'from-indigo-50 to-blue-50',      text: 'text-indigo-700',  iconBg: 'bg-indigo-100 text-indigo-600',   border: 'border-indigo-100' },
  } as const
  const m = map[accent]
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
        'group relative flex items-center justify-between gap-3 p-3 rounded-xl border cursor-pointer',
        'bg-gradient-to-br', m.bg, m.border,
        'transition-all duration-200 hover:shadow-md hover:-translate-y-0.5',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2',
      )}
    >
      <div className="flex items-center gap-3 min-w-0">
        <div className={cn('h-10 w-10 rounded-lg flex items-center justify-center', m.iconBg)}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <p className="font-semibold text-gray-900 truncate">{label}</p>
          <p className="text-xs text-gray-600 truncate">{sub}</p>
        </div>
      </div>
      <span className={cn('text-2xl font-bold tabular-nums', m.text)}>
        {value.toLocaleString()}
      </span>
    </li>
  )
}

// ── State stand-ins ────────────────────────────────────────────────────
function ChartSkeleton() {
  return (
    <div className="h-[300px] flex items-center justify-center">
      <div className="h-full w-full rounded-lg bg-gradient-to-br from-gray-100 to-gray-50 animate-pulse" />
    </div>
  )
}

function ChartEmpty() {
  return (
    <div className="h-[300px] flex items-center justify-center text-sm text-gray-400 italic">
      No data yet — agents will populate this as events arrive.
    </div>
  )
}
