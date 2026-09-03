import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle, ArrowUp, ArrowDown, Minus, RefreshCw, ShieldQuestion,
  Activity, Share2, Moon, Ban, type LucideIcon,
} from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { extractErrorDetail } from '@/utils/errorUtils'
import {
  listRiskScores, getRiskScore, recomputeRiskScores,
  type UserRiskScore, type RiskLevel,
} from '@/lib/risk-scoring-api'
import { usePagination } from '@/lib/hooks/useTableState'
import { PageHeader } from '@/components/ui/page-header'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import Modal, { ModalHeader } from '@/components/ui/Modal'
import { DataPagination } from '@/components/ui/pagination'
import { cn } from '@/lib/utils'

// SeceoKnight-original -- not ported from CyberSentinel-DLP (task #120).
// See risk_scoring_service.py's module docstring for the full rationale:
// both agents already detect sensitive single events; this is the first
// place either product looks at a PATTERN of a user's activity over time
// and across channels, instead of one event in isolation.

// Previously styled entirely with the "cs-*" compatibility token set
// (text-cs-ink, border-cs-hair, rounded-cs-card, ...) ported from the
// CyberSentinel reference implementation. Most of those tokens ARE
// aliased onto this app's real palette (see tailwind.config.cjs), but a
// couple weren't (text-cs-ok, rounded-cs-card) and quietly fell back to
// unstyled defaults -- and the page never adopted PageHeader/Card/Badge,
// so even where the colors technically worked it still looked like a
// different, older app bolted onto the rest of the redesigned dashboard.
// Rebuilt on the same shared components as Dashboard/Events/Alerts.

const LEVEL_VARIANT: Record<RiskLevel, 'success' | 'warning' | 'critical'> = {
  low: 'success',
  medium: 'warning',
  high: 'critical',
  critical: 'critical',
}

const fmt = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')

function TrendIcon({ trend }: { trend: UserRiskScore['trend'] }) {
  if (trend === 'rising') return <ArrowUp className="h-3.5 w-3.5 text-critical" />
  if (trend === 'falling') return <ArrowDown className="h-3.5 w-3.5 text-success" />
  return <Minus className="h-3.5 w-3.5 text-muted-foreground" />
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 75 ? 'bg-critical' : score >= 50 ? 'bg-warning' : score >= 25 ? 'bg-info' : 'bg-success'
  return (
    <div className="flex min-w-[100px] items-center gap-2">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
        <div className={cn('h-full', color)} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
      </div>
      <span className="w-9 text-right text-xs tabular-nums text-foreground">{score.toFixed(0)}</span>
    </div>
  )
}

// ── Component breakdown → clickable event filters ─────────────────────────
// Three of the five components map onto a clean per-event predicate (a
// given event either happened off-hours, was blocked, or was high/critical
// severity), so clicking those tiles genuinely filters the events driving
// that number. Volume and channel diversity are population/set-level
// stats rather than per-event flags -- volume counts every event equally
// (so its "filter" is just showing everything), and channel diversity is
// about which distinct channels are represented, so its tile shows one
// representative (most recent) event per channel instead of a boolean
// subset.
//
// The filter itself runs server-side (RiskScoringService.get_events_for_user)
// over the user's FULL scoring window, not just the events already loaded
// in this modal. A client-side filter over only the most-recent N events
// looked identical for a light user but silently showed "0 of 50" for
// tiles whose qualifying events weren't among the 50 most recent -- e.g.
// an "Off Hours" component of 26 with all of that user's off-hours
// activity earlier in a 282-event window. See risk_scoring.py's
// `component` query param and get_events_for_user's docstring.
type ComponentKey = 'volume' | 'channel_diversity' | 'off_hours' | 'block_ratio' | 'severity_mix'

const COMPONENT_META: Record<ComponentKey, { label: string; icon: LucideIcon }> = {
  volume: { label: 'Volume', icon: Activity },
  channel_diversity: { label: 'Channel Diversity', icon: Share2 },
  off_hours: { label: 'Off Hours', icon: Moon },
  block_ratio: { label: 'Block Ratio', icon: Ban },
  severity_mix: { label: 'Severity Mix', icon: AlertTriangle },
}

const LEVEL_FILTERS: { label: string; value: RiskLevel | '' }[] = [
  { label: 'All', value: '' },
  { label: 'Medium+', value: 'medium' },
  { label: 'High+', value: 'high' },
  { label: 'Critical+', value: 'critical' },
]
const LEVEL_ORDER: RiskLevel[] = ['low', 'medium', 'high', 'critical']

export default function RiskScoring() {
  const qc = useQueryClient()
  const [minLevel, setMinLevel] = useState<RiskLevel | ''>('')
  const [selected, setSelected] = useState<string | null>(null)

  const scoresQ = useQuery({
    queryKey: ['risk-scores', minLevel],
    queryFn: () => listRiskScores({ limit: 500, min_level: minLevel || undefined }),
    refetchInterval: 60000,
  })

  const recompute = useMutation({
    mutationFn: () => recomputeRiskScores(14),
    onSuccess: (r) => {
      toast.success(`Recomputed risk scores for ${r.recomputed_users} user(s)`)
      qc.invalidateQueries({ queryKey: ['risk-scores'] })
    },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Recompute failed')),
  })

  const list = scoresQ.data?.scores || []
  const scoresPg = usePagination(list, 25)

  if (scoresQ.isLoading) return <LoadingSpinner size="lg" />
  if (scoresQ.error) return <ErrorMessage message="Failed to load risk scores" retry={() => scoresQ.refetch()} />

  const counts = scoresQ.data?.counts_by_level
  const countAtOrAbove = (level: RiskLevel) =>
    counts
      ? Object.entries(counts)
          .filter(([k]) => LEVEL_ORDER.indexOf(k as RiskLevel) >= LEVEL_ORDER.indexOf(level))
          .reduce((sum, [, v]) => sum + v, 0)
      : 0

  return (
    <div className="space-y-6">
      <PageHeader
        icon={ShieldQuestion}
        title="Risk Scoring"
        description="Behavioral risk score per user over a rolling window."
        actions={
          <Button onClick={() => recompute.mutate()} disabled={recompute.isPending} loading={recompute.isPending}>
            <RefreshCw className={cn('h-4 w-4', recompute.isPending && 'animate-spin')} />
            Recompute
          </Button>
        }
      />

      {/* Level filter */}
      <div className="flex items-center gap-1 rounded-md border border-border bg-card p-0.5 w-fit">
        {LEVEL_FILTERS.map((f) => (
          <button
            key={f.value || 'all'}
            type="button"
            onClick={() => setMinLevel(f.value)}
            className={cn(
              'rounded px-3 py-1.5 text-xs font-medium transition-colors',
              minLevel === f.value
                ? 'bg-primary text-primary-foreground'
                : 'text-muted-foreground hover:bg-muted hover:text-foreground',
            )}
          >
            {f.label} ({f.value === '' ? list.length : countAtOrAbove(f.value)})
          </button>
        ))}
      </div>

      {/* Table */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>User</th><th>Score</th><th>Level</th><th>Trend</th>
                <th>Events</th><th>Blocked</th><th>Channels</th><th>Computed</th>
              </tr>
            </thead>
            <tbody>
              {list.length === 0 && (
                <tr><td colSpan={8} className="py-10 text-center text-muted-foreground">
                  No risk scores yet. Click Recompute to score users from the last 14 days of events.
                </td></tr>
              )}
              {scoresPg.pageRows.map((s) => (
                <tr key={s.id} className="cursor-pointer" onClick={() => setSelected(s.user_email)}>
                  <td>
                    <div className="font-medium text-foreground">{s.username || s.user_email}</div>
                    <div className="text-xs text-muted-foreground">{s.user_email}{s.department ? ` · ${s.department}` : ''}</div>
                  </td>
                  <td><ScoreBar score={s.score} /></td>
                  <td><Badge variant={LEVEL_VARIANT[s.risk_level]}>{s.risk_level}</Badge></td>
                  <td><TrendIcon trend={s.trend} /></td>
                  <td className="tabular-nums text-muted-foreground">{s.event_count}</td>
                  <td className="tabular-nums text-muted-foreground">{s.blocked_count}</td>
                  <td className="tabular-nums text-muted-foreground">{(s.distinct_channels || []).length}</td>
                  <td className="text-xs text-muted-foreground">{fmt(s.computed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {list.length > 0 && (
          <DataPagination
            page={scoresPg.page}
            pageSize={scoresPg.pageSize}
            total={scoresPg.total}
            onPageChange={scoresPg.setPage}
            onPageSizeChange={scoresPg.setPageSize}
          />
        )}
      </Card>

      {selected && <DetailModal userEmail={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function DetailModal({ userEmail, onClose }: { userEmail: string; onClose: () => void }) {
  const [activeComponent, setActiveComponent] = useState<ComponentKey | null>(null)

  const detailQ = useQuery({
    queryKey: ['risk-score-detail', userEmail, activeComponent],
    queryFn: () => getRiskScore(userEmail, activeComponent),
    // Component tiles read from detailQ.data.components below, which is
    // identical across every component filter for a given user -- keep the
    // score/breakdown visible (not blanked to a loading spinner) while a
    // new filtered event list loads in.
    placeholderData: (prev) => prev,
  })

  const displayedEvents = detailQ.data?.recent_events || []
  const displayedTotal = detailQ.data?.recent_events_total ?? displayedEvents.length

  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      label={userEmail}
      header={
        <ModalHeader
          title={
            <span className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-primary" />
              {userEmail}
            </span>
          }
          onClose={onClose}
        />
      }
    >
          {detailQ.isLoading && <LoadingSpinner size="md" />}
          {detailQ.error && <ErrorMessage message="Failed to load detail" retry={() => detailQ.refetch()} />}
          {detailQ.data && (
            <div className="space-y-5">
              <div className="flex items-center gap-4">
                <ScoreBar score={detailQ.data.score} />
                <Badge variant={LEVEL_VARIANT[detailQ.data.risk_level]}>{detailQ.data.risk_level}</Badge>
                <TrendIcon trend={detailQ.data.trend} />
                {detailQ.data.score_previous != null && (
                  <span className="text-xs text-muted-foreground">was {detailQ.data.score_previous.toFixed(0)}</span>
                )}
              </div>

              {detailQ.data.components && (
                <div>
                  <h3 className="mb-2 text-sm font-semibold text-foreground">Component breakdown</h3>
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                    {(Object.entries(detailQ.data.components) as [ComponentKey, number][]).map(([key, value]) => {
                      const meta = COMPONENT_META[key]
                      if (!meta) return null
                      const active = activeComponent === key
                      const v = Number(value)
                      const barColor = v >= 75 ? 'bg-critical' : v >= 50 ? 'bg-warning' : v >= 25 ? 'bg-info' : 'bg-success'
                      return (
                        <button
                          key={key}
                          type="button"
                          onClick={() => setActiveComponent(active ? null : key)}
                          className={cn(
                            'rounded-md border p-2.5 text-left transition-colors',
                            active
                              ? 'border-primary/50 bg-primary/5 ring-1 ring-primary/30'
                              : 'border-border bg-card hover:border-primary/40',
                          )}
                        >
                          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                            <meta.icon className="h-3.5 w-3.5" />
                            {meta.label}
                          </div>
                          <div className="mt-1 font-semibold tabular-nums text-foreground">{v.toFixed(0)}</div>
                          <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-muted">
                            <div className={cn('h-full', barColor)} style={{ width: `${Math.min(100, Math.max(0, v))}%` }} />
                          </div>
                        </button>
                      )
                    })}
                  </div>
                </div>
              )}

              <div>
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-foreground">
                    {activeComponent ? `${COMPONENT_META[activeComponent].label} events` : 'Recent events'}
                    {' '}({displayedEvents.length}{displayedTotal > displayedEvents.length ? ` of ${displayedTotal}` : ''})
                  </h3>
                  {activeComponent && (
                    <button
                      type="button"
                      onClick={() => setActiveComponent(null)}
                      className="text-xs font-medium text-primary hover:underline"
                    >
                      Clear filter
                    </button>
                  )}
                </div>
                <div className="max-h-64 space-y-1.5 overflow-y-auto">
                  {displayedEvents.map((e: any) => (
                    <div key={e.id} className="flex items-center gap-2 rounded-md border border-border bg-card p-2 text-xs">
                      <Badge variant="info" className="shrink-0">{e.event_type}</Badge>
                      <span className="flex-1 truncate text-muted-foreground">{e.description}</span>
                      <span className={e.action === 'blocked' ? 'text-critical' : 'text-muted-foreground'}>{e.action}</span>
                      <span className="shrink-0 text-muted-foreground">{fmt(e.timestamp)}</span>
                    </div>
                  ))}
                  {displayedEvents.length === 0 && (
                    <p className="text-xs text-muted-foreground">
                      {activeComponent ? 'No events match this filter.' : 'No recent events found.'}
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}
    </Modal>
  )
}
