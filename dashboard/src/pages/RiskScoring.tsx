import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ArrowUp, ArrowDown, Minus, RefreshCw, ShieldQuestion } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { extractErrorDetail } from '@/utils/errorUtils'
import {
  listRiskScores, getRiskScore, recomputeRiskScores,
  type UserRiskScore, type RiskLevel,
} from '@/lib/risk-scoring-api'
import { usePagination } from '@/lib/hooks/useTableState'
import Modal, { ModalHeader } from '@/components/ui/Modal'
import { DataPagination } from '@/components/ui/pagination'

// SeceoKnight-original -- not ported from CyberSentinel-DLP (task #120).
// See risk_scoring_service.py's module docstring for the full rationale:
// both agents already detect sensitive single events; this is the first
// place either product looks at a PATTERN of a user's activity over time
// and across channels, instead of one event in isolation.

const LEVEL_STYLE: Record<RiskLevel, string> = {
  low: 'badge badge-success',
  medium: 'badge badge-warning',
  high: 'badge badge-danger',
  critical: 'badge badge-danger',
}

const fmt = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')

function TrendIcon({ trend }: { trend: UserRiskScore['trend'] }) {
  if (trend === 'rising') return <ArrowUp className="h-3.5 w-3.5 text-critical" />
  if (trend === 'falling') return <ArrowDown className="h-3.5 w-3.5 text-cs-ok" />
  return <Minus className="h-3.5 w-3.5 text-cs-muted" />
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 75 ? 'bg-critical' : score >= 50 ? 'bg-warning' : score >= 25 ? 'bg-cs-indigo' : 'bg-cs-ok'
  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 h-1.5 rounded-full bg-cs-hair overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
      </div>
      <span className="num text-xs w-9 text-right">{score.toFixed(0)}</span>
    </div>
  )
}

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="eyebrow mb-1.5">Detect</p>
          <h1 className="text-2xl font-bold tracking-tight text-cs-ink">Risk Scoring</h1>
          <p className="mt-1 text-sm text-cs-ink-2 max-w-2xl">
            Per-user behavioral score over a 14-day rolling window -- event volume, channel diversity
            (USB + network + print in one window scores higher than heavy use of just one), off-hours
            activity, block ratio, and severity mix. Complements single-event content detection with a
            pattern-over-time view neither this product nor its competitors currently have.
          </p>
        </div>
        <button className="btn btn-primary shrink-0" disabled={recompute.isPending} onClick={() => recompute.mutate()}>
          <RefreshCw className={`h-4 w-4 ${recompute.isPending ? 'animate-spin' : ''}`} /> Recompute
        </button>
      </div>

      {/* Explainability banner */}
      <div className="flex items-center gap-3 rounded-cs-card border border-cs-hair bg-cs-indigo-faint px-4 py-3 text-sm text-cs-ink-2">
        <ShieldQuestion className="h-5 w-5 text-cs-indigo shrink-0" />
        <span>
          Statistical baselining, not a black-box model -- every score's component breakdown is visible
          in the user's detail view, so an analyst can always see exactly why a number is what it is.
        </span>
      </div>

      {/* Level filter chips */}
      <div className="flex flex-wrap items-center gap-2">
        {(['', 'medium', 'high', 'critical'] as const).map((lvl) => (
          <button
            key={lvl || 'all'}
            className={`badge ${minLevel === lvl ? 'badge-info' : 'badge-warning opacity-60 hover:opacity-100'}`}
            onClick={() => setMinLevel(lvl)}
          >
            {lvl === '' ? `All (${list.length})` : `${lvl[0].toUpperCase()}${lvl.slice(1)}+ (${counts ? Object.entries(counts).filter(([k]) => {
              const order = ['low', 'medium', 'high', 'critical']
              return order.indexOf(k) >= order.indexOf(lvl)
            }).reduce((sum, [, v]) => sum + v, 0) : 0})`}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="rounded-cs-card border border-cs-hair bg-cs-panel overflow-hidden">
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
                <tr><td colSpan={8} className="text-center text-cs-muted py-10">
                  No risk scores yet. Click Recompute to score users from the last 14 days of events.
                </td></tr>
              )}
              {scoresPg.pageRows.map((s) => (
                <tr key={s.id} className="cursor-pointer hover:bg-cs-hair-2/50" onClick={() => setSelected(s.user_email)}>
                  <td>
                    <div className="font-medium text-cs-ink">{s.username || s.user_email}</div>
                    <div className="text-xs text-cs-muted">{s.user_email}{s.department ? ` · ${s.department}` : ''}</div>
                  </td>
                  <td><ScoreBar score={s.score} /></td>
                  <td><span className={LEVEL_STYLE[s.risk_level]}>{s.risk_level}</span></td>
                  <td><TrendIcon trend={s.trend} /></td>
                  <td className="num text-cs-ink-2">{s.event_count}</td>
                  <td className="num text-cs-ink-2">{s.blocked_count}</td>
                  <td className="num text-cs-ink-2">{(s.distinct_channels || []).length}</td>
                  <td className="text-cs-muted text-xs">{fmt(s.computed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {list.length > 0 && (
          <div className="px-4 py-3 border-t border-cs-hair">
            <DataPagination
              page={scoresPg.page}
              pageSize={scoresPg.pageSize}
              total={scoresPg.total}
              onPageChange={scoresPg.setPage}
              onPageSizeChange={scoresPg.setPageSize}
            />
          </div>
        )}
      </div>

      {selected && <DetailModal userEmail={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function DetailModal({ userEmail, onClose }: { userEmail: string; onClose: () => void }) {
  const detailQ = useQuery({
    queryKey: ['risk-score-detail', userEmail],
    queryFn: () => getRiskScore(userEmail),
  })

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
              <AlertTriangle className="h-5 w-5 text-cs-indigo" />
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
                <span className={LEVEL_STYLE[detailQ.data.risk_level]}>{detailQ.data.risk_level}</span>
                <TrendIcon trend={detailQ.data.trend} />
                {detailQ.data.score_previous != null && (
                  <span className="text-xs text-cs-muted">was {detailQ.data.score_previous.toFixed(0)}</span>
                )}
              </div>

              {detailQ.data.components && (
                <div>
                  <h3 className="text-sm font-semibold text-cs-ink mb-2">Component breakdown</h3>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {Object.entries(detailQ.data.components).map(([key, value]) => (
                      <div key={key} className="rounded-cs-sm border border-cs-hair p-2">
                        <div className="text-xs text-cs-muted capitalize">{key.replace(/_/g, ' ')}</div>
                        <div className="num text-cs-ink font-medium">{Number(value).toFixed(0)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <h3 className="text-sm font-semibold text-cs-ink mb-2">
                  Recent events ({detailQ.data.recent_events.length})
                </h3>
                <div className="space-y-1.5 max-h-64 overflow-y-auto">
                  {detailQ.data.recent_events.map((e) => (
                    <div key={e.id} className="flex items-center gap-2 text-xs rounded-cs-sm border border-cs-hair p-2">
                      <span className="badge badge-info shrink-0">{e.event_type}</span>
                      <span className="text-cs-ink-2 flex-1 truncate">{e.description}</span>
                      <span className={e.action === 'blocked' ? 'text-critical' : 'text-cs-muted'}>{e.action}</span>
                      <span className="text-cs-muted shrink-0">{fmt(e.timestamp)}</span>
                    </div>
                  ))}
                  {detailQ.data.recent_events.length === 0 && (
                    <p className="text-xs text-cs-muted">No recent events found.</p>
                  )}
                </div>
              </div>
            </div>
          )}
    </Modal>
  )
}
