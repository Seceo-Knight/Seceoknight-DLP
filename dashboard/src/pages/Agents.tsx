import { useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Server, RefreshCw, Trash2, PowerOff, Eraser } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import Modal, { ModalHeader, ModalFooter } from '@/components/ui/Modal'
import {
  getAllAgents,
  deleteAgent,
  decommissionAgent,
  cleanupStaleAgents,
  type Agent,
} from '@/lib/api'
import { formatRelativeTime } from '@/lib/utils'
import { usePagination } from '@/lib/hooks/useTableState'
import { DataPagination } from '@/components/ui/pagination'

type LifecycleTier = 'active' | 'disconnected' | 'inactive' | 'stale'
type FilterType = 'all' | LifecycleTier

// Resolve an agent's lifecycle tier with a backwards-compatible fallback.
// Some older API responses (or in-flight cached payloads) still ship the
// boolean ``is_active`` only, so we degrade gracefully instead of dropping
// the row to "stale".
const resolveTier = (agent: Agent): LifecycleTier => {
  if (agent.lifecycle_status) return agent.lifecycle_status
  return agent.is_active ? 'active' : 'disconnected'
}

const TIER_BADGE: Record<LifecycleTier, { label: string; className: string; dot: string }> = {
  active: {
    label: 'Active',
    className: 'bg-green-500/15 text-green-300',
    dot: 'bg-green-600',
  },
  disconnected: {
    label: 'Disconnected',
    className: 'bg-yellow-500/15 text-yellow-300',
    dot: 'bg-yellow-500',
  },
  inactive: {
    label: 'Inactive',
    className: 'bg-orange-500/15 text-orange-300',
    dot: 'bg-orange-500',
  },
  stale: {
    label: 'Stale',
    className: 'bg-red-500/15 text-red-300',
    dot: 'bg-red-600',
  },
}

const TIER_HINT: Record<LifecycleTier, string> = {
  active: 'Heartbeat within last 60 seconds',
  disconnected: 'No heartbeat for >60 seconds',
  inactive: 'No heartbeat for >24 hours',
  stale: 'No heartbeat for >7 days',
}

type ConfirmAction = 'delete' | 'decommission'

interface ConfirmState {
  agent: Agent
  action: ConfirmAction
}

interface CleanupCandidate {
  agent_id: string
  name?: string
  agent_code?: number
  last_seen?: string | null
}

interface CleanupPreview {
  cutoff: string
  older_than_days: number
  would_remove_count: number
  candidates: CleanupCandidate[]
}

export default function Agents() {
  const [filter, setFilter] = useState<FilterType>('all')
  const [confirm, setConfirm] = useState<ConfirmState | null>(null)
  const [cleanupOpen, setCleanupOpen] = useState(false)
  const [cleanupDays, setCleanupDays] = useState(30)
  const [cleanupPreview, setCleanupPreview] = useState<CleanupPreview | null>(null)
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  // Fetch all agents (including disconnected ones) with frequent refresh
  const {
    data: agents,
    isLoading,
    error,
    refetch,
  } = useQuery<Agent[]>({
    queryKey: ['allAgents'],
    queryFn: getAllAgents,
    refetchInterval: 5000,
    staleTime: 0,
  })

  const deleteMutation = useMutation({
    mutationFn: (agentId: string) => deleteAgent(agentId),
    onSuccess: (_, agentId) => {
      toast.success(`Agent ${agentId.slice(0, 8)}… removed`)
      queryClient.invalidateQueries({ queryKey: ['allAgents'] })
      queryClient.invalidateQueries({ queryKey: ['agents'] })
      setConfirm(null)
    },
    onError: () => {
      toast.error('Failed to remove agent')
    },
  })

  const decommissionMutation = useMutation({
    mutationFn: (agentId: string) => decommissionAgent(agentId),
    onSuccess: (_, agentId) => {
      toast.success(`Agent ${agentId.slice(0, 8)}… marked as decommissioned`)
      queryClient.invalidateQueries({ queryKey: ['allAgents'] })
      queryClient.invalidateQueries({ queryKey: ['agents'] })
      setConfirm(null)
    },
    onError: () => {
      toast.error('Failed to mark agent as decommissioned')
    },
  })

  // Two-step cleanup flow: dry-run preview first so the admin sees the
  // affected set, then a second click with dry_run=false actually applies.
  const cleanupPreviewMutation = useMutation({
    mutationFn: (days: number) => cleanupStaleAgents(days, true),
    onSuccess: (data) => {
      setCleanupPreview(data)
    },
    onError: () => {
      toast.error('Failed to fetch cleanup preview')
    },
  })

  const cleanupApplyMutation = useMutation({
    mutationFn: (days: number) => cleanupStaleAgents(days, false),
    onSuccess: (data) => {
      const removed = data?.removed_count ?? 0
      toast.success(
        removed === 0
          ? 'No stale agents found'
          : `Removed ${removed} stale agent${removed === 1 ? '' : 's'}`,
      )
      queryClient.invalidateQueries({ queryKey: ['allAgents'] })
      queryClient.invalidateQueries({ queryKey: ['agents'] })
      setCleanupOpen(false)
      setCleanupPreview(null)
    },
    onError: () => {
      toast.error('Failed to apply cleanup')
    },
  })

  // This whole derivation -- including usePagination -- has to run
  // unconditionally on every render, before the isLoading/error early
  // returns below, since hooks can't be called conditionally. `agents` is
  // simply undefined while loading, which the Array.isArray guard here
  // already handles.
  const list: Agent[] = Array.isArray(agents) ? agents : []

  const counts: Record<LifecycleTier, number> = {
    active: 0,
    disconnected: 0,
    inactive: 0,
    stale: 0,
  }
  list.forEach((a) => {
    counts[resolveTier(a)] += 1
  })

  const filteredAgents = list.filter((agent) => {
    if (filter === 'all') return true
    return resolveTier(agent) === filter
  })

  const { page, pageSize, pageRows, setPage, setPageSize } = usePagination(filteredAgents, 25)

  if (isLoading) {
    return <LoadingSpinner size="lg" />
  }

  if (error) {
    return (
      <ErrorMessage
        message="Failed to load agents"
        retry={() => refetch()}
      />
    )
  }

  const handleAgentClick = (agentId: string) => {
    navigate(`/events?agent=${agentId}`)
  }

  // The confirm dialog is driven by setConfirm(null) on close, which would
  // otherwise blank the panel mid-exit-animation -- remember the last
  // non-null value so Modal's ~150ms fade-out still has content to show.
  const lastConfirmRef = useRef<ConfirmState | null>(null)
  if (confirm) lastConfirmRef.current = confirm
  const displayConfirm = confirm ?? lastConfirmRef.current

  const confirmTitle =
    displayConfirm?.action === 'delete' ? 'Remove Agent' : 'Mark as Decommissioned'
  const confirmBody =
    displayConfirm?.action === 'delete'
      ? 'This soft-deletes the agent record. Event history is preserved, but the agent will no longer appear in this list. Admins can restore it via the API audit view.'
      : 'This marks the agent as decommissioned. The record stays visible with a "Decommissioned" badge and event history is preserved.'
  const confirmCta = displayConfirm?.action === 'delete' ? 'Remove' : 'Decommission'
  const confirmCtaClass =
    displayConfirm?.action === 'delete'
      ? 'bg-red-600 hover:bg-red-700 text-white'
      : 'bg-amber-600 hover:bg-amber-700 text-white'

  const isMutating = deleteMutation.isPending || decommissionMutation.isPending

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Agents</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Manage and monitor DLP agents (includes agent history)
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setCleanupOpen(true)
              setCleanupPreview(null)
            }}
            className="btn-secondary"
            title="Soft-delete agents that have been silent for N days"
          >
            <Eraser className="h-4 w-4" />
            Cleanup Stale
          </button>
          <button
            onClick={() => refetch()}
            className="btn-secondary"
            disabled={isLoading}
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Lifecycle Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div
          className={`card cursor-pointer hover:shadow-lg transition-shadow ${filter === 'all' ? 'ring-2 ring-blue-500' : ''}`}
          onClick={() => setFilter('all')}
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/15 rounded-lg">
              <Server className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Total</p>
              <p className="text-2xl font-bold text-foreground">{list.length}</p>
              <p className="text-xs text-muted-foreground mt-1">All agents</p>
            </div>
          </div>
        </div>
        {(['active', 'disconnected', 'inactive', 'stale'] as LifecycleTier[]).map((tier) => {
          const meta = TIER_BADGE[tier]
          return (
            <div
              key={tier}
              className={`card cursor-pointer hover:shadow-lg transition-shadow ${filter === tier ? 'ring-2 ring-blue-500' : ''}`}
              onClick={() => setFilter(tier)}
            >
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${meta.className}`}>
                  <Server className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">{meta.label}</p>
                  <p className="text-2xl font-bold text-foreground">{counts[tier]}</p>
                  <p className="text-xs text-muted-foreground mt-1">{TIER_HINT[tier]}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Agents Table */}
      <div className="card p-0">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Agent ID</th>
                <th>Name</th>
                <th>OS</th>
                <th>User</th>
                <th>Version</th>
                <th>IP Address</th>
                <th>Last Seen</th>
                <th>Registered</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAgents.length === 0 ? (
                <tr>
                  <td colSpan={10} className="text-center py-12">
                    <Server className="h-12 w-12 text-muted-foreground/70 mx-auto mb-3" />
                    <p className="text-muted-foreground font-medium">
                      {filter === 'all' ? 'No agents registered' : `No ${TIER_BADGE[filter].label.toLowerCase()} agents`}
                    </p>
                    <p className="text-sm text-muted-foreground mt-1">
                      {filter === 'all'
                        ? 'Agents will appear here once they register with the server'
                        : 'Click "Total" to see all agents'}
                    </p>
                  </td>
                </tr>
              ) : (
                pageRows.map((agent) => {
                  const tier = resolveTier(agent)
                  const badge = TIER_BADGE[tier]
                  return (
                    <tr
                      key={agent.agent_id}
                      className="cursor-pointer hover:bg-accent transition-colors"
                    >
                      <td onClick={() => handleAgentClick(agent.agent_id)}>
                        <div className="flex flex-col gap-1">
                          <span
                            className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${badge.className}`}
                            title={TIER_HINT[tier]}
                          >
                            <span className={`w-2 h-2 rounded-full mr-1.5 ${badge.dot}`}></span>
                            {badge.label}
                          </span>
                          {agent.decommissioned && (
                            <span
                              className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-secondary text-foreground/90 uppercase tracking-wide"
                              title={
                                agent.decommissioned_at
                                  ? `Decommissioned ${formatRelativeTime(agent.decommissioned_at)}`
                                  : 'Decommissioned'
                              }
                            >
                              Decommissioned
                            </span>
                          )}
                        </div>
                      </td>
                      <td onClick={() => handleAgentClick(agent.agent_id)}>
                        <code
                          className="text-xs bg-secondary px-2 py-1 rounded font-mono tabular-nums"
                          title={agent.agent_id}
                        >
                          {typeof agent.agent_code === 'number'
                            ? String(agent.agent_code).padStart(3, '0')
                            : agent.agent_id}
                        </code>
                      </td>
                      <td onClick={() => handleAgentClick(agent.agent_id)}>
                        <div>
                          <div className="font-medium text-foreground">{agent.name}</div>
                          {agent.hostname && (
                            <div className="text-xs text-muted-foreground">{agent.hostname}</div>
                          )}
                        </div>
                      </td>
                      <td onClick={() => handleAgentClick(agent.agent_id)}>
                        <div className="flex items-center gap-2">
                          <span>{agent.os}</span>
                          {agent.os_version && (
                            <span className="text-xs text-muted-foreground">{agent.os_version}</span>
                          )}
                        </div>
                      </td>
                      <td onClick={() => handleAgentClick(agent.agent_id)}>
                        <span className="text-sm text-foreground/90">{agent.username || '—'}</span>
                      </td>
                      <td onClick={() => handleAgentClick(agent.agent_id)}>
                        <code className="text-xs text-muted-foreground">{agent.version || '—'}</code>
                      </td>
                      <td onClick={() => handleAgentClick(agent.agent_id)}>
                        <code className="text-xs">{agent.ip_address}</code>
                      </td>
                      <td onClick={() => handleAgentClick(agent.agent_id)}>
                        <span
                          className="text-sm text-muted-foreground"
                          title={agent.last_seen}
                        >
                          {agent.last_seen
                            ? `${formatRelativeTime(agent.last_seen)}`
                            : 'Never'}
                        </span>
                      </td>
                      <td onClick={() => handleAgentClick(agent.agent_id)}>
                        <span className="text-sm text-muted-foreground">
                          {formatRelativeTime(agent.created_at)}
                        </span>
                      </td>
                      <td className="text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-1">
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              setConfirm({ agent, action: 'decommission' })
                            }}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium text-amber-400 hover:bg-amber-500/10 disabled:opacity-50"
                            disabled={agent.decommissioned || isMutating}
                            title={
                              agent.decommissioned
                                ? 'Already decommissioned'
                                : 'Mark this agent as decommissioned'
                            }
                          >
                            <PowerOff className="h-3.5 w-3.5" />
                            Decommission
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              setConfirm({ agent, action: 'delete' })
                            }}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium text-red-400 hover:bg-red-500/10 disabled:opacity-50"
                            disabled={isMutating}
                            title="Soft-delete this agent (event history is preserved)"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                            Remove
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
        {filteredAgents.length > 0 && (
          <DataPagination
            page={page}
            pageSize={pageSize}
            total={filteredAgents.length}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
          />
        )}
      </div>

      {/* Cleanup-stale modal — admin sweeps agents not seen for >N days */}
      <Modal
        open={cleanupOpen}
        onClose={() => {
          if (cleanupApplyMutation.isPending) return
          setCleanupOpen(false)
          setCleanupPreview(null)
        }}
        size="lg"
        label="Cleanup Stale Agents"
        header={
          <ModalHeader
            title="Cleanup Stale Agents"
            onClose={() => {
              if (cleanupApplyMutation.isPending) return
              setCleanupOpen(false)
              setCleanupPreview(null)
            }}
          />
        }
        footer={
          <ModalFooter>
            <button
              onClick={() => {
                setCleanupOpen(false)
                setCleanupPreview(null)
              }}
              className="px-3 py-1.5 rounded text-sm font-medium text-foreground/90 hover:bg-accent"
              disabled={cleanupApplyMutation.isPending}
            >
              Cancel
            </button>
            <button
              onClick={() => cleanupApplyMutation.mutate(cleanupDays)}
              className="px-3 py-1.5 rounded text-sm font-medium bg-red-600 hover:bg-red-700 text-white disabled:opacity-50"
              disabled={
                !cleanupPreview ||
                cleanupPreview.would_remove_count === 0 ||
                cleanupApplyMutation.isPending
              }
              title={
                !cleanupPreview
                  ? 'Run a preview first'
                  : cleanupPreview.would_remove_count === 0
                    ? 'Nothing to remove'
                    : 'Soft-delete the listed agents'
              }
            >
              {cleanupApplyMutation.isPending ? 'Removing…' : 'Apply Cleanup'}
            </button>
          </ModalFooter>
        }
      >
          <div className="space-y-4 text-sm">
            <p className="text-muted-foreground">
              Soft-deletes agents whose last heartbeat is older than the
              threshold below. Event history is preserved.
            </p>
            <div className="flex items-center gap-3">
              <label className="text-sm font-medium text-foreground/90">
                Older than
              </label>
              <input
                type="number"
                min={1}
                value={cleanupDays}
                onChange={(e) => {
                  const next = Number(e.target.value)
                  setCleanupDays(Number.isFinite(next) && next > 0 ? next : 1)
                  setCleanupPreview(null)
                }}
                className="w-24 px-2 py-1 border border-border rounded text-sm"
                disabled={cleanupApplyMutation.isPending}
              />
              <span className="text-sm text-foreground/90">days</span>
              <button
                onClick={() => cleanupPreviewMutation.mutate(cleanupDays)}
                className="ml-auto px-3 py-1 rounded text-sm font-medium border border-border hover:bg-accent disabled:opacity-50"
                disabled={cleanupPreviewMutation.isPending || cleanupApplyMutation.isPending}
              >
                {cleanupPreviewMutation.isPending ? 'Previewing…' : 'Preview'}
              </button>
            </div>
            {cleanupPreview && (
              <div className="border border-border rounded p-3 bg-muted/30 max-h-60 overflow-y-auto">
                <p className="font-medium text-foreground mb-2">
                  {cleanupPreview.would_remove_count === 0
                    ? 'No agents match — nothing to remove.'
                    : `${cleanupPreview.would_remove_count} agent${cleanupPreview.would_remove_count === 1 ? '' : 's'} would be soft-deleted:`}
                </p>
                {cleanupPreview.candidates.length > 0 && (
                  <ul className="space-y-1 text-xs">
                    {cleanupPreview.candidates.map((c) => (
                      <li key={c.agent_id} className="flex items-center gap-2">
                        {typeof c.agent_code === 'number' && (
                          <span className="font-mono tabular-nums text-muted-foreground">
                            {String(c.agent_code).padStart(3, '0')}
                          </span>
                        )}
                        <span className="font-medium">{c.name || c.agent_id}</span>
                        <span className="text-muted-foreground ml-auto">
                          {c.last_seen ? formatRelativeTime(c.last_seen) : 'Never'}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
      </Modal>

      {/* Confirmation modal — shared for both Remove and Decommission actions */}
      <Modal
        open={!!confirm}
        onClose={() => !isMutating && setConfirm(null)}
        size="md"
        label={confirmTitle}
        header={
          <ModalHeader title={confirmTitle} onClose={() => !isMutating && setConfirm(null)} />
        }
        footer={
          <ModalFooter>
            <button
              onClick={() => setConfirm(null)}
              className="px-3 py-1.5 rounded text-sm font-medium text-foreground/90 hover:bg-accent"
              disabled={isMutating}
            >
              Cancel
            </button>
            <button
              onClick={() => {
                if (!displayConfirm) return
                if (displayConfirm.action === 'delete') {
                  deleteMutation.mutate(displayConfirm.agent.agent_id)
                } else {
                  decommissionMutation.mutate(displayConfirm.agent.agent_id)
                }
              }}
              className={`px-3 py-1.5 rounded text-sm font-medium ${confirmCtaClass} disabled:opacity-50`}
              disabled={isMutating}
            >
              {isMutating ? 'Working…' : confirmCta}
            </button>
          </ModalFooter>
        }
      >
          {displayConfirm && (
            <div className="space-y-3 text-sm">
              <p className="text-foreground/90">
                <span className="font-medium">{displayConfirm.agent.name}</span>
                {typeof displayConfirm.agent.agent_code === 'number' && (
                  <span className="ml-2 font-mono text-xs text-muted-foreground">
                    ({String(displayConfirm.agent.agent_code).padStart(3, '0')})
                  </span>
                )}
              </p>
              <p className="text-muted-foreground">{confirmBody}</p>
            </div>
          )}
      </Modal>
    </div>
  )
}
