import { useState } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Edit, Trash2, Power, PowerOff, TestTube, Search } from 'lucide-react'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import StatsCard from '@/components/StatsCard'
import { PageHeader } from '@/components/ui/page-header'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { EmptyState } from '@/components/ui/empty-state'
import RuleModal from '@/components/rules/RuleModal'
import RuleTestModal from '@/components/rules/RuleTestModal'
import { getRules, getRuleStatistics, deleteRule, toggleRule, type Rule } from '@/lib/rules-api'
import { formatRelativeTime, cn } from '@/lib/utils'
import { usePagination } from '@/lib/hooks/useTableState'
import { DataPagination } from '@/components/ui/pagination'
import { useConfirm } from '@/components/ui/Modal'
import { tone, type Tone } from '@/lib/tone'
import toast from 'react-hot-toast'

type FilterType = 'all' | 'regex' | 'keyword' | 'dictionary'

// Same 4-tone severity ladder as Events/Alerts/Risk Scoring/Log Explorer
// (critical=red, high=orange, medium=yellow, low=blue). This page
// previously mapped low -> green, a scheme that disagreed with every
// other tab's severity colors.
const severityTone = (severity?: string | null): Tone => {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return 'red'
    case 'high': return 'orange'
    case 'medium': return 'yellow'
    case 'low': return 'blue'
    default: return 'gray'
  }
}

// The backend's own hard ceiling (GET /rules/ le=1000) -- there's no
// dedicated pagination UI here (rule sets are a bounded configuration
// resource, not an ever-growing event log), so this just needs to be
// high enough to never silently truncate a real deployment's rule set.
// Previously the page never passed `limit` at all, so it silently rode
// the backend's *default* of 100 -- fine at today's 21 rules, but a
// deployment with more custom regex/keyword/dictionary rules than that
// would have rules quietly missing from the list with no indication.
const RULES_FETCH_LIMIT = 1000

export default function Rules() {
  const { confirm, dialog: confirmDialog } = useConfirm()
  const [filter, setFilter] = useState<FilterType>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [isTestModalOpen, setIsTestModalOpen] = useState(false)
  const queryClient = useQueryClient()

  // Fetch rules
  const { data: rules, isLoading, error, refetch } = useQuery({
    queryKey: ['rules', filter],
    queryFn: () => getRules({ type: filter === 'all' ? undefined : filter, limit: RULES_FETCH_LIMIT }),
    refetchInterval: 30000,
  })

  // Fetch statistics
  const { data: stats } = useQuery({
    queryKey: ['rule-statistics'],
    queryFn: getRuleStatistics,
    refetchInterval: 30000,
  })

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: deleteRule,
    onSuccess: () => {
      toast.success('Rule deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['rule-statistics'] })
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to delete rule'))
    },
  })

  // Toggle mutation
  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      toggleRule(id, enabled),
    onSuccess: (data) => {
      toast.success(`Rule ${data.enabled ? 'enabled' : 'disabled'} successfully`)
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['rule-statistics'] })
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to toggle rule'))
    },
  })

  const handleDelete = async (id: string, name: string) => {
    if (!(await confirm({
      title: 'Delete rule',
      confirmLabel: 'Delete',
      children: `Are you sure you want to delete rule "${name}"?`,
    }))) {
      return
    }
    deleteMutation.mutate(id)
  }

  const handleToggle = (id: string, currentState: boolean) => {
    toggleMutation.mutate({ id, enabled: !currentState })
  }

  const handleEdit = (rule: Rule) => {
    setSelectedRule(rule)
    setIsModalOpen(true)
  }

  const handleCreate = () => {
    setSelectedRule(null)
    setIsModalOpen(true)
  }

  // Filter rules by search query
  const filteredRules = rules?.filter((rule) => {
    if (!searchQuery) return true
    const query = searchQuery.toLowerCase()
    return (
      rule.name.toLowerCase().includes(query) ||
      rule.description?.toLowerCase().includes(query) ||
      rule.category?.toLowerCase().includes(query) ||
      rule.type.toLowerCase().includes(query)
    )
  })

  const { page, pageSize, pageRows, setPage, setPageSize } = usePagination(filteredRules || [], 25)

  if (isLoading) {
    return <LoadingSpinner size="lg" />
  }

  if (error) {
    return <ErrorMessage message="Failed to load rules" retry={() => refetch()} />
  }

  // Honest truncation notice: stats.total_rules is a true DB aggregate
  // (RuleService.get_rule_statistics), independent of RULES_FETCH_LIMIT
  // -- if the two disagree, the list below is missing rules rather than
  // silently showing an incomplete set as if it were everything.
  const fetchedCount = rules?.length ?? 0
  const isTruncated = !!stats && filter === 'all' && stats.total_rules > fetchedCount

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Shield}
        title="Classification Rules"
        description="Manage detection rules for data classification."
        actions={
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setIsTestModalOpen(true)}>
              <TestTube className="h-4 w-4" />
              Test Rules
            </Button>
            <Button onClick={handleCreate}>
              <Plus className="h-4 w-4" />
              Create Rule
            </Button>
          </div>
        }
      />

      {isTruncated && (
        <div className="rounded-lg border border-warning/30 bg-warning/5 px-4 py-3 text-sm text-foreground">
          Showing {fetchedCount.toLocaleString()} of {stats!.total_rules.toLocaleString()} rules
          (fetch cap reached). Narrow your filters or search to find a specific rule.
        </div>
      )}

      {/* Statistics */}
      {stats && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          <StatsCard title="Total Rules" value={stats.total_rules} icon={Shield} color="indigo" />
          <StatsCard title="Enabled" value={stats.enabled_rules} icon={Power} color="green" />
          <StatsCard title="Disabled" value={stats.disabled_rules} icon={PowerOff} color="gray" />
          <Card className="p-4">
            <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">By Type</p>
            <div className="space-y-1 text-sm">
              <div className="flex justify-between"><span className="text-muted-foreground">Regex</span><span className="font-medium text-foreground">{stats.by_type.regex}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Keyword</span><span className="font-medium text-foreground">{stats.by_type.keyword}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Dictionary</span><span className="font-medium text-foreground">{stats.by_type.dictionary}</span></div>
            </div>
          </Card>
        </div>
      )}

      {/* Filters */}
      <Card className="p-4">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search rules by name, category, or type..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9"
            />
          </div>
          <div className="flex items-center gap-1 rounded-md border border-border bg-card p-0.5">
            {(['all', 'regex', 'keyword', 'dictionary'] as const).map((type) => (
              <button
                key={type}
                type="button"
                onClick={() => setFilter(type)}
                className={cn(
                  'rounded px-3 py-1.5 text-xs font-medium transition-colors',
                  filter === type
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                )}
              >
                {type === 'all' ? 'All' : type.charAt(0).toUpperCase() + type.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </Card>

      {/* Rules Table */}
      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Name</th>
                <th>Type</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Weight</th>
                <th>Matches</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules?.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-0">
                    <EmptyState
                      icon={Shield}
                      title="No rules found"
                      description={searchQuery ? 'Try adjusting your search query.' : 'Create your first classification rule.'}
                    />
                  </td>
                </tr>
              ) : (
                pageRows.map((rule) => (
                  <tr key={rule.id} className="hover:bg-accent">
                    <td>
                      <button
                        onClick={() => handleToggle(rule.id, rule.enabled)}
                        className={cn(
                          'inline-flex items-center gap-1 rounded-full border px-2 py-1 text-xs font-medium transition-colors',
                          rule.enabled ? tone('green') : tone('gray'),
                        )}
                      >
                        {rule.enabled ? <Power className="h-3 w-3" /> : <PowerOff className="h-3 w-3" />}
                        {rule.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                    </td>
                    <td>
                      <div>
                        <div className="font-medium text-foreground">{rule.name}</div>
                        {rule.description && (
                          <div className="mt-1 text-xs text-muted-foreground">
                            {rule.description.length > 60
                              ? rule.description.substring(0, 60) + '...'
                              : rule.description}
                          </div>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className={cn('inline-flex items-center rounded-full border px-2 py-1 text-xs font-medium capitalize', tone('indigo'))}>
                        {rule.type}
                      </span>
                    </td>
                    <td>
                      {rule.category ? (
                        <span className="text-sm text-foreground/90">{rule.category}</span>
                      ) : (
                        <span className="text-sm text-muted-foreground/70">-</span>
                      )}
                    </td>
                    <td>
                      {rule.severity && (
                        <span className={cn('inline-flex items-center rounded-full border px-2 py-1 text-xs font-medium', tone(severityTone(rule.severity)))}>
                          {rule.severity}
                        </span>
                      )}
                    </td>
                    <td>
                      <span className="font-mono text-sm text-foreground/90">
                        {rule.weight.toFixed(2)}
                      </span>
                    </td>
                    <td>
                      <div>
                        <div className="text-sm font-medium text-foreground">
                          {rule.match_count.toLocaleString()}
                        </div>
                        {rule.last_matched_at && (
                          <div className="text-xs text-muted-foreground">
                            {formatRelativeTime(rule.last_matched_at)}
                          </div>
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleEdit(rule)}
                          className="rounded p-1 text-primary transition-colors hover:bg-primary/10"
                          title="Edit rule"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(rule.id, rule.name)}
                          className="rounded p-1 text-critical transition-colors hover:bg-critical/10"
                          title="Delete rule"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        {(filteredRules?.length || 0) > 0 && (
          <DataPagination
            page={page}
            pageSize={pageSize}
            total={filteredRules?.length || 0}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
          />
        )}
      </Card>

      {/* Modals */}
      <RuleModal
        rule={selectedRule}
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false)
          setSelectedRule(null)
        }}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['rules'] })
          queryClient.invalidateQueries({ queryKey: ['rule-statistics'] })
        }}
      />

      <RuleTestModal isOpen={isTestModalOpen} onClose={() => setIsTestModalOpen(false)} />

      {confirmDialog}
    </div>
  )
}
