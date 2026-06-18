import { useState } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Edit, Trash2, Power, PowerOff, TestTube, Search, Filter } from 'lucide-react'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import RuleModal from '@/components/rules/RuleModal'
import RuleTestModal from '@/components/rules/RuleTestModal'
import { getRules, getRuleStatistics, deleteRule, toggleRule, type Rule } from '@/lib/rules-api'
import { formatRelativeTime, cn } from '@/lib/utils'
import toast from 'react-hot-toast'

type FilterType = 'all' | 'regex' | 'keyword' | 'dictionary'

export default function Rules() {
  const [filter, setFilter] = useState<FilterType>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedRule, setSelectedRule] = useState<Rule | null>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [isTestModalOpen, setIsTestModalOpen] = useState(false)
  const queryClient = useQueryClient()

  // Fetch rules
  const { data: rules, isLoading, error, refetch } = useQuery({
    queryKey: ['rules', filter],
    queryFn: () => getRules({ type: filter === 'all' ? undefined : filter }),
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
    if (!confirm(`Are you sure you want to delete rule "${name}"?`)) {
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

  if (isLoading) {
    return <LoadingSpinner size="lg" />
  }

  if (error) {
    return <ErrorMessage message="Failed to load rules" retry={() => refetch()} />
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Classification Rules</h1>
          <p className="mt-1 text-sm text-gray-600">
            Manage detection rules for data classification
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => setIsTestModalOpen(true)}
            className="btn-secondary flex items-center gap-2"
          >
            <TestTube className="h-4 w-4" />
            Test Rules
          </button>
          <button onClick={handleCreate} className="btn-primary flex items-center gap-2">
            <Plus className="h-4 w-4" />
            Create Rule
          </button>
        </div>
      </div>

      {/* Statistics Cards */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Shield className="h-5 w-5 text-blue-600" />
              </div>
              <div>
                <p className="text-sm text-gray-600">Total Rules</p>
                <p className="text-2xl font-bold text-gray-900">{stats.total_rules}</p>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 rounded-lg">
                <Power className="h-5 w-5 text-green-600" />
              </div>
              <div>
                <p className="text-sm text-gray-600">Enabled</p>
                <p className="text-2xl font-bold text-green-600">{stats.enabled_rules}</p>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gray-100 rounded-lg">
                <PowerOff className="h-5 w-5 text-gray-600" />
              </div>
              <div>
                <p className="text-sm text-gray-600">Disabled</p>
                <p className="text-2xl font-bold text-gray-600">{stats.disabled_rules}</p>
              </div>
            </div>
          </div>
          <div className="card">
            <div>
              <p className="text-xs text-gray-600 mb-2">By Type</p>
              <div className="space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">Regex:</span>
                  <span className="font-medium">{stats.by_type.regex}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Keyword:</span>
                  <span className="font-medium">{stats.by_type.keyword}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Dictionary:</span>
                  <span className="font-medium">{stats.by_type.dictionary}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card">
        <div className="flex gap-3 items-center">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search rules by name, category, or type..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <div className="flex gap-2">
            {(['all', 'regex', 'keyword', 'dictionary'] as const).map((type) => (
              <button
                key={type}
                onClick={() => setFilter(type)}
                className={cn(
                  'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  filter === type
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                )}
              >
                {type === 'all' ? 'All' : type.charAt(0).toUpperCase() + type.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="card p-0">
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
                  <td colSpan={8} className="text-center py-12">
                    <Shield className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                    <p className="text-gray-600 font-medium">No rules found</p>
                    <p className="text-sm text-gray-500 mt-1">
                      {searchQuery
                        ? 'Try adjusting your search query'
                        : 'Create your first classification rule'}
                    </p>
                  </td>
                </tr>
              ) : (
                filteredRules?.map((rule) => (
                  <tr key={rule.id} className="hover:bg-gray-50">
                    <td>
                      <button
                        onClick={() => handleToggle(rule.id, rule.enabled)}
                        className={cn(
                          'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium',
                          rule.enabled
                            ? 'bg-green-100 text-green-800'
                            : 'bg-gray-100 text-gray-800'
                        )}
                      >
                        {rule.enabled ? (
                          <>
                            <Power className="h-3 w-3 mr-1" />
                            Enabled
                          </>
                        ) : (
                          <>
                            <PowerOff className="h-3 w-3 mr-1" />
                            Disabled
                          </>
                        )}
                      </button>
                    </td>
                    <td>
                      <div>
                        <div className="font-medium text-gray-900">{rule.name}</div>
                        {rule.description && (
                          <div className="text-xs text-gray-500 mt-1">
                            {rule.description.length > 60
                              ? rule.description.substring(0, 60) + '...'
                              : rule.description}
                          </div>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        {rule.type}
                      </span>
                    </td>
                    <td>
                      {rule.category ? (
                        <span className="text-sm text-gray-700">{rule.category}</span>
                      ) : (
                        <span className="text-sm text-gray-400">-</span>
                      )}
                    </td>
                    <td>
                      {rule.severity && (
                        <span
                          className={cn(
                            'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium',
                            rule.severity === 'critical'
                              ? 'bg-red-100 text-red-800'
                              : rule.severity === 'high'
                              ? 'bg-orange-100 text-orange-800'
                              : rule.severity === 'medium'
                              ? 'bg-yellow-100 text-yellow-800'
                              : 'bg-green-100 text-green-800'
                          )}
                        >
                          {rule.severity}
                        </span>
                      )}
                    </td>
                    <td>
                      <span className="text-sm font-mono text-gray-700">
                        {rule.weight.toFixed(2)}
                      </span>
                    </td>
                    <td>
                      <div>
                        <div className="text-sm font-medium text-gray-900">
                          {rule.match_count.toLocaleString()}
                        </div>
                        {rule.last_matched_at && (
                          <div className="text-xs text-gray-500">
                            {formatRelativeTime(rule.last_matched_at)}
                          </div>
                        )}
                      </div>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleEdit(rule)}
                          className="p-1 text-blue-600 hover:bg-blue-50 rounded transition-colors"
                          title="Edit rule"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(rule.id, rule.name)}
                          className="p-1 text-red-600 hover:bg-red-50 rounded transition-colors"
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
      </div>

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
    </div>
  )
}
