import { useState } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Shield, CheckCircle, XCircle, RefreshCw } from 'lucide-react'
import PolicyCreatorModal from '@/components/policies/PolicyCreatorModal'
import PolicyTable from '@/components/policies/PolicyTable'
import PolicyDetailsModal from '@/components/policies/PolicyDetailsModal'
import { Policy } from '@/types/policy'
import {
  getPolicies,
  getPolicyStats,
  createPolicy,
  updatePolicy,
  deletePolicy,
  enablePolicy,
  disablePolicy,
  refreshPolicyBundles,
} from '@/lib/api'
import { transformApiPolicyToFrontend, transformFrontendPolicyToApi } from '@/utils/policyUtils'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { formatDistanceToNow } from 'date-fns'

type PolicyStats = {
  total: number
  active: number
  inactive: number
  violations: number
}

export default function PoliciesPage() {
  const queryClient = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null)
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [showDetailsModal, setShowDetailsModal] = useState(false)
  const [lastRefreshAt, setLastRefreshAt] = useState<Date | null>(null)

  // Fetch policies from API
  const {
    data: policiesData = [],
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['policies'],
    queryFn: async () => {
      const apiPolicies = await getPolicies({ enabled_only: false })
      return apiPolicies.map(transformApiPolicyToFrontend)
    },
    refetchInterval: 30000, // Refresh every 30 seconds
    staleTime: 0, // Always consider data stale, force refetch
    gcTime: 0, // Don't cache data (React Query v5 uses gcTime instead of cacheTime)
    retry: false, // Don't retry on error
  })

  const policies = policiesData as Policy[]
  const {
    data: policyStats,
    isLoading: isStatsLoading,
    error: statsError,
    refetch: refetchPolicyStats,
  } = useQuery<PolicyStats>({
    queryKey: ['policy-stats'],
    queryFn: getPolicyStats,
    refetchInterval: 30000,
    staleTime: 0,
    gcTime: 0,
    retry: false,
  })

  if (statsError) {
    // eslint-disable-next-line no-console
    console.error('[PoliciesPage] Failed to load policy stats', statsError)
  }

  const fallbackStats: PolicyStats = {
    total: policies.length,
    active: policies.filter((p) => p.enabled).length,
    inactive: policies.filter((p) => !p.enabled).length,
    violations: 0,
  }
  const stats = policyStats ?? fallbackStats

  const handleCreatePolicy = () => {
    setEditingPolicy(null)
    setShowModal(true)
  }

  // Create policy mutation
  const createMutation = useMutation({
    mutationFn: async (policyData: Partial<Policy>) => {
      const apiData = transformFrontendPolicyToApi(policyData)
      return await createPolicy(apiData)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      queryClient.invalidateQueries({ queryKey: ['policy-stats'] })
      toast.success('Policy created successfully!')
      setShowModal(false)
      setEditingPolicy(null)
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to create policy'))
    },
  })

  // Update policy mutation
  const updateMutation = useMutation({
    mutationFn: async ({ id, policyData }: { id: string; policyData: Partial<Policy> }) => {
      const apiData = transformFrontendPolicyToApi(policyData)
      return await updatePolicy(id, apiData)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      queryClient.invalidateQueries({ queryKey: ['policy-stats'] })
      toast.success('Policy updated successfully!')
      setShowModal(false)
      setEditingPolicy(null)
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to update policy'))
    },
  })

  const handleSavePolicy = (policyData: Partial<Policy>) => {
    if (editingPolicy && editingPolicy.id) {
      updateMutation.mutate({ id: editingPolicy.id, policyData })
    } else {
      createMutation.mutate(policyData)
    }
  }

  const handleViewDetails = (policy: Policy) => {
    setSelectedPolicy(policy)
    setShowDetailsModal(true)
  }

  const handleEdit = (policy: Policy) => {
    setEditingPolicy(policy)
    setShowModal(true)
  }

  const handleDuplicate = (policy: Policy) => {
    const duplicatedPolicy: Policy = {
      ...policy,
      id: `policy-${Date.now()}`,
      name: `${policy.name} (Copy)`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      violations: 0,
      enabled: false, // Start as inactive
    }
    setEditingPolicy(duplicatedPolicy)
    setShowModal(true)
  }

  // Toggle status mutation
  const toggleStatusMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      if (enabled) {
        return await enablePolicy(id)
      } else {
        return await disablePolicy(id)
      }
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      queryClient.invalidateQueries({ queryKey: ['policy-stats'] })
      toast.success(`Policy ${variables.enabled ? 'activated' : 'deactivated'} successfully!`)
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to toggle policy status'))
    },
  })

  // Delete policy mutation
  const deleteMutation = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      queryClient.invalidateQueries({ queryKey: ['policy-stats'] })
      toast.success('Policy deleted successfully!')
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to delete policy'))
    },
  })

  const handleToggleStatus = (policy: Policy) => {
    if (!policy.id) return
    toggleStatusMutation.mutate({ id: policy.id, enabled: !policy.enabled })
  }

  const handleDelete = (policy: Policy) => {
    if (!confirm(`Are you sure you want to delete "${policy.name}"? This action cannot be undone.`)) {
      return
    }
    if (!policy.id) return
    deleteMutation.mutate(policy.id)
  }

  const refreshBundlesMutation = useMutation({
    mutationFn: refreshPolicyBundles,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies'] })
      queryClient.invalidateQueries({ queryKey: ['policy-stats'] })
      setLastRefreshAt(new Date())
      toast.success('Policy bundles refresh triggered. Agents will sync within ~60s.')
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to refresh policy bundles'))
    },
  })

  const activePolicies = policies.filter(p => p.enabled)
  const inactivePolicies = policies.filter(p => !p.enabled)

  if (isLoading) {
    return <LoadingSpinner size="lg" />
  }

  if (error) {
    return (
      <ErrorMessage
        message="Failed to load policies"
        retry={() => {
          refetch()
          refetchPolicyStats()
        }}
      />
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">DLP Policies</h1>
        <p className="mt-1 text-sm text-gray-600">
          Create and manage data loss prevention policies
        </p>
      </div>

      {/* Header Actions */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex-1" />
        <div className="flex items-center gap-3">
          <button
            onClick={() => refreshBundlesMutation.mutate()}
            disabled={refreshBundlesMutation.isPending}
            className="flex items-center gap-2 border border-gray-300 text-gray-800 px-4 py-3 rounded-xl hover:bg-gray-50 disabled:opacity-60 disabled:cursor-not-allowed"
          >
            <RefreshCw className={`w-4 h-4 ${refreshBundlesMutation.isPending ? 'animate-spin' : ''}`} />
            {refreshBundlesMutation.isPending ? 'Refreshing…' : 'Refresh Bundles'}
          </button>
          <button
            onClick={handleCreatePolicy}
            className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white px-6 py-3 rounded-xl hover:from-indigo-700 hover:to-purple-700 shadow-lg hover:shadow-xl transition-all"
          >
            <Plus className="w-5 h-5" />
            Create Policy
          </button>
        </div>
        {lastRefreshAt && (
          <p className="w-full text-sm text-gray-500">
            Last refresh triggered {formatDistanceToNow(lastRefreshAt, { addSuffix: true })}
          </p>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Policies</p>
              <p className="mt-2 text-3xl font-semibold text-gray-900">
                {isStatsLoading ? '—' : stats.total}
              </p>
            </div>
            <div className="p-3 rounded-lg bg-blue-100 text-blue-600">
              <Shield className="h-6 w-6" />
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Policies</p>
              <p className="mt-2 text-3xl font-semibold text-gray-900">
                {isStatsLoading ? '—' : stats.active}
              </p>
            </div>
            <div className="p-3 rounded-lg bg-green-100 text-green-600">
              <CheckCircle className="h-6 w-6" />
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Inactive Policies</p>
              <p className="mt-2 text-3xl font-semibold text-gray-900">
                {isStatsLoading ? '—' : stats.inactive}
              </p>
            </div>
            <div className="p-3 rounded-lg bg-gray-100 text-gray-600">
              <XCircle className="h-6 w-6" />
            </div>
          </div>
        </div>

        <div className="card md:col-span-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Violations (last 24h)</p>
              <p className="mt-2 text-3xl font-semibold text-gray-900">
                {isStatsLoading ? '—' : stats.violations}
              </p>
            </div>
            <div className="p-3 rounded-lg bg-red-100 text-red-600">
              <Shield className="h-6 w-6" />
            </div>
          </div>
        </div>
      </div>

      {/* Active Policies Table */}
      <PolicyTable
        title="Active Policies"
        policies={activePolicies}
        emptyMessage="No active policies"
        onViewDetails={handleViewDetails}
        onEdit={handleEdit}
        onDuplicate={handleDuplicate}
        onToggleStatus={handleToggleStatus}
        onDelete={handleDelete}
      />

      {/* Inactive Policies Table */}
      <PolicyTable
        title="Inactive Policies"
        policies={inactivePolicies}
        emptyMessage="No inactive policies"
        onViewDetails={handleViewDetails}
        onEdit={handleEdit}
        onDuplicate={handleDuplicate}
        onToggleStatus={handleToggleStatus}
        onDelete={handleDelete}
      />

      {/* Policy Creator Modal */}
      <PolicyCreatorModal
        isOpen={showModal}
        onClose={() => {
          setShowModal(false)
          setEditingPolicy(null)
        }}
        onSave={handleSavePolicy}
        editingPolicy={editingPolicy}
      />

      {/* Policy Details Modal */}
      <PolicyDetailsModal
        isOpen={showDetailsModal}
        policy={selectedPolicy}
        onClose={() => {
          setShowDetailsModal(false)
          setSelectedPolicy(null)
        }}
      />
    </div>
  )
}
