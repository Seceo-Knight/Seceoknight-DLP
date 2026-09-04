import { useState } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Shield, CheckCircle, XCircle, RefreshCw, Download, Upload } from 'lucide-react'
import PolicyCreatorModal from '@/components/policies/PolicyCreatorModal'
import PolicyTable from '@/components/policies/PolicyTable'
import PolicyDetailsModal from '@/components/policies/PolicyDetailsModal'
import ExportPoliciesModal from '@/components/policies/ExportPoliciesModal'
import ImportPoliciesModal from '@/components/policies/ImportPoliciesModal'
import { useConfirm } from '@/components/ui/Modal'
import { PageHeader } from '@/components/ui/page-header'
import { Button } from '@/components/ui/button'
import StatsCard from '@/components/StatsCard'
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

// GET /policies/ defaults to limit=100 (backend max is 1000, enforced via
// Query(..., le=1000)) and the page never passed a limit at all, so any
// deployment with >100 policies would silently show only the first 100 --
// split across the Active/Inactive tables with no indication anything was
// missing. Request the backend's actual max, and warn if even that isn't
// enough (same pattern used for Rules.tsx and Log Explorer's exports).
const POLICIES_FETCH_LIMIT = 1000

export default function PoliciesPage() {
  const { confirm, dialog: confirmDialog } = useConfirm()
  const queryClient = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null)
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [showDetailsModal, setShowDetailsModal] = useState(false)
  const [lastRefreshAt, setLastRefreshAt] = useState<Date | null>(null)
  const [showExportModal, setShowExportModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)

  // Fetch policies from API
  const {
    data: policiesData = [],
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['policies'],
    queryFn: async () => {
      const apiPolicies = await getPolicies({ enabled_only: false, limit: POLICIES_FETCH_LIMIT })
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

  const handleDelete = async (policy: Policy) => {
    if (!(await confirm({
      title: 'Delete policy',
      confirmLabel: 'Delete',
      children: `Are you sure you want to delete "${policy.name}"? This action cannot be undone.`,
    }))) {
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

  // stats.total comes from a separate SQL COUNT(*) that isn't bounded by
  // POLICIES_FETCH_LIMIT, so it stays accurate even if the list fetch above
  // ever gets capped -- compare the two to detect and surface truncation
  // instead of silently showing an incomplete list.
  const isTruncated = !isStatsLoading && policies.length < stats.total

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
      <PageHeader
        icon={Shield}
        title="DLP Policies"
        description="Create and manage data loss prevention policies"
        actions={
          <div className="flex flex-col items-end gap-2">
            <div className="flex items-center gap-2">
              <Button variant="outline" onClick={() => setShowImportModal(true)}>
                <Upload className="h-4 w-4" />
                Import
              </Button>
              <Button variant="outline" onClick={() => setShowExportModal(true)}>
                <Download className="h-4 w-4" />
                Export
              </Button>
              <Button
                variant="outline"
                onClick={() => refreshBundlesMutation.mutate()}
                disabled={refreshBundlesMutation.isPending}
              >
                <RefreshCw className={`h-4 w-4 ${refreshBundlesMutation.isPending ? 'animate-spin' : ''}`} />
                {refreshBundlesMutation.isPending ? 'Refreshing…' : 'Refresh Bundles'}
              </Button>
              <Button onClick={handleCreatePolicy}>
                <Plus className="h-4 w-4" />
                Create Policy
              </Button>
            </div>
            {lastRefreshAt && (
              <p className="text-xs text-muted-foreground">
                Last refresh triggered {formatDistanceToNow(lastRefreshAt, { addSuffix: true })}
              </p>
            )}
          </div>
        }
      />

      {isTruncated && (
        <div className="rounded-lg border border-warning/30 bg-warning/5 px-4 py-3 text-sm text-foreground">
          Showing {policies.length} of {stats.total} policies. Narrow this down or contact an admin to raise the fetch limit.
        </div>
      )}

      {/* Stats -- all four in one row, matching the StatsCard grid used on
          every other tab (Rules, Log Explorer, Alerts, etc). Previously
          the first three tiles were hand-rolled 'card' divs in a 3-col
          grid and Violations forced itself onto its own full-width row
          via md:col-span-3 -- inconsistent with the rest of the app and
          the reason this row didn't read as "one row" of stats. */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title="Total Policies"
          value={isStatsLoading ? '—' : stats.total}
          icon={Shield}
          color="indigo"
        />
        <StatsCard
          title="Active Policies"
          value={isStatsLoading ? '—' : stats.active}
          icon={CheckCircle}
          color="green"
        />
        <StatsCard
          title="Inactive Policies"
          value={isStatsLoading ? '—' : stats.inactive}
          icon={XCircle}
          color="gray"
        />
        <StatsCard
          title="Violations (24h)"
          value={isStatsLoading ? '—' : stats.violations}
          icon={Shield}
          color="red"
        />
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

      {/* Export Policies Modal */}
      <ExportPoliciesModal
        isOpen={showExportModal}
        onClose={() => setShowExportModal(false)}
        policies={policies}
      />

      {/* Import Policies Modal */}
      <ImportPoliciesModal
        isOpen={showImportModal}
        onClose={() => setShowImportModal(false)}
        onImported={() => {
          queryClient.invalidateQueries({ queryKey: ['policies'] })
          queryClient.invalidateQueries({ queryKey: ['policy-stats'] })
        }}
      />

      {confirmDialog}
    </div>
  )
}
