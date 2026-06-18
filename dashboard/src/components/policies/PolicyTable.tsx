import { Policy } from '@/types/policy'
import PolicyRow from './PolicyRow'
import { Shield } from 'lucide-react'

interface PolicyTableProps {
  title: string
  policies: Policy[]
  emptyMessage?: string
  onViewDetails: (policy: Policy) => void
  onEdit: (policy: Policy) => void
  onDuplicate: (policy: Policy) => void
  onToggleStatus: (policy: Policy) => void
  onDelete: (policy: Policy) => void
}

export default function PolicyTable({
  title,
  policies,
  emptyMessage = 'No policies found',
  onViewDetails,
  onEdit,
  onDuplicate,
  onToggleStatus,
  onDelete,
}: PolicyTableProps) {
  return (
    <div className="card p-0">
      {/* Table Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <h3 className="font-semibold text-gray-900">{title}</h3>
        <p className="text-sm text-gray-600 mt-1">
          {policies.length} {policies.length === 1 ? 'policy' : 'policies'}
        </p>
      </div>

      {/* Table Body */}
      <div className="divide-y divide-gray-200">
        {policies.length === 0 ? (
          <div className="p-12 text-center">
            <Shield className="h-12 w-12 text-gray-400 mx-auto mb-3" />
            <p className="text-gray-600 font-medium">{emptyMessage}</p>
          </div>
        ) : (
          policies.map((policy) => (
            <PolicyRow
              key={policy.id}
              policy={policy}
              onViewDetails={onViewDetails}
              onEdit={onEdit}
              onDuplicate={onDuplicate}
              onToggleStatus={onToggleStatus}
              onDelete={onDelete}
            />
          ))
        )}
      </div>
    </div>
  )
}

