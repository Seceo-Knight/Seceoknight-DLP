import { Policy } from '@/types/policy'
import PolicyRow from './PolicyRow'
import { Shield } from 'lucide-react'
import { Card } from '@/components/ui/card'
import { EmptyState } from '@/components/ui/empty-state'

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
    <Card className="p-0 overflow-hidden">
      {/* Table Header */}
      <div className="px-6 py-4 border-b border-border">
        <h3 className="font-semibold text-foreground">{title}</h3>
        <p className="text-sm text-muted-foreground mt-1">
          {policies.length} {policies.length === 1 ? 'policy' : 'policies'}
        </p>
      </div>

      {/* Table Body */}
      <div className="divide-y divide-border">
        {policies.length === 0 ? (
          <EmptyState icon={Shield} title={emptyMessage} />
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
    </Card>
  )
}

