import { Eye, Edit, Copy, Power, Trash2, MoreVertical } from 'lucide-react'
import { Policy } from '@/types/policy'
import { getPolicyTypeIcon, getPolicyTypeLabel, formatPolicyConfig, getSeverityColorLight } from '@/utils/policyUtils'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'

interface PolicyRowProps {
  policy: Policy
  onViewDetails: (policy: Policy) => void
  onEdit: (policy: Policy) => void
  onDuplicate: (policy: Policy) => void
  onToggleStatus: (policy: Policy) => void
  onDelete: (policy: Policy) => void
}

export default function PolicyRow({
  policy,
  onViewDetails,
  onEdit,
  onDuplicate,
  onToggleStatus,
  onDelete,
}: PolicyRowProps) {
  const Icon = getPolicyTypeIcon(policy.type)
  const severityColor = getSeverityColorLight(policy.severity)

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
  }

  return (
    <div className="p-4 hover:bg-accent transition-colors border-b border-border last:border-b-0">
      <div className="flex items-start gap-4">
        {/* Icon */}
        <div className={`p-2 rounded-lg ${severityColor.bg}`}>
          <Icon className={`h-5 w-5 ${severityColor.icon}`} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="font-semibold text-foreground">{policy.name}</h4>
            <span className={`badge ${severityColor.badge}`}>
              {policy.severity}
            </span>
            <span className="badge badge-info">
              {getPolicyTypeLabel(policy.type)}
            </span>
            <span className="badge bg-secondary text-foreground/90">
              {policy.agentIds && policy.agentIds.length > 0
                ? `Scoped (${policy.agentIds.length})`
                : 'All agents'}
            </span>
            {policy.enabled ? (
              <span className="badge badge-success">Active</span>
            ) : (
              <span className="badge bg-secondary text-muted-foreground">Inactive</span>
            )}
          </div>

          {policy.description && (
            <p className="text-sm text-muted-foreground mb-2 line-clamp-1">
              {policy.description}
            </p>
          )}

          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <span className="text-xs text-muted-foreground">
              {formatPolicyConfig(policy)}
            </span>
            <span className="text-muted-foreground/70">•</span>
            <span>
              <span className="text-muted-foreground">Priority:</span>{' '}
              <span className="font-medium text-foreground">{policy.priority}</span>
            </span>
            {policy.violations !== undefined && (
              <>
                <span className="text-muted-foreground/70">•</span>
                <span>
                  <span className="text-muted-foreground">Violations:</span>{' '}
                  <span className="font-medium text-foreground">{policy.violations}</span>
                </span>
              </>
            )}
            <span className="text-muted-foreground/70">•</span>
            <span>Updated {formatDate(policy.updatedAt)}</span>
          </div>
        </div>

        {/* Actions Menu -- Radix DropdownMenu (components/ui/dropdown-menu.tsx)
            instead of a hand-rolled absolute-positioned div. That version
            opened downward with no collision detection and lived inside
            PolicyTable's `overflow-hidden` Card, so for the last row(s) in
            a list the menu -- and "Delete Policy" specifically, since it
            was the last item -- got clipped and was impossible to click.
            Radix's Content portals to document.body and auto-flips to stay
            in the viewport, which fixes both the container-clipping and
            the near-bottom-of-page case at once. */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className="p-2 rounded-lg hover:bg-accent transition-colors"
              aria-label="Policy actions"
            >
              <MoreVertical className="h-5 w-5 text-muted-foreground/70" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuItem onClick={() => onViewDetails(policy)}>
              <Eye className="h-4 w-4" />
              View Details
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => onEdit(policy)}>
              <Edit className="h-4 w-4" />
              Edit Policy
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => onDuplicate(policy)}>
              <Copy className="h-4 w-4" />
              Duplicate Policy
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => onToggleStatus(policy)}>
              <Power className="h-4 w-4" />
              {policy.enabled ? 'Deactivate' : 'Activate'}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => onDelete(policy)}
              className="text-critical focus:bg-critical/10 focus:text-critical"
            >
              <Trash2 className="h-4 w-4" />
              Delete Policy
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  )
}

