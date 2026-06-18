import { useState, useRef, useEffect } from 'react'
import { MoreVertical, Shield } from 'lucide-react'
import { Policy } from '@/types/policy'
import { getPolicyTypeIcon, getPolicyTypeLabel, formatPolicyConfig, getSeverityColorLight } from '@/utils/policyUtils'
import PolicyContextMenu from './PolicyContextMenu'

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
  const [showMenu, setShowMenu] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)

  const Icon = getPolicyTypeIcon(policy.type)
  const severityColor = getSeverityColorLight(policy.severity)

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        menuRef.current &&
        buttonRef.current &&
        !menuRef.current.contains(event.target as Node) &&
        !buttonRef.current.contains(event.target as Node)
      ) {
        setShowMenu(false)
      }
    }

    if (showMenu) {
      document.addEventListener('mousedown', handleClickOutside)
      return () => document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [showMenu])

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    })
  }

  return (
    <div className="p-4 hover:bg-gray-50 transition-colors border-b border-gray-200 last:border-b-0">
      <div className="flex items-start gap-4">
        {/* Icon */}
        <div className={`p-2 rounded-lg ${severityColor.bg}`}>
          <Icon className={`h-5 w-5 ${severityColor.icon}`} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="font-semibold text-gray-900">{policy.name}</h4>
            <span className={`badge ${severityColor.badge}`}>
              {policy.severity}
            </span>
            <span className="badge badge-info">
              {getPolicyTypeLabel(policy.type)}
            </span>
            <span className="badge bg-gray-100 text-gray-700">
              {policy.agentIds && policy.agentIds.length > 0
                ? `Scoped (${policy.agentIds.length})`
                : 'All agents'}
            </span>
            {policy.enabled ? (
              <span className="badge badge-success">Active</span>
            ) : (
              <span className="badge bg-gray-100 text-gray-600">Inactive</span>
            )}
          </div>

          {policy.description && (
            <p className="text-sm text-gray-600 mb-2 line-clamp-1">
              {policy.description}
            </p>
          )}

          <div className="flex items-center gap-3 text-sm text-gray-600">
            <span className="text-xs text-gray-500">
              {formatPolicyConfig(policy)}
            </span>
            <span className="text-gray-400">•</span>
            <span>
              <span className="text-gray-500">Priority:</span>{' '}
              <span className="font-medium text-gray-900">{policy.priority}</span>
            </span>
            {policy.violations !== undefined && (
              <>
                <span className="text-gray-400">•</span>
                <span>
                  <span className="text-gray-500">Violations:</span>{' '}
                  <span className="font-medium text-gray-900">{policy.violations}</span>
                </span>
              </>
            )}
            <span className="text-gray-400">•</span>
            <span>Updated {formatDate(policy.updatedAt)}</span>
          </div>
        </div>

        {/* Actions Menu */}
        <div className="relative">
          <button
            ref={buttonRef}
            onClick={() => setShowMenu(!showMenu)}
            className="p-2 rounded-lg hover:bg-gray-100 transition-colors"
            aria-label="Policy actions"
          >
            <MoreVertical className="h-5 w-5 text-gray-400" />
          </button>

          {showMenu && (
            <PolicyContextMenu
              ref={menuRef}
              policy={policy}
              onViewDetails={() => {
                setShowMenu(false)
                onViewDetails(policy)
              }}
              onEdit={() => {
                setShowMenu(false)
                onEdit(policy)
              }}
              onDuplicate={() => {
                setShowMenu(false)
                onDuplicate(policy)
              }}
              onToggleStatus={() => {
                setShowMenu(false)
                onToggleStatus(policy)
              }}
              onDelete={() => {
                setShowMenu(false)
                onDelete(policy)
              }}
            />
          )}
        </div>
      </div>
    </div>
  )
}

