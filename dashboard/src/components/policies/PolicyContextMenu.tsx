import { forwardRef } from 'react'
import { Eye, Edit, Copy, Power, Trash2 } from 'lucide-react'
import { Policy } from '@/types/policy'

interface PolicyContextMenuProps {
  policy: Policy
  onViewDetails: () => void
  onEdit: () => void
  onDuplicate: () => void
  onToggleStatus: () => void
  onDelete: () => void
}

const PolicyContextMenu = forwardRef<HTMLDivElement, PolicyContextMenuProps>(
  ({ policy, onViewDetails, onEdit, onDuplicate, onToggleStatus, onDelete }, ref) => {
    return (
      <div
        ref={ref}
        className="absolute right-0 top-full mt-1 w-48 bg-white rounded-lg shadow-lg border border-gray-200 py-1 z-50"
      >
        <button
          onClick={onViewDetails}
          className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2 transition-colors"
        >
          <Eye className="h-4 w-4" />
          View Details
        </button>

        <button
          onClick={onEdit}
          className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2 transition-colors"
        >
          <Edit className="h-4 w-4" />
          Edit Policy
        </button>

        <button
          onClick={onDuplicate}
          className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2 transition-colors"
        >
          <Copy className="h-4 w-4" />
          Duplicate Policy
        </button>

        <div className="border-t border-gray-200 my-1" />

        <button
          onClick={onToggleStatus}
          className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2 transition-colors"
        >
          <Power className="h-4 w-4" />
          {policy.enabled ? 'Deactivate' : 'Activate'}
        </button>

        <div className="border-t border-gray-200 my-1" />

        <button
          onClick={onDelete}
          className="w-full px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50 flex items-center gap-2 transition-colors"
        >
          <Trash2 className="h-4 w-4" />
          Delete Policy
        </button>
      </div>
    )
  }
)

PolicyContextMenu.displayName = 'PolicyContextMenu'

export default PolicyContextMenu

