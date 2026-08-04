'use client'

import { useState, useEffect } from 'react'
import { X, Download, CheckSquare, Square } from 'lucide-react'
import { Policy } from '@/types/policy'
import { exportPolicies } from '@/lib/api'
import { getPolicyTypeLabel } from '@/utils/policyUtils'
import toast from 'react-hot-toast'

interface ExportPoliciesModalProps {
  isOpen: boolean
  onClose: () => void
  policies: Policy[]
}

export default function ExportPoliciesModal({ isOpen, onClose, policies }: ExportPoliciesModalProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [exporting, setExporting] = useState(false)

  // Default to "everything selected" each time the modal opens, rather than
  // remembering a stale selection from a previous open.
  useEffect(() => {
    if (isOpen) {
      setSelected(new Set(policies.map((p) => p.id)))
    }
  }, [isOpen, policies])

  if (!isOpen) return null

  const allSelected = selected.size === policies.length && policies.length > 0

  const toggleAll = () => {
    setSelected(allSelected ? new Set() : new Set(policies.map((p) => p.id)))
  }

  const toggleOne = (id: string) => {
    const next = new Set(selected)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelected(next)
  }

  const handleExport = async () => {
    if (selected.size === 0) {
      toast.error('Select at least one policy to export')
      return
    }
    setExporting(true)
    try {
      const bundle = await exportPolicies(Array.from(selected))
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const date = new Date().toISOString().slice(0, 10)
      a.download = `seceoknight-policies-${date}.json`
      a.click()
      URL.revokeObjectURL(url)
      toast.success(`Exported ${bundle.policy_count} polic${bundle.policy_count === 1 ? 'y' : 'ies'}`)
      onClose()
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Failed to export policies')
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-gray-800 rounded-2xl max-w-lg w-full max-h-[85vh] overflow-y-auto border border-gray-700"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-6 border-b border-gray-700 sticky top-0 bg-gray-800 z-10">
          <h3 className="text-xl font-bold text-white">Export Policies</h3>
          <button onClick={onClose} className="text-muted-foreground/70 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <p className="text-sm text-muted-foreground/70">
            Downloads a JSON file that can be imported into any other SeceoKnight deployment.
            Agent scoping is not included -- imported policies apply to all agents until re-scoped.
          </p>

          <button
            onClick={toggleAll}
            className="flex items-center gap-2 text-sm text-indigo-300 hover:text-indigo-200 transition-colors"
          >
            {allSelected ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4" />}
            {allSelected ? 'Deselect all' : 'Select all'}
          </button>

          <div className="space-y-2 max-h-80 overflow-y-auto">
            {policies.length === 0 && (
              <p className="text-sm text-muted-foreground/70 py-4 text-center">No policies to export</p>
            )}
            {policies.map((policy) => (
              <label
                key={policy.id}
                className="flex items-center gap-3 p-3 rounded-lg border border-gray-700 bg-gray-900/50 cursor-pointer hover:border-gray-600 transition-all"
              >
                <input
                  type="checkbox"
                  checked={selected.has(policy.id)}
                  onChange={() => toggleOne(policy.id)}
                  className="w-4 h-4 text-indigo-400 rounded"
                />
                <div className="flex-1 min-w-0">
                  <div className="text-white text-sm font-medium truncate">{policy.name}</div>
                  <div className="text-xs text-muted-foreground/70">
                    {policy.type ? getPolicyTypeLabel(policy.type) : 'Classification-aware'}
                  </div>
                </div>
              </label>
            ))}
          </div>
        </div>

        <div className="flex items-center justify-end gap-3 p-6 border-t border-gray-700">
          <button
            onClick={onClose}
            className="px-4 py-2 text-muted-foreground/70 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleExport}
            disabled={exporting || selected.size === 0}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-700 disabled:text-muted-foreground text-white rounded-lg transition-colors text-sm font-medium"
          >
            <Download className="w-4 h-4" />
            {exporting ? 'Exporting…' : `Export ${selected.size} Polic${selected.size === 1 ? 'y' : 'ies'}`}
          </button>
        </div>
      </div>
    </div>
  )
}
