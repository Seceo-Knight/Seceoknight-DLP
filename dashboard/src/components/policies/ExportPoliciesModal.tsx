'use client'

import { useState, useEffect } from 'react'
import { Download, CheckSquare, Square } from 'lucide-react'
import { Policy } from '@/types/policy'
import { exportPolicies } from '@/lib/api'
import { getPolicyTypeLabel } from '@/utils/policyUtils'
import toast from 'react-hot-toast'
import Modal, { ModalHeader, ModalFooter } from '@/components/ui/Modal'

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
    <Modal
      open={isOpen}
      onClose={onClose}
      size="md"
      label="Export Policies"
      header={<ModalHeader title="Export Policies" onClose={onClose} />}
      footer={
        <ModalFooter>
          <button
            onClick={onClose}
            className="px-4 py-2 text-muted-foreground hover:text-foreground transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleExport}
            disabled={exporting || selected.size === 0}
            className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 disabled:bg-secondary disabled:text-muted-foreground text-white rounded-lg transition-colors text-sm font-medium"
          >
            <Download className="w-4 h-4" />
            {exporting ? 'Exporting...' : `Export ${selected.size} Polic${selected.size === 1 ? 'y' : 'ies'}`}
          </button>
        </ModalFooter>
      }
    >
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Downloads a JSON file that can be imported into any other SeceoKnight deployment.
            Agent scoping is not included -- imported policies apply to all agents until re-scoped.
          </p>

          <button
            onClick={toggleAll}
            className="flex items-center gap-2 text-sm text-primary hover:text-primary/80 transition-colors"
          >
            {allSelected ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4" />}
            {allSelected ? 'Deselect all' : 'Select all'}
          </button>

          <div className="space-y-2 max-h-80 overflow-y-auto">
            {policies.length === 0 && (
              <p className="text-sm text-muted-foreground py-4 text-center">No policies to export</p>
            )}
            {policies.map((policy) => (
              <label
                key={policy.id}
                className="flex items-center gap-3 p-3 rounded-lg border border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all"
              >
                <input
                  type="checkbox"
                  checked={selected.has(policy.id)}
                  onChange={() => toggleOne(policy.id)}
                  className="w-4 h-4 text-primary rounded"
                />
                <div className="flex-1 min-w-0">
                  <div className="text-foreground text-sm font-medium truncate">{policy.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {policy.type ? getPolicyTypeLabel(policy.type) : 'Classification-aware'}
                  </div>
                </div>
              </label>
            ))}
          </div>
        </div>
    </Modal>
  )
}
