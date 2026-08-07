'use client'

import { PrinterControlConfig } from '@/types/policy'

interface PrinterControlPolicyFormProps {
  config: PrinterControlConfig
  onChange: (config: PrinterControlConfig) => void
}

export default function PrinterControlPolicyForm({ config: rawConfig, onChange }: PrinterControlPolicyFormProps) {
  const config: PrinterControlConfig = {
    mode: rawConfig?.mode ?? 'enforce',
    scope: rawConfig?.scope ?? 'block_network',
  }

  return (
    <div className="space-y-6">
      <div className="p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg text-sm text-amber-200/90">
        Device-level printer access control -- cancels print jobs based on <strong>which printer</strong> they're
        going to, regardless of document content. Independent of and additive to the separate{' '}
        <strong>Print Content Prevention</strong> policy type, which inspects the document text instead. The
        sanctioned-printer allowlist itself is still managed on the Printers page; this policy controls the
        overall mode and scope of enforcement.
      </div>

      {/* Mode */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Mode</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="printer-control-mode"
              value="enforce"
              checked={config.mode === 'enforce'}
              onChange={() => onChange({ ...config, mode: 'enforce' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Enforce</div>
              <div className="text-muted-foreground/70 text-xs">Actually cancel print jobs that violate the scope below</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="printer-control-mode"
              value="audit"
              checked={config.mode === 'audit'}
              onChange={() => onChange({ ...config, mode: 'audit' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Audit</div>
              <div className="text-muted-foreground/70 text-xs">Log a "would block" event but let the job print -- validate before enforcing</div>
            </div>
          </label>
        </div>
      </div>

      {/* Scope */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Scope</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="printer-control-scope"
              value="block_all"
              checked={config.scope === 'block_all'}
              onChange={() => onChange({ ...config, scope: 'block_all' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Block All Printing</div>
              <div className="text-muted-foreground/70 text-xs">No printer -- local or network -- is allowed</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="printer-control-scope"
              value="block_network"
              checked={config.scope === 'block_network'}
              onChange={() => onChange({ ...config, scope: 'block_network' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Block Network Printers Only</div>
              <div className="text-muted-foreground/70 text-xs">Directly-attached local printers still work; network/shared printers are blocked</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="printer-control-scope"
              value="block_local"
              checked={config.scope === 'block_local'}
              onChange={() => onChange({ ...config, scope: 'block_local' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Block Local Printers Only</div>
              <div className="text-muted-foreground/70 text-xs">Network/shared printers still work; directly-attached local printers are blocked</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="printer-control-scope"
              value="allowlist"
              checked={config.scope === 'allowlist'}
              onChange={() => onChange({ ...config, scope: 'allowlist' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Allowlist</div>
              <div className="text-muted-foreground/70 text-xs">Only printers sanctioned on the Printers page may be used</div>
            </div>
          </label>
        </div>
      </div>

      <p className="text-xs text-muted-foreground/70">
        Manage the sanctioned-printer list itself on the <strong>Printers</strong> page. That allowlist only takes
        effect here when Scope is set to Allowlist.
      </p>
    </div>
  )
}
