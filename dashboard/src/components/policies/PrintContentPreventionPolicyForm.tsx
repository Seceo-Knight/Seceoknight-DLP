'use client'

import { PrintContentPreventionConfig } from '@/types/policy'

interface PrintContentPreventionPolicyFormProps {
  config: PrintContentPreventionConfig
  onChange: (config: PrintContentPreventionConfig) => void
}

export default function PrintContentPreventionPolicyForm({ config: rawConfig, onChange }: PrintContentPreventionPolicyFormProps) {
  const config: PrintContentPreventionConfig = {
    mode: rawConfig?.mode ?? 'audit',
  }

  return (
    <div className="space-y-6">
      <div className="p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg text-sm text-amber-200/90">
        Inspects the actual text of a spooled print job -- not just the document&apos;s filename -- and cancels
        the job if it contains Confidential / Restricted content. Independent of the printer-device allowlist
        managed on the Printers page; this is content-level inspection, that is device-level access control.
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Mode</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="print-content-mode"
              value="enforce"
              checked={config.mode === 'enforce'}
              onChange={() => onChange({ ...config, mode: 'enforce' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Enforce</div>
              <div className="text-muted-foreground/70 text-xs">Cancel the print job when sensitive content is detected</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="print-content-mode"
              value="audit"
              checked={config.mode === 'audit'}
              onChange={() => onChange({ ...config, mode: 'audit' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Audit</div>
              <div className="text-muted-foreground/70 text-xs">Log an event on sensitive content but let the job print -- validate before enforcing</div>
            </div>
          </label>
        </div>
      </div>

      <p className="text-xs text-muted-foreground/70">
        The agent pauses the spool job, extracts readable text from the raw EMF/RAW/PS/PCL spool data, sends it
        for classification, then cancels (enforce) or resumes (audit) the job. Want to also restrict{' '}
        <em>which printers</em> can be used at all? That&apos;s the separate allowlist on the Printers page.
      </p>
    </div>
  )
}
