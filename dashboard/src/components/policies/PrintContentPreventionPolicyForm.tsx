'use client'

import { PrintContentPreventionConfig } from '@/types/policy'

interface PrintContentPreventionPolicyFormProps {
  config: PrintContentPreventionConfig
  onChange: (config: PrintContentPreventionConfig) => void
}

export default function PrintContentPreventionPolicyForm({ config: rawConfig, onChange }: PrintContentPreventionPolicyFormProps) {
  const config: PrintContentPreventionConfig = {
    mode: rawConfig?.mode ?? 'audit',
    unknownContentAction: rawConfig?.unknownContentAction ?? 'allow',
  }

  return (
    <div className="space-y-6">
      <div className="p-4 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
        Inspects the actual text of a spooled print job -- not just the document&apos;s filename -- and cancels
        the job if it contains Confidential / Restricted content. Independent of the printer-device allowlist
        managed on the Printers page; this is content-level inspection, that is device-level access control.
      </div>

      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">Mode</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="print-content-mode"
              value="enforce"
              checked={config.mode === 'enforce'}
              onChange={() => onChange({ ...config, mode: 'enforce' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Enforce</div>
              <div className="text-muted-foreground text-xs">Cancel the print job when sensitive content is detected</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="print-content-mode"
              value="audit"
              checked={config.mode === 'audit'}
              onChange={() => onChange({ ...config, mode: 'audit' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Audit</div>
              <div className="text-muted-foreground text-xs">Log an event on sensitive content but let the job print -- validate before enforcing</div>
            </div>
          </label>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          When content genuinely can&apos;t be read
        </label>
        <div className="p-3 mb-3 rounded-lg bg-info/10 border border-info/30 text-xs text-info">
          Some printer drivers never produce a readable spool file at all -- not a bug in one specific job, a
          permanent gap for that printer. This setting controls what happens for a job the agent genuinely
          could not verify, as distinct from one it inspected and found clean.
        </div>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="print-content-unknown-action"
              value="allow"
              checked={config.unknownContentAction === 'allow'}
              onChange={() => onChange({ ...config, unknownContentAction: 'allow' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Allow (default)</div>
              <div className="text-muted-foreground text-xs">Let the job print -- consistent with how inspection has always behaved when content can&apos;t be read</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="print-content-unknown-action"
              value="block"
              checked={config.unknownContentAction === 'block'}
              onChange={() => onChange({ ...config, unknownContentAction: 'block' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Block (strict / fail-closed)</div>
              <div className="text-muted-foreground text-xs">Treat unverifiable content as a precaution -- cancel the job rather than pass content nobody actually checked</div>
            </div>
          </label>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        The agent pauses the spool job, extracts readable text from the raw EMF/RAW/PS/PCL spool data, sends it
        for classification, then cancels (enforce) or resumes (audit) the job. Want to also restrict{' '}
        <em>which printers</em> can be used at all? That&apos;s the separate allowlist on the Printers page.
      </p>
    </div>
  )
}
