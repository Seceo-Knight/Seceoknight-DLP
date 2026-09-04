'use client'

import { NetworkShareControlConfig } from '@/types/policy'

interface NetworkShareControlPolicyFormProps {
  config: NetworkShareControlConfig
  onChange: (config: NetworkShareControlConfig) => void
}

function toList(text: string): string[] {
  return text.split(',').map((s) => s.trim()).filter(Boolean)
}
function fromList(list?: string[]): string {
  return (list || []).join(', ')
}

export default function NetworkShareControlPolicyForm({ config: rawConfig, onChange }: NetworkShareControlPolicyFormProps) {
  const config: NetworkShareControlConfig = {
    mode: rawConfig?.mode ?? 'block_all',
    action: rawConfig?.action ?? 'audit',
    exception_shares: rawConfig?.exception_shares ?? [],
    exception_users: rawConfig?.exception_users ?? [],
    exception_paths: rawConfig?.exception_paths ?? [],
    exception_file_types: rawConfig?.exception_file_types ?? [],
  }

  return (
    <div className="space-y-6">
      <div className="p-4 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
        Controls copying files to mapped network drives (e.g. <code>Z:</code> mapped to <code>\\server\share</code>).
        A distinct exfiltration path from USB -- covers copying to a network share instead of a USB stick.
        Any single exception below always allows the transfer.
      </div>

      {/* Mode */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">What to Block</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="network-share-mode"
              value="block_all"
              checked={config.mode === 'block_all'}
              onChange={() => onChange({ ...config, mode: 'block_all' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Block All Transfers</div>
              <div className="text-muted-foreground text-xs">Block every file copied to a network share, regardless of content</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="network-share-mode"
              value="content_aware"
              checked={config.mode === 'content_aware'}
              onChange={() => onChange({ ...config, mode: 'content_aware' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Only Sensitive Files</div>
              <div className="text-muted-foreground text-xs">Allow copies, but inspect content and block only Confidential / Restricted files</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="network-share-mode"
              value="off"
              checked={config.mode === 'off'}
              onChange={() => onChange({ ...config, mode: 'off' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Off</div>
              <div className="text-muted-foreground text-xs">Disable network share monitoring entirely</div>
            </div>
          </label>
        </div>
      </div>

      {/* Action */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">Action on a Match</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="network-share-action"
              value="audit"
              checked={config.action === 'audit'}
              onChange={() => onChange({ ...config, action: 'audit' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Audit (Log Only)</div>
              <div className="text-muted-foreground text-xs">Record an event but never delete -- use to validate the rule before enforcing</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="network-share-action"
              value="block"
              checked={config.action === 'block'}
              onChange={() => onChange({ ...config, action: 'block' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Enforce (Quarantine + Remove)</div>
              <div className="text-muted-foreground text-xs">Quarantine a copy, then remove the file from the share -- enable only after auditing</div>
            </div>
          </label>
        </div>
      </div>

      {/* Exceptions */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">Exceptions (Always Allowed)</label>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Shares / Servers</label>
            <input
              type="text"
              defaultValue={fromList(config.exception_shares)}
              onChange={(e) => onChange({ ...config, exception_shares: toList(e.target.value) })}
              placeholder="\\fileserver\public"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Users / Groups</label>
            <input
              type="text"
              defaultValue={fromList(config.exception_users)}
              onChange={(e) => onChange({ ...config, exception_users: toList(e.target.value) })}
              placeholder="DOMAIN\admin"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Source Paths / Folders</label>
            <input
              type="text"
              defaultValue={fromList(config.exception_paths)}
              onChange={(e) => onChange({ ...config, exception_paths: toList(e.target.value) })}
              placeholder="C:\Public\"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">File Types</label>
            <input
              type="text"
              defaultValue={fromList(config.exception_file_types)}
              onChange={(e) => onChange({ ...config, exception_file_types: toList(e.target.value) })}
              placeholder="txt, log"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
            />
          </div>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        The endpoint agent watches mapped network drives and enforces on copy. Direct <code>\\server\share</code>{' '}
        paths used without a mapped drive letter are not covered.
      </p>
    </div>
  )
}
