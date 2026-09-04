'use client'

import { useState } from 'react'
import { ApplicationControlConfig } from '@/types/policy'
import { Plus, X } from 'lucide-react'

interface ApplicationControlPolicyFormProps {
  config: ApplicationControlConfig
  onChange: (config: ApplicationControlConfig) => void
}

// Common CLI transfer tools admins reach for first -- the same set the
// Windows agent's network-exfil CLI-interception path already recognizes.
const commonApps = ['curl.exe', 'wget.exe', 'powershell.exe', 'bitsadmin.exe', 'certutil.exe', 'rclone.exe']

function toList(text: string): string[] {
  return text.split(',').map((s) => s.trim()).filter(Boolean)
}
function fromList(list?: string[]): string {
  return (list || []).join(', ')
}

export default function ApplicationControlPolicyForm({ config: rawConfig, onChange }: ApplicationControlPolicyFormProps) {
  const config: ApplicationControlConfig = {
    mode: rawConfig?.mode ?? 'blocklist',
    applications: rawConfig?.applications ?? [],
    channels: rawConfig?.channels ?? [],
    exceptions: {
      applications: rawConfig?.exceptions?.applications ?? [],
      users: rawConfig?.exceptions?.users ?? [],
      paths: rawConfig?.exceptions?.paths ?? [],
      file_types: rawConfig?.exceptions?.file_types ?? [],
    },
  }

  const [newApp, setNewApp] = useState('')

  const handleToggleApp = (app: string) => {
    const current = config.applications || []
    const next = current.includes(app) ? current.filter((a) => a !== app) : [...current, app]
    onChange({ ...config, applications: next })
  }

  const handleAddApp = () => {
    const app = newApp.trim().toLowerCase()
    if (!app) return
    const current = config.applications || []
    if (current.includes(app)) {
      setNewApp('')
      return
    }
    onChange({ ...config, applications: [...current, app] })
    setNewApp('')
  }

  const handleRemoveApp = (app: string) => {
    onChange({ ...config, applications: (config.applications || []).filter((a) => a !== app) })
  }

  const setExc = (key: 'applications' | 'users' | 'paths' | 'file_types', value: string) =>
    onChange({ ...config, exceptions: { ...config.exceptions, [key]: toList(value) } })

  return (
    <div className="space-y-6">
      <div className="p-4 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
        Allow/block a network upload by <strong>which application performs it</strong>, independent of content --
        e.g. deny <code>curl.exe</code> entirely, or restrict uploads to an approved allowlist of tools.
      </div>

      {/* Mode */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">Mode</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="app-control-mode"
              value="blocklist"
              checked={config.mode === 'blocklist'}
              onChange={() => onChange({ ...config, mode: 'blocklist' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Blocklist</div>
              <div className="text-muted-foreground text-xs">Block the applications listed below; everything else is allowed</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="app-control-mode"
              value="allowlist"
              checked={config.mode === 'allowlist'}
              onChange={() => onChange({ ...config, mode: 'allowlist' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Allowlist</div>
              <div className="text-muted-foreground text-xs">Only the applications listed below may transfer; everything else is blocked</div>
            </div>
          </label>
        </div>
      </div>

      {/* Managed applications */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          {config.mode === 'allowlist' ? 'Allowed Applications' : 'Blocked Applications'}
        </label>

        <div className="flex flex-wrap gap-2 mb-3">
          {commonApps.map((app) => {
            const isSelected = config.applications?.includes(app) || false
            return (
              <button
                key={app}
                type="button"
                onClick={() => handleToggleApp(app)}
                className={`px-3 py-1 rounded-lg border-2 text-sm font-mono transition-all ${
                  isSelected
                    ? 'border-primary bg-primary/10 text-white'
                    : 'border-border bg-muted/30 text-muted-foreground hover:border-primary/40'
                }`}
              >
                {app}
              </button>
            )
          })}
        </div>

        {config.applications && config.applications.length > 0 && (
          <div className="mb-3">
            <div className="text-xs text-muted-foreground mb-2">Selected:</div>
            <div className="flex flex-wrap gap-2">
              {config.applications.map((app) => (
                <div key={app} className="flex items-center gap-2 px-3 py-1 bg-primary/10 border border-primary/30 rounded-lg text-sm">
                  <code className="text-primary">{app}</code>
                  <button type="button" onClick={() => handleRemoveApp(app)} className="text-muted-foreground hover:text-critical transition-colors">
                    <X className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="flex gap-2">
          <input
            type="text"
            value={newApp}
            onChange={(e) => setNewApp(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleAddApp()}
            placeholder="e.g., rclone.exe"
            className="flex-1 px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
          />
          <button
            type="button"
            onClick={handleAddApp}
            className="px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add
          </button>
        </div>
      </div>

      {/* Channels */}
      <div>
        <label className="block text-xs text-muted-foreground mb-1">Covered Channels (blank = all)</label>
        <input
          type="text"
          defaultValue={fromList(config.channels)}
          onChange={(e) => onChange({ ...config, channels: toList(e.target.value) })}
          placeholder="network"
          className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
        />
      </div>

      {/* Exceptions */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">Exceptions (Always Allowed)</label>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Applications</label>
            <input
              type="text"
              defaultValue={fromList(config.exceptions?.applications)}
              onChange={(e) => setExc('applications', e.target.value)}
              placeholder="approved-tool.exe"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Users</label>
            <input
              type="text"
              defaultValue={fromList(config.exceptions?.users)}
              onChange={(e) => setExc('users', e.target.value)}
              placeholder="DOMAIN\admin"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Paths</label>
            <input
              type="text"
              defaultValue={fromList(config.exceptions?.paths)}
              onChange={(e) => setExc('paths', e.target.value)}
              placeholder="C:\Public\"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">File Types</label>
            <input
              type="text"
              defaultValue={fromList(config.exceptions?.file_types)}
              onChange={(e) => setExc('file_types', e.target.value)}
              placeholder="txt, log"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
            />
          </div>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        Enforced by the Windows agent&apos;s network-exfil CLI-transfer interception path -- a block here fires
        regardless of what the application is uploading.
      </p>
    </div>
  )
}
