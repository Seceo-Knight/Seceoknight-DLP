'use client'

import { FileAccessControlConfig } from '@/types/policy'

interface FileAccessControlPolicyFormProps {
  config: FileAccessControlConfig
  onChange: (config: FileAccessControlConfig) => void
}

const classificationLevels = ['Public', 'Internal', 'Confidential', 'Restricted']

function toList(text: string): string[] {
  return text.split(',').map((s) => s.trim()).filter(Boolean)
}
function fromList(list?: string[]): string {
  return (list || []).join(', ')
}

export default function FileAccessControlPolicyForm({ config: rawConfig, onChange }: FileAccessControlPolicyFormProps) {
  const config: FileAccessControlConfig = {
    mode: rawConfig?.mode ?? 'audit',
    classification_levels: rawConfig?.classification_levels ?? [],
    explicit_paths: rawConfig?.explicit_paths ?? [],
    authorized_users: rawConfig?.authorized_users ?? [],
    authorized_groups: rawConfig?.authorized_groups ?? [],
    always_allow_admins: rawConfig?.always_allow_admins ?? true,
  }

  const toggleLevel = (level: string) => {
    const current = config.classification_levels || []
    const next = current.includes(level) ? current.filter((l) => l !== level) : [...current, level]
    onChange({ ...config, classification_levels: next })
  }

  const noTargeting = config.classification_levels.length === 0 && config.explicit_paths.length === 0
  const noPrincipals = config.authorized_users.length === 0 && config.authorized_groups.length === 0

  return (
    <div className="space-y-6">
      <div className="p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg text-sm text-amber-200/90">
        Restricts <strong>who may open a file at all</strong> -- enforced as a native NTFS permission change on the
        Windows agent, not a transfer-time block like other policy types. SYSTEM and local Administrators always
        keep full control, so an admin can never lock themselves out. Everyone else is denied unless named below.
      </div>

      {/* Mode */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Mode</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="file-access-mode"
              value="enforce"
              checked={config.mode === 'enforce'}
              onChange={() => onChange({ ...config, mode: 'enforce' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Enforce</div>
              <div className="text-muted-foreground/70 text-xs">Actually set the NTFS permissions described below</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="file-access-mode"
              value="audit"
              checked={config.mode === 'audit'}
              onChange={() => onChange({ ...config, mode: 'audit' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Audit</div>
              <div className="text-muted-foreground/70 text-xs">Evaluate and log what would be restricted -- no permission changes. Use this first.</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="file-access-mode"
              value="off"
              checked={config.mode === 'off'}
              onChange={() => onChange({ ...config, mode: 'off' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Off</div>
              <div className="text-muted-foreground/70 text-xs">Disable this policy entirely; the agent reverts any permissions it previously set for it</div>
            </div>
          </label>
        </div>
      </div>

      {/* Targeting: classification */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-2">Restrict by Classification</label>
        <p className="text-xs text-muted-foreground/70 mb-3">
          Applied the moment a monitored file is written and classified at one of these levels.
        </p>
        <div className="flex flex-wrap gap-2">
          {classificationLevels.map((level) => {
            const isSelected = config.classification_levels.includes(level)
            return (
              <button
                key={level}
                type="button"
                onClick={() => toggleLevel(level)}
                className={`px-3 py-1 rounded-lg border-2 text-sm transition-all ${
                  isSelected
                    ? 'border-indigo-500 bg-indigo-900/30 text-white'
                    : 'border-gray-600 bg-gray-900/30 text-muted-foreground/70 hover:border-gray-500'
                }`}
              >
                {level}
              </button>
            )
          })}
        </div>
      </div>

      {/* Targeting: explicit paths */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-2">Restrict by Path (optional)</label>
        <p className="text-xs text-muted-foreground/70 mb-2">
          Specific files or folders, independent of classification. Reconciled on every policy-sync cycle.
        </p>
        <input
          type="text"
          defaultValue={fromList(config.explicit_paths)}
          onChange={(e) => onChange({ ...config, explicit_paths: toList(e.target.value) })}
          placeholder={'C:\\Shared\\HR, C:\\Shared\\Finance'}
          className="w-full px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-muted-foreground focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
        />
      </div>

      {noTargeting && (
        <div className="p-3 bg-red-900/20 border border-red-500/30 rounded-lg text-xs text-red-200/90">
          No classification levels or paths selected -- this policy won&apos;t apply to anything yet.
        </div>
      )}

      {/* Authorized principals */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Authorized Users &amp; Groups</label>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="block text-xs text-muted-foreground/70 mb-1">Users</label>
            <input
              type="text"
              defaultValue={fromList(config.authorized_users)}
              onChange={(e) => onChange({ ...config, authorized_users: toList(e.target.value) })}
              placeholder="jdoe, asmith"
              className="w-full px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-muted-foreground focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground/70 mb-1">Groups</label>
            <input
              type="text"
              defaultValue={fromList(config.authorized_groups)}
              onChange={(e) => onChange({ ...config, authorized_groups: toList(e.target.value) })}
              placeholder="HR-Team, DOMAIN\Finance"
              className="w-full px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-muted-foreground focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
            />
          </div>
        </div>
        <p className="text-xs text-muted-foreground/70 mt-2">
          Local Windows accounts by name, or <code>DOMAIN\name</code> for Active Directory accounts/groups if the
          endpoint is domain-joined.
        </p>
      </div>

      {noPrincipals && !noTargeting && (
        <div className="p-3 bg-red-900/20 border border-red-500/30 rounded-lg text-xs text-red-200/90">
          No authorized users or groups listed -- this policy won&apos;t apply until at least one is added.
        </div>
      )}

      {/* Admin safety */}
      <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
        <input
          type="checkbox"
          checked={config.always_allow_admins ?? true}
          onChange={(e) => onChange({ ...config, always_allow_admins: e.target.checked })}
          className="w-4 h-4 text-indigo-400 rounded"
        />
        <div>
          <div className="text-white font-medium text-sm">Always allow Administrators</div>
          <div className="text-muted-foreground/70 text-xs">
            Keep the local Administrators group&apos;s access regardless of this policy (recommended -- avoids IT lockout)
          </div>
        </div>
      </label>

      <p className="text-xs text-muted-foreground/70">
        Windows only. Enforced as an explicit NTFS DACL set by the agent (SetNamedSecurityInfo, inheritance broken
        on the target). Logging who was denied access requires Windows Security auditing and is not yet wired up --
        this policy prevents access but does not yet report attempted, denied opens as events.
      </p>
    </div>
  )
}
