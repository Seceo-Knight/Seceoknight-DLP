'use client'

import { useState } from 'react'
import { MessagingAppControlConfig, MESSAGING_DATA_TYPES } from '@/types/policy'
import { Plus, X, Keyboard } from 'lucide-react'

interface MessagingAppControlPolicyFormProps {
  config: MessagingAppControlConfig
  onChange: (config: MessagingAppControlConfig) => void
}

// Matches the server's own _DEFAULT_MESSAGING_APPS fallback (used when a
// policy is active but names no apps) and the agent-side fallback list.
// whatsapp.root.exe: current WhatsApp for Windows is a WebView2 app whose
// window belongs to WhatsApp.Root.exe -- a machine with it installed has no
// whatsapp.exe at all (gap-scan of CyberSentinel-DLP commit 07ea6ba).
const defaultApps = ['teams.exe', 'whatsapp.exe', 'whatsapp.root.exe', 'telegram.exe', 'slack.exe', 'discord.exe', 'signal.exe']

function toList(text: string): string[] {
  return text.split(',').map((s) => s.trim()).filter(Boolean)
}
function fromList(list?: string[]): string {
  return (list || []).join(', ')
}

export default function MessagingAppControlPolicyForm({ config: rawConfig, onChange }: MessagingAppControlPolicyFormProps) {
  const config: MessagingAppControlConfig = {
    action: rawConfig?.action ?? 'alert',
    apps: rawConfig?.apps ?? [],
    exceptions: {
      users: rawConfig?.exceptions?.users ?? [],
      file_types: rawConfig?.exceptions?.file_types ?? [],
    },
    inspect_messages: rawConfig?.inspect_messages ?? false,
    message_data_types: rawConfig?.message_data_types,
  }

  const toggleDataType = (type: string) => {
    // undefined means "server default (everything except INDIAN_PHONE)" --
    // the first click here has to materialize that into an explicit list
    // before it can be edited, otherwise toggling one type off would look
    // like it did nothing (still undefined, still "default").
    const current = config.message_data_types ?? MESSAGING_DATA_TYPES.filter((t) => t !== 'INDIAN_PHONE')
    const next = current.includes(type) ? current.filter((t) => t !== type) : [...current, type]
    onChange({ ...config, message_data_types: next })
  }

  const [newApp, setNewApp] = useState('')

  const handleToggleApp = (app: string) => {
    const current = config.apps || []
    const next = current.includes(app) ? current.filter((a) => a !== app) : [...current, app]
    onChange({ ...config, apps: next })
  }

  const handleAddApp = () => {
    const app = newApp.trim().toLowerCase()
    if (!app) return
    const current = config.apps || []
    if (current.includes(app)) {
      setNewApp('')
      return
    }
    onChange({ ...config, apps: [...current, app] })
    setNewApp('')
  }

  const handleRemoveApp = (app: string) => {
    onChange({ ...config, apps: (config.apps || []).filter((a) => a !== app) })
  }

  const setExc = (key: 'users' | 'file_types', value: string) =>
    onChange({ ...config, exceptions: { ...config.exceptions, [key]: toList(value) } })

  return (
    <div className="space-y-6">
      <div className="p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg text-sm text-amber-200/90">
        Intercepts file-picker attachments in managed messaging / thick-client apps. Alert-first by design:
        leave on <strong>Alert</strong> so enabling this policy never terminates an app until you deliberately
        opt into <strong>Block</strong>. Drag-and-drop attachments bypass the common file dialog and aren&apos;t
        covered -- only file-picker attachments are visible to this control.
      </div>

      {/* Action */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Action on Sensitive Attachment</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="messaging-action"
              value="alert"
              checked={config.action === 'alert'}
              onChange={() => onChange({ ...config, action: 'alert' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Alert</div>
              <div className="text-muted-foreground/70 text-xs">Log an event; the app keeps running and the attachment goes through</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="messaging-action"
              value="block"
              checked={config.action === 'block'}
              onChange={() => onChange({ ...config, action: 'block' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Block</div>
              <div className="text-muted-foreground/70 text-xs">Terminate the app when a sensitive attachment is picked -- only enable after auditing</div>
            </div>
          </label>
        </div>
      </div>

      {/* Managed apps */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Managed Apps</label>
        <p className="text-xs text-muted-foreground/70 mb-3">
          Leave empty to use the built-in default list ({defaultApps.join(', ')}).
        </p>

        <div className="flex flex-wrap gap-2 mb-3">
          {defaultApps.map((app) => {
            const isSelected = config.apps?.includes(app) || false
            return (
              <button
                key={app}
                type="button"
                onClick={() => handleToggleApp(app)}
                className={`px-3 py-1 rounded-lg border-2 text-sm font-mono transition-all ${
                  isSelected
                    ? 'border-indigo-500 bg-indigo-900/30 text-white'
                    : 'border-gray-600 bg-gray-900/30 text-muted-foreground/70 hover:border-gray-500'
                }`}
              >
                {app}
              </button>
            )
          })}
        </div>

        {config.apps && config.apps.length > 0 && (
          <div className="mb-3">
            <div className="text-xs text-muted-foreground/70 mb-2">Selected:</div>
            <div className="flex flex-wrap gap-2">
              {config.apps.map((app) => (
                <div key={app} className="flex items-center gap-2 px-3 py-1 bg-indigo-900/30 border border-indigo-500/50 rounded-lg text-sm">
                  <code className="text-indigo-300">{app}</code>
                  <button type="button" onClick={() => handleRemoveApp(app)} className="text-muted-foreground/70 hover:text-red-400 transition-colors">
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
            placeholder="e.g., skype.exe"
            className="flex-1 px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-muted-foreground focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
          />
          <button
            type="button"
            onClick={handleAddApp}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add
          </button>
        </div>
      </div>

      {/* Typed-message inspection */}
      <div className="border-t border-gray-700 pt-6">
        <label className="flex items-start gap-3 p-3 rounded-lg border-2 border-amber-500/40 bg-amber-900/10 cursor-pointer hover:border-amber-500/60 transition-all">
          <input
            type="checkbox"
            checked={config.inspect_messages ?? false}
            onChange={(e) => onChange({ ...config, inspect_messages: e.target.checked })}
            className="w-4 h-4 mt-0.5 text-indigo-400"
          />
          <div>
            <div className="text-white font-medium text-sm flex items-center gap-2">
              <Keyboard className="w-4 h-4 text-amber-400" />
              Also inspect typed messages (not just file attachments)
            </div>
            <div className="text-muted-foreground/70 text-xs mt-1">
              A different, separate control from the attachment settings above. When on, the agent watches for
              the send key (Enter) in a managed app, reads the message box, and classifies it locally before the
              message leaves. Off by default and does not inherit from anything else on this policy -- this is a
              decision to make on purpose.
            </div>
            {(config.inspect_messages ?? false) && config.action === 'block' && (
              <div className="text-amber-300 text-xs mt-2 font-medium">
                ⚠ Action is set to Block above, so this will hold and drop the send keystroke for a sensitive
                message in a managed app. Strongly recommended: validate on Alert first (switch Action to Alert),
                confirm detections on the dashboard look right, THEN switch to Block. Alert mode never touches
                the keyboard at all.
              </div>
            )}
          </div>
        </label>

        {(config.inspect_messages ?? false) && (
          <div className="mt-3">
            <label className="block text-xs text-muted-foreground/70 mb-2">
              Data types that count as sensitive in a typed message (separate from attachments -- a phone number
              typed into chat is ordinary; leave INDIAN_PHONE off unless you actually want it flagged there).
            </label>
            <div className="flex flex-wrap gap-2">
              {MESSAGING_DATA_TYPES.map((type) => {
                const selected = config.message_data_types ?? MESSAGING_DATA_TYPES.filter((t) => t !== 'INDIAN_PHONE')
                const isSelected = selected.includes(type)
                return (
                  <button
                    key={type}
                    type="button"
                    onClick={() => toggleDataType(type)}
                    className={`px-3 py-1 rounded-lg border-2 text-xs font-mono transition-all ${
                      isSelected
                        ? 'border-indigo-500 bg-indigo-900/30 text-white'
                        : 'border-gray-600 bg-gray-900/30 text-muted-foreground/70 hover:border-gray-500'
                    }`}
                  >
                    {type}
                  </button>
                )
              })}
            </div>
            {(config.message_data_types ?? []).length === 0 && rawConfig?.message_data_types !== undefined && (
              <div className="text-muted-foreground/70 text-xs mt-2">
                No data types selected -- typed-message inspection is effectively off even though the checkbox
                above is checked.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Exceptions */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Exceptions (Always Allowed)</label>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="block text-xs text-muted-foreground/70 mb-1">Users</label>
            <input
              type="text"
              defaultValue={fromList(config.exceptions?.users)}
              onChange={(e) => setExc('users', e.target.value)}
              placeholder="DOMAIN\admin"
              className="w-full px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-muted-foreground focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground/70 mb-1">File Types</label>
            <input
              type="text"
              defaultValue={fromList(config.exceptions?.file_types)}
              onChange={(e) => setExc('file_types', e.target.value)}
              placeholder="txt, log"
              className="w-full px-3 py-2 bg-gray-900/50 border-2 border-gray-600 rounded-lg text-white placeholder-muted-foreground focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 transition-all font-mono text-sm"
            />
          </div>
        </div>
      </div>
    </div>
  )
}
