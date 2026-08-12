'use client'

import { EmailConfig, EmailTriggerLevel } from '@/types/policy'

interface EmailPolicyFormProps {
  config: EmailConfig
  onChange: (config: EmailConfig) => void
}

const TRIGGER_LEVELS: Array<{ value: EmailTriggerLevel; label: string; description: string }> = [
  { value: 'Internal', label: 'Internal', description: 'Internal-use content -- not public, but not highly sensitive either' },
  { value: 'Confidential', label: 'Confidential', description: 'Sensitive business data -- financial figures, internal plans, credentials, etc.' },
  { value: 'Restricted', label: 'Restricted', description: 'Highly sensitive data -- PII, payment card data, regulated data types' },
]

export default function EmailPolicyForm({ config: rawConfig, onChange }: EmailPolicyFormProps) {
  const config: EmailConfig = {
    action: rawConfig?.action ?? 'block',
    triggerLevels: rawConfig?.triggerLevels ?? ['Confidential', 'Restricted'],
  }

  const toggleLevel = (level: EmailTriggerLevel) => {
    const has = config.triggerLevels.includes(level)
    const next = has
      ? config.triggerLevels.filter((l) => l !== level)
      : [...config.triggerLevels, level]
    onChange({ ...config, triggerLevels: next })
  }

  return (
    <div className="space-y-6">
      <div className="p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg text-sm text-amber-200/90">
        Inspects outbound email content routed through the SMTP relay (<strong>smtp-relay/</strong>) before it
        leaves the network -- the same real-time classify-then-decide pipeline used for USB and file-transfer
        content policies, not a device toggle. This policy controls what action fires and which classification
        levels trigger it; the relay itself has to be configured and running (see DEPLOYMENT docs) for outbound
        mail to reach this check at all.
      </div>

      {/* Action */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Action</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="email-action"
              value="block"
              checked={config.action === 'block'}
              onChange={() => onChange({ ...config, action: 'block' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Block</div>
              <div className="text-muted-foreground/70 text-xs">Reject the message -- it never reaches the recipient</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="email-action"
              value="alert"
              checked={config.action === 'alert'}
              onChange={() => onChange({ ...config, action: 'alert' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Alert</div>
              <div className="text-muted-foreground/70 text-xs">Let the message send, but raise a high-visibility event</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="email-action"
              value="log"
              checked={config.action === 'log'}
              onChange={() => onChange({ ...config, action: 'log' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Log only</div>
              <div className="text-muted-foreground/70 text-xs">Record the event for audit/reporting -- no visible action taken</div>
            </div>
          </label>
        </div>
      </div>

      {/* Trigger levels */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Trigger on classification level</label>
        <div className="space-y-2">
          {TRIGGER_LEVELS.map(({ value, label, description }) => (
            <label
              key={value}
              className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all"
            >
              <input
                type="checkbox"
                checked={config.triggerLevels.includes(value)}
                onChange={() => toggleLevel(value)}
                className="w-4 h-4 text-indigo-400"
              />
              <div>
                <div className="text-white font-medium text-sm">{label}</div>
                <div className="text-muted-foreground/70 text-xs">{description}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <p className="text-xs text-muted-foreground/70">
        Public-classified content never triggers this policy. Selecting no levels means the action never fires --
        the policy still records the underlying email event either way.
      </p>
    </div>
  )
}
