'use client'

import { WebActivityControlConfig, WebActivityAction } from '@/types/policy'
import { Bot, Mail, Users } from 'lucide-react'

interface WebActivityControlPolicyFormProps {
  config: WebActivityControlConfig
  onChange: (config: WebActivityControlConfig) => void
}

// One row per currently-meaningful (category, activity) cell --
// MEANINGFUL_CELLS in server/app/core/web_activity.py. Deliberately NOT a
// full 4-category x 6-activity matrix grid: upload/attach/download aren't
// wired to anything yet (the browser extension's file uploads still go
// through the older Cloud Upload Guard path to avoid double-logging), so a
// control for them would look configurable but never actually fire. Only
// showing cells that do something real.
const rows: Array<{
  key: keyof WebActivityControlConfig['matrix']
  label: string
  description: string
  icon: typeof Bot
}> = [
  {
    key: 'genai.post',
    label: 'GenAI — Prompt Sent',
    description: 'A message/prompt typed into ChatGPT, Copilot, Gemini, Claude, Perplexity, etc.',
    icon: Bot,
  },
  {
    key: 'genai.ai_response',
    label: 'GenAI — Response Received',
    description: 'The reply streaming back from a GenAI assistant (e.g. it echoes sensitive context back)',
    icon: Bot,
  },
  {
    key: 'webmail.send',
    label: 'Webmail — Message Sent',
    description: 'A composed message submitted via Gmail, Outlook Web, etc.',
    icon: Mail,
  },
  {
    key: 'collaboration.send',
    label: 'Collaboration — Message Sent',
    description: 'A composed message submitted via Slack, Teams, Discord, WhatsApp Web, etc.',
    icon: Users,
  },
]

const actionOptions: Array<{ value: WebActivityAction; label: string; hint: string }> = [
  { value: 'allow', label: 'Allow', hint: 'Let it through, no logging beyond the standard event' },
  { value: 'alert', label: 'Alert', hint: 'Let it through, raise a medium-severity alert if sensitive' },
  { value: 'redact', label: 'Redact', hint: 'Strip sensitive values out, then let the rest through' },
  { value: 'block', label: 'Block', hint: 'Stop it entirely if the content is genuinely sensitive' },
]

export default function WebActivityControlPolicyForm({ config: rawConfig, onChange }: WebActivityControlPolicyFormProps) {
  const config: WebActivityControlConfig = {
    matrix: rawConfig?.matrix ?? {},
  }

  const handleSetAction = (key: keyof WebActivityControlConfig['matrix'], action: WebActivityAction | '') => {
    const nextMatrix = { ...config.matrix }
    if (action === '') {
      delete nextMatrix[key]
    } else {
      nextMatrix[key] = action
    }
    onChange({ matrix: nextMatrix })
  }

  return (
    <div className="space-y-6">
      <div className="p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg text-sm text-amber-200/90">
        Detects and controls sensitive-data leakage through GenAI assistants and webmail/collaboration tools, via
        the browser extension. Each row below is independent — leave a row unset (&quot;Not configured&quot;) to
        take no action on that activity. &quot;Block&quot; and &quot;Alert&quot; only actually fire when the
        content is genuinely sensitive (Confidential/Restricted); otherwise traffic passes through untouched.
      </div>

      <div className="space-y-3">
        {rows.map(({ key, label, description, icon: Icon }) => {
          const current = config.matrix[key] || ''
          return (
            <div
              key={key}
              className="p-4 rounded-lg border-2 border-gray-600 bg-gray-900/30"
            >
              <div className="flex items-start gap-3 mb-3">
                <div className="p-2 rounded-lg bg-gray-800/50 text-indigo-300">
                  <Icon className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="text-white font-medium text-sm">{label}</div>
                  <div className="text-muted-foreground/70 text-xs mt-0.5">{description}</div>
                </div>
              </div>

              <div className="ml-11 grid grid-cols-2 sm:grid-cols-5 gap-2">
                <button
                  type="button"
                  onClick={() => handleSetAction(key, '')}
                  className={`px-3 py-2 rounded-lg border-2 text-xs font-medium transition-all text-left ${
                    current === ''
                      ? 'border-gray-400 bg-gray-700/50 text-white'
                      : 'border-gray-700 bg-gray-900/30 text-muted-foreground/70 hover:border-gray-500'
                  }`}
                  title="No action configured for this activity"
                >
                  Not configured
                </button>
                {actionOptions.map((opt) => (
                  <button
                    type="button"
                    key={opt.value}
                    onClick={() => handleSetAction(key, opt.value)}
                    className={`px-3 py-2 rounded-lg border-2 text-xs font-medium transition-all text-left ${
                      current === opt.value
                        ? opt.value === 'block'
                          ? 'border-red-500 bg-red-900/30 text-white'
                          : opt.value === 'redact'
                            ? 'border-purple-500 bg-purple-900/30 text-white'
                            : opt.value === 'alert'
                              ? 'border-amber-500 bg-amber-900/30 text-white'
                              : 'border-green-500 bg-green-900/30 text-white'
                        : 'border-gray-700 bg-gray-900/30 text-muted-foreground/70 hover:border-gray-500'
                    }`}
                    title={opt.hint}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          )
        })}
      </div>

      <div className="p-3 bg-gray-900/40 border border-gray-700 rounded-lg text-xs text-muted-foreground/70">
        Requires the SeceoKnight browser extension (with Web Activity Control support) to be installed on the
        target endpoint(s). File uploads/attachments/downloads to these same destinations are covered separately
        by Cloud Upload Guard, not by this policy.
      </div>
    </div>
  )
}
