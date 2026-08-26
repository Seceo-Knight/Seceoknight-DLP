'use client'

import { WebActivityControlConfig, WebActivityAction } from '@/types/policy'
import { Bot, Mail, Users, Cloud } from 'lucide-react'

interface WebActivityControlPolicyFormProps {
  config: WebActivityControlConfig
  onChange: (config: WebActivityControlConfig) => void
}

// One row per currently-meaningful (category, activity) cell --
// MEANINGFUL_CELLS in server/app/core/web_activity.py. Deliberately NOT a
// full 4-category x 6-activity matrix grid: upload/attach aren't wired to
// anything yet (the browser extension's file uploads still go through the
// older Cloud Upload Guard path to avoid double-logging), so a control for
// them would look configurable but never actually fire.
//
// "download" rows (gap-scan of CyberSentinel-DLP, August 24, 2026, REVISED
// August 26, 2026): originally designed to cancel-then-re-issue downloads
// so a block could actually stop one, but that broke real downloads
// outright -- Google Drive, SharePoint/OneDrive, and likely most other
// providers mint a one-time signed download URL, and cancelling the
// original request spends it, so re-issuing the same URL just fails
// ("Failed - Forbidden" / "Failed - Needs authorization", confirmed on a
// real endpoint). background.js's downloads hook now NEVER cancels or
// re-issues a download -- the file always reaches disk normally. It only
// still inspects the content for logging/alerting, best-effort. So
// "Block" on a download row means "raise a critical alert", not "stop the
// download" -- see the blockLabel/blockHint override below, which is the
// UI being honest about that rather than implying an enforcement guarantee
// this hook cannot back up. genai.download is left out entirely until it's
// been verified against real GenAI file-output domains.
const rows: Array<{
  key: keyof WebActivityControlConfig['matrix']
  label: string
  description: string
  icon: typeof Bot
  // Restricts which of the 4 actionOptions below are offered for this row.
  // Omitted = all 4. "redact" only makes sense where there's a text stream
  // to substitute into (a fetch request/response body) -- a download is
  // arbitrary bytes hitting local disk with nothing to substitute text
  // into, so offering it here would be exactly the "control that silently
  // does nothing" the comment above says this form avoids.
  actions?: WebActivityAction[]
  // Overrides the "Block" button's label/hint for this row only -- see the
  // download-rows note above for why "Block" doesn't mean "stop it" here.
  blockLabel?: string
  blockHint?: string
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
    key: 'webmail.download',
    label: 'Webmail — Attachment Downloaded',
    description: 'A file downloaded from an email attachment in Gmail, Outlook Web, etc.',
    icon: Mail,
    actions: ['allow', 'alert', 'block'],
    blockLabel: 'Alert (Critical)',
    blockHint: 'Cannot actually stop the download (one-time signed download links break on a second request) -- raises a critical-severity alert instead if the content is genuinely sensitive',
  },
  {
    key: 'collaboration.send',
    label: 'Collaboration — Message Sent',
    description: 'A composed message submitted via Slack, Teams, Discord, WhatsApp Web, etc.',
    icon: Users,
  },
  {
    key: 'collaboration.download',
    label: 'Collaboration — File Downloaded',
    description: 'A file downloaded from a shared link/attachment in Slack, Teams, Discord, etc.',
    icon: Users,
    actions: ['allow', 'alert', 'block'],
    blockLabel: 'Alert (Critical)',
    blockHint: 'Cannot actually stop the download (one-time signed download links break on a second request) -- raises a critical-severity alert instead if the content is genuinely sensitive',
  },
  {
    key: 'file_sharing.download',
    label: 'File Sharing — File Downloaded',
    description: 'A file downloaded from Google Drive, OneDrive, Dropbox, Box, etc. to local disk',
    icon: Cloud,
    actions: ['allow', 'alert', 'block'],
    blockLabel: 'Alert (Critical)',
    blockHint: 'Cannot actually stop the download (Drive/SharePoint/OneDrive use one-time signed download links that break on a second request) -- raises a critical-severity alert instead if the content is genuinely sensitive',
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
        Detects and controls sensitive-data leakage through GenAI assistants, webmail/collaboration tools, and file
        downloads from managed cloud apps, via the browser extension. Each row below is independent — leave a row
        unset (&quot;Not configured&quot;) to take no action on that activity. &quot;Block&quot; and
        &quot;Alert&quot; only actually fire when the content is genuinely sensitive (Confidential/Restricted);
        otherwise traffic passes through untouched.
      </div>

      <div className="space-y-3">
        {rows.map(({ key, label, description, icon: Icon, actions, blockLabel, blockHint }) => {
          const current = config.matrix[key] || ''
          const baseOptionsForRow = actions ? actionOptions.filter((opt) => actions.includes(opt.value)) : actionOptions
          const optionsForRow = baseOptionsForRow.map((opt) =>
            opt.value === 'block' && (blockLabel || blockHint)
              ? { ...opt, label: blockLabel || opt.label, hint: blockHint || opt.hint }
              : opt
          )
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
                {optionsForRow.map((opt) => (
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
        target endpoint(s). File uploads/attachments TO these destinations are covered separately by Cloud Upload
        Guard, not by this policy — the Download rows above are detection and alerting only: the download always
        completes normally (Drive/SharePoint/OneDrive-style one-time signed links make actually stopping a
        download unreliable in a browser extension), and the extension classifies its content best-effort for
        logging and alerting on this dashboard.
      </div>
    </div>
  )
}
