'use client'

import { useState } from 'react'
import { WebActivityControlConfig, WebActivityAction } from '@/types/policy'
import { validateRegex, testRegex } from '@/utils/policyUtils'
import { Bot, Mail, Users, Cloud, Plus, Trash2, Check, X } from 'lucide-react'
import { useCustomDetectionRules } from '@/hooks/useCustomDetectionRules'

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
    patterns: { custom: rawConfig?.patterns?.custom ?? [] },
  }

  const [customRegex, setCustomRegex] = useState('')
  const [customDescription, setCustomDescription] = useState('')
  const [testText, setTestText] = useState('')
  const [testResult, setTestResult] = useState<boolean | null>(null)

  // Same Rules-tab source FileSystemPolicyForm uses -- picking a rule here
  // stores the exact same {regex, description} pair it would there.
  const { rules: customRules } = useCustomDetectionRules()

  const handleSetAction = (key: keyof WebActivityControlConfig['matrix'], action: WebActivityAction | '') => {
    const nextMatrix = { ...config.matrix }
    if (action === '') {
      delete nextMatrix[key]
    } else {
      nextMatrix[key] = action
    }
    onChange({ ...config, matrix: nextMatrix })
  }

  const handleRuleToggle = (pattern: { regex: string; description?: string }) => {
    const current = config.patterns!.custom
    const isSelected = current.some((c) => c.regex === pattern.regex)
    const next = isSelected
      ? current.filter((c) => c.regex !== pattern.regex)
      : [...current, pattern]
    onChange({ ...config, patterns: { custom: next } })
  }

  const handleAddCustomPattern = () => {
    const validation = validateRegex(customRegex)
    if (!validation.valid) {
      alert(validation.error)
      return
    }
    onChange({
      ...config,
      patterns: { custom: [...config.patterns!.custom, { regex: customRegex, description: customDescription || undefined }] },
    })
    setCustomRegex('')
    setCustomDescription('')
  }

  const handleRemoveCustomPattern = (index: number) => {
    onChange({ ...config, patterns: { custom: config.patterns!.custom.filter((_, i) => i !== index) } })
  }

  const handleTestRegex = () => {
    if (!customRegex.trim()) {
      alert('Please enter a regex pattern to test')
      return
    }
    const validation = validateRegex(customRegex)
    if (!validation.valid) {
      alert(validation.error)
      return
    }
    setTestResult(testRegex(customRegex, testText))
  }

  const regexValidation = customRegex ? validateRegex(customRegex) : null

  return (
    <div className="space-y-6">
      <div className="p-4 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
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
              className="p-4 rounded-lg border-2 border-border bg-muted/30"
            >
              <div className="flex items-start gap-3 mb-3">
                <div className="p-2 rounded-lg bg-secondary text-primary">
                  <Icon className="w-4 h-4" />
                </div>
                <div className="flex-1">
                  <div className="text-foreground font-medium text-sm">{label}</div>
                  <div className="text-muted-foreground text-xs mt-0.5">{description}</div>
                </div>
              </div>

              <div className="ml-11 grid grid-cols-2 sm:grid-cols-5 gap-2">
                <button
                  type="button"
                  onClick={() => handleSetAction(key, '')}
                  className={`px-3 py-2 rounded-lg border-2 text-xs font-medium transition-all text-left ${
                    current === ''
                      ? 'border-border bg-secondary/50 text-foreground'
                      : 'border-border bg-muted/30 text-muted-foreground hover:border-primary/40'
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
                          ? 'border-critical bg-critical/10 text-foreground'
                          : opt.value === 'redact'
                            ? 'border-purple-500 bg-purple-500/10 text-foreground'
                            : opt.value === 'alert'
                              ? 'border-warning bg-warning/10 text-foreground'
                              : 'border-success bg-success/10 text-foreground'
                        : 'border-border bg-muted/30 text-muted-foreground hover:border-primary/40'
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

      {/* Detection Patterns */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Detection Patterns (Optional)
        </label>
        <p className="text-xs text-muted-foreground mb-3">
          Checked in addition to whatever Rules are already enabled system-wide (Rules tab) — use this to make
          sure a specific rule (or a one-off regex) is always considered for prompts/replies/messages this policy
          covers, regardless of that rule&apos;s own enabled/disabled state elsewhere. Leave empty to rely purely on
          the globally enabled Rules, same as before.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
          {customRules.map(({ rule, pattern }) => {
            const isSelected = config.patterns!.custom.some((c) => c.regex === pattern.regex)
            const preview = rule.type === 'keyword' ? (rule.keywords || []).join(', ') : pattern.regex
            return (
              <button
                type="button"
                key={`rule-${rule.id}`}
                onClick={() => handleRuleToggle(pattern)}
                className={`p-3 rounded-lg border-2 text-left transition-all ${
                  isSelected
                    ? 'border-primary bg-primary/10 text-white'
                    : 'border-border bg-muted/30 text-muted-foreground hover:border-primary/40'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="min-w-0">
                    <div className="font-medium text-sm truncate">{rule.name}</div>
                    <div className="text-xs mt-1 opacity-70 font-mono truncate">{preview}</div>
                  </div>
                  {isSelected && <Check className="w-5 h-5 text-primary" />}
                </div>
              </button>
            )
          })}
          {customRules.length === 0 && (
            <div className="md:col-span-2 text-xs text-muted-foreground italic">
              No Rules found yet — create one in the Rules tab, or add a one-off regex below.
            </div>
          )}
        </div>

        {config.patterns!.custom.length > 0 && (
          <div className="space-y-2 mb-4">
            {config.patterns!.custom.map((custom, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-3 bg-muted/30 rounded-lg border border-border"
              >
                <div className="flex-1">
                  <code className="text-sm text-primary">{custom.regex}</code>
                  {custom.description && (
                    <p className="text-xs text-muted-foreground mt-1">{custom.description}</p>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => handleRemoveCustomPattern(index)}
                  className="ml-3 p-1 text-muted-foreground hover:text-critical transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}

        <div className="space-y-3 p-4 bg-muted/30 rounded-lg border border-border">
          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-2">
              Custom Regex Pattern
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={customRegex}
                onChange={(e) => setCustomRegex(e.target.value)}
                placeholder="e.g., \\d{4}-\\d{4}-\\d{4}"
                className="flex-1 px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all font-mono text-sm"
              />
              {regexValidation && (
                <div className={`flex items-center px-2 ${regexValidation.valid ? 'text-success' : 'text-critical'}`}>
                  {regexValidation.valid ? <Check className="w-5 h-5" /> : <X className="w-5 h-5" />}
                </div>
              )}
            </div>
            {regexValidation && !regexValidation.valid && (
              <p className="text-xs text-critical mt-1">{regexValidation.error}</p>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-2">
              Description (Optional)
            </label>
            <input
              type="text"
              value={customDescription}
              onChange={(e) => setCustomDescription(e.target.value)}
              placeholder="e.g., Internal Project Codename"
              className="w-full px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all text-sm"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-muted-foreground mb-2">
              Test Pattern
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={testText}
                onChange={(e) => setTestText(e.target.value)}
                placeholder="Enter sample text to test"
                className="flex-1 px-3 py-2 bg-muted/30 border-2 border-border rounded-lg text-foreground placeholder-muted-foreground focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all text-sm"
              />
              <button
                type="button"
                onClick={handleTestRegex}
                disabled={!customRegex.trim() || !testText.trim()}
                className="px-4 py-2 bg-primary hover:bg-primary/90 disabled:bg-secondary disabled:text-muted-foreground text-white rounded-lg transition-colors text-sm font-medium"
              >
                Test
              </button>
            </div>
            {testResult !== null && (
              <p className={`text-xs mt-2 ${testResult ? 'text-success' : 'text-critical'}`}>
                {testResult ? '✓ Pattern matches!' : '✗ Pattern does not match'}
              </p>
            )}
          </div>

          <button
            type="button"
            onClick={handleAddCustomPattern}
            disabled={!customRegex.trim() || (regexValidation !== null && !regexValidation.valid)}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 disabled:bg-secondary disabled:text-muted-foreground text-white rounded-lg transition-colors text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            Add Custom Pattern
          </button>
        </div>
      </div>

      <div className="p-3 bg-muted/30 border border-border rounded-lg text-xs text-muted-foreground">
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
