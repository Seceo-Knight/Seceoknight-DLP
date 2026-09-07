'use client'

import { useEffect, useState } from 'react'
import { Plus, Check, Loader2 } from 'lucide-react'
import { getRules, type Rule } from '@/lib/rules-api'
import { validateRegex } from '@/utils/policyUtils'

interface ImportablePattern {
  regex: string
  description: string
}

interface RuleImportPickerProps {
  /** Regex strings already present in the policy's custom pattern list --
   *  used to grey out rules that have already been imported so re-clicking
   *  Add is a no-op instead of creating a duplicate entry. */
  existingRegexes: string[]
  onImport: (pattern: ImportablePattern) => void
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Derive a single regex pattern from a custom Rule (Rules tab) so it can be
 * dropped straight into a policy's `patterns.custom` list -- that list only
 * stores {regex, description} pairs, there's no separate flags/keywords/
 * dictionary concept on the policy side.
 *
 * - regex-type rules use their pattern as-is, prefixed with `(?i)` when the
 *   rule is case-insensitive -- the same inline-flag convention the built-in
 *   "API Key" predefined pattern already uses (see utils/policyUtils.ts).
 * - keyword-type rules become an escaped word-boundary alternation.
 * - dictionary-type rules reference an external wordlist file with no
 *   single-regex equivalent, so they're not importable here.
 */
function ruleToPattern(rule: Rule): ImportablePattern | null {
  if (rule.type === 'regex' && rule.pattern) {
    const caseInsensitive = rule.case_sensitive === false || (rule.regex_flags || []).includes('i')
    const regex = caseInsensitive && !rule.pattern.startsWith('(?i)') ? `(?i)${rule.pattern}` : rule.pattern
    return { regex, description: rule.name }
  }
  if (rule.type === 'keyword' && rule.keywords && rule.keywords.length > 0) {
    const escaped = rule.keywords.filter(Boolean).map(escapeRegExp)
    if (escaped.length === 0) return null
    const body = `\\b(?:${escaped.join('|')})\\b`
    const regex = rule.case_sensitive === false ? `(?i)${body}` : body
    return { regex, description: rule.name }
  }
  return null
}

/**
 * Lets a policy's "Custom Regex Patterns" section pull in patterns the
 * admin already defined in the Rules tab instead of forcing them to
 * retype the same regex/keywords by hand for every policy that should
 * catch it. Used by ClipboardPolicyForm and FileSystemPolicyForm.
 */
export default function RuleImportPicker({ existingRegexes, onImport }: RuleImportPickerProps) {
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    getRules({ enabled_only: true, limit: 500 })
      .then((data) => { if (!cancelled) setRules(Array.isArray(data) ? data : []) })
      .catch(() => { /* Rules tab data is a nice-to-have here -- don't block policy creation if it's unreachable */ })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  const importable = rules
    .map((rule) => ({ rule, pattern: ruleToPattern(rule) }))
    .filter((x): x is { rule: Rule; pattern: ImportablePattern } => x.pattern !== null && validateRegex(x.pattern.regex).valid)

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground px-1 mb-4">
        <Loader2 className="w-3.5 h-3.5 animate-spin" />
        Loading your Rules...
      </div>
    )
  }

  if (importable.length === 0) {
    return null
  }

  return (
    <div className="mb-4">
      <label className="block text-xs font-medium text-muted-foreground mb-2">
        Import from Your Rules (Rules tab)
      </label>
      <div className="space-y-2">
        {importable.map(({ rule, pattern }) => {
          const alreadyAdded = existingRegexes.includes(pattern.regex)
          return (
            <div
              key={rule.id}
              className="flex items-center justify-between gap-3 p-3 bg-muted/30 rounded-lg border border-border"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-foreground truncate">{rule.name}</span>
                  <span className="badge bg-secondary text-foreground/90 shrink-0">{rule.type}</span>
                  {rule.category && (
                    <span className="badge badge-info shrink-0">{rule.category}</span>
                  )}
                </div>
                <code className="text-xs text-primary block truncate mt-0.5">{pattern.regex}</code>
              </div>
              <button
                onClick={() => !alreadyAdded && onImport(pattern)}
                disabled={alreadyAdded}
                className="shrink-0 flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors bg-primary hover:bg-primary/90 disabled:bg-secondary disabled:text-muted-foreground text-white"
              >
                {alreadyAdded ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    Added
                  </>
                ) : (
                  <>
                    <Plus className="w-3.5 h-3.5" />
                    Add
                  </>
                )}
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}
