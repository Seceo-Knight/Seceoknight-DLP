import { useEffect, useState } from 'react'
import { getRules, type Rule } from '@/lib/rules-api'
import { validateRegex } from '@/utils/policyUtils'

export interface DetectionPattern {
  regex: string
  description: string
}

export interface SelectableRule {
  rule: Rule
  pattern: DetectionPattern
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Derive a single regex pattern from a custom Rule (Rules tab) so it can be
 * used exactly like a built-in predefined pattern -- a policy's
 * `patterns.custom` list only stores {regex, description} pairs, there's no
 * separate flags/keywords/dictionary concept on the policy side.
 *
 * - regex-type rules use their pattern as-is, prefixed with `(?i)` when the
 *   rule is case-insensitive -- the same inline-flag convention the built-in
 *   "API Key" predefined pattern already uses (see utils/policyUtils.ts).
 * - keyword-type rules become an escaped word-boundary alternation.
 * - dictionary-type rules reference an external wordlist file with no
 *   single-regex equivalent, so they're not selectable here.
 */
function ruleToPattern(rule: Rule): DetectionPattern | null {
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
 * Loads the admin's enabled custom Rules (from the Rules tab) as
 * ready-to-use detection patterns, so a policy's Detection Patterns picker
 * can show them as ordinary selectable tiles right alongside the built-in
 * SSN/Credit Card/Phone Number/etc. patterns -- instead of a separate
 * "import" flow the admin has to discover and understand on top of the
 * pattern picker they already know.
 */
export function useCustomDetectionRules(): { rules: SelectableRule[]; loading: boolean } {
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

  const selectable = rules
    .map((rule) => ({ rule, pattern: ruleToPattern(rule) }))
    .filter((x): x is SelectableRule => x.pattern !== null && validateRegex(x.pattern.regex).valid)

  return { rules: selectable, loading }
}
