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

// JS's RegExp doesn't support Python/PCRE-style inline mode modifiers like
// `(?i)` -- `new RegExp('(?i)foo')` throws "Invalid group". Rules imported
// or hand-written with one baked into `pattern` would otherwise fail the
// validateRegex() check below and silently vanish from the picker for a
// reason that isn't visible anywhere in the UI. Stripping a leading one
// just downgrades that one rule to case-sensitive matching instead of
// making it disappear entirely.
function stripLeadingInlineFlags(pattern: string): string {
  return pattern.replace(/^\(\?[a-zA-Z]+\)/, '')
}

/**
 * Derive a single regex pattern from a custom Rule (Rules tab) so it can be
 * used exactly like a built-in predefined pattern -- a policy's
 * `patterns.custom` list only stores {regex, description} pairs, there's no
 * separate flags/keywords/dictionary concept on the policy side.
 *
 * IMPORTANT: this does NOT try to translate Rule.case_sensitive into an
 * `(?i)` prefix. Rule.case_sensitive defaults to `false` at the DB column
 * level (see app/models/rule.py) for any row that didn't explicitly set
 * it -- which in practice is nearly every seeded default rule. An earlier
 * version of this function prefixed `(?i)` whenever case_sensitive was
 * false, which is invalid JS regex syntax (see stripLeadingInlineFlags
 * above) and made validateRegex() reject almost every rule, silently
 * emptying this picker down to just the one rule that happened to have
 * case_sensitive=true. Case-sensitivity just isn't preserved here --
 * there's nowhere to put a separate flag in `patterns.custom`'s shape.
 *
 * - regex-type rules use their pattern as-is (minus any leading inline
 *   flag group).
 * - keyword-type rules become an escaped word-boundary alternation.
 * - dictionary-type rules reference an external wordlist file with no
 *   single-regex equivalent, so they're not selectable here.
 */
function ruleToPattern(rule: Rule): DetectionPattern | null {
  if (rule.type === 'regex' && rule.pattern) {
    return { regex: stripLeadingInlineFlags(rule.pattern), description: rule.name }
  }
  if (rule.type === 'keyword' && rule.keywords && rule.keywords.length > 0) {
    const escaped = rule.keywords.filter(Boolean).map(escapeRegExp)
    if (escaped.length === 0) return null
    return { regex: `\\b(?:${escaped.join('|')})\\b`, description: rule.name }
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
