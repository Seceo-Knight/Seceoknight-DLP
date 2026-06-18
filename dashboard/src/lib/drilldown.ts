/**
 * Centralised drill-down URL builder.
 *
 * Every clickable surface on the dashboard funnels through this helper
 * so the field→URL-param mapping stays in one place. The destination is
 * always ``/events`` because the Events page is the single investigation
 * surface the rest of the app navigates to (the v2 ``/explore`` page was
 * removed earlier; ``/events`` already accepts the same filter keys).
 *
 * Usage::
 *
 *   navigate(drillDownUrl({ severity: 'critical' }))
 *   // → /events?severity=critical
 *
 *   navigate(drillDownUrl({ module: 'usb', action: 'blocked' }))
 *   // → /events?module=usb&action=blocked
 *
 * Field names match what the backend GET /events/ accepts as query
 * params, see server/app/api/v1/events.py.
 */

/** Fields the Events page knows how to filter on. Adding new ones here
 *  is intentionally explicit so we never accidentally pass a column
 *  name the backend doesn't whitelist. */
export type DrillField =
  | 'severity'
  | 'module'         // alias for event_type
  | 'event_type'
  | 'action'
  | 'classification' // classification_level tier
  | 'channel'

export type DrillFilters = Partial<Record<DrillField, string>> & {
  start_date?: string
  end_date?: string
  time_range?: string
}

/** Build a /events URL with the given filters. Empty/null values are
 *  silently dropped so chart click handlers can pass through the raw
 *  segment label without pre-checking. */
export function drillDownUrl(filters: DrillFilters): string {
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(filters)) {
    if (v === null || v === undefined) continue
    const s = String(v).trim()
    if (!s) continue
    // The Events page treats values case-insensitively; keep lower-case
    // so URLs are stable regardless of which chart the user clicked.
    params.set(k, isCaseSensitive(k) ? s : s.toLowerCase())
  }
  const qs = params.toString()
  return qs ? `/events?${qs}` : '/events'
}

/** Classification levels are stored title-cased ("Confidential", etc.).
 *  Channel and user emails are case-sensitive in storage. Don't lowercase
 *  those at URL-build time. */
function isCaseSensitive(key: string): boolean {
  return key === 'classification' || key === 'channel' || key === 'user_email'
}

/** Tooltip copy used everywhere a drill-down is wired up. Keeping the
 *  string in one place makes it easy to localise later. */
export const DRILL_TOOLTIP = 'Click to drill down to matching events'
