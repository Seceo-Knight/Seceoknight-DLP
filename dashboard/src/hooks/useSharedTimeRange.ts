/**
 * Shared "time range" selection (12h / 24h / 3d / 7d / 90d, and "All time"
 * on pages that support it) persisted in localStorage across pages.
 *
 * Found: Dashboard.tsx and Events.tsx each held `rangeHours` in a fully
 * independent `useState`, always initialized to that page's own hardcoded
 * default (24 for Dashboard, "All time" for Events). Picking "3 days" on
 * one page and navigating to the other silently discarded it and came
 * back to that page's default -- there was never any shared state to
 * begin with, in-app navigation or not. September 2026.
 *
 * Deliberately a plain localStorage-backed hook rather than a React
 * Context/provider: this codebase has no existing Context usage, Dashboard
 * and Events are never mounted at the same time (single-route SPA), so
 * there's nothing to keep in sync live -- each page just needs to read the
 * last-written value on its own mount and write back on change, which
 * localStorage does directly. This also means the selection survives a
 * full page reload/reopen, not just client-side route changes.
 */

import { useState } from 'react'

const STORAGE_KEY = 'dlp-time-range-hours'

function readStoredHours(): number | 'all' | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw === null) return null
    if (raw === 'all') return 'all'
    const parsed = Number(raw)
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null
  } catch {
    // localStorage unavailable (private browsing, quota, SSR) -- behave as
    // if nothing were stored; callers fall back to their own default.
    return null
  }
}

function writeStoredHours(hours: number | undefined): void {
  try {
    localStorage.setItem(STORAGE_KEY, hours === undefined ? 'all' : String(hours))
  } catch {
    // Same as above -- non-fatal, selection just won't persist this session.
  }
}

/**
 * For pages that always need a concrete window (Dashboard: its stats/
 * time-series queries have no "all time" mode). Falls back to
 * `fallbackHours` if nothing is stored yet, or if the last thing stored
 * was "All time" from a page that does support it -- this page can't
 * honor that, so it uses its own default instead of passing `undefined`
 * somewhere that expects a number.
 */
export function useSharedRangeHours(fallbackHours: number): [number, (hours: number) => void] {
  const [hours, setHours] = useState<number>(() => {
    const stored = readStoredHours()
    return typeof stored === 'number' ? stored : fallbackHours
  })
  const set = (h: number) => {
    setHours(h)
    writeStoredHours(h)
  }
  return [hours, set]
}

/**
 * For pages that also support "All time" (Events: `hours: undefined`
 * means no lower bound on the query).
 */
export function useSharedRangeHoursOrAll(
  fallbackHours: number | undefined,
): [number | undefined, (hours: number | undefined) => void] {
  const [hours, setHours] = useState<number | undefined>(() => {
    const stored = readStoredHours()
    if (stored === 'all') return undefined
    if (typeof stored === 'number') return stored
    return fallbackHours
  })
  const set = (h: number | undefined) => {
    setHours(h)
    writeStoredHours(h)
  }
  return [hours, set]
}
