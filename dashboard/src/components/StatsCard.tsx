import { LucideIcon } from 'lucide-react'
import { Link } from 'react-router-dom'
import { ArrowUpRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { DRILL_TOOLTIP } from '@/lib/drilldown'

export type StatsColor = 'indigo' | 'red' | 'orange' | 'green' | 'gray'
type LegacyColor = 'blue' | 'green' | 'red' | 'yellow'
export type StatsCardColor = StatsColor | LegacyColor

interface StatsCardProps {
  title: string
  value: string | number
  icon: LucideIcon
  /** Trend chip rendered under the metric. Negative numbers come in
   *  red, positive in green; the +/- sign is added automatically. */
  trend?: { value: number; isPositive: boolean }
  /** Optional sub-label rendered below the metric (e.g. "of 5 total"). */
  subtext?: string
  /** Semantic colour (PART 1). Accepts both the new palette
   *  ('indigo'|'red'|'orange'|'green'|'gray') and the legacy palette
   *  ('blue'|'green'|'red'|'yellow') for back-compat with older pages.
   */
  color?: StatsCardColor
  /** Drill-down destination. When set, the card becomes a Link with
   *  cursor-pointer + tooltip + a small arrow affordance in the corner. */
  to?: string
  /** Tooltip override for the drill-down. Defaults to the shared
   *  "Click to drill down" copy. */
  drillTooltip?: string
}

// Per-color visual treatments. Kept in one map so the typography stays
// consistent and palette tweaks live in a single place.
const PALETTES: Record<StatsColor, {
  blob: string                 // background blob colour
  iconBg: string               // gradient on the icon bubble
  iconRing: string             // soft ring round the bubble
  text: string                 // gradient on the metric number
  accent: string               // tiny top-stripe accent
}> = {
  indigo: {
    blob:    'bg-indigo-500',
    iconBg:  'bg-gradient-to-br from-indigo-500 to-blue-600',
    iconRing:'ring-indigo-100',
    text:    'text-gradient-indigo',
    accent:  'from-indigo-500 to-blue-500',
  },
  red: {
    blob:    'bg-red-500',
    iconBg:  'bg-gradient-to-br from-red-500 to-rose-600',
    iconRing:'ring-red-100',
    text:    'text-gradient-red',
    accent:  'from-red-500 to-rose-500',
  },
  orange: {
    blob:    'bg-orange-500',
    iconBg:  'bg-gradient-to-br from-orange-500 to-amber-600',
    iconRing:'ring-orange-100',
    text:    'text-gradient-orange',
    accent:  'from-orange-500 to-amber-500',
  },
  green: {
    blob:    'bg-emerald-500',
    iconBg:  'bg-gradient-to-br from-emerald-500 to-green-600',
    iconRing:'ring-emerald-100',
    text:    'text-gradient-green',
    accent:  'from-emerald-500 to-green-500',
  },
  gray: {
    blob:    'bg-slate-400',
    iconBg:  'bg-gradient-to-br from-slate-500 to-slate-600',
    iconRing:'ring-slate-100',
    text:    'text-slate-900',
    accent:  'from-slate-400 to-slate-500',
  },
}

// Map the legacy ``color="blue|green|red|yellow"`` prop onto the new
// semantic palette so existing pages don't break visually.
const LEGACY_COLOR: Record<LegacyColor, StatsColor> = {
  blue:   'indigo',
  green:  'green',
  red:    'red',
  yellow: 'orange',
}

function normalize(c: StatsCardColor | undefined): StatsColor {
  if (!c) return 'indigo'
  if (c in PALETTES) return c as StatsColor
  return LEGACY_COLOR[c as LegacyColor] ?? 'indigo'
}

export default function StatsCard({
  title,
  value,
  icon: Icon,
  trend,
  subtext,
  color,
  to,
  drillTooltip,
}: StatsCardProps) {
  const semantic: StatsColor = normalize(color)
  const p = PALETTES[semantic]
  const interactive = !!to

  const body = (
    <>
      {/* Soft blob in the corner — pulls the eye to the metric without
          overpowering it. Gets its colour from the semantic palette. */}
      <div className={cn('stats-blob', p.blob)} />

      {/* Top accent stripe — 2px gradient bar bonded to the card. */}
      <div
        className={cn(
          'absolute inset-x-0 top-0 h-[2px] rounded-t-2xl bg-gradient-to-r',
          p.accent,
        )}
      />

      {/* Drill-down affordance: a small arrow in the top-right that
          lights up on hover. Only rendered when ``to`` is set so the
          card visually advertises "click me" without saying so. */}
      {interactive && (
        <span
          aria-hidden
          className="absolute top-3 right-3 text-gray-300 transition-colors group-hover:text-indigo-600"
        >
          <ArrowUpRight className="h-4 w-4" />
        </span>
      )}

      <div className="relative flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="metric-label">{title}</p>
          <p className={cn('metric-value mt-3', p.text)}>{value}</p>
          {subtext && (
            <p className="mt-1 text-xs text-gray-500">{subtext}</p>
          )}
          {trend && (
            <span
              className={cn(
                'mt-3 inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold',
                trend.isPositive
                  ? 'bg-emerald-50 text-emerald-700'
                  : 'bg-red-50 text-red-700',
              )}
            >
              <span aria-hidden>{trend.isPositive ? '↑' : '↓'}</span>
              {Math.abs(trend.value)}%
            </span>
          )}
        </div>
        <div
          className={cn(
            'h-11 w-11 shrink-0 rounded-xl flex items-center justify-center text-white shadow-sm ring-4',
            p.iconBg,
            p.iconRing,
          )}
        >
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </>
  )

  // Non-interactive: plain div surface. Interactive: <Link> with
  // cursor-pointer, focus ring, and a slightly stronger hover lift so
  // the drill-down affordance is unmistakable.
  if (interactive) {
    return (
      <Link
        to={to!}
        title={drillTooltip ?? DRILL_TOOLTIP}
        aria-label={`${title}: ${drillTooltip ?? DRILL_TOOLTIP}`}
        className={cn(
          'card-modern relative overflow-hidden block group cursor-pointer',
          'hover:-translate-y-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2',
        )}
      >
        {body}
      </Link>
    )
  }
  return <div className="card-modern relative overflow-hidden">{body}</div>
}
