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

// Per-color visual treatments mapped onto the new semantic design tokens
// (bg-primary, bg-critical, bg-warning, bg-success, bg-muted). Kept in one
// map so palette tweaks live in a single place.
const PALETTES: Record<StatsColor, {
  wash: string      // faint tinted background wash
  iconBg: string     // icon bubble background
  iconFg: string      // icon color
  ring: string        // soft ring round the bubble
  value: string        // metric number color
  accent: string        // 2px top accent bar gradient
}> = {
  indigo: {
    wash:   'bg-primary/5',
    iconBg: 'bg-primary/15',
    iconFg: 'text-primary',
    ring:   'ring-primary/10',
    value:  'text-foreground',
    accent: 'from-primary to-info',
  },
  red: {
    wash:   'bg-critical/5',
    iconBg: 'bg-critical/15',
    iconFg: 'text-critical',
    ring:   'ring-critical/10',
    value:  'text-foreground',
    accent: 'from-critical to-destructive',
  },
  orange: {
    wash:   'bg-warning/5',
    iconBg: 'bg-warning/15',
    iconFg: 'text-warning',
    ring:   'ring-warning/10',
    value:  'text-foreground',
    accent: 'from-warning to-critical',
  },
  green: {
    wash:   'bg-success/5',
    iconBg: 'bg-success/15',
    iconFg: 'text-success',
    ring:   'ring-success/10',
    value:  'text-foreground',
    accent: 'from-success to-primary',
  },
  gray: {
    wash:   'bg-muted/40',
    iconBg: 'bg-secondary',
    iconFg: 'text-muted-foreground',
    ring:   'ring-border',
    value:  'text-foreground',
    accent: 'from-muted-foreground/40 to-muted-foreground/10',
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
      {/* Top accent stripe — 2px gradient bar bonded to the card. */}
      <div className={cn('absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r', p.accent)} />

      {/* Drill-down affordance: a small arrow in the top-right that
          lights up on hover. Only rendered when ``to`` is set so the
          card visually advertises "click me" without saying so. */}
      {interactive && (
        <span
          aria-hidden
          className="absolute right-3 top-3 text-muted-foreground/50 transition-colors group-hover:text-primary"
        >
          <ArrowUpRight className="h-4 w-4" />
        </span>
      )}

      <div className="relative flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{title}</p>
          <p className={cn('mt-2 text-3xl font-bold tabular-nums tracking-tight', p.value)}>{value}</p>
          {subtext && <p className="mt-1 text-xs text-muted-foreground">{subtext}</p>}
          {trend && (
            <span
              className={cn(
                'mt-3 inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold',
                trend.isPositive ? 'bg-success/15 text-success' : 'bg-critical/15 text-critical',
              )}
            >
              <span aria-hidden>{trend.isPositive ? '↑' : '↓'}</span>
              {Math.abs(trend.value)}%
            </span>
          )}
        </div>
        <div
          className={cn(
            'flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ring-4',
            p.iconBg, p.iconFg, p.ring,
          )}
        >
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </>
  )

  const surface = cn(
    'group relative overflow-hidden rounded-xl border border-border bg-card p-5 shadow-sm transition-all duration-200',
    p.wash,
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
          surface,
          'block cursor-pointer hover:-translate-y-1 hover:border-primary/30 hover:shadow-md',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
        )}
      >
        {body}
      </Link>
    )
  }
  return <div className={surface}>{body}</div>
}
