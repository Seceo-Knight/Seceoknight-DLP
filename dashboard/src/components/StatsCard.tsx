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
  /** Makes the card a toggle button instead of a display tile or a Link
   *  (mutually exclusive with `to`) -- for stat tiles that filter an
   *  on-page list rather than navigate away, e.g. Alerts' Total/High/
   *  Critical tiles. */
  onClick?: () => void
  /** Whether this toggle tile is the currently-selected filter. Only
   *  meaningful together with `onClick`. Renders a restrained selected
   *  state (tinted border + 1px ring) rather than a bright glowing ring. */
  active?: boolean
}

// Per-color visual treatments mapped onto the new semantic design tokens
// (bg-primary, bg-critical, bg-warning, bg-success, bg-muted). Kept in one
// map so palette tweaks live in a single place.
//
// Deliberately restrained (Purview/Azure Portal register, not a marketing
// stat card): no tinted card background, no ring halo, no gradient accent
// bar -- color shows up only in the icon and the left rule, which is
// enough to carry meaning without the card reading as a colorful tile.
const PALETTES: Record<StatsColor, {
  iconBg: string    // icon bubble background
  iconFg: string    // icon color
  rule: string       // 2px left border rule
  value: string        // metric number color
  activeRing: string  // toggle-mode selected state
}> = {
  indigo: {
    iconBg: 'bg-primary/10',
    iconFg: 'text-primary',
    rule:   'border-l-primary',
    value:  'text-foreground',
    activeRing: 'ring-1 ring-primary/30 border-primary/40 bg-primary/[0.03]',
  },
  red: {
    iconBg: 'bg-critical/10',
    iconFg: 'text-critical',
    rule:   'border-l-critical',
    value:  'text-foreground',
    activeRing: 'ring-1 ring-critical/30 border-critical/40 bg-critical/[0.03]',
  },
  orange: {
    iconBg: 'bg-warning/10',
    iconFg: 'text-warning',
    rule:   'border-l-warning',
    value:  'text-foreground',
    activeRing: 'ring-1 ring-warning/30 border-warning/40 bg-warning/[0.03]',
  },
  green: {
    iconBg: 'bg-success/10',
    iconFg: 'text-success',
    rule:   'border-l-success',
    value:  'text-foreground',
    activeRing: 'ring-1 ring-success/30 border-success/40 bg-success/[0.03]',
  },
  gray: {
    iconBg: 'bg-secondary',
    iconFg: 'text-muted-foreground',
    rule:   'border-l-border',
    value:  'text-foreground',
    activeRing: 'ring-1 ring-border bg-muted/40',
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
  onClick,
  active,
}: StatsCardProps) {
  const semantic: StatsColor = normalize(color)
  const p = PALETTES[semantic]
  const interactive = !!to
  const toggleable = !!onClick && !to

  const body = (
    <>
      {/* Drill-down affordance: a small arrow in the top-right that
          lights up on hover. Only rendered when ``to`` is set so the
          card visually advertises "click me" without saying so. */}
      {interactive && (
        <span
          aria-hidden
          className="absolute right-2.5 top-2.5 text-muted-foreground/40 transition-colors group-hover:text-primary"
        >
          <ArrowUpRight className="h-3.5 w-3.5" />
        </span>
      )}

      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{title}</p>
          <p className={cn('mt-1.5 text-2xl font-semibold tabular-nums tracking-tight', p.value)}>{value}</p>
          {subtext && <p className="mt-1 text-xs text-muted-foreground">{subtext}</p>}
          {trend && (
            <span
              className={cn(
                'mt-2 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-semibold',
                trend.isPositive ? 'bg-success/10 text-success' : 'bg-critical/10 text-critical',
              )}
            >
              <span aria-hidden>{trend.isPositive ? '↑' : '↓'}</span>
              {Math.abs(trend.value)}%
            </span>
          )}
        </div>
        <div
          className={cn(
            'flex h-8 w-8 shrink-0 items-center justify-center rounded-md',
            p.iconBg, p.iconFg,
          )}
        >
          <Icon className="h-4 w-4" />
        </div>
      </div>
    </>
  )

  const surface = cn(
    'group relative rounded-lg border border-l-2 border-border bg-card p-4 shadow-sm transition-colors duration-150',
    p.rule,
  )

  // Non-interactive: plain div surface. Interactive: <Link> with
  // cursor-pointer and a focus ring -- no hover lift, just a border tint,
  // so the drill-down affordance reads as "clickable data" rather than a
  // marketing card.
  if (interactive) {
    return (
      <Link
        to={to!}
        title={drillTooltip ?? DRILL_TOOLTIP}
        aria-label={`${title}: ${drillTooltip ?? DRILL_TOOLTIP}`}
        className={cn(
          surface,
          'block cursor-pointer hover:border-primary/40',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
        )}
      >
        {body}
      </Link>
    )
  }

  // Toggle mode: a filter tile (Alerts' Total/High/Critical, etc). The
  // selected state is a tinted border + a 1px ring in the tile's own
  // color, not the old bright ring-2 ring-{color}-500 glow -- enough to
  // read as "this filter is active" without the page reading as a
  // marketing dashboard.
  if (toggleable) {
    return (
      <button
        type="button"
        onClick={onClick}
        aria-pressed={!!active}
        className={cn(
          surface,
          'block w-full text-left cursor-pointer hover:border-primary/40',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
          active && p.activeRing,
        )}
      >
        {body}
      </button>
    )
  }

  return <div className={surface}>{body}</div>
}
