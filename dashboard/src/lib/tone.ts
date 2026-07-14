/**
 * Shared "tone" helper — maps a semantic colour name onto the dark-theme
 * design-token palette (or a literal Tailwind colour at low opacity for
 * tones that don't have a dedicated CSS variable, e.g. purple). Used
 * across pages so every status/severity badge in the app reads
 * consistently instead of each page inventing its own light-mode
 * (bg-red-100 text-red-700 …) classes that wash out on a dark surface.
 */
export type Tone = 'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'purple' | 'indigo' | 'gray'

export function tone(t: Tone): string {
  switch (t) {
    case 'red':    return 'bg-critical/15 border-critical/30 text-critical'
    case 'orange': return 'bg-warning/15 border-warning/30 text-warning'
    case 'yellow': return 'bg-warning/10 border-warning/25 text-warning'
    case 'green':  return 'bg-success/15 border-success/30 text-success'
    case 'blue':   return 'bg-info/15 border-info/30 text-info'
    case 'purple': return 'bg-violet-500/15 border-violet-500/30 text-violet-400'
    case 'indigo': return 'bg-primary/15 border-primary/30 text-primary'
    case 'gray':
    default:       return 'bg-secondary border-border text-muted-foreground'
  }
}

/** Shared surface classes for boxed sub-sections inside detail panels/modals. */
export const surfaceBox = 'bg-muted/30 rounded-xl p-6 border border-border'
export const innerBox = 'bg-card rounded-lg p-4 border border-border'
export const labelCls = 'text-xs text-muted-foreground uppercase font-medium mb-1 block'
