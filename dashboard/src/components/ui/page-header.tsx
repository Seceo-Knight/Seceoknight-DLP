import * as React from 'react'
import { cn } from '@/lib/utils'

interface PageHeaderProps {
  title: string
  description?: string
  actions?: React.ReactNode
  icon?: React.ComponentType<{ className?: string }>
  /** Small caps-style label above the title, e.g. "Device Control". */
  eyebrow?: string
  /** Status chip rendered inline next to the title, e.g. an enforcement badge. */
  badge?: React.ReactNode
  className?: string
}

/** Consistent title/description/actions row used at the top of every page. */
export function PageHeader({ title, description, actions, icon: Icon, eyebrow, badge, className }: PageHeaderProps) {
  return (
    <div className={cn('flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between', className)}>
      <div className="flex items-start gap-3">
        {Icon && (
          <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10">
            <Icon className="h-[18px] w-[18px] text-primary" />
          </div>
        )}
        <div>
          {eyebrow && <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-primary">{eyebrow}</p>}
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-semibold tracking-tight text-foreground">{title}</h1>
            {badge}
          </div>
          {description && <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex flex-shrink-0 items-center gap-2">{actions}</div>}
    </div>
  )
}
