import { useEffect, useState } from 'react'
import { Command } from 'cmdk'
import { useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import { useVisibleNav } from '@/components/Sidebar'
import { cn } from '@/lib/utils'

/**
 * Global Cmd+K / Ctrl+K quick-navigation palette. Jumps to any page the
 * current user has permission to see — same nav list Sidebar renders,
 * so there's exactly one source of truth for "what pages exist."
 */
export function CommandMenu() {
  const [open, setOpen] = useState(false)
  const navigate = useNavigate()
  const nav = useVisibleNav()

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    document.addEventListener('keydown', down)
    return () => document.removeEventListener('keydown', down)
  }, [])

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className={cn(
          'flex h-8 w-full max-w-xs items-center gap-2 rounded-md border border-input bg-background px-3 ',
          'text-xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground'
        )}
      >
        <Search className="h-3.5 w-3.5" />
        <span className="flex-1 text-left">Search or jump to…</span>
        <kbd className="rounded border border-border bg-secondary px-1.5 py-0.5 font-mono text-[10px]">⌘K</kbd>
      </button>

      <Command.Dialog
        open={open}
        onOpenChange={setOpen}
        label="Global command menu"
        className={cn(
          'fixed left-1/2 top-[20%] z-[100] w-full max-w-lg -translate-x-1/2 overflow-hidden rounded-xl',
          'border border-border bg-popover text-popover-foreground shadow-2xl animate-in fade-in-0 zoom-in-95'
        )}
      >
        <div className="flex items-center gap-2 border-b border-border px-3">
          <Search className="h-4 w-4 text-muted-foreground" />
          <Command.Input
            placeholder="Type a page name…"
            className="h-11 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
        </div>
        <Command.List className="max-h-80 overflow-y-auto p-2">
          <Command.Empty className="py-6 text-center text-sm text-muted-foreground">No results found.</Command.Empty>
          <Command.Group heading="Navigate" className="text-xs text-muted-foreground [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5">
            {nav.map((item) => (
              <Command.Item
                key={item.to}
                onSelect={() => {
                  navigate(item.to)
                  setOpen(false)
                }}
                className={cn(
                  'flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-foreground',
                  'data-[selected=true]:bg-accent'
                )}
              >
                <item.icon className="h-4 w-4 text-muted-foreground" />
                {item.name}
              </Command.Item>
            ))}
          </Command.Group>
        </Command.List>
      </Command.Dialog>
    </>
  )
}
