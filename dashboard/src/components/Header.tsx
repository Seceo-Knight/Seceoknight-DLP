import { LogOut, Settings as SettingsIcon, ChevronDown, Menu, Bell, ShieldAlert } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '@/lib/store/auth'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { CommandMenu } from '@/components/CommandMenu'
import { getAlerts } from '@/lib/api'
import { formatRelativeTime, getSeverityColor, cn } from '@/lib/utils'

function initials(email?: string | null) {
  if (!email) return 'A'
  const name = email.split('@')[0]
  return name.slice(0, 2).toUpperCase()
}

// getAlerts() has shipped two response shapes over time (a bare array, and
// an { alerts, counts } envelope) -- see the same normalization in
// pages/Alerts.tsx. Kept in sync manually since there's no shared hook yet.
function normalizeAlerts(alertsData: unknown): any[] {
  if (!alertsData) return []
  if (Array.isArray(alertsData)) return alertsData
  if (typeof alertsData === 'object' && alertsData !== null && 'alerts' in (alertsData as any)) {
    const list = (alertsData as any).alerts
    return Array.isArray(list) ? list : []
  }
  return []
}

interface HeaderProps {
  onOpenMobileNav: () => void
}

export default function Header({ onOpenMobileNav }: HeaderProps) {
  const navigate = useNavigate()
  const { user, logout } = useAuthStore()

  const { data: alertsData } = useQuery({
    queryKey: ['alerts'],
    queryFn: getAlerts,
    refetchInterval: 30000,
  })
  const alerts = normalizeAlerts(alertsData)
  const recentAlerts = [...alerts]
    .sort((a, b) => new Date(b?.created_at ?? 0).getTime() - new Date(a?.created_at ?? 0).getTime())
    .slice(0, 5)
  const unreadCount = alerts.filter((a) => a?.status === 'new').length

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <header className="flex h-16 shrink-0 items-center gap-3 border-b border-border bg-card px-4 sm:px-6">
      <Button variant="ghost" size="icon" className="lg:hidden" onClick={onOpenMobileNav} aria-label="Open menu">
        <Menu className="h-5 w-5" />
      </Button>

      <div className="hidden flex-1 sm:flex">
        <CommandMenu />
      </div>
      <div className="flex-1 sm:hidden" />

      <div className="flex items-center gap-2">
        <span className="hidden items-center gap-1.5 rounded-full border border-success/30 bg-success/10 px-2.5 py-1 text-[11px] font-medium text-success md:flex">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-success" />
          </span>
          Live
        </span>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label="Notifications" className="relative">
              <Bell className="h-[18px] w-[18px]" />
              {unreadCount > 0 && (
                <span className="absolute right-1.5 top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-semibold leading-none text-destructive-foreground">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-80">
            <DropdownMenuLabel className="flex items-center justify-between">
              <span>Notifications</span>
              {unreadCount > 0 && (
                <span className="text-xs font-normal text-muted-foreground">{unreadCount} new</span>
              )}
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            {recentAlerts.length === 0 ? (
              <div className="px-2 py-6 text-center text-sm text-muted-foreground">
                No alerts yet
              </div>
            ) : (
              recentAlerts.map((alert) => (
                <DropdownMenuItem
                  key={alert.id}
                  onSelect={() => navigate('/alerts')}
                  className="flex items-start gap-2.5 py-2.5"
                >
                  <ShieldAlert className={cn('mt-0.5 h-4 w-4 shrink-0', getSeverityColor(alert.severity).split(' ')[0])} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-foreground">
                      {alert.title || 'Untitled alert'}
                    </p>
                    <p className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
                      <span className={cn('rounded-full px-1.5 py-0.5 text-[10px] font-medium capitalize', getSeverityColor(alert.severity))}>
                        {alert.severity || 'info'}
                      </span>
                      {alert.created_at && <span>{formatRelativeTime(alert.created_at)}</span>}
                    </p>
                  </div>
                  {alert.status === 'new' && (
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                  )}
                </DropdownMenuItem>
              ))
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => navigate('/alerts')} className="justify-center text-sm font-medium text-primary">
              View all alerts
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="gap-2 px-2">
              <Avatar className="h-7 w-7">
                <AvatarFallback className="bg-primary/15 text-primary">{initials(user?.email)}</AvatarFallback>
              </Avatar>
              <span className="hidden max-w-[10rem] truncate text-sm font-medium sm:inline">
                {user?.email || 'Admin'}
              </span>
              <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>
              <p className="truncate text-sm font-medium text-foreground">{user?.email || 'admin'}</p>
              <p className="truncate text-xs capitalize text-muted-foreground">{user?.role || 'Administrator'}</p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => navigate('/settings')}>
              <SettingsIcon className="h-4 w-4" />
              Settings
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={handleLogout} className="text-destructive focus:text-destructive">
              <LogOut className="h-4 w-4" />
              Logout
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
