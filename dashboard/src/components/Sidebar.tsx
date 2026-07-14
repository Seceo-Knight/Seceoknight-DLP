import { NavLink } from 'react-router-dom'
import logo from '@/elements/logo.png'
import {
  LayoutDashboard,
  Server,
  AlertCircle,
  FileText,
  Shield,
  Settings,
  ChevronLeft,
  ChevronRight,
  List,
  AlertTriangle,
  Search,
  BarChart2,
  UserCog,
  Radar,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { usePermission } from '@/hooks/usePermission'

// Each nav item declares the permissions that would make it relevant.
// An item is shown if the user has ANY of the listed permissions, OR if
// the list is empty (always-shown). ADMIN is implicitly granted everything
// via usePermission.hasAny.
type NavItem = {
  name: string
  to: string
  icon: typeof LayoutDashboard
  requires: string[]
  // Threat Intel's API is coarse ADMIN-only (require_role("admin")) — unlike
  // the domain-admin roles, which pass permission checks but are explicitly
  // NOT admin-tier (see core/security.py require_role). Gate on the real
  // role here instead of a permission name so domain admins don't see a
  // link that 403s.
  adminOnly?: boolean
}

const navigation: NavItem[] = [
  { name: 'Dashboard',       to: '/dashboard',     icon: LayoutDashboard, requires: ['view_dashboard'] },
  { name: 'Agents',          to: '/agents',        icon: Server,          requires: ['view_events'] },
  { name: 'Events',          to: '/events',        icon: FileText,        requires: ['view_events'] },
  { name: 'Alerts',          to: '/alerts',        icon: AlertCircle,     requires: ['view_alerts'] },
  { name: 'Incidents',       to: '/incidents',     icon: AlertTriangle,   requires: ['view_alerts'] },
  { name: 'Log Explorer',    to: '/log-explorer',  icon: Search,          requires: ['view_events'] },
  { name: 'Rules',           to: '/rules',         icon: List,            requires: ['create_policy', 'update_policy'] },
  { name: 'Policies',        to: '/policies',      icon: Shield,          requires: ['create_policy', 'update_policy'] },
  { name: 'Reports',         to: '/reports',       icon: BarChart2,       requires: ['view_events'] },
  { name: 'Threat Intel',    to: '/threat-intel',  icon: Radar,           requires: [], adminOnly: true },
  { name: 'User Management', to: '/admin/users',   icon: UserCog,         requires: ['manage_users'] },
  { name: 'Settings',        to: '/settings',      icon: Settings,        requires: [] },
]

interface SidebarProps {
  collapsed: boolean
  onToggleCollapsed: () => void
  /** When set, renders as the content of a mobile Sheet drawer instead of a fixed desktop rail. */
  variant?: 'desktop' | 'mobile'
  onNavigate?: () => void
}

export function useVisibleNav() {
  const { hasAny, isAdmin } = usePermission()
  return navigation.filter((item) => {
    if (item.adminOnly && !isAdmin) return false
    return item.requires.length === 0 || hasAny(item.requires)
  })
}

export default function Sidebar({ collapsed, onToggleCollapsed, variant = 'desktop', onNavigate }: SidebarProps) {
  const visibleNav = useVisibleNav()
  const isCollapsed = variant === 'desktop' && collapsed

  return (
    <aside
      className={cn(
        'flex h-full flex-col bg-card transition-[width] duration-200 ease-out',
        variant === 'desktop' && 'border-r border-border',
        isCollapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo */}
      <div className="flex h-16 items-center gap-2 border-b border-border px-4">
        <img src={logo} alt="SeceoKnight DLP" className="h-9 w-9 shrink-0 rounded-lg object-contain" />
        {!isCollapsed && (
          <div className="min-w-0 overflow-hidden">
            <p className="truncate text-sm font-semibold leading-tight text-foreground">SeceoKnight</p>
            <p className="truncate text-[11px] leading-tight text-muted-foreground">DLP Platform</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2.5 py-4">
        {visibleNav.map((item) => (
          <NavLink
            key={item.name}
            to={item.to}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                'group relative flex items-center gap-3 rounded-md px-2.5 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary/10 text-foreground'
                  : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                isCollapsed && 'justify-center px-0'
              )
            }
            title={isCollapsed ? item.name : undefined}
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <span className="absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r bg-primary" />
                )}
                <item.icon
                  className={cn('h-[18px] w-[18px] shrink-0', isActive ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground')}
                />
                {!isCollapsed && <span className="truncate">{item.name}</span>}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Collapse toggle — desktop only */}
      {variant === 'desktop' && (
        <button
          onClick={onToggleCollapsed}
          className="mx-2.5 mb-2 flex items-center justify-center gap-2 rounded-md px-2.5 py-2 text-xs font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        >
          {isCollapsed ? <ChevronRight className="h-4 w-4" /> : <><ChevronLeft className="h-4 w-4" /> Collapse</>}
        </button>
      )}

      {/* Footer */}
      {!isCollapsed && (
        <div className="border-t border-border px-4 py-3 text-[11px] text-muted-foreground">
          <div>Version 2.0.0</div>
          <div className="mt-0.5">© {new Date().getFullYear()} SeceoKnight DLP</div>
        </div>
      )}
    </aside>
  )
}
