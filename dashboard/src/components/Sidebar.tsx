import { useState } from 'react'
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
  ClipboardList,
  UserCog,
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
}

const navigation: NavItem[] = [
  { name: 'Dashboard',        to: '/dashboard',     icon: LayoutDashboard, requires: ['view_dashboard'] },
  { name: 'Agents',       to: '/agents',       icon: Server,          requires: ['view_events'] },
  { name: 'Events',       to: '/events',       icon: FileText,        requires: ['view_events'] },
  { name: 'Alerts',       to: '/alerts',       icon: AlertCircle,     requires: ['view_alerts'] },
  { name: 'Incidents',    to: '/incidents',    icon: AlertTriangle,   requires: ['view_alerts'] },
  { name: 'Log Explorer', to: '/log-explorer', icon: Search,          requires: ['view_events'] },
  { name: 'Rules',        to: '/rules',        icon: List,            requires: ['create_policy', 'update_policy'] },
  { name: 'Policies',        to: '/policies',     icon: Shield,     requires: ['create_policy', 'update_policy'] },
  { name: 'User Management', to: '/admin/users',  icon: UserCog,    requires: ['manage_users'] },
  { name: 'Settings',        to: '/settings',     icon: Settings,   requires: ['manage_users', 'manage_roles'] },
]

export default function Sidebar() {
  const [isCollapsed, setIsCollapsed] = useState(false)
  const { hasAny } = usePermission()
  const visibleNav = navigation.filter(
    (item) => item.requires.length === 0 || hasAny(item.requires),
  )

  return (
    <aside className={cn(
      "bg-[#1a1d1f] text-white flex flex-col transition-all duration-300",
      isCollapsed ? "w-16" : "w-64"
    )}>
      {/* Logo */}
      <div className="h-16 flex items-center justify-between px-3 border-b border-gray-800">
        <div className="flex items-center overflow-hidden">
          <img
            src={logo}
            alt="CyberSentinel-DLP Logo"
            className="h-12 w-12 object-contain flex-shrink-0"
          />
          {!isCollapsed && (
            <span className="ml-1 text-xl font-semibold whitespace-nowrap">CyberSentinel-DLP</span>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-6 space-y-1 overflow-y-auto">
        {visibleNav.map((item) => (
          <NavLink
            key={item.name}
            to={item.to}
            className={({ isActive }) =>
              cn(
                'flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-200',
                isActive
                  ? 'bg-primary-600 text-white'
                  : 'text-gray-300 hover:bg-[#2a2d2f] hover:text-white',
                isCollapsed && 'justify-center'
              )
            }
            title={isCollapsed ? item.name : undefined}
          >
            <item.icon className={cn("h-5 w-5", !isCollapsed && "mr-3")} />
            {!isCollapsed && item.name}
          </NavLink>
        ))}
      </nav>

      {/* Toggle Button */}
      <button
        onClick={() => setIsCollapsed(!isCollapsed)}
        className="mx-3 mb-3 p-2 hover:bg-[#2a2d2f] rounded-lg transition-colors flex items-center justify-center"
        title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {isCollapsed ? (
          <ChevronRight className="h-5 w-5" />
        ) : (
          <ChevronLeft className="h-5 w-5" />
        )}
      </button>

      {/* Footer */}
      {!isCollapsed && (
        <div className="px-6 py-4 border-t border-gray-800 text-xs text-gray-400">
          <div>Version 2.0.0</div>
          <div className="mt-1">© 2025 CyberSentinel DLP</div>
        </div>
      )}
    </aside>
  )
}
