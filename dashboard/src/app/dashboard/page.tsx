'use client'

import { useQuery } from '@tanstack/react-query'
import DashboardLayout from '@/components/layout/DashboardLayout'
import StatsCard from '@/components/dashboard/StatsCard'
import EventsTimeline from '@/components/dashboard/EventsTimeline'
import RecentEvents from '@/components/dashboard/RecentEvents'
import TopViolations from '@/components/dashboard/TopViolations'
import TopUsers from '@/components/dashboard/TopUsers'
import { api } from '@/lib/api'
import { Shield, AlertTriangle, Ban, FileCheck } from 'lucide-react'

export default function DashboardPage() {
  const { data: overview, isLoading } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: api.getDashboardOverview,
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  if (isLoading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-96">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
        </div>
      </DashboardLayout>
    )
  }

  const metrics = overview?.metrics || {}

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-600 mt-2">Real-time data loss prevention monitoring</p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatsCard
            title="Total Events (24h)"
            value={metrics.events_24h?.toLocaleString() || '0'}
            change="+12%"
            icon={Shield}
            color="blue"
          />
          <StatsCard
            title="Blocked Events (24h)"
            value={metrics.blocked_24h?.toLocaleString() || '0'}
            change="+8%"
            icon={Ban}
            color="red"
          />
          <StatsCard
            title="Critical Alerts (24h)"
            value={metrics.critical_24h?.toLocaleString() || '0'}
            change="-5%"
            icon={AlertTriangle}
            color="yellow"
          />
          <StatsCard
            title="Active Policies"
            value={metrics.active_policies?.toLocaleString() || '0'}
            change="0%"
            icon={FileCheck}
            color="green"
          />
        </div>

        {/* Timeline Chart */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Events Timeline</h2>
          <EventsTimeline />
        </div>

        {/* Three Column Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <RecentEvents events={overview?.recent_events || []} />
          </div>
          <div className="space-y-6">
            <TopViolations violations={overview?.top_violations || []} />
            <TopUsers users={overview?.top_users || []} />
          </div>
        </div>
      </div>
    </DashboardLayout>
  )
}
/* build 1775198805 */
