import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, AlertTriangle, ShieldAlert, Search } from 'lucide-react'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import AlertDetailsModal from '@/components/alerts/AlertDetailsModal'
import { getAlerts } from '@/lib/api'
import { formatRelativeTime, getSeverityColor, cn } from '@/lib/utils'

type FilterType = 'all' | 'high' | 'critical'

export default function Alerts() {
  const [selectedAlert, setSelectedAlert] = useState<any>(null)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [filter, setFilter] = useState<FilterType>('all')
  const [searchQuery, setSearchQuery] = useState('')

  const { data: alertsData, isLoading, error, refetch } = useQuery({
    queryKey: ['alerts'],
    queryFn: getAlerts,
    refetchInterval: 10000,
  })

  const handleAlertClick = (alert: any) => {
    setSelectedAlert(alert)
    setIsModalOpen(true)
  }

  if (isLoading) {
    return <LoadingSpinner size="lg" />
  }

  if (error) {
    return <ErrorMessage message="Failed to load alerts" retry={() => refetch()} />
  }

  // Handle both old format (array) and new format (object with alerts and counts)
  let alerts: any[] = []
  let counts: Record<string, number> = {}
  
  if (!alertsData) {
    // No data - use empty arrays
    alerts = []
  } else if (Array.isArray(alertsData)) {
    // Old format: direct array
    alerts = alertsData
  } else if (typeof alertsData === 'object' && alertsData !== null) {
    // New format: object with alerts and counts
    if ('alerts' in alertsData && Array.isArray(alertsData.alerts)) {
      alerts = alertsData.alerts
    }
    if ('counts' in alertsData && typeof alertsData.counts === 'object' && alertsData.counts !== null) {
      counts = alertsData.counts
    }
  }
  
  // Ensure alerts is always an array
  if (!Array.isArray(alerts)) {
    alerts = []
  }
  
  // Calculate alert counts by type
  const totalAlertsCount = typeof counts.total === 'number' ? counts.total : alerts.length
  const highAlertsCount = alerts.filter((a) => a && a.severity === 'high').length
  const criticalAlertsCount = alerts.filter((a) => a && a.severity === 'critical').length

  // Filter and search alerts
  const filteredAlerts = alerts.filter((alert) => {
    // Apply severity filter
    if (filter === 'high' && alert.severity !== 'high') return false
    if (filter === 'critical' && alert.severity !== 'critical') return false

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        alert.title?.toLowerCase().includes(query) ||
        alert.description?.toLowerCase().includes(query) ||
        alert.agent_id?.toLowerCase().includes(query) ||
        alert.event_id?.toLowerCase().includes(query) ||
        alert.severity?.toLowerCase().includes(query)
      )
    }

    return true
  })

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
        <p className="mt-1 text-sm text-gray-600">
          Manage security alerts from DLP policies
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div
          className={`card cursor-pointer hover:shadow-lg transition-shadow ${filter === 'all' ? 'ring-2 ring-blue-500' : ''}`}
          onClick={() => setFilter('all')}
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <ShieldAlert className="h-5 w-5 text-blue-600" />
            </div>
            <div>
              <p className="text-sm text-gray-600">Total Alerts</p>
              <p className="text-2xl font-bold text-blue-600">{totalAlertsCount}</p>
            </div>
          </div>
        </div>

        <div
          className={`card cursor-pointer hover:shadow-lg transition-shadow ${filter === 'high' ? 'ring-2 ring-orange-500' : ''}`}
          onClick={() => setFilter('high')}
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-100 rounded-lg">
              <AlertTriangle className="h-5 w-5 text-orange-600" />
            </div>
            <div>
              <p className="text-sm text-gray-600">High Alerts</p>
              <p className="text-2xl font-bold text-orange-600">
                {highAlertsCount}
              </p>
            </div>
          </div>
        </div>

        <div
          className={`card cursor-pointer hover:shadow-lg transition-shadow ${filter === 'critical' ? 'ring-2 ring-red-500' : ''}`}
          onClick={() => setFilter('critical')}
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-100 rounded-lg">
              <AlertCircle className="h-5 w-5 text-red-600" />
            </div>
            <div>
              <p className="text-sm text-gray-600">Critical Alerts</p>
              <p className="text-2xl font-bold text-red-600">
                {criticalAlertsCount}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Search Bar */}
      <div className="card">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search alerts by title, description, agent ID, severity..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>
      </div>

      {/* Alerts List */}
      <div className="card p-0">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="font-semibold text-gray-900">
            {filter === 'all' ? 'All Alerts' : filter === 'high' ? 'High Severity Alerts' : 'Critical Severity Alerts'}
            {searchQuery && ` - Search: "${searchQuery}"`}
          </h3>
        </div>

        <div className="divide-y divide-gray-200">
          {!filteredAlerts || filteredAlerts.length === 0 ? (
            <div className="p-12 text-center">
              <AlertCircle className="h-12 w-12 text-gray-400 mx-auto mb-3" />
              <p className="text-gray-600 font-medium">
                {searchQuery ? 'No alerts found' : filter === 'all' ? 'No alerts' : `No ${filter} severity alerts`}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                {searchQuery
                  ? 'Try adjusting your search query'
                  : filter === 'all'
                  ? 'Alerts will appear here when policies trigger'
                  : 'Click "Total Alerts" to see all alerts'
                }
              </p>
            </div>
          ) : (
            filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                className="p-4 hover:bg-gray-50 cursor-pointer transition-colors"
                onClick={() => handleAlertClick(alert)}
              >
                <div className="flex items-start gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span
                        className={cn('badge', getSeverityColor(alert.severity))}
                      >
                        {alert.severity}
                      </span>
                      {alert.status === 'new' && (
                        <span className="badge badge-danger">New</span>
                      )}
                      {alert.status === 'acknowledged' && (
                        <span className="badge badge-warning">Acknowledged</span>
                      )}
                      {alert.status === 'resolved' && (
                        <span className="badge badge-success">Resolved</span>
                      )}
                    </div>

                    <h4 className="font-medium text-gray-900">{alert.title}</h4>
                    <p className="mt-1 text-sm text-gray-600">
                      {alert.description}
                    </p>

                    <div className="mt-2 flex items-center gap-3 text-xs text-gray-500">
                      <span>Agent: {alert.agent_id}</span>
                      <span>•</span>
                      <span>{formatRelativeTime(alert.created_at)}</span>
                      <span>•</span>
                      <code className="bg-gray-100 px-1 py-0.5 rounded">
                        {alert.event_id}
                      </code>
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Alert Details Modal */}
      <AlertDetailsModal
        alert={selectedAlert}
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false)
          setSelectedAlert(null)
        }}
      />
    </div>
  )
}
