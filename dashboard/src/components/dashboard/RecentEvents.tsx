import { AlertCircle, Ban, CheckCircle, Clock } from 'lucide-react'
import { formatTimeIST } from '@/lib/utils'

interface Event {
  id: string
  timestamp: string
  severity: string
  description: string
  blocked: boolean
}

interface RecentEventsProps {
  events: Event[]
}

const severityColors = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
}

export default function RecentEvents({ events }: RecentEventsProps) {
  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Recent Events</h2>

      <div className="space-y-4">
        {events.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <AlertCircle className="w-12 h-12 mx-auto mb-3 text-gray-400" />
            <p>No recent events</p>
          </div>
        ) : (
          events.map((event) => (
            <div
              key={event.id}
              className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-all"
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 rounded-md text-xs font-medium border ${severityColors[event.severity as keyof typeof severityColors] || severityColors.low}`}>
                    {event.severity.toUpperCase()}
                  </span>
                  {event.blocked ? (
                    <span className="flex items-center gap-1 px-2 py-1 bg-red-50 text-red-700 rounded-md text-xs font-medium">
                      <Ban className="w-3 h-3" />
                      Blocked
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 px-2 py-1 bg-green-50 text-green-700 rounded-md text-xs font-medium">
                      <CheckCircle className="w-3 h-3" />
                      Allowed
                    </span>
                  )}
                </div>
                <span className="flex items-center gap-1 text-xs text-gray-500">
                  <Clock className="w-3 h-3" />
                  {formatTimeIST(event.timestamp)}
                </span>
              </div>
              <p className="text-sm text-gray-700">{event.description}</p>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
