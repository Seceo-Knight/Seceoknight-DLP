import { User } from 'lucide-react'

interface TopUser {
  email: string
  event_count: number
}

interface TopUsersProps {
  users: TopUser[]
}

export default function TopUsers({ users }: TopUsersProps) {
  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Top Users</h2>

      <div className="space-y-3">
        {users.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <User className="w-10 h-10 mx-auto mb-2 text-gray-400" />
            <p className="text-sm">No data available</p>
          </div>
        ) : (
          users.map((user, index) => (
            <div
              key={index}
              className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
            >
              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center text-white font-semibold flex-shrink-0">
                {user.email[0]?.toUpperCase() || 'U'}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 truncate">{user.email}</p>
                <p className="text-xs text-gray-500">{user.event_count} events</p>
              </div>
              <div className="text-xs font-semibold text-blue-600">
                #{index + 1}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
