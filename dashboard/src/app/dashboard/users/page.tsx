'use client'

import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import DashboardLayout from '@/components/layout/DashboardLayout'
import { Users as UsersIcon, User, Shield, AlertTriangle, Loader2 } from 'lucide-react'

export default function UsersPage() {
  // Fetch users from API
  const { data: users = [], isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.getUsers(),
    refetchInterval: 30000,
  })

  // Fetch user stats
  const { data: userStats } = useQuery({
    queryKey: ['user-stats'],
    queryFn: () => api.getUserStats(),
    refetchInterval: 30000,
  })

  const stats = {
    total: userStats?.total_users || users.length || 0,
    highRisk: userStats?.high_risk || users.filter((u: any) => u.risk_score === 'high').length || 0,
    mediumRisk: userStats?.medium_risk || users.filter((u: any) => u.risk_score === 'medium').length || 0,
    violations: userStats?.total_violations || users.reduce((sum: number, u: any) => sum + (u.violations || 0), 0) || 0,
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'high': return 'text-red-400 bg-red-900/30 border-red-500/50'
      case 'medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/50'
      case 'low': return 'text-green-400 bg-green-900/30 border-green-500/50'
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500/50'
    }
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Users</h1>
          <p className="text-gray-400 mt-2">Monitor user activity and risk scores</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Users</p>
                <p className="text-3xl font-bold text-white mt-2">{stats.total}</p>
              </div>
              <UsersIcon className="w-12 h-12 text-indigo-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">High Risk</p>
                <p className="text-3xl font-bold text-red-400 mt-2">{stats.highRisk}</p>
              </div>
              <AlertTriangle className="w-12 h-12 text-red-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Medium Risk</p>
                <p className="text-3xl font-bold text-yellow-400 mt-2">{stats.mediumRisk}</p>
              </div>
              <Shield className="w-12 h-12 text-yellow-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-6 border border-gray-700/50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Violations</p>
                <p className="text-3xl font-bold text-red-400 mt-2">{stats.violations}</p>
              </div>
              <AlertTriangle className="w-12 h-12 text-red-400" />
            </div>
          </div>
        </div>

        <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 overflow-hidden">
          <div className="p-6 border-b border-gray-700">
            <h2 className="text-xl font-semibold text-white">User List</h2>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center p-12">
              <Loader2 className="w-8 h-8 text-indigo-400 animate-spin" />
            </div>
          ) : users.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-12">
              <UsersIcon className="w-16 h-16 text-gray-600 mb-4" />
              <h3 className="text-lg font-semibold text-white mb-2">No Users Found</h3>
              <p className="text-gray-400 text-center max-w-md">
                No users are being monitored yet. Deploy agents to start tracking user activity.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-900/50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Name</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Email</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Department</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Role</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Violations</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Risk Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {users.map((user: any) => (
                    <tr key={user.user_id || user.id} className="hover:bg-gray-700/30 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 via-purple-500 to-pink-500 rounded-full flex items-center justify-center text-white font-semibold">
                            {(user.name || user.email || 'U')[0].toUpperCase()}
                          </div>
                          <span className="text-white font-medium">{user.name || user.email}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-300">{user.email}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-300">{user.department || 'N/A'}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-300">{user.role || 'User'}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`font-bold ${
                          (user.violations || 0) > 5 ? 'text-red-400' :
                          (user.violations || 0) > 2 ? 'text-yellow-400' :
                          'text-gray-400'
                        }`}>
                          {user.violations || 0}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-lg border text-xs font-medium uppercase ${getRiskColor(user.risk_score || 'low')}`}>
                          {user.risk_score || 'low'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  )
}
