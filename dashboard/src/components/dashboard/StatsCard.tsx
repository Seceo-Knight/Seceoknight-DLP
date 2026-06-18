import { LucideIcon } from 'lucide-react'

interface StatsCardProps {
  title: string
  value: string
  change: string
  icon: LucideIcon
  color: 'blue' | 'red' | 'green' | 'yellow'
}

const colorClasses = {
  blue: {
    bg: 'bg-blue-50',
    icon: 'bg-blue-500',
    text: 'text-blue-700',
    border: 'border-blue-200'
  },
  red: {
    bg: 'bg-red-50',
    icon: 'bg-red-500',
    text: 'text-red-700',
    border: 'border-red-200'
  },
  green: {
    bg: 'bg-green-50',
    icon: 'bg-green-500',
    text: 'text-green-700',
    border: 'border-green-200'
  },
  yellow: {
    bg: 'bg-yellow-50',
    icon: 'bg-yellow-500',
    text: 'text-yellow-700',
    border: 'border-yellow-200'
  }
}

export default function StatsCard({ title, value, change, icon: Icon, color }: StatsCardProps) {
  const colors = colorClasses[color]
  const isPositive = change.startsWith('+')
  const isNegative = change.startsWith('-')

  return (
    <div className={`${colors.bg} border ${colors.border} rounded-lg p-6 transition-all hover:shadow-md`}>
      <div className="flex items-center justify-between mb-4">
        <div className={`${colors.icon} w-12 h-12 rounded-lg flex items-center justify-center`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
        <span className={`text-sm font-medium ${isPositive ? 'text-green-600' : isNegative ? 'text-red-600' : 'text-gray-600'}`}>
          {change}
        </span>
      </div>
      <h3 className="text-gray-600 text-sm font-medium mb-1">{title}</h3>
      <p className={`text-3xl font-bold ${colors.text}`}>{value}</p>
    </div>
  )
}
