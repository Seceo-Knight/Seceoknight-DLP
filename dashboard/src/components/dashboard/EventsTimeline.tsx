'use client'

import { useQuery } from '@tanstack/react-query'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { api } from '@/lib/api'
import { CHART_COLORS, RECHARTS_CONFIG, tickStyle } from '@/styles/charts'
import CustomTooltip from '@/components/charts/CustomTooltip'

// IST timezone
const IST_TIMEZONE = 'Asia/Kolkata'

// Helper to format time in IST
const formatTimeIST = (date: Date) => {
  return new Intl.DateTimeFormat('en-IN', {
    timeZone: IST_TIMEZONE,
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  }).format(date)
}

export default function EventsTimeline() {
  const { data, isLoading } = useQuery({
    queryKey: ['event-timeline'],
    queryFn: () => api.getEventTimeline(24),
    refetchInterval: 60000, // Refresh every minute
  })

  if (isLoading) {
    return (
      <div className="h-80 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  const chartData = data?.timeline || []

  return (
    <ResponsiveContainer width="100%" height={320}>
      <LineChart data={chartData}>
        <CartesianGrid
          strokeDasharray="3 3"
          stroke={RECHARTS_CONFIG.gridStroke}
          opacity={RECHARTS_CONFIG.gridOpacity}
        />
        <XAxis
          dataKey="timestamp"
          stroke={RECHARTS_CONFIG.axisStroke}
          tick={tickStyle}
          tickFormatter={(value) => {
            return formatTimeIST(new Date(value))
          }}
        />
        <YAxis stroke={RECHARTS_CONFIG.axisStroke} tick={tickStyle} />
        <Tooltip
          content={<CustomTooltip />}
          cursor={{ stroke: RECHARTS_CONFIG.cursorStroke, opacity: RECHARTS_CONFIG.cursorOpacity }}
        />
        <Legend wrapperStyle={{ color: RECHARTS_CONFIG.legendTextColor }} />
        <Line
          type="monotone"
          dataKey="total_events"
          stroke={CHART_COLORS.primary}
          strokeWidth={2}
          name="Total Events"
          dot={false}
        />
        <Line
          type="monotone"
          dataKey="blocked_events"
          stroke={CHART_COLORS.critical}
          strokeWidth={2}
          name="Blocked"
          dot={false}
        />
        <Line
          type="monotone"
          dataKey="critical_events"
          stroke={CHART_COLORS.warning}
          strokeWidth={2}
          name="Critical"
          dot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}
