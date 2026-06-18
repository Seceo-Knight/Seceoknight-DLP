import React from 'react'

import { CHART_COLORS, RECHARTS_CONFIG } from '../../styles/charts'

interface CustomTooltipPayloadEntry {
  name?: string | number
  value?: number | string
  color?: string
  dataKey?: string | number
  payload?: Record<string, any>
}

interface CustomTooltipProps {
  active?: boolean
  payload?: CustomTooltipPayloadEntry[]
  label?: string | number
  labelFormatter?: (label: any) => React.ReactNode
}

const CustomTooltip: React.FC<CustomTooltipProps> = ({
  active,
  payload,
  label,
  labelFormatter,
}) => {
  if (!active || !payload || payload.length === 0) return null

  return (
    <div
      style={{
        backgroundColor: RECHARTS_CONFIG.tooltipBackground,
        border: `0.5px solid ${RECHARTS_CONFIG.tooltipBorder}`,
        borderRadius: RECHARTS_CONFIG.tooltipBorderRadius,
        padding: RECHARTS_CONFIG.tooltipPadding,
        boxShadow: 'none',
        color: RECHARTS_CONFIG.tooltipTextColor,
      }}
    >
      {label !== undefined && (
        <p
          style={{
            color: CHART_COLORS.text.secondary,
            fontSize: 12,
            margin: '0 0 8px 0',
            fontWeight: 500,
          }}
        >
          {labelFormatter ? labelFormatter(label) : label}
        </p>
      )}

      {payload.map((entry, index) => (
        <p
          key={`tooltip-item-${index}`}
          style={{
            color: CHART_COLORS.text.primary,
            fontSize: 12,
            margin: '4px 0',
            lineHeight: '1.4',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <span
            style={{
              display: 'inline-block',
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: entry.color || CHART_COLORS.primary,
              marginRight: 8,
              flexShrink: 0,
            }}
          />
          <span style={{ color: CHART_COLORS.text.secondary, marginRight: 6 }}>
            {entry.name ?? entry.dataKey}:
          </span>
          <span style={{ fontWeight: 600 }}>
            {typeof entry.value === 'number'
              ? entry.value.toLocaleString()
              : entry.value}
          </span>
        </p>
      ))}
    </div>
  )
}

export default CustomTooltip
