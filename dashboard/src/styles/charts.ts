// Light enterprise theme tokens for Recharts (Microsoft Purview / Azure
// Portal style, September 2026 redesign). Hex values mirror the CSS
// variables defined in dashboard/src/styles/obsidian-vault.css and
// dashboard/src/index.css — keep all three in sync if the palette is
// ever retuned.

export const CHART_COLORS = {
  primary: '#2563EB',
  secondary: '#16A34A',
  success: '#16A34A',
  warning: '#D97706',
  critical: '#DC2626',
  info: '#2563EB',

  palette: [
    '#2563EB',
    '#16A34A',
    '#D97706',
    '#DC2626',
    '#7C3AED',
    '#0891B2',
    '#DB2777',
    '#65A30D',
  ],

  backgrounds: {
    dark: '#F8F9FA',
    surface: '#FFFFFF',
    tertiary: '#F1F3F5',
  },

  text: {
    primary: '#1F2328',
    secondary: '#57606A',
    tertiary: '#6E7781',
  },

  line: {
    stroke: '#2563EB',
    fill: 'rgba(37, 99, 235, 0.08)',
    dot: '#2563EB',
  },

  bar: {
    primary: '#2563EB',
    hover: '#3B82F6',
  },

  pie: {
    colors: ['#2563EB', '#16A34A', '#D97706', '#DC2626', '#7C3AED'],
  },
} as const

export const RECHARTS_CONFIG = {
  gridStroke: '#E1E4E8',
  gridOpacity: 0.8,

  axisStroke: '#E1E4E8',
  axisTickFill: '#57606A',
  axisLabelFill: '#57606A',
  axisTickFontSize: 12,

  tooltipBackground: '#FFFFFF',
  tooltipBorder: '#E1E4E8',
  tooltipTextColor: '#1F2328',
  tooltipPadding: 12,
  tooltipBorderRadius: 6,

  cursorStroke: '#2563EB',
  cursorOpacity: 0.15,

  legendTextColor: '#57606A',
  legendFontSize: 12,
} as const

export const tooltipContentStyle = {
  backgroundColor: RECHARTS_CONFIG.tooltipBackground,
  border: `0.5px solid ${RECHARTS_CONFIG.tooltipBorder}`,
  borderRadius: RECHARTS_CONFIG.tooltipBorderRadius,
  padding: RECHARTS_CONFIG.tooltipPadding,
  boxShadow: '0 4px 12px -2px rgb(0 0 0 / 0.1)',
  color: RECHARTS_CONFIG.tooltipTextColor,
}

export const tickStyle = {
  fill: RECHARTS_CONFIG.axisTickFill,
  fontSize: RECHARTS_CONFIG.axisTickFontSize,
}

export const labelStyle = {
  fill: RECHARTS_CONFIG.axisLabelFill,
  fontSize: RECHARTS_CONFIG.axisTickFontSize,
  fontWeight: 500,
}
