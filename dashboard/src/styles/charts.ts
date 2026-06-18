// Obsidian Vault theme tokens for Recharts. Hex values mirror the
// CSS variables defined in dashboard/src/styles/obsidian-vault.css —
// keep both in sync if the palette is ever retuned.

export const CHART_COLORS = {
  primary: '#5B7EFF',
  secondary: '#2DD4BF',
  success: '#2DD4BF',
  warning: '#FB923C',
  critical: '#F87171',
  info: '#5B7EFF',

  palette: [
    '#5B7EFF',
    '#2DD4BF',
    '#FB923C',
    '#F87171',
    '#7B9EFF',
    '#34D399',
    '#FBBF24',
    '#60A5FA',
  ],

  backgrounds: {
    dark: '#0A0A0D',
    surface: '#111118',
    tertiary: '#1E1E2E',
  },

  text: {
    primary: '#E8E8F0',
    secondary: '#A0A0B8',
    tertiary: '#606080',
  },

  line: {
    stroke: '#5B7EFF',
    fill: 'rgba(91, 126, 255, 0.1)',
    dot: '#5B7EFF',
  },

  bar: {
    primary: '#5B7EFF',
    hover: '#7B9EFF',
  },

  pie: {
    colors: ['#5B7EFF', '#2DD4BF', '#FB923C', '#F87171', '#7B9EFF'],
  },
} as const

export const RECHARTS_CONFIG = {
  gridStroke: '#1E1E2E',
  gridOpacity: 0.5,

  axisStroke: '#1E1E2E',
  axisTickFill: '#A0A0B8',
  axisLabelFill: '#A0A0B8',
  axisTickFontSize: 12,

  tooltipBackground: '#111118',
  tooltipBorder: '#1E1E2E',
  tooltipTextColor: '#E8E8F0',
  tooltipPadding: 12,
  tooltipBorderRadius: 6,

  cursorStroke: '#5B7EFF',
  cursorOpacity: 0.5,

  legendTextColor: '#A0A0B8',
  legendFontSize: 12,
} as const

export const tooltipContentStyle = {
  backgroundColor: RECHARTS_CONFIG.tooltipBackground,
  border: `0.5px solid ${RECHARTS_CONFIG.tooltipBorder}`,
  borderRadius: RECHARTS_CONFIG.tooltipBorderRadius,
  padding: RECHARTS_CONFIG.tooltipPadding,
  boxShadow: 'none',
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
