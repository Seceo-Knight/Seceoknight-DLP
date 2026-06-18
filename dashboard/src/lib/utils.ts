import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { format, formatDistanceToNow } from 'date-fns'

// IST timezone
const IST_TIMEZONE = 'Asia/Kolkata'

/**
 * Utility function to merge Tailwind CSS classes
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Get IST date components using Intl.DateTimeFormat
 */
function getISTComponents(date: Date) {
  const formatter = new Intl.DateTimeFormat('en-IN', {
    timeZone: IST_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  })
  
  const parts = formatter.formatToParts(date)
  const result: Record<string, string> = {}
  parts.forEach(part => {
    result[part.type] = part.value
  })
  return result
}

/**
 * Parse date string as UTC (handles both with and without timezone)
 */
function parseAsUTC(date: string | Date): Date {
  if (date instanceof Date) return date
  
  // If string doesn't end with Z or timezone offset, assume it's UTC
  const dateStr = date.trim()
  if (!dateStr.includes('Z') && !dateStr.match(/[+-]\d{2}:\d{2}$/)) {
    // No timezone info - append Z to treat as UTC
    return new Date(dateStr.endsWith('Z') ? dateStr : dateStr + 'Z')
  }
  
  return new Date(dateStr)
}

/**
 * Render an agent reference as "NAME (NNN)" for the UI.
 *
 * Resolution order: server-enriched name → caller-provided fallback name
 * (e.g. the local agentMap lookup) → "Unknown Agent". The agent_code is
 * zero-padded to three digits to match the Agents page convention. The
 * raw ``agent_id`` UUID is intentionally not surfaced here — callers
 * that want it visible should pass it via ``title=`` on the rendered
 * element.
 */
export function formatAgentLabel(
  name?: string | null,
  code?: number | null,
  fallbackName?: string | null,
): string {
  const resolvedName = name || fallbackName
  if (!resolvedName) return 'Unknown Agent'
  if (typeof code === 'number') {
    return `${resolvedName} (${String(code).padStart(3, '0')})`
  }
  return resolvedName
}

/**
 * Format date to human-readable string in IST
 */
export function formatDate(date: string | Date, formatStr = 'PPpp'): string {
  if (!date) return 'Never'
  try {
    const d = parseAsUTC(date)
    if (isNaN(d.getTime())) return 'Invalid date'
    
    // Use Intl.DateTimeFormat to get IST representation
    const formatter = new Intl.DateTimeFormat('en-IN', {
      timeZone: IST_TIMEZONE,
      dateStyle: 'long',
      timeStyle: 'long'
    })
    return formatter.format(d)
  } catch (error) {
    return 'Invalid date'
  }
}

/**
 * Format date as relative time (e.g., "2 hours ago") - calculated from IST
 */
export function formatRelativeTime(date: string | Date | null | undefined): string {
  if (!date) return 'Never'
  try {
    const d = parseAsUTC(date)
    if (isNaN(d.getTime())) return 'Invalid date'
    // Calculate relative time - date-fns works with Date objects correctly
    return formatDistanceToNow(d, { addSuffix: true })
  } catch (error) {
    return 'Invalid date'
  }
}

/**
 * Format time in IST (for time-only displays)
 */
export function formatTimeIST(date: string | Date): string {
  if (!date) return 'Never'
  try {
    const d = parseAsUTC(date)
    if (isNaN(d.getTime())) return 'Invalid date'
    
    const formatter = new Intl.DateTimeFormat('en-IN', {
      timeZone: IST_TIMEZONE,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    })
    return formatter.format(d)
  } catch (error) {
    return 'Invalid date'
  }
}

/**
 * Format date and time in IST (for toLocaleString replacement)
 */
export function formatDateTimeIST(date: string | Date): string {
  if (!date) return 'Never'
  try {
    const d = parseAsUTC(date)
    if (isNaN(d.getTime())) return 'Invalid date'
    
    const formatter = new Intl.DateTimeFormat('en-IN', {
      timeZone: IST_TIMEZONE,
      dateStyle: 'long',
      timeStyle: 'long'
    })
    return formatter.format(d)
  } catch (error) {
    return 'Invalid date'
  }
}

/**
 * Format bytes to human-readable size
 */
export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 Bytes'

  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']

  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]
}

/**
 * Get severity color
 */
export function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'text-red-600 bg-red-100'
    case 'high':
      return 'text-orange-600 bg-orange-100'
    case 'medium':
      return 'text-yellow-600 bg-yellow-100'
    case 'low':
      return 'text-blue-600 bg-blue-100'
    default:
      return 'text-gray-600 bg-gray-100'
  }
}

/**
 * Get status color
 */
export function getStatusColor(status: string): string {
  switch (status) {
    case 'active':
      return 'text-green-600 bg-green-100'
    case 'inactive':
      return 'text-gray-600 bg-gray-100'
    case 'pending':
      return 'text-yellow-600 bg-yellow-100'
    case 'suspended':
      return 'text-red-600 bg-red-100'
    default:
      return 'text-gray-600 bg-gray-100'
  }
}

/**
 * Truncate string
 */
export function truncate(str: string, length: number): string {
  if (str.length <= length) return str
  return str.substring(0, length) + '...'
}

/**
 * Copy to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch (err) {
    console.error('Failed to copy:', err)
    return false
  }
}

/**
 * Parse KQL query
 */
export function parseKQL(query: string): {
  field?: string
  operator?: string
  value?: string
  valid: boolean
} {
  // Simple KQL parsing (field:value or field operator value)
  const colonMatch = query.match(/^(\w+(?:\.\w+)*):(.+)$/)
  if (colonMatch) {
    return {
      field: colonMatch[1],
      operator: ':',
      value: colonMatch[2],
      valid: true,
    }
  }

  const operatorMatch = query.match(/^(\w+(?:\.\w+)*)\s*(>=|<=|>|<|=)\s*(.+)$/)
  if (operatorMatch) {
    return {
      field: operatorMatch[1],
      operator: operatorMatch[2],
      value: operatorMatch[3],
      valid: true,
    }
  }

  return { valid: false }
}

/**
 * Highlight text matches
 */
export function highlightText(
  text: string,
  search: string
): { text: string; isMatch: boolean }[] {
  if (!search) return [{ text, isMatch: false }]

  const parts: { text: string; isMatch: boolean }[] = []
  const regex = new RegExp(`(${search})`, 'gi')
  const matches = text.split(regex)

  matches.forEach((part) => {
    if (part.toLowerCase() === search.toLowerCase()) {
      parts.push({ text: part, isMatch: true })
    } else if (part) {
      parts.push({ text: part, isMatch: false })
    }
  })

  return parts
}
