/**
 * Policy Utility Functions
 * Helper functions for policy operations and formatting
 */

import { 
  Policy, 
  PolicyType,
  PolicySeverity,
  ClipboardConfig, 
  FileSystemConfig, 
  USBDeviceConfig, 
  USBTransferConfig,
  FileTransferConfig
} from '@/types/policy'
import { Clipboard, FileText, Usb, HardDrive, Cloud } from 'lucide-react'

/**
 * Get icon component for policy type
 */
export const getPolicyTypeIcon = (type: PolicyType) => {
  switch (type) {
    case 'clipboard_monitoring':
      return Clipboard
    case 'file_system_monitoring':
      return FileText
    case 'file_transfer_monitoring':
      return HardDrive
    case 'usb_device_monitoring':
      return Usb
    case 'usb_file_transfer_monitoring':
      return HardDrive
    case 'google_drive_local_monitoring':
      return Cloud
    case 'google_drive_cloud_monitoring':
      return Cloud
    default:
      return FileText
  }
}

/**
 * Get human-readable label for policy type
 */
export const getPolicyTypeLabel = (type: PolicyType): string => {
  switch (type) {
    case 'clipboard_monitoring':
      return 'Clipboard Monitoring'
    case 'file_system_monitoring':
      return 'File System Monitoring'
    case 'usb_device_monitoring':
      return 'USB Device Monitoring'
    case 'usb_file_transfer_monitoring':
      return 'USB File Transfer Monitoring'
    case 'file_transfer_monitoring':
      return 'File Transfer Monitoring'
    case 'google_drive_local_monitoring':
      return 'Google Drive (Local)'
    case 'google_drive_cloud_monitoring':
      return 'Google Drive (Cloud)'
    default:
      return 'Unknown'
  }
}

/**
 * Format policy configuration for display
 */
export const formatPolicyConfig = (policy: Policy): string => {
  const { type, config } = policy

  if (!config || typeof config !== 'object') return 'No configuration'

  try {
    switch (type) {
      case 'clipboard_monitoring': {
        const c = config as ClipboardConfig
        if (!c.patterns) return `Action: ${c.action || 'alert'}`
        const predefined = (c.patterns.predefined || []).map(p => {
          const labels: Record<string, string> = {
            'ssn': 'SSN',
            'credit_card': 'Credit Card',
            'email': 'Email',
            'phone': 'Phone',
            'api_key': 'API Key',
            'private_key': 'Private Key'
          }
          return labels[p] || p
        }).join(', ')
        const custom = (c.patterns.custom || []).length > 0
          ? `, ${c.patterns.custom.length} custom pattern(s)`
          : ''
        return `Patterns: ${predefined}${custom} | Action: ${c.action || 'alert'}`
      }

      case 'file_system_monitoring': {
        const c = config as FileSystemConfig
        const events = Object.entries(c.events || {})
          .filter(([_, enabled]) => enabled)
          .map(([event]) => event.charAt(0).toUpperCase() + event.slice(1))
          .join(', ')
        const paths = (c.monitoredPaths || []).length > 0
          ? `${c.monitoredPaths.length} path(s)`
          : 'No paths'
        return `Paths: ${paths} | Events: ${events} | Action: ${c.action || 'alert'}`
      }

      case 'file_transfer_monitoring': {
        const c = config as FileTransferConfig
        const protectedCount = (c.protectedPaths || []).length
        const destCount = (c.monitoredDestinations || []).length
        const events = Object.entries(c.events || {})
          .filter(([_, enabled]) => enabled)
          .map(([event]) => event.charAt(0).toUpperCase() + event.slice(1))
          .join(', ')
        return `Protected: ${protectedCount} path(s) | Destinations: ${destCount} | Events: ${events || 'None'} | Action: ${c.action || 'alert'}`
      }

      case 'usb_device_monitoring': {
        const c = config as USBDeviceConfig
        const events = Object.entries(c.events || {})
          .filter(([_, enabled]) => enabled)
          .map(([event]) => event.charAt(0).toUpperCase() + event.slice(1))
          .join(', ')
        return `Events: ${events} | Action: ${c.action || 'alert'}`
      }

      case 'usb_file_transfer_monitoring': {
        const c = config as USBTransferConfig
        const paths = (c.monitoredPaths || []).length > 0
          ? `${c.monitoredPaths.length} path(s)`
          : 'All paths'
        return `Paths: ${paths} | Action: ${c.action || 'block'}`
      }

      case 'google_drive_local_monitoring': {
        const c = config as any
        const folders = (c.monitoredFolders || []).length > 0
          ? `${c.monitoredFolders.length} folder(s)`
          : 'Entire drive'
        const events = Object.entries(c.events || {})
          .filter(([_, enabled]) => enabled)
          .map(([event]) => event.charAt(0).toUpperCase() + event.slice(1))
          .join(', ')
        return `Base: ${c.basePath || 'G:\\My Drive\\'} | Folders: ${folders} | Events: ${events || 'None'} | Action: ${c.action || 'alert'}`
      }

      case 'google_drive_cloud_monitoring': {
        const c = config as any
        const folders = (c.protectedFolders || []).length > 0
          ? `${c.protectedFolders.length} folder(s)`
          : 'None'
        return `Folders: ${folders} | Interval: ${c.pollingInterval || 10} min | Action: log`
      }

      default:
        return (config as any).description || 'Custom configuration'
    }
  } catch {
    return 'Configuration available'
  }
}

/**
 * Validate regex pattern
 */
export const validateRegex = (regex: string): { valid: boolean; error?: string } => {
  if (!regex.trim()) {
    return { valid: false, error: 'Regex pattern cannot be empty' }
  }
  
  try {
    new RegExp(regex)
    return { valid: true }
  } catch (e) {
    return { valid: false, error: 'Invalid regex pattern' }
  }
}

/**
 * Test regex against sample text
 */
export const testRegex = (regex: string, sampleText: string): boolean => {
  try {
    const pattern = new RegExp(regex)
    return pattern.test(sampleText)
  } catch {
    return false
  }
}

/**
 * Validate policy before save
 */
export const validatePolicy = (policy: Partial<Policy>): { valid: boolean; errors: string[] } => {
  const errors: string[] = []
  
  if (!policy.name || !policy.name.trim()) {
    errors.push('Policy name is required')
  }
  
  if (!policy.type) {
    errors.push('Policy type is required')
  }
  
  if (!policy.config) {
    errors.push('Policy configuration is required')
  } else {
    // Type-specific validation
    switch (policy.type) {
      case 'clipboard_monitoring': {
        const c = policy.config as ClipboardConfig
        if (c.patterns.predefined.length === 0 && c.patterns.custom.length === 0) {
          errors.push('At least one pattern must be selected')
        }
        // Validate custom regex patterns
        c.patterns.custom.forEach((custom, index) => {
          const validation = validateRegex(custom.regex)
          if (!validation.valid) {
            errors.push(`Custom pattern ${index + 1}: ${validation.error}`)
          }
        })
        break
      }
      
      case 'file_system_monitoring': {
        const c = policy.config as FileSystemConfig
        if (c.monitoredPaths.length === 0) {
          errors.push('At least one monitored path is required')
        }
        if (!Object.values(c.events).some(v => v)) {
          errors.push('At least one event type must be selected')
        }
        if (c.action !== 'alert' && c.action !== 'log') {
          errors.push('File system monitoring is detection-only (alert/log)')
        }
        break
      }

      case 'file_transfer_monitoring': {
        const c = policy.config as FileTransferConfig
        if (c.protectedPaths.length === 0) {
          errors.push('At least one protected path is required')
        }
        if (c.monitoredDestinations.length === 0) {
          errors.push('At least one destination path is required')
        }
        if (!Object.values(c.events).some(v => v)) {
          errors.push('At least one event type must be selected')
        }
        if (c.action === 'quarantine' && !c.quarantinePath?.trim()) {
          errors.push('Quarantine path is required when action is quarantine')
        }
        break
      }
      
      case 'usb_device_monitoring': {
        const c = policy.config as USBDeviceConfig
        if (!Object.values(c.events).some(v => v)) {
          errors.push('At least one event type must be selected')
        }
        break
      }
      
      case 'usb_file_transfer_monitoring': {
        const c = policy.config as USBTransferConfig
        if (c.monitoredPaths.length === 0) {
          errors.push('At least one monitored path is required')
        }
        if (c.action === 'quarantine' && !c.quarantinePath?.trim()) {
          errors.push('Quarantine path is required when action is quarantine')
        }
        break
      }
    }
  }

  // Agent scoping: allow at most one agent_id
  const scoped = policy.agentIds || []
  if (scoped.length > 1) {
    errors.push('Only one agent can be selected')
  }
  
  return {
    valid: errors.length === 0,
    errors
  }
}

/**
 * Get severity color classes (dark theme)
 */
export const getSeverityColor = (severity: string): string => {
  switch (severity) {
    case 'critical':
      return 'text-red-400 bg-red-900/30 border-red-500/50'
    case 'high':
      return 'text-orange-400 bg-orange-900/30 border-orange-500/50'
    case 'medium':
      return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/50'
    case 'low':
      return 'text-green-400 bg-green-900/30 border-green-500/50'
    default:
      return 'text-gray-400 bg-gray-900/30 border-gray-500/50'
  }
}

/**
 * Get severity color classes (light theme - Dashboard style)
 */
export const getSeverityColorLight = (severity: string): {
  bg: string
  icon: string
  badge: string
} => {
  switch (severity) {
    case 'critical':
      return {
        bg: 'bg-red-100',
        icon: 'text-red-600',
        badge: 'badge-danger'
      }
    case 'high':
      return {
        bg: 'bg-orange-100',
        icon: 'text-orange-600',
        badge: 'badge-warning'
      }
    case 'medium':
      return {
        bg: 'bg-yellow-100',
        icon: 'text-yellow-600',
        badge: 'badge-warning'
      }
    case 'low':
      return {
        bg: 'bg-green-100',
        icon: 'text-green-600',
        badge: 'badge-success'
      }
    default:
      return {
        bg: 'bg-gray-100',
        icon: 'text-gray-600',
        badge: 'badge-info'
      }
  }
}

/**
 * Transform API policy response to frontend Policy format.
 *
 * SHAPE MISMATCH NOTE:
 *   The backend serializer at server/app/api/v1/policies.py returns
 *     conditions: a flat LIST of rules  (from policy.conditions.get('rules', []))
 *     actions:    a LIST of {type, parameters} objects
 *
 *   But the React edit form (ClassificationPolicyForm) expects
 *     conditions: { match: 'all' | 'any', rules: [...] }
 *     actions:    { alert?: {...}, block?: {...}, quarantine?: {...} }
 *
 *   Without this reshape, clicking "Edit" on any classification-aware
 *   policy caused the form to dereference `.conditions.match` on an
 *   array → TypeError → blank white screen.
 */
export const transformApiPolicyToFrontend = (apiPolicy: any): Policy => {
  // ── conditions: list-of-rules → { match, rules } ─────────────────
  let conditions: any
  if (Array.isArray(apiPolicy.conditions)) {
    conditions = {
      match: (apiPolicy.match as 'all' | 'any') || 'all',
      rules: apiPolicy.conditions,
    }
  } else if (apiPolicy.conditions && typeof apiPolicy.conditions === 'object') {
    // Already in {match, rules} shape — pass through, defensively fill blanks.
    conditions = {
      match: apiPolicy.conditions.match || 'all',
      rules: Array.isArray(apiPolicy.conditions.rules)
        ? apiPolicy.conditions.rules
        : [],
    }
  } else {
    conditions = { match: 'all', rules: [] }
  }

  // ── actions: list of {type, parameters} → { alert, block, quarantine, ... } ──
  let actions: Record<string, any> = {}
  if (Array.isArray(apiPolicy.actions)) {
    for (const entry of apiPolicy.actions) {
      if (entry && typeof entry === 'object' && entry.type) {
        actions[entry.type] = entry.parameters ?? {}
      }
    }
  } else if (apiPolicy.actions && typeof apiPolicy.actions === 'object') {
    actions = apiPolicy.actions
  }

  return {
    id: apiPolicy.id || '',
    name: apiPolicy.name || '',
    description: apiPolicy.description || '',
    type: apiPolicy.type as PolicyType,
    enabled: apiPolicy.enabled ?? true,
    severity: (apiPolicy.severity || 'medium') as PolicySeverity,
    priority: apiPolicy.priority || 100,
    createdAt: apiPolicy.created_at || new Date().toISOString(),
    updatedAt: apiPolicy.updated_at || new Date().toISOString(),
    createdBy: apiPolicy.created_by || undefined,
    violations: 0, // TODO: Get from stats endpoint
    lastViolation: undefined, // TODO: Get from stats endpoint
    config: apiPolicy.config || getDefaultConfig(apiPolicy.type as PolicyType),
    conditions,
    actions,
    agentIds: apiPolicy.agent_ids || [],
  }
}

/**
 * Transform frontend Policy format to API request format.
 *
 * Reverses the reshape above so POST/PUT bodies match what the
 * backend Policy model and transform_frontend_config_to_backend()
 * helper expect.
 */
export const transformFrontendPolicyToApi = (policy: Partial<Policy>): any => {
  // ── conditions: { match, rules } → List[PolicyCondition] ──────────
  //
  // The backend PolicyUpsert model declares:
  //   conditions: Optional[List[PolicyCondition]] = []
  // where PolicyCondition = {field, operator, value}.
  //
  // The frontend edit form stores conditions as {match, rules: [...]}.
  // We extract just the `rules` array, which IS the list of
  // PolicyCondition dicts. Sending the wrapper object ({match, rules})
  // instead of the list causes pydantic to reject with
  //   422 "input should be a valid list".
  let conditionsList: any[] = []
  let conditionsMatch: 'all' | 'any' | 'none' = 'all'
  const fc: any = policy.conditions
  if (fc && typeof fc === 'object' && !Array.isArray(fc)) {
    // Frontend shape: {match, rules: [...]}
    conditionsList = Array.isArray(fc.rules) ? fc.rules : []
    if (fc.match === 'all' || fc.match === 'any' || fc.match === 'none') {
      conditionsMatch = fc.match
    }
  } else if (Array.isArray(fc)) {
    conditionsList = fc
  }
  // Top-level `match` (when modal flattens conditions to a list) takes precedence
  const topMatch = (policy as any).match
  if (topMatch === 'all' || topMatch === 'any' || topMatch === 'none') {
    conditionsMatch = topMatch
  }

  // ── actions: { alert: {...}, block: {...} } → List[PolicyAction] ──
  //
  // The backend declares:
  //   actions: Optional[List[PolicyAction]] = []
  // where PolicyAction = {type: str, parameters: dict}.
  //
  // The frontend edit form stores actions as {alert: {...}, block: {...}}.
  // We convert each truthy entry back into {type, parameters}.
  let actionsList: any[] = []
  const fa: any = policy.actions
  if (fa && typeof fa === 'object' && !Array.isArray(fa)) {
    for (const [key, value] of Object.entries(fa)) {
      if (value) {
        actionsList.push({ type: key, parameters: value })
      }
    }
  } else if (Array.isArray(fa)) {
    actionsList = fa
  }

  return {
    name: policy.name || '',
    description: policy.description || '',
    type: policy.type,
    severity: policy.severity || 'medium',
    priority: policy.priority || 100,
    enabled: policy.enabled ?? true,
    config: policy.config,
    agent_ids: policy.agentIds || [],
    match: conditionsMatch,
    conditions: conditionsList,
    actions: actionsList,
    compliance_tags: [],
  }
}

/**
 * Get default config for policy type (helper for transformation)
 */
const getDefaultConfig = (type: PolicyType): any => {
  switch (type) {
    case 'clipboard_monitoring':
      return { patterns: { predefined: [], custom: [] }, action: 'alert' }
    case 'file_system_monitoring':
      return { monitoredPaths: [], events: { create: false, modify: false, delete: false, move: false }, action: 'alert' }
    case 'usb_device_monitoring':
      return { events: { connect: false, disconnect: false, fileTransfer: false }, action: 'alert' }
    case 'usb_file_transfer_monitoring':
      return { monitoredPaths: [], action: 'block' }
    case 'google_drive_local_monitoring':
      return {
        basePath: 'G:\\My Drive\\',
        monitoredFolders: [],
        fileExtensions: [],
        events: { create: true, modify: false, delete: false, move: false },
        action: 'alert'
      }
    case 'google_drive_cloud_monitoring':
      return {
        connectionId: '',
        protectedFolders: [],
        pollingInterval: 10,
        action: 'log'
      }
    case 'onedrive_cloud_monitoring':
      return {
        connectionId: '',
        protectedFolders: [],
        pollingInterval: 10,
        action: 'log'
      }
    default:
      return {}
  }
}

/**
 * Predefined pattern definitions
 */
export const predefinedPatterns = [
  { 
    id: 'ssn', 
    name: 'Social Security Number (SSN)', 
    example: '123-45-6789',
    regex: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
  },
  { 
    id: 'credit_card', 
    name: 'Credit Card Number', 
    example: '4111-1111-1111-1111',
    regex: '\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b'
  },
  { 
    id: 'email', 
    name: 'Email Address', 
    example: 'user@example.com',
    regex: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
  },
  { 
    id: 'phone', 
    name: 'Phone Number', 
    example: '+1-555-123-4567',
    regex: '\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b'
  },
  { 
    id: 'api_key', 
    name: 'API Key', 
    example: 'sk_live_...',
    regex: '\\b[A-Za-z0-9_-]{32,}\\b'
  },
  { 
    id: 'private_key', 
    name: 'Private Key', 
    example: '-----BEGIN PRIVATE KEY-----',
    regex: '-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
  },
  // Indian identifiers
  { 
    id: 'aadhaar', 
    name: 'Aadhaar Number', 
    example: '1234 5678 9012',
    regex: '\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b'
  },
  { 
    id: 'pan', 
    name: 'PAN Number', 
    example: 'ABCDE1234F',
    regex: '\\b[A-Z]{5}\\d{4}[A-Z]{1}\\b'
  },
  { 
    id: 'ifsc', 
    name: 'IFSC Code', 
    example: 'SBIN0001234',
    regex: '\\b[A-Z]{4}0[A-Z0-9]{6}\\b'
  },
  { 
    id: 'indian_bank_account', 
    name: 'Indian Bank Account Number', 
    example: '123456789012',
    regex: '\\b\\d{9,18}\\b'
  },
  { 
    id: 'indian_phone', 
    name: 'Indian Phone Number', 
    example: '+91-9876543210',
    regex: '\\b(\\+91|91|0)?[6-9]\\d{9}\\b'
  },
  { 
    id: 'upi_id', 
    name: 'UPI ID', 
    example: 'user@paytm',
    regex: '\\b[\\w.-]+@(paytm|phonepe|ybl|okaxis|okhdfcbank|oksbi|okicici)\\b'
  },
  { 
    id: 'micr', 
    name: 'MICR Code', 
    example: '123456789',
    regex: '\\b\\d{9}\\b'
  },
  { 
    id: 'indian_dob', 
    name: 'Date of Birth (DD/MM/YYYY)', 
    example: '15/08/1990',
    regex: '\\b(0[1-9]|[12][0-9]|3[01])[/-](0[1-9]|1[0-2])[/-](19|20)\\d{2}\\b'
  },
  // Source code detection
  { 
    id: 'source_code_content', 
    name: 'Source Code Content', 
    example: 'function myFunction()',
    regex: '\\b(function|def|class|public|private|protected|static|import|from|require|include|using|package|const|let|var|int|string|float|bool)\\s+\\w+'
  },
  { 
    id: 'api_key_in_code', 
    name: 'API Keys in Source Code', 
    example: 'api_key: "sk_live_..."',
    regex: '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|api[_-]?key["\']?\\s*[:=]\\s*["\']?[a-zA-Z0-9_\\-]{32,}["\']?)'
  },
  { 
    id: 'database_connection_string', 
    name: 'Database Connection Strings', 
    example: 'jdbc:mysql://localhost:3306/mydb',
    regex: '(jdbc:(mysql|postgresql|oracle|sqlserver)://|mongodb://|mongodb\\+srv://|redis://|rediss://)'
  }
]
