/**
 * Policy Type Definitions
 * Shared types for policy management
 */

export type PolicyType =
  | 'clipboard_monitoring'
  | 'file_system_monitoring'
  | 'file_transfer_monitoring'
  | 'usb_device_monitoring'
  | 'usb_file_transfer_monitoring'
  | 'google_drive_local_monitoring'
  | 'google_drive_cloud_monitoring'
  | 'onedrive_cloud_monitoring'
  | 'classification_aware_policy'
  | 'browser_upload_monitoring'
  | 'file_identity_denylist'
  | 'network_share_transfer_control'
  | 'application_control'
  | 'wireless_transfer_control'
  | 'print_content_prevention'
  | 'messaging_app_control'
  | 'printer_control'
  | 'email_send_prevention'
  | 'web_activity_control'
  | 'file_access_control'

export type PolicySeverity = 'low' | 'medium' | 'high' | 'critical'
export type ClipboardAction = 'alert' | 'log'
export type FileSystemAction = 'alert' | 'log' | 'quarantine' | 'block'
export type FileTransferAction = 'block' | 'quarantine' | 'alert'
export type USBDeviceAction = 'alert' | 'log' | 'block'
export type USBTransferAction = 'block' | 'quarantine' | 'alert'
export type FileIdentityDenylistAction = 'block' | 'quarantine' | 'alert' | 'log'

export interface ClipboardConfig {
  patterns: {
    predefined: string[]  // ['ssn', 'credit_card', 'api_key']
    custom: Array<{ regex: string, description?: string }>
  }
  action: ClipboardAction
}

export interface FileSystemConfig {
  monitoredPaths: string[]
  fileExtensions?: string[]
  events: {
    create: boolean
    modify: boolean
    delete: boolean
    move: boolean
  }
  // Content patterns to check file contents against (including OCR'd
  // text from images/screenshots). Optional — leaving both empty falls
  // back to "pure monitoring" (alert/quarantine on any matching file,
  // regardless of content), which the agent already supports.
  patterns?: {
    predefined: string[]
    custom: Array<{ regex: string, description?: string }>
  }
  action: FileSystemAction
  quarantinePath?: string
}

export interface FileTransferConfig {
  protectedPaths: string[]
  monitoredDestinations: string[]
  fileExtensions?: string[]
  events: {
    create: boolean
    modify: boolean
    delete: boolean
    move: boolean
  }
  action: FileTransferAction
  quarantinePath?: string
}

export interface USBDeviceConfig {
  events: {
    connect: boolean
    disconnect: boolean
    fileTransfer: boolean
  }
  action: USBDeviceAction
}

export interface USBTransferConfig {
  monitoredPaths: string[]
  action: USBTransferAction
  quarantinePath?: string
}

export interface GoogleDriveLocalConfig {
  basePath: string  // Default: "G:\\My Drive\\"
  monitoredFolders: string[]  // Subfolders within basePath
  fileExtensions?: string[]
  events: {
    create: boolean
    modify: boolean
    delete: boolean
    move: boolean
  }
  action: FileSystemAction
  quarantinePath?: string
}

export interface GoogleDriveCloudConfig {
  connectionId: string
  protectedFolders: Array<{
    id: string
    name: string
    path?: string
  }>
  pollingInterval: number // minutes
  action: 'log'
}

export interface OneDriveCloudConfig {
  connectionId: string
  protectedFolders: Array<{
    id: string
    name: string
    path?: string
  }>
  pollingInterval: number // minutes
  action: 'log'
}

export interface FileIdentityDenylistConfig {
  // Content-independent identity denylist -- blocks by what a file *is*
  // (extension or exact-content hash), not what's inside it. At least one
  // of extensions/hashes should be populated or the policy never matches.
  extensions?: string[]  // e.g. ['.exe', '.bat', '.scr']
  hashes?: string[]      // SHA-256 hex, e.g. from an Events row's file_hash
  action: FileIdentityDenylistAction
  quarantinePath?: string
}

// ── Ported from CyberSentinel-DLP (task #118) ──────────────────────────
// Config shapes match the server contract exactly -- see the docstrings on
// each GET /agents/{agent_id}/<x>-policy endpoint in
// server/app/api/v1/agents.py, which is what the Windows agent actually
// consumes and enforces.

export type NetworkShareTransferMode = 'block_all' | 'content_aware' | 'off'
export type NetworkShareTransferAction = 'audit' | 'block'

export interface NetworkShareControlConfig {
  mode: NetworkShareTransferMode
  action: NetworkShareTransferAction
  exception_shares?: string[]
  exception_users?: string[]
  exception_paths?: string[]
  exception_file_types?: string[]
}

export type ApplicationControlMode = 'allowlist' | 'blocklist'

export interface ApplicationControlConfig {
  mode: ApplicationControlMode
  applications: string[]
  channels?: string[]
  exceptions?: {
    applications?: string[]
    users?: string[]
    paths?: string[]
    file_types?: string[]
  }
}

export type WirelessTransferMode = 'enforce' | 'audit' | 'off'

export interface WirelessTransferControlConfig {
  mode: WirelessTransferMode
  block_bluetooth_file_transfer: boolean
  block_nearby_sharing: boolean
}

export type PrintContentMode = 'enforce' | 'audit'
// "allow" | "block" -- what to do when inspection is active but genuinely
// could NOT read a job's real spooled content (as opposed to reading it and
// finding it clean). Added after a real production investigation found a
// printer/driver/OS combination where no spool file is EVER observable on
// disk, making "unavailable" a permanent state for that printer rather than
// a rare edge case -- fail-open there meant content inspection provided
// zero actual protection while still looking fully configured. Defaults to
// "allow" (non-breaking); admins running a stricter posture can flip it.
export type PrintUnknownContentAction = 'allow' | 'block'

export interface PrintContentPreventionConfig {
  mode: PrintContentMode
  unknownContentAction?: PrintUnknownContentAction
}

export type FileAccessControlMode = 'enforce' | 'audit' | 'off'

export interface FileAccessControlConfig {
  mode: FileAccessControlMode
  // Applied the moment the agent's file_system_monitoring pipeline
  // classifies a newly written/modified file under a monitored path as one
  // of these levels — e.g. ["Confidential", "Restricted"].
  classification_levels: string[]
  // Applied/reconciled every policy-sync cycle, independent of
  // classification — admin-named files/folders (e.g. "C:\\Shared\\HR").
  explicit_paths: string[]
  // Local Windows accounts, or AD accounts if the endpoint is domain-joined
  // (resolved via LookupAccountNameW on the agent) — by name, not SID.
  authorized_users: string[]
  authorized_groups: string[]
  // SYSTEM + local Administrators always keep full control regardless of
  // this setting, so an admin can never lock themselves out entirely; this
  // only controls whether the *domain* Administrators group / other admin
  // groups are also always-allowed. Defaults to true.
  always_allow_admins?: boolean
}

export type MessagingAppAction = 'alert' | 'block'

export interface MessagingAppControlConfig {
  action: MessagingAppAction
  apps?: string[]
  exceptions?: {
    users?: string[]
    file_types?: string[]
  }
  // Typed-message inspection, a different surface from the file-attachment
  // control above -- the agent holds the send keystroke in a managed app,
  // reads the composer via UI Automation, classifies it locally, and
  // re-injects the key if clean or drops it (in Block mode) if not. Ported
  // from CyberSentinel-DLP, gap-scan of August 26 2026. `action` above is
  // SHARED between both surfaces once switched on; this flag is only
  // whether the typed-message one is on AT ALL, and it defaults to false /
  // does not inherit from the rest of this policy on purpose -- see
  // MessagingTypedMessagePanel's warning copy.
  inspect_messages?: boolean
  // Which detector types count as sensitive for a TYPED message specifically.
  // Undefined/omitted = server-side default (every type except INDIAN_PHONE,
  // since a phone number is the most ordinary thing typed into a chat app).
  // An explicit empty array is a real choice and means inspection is
  // effectively off, mirrored by the server collapsing inspect_messages to
  // false when the list is empty.
  message_data_types?: string[]
}

// Kept in sync with _MESSAGING_DATA_TYPES in server/app/api/v1/agents.py.
export const MESSAGING_DATA_TYPES = [
  'CREDIT_CARD', 'AADHAAR', 'PAN', 'SSN', 'INDIAN_PASSPORT',
  'AWS_KEY', 'PRIVATE_KEY', 'JWT_TOKEN', 'IFSC', 'UPI_ID', 'INDIAN_PHONE',
] as const

export type PrinterControlMode = 'enforce' | 'audit'
export type PrinterControlScope = 'block_all' | 'block_network' | 'block_local' | 'allowlist'

export interface PrinterControlConfig {
  mode: PrinterControlMode
  scope: PrinterControlScope
}

// Ported from CyberSentinel-DLP (dedicated Email DLP policy type, task
// #134's gap scan). Unlike printer_control/print_content_prevention/
// messaging_app_control -- which are agent-polled config toggles read
// directly by GET /agents/{id}/<x>-policy endpoints -- the smtp-relay
// (smtp-relay/app/dlp_client.py) is a synchronous server-side component
// with no polling loop: it POSTs each outbound message's content straight
// to the generic /agents/{id}/policy/evaluate endpoint and expects an
// inline block/allow decision back from DatabasePolicyEvaluator's
// conditions/actions rule engine. So this config is transformed (see
// server/app/utils/policy_transformer.py's _transform_email_config) into
// ordinary conditions/rules matching destination_type=="email" plus
// classification_level, the same pattern usb_file_transfer_monitoring
// already uses -- NOT a dedicated polled-config endpoint like
// printer_control's.
export type EmailAction = 'block' | 'alert' | 'log'
export type EmailTriggerLevel = 'Internal' | 'Confidential' | 'Restricted'

export interface EmailConfig {
  action: EmailAction
  // Which classification levels trigger the action. Public is deliberately
  // excluded from the picker (never worth blocking/alerting on).
  triggerLevels: EmailTriggerLevel[]
}

// New capability (GenAI / Web Activity Control) -- new server-side gap
// scan, task #135. See server/app/core/web_activity.py for the shared
// vocabulary this mirrors. A policy's real configuration is a matrix of
// (app category, activity) -> action, keyed as flat strings ("genai.post")
// exactly matching wa.cell_key() server-side so policy.config round-trips
// through the generic policies API without any server-side reshaping (the
// same "config saved verbatim" pattern printer_control/
// file_identity_denylist already use).
//
// Only the currently-meaningful/enforced cells are exposed here --
// MEANINGFUL_CELLS in web_activity.py deliberately leaves upload/attach (and
// genai.download) unwired (see that file's docstring), so this form never
// shows a control that silently does nothing. "download" cells (gap-scan of
// CyberSentinel-DLP, August 24, 2026) were added for the three categories
// where the browser extension's chrome.downloads hook actually fires --
// file_sharing/webmail/collaboration -- see background.js.
export type WebActivityAction = 'allow' | 'alert' | 'block' | 'redact'

export interface WebActivityControlConfig {
  matrix: {
    'webmail.send'?: WebActivityAction
    'webmail.download'?: WebActivityAction
    'collaboration.send'?: WebActivityAction
    'collaboration.download'?: WebActivityAction
    'genai.post'?: WebActivityAction
    'genai.ai_response'?: WebActivityAction
    'file_sharing.download'?: WebActivityAction
  }
}

// Classification-aware policy types
export interface PolicyCondition {
  field: string
  operator: string
  value: any
}

export interface ClassificationPolicyConfig {
  conditions: {
    match: 'all' | 'any'
    rules: PolicyCondition[]
  }
  actions: {
    alert?: {
      severity: 'low' | 'medium' | 'high' | 'critical'
      message?: string
    }
    block?: {}
    quarantine?: {
      location?: string
    }
    log?: {
      level?: 'info' | 'warning' | 'error'
    }
  }
}

export type PolicyConfig =
  | ClipboardConfig
  | FileSystemConfig
  | FileTransferConfig
  | USBDeviceConfig
  | USBTransferConfig
  | GoogleDriveLocalConfig
  | GoogleDriveCloudConfig
  | OneDriveCloudConfig
  | ClassificationPolicyConfig
  | FileIdentityDenylistConfig
  | NetworkShareControlConfig
  | ApplicationControlConfig
  | WirelessTransferControlConfig
  | PrintContentPreventionConfig
  | MessagingAppControlConfig
  | PrinterControlConfig
  | EmailConfig
  | WebActivityControlConfig
  | FileAccessControlConfig

export interface Policy {
  id: string
  name: string
  description: string
  type?: PolicyType  // Optional for classification-aware policies
  severity?: PolicySeverity  // Optional for classification-aware policies
  priority: number
  enabled: boolean
  config?: PolicyConfig  // Optional - used for traditional policies
  // Classification-aware policy fields (alternative to type/config)
  conditions?: {
    match: 'all' | 'any'
    rules: PolicyCondition[]
  }
  actions?: {
    alert?: {
      severity: 'low' | 'medium' | 'high' | 'critical'
      message?: string
    }
    block?: {}
    quarantine?: {
      location?: string
    }
    log?: {
      level?: 'info' | 'warning' | 'error'
    }
  }
  agentId?: string
  agentIds?: string[]
  createdAt?: string
  updatedAt?: string
  createdBy?: string
  violations?: number
  lastViolation?: string
}


