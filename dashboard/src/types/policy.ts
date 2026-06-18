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

export type PolicySeverity = 'low' | 'medium' | 'high' | 'critical'
export type ClipboardAction = 'alert' | 'log'
export type FileSystemAction = 'alert' | 'log'
export type FileTransferAction = 'block' | 'quarantine' | 'alert'
export type USBDeviceAction = 'alert' | 'log' | 'block'
export type USBTransferAction = 'block' | 'quarantine' | 'alert'

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
  action: FileSystemAction
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


