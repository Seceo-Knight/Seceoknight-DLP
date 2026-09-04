'use client'

import { PolicyType } from '@/types/policy'
import { Clipboard, FileText, Usb, HardDrive, Cloud, Shield, Globe, Ban, FolderInput, AppWindow, Bluetooth, Printer, MessageSquare, Mail, Bot } from 'lucide-react'

interface PolicyTypeSelectorProps {
  selectedType: PolicyType | null
  onSelectType: (type: PolicyType) => void
}

const policyTypes: Array<{
  type: PolicyType
  label: string
  description: string
  icon: typeof Clipboard
}> = [
  {
    type: 'clipboard_monitoring',
    label: 'Clipboard Monitoring',
    description: 'Monitor clipboard for sensitive data',
    icon: Clipboard
  },
  {
    type: 'file_system_monitoring',
    label: 'File System Monitoring',
    description: 'Monitor directories for file operations (detect only)',
    icon: FileText
  },
  {
    type: 'file_transfer_monitoring',
    label: 'File Transfer Monitoring',
    description: 'Block/quarantine transfers between protected and destination folders',
    icon: HardDrive
  },
  {
    type: 'usb_device_monitoring',
    label: 'USB Device Monitoring',
    description: 'Monitor USB device connections',
    icon: Usb
  },
  {
    type: 'usb_file_transfer_monitoring',
    label: 'USB File Transfer Monitoring',
    description: 'Monitor and control file transfers to USB',
    icon: HardDrive
  },
  {
    type: 'google_drive_local_monitoring',
    label: 'Google Drive (Local)',
    description: 'Monitor Windows G:\\My Drive (Google Drive desktop app)',
    icon: Cloud
  },
  {
    type: 'google_drive_cloud_monitoring',
    label: 'Google Drive (Cloud)',
    description: 'Monitor Google Drive via Cloud API (OAuth required)',
    icon: Cloud
  },
  {
    type: 'onedrive_cloud_monitoring',
    label: 'OneDrive (Cloud)',
    description: 'Monitor OneDrive via Cloud API (OAuth required)',
    icon: Cloud
  },
  {
    type: 'classification_aware_policy',
    label: 'Classification-Aware Policy',
    description: 'Advanced policy based on content classification and confidence scores',
    icon: Shield
  },
  {
    type: 'browser_upload_monitoring',
    label: 'Browser Upload Monitoring',
    description: 'Detect and alert when files are uploaded via browser file dialog',
    icon: Globe
  },
  {
    type: 'file_identity_denylist',
    label: 'File Identity Denylist',
    description: 'Block files by extension or exact hash, independent of content classification',
    icon: Ban
  },
  {
    type: 'network_share_transfer_control',
    label: 'Network Share Transfer Control',
    description: 'Control copying files to mapped network drives (UNC shares)',
    icon: FolderInput
  },
  {
    type: 'application_control',
    label: 'Application Control',
    description: 'Allow/block a network upload by which application performs it',
    icon: AppWindow
  },
  {
    type: 'wireless_transfer_control',
    label: 'Wireless / Bluetooth Transfer Control',
    description: 'Block the Bluetooth file wizard and/or Wi-Fi Direct / Nearby Sharing',
    icon: Bluetooth
  },
  {
    type: 'print_content_prevention',
    label: 'Print Content Prevention',
    description: 'Inspect spooled print job text and cancel jobs with sensitive content',
    icon: Printer
  },
  {
    type: 'messaging_app_control',
    label: 'Messaging App Attachment Control',
    description: 'Alert or block sensitive attachments picked in Teams/WhatsApp/Slack/etc.',
    icon: MessageSquare
  },
  {
    type: 'printer_control',
    label: 'Printer Device Control',
    description: 'Block printing entirely, or restrict to local/network/allowlisted printers',
    icon: Printer
  },
  {
    type: 'email_send_prevention',
    label: 'Email DLP (Outbound)',
    description: 'Inspect outbound email content via the SMTP relay and block/alert on sensitive data',
    icon: Mail
  },
  {
    type: 'web_activity_control',
    label: 'Web Activity Control (GenAI DLP)',
    description: 'Detect and control sensitive data sent to/from ChatGPT, Copilot, Gemini, Claude, webmail, and collaboration tools',
    icon: Bot
  }
]

export default function PolicyTypeSelector({ selectedType, onSelectType }: PolicyTypeSelectorProps) {
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold text-foreground mb-2">Select Policy Type</h3>
        <p className="text-sm text-muted-foreground">Choose the type of monitoring policy you want to create</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {policyTypes.map(({ type, label, description, icon: Icon }) => {
          const isSelected = selectedType === type

          return (
            <button
              key={type}
              onClick={() => onSelectType(type)}
              className={`p-4 rounded-xl border-2 transition-all text-left ${
                isSelected
                  ? 'border-primary bg-primary/10'
                  : 'border-border bg-card hover:border-primary/40 hover:bg-accent'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className={`p-2 rounded-lg shrink-0 ${
                  isSelected
                    ? 'bg-primary/15 text-primary'
                    : 'bg-secondary text-muted-foreground'
                }`}>
                  <Icon className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <h4 className="font-semibold text-sm mb-1 text-foreground">{label}</h4>
                  <p className="text-xs text-muted-foreground">{description}</p>
                </div>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

