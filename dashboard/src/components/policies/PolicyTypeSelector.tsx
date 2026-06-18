'use client'

import { PolicyType } from '@/types/policy'
import { Clipboard, FileText, Usb, HardDrive, Cloud, Shield } from 'lucide-react'

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
  }
]

export default function PolicyTypeSelector({ selectedType, onSelectType }: PolicyTypeSelectorProps) {
  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold text-white mb-2">Select Policy Type (v2)</h3>
        <p className="text-sm text-gray-400">Choose the type of monitoring policy you want to create</p>
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
                  ? 'border-indigo-500 bg-indigo-900/30 text-white'
                  : 'border-gray-600 bg-gray-900/30 text-gray-400 hover:border-gray-500 hover:text-gray-300'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className={`p-2 rounded-lg ${
                  isSelected 
                    ? 'bg-indigo-800/50 text-indigo-300' 
                    : 'bg-gray-800/50 text-gray-500'
                }`}>
                  <Icon className="w-5 h-5" />
                </div>
                <div className="flex-1">
                  <h4 className="font-semibold text-sm mb-1">{label}</h4>
                  <p className="text-xs opacity-70">{description}</p>
                </div>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}

