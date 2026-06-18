'use client'

import { USBDeviceConfig } from '@/types/policy'

interface USBDevicePolicyFormProps {
  config: USBDeviceConfig
  onChange: (config: USBDeviceConfig) => void
}

export default function USBDevicePolicyForm({ config, onChange }: USBDevicePolicyFormProps) {
  const handleToggleEvent = (event: keyof USBDeviceConfig['events']) => {
    onChange({
      ...config,
      events: {
        ...config.events,
        [event]: !config.events[event]
      }
    })
  }

  return (
    <div className="space-y-6">
      {/* Events to Monitor */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Events to Monitor *
        </label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="checkbox"
              checked={config.events.connect}
              onChange={() => handleToggleEvent('connect')}
              className="w-4 h-4 text-indigo-600 rounded"
            />
            <div>
              <div className="text-white font-medium text-sm">Device Connection</div>
              <div className="text-gray-400 text-xs">Monitor when USB devices are connected</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="checkbox"
              checked={config.events.disconnect}
              onChange={() => handleToggleEvent('disconnect')}
              className="w-4 h-4 text-indigo-600 rounded"
            />
            <div>
              <div className="text-white font-medium text-sm">Device Disconnection</div>
              <div className="text-gray-400 text-xs">Monitor when USB devices are disconnected</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="checkbox"
              checked={config.events.fileTransfer}
              onChange={() => handleToggleEvent('fileTransfer')}
              className="w-4 h-4 text-indigo-600 rounded"
            />
            <div>
              <div className="text-white font-medium text-sm">File Transfer</div>
              <div className="text-gray-400 text-xs">Monitor file transfer operations on USB devices</div>
            </div>
          </label>
        </div>
      </div>

      {/* Action Selection */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">
          Action When Event Detected
        </label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="usb-device-action"
              value="alert"
              checked={config.action === 'alert'}
              onChange={() => onChange({ ...config, action: 'alert' })}
              className="w-4 h-4 text-indigo-600"
            />
            <div>
              <div className="text-white font-medium text-sm">Alert</div>
              <div className="text-gray-400 text-xs">Send alert notification</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="usb-device-action"
              value="log"
              checked={config.action === 'log'}
              onChange={() => onChange({ ...config, action: 'log' })}
              className="w-4 h-4 text-indigo-600"
            />
            <div>
              <div className="text-white font-medium text-sm">Log Only</div>
              <div className="text-gray-400 text-xs">Log the event without sending alerts</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="usb-device-action"
              value="block"
              checked={config.action === 'block'}
              onChange={() => onChange({ ...config, action: 'block' })}
              className="w-4 h-4 text-indigo-600"
            />
            <div>
              <div className="text-white font-medium text-sm">Block Device</div>
              <div className="text-gray-400 text-xs">Block USB device access (if supported)</div>
            </div>
          </label>
        </div>
      </div>
    </div>
  )
}

