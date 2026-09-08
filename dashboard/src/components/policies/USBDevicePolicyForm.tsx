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
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Events to Monitor *
        </label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="checkbox"
              checked={config.events.connect}
              onChange={() => handleToggleEvent('connect')}
              className="w-4 h-4 text-primary rounded"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Device Connection</div>
              <div className="text-muted-foreground text-xs">Monitor when USB devices are connected</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="checkbox"
              checked={config.events.disconnect}
              onChange={() => handleToggleEvent('disconnect')}
              className="w-4 h-4 text-primary rounded"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Device Disconnection</div>
              <div className="text-muted-foreground text-xs">Monitor when USB devices are disconnected</div>
            </div>
          </label>

          {/* "File Transfer" checkbox intentionally removed (September 2026):
              it looked like it worked -- the config saved, the server built a
              usb_event_type=="file_transfer" condition from it -- but no code
              path in the Windows agent ever emitted that event under a
              usb_device_monitoring policy (HandleUsbEvent is only ever called
              with "connect"/"disconnect"; the one function that DID check for
              it, HandleUsbFileTransfer, depended on ScanUsbDriveForChanges,
              which nothing ever calls, and was ALSO separately gated behind
              hasUsbTransferPolicies -- a flag only a completely different
              policy type, USB File Transfer Monitoring, ever sets). Checking
              it created a false sense of coverage. Real USB file-transfer
              detection lives entirely in the USB File Transfer Monitoring
              policy type (source/destination hash correlation via
              MonitorUSBTransferDirectories) -- use that policy instead. */}
        </div>
      </div>

      {/* Action Selection */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">
          Action When Event Detected
        </label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="usb-device-action"
              value="alert"
              checked={config.action === 'alert'}
              onChange={() => onChange({ ...config, action: 'alert' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Alert</div>
              <div className="text-muted-foreground text-xs">Send alert notification</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="usb-device-action"
              value="log"
              checked={config.action === 'log'}
              onChange={() => onChange({ ...config, action: 'log' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Log Only</div>
              <div className="text-muted-foreground text-xs">Log the event without sending alerts</div>
            </div>
          </label>

          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="usb-device-action"
              value="block"
              checked={config.action === 'block'}
              onChange={() => onChange({ ...config, action: 'block' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Block Device</div>
              <div className="text-muted-foreground text-xs">Block USB device access (if supported)</div>
            </div>
          </label>
        </div>
      </div>
    </div>
  )
}

