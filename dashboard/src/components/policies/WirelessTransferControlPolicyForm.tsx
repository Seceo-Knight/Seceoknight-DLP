'use client'

import { WirelessTransferControlConfig } from '@/types/policy'

interface WirelessTransferControlPolicyFormProps {
  config: WirelessTransferControlConfig
  onChange: (config: WirelessTransferControlConfig) => void
}

export default function WirelessTransferControlPolicyForm({ config: rawConfig, onChange }: WirelessTransferControlPolicyFormProps) {
  const config: WirelessTransferControlConfig = {
    mode: rawConfig?.mode ?? 'audit',
    block_bluetooth_file_transfer: rawConfig?.block_bluetooth_file_transfer ?? false,
    block_nearby_sharing: rawConfig?.block_nearby_sharing ?? false,
  }

  return (
    <div className="space-y-6">
      <div className="p-4 bg-amber-900/20 border border-amber-500/30 rounded-lg text-sm text-amber-200/90">
        Blocks the built-in Bluetooth file-transfer wizard and/or Wi-Fi Direct / Windows Nearby Sharing -- an
        exfiltration channel independent of USB, network share, and print. Audio (headphones/speakers) and input
        (mouse/keyboard) Bluetooth devices are never affected.
      </div>

      {/* Mode */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Mode</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="wireless-mode"
              value="enforce"
              checked={config.mode === 'enforce'}
              onChange={() => onChange({ ...config, mode: 'enforce' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Enforce</div>
              <div className="text-muted-foreground/70 text-xs">Actually block the channels selected below</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="wireless-mode"
              value="audit"
              checked={config.mode === 'audit'}
              onChange={() => onChange({ ...config, mode: 'audit' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Audit</div>
              <div className="text-muted-foreground/70 text-xs">Log attempted transfers without blocking -- validate before enforcing</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="radio"
              name="wireless-mode"
              value="off"
              checked={config.mode === 'off'}
              onChange={() => onChange({ ...config, mode: 'off' })}
              className="w-4 h-4 text-indigo-400"
            />
            <div>
              <div className="text-white font-medium text-sm">Off</div>
              <div className="text-muted-foreground/70 text-xs">Disable wireless transfer control entirely</div>
            </div>
          </label>
        </div>
      </div>

      {/* Channels */}
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-3">Channels to Block</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="checkbox"
              checked={config.block_bluetooth_file_transfer}
              onChange={(e) => onChange({ ...config, block_bluetooth_file_transfer: e.target.checked })}
              className="w-4 h-4 text-indigo-400 rounded"
            />
            <div>
              <div className="text-white font-medium text-sm">Bluetooth File Transfer</div>
              <div className="text-muted-foreground/70 text-xs">Blocks the built-in Bluetooth file-transfer wizard (fsquirt.exe)</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-gray-600 bg-gray-900/30 cursor-pointer hover:border-gray-500 transition-all">
            <input
              type="checkbox"
              checked={config.block_nearby_sharing}
              onChange={(e) => onChange({ ...config, block_nearby_sharing: e.target.checked })}
              className="w-4 h-4 text-indigo-400 rounded"
            />
            <div>
              <div className="text-white font-medium text-sm">Wi-Fi Direct / Nearby Sharing</div>
              <div className="text-muted-foreground/70 text-xs">Blocks Windows Nearby Sharing and Wi-Fi Direct device-to-device transfer</div>
            </div>
          </label>
        </div>
      </div>

      <p className="text-xs text-muted-foreground/70">
        Enforced via registry policy (IFEO debugger redirection for the Bluetooth wizard, Wi-Fi Direct/Nearby
        Sharing policy keys). Reconciled on every policy sync.
      </p>
    </div>
  )
}
