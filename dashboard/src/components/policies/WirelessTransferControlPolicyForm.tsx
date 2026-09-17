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
      <div className="p-4 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
        Blocks the built-in Bluetooth file-transfer wizard and/or Windows Nearby Sharing -- an exfiltration channel
        independent of USB, network share, and print. Audio (headphones/speakers) and input (mouse/keyboard)
        Bluetooth devices are never affected. Note: this does not disable the Wi-Fi Direct radio itself (see below).
      </div>

      {/* Mode */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">Mode</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="wireless-mode"
              value="enforce"
              checked={config.mode === 'enforce'}
              onChange={() => onChange({ ...config, mode: 'enforce' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Enforce</div>
              <div className="text-muted-foreground text-xs">Actually block the channels selected below</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="wireless-mode"
              value="audit"
              checked={config.mode === 'audit'}
              onChange={() => onChange({ ...config, mode: 'audit' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Audit</div>
              <div className="text-muted-foreground text-xs">Log attempted transfers without blocking -- validate before enforcing</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="radio"
              name="wireless-mode"
              value="off"
              checked={config.mode === 'off'}
              onChange={() => onChange({ ...config, mode: 'off' })}
              className="w-4 h-4 text-primary"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Off</div>
              <div className="text-muted-foreground text-xs">Disable wireless transfer control entirely</div>
            </div>
          </label>
        </div>
      </div>

      {/* Channels */}
      <div>
        <label className="block text-sm font-medium text-foreground/90 mb-3">Channels to Block</label>
        <div className="space-y-2">
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="checkbox"
              checked={config.block_bluetooth_file_transfer}
              onChange={(e) => onChange({ ...config, block_bluetooth_file_transfer: e.target.checked })}
              className="w-4 h-4 text-primary rounded"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Bluetooth File Transfer</div>
              <div className="text-muted-foreground text-xs">Blocks the built-in Bluetooth file-transfer wizard (fsquirt.exe)</div>
            </div>
          </label>
          <label className="flex items-center gap-3 p-3 rounded-lg border-2 border-border bg-muted/30 cursor-pointer hover:border-primary/40 transition-all">
            <input
              type="checkbox"
              checked={config.block_nearby_sharing}
              onChange={(e) => onChange({ ...config, block_nearby_sharing: e.target.checked })}
              className="w-4 h-4 text-primary rounded"
            />
            <div>
              <div className="text-foreground font-medium text-sm">Nearby Sharing</div>
              <div className="text-muted-foreground text-xs">
                Disables Windows Nearby Sharing (the share-sheet "Nearby sharing" target, which uses Wi-Fi Direct +
                Bluetooth under the hood) via the CDP policy key. Does not disable the Wi-Fi Direct radio/driver
                itself -- other Wi-Fi Direct-based apps outside Nearby Sharing are not covered.
              </div>
            </div>
          </label>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        Enforced via registry policy: IFEO debugger redirection for the Bluetooth file-transfer wizard
        (fsquirt.exe), and the Nearby Sharing/CDP policy key for Nearby Sharing. Reconciled on every policy sync.
      </p>
      <p className="text-xs text-muted-foreground">
        Known limitation: a blocked Bluetooth file-transfer attempt creates a full audit-trail event (who, when,
        blocked) because launching fsquirt.exe is a distinct, interceptable action. A blocked Nearby Sharing
        attempt does not -- disabling Nearby Sharing is a passive feature killswitch with no equivalent
        interception point, so attempted (and failed) use of Nearby Sharing while this policy is enforced produces
        no event and will not appear in Events/Alerts.
      </p>
    </div>
  )
}
