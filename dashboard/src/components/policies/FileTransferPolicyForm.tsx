import { FileTransferConfig } from '@/types/policy'

interface Props {
  config: FileTransferConfig
  onChange: (config: FileTransferConfig) => void
}

export default function FileTransferPolicyForm({ config, onChange }: Props) {
  const update = (partial: Partial<FileTransferConfig>) =>
    onChange({ ...config, ...partial })

  const toggleEvent = (key: keyof FileTransferConfig['events']) =>
    update({ events: { ...config.events, [key]: !config.events[key] } })

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-200 mb-1">Protected paths</label>
        <textarea
          className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm text-white"
          rows={3}
          placeholder="One path per line (e.g. C:\Sensitive or /opt/data)"
          value={config.protectedPaths.join('\n')}
          onChange={(e) => update({ protectedPaths: e.target.value.split('\n').map(s => s.trim()).filter(Boolean) })}
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-200 mb-1">Destination paths to monitor</label>
        <textarea
          className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm text-white"
          rows={3}
          placeholder="One path per line (e.g. D:\Staging or /mnt/share)"
          value={config.monitoredDestinations.join('\n')}
          onChange={(e) => update({ monitoredDestinations: e.target.value.split('\n').map(s => s.trim()).filter(Boolean) })}
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-200 mb-1">File extensions (optional)</label>
        <input
          className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm text-white"
          placeholder=".txt, .pdf, .docx"
          value={(config.fileExtensions || []).join(', ')}
          onChange={(e) => update({ fileExtensions: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })}
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-200 mb-1">Events</label>
        <div className="grid grid-cols-2 gap-2 text-sm text-white">
          {(['create', 'modify', 'delete', 'move'] as const).map(key => (
            <label key={key} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={config.events[key]}
                onChange={() => toggleEvent(key)}
              />
              <span className="capitalize">{key}</span>
            </label>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-200 mb-1">Action</label>
          <select
            className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm text-white"
            value={config.action}
            onChange={(e) => update({ action: e.target.value as FileTransferConfig['action'] })}
          >
            <option value="block">Block</option>
            <option value="quarantine">Quarantine</option>
            <option value="alert">Alert only</option>
          </select>
        </div>

        {config.action === 'quarantine' && (
          <div>
            <label className="block text-sm font-medium text-gray-200 mb-1">Quarantine path</label>
            <input
              className="w-full bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm text-white"
              placeholder="C:\Quarantine or /quarantine"
              value={config.quarantinePath || ''}
              onChange={(e) => update({ quarantinePath: e.target.value })}
            />
          </div>
        )}
      </div>
    </div>
  )
}



