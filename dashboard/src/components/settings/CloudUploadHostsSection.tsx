import { useEffect, useState } from 'react'
import { UploadCloud, Trash2, Plus } from 'lucide-react'
import toast from 'react-hot-toast'
import {
  getCloudUploadHosts,
  addCloudUploadHost,
  deleteCloudUploadHost,
  type CloudUploadHost,
} from '@/lib/api'

export default function CloudUploadHostsSection() {
  const [entries, setEntries] = useState<CloudUploadHost[]>([])
  const [loading, setLoading] = useState(true)
  const [domain, setDomain] = useState('')
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)

  const load = async () => {
    try {
      const data = await getCloudUploadHosts()
      setEntries(data.entries || [])
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to load monitored destinations')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      const res = await addCloudUploadHost(domain.trim(), label.trim() || undefined)
      toast.success(`Now monitoring ${res?.added ?? domain.trim()}`)
      setDomain('')
      setLabel('')
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to add destination')
    } finally {
      setBusy(false)
    }
  }

  const handleDelete = async (entry: CloudUploadHost) => {
    if (!window.confirm(`Stop monitoring ${entry.domain}?`)) return
    try {
      await deleteCloudUploadHost(entry.id)
      toast.success(`Removed ${entry.domain}`)
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to remove entry')
    }
  }

  return (
    <div className="card">
      <div className="flex items-start gap-3 mb-4">
        <div className="p-2 bg-cs-indigo-faint rounded-cs-sm">
          <UploadCloud className="h-5 w-5 text-cs-indigo" />
        </div>
        <div className="flex-1">
          <h3 className="section-title">Cloud Upload Guard — Extra Destinations</h3>
          <p className="text-sm text-cs-muted">
            The browser extension already watches a built-in list of cloud apps (Gmail, Outlook,
            Drive, Dropbox, OneDrive, Box, Slack, and more). Add a destination here — e.g. a
            partner's file-sharing portal — to start monitoring it fleet-wide without reinstalling
            the extension. This list only ever adds destinations; it can't disable one of the
            built-in ones.
          </p>
        </div>
      </div>

      {loading ? (
        <p className="text-sm text-cs-muted">Loading…</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-cs-muted mb-4">No extra destinations added yet.</p>
      ) : (
        <div className="overflow-x-auto mb-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-cs-muted border-b border-cs-hair-2">
                <th className="py-2 pr-4 font-medium">Domain</th>
                <th className="py-2 pr-4 font-medium">Label</th>
                <th className="py-2 pr-4 font-medium">Added</th>
                <th className="py-2 w-10"></th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className="border-b border-cs-hair-2 last:border-0">
                  <td className="py-2 pr-4 num text-cs-ink">{e.domain}</td>
                  <td className="py-2 pr-4 text-cs-ink-2">{e.label || '—'}</td>
                  <td className="py-2 pr-4 text-cs-muted num">
                    {e.created_at ? new Date(e.created_at).toLocaleDateString() : '—'}
                  </td>
                  <td className="py-2">
                    <button
                      onClick={() => handleDelete(e)}
                      className="p-1.5 rounded-cs-sm text-cs-muted-2 hover:text-cs-crit hover:bg-[color-mix(in_srgb,var(--cs-crit)_10%,var(--cs-panel))] transition-colors"
                      title="Remove"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <form onSubmit={handleAdd} className="flex flex-col sm:flex-row gap-3 sm:items-end pt-2 border-t border-cs-hair-2">
        <div className="flex-1">
          <label className="block text-sm font-medium text-cs-ink-2 mb-1.5">
            Domain to monitor
          </label>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            required
            className="input num"
            placeholder="sharefile.com"
          />
        </div>
        <div className="flex-1">
          <label className="block text-sm font-medium text-cs-ink-2 mb-1.5">
            Label <span className="text-cs-muted-2 font-normal">(optional)</span>
          </label>
          <input
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            className="input"
            placeholder="Partner SFTP portal"
          />
        </div>
        <button
          type="submit"
          disabled={busy}
          className="btn-primary inline-flex items-center gap-2 disabled:opacity-60 disabled:cursor-not-allowed"
        >
          <Plus className="h-4 w-4" />
          {busy ? 'Adding…' : 'Add'}
        </button>
      </form>

      <p className="text-xs text-cs-muted mt-3">
        Endpoints pick up changes within about 15 minutes (or immediately after a browser restart).
      </p>
    </div>
  )
}
