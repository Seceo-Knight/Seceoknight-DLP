import { useEffect, useState } from 'react'
import { Network, Trash2, Plus } from 'lucide-react'
import toast from 'react-hot-toast'
import {
  getIpAllowlist,
  addIpAllowlist,
  deleteIpAllowlist,
  type IPAllowlistEntry,
} from '@/lib/api'

export default function IpAllowlistSection() {
  const [entries, setEntries] = useState<IPAllowlistEntry[]>([])
  const [yourIp, setYourIp] = useState('')
  const [enforced, setEnforced] = useState(false)
  const [loading, setLoading] = useState(true)
  const [cidr, setCidr] = useState('')
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)

  const load = async () => {
    try {
      const data = await getIpAllowlist()
      setEntries(data.entries || [])
      setYourIp(data.your_ip || '')
      setEnforced(!!data.enforced)
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to load IP allowlist')
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
      const res = await addIpAllowlist(cidr.trim(), label.trim() || undefined)
      if (res?.auto_added_your_ip) {
        toast.success(`Added ${res.added}. Your IP (${res.auto_added_your_ip}) was auto-added so you don't lock yourself out.`)
      } else {
        toast.success(`Added ${res?.added ?? cidr.trim()}`)
      }
      setCidr('')
      setLabel('')
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to add IP range')
    } finally {
      setBusy(false)
    }
  }

  const handleDelete = async (entry: IPAllowlistEntry) => {
    if (!window.confirm(`Remove ${entry.cidr} from the allowlist?`)) return
    try {
      await deleteIpAllowlist(entry.id)
      toast.success(`Removed ${entry.cidr}`)
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to remove entry')
    }
  }

  return (
    <div className="card">
      <div className="flex items-start gap-3 mb-4">
        <div className="p-2 bg-cs-indigo-faint rounded-cs-sm">
          <Network className="h-5 w-5 text-cs-indigo" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <h3 className="section-title">Authorized IP Addresses</h3>
            {!loading && (
              enforced
                ? <span className="badge badge-success">Enforcing</span>
                : <span className="badge badge-warning">Not enforced</span>
            )}
          </div>
          <p className="text-sm text-cs-muted">
            Restrict the admin portal to these networks. Agent reporting endpoints are always
            reachable. Loopback is always allowed.
          </p>
        </div>
      </div>

      {!enforced && !loading && (
        <div className="mb-4 p-3 rounded-cs-sm border border-[color-mix(in_srgb,var(--cs-med)_30%,var(--cs-panel))] bg-[color-mix(in_srgb,var(--cs-med)_10%,var(--cs-panel))]">
          <p className="text-sm text-cs-ink-2">
            The allowlist is empty, so this control is currently <strong>off</strong> — the portal
            is reachable from any IP. Add at least one range to start enforcing.
          </p>
        </div>
      )}

      {/* Current entries */}
      {loading ? (
        <p className="text-sm text-cs-muted">Loading…</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-cs-muted mb-4">No authorized IP ranges yet.</p>
      ) : (
        <div className="overflow-x-auto mb-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-cs-muted border-b border-cs-hair-2">
                <th className="py-2 pr-4 font-medium">IP / CIDR</th>
                <th className="py-2 pr-4 font-medium">Label</th>
                <th className="py-2 pr-4 font-medium">Added</th>
                <th className="py-2 w-10"></th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className="border-b border-cs-hair-2 last:border-0">
                  <td className="py-2 pr-4 num text-cs-ink">{e.cidr}</td>
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

      {/* Add form */}
      <form onSubmit={handleAdd} className="flex flex-col sm:flex-row gap-3 sm:items-end pt-2 border-t border-cs-hair-2">
        <div className="flex-1">
          <label className="block text-sm font-medium text-cs-ink-2 mb-1.5">
            IP address or CIDR range
          </label>
          <input
            type="text"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            required
            className="input num"
            placeholder="203.0.113.7  or  203.0.113.0/24"
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
            placeholder="HQ office"
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

      {yourIp && (
        <p className="text-xs text-cs-muted mt-3">
          Your current IP: <span className="num text-cs-ink-2">{yourIp}</span>
        </p>
      )}
    </div>
  )
}
