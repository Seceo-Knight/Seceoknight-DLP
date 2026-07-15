import { useEffect, useState } from 'react'
import { Share2, Trash2, Plus, Radio } from 'lucide-react'
import toast from 'react-hot-toast'
import {
  getSiemConnectors,
  registerSyslogConnector,
  testSiemConnector,
  deleteSiemConnector,
  type SiemConnector,
} from '@/lib/api'

const PROTOCOLS = ['udp', 'tcp', 'tls']
const FORMATS = ['cef', 'leef']
const FACILITIES = ['local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']

const DEFAULT_FORM = {
  name: '',
  host: '',
  port: 514,
  protocol: 'udp',
  log_format: 'cef',
  facility: 'local0',
  min_severity: 'low',
}

export default function SiemForwardingSection() {
  const [connectors, setConnectors] = useState<SiemConnector[]>([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState({ ...DEFAULT_FORM })
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState<string | null>(null)

  const load = async () => {
    try {
      setConnectors(await getSiemConnectors())
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to load SIEM connectors')
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
      await registerSyslogConnector({ ...form, port: Number(form.port) })
      toast.success(`Connector "${form.name}" added`)
      setForm({ ...DEFAULT_FORM })
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to add connector')
    } finally {
      setBusy(false)
    }
  }

  const handleTest = async (name: string) => {
    setTesting(name)
    try {
      const res = await testSiemConnector(name)
      if (res?.success) toast.success(res.message || 'Test record sent')
      else toast.error(res?.error || 'Test failed')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Test failed')
    } finally {
      setTesting(null)
    }
  }

  const handleDelete = async (name: string) => {
    if (!window.confirm(`Remove SIEM connector "${name}"?`)) return
    try {
      await deleteSiemConnector(name)
      toast.success(`Removed "${name}"`)
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to remove connector')
    }
  }

  const set = (k: string, v: string | number) => setForm((f) => ({ ...f, [k]: v }))

  return (
    <div className="card">
      <div className="flex items-center gap-3 mb-6 pb-5 border-b border-border">
        <div className="p-2.5 bg-indigo-500/10 rounded-xl border border-indigo-500/20">
          <Share2 className="h-5 w-5 text-indigo-400" />
        </div>
        <div>
          <h2 className="font-semibold text-foreground">SIEM Log Forwarding</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Forward DLP events over syslog (RFC 5424, CEF/LEEF) to Wazuh, QRadar, ArcSight, or any
            on-prem SIEM. Each connector only receives events at or above its severity threshold.
          </p>
        </div>
      </div>

      {/* Existing connectors */}
      {loading ? (
        <p className="text-sm text-muted-foreground mb-4">Loading…</p>
      ) : connectors.length === 0 ? (
        <p className="text-sm text-muted-foreground mb-4">No SIEM connectors configured yet.</p>
      ) : (
        <div className="overflow-x-auto mb-5">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Destination</th>
                <th>Transport</th>
                <th>Format</th>
                <th>Min severity</th>
                <th>Status</th>
                <th className="w-24" />
              </tr>
            </thead>
            <tbody>
              {connectors.map((c) => (
                <tr key={c.name}>
                  <td className="font-medium text-foreground">{c.name}</td>
                  <td className="font-mono text-xs text-foreground/90">
                    {c.host ? `${c.host}:${c.port}` : c.siem_type}
                  </td>
                  <td className="uppercase text-muted-foreground">{c.protocol || c.siem_type}</td>
                  <td className="uppercase text-muted-foreground">{c.format || '—'}</td>
                  <td className="capitalize text-muted-foreground">{c.min_severity || '—'}</td>
                  <td>
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wide ${
                      c.connected
                        ? 'bg-green-500/15 text-green-400'
                        : 'bg-red-500/10 text-red-400 border border-red-500/20'
                    }`}>
                      {c.connected ? 'Connected' : 'Down'}
                    </span>
                  </td>
                  <td>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleTest(c.name)}
                        disabled={testing === c.name}
                        className="p-1.5 rounded-lg text-muted-foreground/70 hover:text-indigo-400 hover:bg-indigo-500/10 transition-colors disabled:opacity-50"
                        title="Send test record"
                      >
                        <Radio className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(c.name)}
                        className="p-1.5 rounded-lg text-muted-foreground/70 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        title="Remove"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Add syslog connector */}
      <form onSubmit={handleAdd} className="space-y-4 pt-4 border-t border-border">
        <span className="text-sm font-semibold text-foreground">Add a syslog connector</span>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Name</label>
            <input className="input" value={form.name} required
              onChange={(e) => set('name', e.target.value)} placeholder="wazuh-prod" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Host / IP</label>
            <input className="input font-mono" value={form.host} required
              onChange={(e) => set('host', e.target.value)} placeholder="10.20.0.15" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Port</label>
            <input className="input font-mono" type="number" value={form.port} required min={1} max={65535}
              onChange={(e) => set('port', Number(e.target.value))} />
          </div>
          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Transport</label>
            <select className="input uppercase" value={form.protocol}
              onChange={(e) => set('protocol', e.target.value)}>
              {PROTOCOLS.map((p) => <option key={p} value={p}>{p.toUpperCase()}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Format</label>
            <select className="input uppercase" value={form.log_format}
              onChange={(e) => set('log_format', e.target.value)}>
              {FORMATS.map((p) => <option key={p} value={p}>{p.toUpperCase()}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Facility</label>
            <select className="input" value={form.facility}
              onChange={(e) => set('facility', e.target.value)}>
              {FACILITIES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">Min severity</label>
            <select className="input capitalize" value={form.min_severity}
              onChange={(e) => set('min_severity', e.target.value)}>
              {SEVERITIES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>
        </div>
        <button type="submit" disabled={busy}
          className="flex items-center gap-2 px-5 py-2 bg-blue-600 text-white text-sm font-semibold rounded-xl hover:bg-blue-700 disabled:opacity-60 transition-colors">
          <Plus className="h-4 w-4" />
          {busy ? 'Adding…' : 'Add connector'}
        </button>
      </form>
    </div>
  )
}
