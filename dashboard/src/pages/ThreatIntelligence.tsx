import { useEffect, useState } from 'react'
import { ShieldAlert, Plus, Trash2, Share2, Upload, Rss, RefreshCw, Radar, Server, Copy, Check } from 'lucide-react'
import toast from 'react-hot-toast'
import {
  getIocs, getIocStats, addIoc, deleteIoc, shareIoc, importIocs,
  getTaxiiFeeds, addTaxiiFeed, deleteTaxiiFeed, pollTaxiiFeed, getIocMatches,
  getSharingConfig, updateSharingConfig,
  type IOC, type TaxiiFeed, type IocStats, type SharingConfig,
} from '@/lib/api'

const IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'email', 'file_sha256', 'file_sha1', 'file_md5']
const TLPS = ['white', 'green', 'amber', 'red']

const tlpClass: Record<string, string> = {
  white: 'bg-cs-hair-2 text-cs-ink-2',
  green: 'badge-success',
  amber: 'badge-warning',
  red: 'badge-danger',
}

export default function ThreatIntelligence() {
  const [stats, setStats] = useState<IocStats | null>(null)
  const [iocs, setIocs] = useState<IOC[]>([])
  const [feeds, setFeeds] = useState<TaxiiFeed[]>([])
  const [matches, setMatches] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [polling, setPolling] = useState<string | null>(null)

  const [iocForm, setIocForm] = useState({ ioc_type: 'ipv4', value: '', tlp: 'amber' })
  const [importForm, setImportForm] = useState({ format: 'csv' as 'csv' | 'stix', content: '' })
  const [feedForm, setFeedForm] = useState({ name: '', server_url: '', collection_id: '', username: '', password: '' })

  const [sharing, setSharing] = useState<SharingConfig | null>(null)
  const [shareForm, setShareForm] = useState({ enabled: false, username: '', password: '' })
  const [savingShare, setSavingShare] = useState(false)
  const [copied, setCopied] = useState(false)

  const load = async () => {
    try {
      const [s, i, f, m, sh] = await Promise.all([
        getIocStats(), getIocs(), getTaxiiFeeds(), getIocMatches(), getSharingConfig(),
      ])
      setStats(s); setIocs(i); setFeeds(f); setMatches(m)
      setSharing(sh); setShareForm({ enabled: sh.enabled, username: sh.username, password: '' })
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to load threat intel')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [])

  const shareUrl = sharing ? `${window.location.origin}${sharing.taxii_path}` : ''

  const handleSaveSharing = async (e: React.FormEvent) => {
    e.preventDefault()
    setSavingShare(true)
    try {
      const body: { enabled: boolean; username?: string; password?: string } = {
        enabled: shareForm.enabled,
        username: shareForm.username || undefined,
      }
      if (shareForm.password) body.password = shareForm.password
      const sh = await updateSharingConfig(body)
      setSharing(sh); setShareForm({ enabled: sh.enabled, username: sh.username, password: '' })
      toast.success(sh.enabled ? 'Partner sharing enabled' : 'Partner sharing disabled')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to save sharing config')
    } finally {
      setSavingShare(false)
    }
  }

  const copyUrl = async () => {
    try { await navigator.clipboard.writeText(shareUrl); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* noop */ }
  }

  const handleAddIoc = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await addIoc({ ...iocForm })
      toast.success('Indicator added')
      setIocForm({ ioc_type: 'ipv4', value: '', tlp: 'amber' })
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to add indicator')
    }
  }

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const res = await importIocs(importForm.format, importForm.content)
      toast.success(`Imported ${res.created} new of ${res.processed}`)
      setImportForm({ ...importForm, content: '' })
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Import failed')
    }
  }

  const handleShare = async (i: IOC) => {
    try {
      await shareIoc(i.id, !i.is_shared)
      setIocs((xs) => xs.map((x) => x.id === i.id ? { ...x, is_shared: !i.is_shared } : x))
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to update sharing')
    }
  }

  const handleDeleteIoc = async (i: IOC) => {
    if (!window.confirm(`Delete indicator ${i.value}?`)) return
    try {
      await deleteIoc(i.id); toast.success('Deleted'); await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Delete failed')
    }
  }

  const handleAddFeed = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await addTaxiiFeed({
        name: feedForm.name, server_url: feedForm.server_url,
        collection_id: feedForm.collection_id || undefined,
        username: feedForm.username || undefined,
        password: feedForm.password || undefined,
      })
      toast.success('Feed added')
      setFeedForm({ name: '', server_url: '', collection_id: '', username: '', password: '' })
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to add feed')
    }
  }

  const handlePoll = async (f: TaxiiFeed) => {
    setPolling(f.id)
    try {
      const res = await pollTaxiiFeed(f.id)
      if (res?.ok) toast.success(`${f.name}: +${res.created} new / ${res.seen} indicators`)
      else toast.error(`${f.name}: ${res?.error || 'poll failed'}`)
      await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Poll failed')
    } finally {
      setPolling(null)
    }
  }

  const handleDeleteFeed = async (f: TaxiiFeed) => {
    if (!window.confirm(`Remove feed "${f.name}"?`)) return
    try {
      await deleteTaxiiFeed(f.id); toast.success('Removed'); await load()
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Delete failed')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="eyebrow mb-1.5">Threat Intelligence</p>
        <h1 className="text-2xl font-bold tracking-tight text-cs-ink">Indicators of Compromise</h1>
        <p className="mt-1 text-sm text-cs-ink-2">
          Ingest IOCs from TAXII 2.1 feeds, match them against DLP activity, and share curated
          indicators with partner vendors over STIX 2.1.
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total IOCs', value: stats?.total ?? '—' },
          { label: 'Active', value: stats?.active ?? '—' },
          { label: 'Shared out', value: stats?.shared ?? '—' },
          { label: 'TAXII feeds', value: stats?.feeds ?? '—' },
        ].map((s) => (
          <div key={s.label} className="card">
            <p className="text-sm text-cs-muted">{s.label}</p>
            <p className="text-2xl font-bold text-cs-ink num mt-1">{s.value}</p>
          </div>
        ))}
      </div>

      {/* Partner sharing — TAXII server config */}
      <div className="card">
        <div className="flex items-start gap-3 mb-4">
          <div className="p-2 bg-cs-indigo-faint rounded-cs-sm"><Server className="h-5 w-5 text-cs-indigo" /></div>
          <div className="flex-1">
            <h3 className="section-title">Partner Sharing — TAXII 2.1 Server</h3>
            <p className="text-sm text-cs-muted">
              Enable the outbound TAXII server and set the credential partner vendors use to poll your
              shared indicators. Only IOCs you mark <strong>Share</strong> below are published.
            </p>
          </div>
          <span className={`badge ${sharing?.enabled ? 'badge-success' : 'bg-cs-hair-2 text-cs-ink-2'}`}>
            {sharing?.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        <form onSubmit={handleSaveSharing} className="space-y-4">
          <label className="flex items-center gap-2.5 cursor-pointer select-none">
            <input type="checkbox" className="h-4 w-4 accent-cs-indigo" checked={shareForm.enabled}
              onChange={(e) => setShareForm({ ...shareForm, enabled: e.target.checked })} />
            <span className="text-sm font-medium text-cs-ink">Enable partner sharing</span>
          </label>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-cs-muted mb-1">Partner username</label>
              <input className="input" value={shareForm.username} placeholder="partner"
                onChange={(e) => setShareForm({ ...shareForm, username: e.target.value })} />
            </div>
            <div>
              <label className="block text-xs font-medium text-cs-muted mb-1">Partner password</label>
              <input className="input" type="password" value={shareForm.password}
                placeholder={sharing?.has_password ? '•••••••• (unchanged — blank keeps it)' : 'set a partner password'}
                onChange={(e) => setShareForm({ ...shareForm, password: e.target.value })} />
            </div>
          </div>

          {sharing?.source === 'environment' && (
            <p className="text-xs text-cs-muted">
              Currently set via environment variable. Saving here stores the credential in the database
              (Fernet-encrypted) and takes over.
            </p>
          )}

          <button type="submit" disabled={savingShare}
            className="btn-primary inline-flex items-center gap-2 disabled:opacity-50">
            <Server className="h-4 w-4" />{savingShare ? 'Saving…' : 'Save sharing settings'}
          </button>
        </form>

        {/* Partner-facing endpoint to hand out */}
        <div className="mt-5 pt-4 border-t border-cs-hair-2">
          <p className="text-xs font-medium text-cs-muted mb-2">Give partners this TAXII 2.1 discovery URL</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 num text-xs bg-cs-hair-2 text-cs-ink-2 rounded-cs-sm px-3 py-2 break-all">{shareUrl || '—'}</code>
            <button type="button" onClick={copyUrl} title="Copy URL"
              className="p-2 rounded-cs-sm text-cs-muted-2 hover:text-cs-indigo hover:bg-cs-indigo-faint transition-colors">
              {copied ? <Check className="h-4 w-4 text-cs-indigo" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
          <p className="text-xs text-cs-muted mt-2">
            Collection <span className="num">{sharing?.collection_id || 'dlp-shared-iocs'}</span> · partners authenticate with HTTP Basic using the credential above.
          </p>
        </div>
      </div>

      {/* Recent matches */}
      <div className="card">
        <div className="flex items-start gap-3 mb-4">
          <div className="p-2 bg-cs-indigo-faint rounded-cs-sm"><Radar className="h-5 w-5 text-cs-indigo" /></div>
          <div>
            <h3 className="section-title">Recent IOC Matches</h3>
            <p className="text-sm text-cs-muted">DLP events whose destination or file hash matched an ingested indicator.</p>
          </div>
        </div>
        {matches.length === 0 ? (
          <p className="text-sm text-cs-muted">No matches yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-cs-muted border-b border-cs-hair-2">
                <th className="py-2 pr-4 font-medium">When</th>
                <th className="py-2 pr-4 font-medium">Event</th>
                <th className="py-2 pr-4 font-medium">Matched indicator(s)</th>
              </tr></thead>
              <tbody>
                {matches.map((m, idx) => (
                  <tr key={idx} className="border-b border-cs-hair-2 last:border-0">
                    <td className="py-2 pr-4 num text-cs-muted">{m.timestamp ? new Date(m.timestamp).toLocaleString() : '—'}</td>
                    <td className="py-2 pr-4 text-cs-ink-2">{m.event_type} · {m.destination || m.file_path || '—'}</td>
                    <td className="py-2 pr-4 num text-cs-ink">
                      {(m.matches || []).map((x: any) => `${x.ioc_type}:${x.value}`).join(', ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* IOC list + add */}
      <div className="card">
        <div className="flex items-start gap-3 mb-4">
          <div className="p-2 bg-cs-indigo-faint rounded-cs-sm"><ShieldAlert className="h-5 w-5 text-cs-indigo" /></div>
          <div><h3 className="section-title">Indicators</h3>
            <p className="text-sm text-cs-muted">Toggle <strong>Share</strong> to publish an indicator to partner vendors via the TAXII server.</p></div>
        </div>

        <form onSubmit={handleAddIoc} className="flex flex-col sm:flex-row gap-3 sm:items-end mb-5">
          <div>
            <label className="block text-xs font-medium text-cs-muted mb-1">Type</label>
            <select className="input" value={iocForm.ioc_type} onChange={(e) => setIocForm({ ...iocForm, ioc_type: e.target.value })}>
              {IOC_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div className="flex-1">
            <label className="block text-xs font-medium text-cs-muted mb-1">Value</label>
            <input className="input num" required value={iocForm.value}
              onChange={(e) => setIocForm({ ...iocForm, value: e.target.value })} placeholder="203.0.113.10 / evil.example / <hash>" />
          </div>
          <div>
            <label className="block text-xs font-medium text-cs-muted mb-1">TLP</label>
            <select className="input" value={iocForm.tlp} onChange={(e) => setIocForm({ ...iocForm, tlp: e.target.value })}>
              {TLPS.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <button type="submit" className="btn-primary inline-flex items-center gap-2"><Plus className="h-4 w-4" />Add</button>
        </form>

        {loading ? <p className="text-sm text-cs-muted">Loading…</p> : iocs.length === 0 ? (
          <p className="text-sm text-cs-muted">No indicators yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-cs-muted border-b border-cs-hair-2">
                <th className="py-2 pr-4 font-medium">Type</th>
                <th className="py-2 pr-4 font-medium">Value</th>
                <th className="py-2 pr-4 font-medium">TLP</th>
                <th className="py-2 pr-4 font-medium">Source</th>
                <th className="py-2 pr-4 font-medium">Shared</th>
                <th className="py-2 w-10"></th>
              </tr></thead>
              <tbody>
                {iocs.map((i) => (
                  <tr key={i.id} className="border-b border-cs-hair-2 last:border-0">
                    <td className="py-2 pr-4 text-cs-ink-2">{i.ioc_type}</td>
                    <td className="py-2 pr-4 num text-cs-ink break-all">{i.value}</td>
                    <td className="py-2 pr-4"><span className={`badge ${tlpClass[i.tlp || 'amber']}`}>{(i.tlp || 'amber').toUpperCase()}</span></td>
                    <td className="py-2 pr-4 text-cs-muted">{i.source}</td>
                    <td className="py-2 pr-4">
                      <button onClick={() => handleShare(i)}
                        className={`inline-flex items-center gap-1.5 text-xs font-medium px-2 py-1 rounded-cs-pill transition-colors ${i.is_shared ? 'bg-cs-indigo-faint text-cs-indigo' : 'text-cs-muted-2 hover:text-cs-ink-2'}`}>
                        <Share2 className="h-3.5 w-3.5" />{i.is_shared ? 'Shared' : 'Share'}
                      </button>
                    </td>
                    <td className="py-2">
                      <button onClick={() => handleDeleteIoc(i)} title="Delete"
                        className="p-1.5 rounded-cs-sm text-cs-muted-2 hover:text-cs-crit hover:bg-[color-mix(in_srgb,var(--cs-crit)_10%,var(--cs-panel))] transition-colors">
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Import */}
      <div className="card">
        <div className="flex items-start gap-3 mb-4">
          <div className="p-2 bg-cs-indigo-faint rounded-cs-sm"><Upload className="h-5 w-5 text-cs-indigo" /></div>
          <div><h3 className="section-title">Bulk Import</h3>
            <p className="text-sm text-cs-muted">Paste CSV (<span className="num">type,value</span> per line) or a STIX 2.1 bundle.</p></div>
        </div>
        <form onSubmit={handleImport} className="space-y-3">
          <div className="flex gap-3 items-center">
            <label className="text-sm text-cs-ink-2">Format</label>
            <select className="input max-w-[140px]" value={importForm.format}
              onChange={(e) => setImportForm({ ...importForm, format: e.target.value as 'csv' | 'stix' })}>
              <option value="csv">CSV</option>
              <option value="stix">STIX bundle</option>
            </select>
          </div>
          <textarea className="input font-mono text-xs h-32" value={importForm.content} required
            onChange={(e) => setImportForm({ ...importForm, content: e.target.value })}
            placeholder={importForm.format === 'csv' ? 'ipv4,203.0.113.10\ndomain,evil.example' : '{ "type": "bundle", "objects": [ ... ] }'} />
          <button type="submit" className="btn-primary inline-flex items-center gap-2"><Upload className="h-4 w-4" />Import</button>
        </form>
      </div>

      {/* TAXII feeds */}
      <div className="card">
        <div className="flex items-start gap-3 mb-4">
          <div className="p-2 bg-cs-indigo-faint rounded-cs-sm"><Rss className="h-5 w-5 text-cs-indigo" /></div>
          <div><h3 className="section-title">TAXII 2.1 Feeds</h3>
            <p className="text-sm text-cs-muted">Remote collections we poll for indicators.</p></div>
        </div>

        {feeds.length > 0 && (
          <div className="overflow-x-auto mb-5">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-cs-muted border-b border-cs-hair-2">
                <th className="py-2 pr-4 font-medium">Name</th>
                <th className="py-2 pr-4 font-medium">Server</th>
                <th className="py-2 pr-4 font-medium">Last poll</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">Imported</th>
                <th className="py-2 w-24"></th>
              </tr></thead>
              <tbody>
                {feeds.map((f) => (
                  <tr key={f.id} className="border-b border-cs-hair-2 last:border-0">
                    <td className="py-2 pr-4 font-medium text-cs-ink">{f.name}</td>
                    <td className="py-2 pr-4 num text-cs-ink-2 break-all">{f.server_url}</td>
                    <td className="py-2 pr-4 num text-cs-muted">{f.last_polled_at ? new Date(f.last_polled_at).toLocaleString() : 'never'}</td>
                    <td className="py-2 pr-4 text-cs-muted">{f.last_status || '—'}</td>
                    <td className="py-2 pr-4 num text-cs-ink-2">{f.total_imported}</td>
                    <td className="py-2">
                      <div className="flex items-center gap-1">
                        <button onClick={() => handlePoll(f)} disabled={polling === f.id} title="Poll now"
                          className="p-1.5 rounded-cs-sm text-cs-muted-2 hover:text-cs-indigo hover:bg-cs-indigo-faint transition-colors disabled:opacity-50">
                          <RefreshCw className={`h-4 w-4 ${polling === f.id ? 'animate-spin' : ''}`} />
                        </button>
                        <button onClick={() => handleDeleteFeed(f)} title="Remove"
                          className="p-1.5 rounded-cs-sm text-cs-muted-2 hover:text-cs-crit hover:bg-[color-mix(in_srgb,var(--cs-crit)_10%,var(--cs-panel))] transition-colors">
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

        <form onSubmit={handleAddFeed} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <input className="input" required placeholder="Feed name" value={feedForm.name}
            onChange={(e) => setFeedForm({ ...feedForm, name: e.target.value })} />
          <input className="input num" required placeholder="https://taxii.example/api/" value={feedForm.server_url}
            onChange={(e) => setFeedForm({ ...feedForm, server_url: e.target.value })} />
          <input className="input num" placeholder="Collection ID (optional)" value={feedForm.collection_id}
            onChange={(e) => setFeedForm({ ...feedForm, collection_id: e.target.value })} />
          <input className="input" placeholder="Username (optional)" value={feedForm.username}
            onChange={(e) => setFeedForm({ ...feedForm, username: e.target.value })} />
          <input className="input" type="password" placeholder="Password/token (optional)" value={feedForm.password}
            onChange={(e) => setFeedForm({ ...feedForm, password: e.target.value })} />
          <button type="submit" className="btn-primary inline-flex items-center gap-2 justify-center"><Plus className="h-4 w-4" />Add feed</button>
        </form>
      </div>
    </div>
  )
}
