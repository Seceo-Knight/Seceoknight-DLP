import { useState, useEffect, useCallback } from 'react'
import {
  BarChart2,
  Download,
  RefreshCw,
  Plus,
  X,
  CheckCircle,
  Clock,
  AlertCircle,
  Loader2,
  FileText,
  Trash2,
  Mail,
  Calendar,
} from 'lucide-react'
import toast from 'react-hot-toast'
import {
  getReports,
  getReportsSummary,
  generateReport,
  downloadReportBlob,
  deleteReport,
} from '@/lib/api'
import { useAuthStore } from '@/lib/store/auth'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Report {
  id: string
  name: string
  report_type: string
  frequency: string
  status: 'pending' | 'generating' | 'completed' | 'failed'
  generated_by?: string
  period_start?: string
  period_end?: string
  formats?: string[]
  recipients?: string[]
  has_pdf: boolean
  has_csv: boolean
  file_size_bytes?: number
  error_message?: string
  email_sent?: string
  summary?: Record<string, any>
  created_at: string
  completed_at?: string
}

interface Summary {
  total: number
  pending: number
  generating: number
  completed: number
  failed: number
  recent_completed: Report[]
}

// ── Constants ─────────────────────────────────────────────────────────────────

const REPORT_TYPES = [
  { value: 'summary', label: 'Executive Summary' },
  { value: 'violations', label: 'Policy Violations' },
  { value: 'trends', label: 'Incident Trends' },
  { value: 'violators', label: 'Top Violators' },
  { value: 'policies', label: 'Policy Effectiveness' },
  { value: 'compliance', label: 'Compliance Report' },
  { value: 'incident_detail', label: 'Incident Detail Report' },
  { value: 'gdpr_art30', label: 'GDPR Article 30 (Records of Processing)' },
  { value: 'hipaa_breach', label: 'HIPAA Breach Notification' },
  { value: 'pci_scope', label: 'PCI DSS Scope Report' },
]

const STATUS_CONFIG = {
  pending:    { icon: Clock,       color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20', label: 'Pending' },
  generating: { icon: Loader2,     color: 'text-blue-400',   bg: 'bg-blue-500/10 border-blue-500/20',   label: 'Generating' },
  completed:  { icon: CheckCircle, color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/20', label: 'Completed' },
  failed:     { icon: AlertCircle, color: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/20',     label: 'Failed' },
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmt(dt?: string) {
  if (!dt) return '—'
  return new Date(dt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
}

function fmtDate(dt?: string) {
  if (!dt) return '—'
  return new Date(dt).toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata' })
}

function fmtSize(bytes?: number) {
  if (!bytes) return ''
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function defaultStartDate() {
  const d = new Date()
  d.setDate(d.getDate() - 30)
  return d.toISOString().slice(0, 16)
}

function defaultEndDate() {
  return new Date().toISOString().slice(0, 16)
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
      <p className="text-xs text-muted-foreground/70 uppercase tracking-wide mb-1">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value}</p>
    </div>
  )
}

function StatusBadge({ status }: { status: Report['status'] }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border ${cfg.bg} ${cfg.color}`}>
      <Icon className={`w-3 h-3 ${status === 'generating' ? 'animate-spin' : ''}`} />
      {cfg.label}
    </span>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function Reports() {
  const { user } = useAuthStore()
  const isAdmin = (user as any)?.role === 'admin' || (user as any)?.role === 'ADMIN'

  // Data state
  const [reports, setReports] = useState<Report[]>([])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  // Filters
  const [filterStatus, setFilterStatus] = useState('')
  const [filterType, setFilterType] = useState('')

  // Generate form
  const [showForm, setShowForm] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [form, setForm] = useState({
    name: '',
    report_types: ['summary'] as string[],
    start_date: defaultStartDate(),
    end_date: defaultEndDate(),
    formats: ['pdf'] as string[],
    recipients: '',
  })

  // Download state
  const [downloading, setDownloading] = useState<string>('')

  // ── Fetch ───────────────────────────────────────────────────────────────────

  const fetchAll = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    try {
      const params: any = { limit: 100 }
      if (filterStatus) params.status = filterStatus
      if (filterType) params.report_type = filterType
      const [list, summ] = await Promise.all([
        getReports(params),
        getReportsSummary().catch(() => null),
      ])
      setReports(Array.isArray(list) ? list : [])
      if (summ) setSummary(summ)
    } catch {
      toast.error('Failed to load reports')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [filterStatus, filterType])

  useEffect(() => { fetchAll() }, [fetchAll])

  // Auto-refresh while any report is pending/generating
  useEffect(() => {
    const hasPending = reports.some(r => r.status === 'pending' || r.status === 'generating')
    if (!hasPending) return
    const timer = setInterval(() => fetchAll(true), 5000)
    return () => clearInterval(timer)
  }, [reports, fetchAll])

  // ── Actions ─────────────────────────────────────────────────────────────────

  const handleGenerate = async () => {
    if (!form.name.trim()) { toast.error('Report name is required'); return }
    if (form.report_types.length === 0) { toast.error('Select at least one report type'); return }
    if (!form.start_date || !form.end_date) { toast.error('Date range is required'); return }
    if (new Date(form.start_date) >= new Date(form.end_date)) {
      toast.error('Start date must be before end date'); return
    }

    setGenerating(true)
    try {
      await generateReport({
        name: form.name.trim(),
        report_types: form.report_types,
        start_date: new Date(form.start_date).toISOString(),
        end_date: new Date(form.end_date).toISOString(),
        formats: form.formats,
        recipients: form.recipients.split(',').map(s => s.trim()).filter(Boolean),
      })
      toast.success('Report queued — it will appear below when ready')
      setShowForm(false)
      setForm({ name: '', report_types: ['summary'], start_date: defaultStartDate(), end_date: defaultEndDate(), formats: ['pdf'], recipients: '' })
      await fetchAll()
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Failed to queue report')
    } finally {
      setGenerating(false)
    }
  }

  const handleDownload = async (report: Report, fmt: 'pdf' | 'csv') => {
    const key = `${report.id}-${fmt}`
    setDownloading(key)
    try {
      const response = await downloadReportBlob(report.id, fmt)
      const blob = new Blob([response.data], {
        type: fmt === 'pdf' ? 'application/pdf' : 'text/csv',
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const period = report.period_start ? `_${fmtDate(report.period_start).replace(/\//g, '-')}` : ''
      a.download = `${report.name.replace(/\s+/g, '_')}${period}.${fmt}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || `Failed to download ${fmt.toUpperCase()}`)
    } finally {
      setDownloading('')
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this report and its files? This cannot be undone.')) return
    try {
      await deleteReport(id)
      toast.success('Report deleted')
      setReports(prev => prev.filter(r => r.id !== id))
    } catch {
      toast.error('Failed to delete report')
    }
  }

  const toggleReportType = (val: string) => {
    setForm(prev => ({
      ...prev,
      report_types: prev.report_types.includes(val)
        ? prev.report_types.filter(t => t !== val)
        : [...prev.report_types, val],
    }))
  }

  const toggleFormat = (val: string) => {
    setForm(prev => ({
      ...prev,
      formats: prev.formats.includes(val)
        ? prev.formats.filter(f => f !== val)
        : [...prev.formats, val],
    }))
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 text-indigo-400 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <BarChart2 className="w-6 h-6 text-indigo-400" />
          <div>
            <h1 className="text-xl font-bold text-white">Reports &amp; Compliance</h1>
            <p className="text-sm text-muted-foreground/70">Generate and download compliance reports</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchAll(true)}
            disabled={refreshing}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-gray-700 hover:bg-gray-600 text-muted-foreground/50 rounded-lg transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowForm(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Generate Report
          </button>
        </div>
      </div>

      {/* Stats */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard label="Total" value={summary.total} color="text-white" />
          <StatCard label="Completed" value={summary.completed} color="text-green-400" />
          <StatCard label="Generating" value={summary.pending + summary.generating} color="text-blue-400" />
          <StatCard label="Failed" value={summary.failed} color="text-red-400" />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <select
          value={filterStatus}
          onChange={e => setFilterStatus(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-muted-foreground/50 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Statuses</option>
          <option value="completed">Completed</option>
          <option value="generating">Generating</option>
          <option value="pending">Pending</option>
          <option value="failed">Failed</option>
        </select>
        <select
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-muted-foreground/50 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Types</option>
          {REPORT_TYPES.map(t => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
        <span className="text-sm text-muted-foreground/70">{reports.length} report{reports.length !== 1 ? 's' : ''}</span>
      </div>

      {/* Reports Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
        {reports.length === 0 ? (
          <div className="text-center py-16">
            <BarChart2 className="w-12 h-12 text-muted-foreground mx-auto mb-3" />
            <p className="text-muted-foreground/70 font-medium">No reports yet</p>
            <p className="text-muted-foreground text-sm mt-1">Click "Generate Report" to create your first compliance report</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 bg-gray-900/40">
                  <th className="text-left px-4 py-3 text-muted-foreground/70 font-medium">Report</th>
                  <th className="text-left px-4 py-3 text-muted-foreground/70 font-medium">Type</th>
                  <th className="text-left px-4 py-3 text-muted-foreground/70 font-medium">Period</th>
                  <th className="text-left px-4 py-3 text-muted-foreground/70 font-medium">Status</th>
                  <th className="text-left px-4 py-3 text-muted-foreground/70 font-medium">Email</th>
                  <th className="text-right px-4 py-3 text-muted-foreground/70 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {reports.map(report => (
                  <tr key={report.id} className="hover:bg-gray-700/30 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-medium text-white">{report.name}</div>
                      <div className="text-xs text-muted-foreground mt-0.5">
                        {fmt(report.created_at)}
                        {report.file_size_bytes ? ` · ${fmtSize(report.file_size_bytes)}` : ''}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-block px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs">
                        {REPORT_TYPES.find(t => t.value === report.report_type)?.label || report.report_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-muted-foreground/70 text-xs">
                      <div className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {fmtDate(report.period_start)} – {fmtDate(report.period_end)}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={report.status} />
                      {report.status === 'failed' && report.error_message && (
                        <p className="text-red-400 text-xs mt-1 max-w-xs truncate" title={report.error_message}>
                          {report.error_message}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {report.email_sent === 'yes' ? (
                        <span className="flex items-center gap-1 text-xs text-green-400">
                          <Mail className="w-3 h-3" /> Sent
                        </span>
                      ) : report.email_sent === 'no' ? (
                        <span className="text-xs text-red-400">Failed</span>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1 justify-end">
                        {report.status === 'completed' && report.has_pdf && (
                          <button
                            onClick={() => handleDownload(report, 'pdf')}
                            disabled={downloading === `${report.id}-pdf`}
                            title="Download PDF"
                            className="flex items-center gap-1 px-2 py-1 text-xs bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-300 rounded transition-colors disabled:opacity-50"
                          >
                            {downloading === `${report.id}-pdf`
                              ? <Loader2 className="w-3 h-3 animate-spin" />
                              : <Download className="w-3 h-3" />}
                            PDF
                          </button>
                        )}
                        {report.status === 'completed' && report.has_csv && (
                          <button
                            onClick={() => handleDownload(report, 'csv')}
                            disabled={downloading === `${report.id}-csv`}
                            title="Download CSV"
                            className="flex items-center gap-1 px-2 py-1 text-xs bg-green-500/10 hover:bg-green-500/20 border border-green-500/20 text-green-300 rounded transition-colors disabled:opacity-50"
                          >
                            {downloading === `${report.id}-csv`
                              ? <Loader2 className="w-3 h-3 animate-spin" />
                              : <Download className="w-3 h-3" />}
                            CSV
                          </button>
                        )}
                        {isAdmin && (
                          <button
                            onClick={() => handleDelete(report.id)}
                            title="Delete"
                            className="p-1 text-muted-foreground hover:text-red-400 transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Scheduled reports info */}
      <div className="bg-indigo-900/20 border border-indigo-500/20 rounded-xl p-4">
        <div className="flex items-start gap-3">
          <Clock className="w-5 h-5 text-indigo-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-sm font-medium text-indigo-300">Scheduled Reports</p>
            <p className="text-sm text-muted-foreground/70 mt-1">
              Automated reports run on a fixed schedule: daily at 8:00 AM UTC, weekly every Monday at 9:00 AM UTC,
              and monthly on the 1st at 10:00 AM UTC. Configure recipients and SMTP settings in your <code className="text-indigo-300">.env</code> file.
            </p>
          </div>
        </div>
      </div>

      {/* Generate Report Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-gray-800 border border-gray-700 rounded-2xl w-full max-w-lg shadow-2xl">
            {/* Modal header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-indigo-400" />
                <h2 className="text-lg font-semibold text-white">Generate Report</h2>
              </div>
              <button onClick={() => setShowForm(false)} className="text-muted-foreground/70 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-6 py-5 space-y-5">
              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-muted-foreground/50 mb-1">Report Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="e.g. Q2 Compliance Summary"
                  className="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
                />
              </div>

              {/* Report types */}
              <div>
                <label className="block text-sm font-medium text-muted-foreground/50 mb-2">Report Types</label>
                <div className="grid grid-cols-2 gap-2">
                  {REPORT_TYPES.map(t => (
                    <label key={t.value} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={form.report_types.includes(t.value)}
                        onChange={() => toggleReportType(t.value)}
                        className="accent-indigo-500"
                      />
                      <span className="text-sm text-muted-foreground/50">{t.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Date range */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm font-medium text-muted-foreground/50 mb-1">From</label>
                  <input
                    type="datetime-local"
                    value={form.start_date}
                    onChange={e => setForm(prev => ({ ...prev, start_date: e.target.value }))}
                    className="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-muted-foreground/50 mb-1">To</label>
                  <input
                    type="datetime-local"
                    value={form.end_date}
                    onChange={e => setForm(prev => ({ ...prev, end_date: e.target.value }))}
                    className="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              {/* Formats */}
              <div>
                <label className="block text-sm font-medium text-muted-foreground/50 mb-2">Output Formats</label>
                <div className="flex gap-4">
                  {['pdf', 'csv'].map(f => (
                    <label key={f} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={form.formats.includes(f)}
                        onChange={() => toggleFormat(f)}
                        className="accent-indigo-500"
                      />
                      <span className="text-sm text-muted-foreground/50 uppercase">{f}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Recipients */}
              <div>
                <label className="block text-sm font-medium text-muted-foreground/50 mb-1">
                  Email Recipients <span className="text-muted-foreground font-normal">(optional, comma-separated)</span>
                </label>
                <input
                  type="text"
                  value={form.recipients}
                  onChange={e => setForm(prev => ({ ...prev, recipients: e.target.value }))}
                  placeholder="ciso@company.com, security@company.com"
                  className="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            {/* Modal footer */}
            <div className="flex gap-3 px-6 py-4 border-t border-gray-700">
              <button
                onClick={() => setShowForm(false)}
                className="flex-1 px-4 py-2 text-sm text-muted-foreground/50 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerate}
                disabled={generating}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {generating ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Queueing...</>
                ) : (
                  <><BarChart2 className="w-4 h-4" /> Generate</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
