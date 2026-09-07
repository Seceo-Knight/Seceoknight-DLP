import { useState, useEffect, useCallback } from 'react'
import {
  BarChart2,
  Download,
  RefreshCw,
  Plus,
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
import { PageHeader } from '@/components/ui/page-header'
import { Button } from '@/components/ui/button'
import StatsCard from '@/components/StatsCard'
import { DataPagination } from '@/components/ui/pagination'
import { EmptyState } from '@/components/ui/empty-state'
import Modal, { ModalHeader, ModalFooter, useConfirm } from '@/components/ui/Modal'
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

// Semantic status tokens -- matches the warning/info/success/critical
// vocabulary used everywhere else in the app (Alerts, Incidents, Events)
// instead of literal yellow-700/blue-700/green-700/red-700, which don't
// track theme/contrast tuning done centrally in index.css.
const STATUS_CONFIG = {
  pending:    { icon: Clock,       color: 'text-warning',  bg: 'bg-warning/10 border-warning/30',   label: 'Pending' },
  generating: { icon: Loader2,     color: 'text-info',      bg: 'bg-info/10 border-info/30',        label: 'Generating' },
  completed:  { icon: CheckCircle, color: 'text-success',  bg: 'bg-success/10 border-success/30',   label: 'Completed' },
  failed:     { icon: AlertCircle, color: 'text-critical', bg: 'bg-critical/10 border-critical/30', label: 'Failed' },
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
  const { confirm, dialog: confirmDialog } = useConfirm()
  const { user } = useAuthStore()
  const isAdmin = (user as any)?.role === 'admin' || (user as any)?.role === 'ADMIN'

  // Data state
  const [reports, setReports] = useState<Report[]>([])
  const [total, setTotal] = useState(0)
  const [summary, setSummary] = useState<Summary | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  // Filters
  const [filterStatus, setFilterStatus] = useState('')
  const [filterType, setFilterType] = useState('')

  // Pagination -- real server-side paging (the backend now returns the
  // filtered total alongside the page, matching Events/Alerts) instead of
  // the old flat `limit: 100` fetch with no way to see or reach anything
  // past the 101st report.
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)

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
      const params: any = { limit: pageSize, offset: (page - 1) * pageSize }
      if (filterStatus) params.status = filterStatus
      if (filterType) params.report_type = filterType
      const [list, summ] = await Promise.all([
        getReports(params),
        getReportsSummary().catch(() => null),
      ])
      setReports(Array.isArray(list?.reports) ? list.reports : [])
      setTotal(typeof list?.total === 'number' ? list.total : 0)
      if (summ) setSummary(summ)
    } catch {
      toast.error('Failed to load reports')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [filterStatus, filterType, page, pageSize])

  useEffect(() => { fetchAll() }, [fetchAll])

  // Changing a filter invalidates the current page -- jump back to page 1
  // so we don't land on an out-of-range page for the new, narrower result set.
  useEffect(() => { setPage(1) }, [filterStatus, filterType])

  // Auto-refresh while any report on the current page is pending/generating
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
      setPage(1)
      await fetchAll()
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Failed to queue report')
    } finally {
      setGenerating(false)
    }
  }

  const handleDownload = async (report: Report, fmtKey: 'pdf' | 'csv') => {
    const key = `${report.id}-${fmtKey}`
    setDownloading(key)
    try {
      const response = await downloadReportBlob(report.id, fmtKey)
      const blob = new Blob([response.data], {
        type: fmtKey === 'pdf' ? 'application/pdf' : 'text/csv',
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const period = report.period_start ? `_${fmtDate(report.period_start).replace(/\//g, '-')}` : ''
      a.download = `${report.name.replace(/\s+/g, '_')}${period}.${fmtKey}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || `Failed to download ${fmtKey.toUpperCase()}`)
    } finally {
      setDownloading('')
    }
  }

  const handleDelete = async (id: string) => {
    if (!(await confirm({
      title: 'Delete report',
      confirmLabel: 'Delete',
      children: 'Delete this report and its files? This cannot be undone.',
    }))) return
    try {
      await deleteReport(id)
      toast.success('Report deleted')
      setReports(prev => prev.filter(r => r.id !== id))
      setTotal(prev => Math.max(0, prev - 1))
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
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={BarChart2}
        eyebrow="Compliance"
        title="Reports"
        description="Generate and download compliance reports"
        actions={
          <>
            <Button variant="outline" onClick={() => fetchAll(true)} disabled={refreshing}>
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button onClick={() => setShowForm(true)}>
              <Plus className="w-4 h-4" />
              Generate Report
            </Button>
          </>
        }
      />

      {/* Stats */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatsCard title="Total" value={summary.total} icon={BarChart2} color="indigo" />
          <StatsCard title="Completed" value={summary.completed} icon={CheckCircle} color="green" />
          <StatsCard title="Generating" value={summary.pending + summary.generating} icon={Loader2} color="indigo" />
          <StatsCard title="Failed" value={summary.failed} icon={AlertCircle} color="red" />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <select
          value={filterStatus}
          onChange={e => setFilterStatus(e.target.value)}
          className="bg-card border border-border text-muted-foreground text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-primary"
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
          className="bg-card border border-border text-muted-foreground text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-primary"
        >
          <option value="">All Types</option>
          {REPORT_TYPES.map(t => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
        <span className="text-sm text-muted-foreground">{total} report{total !== 1 ? 's' : ''}</span>
      </div>

      {/* Reports Table */}
      <div className="bg-card border border-border rounded-lg overflow-hidden">
        {reports.length === 0 ? (
          <EmptyState
            icon={BarChart2}
            title="No reports yet"
            description={'Click "Generate Report" to create your first compliance report'}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/60">
                    <th className="text-left px-4 py-3 text-muted-foreground font-medium">Report</th>
                    <th className="text-left px-4 py-3 text-muted-foreground font-medium">Type</th>
                    <th className="text-left px-4 py-3 text-muted-foreground font-medium">Period</th>
                    <th className="text-left px-4 py-3 text-muted-foreground font-medium">Status</th>
                    <th className="text-left px-4 py-3 text-muted-foreground font-medium">Email</th>
                    <th className="text-right px-4 py-3 text-muted-foreground font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {reports.map(report => (
                    <tr key={report.id} className="hover:bg-accent transition-colors">
                      <td className="px-4 py-3">
                        <div className="font-medium text-foreground">{report.name}</div>
                        <div className="text-xs text-muted-foreground mt-0.5">
                          {fmt(report.created_at)}
                          {report.file_size_bytes ? ` · ${fmtSize(report.file_size_bytes)}` : ''}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-block px-2 py-0.5 rounded bg-primary/10 border border-primary/20 text-primary text-xs">
                          {REPORT_TYPES.find(t => t.value === report.report_type)?.label || report.report_type}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-muted-foreground text-xs">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {fmtDate(report.period_start)} – {fmtDate(report.period_end)}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={report.status} />
                        {report.status === 'failed' && report.error_message && (
                          <p className="text-critical text-xs mt-1 max-w-xs truncate" title={report.error_message}>
                            {report.error_message}
                          </p>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {report.email_sent === 'yes' ? (
                          <span className="flex items-center gap-1 text-xs text-success">
                            <Mail className="w-3 h-3" /> Sent
                          </span>
                        ) : report.email_sent === 'no' ? (
                          <span className="text-xs text-critical">Failed</span>
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
                              className="flex items-center gap-1 px-2 py-1 text-xs bg-critical/10 hover:bg-critical/20 border border-critical/20 text-critical rounded transition-colors disabled:opacity-50"
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
                              className="flex items-center gap-1 px-2 py-1 text-xs bg-success/10 hover:bg-success/20 border border-success/20 text-success rounded transition-colors disabled:opacity-50"
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
                              className="p-1 text-muted-foreground hover:text-critical transition-colors"
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
            <DataPagination
              page={page}
              pageSize={pageSize}
              total={total}
              onPageChange={setPage}
              onPageSizeChange={(size) => { setPageSize(size); setPage(1) }}
              pageSizeOptions={[10, 25, 50, 100, 200]}
            />
          </>
        )}
      </div>

      {/* Scheduled reports info */}
      <div className="bg-primary/5 border border-primary/20 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Clock className="w-5 h-5 text-primary mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-sm font-medium text-primary">Scheduled Reports</p>
            <p className="text-sm text-muted-foreground mt-1">
              Automated reports run on a fixed schedule: daily at 8:00 AM UTC, weekly every Monday at 9:00 AM UTC,
              and monthly on the 1st at 10:00 AM UTC. Configure recipients and SMTP settings in your <code className="text-primary">.env</code> file.
            </p>
          </div>
        </div>
      </div>

      {/* Generate Report Modal */}
      <Modal
        open={showForm}
        onClose={() => setShowForm(false)}
        size="md"
        label="Generate Report"
        header={
          <ModalHeader
            title={
              <span className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-primary" />
                Generate Report
              </span>
            }
            onClose={() => setShowForm(false)}
          />
        }
        footer={
          <ModalFooter>
            <button onClick={() => setShowForm(false)} className="btn btn-secondary flex-1">
              Cancel
            </button>
            <button onClick={handleGenerate} disabled={generating} className="btn btn-primary flex-1">
              {generating ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Queueing...</>
              ) : (
                <><BarChart2 className="w-4 h-4" /> Generate</>
              )}
            </button>
          </ModalFooter>
        }
      >
            <div className="space-y-5">
              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-muted-foreground mb-1">Report Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="e.g. Q2 Compliance Summary"
                  className="input"
                />
              </div>

              {/* Report types */}
              <div>
                <label className="block text-sm font-medium text-muted-foreground mb-2">Report Types</label>
                <div className="grid grid-cols-2 gap-2">
                  {REPORT_TYPES.map(t => (
                    <label key={t.value} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={form.report_types.includes(t.value)}
                        onChange={() => toggleReportType(t.value)}
                        className="accent-primary"
                      />
                      <span className="text-sm text-muted-foreground">{t.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Date range */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">From</label>
                  <input
                    type="datetime-local"
                    value={form.start_date}
                    onChange={e => setForm(prev => ({ ...prev, start_date: e.target.value }))}
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">To</label>
                  <input
                    type="datetime-local"
                    value={form.end_date}
                    onChange={e => setForm(prev => ({ ...prev, end_date: e.target.value }))}
                    className="input"
                  />
                </div>
              </div>

              {/* Formats */}
              <div>
                <label className="block text-sm font-medium text-muted-foreground mb-2">Output Formats</label>
                <div className="flex gap-4">
                  {['pdf', 'csv'].map(f => (
                    <label key={f} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={form.formats.includes(f)}
                        onChange={() => toggleFormat(f)}
                        className="accent-primary"
                      />
                      <span className="text-sm text-muted-foreground uppercase">{f}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Recipients */}
              <div>
                <label className="block text-sm font-medium text-muted-foreground mb-1">
                  Email Recipients <span className="text-muted-foreground font-normal">(optional, comma-separated)</span>
                </label>
                <input
                  type="text"
                  value={form.recipients}
                  onChange={e => setForm(prev => ({ ...prev, recipients: e.target.value }))}
                  placeholder="ciso@company.com, security@company.com"
                  className="input"
                />
              </div>
            </div>
      </Modal>

      {confirmDialog}
    </div>
  )
}
