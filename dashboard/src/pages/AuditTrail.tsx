import { useState, useEffect } from 'react'
import { ClipboardList, ChevronDown, ChevronUp } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import { PageHeader } from '@/components/ui/page-header'
import { DataPagination } from '@/components/ui/pagination'
import { getAuditLogs, getAuditActions } from '@/lib/api'
import { formatDateTimeIST } from '@/lib/utils'

// Semantic tokens instead of literal Tailwind colors (bg-green-100 etc) --
// matches the vocabulary used everywhere else in the app (success/info/
// critical), rather than a 4th independently-invented color scheme.
const ACTION_COLORS: Record<string, string> = {
  create: 'bg-success/15 text-success',
  update: 'bg-info/15 text-info',
  delete: 'bg-critical/15 text-critical',
  login: 'bg-violet-500/15 text-violet-400',
  logout: 'bg-muted text-muted-foreground',
}

export default function AuditTrail() {
  const [logs, setLogs] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [actions, setActions] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [filterAction, setFilterAction] = useState('')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [expandedRow, setExpandedRow] = useState<number | null>(null)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)

  const fetchData = async () => {
    setLoading(true)
    try {
      const params: any = { skip: (page - 1) * pageSize, limit: pageSize }
      if (filterAction) params.action = filterAction
      if (startDate) params.start_date = startDate
      if (endDate) params.end_date = endDate
      const data = await getAuditLogs(params)
      setLogs(Array.isArray(data) ? data : data?.logs || [])
      setTotal(Array.isArray(data) ? data.length : (typeof data?.total === 'number' ? data.total : 0))
    } catch {
      toast.error('Failed to load audit logs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    getAuditActions().then((d) => setActions(Array.isArray(d) ? d : d?.actions || [])).catch(() => {})
  }, [])

  useEffect(() => { fetchData() }, [page, pageSize, filterAction, startDate, endDate])

  if (loading && page === 1 && logs.length === 0) return <LoadingSpinner />

  return (
    <div className="space-y-6">
      <PageHeader
        icon={ClipboardList}
        eyebrow="Security"
        title="Audit Trail"
        description="Immutable log of admin actions and login events across the platform."
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select value={filterAction} onChange={(e) => { setFilterAction(e.target.value); setPage(1) }}
          className="input w-auto">
          <option value="">All Actions</option>
          {actions.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <input type="date" value={startDate} onChange={(e) => { setStartDate(e.target.value); setPage(1) }}
          className="input w-auto" />
        <input type="date" value={endDate} onChange={(e) => { setEndDate(e.target.value); setPage(1) }}
          className="input w-auto" />
      </div>

      {/* Table */}
      <div className="bg-card rounded-lg border border-border overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="text-muted-foreground border-b border-border">
            <tr>
              <th className="px-4 py-3">Timestamp</th>
              <th className="px-4 py-3">User</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Details</th>
            </tr>
          </thead>
          <tbody className="text-foreground">
            {logs.length === 0 ? (
              <tr><td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">No audit logs found</td></tr>
            ) : logs.map((log, i) => {
              const actionBase = (log.action || '').split('.')[0].toLowerCase()
              const color = ACTION_COLORS[actionBase] || 'bg-muted text-muted-foreground'
              const expanded = expandedRow === i
              return (
                <tr key={log.id || i} className="border-b border-border/50">
                  <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">{log.created_at || log.timestamp ? formatDateTimeIST(log.created_at || log.timestamp) : '-'}</td>
                  <td className="px-4 py-3">
                    {log.user_email ? (
                      <span className="text-foreground">{log.user_email}</span>
                    ) : log.user_id || log.user ? (
                      // Falls back to the raw UUID only when the user row is
                      // gone (deleted account) or the log predates email
                      // resolution -- shown muted + monospace so it still
                      // reads as "un-resolvable ID", not a normal name.
                      <span className="font-mono text-xs text-muted-foreground" title={log.user_id || log.user}>{log.user_id || log.user}</span>
                    ) : (
                      <span className="text-muted-foreground">System</span>
                    )}
                  </td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium ${color}`}>{log.action}</span></td>
                  <td className="px-4 py-3">
                    <button onClick={() => setExpandedRow(expanded ? null : i)} className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-xs">
                      {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                      {expanded ? 'Hide' : 'Show'}
                    </button>
                    {expanded && (
                      <pre className="mt-2 p-2 bg-muted rounded text-xs text-muted-foreground overflow-x-auto max-w-lg whitespace-pre-wrap">
                        {JSON.stringify(log.details || log.metadata || log, null, 2)}
                      </pre>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        <DataPagination
          page={page}
          pageSize={pageSize}
          total={total}
          onPageChange={setPage}
          onPageSizeChange={(size) => { setPageSize(size); setPage(1) }}
          pageSizeOptions={[25, 50, 100, 200]}
        />
      </div>
    </div>
  )
}
