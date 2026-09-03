import { useState, useEffect } from 'react'
import { ClipboardList, ChevronDown, ChevronUp, ChevronLeft, ChevronRight } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import { getAuditLogs, getAuditActions } from '@/lib/api'
import { formatDateTimeIST } from '@/lib/utils'

const ACTION_COLORS: Record<string, string> = {
  create: 'bg-green-100 text-green-700',
  update: 'bg-blue-100 text-blue-700',
  delete: 'bg-red-100 text-red-700',
  login: 'bg-purple-100 text-purple-700',
  logout: 'bg-muted text-muted-foreground',
}

export default function AuditTrail() {
  const [logs, setLogs] = useState<any[]>([])
  const [actions, setActions] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [filterAction, setFilterAction] = useState('')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [expandedRow, setExpandedRow] = useState<number | null>(null)
  const [page, setPage] = useState(0)
  const limit = 50

  const fetchData = async () => {
    setLoading(true)
    try {
      const params: any = { skip: page * limit, limit }
      if (filterAction) params.action = filterAction
      if (startDate) params.start_date = startDate
      if (endDate) params.end_date = endDate
      const data = await getAuditLogs(params)
      setLogs(Array.isArray(data) ? data : data?.logs || [])
    } catch {
      toast.error('Failed to load audit logs')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    getAuditActions().then((d) => setActions(Array.isArray(d) ? d : d?.actions || [])).catch(() => {})
  }, [])

  useEffect(() => { fetchData() }, [page, filterAction, startDate, endDate])

  if (loading && page === 0) return <LoadingSpinner />

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
        <ClipboardList className="h-6 w-6" /> Audit Trail
      </h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select value={filterAction} onChange={(e) => { setFilterAction(e.target.value); setPage(0) }}
          className="px-3 py-2 bg-card border border-border rounded-lg text-foreground text-sm">
          <option value="">All Actions</option>
          {actions.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <input type="date" value={startDate} onChange={(e) => { setStartDate(e.target.value); setPage(0) }}
          className="px-3 py-2 bg-card border border-border rounded-lg text-foreground text-sm" />
        <input type="date" value={endDate} onChange={(e) => { setEndDate(e.target.value); setPage(0) }}
          className="px-3 py-2 bg-card border border-border rounded-lg text-foreground text-sm" />
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
                <tr key={i} className="border-b border-border/50">
                  <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">{log.created_at || log.timestamp ? formatDateTimeIST(log.created_at || log.timestamp) : '-'}</td>
                  <td className="px-4 py-3">{log.user_id || log.user || '-'}</td>
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
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">Page {page + 1}</span>
        <div className="flex gap-2">
          <button onClick={() => setPage(Math.max(0, page - 1))} disabled={page === 0}
            className="px-3 py-1.5 bg-card border border-border rounded-lg text-sm text-foreground disabled:opacity-50 flex items-center gap-1">
            <ChevronLeft className="h-4 w-4" /> Prev
          </button>
          <button onClick={() => setPage(page + 1)} disabled={logs.length < limit}
            className="px-3 py-1.5 bg-card border border-border rounded-lg text-sm text-foreground disabled:opacity-50 flex items-center gap-1">
            Next <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  )
}
