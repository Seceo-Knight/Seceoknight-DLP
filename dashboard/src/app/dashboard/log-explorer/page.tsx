

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'

import { Search, Loader2, X, Download, RefreshCcw, ChevronDown, ChevronUp, Filter, FileText } from 'lucide-react'
import { getEvents as fetchEvents } from '@/lib/api'
import { formatDateTimeIST } from '@/lib/utils'
import toast from 'react-hot-toast'

const TIME_PRESETS = [
  { label: '5m', value: 5 }, { label: '10m', value: 10 }, { label: '15m', value: 15 },
  { label: '30m', value: 30 }, { label: '1h', value: 60 }, { label: '24h', value: 1440 },
  { label: '7d', value: 10080 }, { label: '30d', value: 43200 }, { label: '90d', value: 129600 },
]

const classificationColors: Record<string, string> = {
  Restricted: 'bg-red-50 border-red-300 text-red-700',
  Confidential: 'bg-orange-50 border-orange-300 text-orange-700',
  Internal: 'bg-yellow-50 border-yellow-300 text-yellow-700',
  Public: 'bg-gray-50 border-gray-300 text-gray-500',
}
const severityColors: Record<string, string> = {
  critical: 'bg-red-50 border-red-300 text-red-700',
  high: 'bg-orange-50 border-orange-300 text-orange-700',
  medium: 'bg-yellow-50 border-yellow-300 text-yellow-700',
  low: 'bg-green-50 border-green-300 text-green-700',
}

export default function LogExplorerPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [eventType, setEventType] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [classification, setClassification] = useState('all')
  const [timePreset, setTimePreset] = useState<number | null>(null)
  const [startTime, setStartTime] = useState('')
  const [endTime, setEndTime] = useState('')
  const [agentFilter, setAgentFilter] = useState('')
  const [userFilter, setUserFilter] = useState('')
  const [limit, setLimit] = useState(100)
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null)
  const [showFilters, setShowFilters] = useState(true)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['log-explorer', eventType, severity, limit],
    queryFn: () => fetchEvents({ limit, event_type: eventType !== 'all' ? eventType : undefined, severity: severity !== 'all' ? severity : undefined }),
    staleTime: 0, retry: false,
  })

  const rawEvents = data?.events || (Array.isArray(data) ? data : [])

  const events = useMemo(() => rawEvents.filter((e: any) => {
    if (classification !== 'all') { const cat = (e.classification_category || e.classification_level || 'Public'); if (cat.toLowerCase() !== classification.toLowerCase()) return false }
    if (timePreset) { if (new Date(e.timestamp).getTime() < Date.now() - timePreset * 60000) return false }
    if (startTime && new Date(e.timestamp).getTime() < new Date(startTime).getTime()) return false
    if (endTime && new Date(e.timestamp).getTime() > new Date(endTime).getTime()) return false
    if (agentFilter && !(e.agent_id || '').toLowerCase().includes(agentFilter.toLowerCase())) return false
    if (userFilter && !(e.user_email || '').toLowerCase().includes(userFilter.toLowerCase())) return false
    if (searchQuery) { const q = searchQuery.toLowerCase(); const fields = [e.description, e.event_type, e.agent_id, e.user_email, e.file_path, e.detected_content, ...(e.classification_rules_matched || [])].filter(Boolean).join(' ').toLowerCase(); if (!fields.includes(q)) return false }
    return true
  }), [rawEvents, classification, timePreset, startTime, endTime, agentFilter, userFilter, searchQuery])

  const stats = useMemo(() => ({
    total: events.length,
    clipboard: events.filter((e: any) => e.event_type === 'clipboard').length,
    usb: events.filter((e: any) => e.event_type === 'usb').length,
    blocked: events.filter((e: any) => e.blocked || e.action_taken === 'block').length,
  }), [events])

  const exportCSV = () => {
    const rows = [['Timestamp','Type','Severity','Classification','Action','Blocked','Rules','Description','Agent','User'].join(','),
      ...events.map((e: any) => [e.timestamp, e.event_type, e.severity, e.classification_category || e.classification_level || 'Public', e.action_taken || 'logged', e.blocked ? 'Yes' : 'No', (e.classification_rules_matched || []).join('; '), `"${(e.description || '').replace(/"/g, '""').replace(/\n/g, ' ')}"`, e.agent_id, e.user_email].join(','))]
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `dlp-logs-${new Date().toISOString().slice(0,10)}.csv`; a.click()
    toast.success(`Exported ${events.length} events`)
  }
  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `dlp-logs-${new Date().toISOString().slice(0,10)}.json`; a.click()
    toast.success(`Exported ${events.length} events`)
  }

  const clearFilters = () => { setSearchQuery(''); setEventType('all'); setSeverity('all'); setClassification('all'); setTimePreset(null); setStartTime(''); setEndTime(''); setAgentFilter(''); setUserFilter('') }
  const hasFilters = searchQuery || eventType !== 'all' || severity !== 'all' || classification !== 'all' || timePreset || startTime || endTime || agentFilter || userFilter

  return (
    <>
      <div className="space-y-6 p-6 bg-white min-h-screen">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Log Explorer</h1>
            <p className="text-gray-500 text-sm mt-1">Search, filter, and investigate DLP events</p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => refetch()} className="flex items-center gap-2 px-3 py-2 bg-gray-100 text-gray-600 rounded-lg border border-gray-200 hover:bg-gray-200 text-sm"><RefreshCcw className="w-4 h-4" /> Refresh</button>
            <button onClick={exportCSV} className="flex items-center gap-2 px-3 py-2 bg-gray-100 text-gray-600 rounded-lg border border-gray-200 hover:bg-gray-200 text-sm"><Download className="w-4 h-4" /> CSV</button>
            <button onClick={exportJSON} className="flex items-center gap-2 px-3 py-2 bg-gray-100 text-gray-600 rounded-lg border border-gray-200 hover:bg-gray-200 text-sm"><FileText className="w-4 h-4" /> JSON</button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Results', value: stats.total, color: 'text-gray-900', border: 'border-gray-200' },
            { label: 'Clipboard', value: stats.clipboard, color: 'text-purple-700', border: 'border-purple-200' },
            { label: 'USB', value: stats.usb, color: 'text-blue-700', border: 'border-blue-200' },
            { label: 'Blocked', value: stats.blocked, color: 'text-red-700', border: 'border-red-200' },
          ].map((s) => (
            <div key={s.label} className={`bg-white rounded-xl p-4 border ${s.border} shadow-sm`}>
              <p className="text-gray-500 text-xs uppercase">{s.label}</p>
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Search + Filters */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="p-4 border-b border-gray-100">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by description, agent, user, file path, classification rules..."
                className="w-full pl-10 pr-20 py-2.5 bg-gray-50 border border-gray-200 rounded-lg text-gray-900 text-sm placeholder-gray-400 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500" />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                {hasFilters && <button onClick={clearFilters} className="px-2 py-1 text-xs text-gray-400 hover:text-gray-700">Clear</button>}
                <button onClick={() => setShowFilters(!showFilters)} className={`p-1.5 rounded ${showFilters ? 'text-purple-600' : 'text-gray-400'}`}><Filter className="w-4 h-4" /></button>
              </div>
            </div>
          </div>

          {showFilters && (
            <div className="p-4 space-y-4 border-b border-gray-100 bg-gray-50/50">
              <div>
                <label className="text-xs text-gray-500 uppercase block mb-2">Time Range</label>
                <div className="flex gap-1.5 flex-wrap">
                  <button onClick={() => setTimePreset(null)} className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${!timePreset ? 'bg-purple-600 text-white border-purple-600' : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'}`}>All Time</button>
                  {TIME_PRESETS.map((p) => (
                    <button key={p.value} onClick={() => { setTimePreset(p.value); setStartTime(''); setEndTime('') }}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${timePreset === p.value ? 'bg-purple-600 text-white border-purple-600' : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'}`}>{p.label}</button>
                  ))}
                </div>
                <div className="flex gap-3 mt-2">
                  <div className="flex-1"><label className="text-xs text-gray-500 block mb-1">Start</label><input type="datetime-local" value={startTime} onChange={(e) => { setStartTime(e.target.value); setTimePreset(null) }} className="w-full bg-white border border-gray-200 rounded-lg px-3 py-1.5 text-sm text-gray-900 focus:outline-none focus:border-purple-500" /></div>
                  <div className="flex-1"><label className="text-xs text-gray-500 block mb-1">End</label><input type="datetime-local" value={endTime} onChange={(e) => { setEndTime(e.target.value); setTimePreset(null) }} className="w-full bg-white border border-gray-200 rounded-lg px-3 py-1.5 text-sm text-gray-900 focus:outline-none focus:border-purple-500" /></div>
                </div>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <div><label className="text-xs text-gray-500 block mb-1">Event Type</label><select value={eventType} onChange={(e) => setEventType(e.target.value)} className="w-full bg-white border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-900"><option value="all">All</option><option value="clipboard">Clipboard</option><option value="usb">USB</option><option value="file">File</option></select></div>
                <div><label className="text-xs text-gray-500 block mb-1">Severity</label><select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full bg-white border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-900"><option value="all">All</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
                <div><label className="text-xs text-gray-500 block mb-1">Classification</label><select value={classification} onChange={(e) => setClassification(e.target.value)} className="w-full bg-white border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-900"><option value="all">All</option><option value="Restricted">Restricted</option><option value="Confidential">Confidential</option><option value="Internal">Internal</option><option value="Public">Public</option></select></div>
                <div><label className="text-xs text-gray-500 block mb-1">Agent</label><input value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)} placeholder="Agent ID..." className="w-full bg-white border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-900 placeholder-gray-400" /></div>
                <div><label className="text-xs text-gray-500 block mb-1">User</label><input value={userFilter} onChange={(e) => setUserFilter(e.target.value)} placeholder="Email..." className="w-full bg-white border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-900 placeholder-gray-400" /></div>
              </div>
            </div>
          )}
        </div>

        {/* Results */}
        {isLoading ? (
          <div className="flex justify-center py-12"><Loader2 className="w-8 h-8 animate-spin text-purple-600" /></div>
        ) : error ? (
          <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center"><p className="text-red-700">Failed to load events</p></div>
        ) : events.length === 0 ? (
          <div className="bg-gray-50 border border-gray-200 rounded-xl p-12 text-center"><Search className="w-12 h-12 text-gray-300 mx-auto mb-3" /><p className="text-gray-500">No events match your filters</p></div>
        ) : (
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
            <div className="grid grid-cols-12 gap-2 px-4 py-3 border-b border-gray-200 text-xs text-gray-500 uppercase font-medium bg-gray-50">
              <div className="col-span-1">Type</div><div className="col-span-3">Description</div><div className="col-span-2">Classification</div><div className="col-span-1">Severity</div><div className="col-span-1">Action</div><div className="col-span-2">User</div><div className="col-span-2">Time</div>
            </div>
            <div className="divide-y divide-gray-100">
              {events.map((event: any, idx: number) => {
                const isExpanded = expandedEvent === (event.id || idx.toString())
                const category = event.classification_category || event.classification_level || 'Public'
                return (
                  <div key={event.id || idx}>
                    <div onClick={() => setExpandedEvent(isExpanded ? null : (event.id || idx.toString()))} className="grid grid-cols-12 gap-2 px-4 py-3 hover:bg-gray-50 cursor-pointer transition-colors items-center text-sm">
                      <div className="col-span-1"><span className="text-xs text-gray-600 capitalize">{event.event_type}</span></div>
                      <div className="col-span-3 truncate text-gray-900 font-medium">{event.description || `${event.event_type} event`}</div>
                      <div className="col-span-2"><span className={`px-2 py-0.5 rounded border text-xs font-medium ${classificationColors[category] || classificationColors.Public}`}>{category}</span></div>
                      <div className="col-span-1"><span className={`px-2 py-0.5 rounded border text-xs font-medium ${severityColors[event.severity] || severityColors.low}`}>{event.severity}</span></div>
                      <div className="col-span-1"><span className={`text-xs font-medium ${event.blocked ? 'text-red-700' : 'text-gray-500'}`}>{event.action_taken || 'logged'}</span></div>
                      <div className="col-span-2 truncate text-gray-500 text-xs">{event.user_email || '-'}</div>
                      <div className="col-span-2 flex items-center justify-between">
                        <span className="text-gray-500 text-xs">{formatDateTimeIST(event.timestamp)}</span>
                        {isExpanded ? <ChevronUp className="w-3 h-3 text-gray-400" /> : <ChevronDown className="w-3 h-3 text-gray-400" />}
                      </div>
                    </div>
                    {isExpanded && (
                      <div className="px-4 pb-4 bg-gray-50 space-y-3 border-t border-gray-100">
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3">
                          <div><label className="text-xs text-gray-500">Event Type</label><p className="text-gray-900 text-sm capitalize">{event.event_subtype || event.event_type}</p></div>
                          <div><label className="text-xs text-gray-500">Action</label><p className="text-gray-900 text-sm">{event.action_taken || 'logged'}</p></div>
                          <div><label className="text-xs text-gray-500">Confidence</label><p className="text-gray-900 text-sm font-bold">{((event.classification_score || 0) * 100).toFixed(0)}%</p></div>
                          <div><label className="text-xs text-gray-500">Agent</label><p className="text-gray-900 text-xs font-mono">{event.agent_id}</p></div>
                        </div>
                        {event.classification_rules_matched && event.classification_rules_matched.length > 0 && (
                          <div><label className="text-xs text-gray-500">Matched Rules</label><div className="flex gap-1.5 mt-1 flex-wrap">{event.classification_rules_matched.map((r: string, i: number) => (<span key={i} className="px-2 py-0.5 rounded-full text-xs font-medium bg-purple-50 text-purple-700 border border-purple-200">{r}</span>))}</div></div>
                        )}
                        {event.detected_content && (
                          <div><label className="text-xs text-gray-500">Detected Content</label><pre className="mt-1 text-xs text-gray-700 bg-white rounded-lg p-3 border border-gray-200 whitespace-pre-wrap">{event.detected_content}</pre></div>
                        )}
                        <details><summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-700">Raw JSON</summary><pre className="mt-2 text-xs text-gray-600 bg-white rounded-lg p-3 overflow-x-auto border border-gray-200 whitespace-pre-wrap">{JSON.stringify(event, null, 2)}</pre></details>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </>
  )
}
