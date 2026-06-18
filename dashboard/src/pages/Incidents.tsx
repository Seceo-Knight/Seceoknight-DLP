import { useState, useEffect } from 'react'
import { AlertTriangle, Plus, X, MessageSquare, Send } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import {
  getIncidents,
  getIncident,
  createIncident,
  updateIncident,
  getIncidentComments,
  addIncidentComment,
  getIncidentStats,
} from '@/lib/api'
import { formatDateTimeIST } from '@/lib/utils'

const SEVERITY_MAP: Record<number, { label: string; color: string }> = {
  0: { label: 'Info', color: 'bg-gray-500/20 text-gray-300' },
  1: { label: 'Low', color: 'bg-blue-500/20 text-blue-300' },
  2: { label: 'Medium', color: 'bg-yellow-500/20 text-yellow-300' },
  3: { label: 'High', color: 'bg-orange-500/20 text-orange-300' },
  4: { label: 'Critical', color: 'bg-red-500/20 text-red-300' },
}

const STATUS_COLORS: Record<string, string> = {
  open: 'bg-red-500/20 text-red-300',
  investigating: 'bg-yellow-500/20 text-yellow-300',
  resolved: 'bg-green-500/20 text-green-300',
}

export default function Incidents() {
  const [incidents, setIncidents] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [filterSeverity, setFilterSeverity] = useState<string>('')
  const [filterStatus, setFilterStatus] = useState<string>('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<any>(null)
  const [comments, setComments] = useState<any[]>([])
  const [newComment, setNewComment] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({ title: '', description: '', severity: 2, event_id: '' })

  const fetchData = async () => {
    try {
      const params: any = { limit: 100 }
      if (filterSeverity !== '') params.severity = Number(filterSeverity)
      if (filterStatus) params.status = filterStatus
      const [inc, st] = await Promise.all([getIncidents(params), getIncidentStats().catch(() => null)])
      setIncidents(Array.isArray(inc) ? inc : inc?.incidents || [])
      if (st) setStats(st)
    } catch (e: any) {
      toast.error('Failed to load incidents')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() }, [filterSeverity, filterStatus])

  const openDetail = async (inc: any) => {
    setSelected(inc)
    try {
      const c = await getIncidentComments(inc.id || inc._id)
      setComments(Array.isArray(c) ? c : c?.comments || [])
    } catch { setComments([]) }
  }

  const handleStatusChange = async (status: string) => {
    if (!selected) return
    try {
      await updateIncident(selected.id || selected._id, { status })
      toast.success(`Status updated to ${status}`)
      setSelected({ ...selected, status })
      fetchData()
    } catch { toast.error('Failed to update status') }
  }

  const handleAssign = async (assigned_to: string) => {
    if (!selected) return
    try {
      await updateIncident(selected.id || selected._id, { assigned_to })
      setSelected({ ...selected, assigned_to })
      toast.success('Assignment updated')
    } catch { toast.error('Failed to assign') }
  }

  const handleAddComment = async () => {
    if (!newComment.trim() || !selected) return
    try {
      await addIncidentComment(selected.id || selected._id, newComment)
      setNewComment('')
      const c = await getIncidentComments(selected.id || selected._id)
      setComments(Array.isArray(c) ? c : c?.comments || [])
      toast.success('Comment added')
    } catch { toast.error('Failed to add comment') }
  }

  const handleCreate = async () => {
    if (!createForm.title.trim()) return toast.error('Title is required')
    try {
      await createIncident({
        title: createForm.title,
        severity: createForm.severity,
        description: createForm.description || undefined,
        event_id: createForm.event_id || undefined,
      })
      toast.success('Incident created')
      setShowCreate(false)
      setCreateForm({ title: '', description: '', severity: 2, event_id: '' })
      fetchData()
    } catch { toast.error('Failed to create incident') }
  }

  const filtered = incidents.filter((i) =>
    search ? (i.title || '').toLowerCase().includes(search.toLowerCase()) : true
  )

  if (loading) return <LoadingSpinner />

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <AlertTriangle className="h-6 w-6" /> Incidents
        </h1>
        <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-sm">
          <Plus className="h-4 w-4" /> Create Incident
        </button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Open', value: stats.open ?? 0, color: 'text-red-400' },
            { label: 'Investigating', value: stats.investigating ?? 0, color: 'text-yellow-400' },
            { label: 'Resolved', value: stats.resolved ?? 0, color: 'text-green-400' },
            { label: 'Total', value: stats.total ?? 0, color: 'text-white' },
          ].map((s) => (
            <div key={s.label} className="bg-[#1e2124] rounded-lg p-4 border border-gray-700">
              <div className="text-sm text-gray-400">{s.label}</div>
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search incidents..." className="px-3 py-2 bg-[#1e2124] border border-gray-700 rounded-lg text-white text-sm placeholder-gray-500 w-64" />
        <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)} className="px-3 py-2 bg-[#1e2124] border border-gray-700 rounded-lg text-white text-sm">
          <option value="">All Severities</option>
          {[0, 1, 2, 3, 4].map((s) => <option key={s} value={s}>{SEVERITY_MAP[s].label}</option>)}
        </select>
        <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="px-3 py-2 bg-[#1e2124] border border-gray-700 rounded-lg text-white text-sm">
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-[#1e2124] rounded-lg border border-gray-700 overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="text-gray-400 border-b border-gray-700">
            <tr>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Event ID</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Assigned To</th>
              <th className="px-4 py-3">Created</th>
            </tr>
          </thead>
          <tbody className="text-white">
            {filtered.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No incidents found</td></tr>
            ) : filtered.map((inc) => {
              const sev = SEVERITY_MAP[inc.severity] || SEVERITY_MAP[0]
              return (
                <tr key={inc.id || inc._id} onClick={() => openDetail(inc)} className="border-b border-gray-700/50 hover:bg-[#2a2d2f] cursor-pointer">
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium ${sev.color}`}>{sev.label}</span></td>
                  <td className="px-4 py-3 font-medium">{inc.title}</td>
                  <td className="px-4 py-3 text-gray-400 font-mono text-xs">{inc.event_id || '-'}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[inc.status] || 'bg-gray-500/20 text-gray-300'}`}>{inc.status}</span></td>
                  <td className="px-4 py-3 text-gray-400">{inc.assigned_to || '-'}</td>
                  <td className="px-4 py-3 text-gray-400">{inc.created_at ? formatDateTimeIST(inc.created_at) : '-'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Detail Modal */}
      {selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setSelected(null)}>
          <div className="bg-[#1e2124] rounded-lg border border-gray-700 w-full max-w-2xl max-h-[80vh] overflow-y-auto p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-white">{selected.title}</h2>
              <button onClick={() => setSelected(null)} className="text-gray-400 hover:text-white"><X className="h-5 w-5" /></button>
            </div>
            <div className="space-y-4">
              <div className="flex flex-wrap gap-3 text-sm">
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${(SEVERITY_MAP[selected.severity] || SEVERITY_MAP[0]).color}`}>{(SEVERITY_MAP[selected.severity] || SEVERITY_MAP[0]).label}</span>
                <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[selected.status] || ''}`}>{selected.status}</span>
                {selected.event_id && <span className="text-gray-400 font-mono">Event: {selected.event_id}</span>}
              </div>
              {selected.description && <p className="text-gray-300 text-sm">{selected.description}</p>}

              {/* Status buttons */}
              <div className="flex gap-2">
                {['open', 'investigating', 'resolved'].map((s) => (
                  <button key={s} disabled={selected.status === s} onClick={() => handleStatusChange(s)}
                    className={`px-3 py-1.5 rounded text-xs font-medium ${selected.status === s ? 'bg-gray-600 text-gray-400 cursor-not-allowed' : 'bg-[#2a2d2f] text-white hover:bg-[#353839]'}`}>
                    {s.charAt(0).toUpperCase() + s.slice(1)}
                  </button>
                ))}
              </div>

              {/* Assign */}
              <div>
                <label className="text-xs text-gray-400 block mb-1">Assign To</label>
                <input value={selected.assigned_to || ''} onChange={(e) => setSelected({ ...selected, assigned_to: e.target.value })}
                  onBlur={(e) => handleAssign(e.target.value)}
                  className="px-3 py-2 bg-[#2a2d2f] border border-gray-700 rounded-lg text-white text-sm w-full" placeholder="Username" />
              </div>

              {/* Comments */}
              <div>
                <h3 className="text-sm font-medium text-gray-300 flex items-center gap-1 mb-2"><MessageSquare className="h-4 w-4" /> Comments</h3>
                <div className="space-y-2 max-h-48 overflow-y-auto mb-2">
                  {comments.length === 0 ? (
                    <p className="text-gray-500 text-xs">No comments yet</p>
                  ) : comments.map((c, i) => (
                    <div key={i} className="bg-[#2a2d2f] rounded p-2 text-sm">
                      <div className="text-xs text-gray-400 mb-1">{c.user || 'Unknown'} &middot; {c.created_at ? formatDateTimeIST(c.created_at) : ''}</div>
                      <div className="text-gray-200">{c.comment || c.text}</div>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2">
                  <input value={newComment} onChange={(e) => setNewComment(e.target.value)} placeholder="Add a comment..."
                    onKeyDown={(e) => e.key === 'Enter' && handleAddComment()}
                    className="flex-1 px-3 py-2 bg-[#2a2d2f] border border-gray-700 rounded-lg text-white text-sm" />
                  <button onClick={handleAddComment} className="px-3 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white"><Send className="h-4 w-4" /></button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setShowCreate(false)}>
          <div className="bg-[#1e2124] rounded-lg border border-gray-700 w-full max-w-lg p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold text-white">Create Incident</h2>
              <button onClick={() => setShowCreate(false)} className="text-gray-400 hover:text-white"><X className="h-5 w-5" /></button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1">Title *</label>
                <input value={createForm.title} onChange={(e) => setCreateForm({ ...createForm, title: e.target.value })}
                  className="w-full px-3 py-2 bg-[#2a2d2f] border border-gray-700 rounded-lg text-white text-sm" />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Severity</label>
                <select value={createForm.severity} onChange={(e) => setCreateForm({ ...createForm, severity: Number(e.target.value) })}
                  className="w-full px-3 py-2 bg-[#2a2d2f] border border-gray-700 rounded-lg text-white text-sm">
                  {[0, 1, 2, 3, 4].map((s) => <option key={s} value={s}>{SEVERITY_MAP[s].label}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Description</label>
                <textarea value={createForm.description} onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
                  rows={3} className="w-full px-3 py-2 bg-[#2a2d2f] border border-gray-700 rounded-lg text-white text-sm" />
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1">Event ID (optional)</label>
                <input value={createForm.event_id} onChange={(e) => setCreateForm({ ...createForm, event_id: e.target.value })}
                  className="w-full px-3 py-2 bg-[#2a2d2f] border border-gray-700 rounded-lg text-white text-sm" />
              </div>
              <button onClick={handleCreate} className="w-full px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg text-sm font-medium">Create</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
