import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Fingerprint, Plus, Trash2, Power, PowerOff, FlaskConical, ShieldCheck } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { extractErrorDetail } from '@/utils/errorUtils'
import {
  listSources, createEdm, createFingerprint, updateSource, deleteSource,
  testContent, fileToBase64, type MatchResult,
} from '@/lib/data-matching-api'
import { usePagination } from '@/lib/hooks/useTableState'
import { DataPagination } from '@/components/ui/pagination'
import SharedModal, { ModalHeader, useConfirm } from '@/components/ui/Modal'

// Ported from the CyberSentinel-DLP reference project. Closes task #123 --
// the data-matching server API (server/app/api/v1/data_matching.py) was
// already ported earlier (task #109) but had no dashboard surface, so
// admins could only create EDM/fingerprint sources via raw API calls.

const CLASSIFICATIONS = ['Restricted', 'Confidential', 'Internal']
const utf8ToB64 = (s: string) => btoa(unescape(encodeURIComponent(s)))

export default function DataMatching() {
  const qc = useQueryClient()
  const { confirm, dialog: confirmDialog } = useConfirm()
  const [createOpen, setCreateOpen] = useState(false)
  const [testOpen, setTestOpen] = useState(false)

  const { data: sources, isLoading, error, refetch } = useQuery({
    queryKey: ['data-match-sources'],
    queryFn: () => listSources(),
    refetchInterval: 30000,
  })

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => updateSource(id, { enabled }),
    onSuccess: (s) => { toast.success(`${s.name} ${s.enabled ? 'enabled' : 'disabled'}`); qc.invalidateQueries({ queryKey: ['data-match-sources'] }) },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Update failed')),
  })
  const remove = useMutation({
    mutationFn: (id: string) => deleteSource(id),
    onSuccess: () => { toast.success('Source deleted'); qc.invalidateQueries({ queryKey: ['data-match-sources'] }) },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Delete failed')),
  })

  // Must run before the isLoading/error early returns -- see the same note
  // in UsbDevices.tsx / Printers.tsx (hooks can't be called conditionally).
  const list = sources || []
  const sourcesPg = usePagination(list, 25)

  if (isLoading) return <LoadingSpinner size="lg" />
  if (error) return <ErrorMessage message="Failed to load data-match sources" retry={() => refetch()} />

  const edmCount = list.filter((s) => s.source_type === 'edm').length
  const fpCount = list.filter((s) => s.source_type === 'fingerprint').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="eyebrow mb-1.5">Enforce</p>
          <h1 className="text-2xl font-bold tracking-tight text-cs-ink">Data Matching</h1>
          <p className="mt-1 text-sm text-cs-ink-2 max-w-2xl">
            Match content against your <strong>actual</strong> protected data -- real records
            (Exact Data Matching) and sensitive documents (fingerprinting). Matching runs on this
            server against <strong>keyed one-way hashes only</strong>; the uploaded data is indexed
            and then discarded -- never stored.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button className="btn btn-secondary" onClick={() => setTestOpen(true)}>
            <FlaskConical className="h-4 w-4" /> Test content
          </button>
          <button className="btn btn-primary" onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4" /> New source
          </button>
        </div>
      </div>

      {/* Trust banner */}
      <div className="flex items-center gap-3 rounded-cs-card border border-cs-hair bg-cs-indigo-faint px-4 py-3 text-sm text-cs-ink-2">
        <ShieldCheck className="h-5 w-5 text-cs-indigo shrink-0" />
        <span>
          Plaintext is never persisted. Each source stores only HMAC digests keyed with a
          per-deployment secret, so a stolen index cannot be reversed. EDM fires only on a
          combination of fields from one record, keeping false positives near zero.
        </span>
      </div>

      {/* Table */}
      <div className="rounded-cs-card border border-cs-hair bg-cs-panel overflow-hidden">
        <div className="flex items-center gap-4 px-4 py-3 border-b border-cs-hair text-xs text-cs-muted">
          <span>{list.length} source(s)</span>
          <span className="badge badge-info">{edmCount} EDM</span>
          <span className="badge badge-info">{fpCount} Fingerprint</span>
        </div>
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th><th>Type</th><th>Indexed</th><th>Threshold</th>
                <th>On match</th><th>Status</th><th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {list.length === 0 && (
                <tr><td colSpan={7} className="text-center text-cs-muted py-10">
                  No sources yet. Add a dataset (EDM) or a document (fingerprint) to start matching real data.
                </td></tr>
              )}
              {sourcesPg.pageRows.map((s) => (
                <tr key={s.id}>
                  <td>
                    <div className="font-medium text-cs-ink">{s.name}</div>
                    {s.description && <div className="text-xs text-cs-muted">{s.description}</div>}
                  </td>
                  <td>
                    <span className="badge badge-info">
                      {s.source_type === 'edm' ? 'EDM' : 'Fingerprint'}
                    </span>
                  </td>
                  <td className="text-cs-ink-2">
                    {s.source_type === 'edm'
                      ? <span><span className="num">{s.row_count ?? 0}</span> records &middot; {(s.columns || []).length} cols</span>
                      : <span><span className="num">{s.shingle_count ?? 0}</span> shingles</span>}
                  </td>
                  <td className="text-cs-ink-2 text-xs">
                    {s.source_type === 'edm'
                      ? <>&ge; <span className="num">{s.min_fields}</span> fields / record</>
                      : <>&ge; <span className="num">{s.min_shingles}</span> shingles or <span className="num">{Math.round(s.min_containment * 100)}%</span></>}
                  </td>
                  <td><span className="badge badge-danger">{s.classification}</span></td>
                  <td>
                    <span className={s.enabled ? 'badge badge-success' : 'badge badge-warning'}>
                      {s.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td>
                    <div className="flex items-center justify-end gap-1">
                      <button
                        className="p-1.5 rounded-cs-sm hover:bg-cs-hair-2 text-cs-muted"
                        title={s.enabled ? 'Disable' : 'Enable'}
                        onClick={() => toggle.mutate({ id: s.id, enabled: !s.enabled })}
                      >
                        {s.enabled ? <PowerOff className="h-4 w-4" /> : <Power className="h-4 w-4" />}
                      </button>
                      <button
                        className="p-1.5 rounded-cs-sm hover:bg-cs-hair-2 text-cs-crit"
                        title="Delete"
                        onClick={async () => {
                          if (await confirm({
                            title: 'Delete data-match source',
                            confirmLabel: 'Delete',
                            children: `Delete "${s.name}"? Its index is removed.`,
                          })) remove.mutate(s.id)
                        }}
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
        {list.length > 0 && (
          <div className="px-4 py-3 border-t border-cs-hair">
            <DataPagination
              page={sourcesPg.page}
              pageSize={sourcesPg.pageSize}
              total={sourcesPg.total}
              onPageChange={sourcesPg.setPage}
              onPageSizeChange={sourcesPg.setPageSize}
            />
          </div>
        )}
      </div>

      {createOpen && <CreateModal onClose={() => setCreateOpen(false)} onSaved={() => { setCreateOpen(false); qc.invalidateQueries({ queryKey: ['data-match-sources'] }) }} />}
      {testOpen && <TestModal onClose={() => setTestOpen(false)} />}
      {confirmDialog}
    </div>
  )
}

// -- Create modal --------------------------------------------------------
function CreateModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [tab, setTab] = useState<'edm' | 'fingerprint'>('edm')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [classification, setClassification] = useState('Restricted')
  // EDM
  const [csvText, setCsvText] = useState('')
  const [csvFile, setCsvFile] = useState<File | null>(null)
  const [columns, setColumns] = useState('')
  const [minFields, setMinFields] = useState(2)
  // Fingerprint
  const [docText, setDocText] = useState('')
  const [docFile, setDocFile] = useState<File | null>(null)
  const [minShingles, setMinShingles] = useState(4)
  const [minContainment, setMinContainment] = useState(0.25)

  const save = useMutation({
    mutationFn: async () => {
      if (!name.trim()) throw new Error('Name is required')
      if (tab === 'edm') {
        const cols = columns.split(',').map((c) => c.trim()).filter(Boolean)
        const csv_b64 = csvFile ? await fileToBase64(csvFile) : (csvText.trim() ? utf8ToB64(csvText) : undefined)
        if (!csv_b64) throw new Error('Provide a CSV file or paste CSV text')
        return createEdm({ name, description, columns: cols.length ? cols : undefined, csv_b64, min_fields: minFields, classification })
      }
      const file_b64 = docFile ? await fileToBase64(docFile) : undefined
      const content = docText.trim() || undefined
      if (!file_b64 && !content) throw new Error('Provide a document file or paste text')
      return createFingerprint({ name, description, content, file_b64, filename: docFile?.name, min_shingles: minShingles, min_containment: minContainment, classification })
    },
    onSuccess: () => { toast.success('Source indexed -- plaintext discarded'); onSaved() },
    onError: (e: any) => toast.error(extractErrorDetail(e, e?.message || 'Failed to index source')),
  })

  return (
    <Modal title="New data-match source" onClose={onClose}>
      <div className="flex gap-1 mb-4 border-b border-cs-hair">
        {(['edm', 'fingerprint'] as const).map((t) => (
          <button key={t}
            className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px ${tab === t ? 'border-cs-indigo text-cs-indigo' : 'border-transparent text-cs-muted'}`}
            onClick={() => setTab(t)}>
            {t === 'edm' ? 'Exact Data Match (records)' : 'Fingerprint (document)'}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        <Field label="Name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={tab === 'edm' ? 'Customer PII 2026' : 'Board memo Q3'} /></Field>
        <Field label="Description (optional)"><input className="input" value={description} onChange={(e) => setDescription(e.target.value)} /></Field>

        {tab === 'edm' ? (
          <>
            <Field label="CSV file"><input type="file" accept=".csv,text/csv" onChange={(e) => setCsvFile(e.target.files?.[0] || null)} className="text-sm" /></Field>
            <Field label="...or paste CSV (header row + records)">
              <textarea className="input font-mono text-xs" rows={4} value={csvText} onChange={(e) => setCsvText(e.target.value)}
                placeholder={'first,last,ssn\nJane,Doe,123-45-6789'} />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Columns to index (optional, comma-sep)"><input className="input" value={columns} onChange={(e) => setColumns(e.target.value)} placeholder="all columns" /></Field>
              <Field label="Fields required to match">
                <input type="number" min={1} max={20} className="input" value={minFields} onChange={(e) => setMinFields(Number(e.target.value) || 2)} />
              </Field>
            </div>
            <p className="text-xs text-cs-muted">A record fires only when this many of its fields appear together -- the combination rule that stops random look-alikes.</p>
          </>
        ) : (
          <>
            <Field label="Document file"><input type="file" onChange={(e) => setDocFile(e.target.files?.[0] || null)} className="text-sm" /></Field>
            <Field label="...or paste document text"><textarea className="input text-xs" rows={5} value={docText} onChange={(e) => setDocText(e.target.value)} /></Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Min overlapping shingles"><input type="number" min={1} className="input" value={minShingles} onChange={(e) => setMinShingles(Number(e.target.value) || 4)} /></Field>
              <Field label="...or containment"><input type="number" step={0.05} min={0.01} max={1} className="input" value={minContainment} onChange={(e) => setMinContainment(Number(e.target.value) || 0.25)} /></Field>
            </div>
            <p className="text-xs text-cs-muted">Catches partial and lightly-edited copies, not just byte-identical files.</p>
          </>
        )}

        <Field label="Classify a match as">
          <select className="input" value={classification} onChange={(e) => setClassification(e.target.value)}>
            {CLASSIFICATIONS.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </Field>
      </div>

      <div className="flex justify-end gap-2 mt-5">
        <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" disabled={save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? 'Indexing...' : 'Index source'}
        </button>
      </div>
    </Modal>
  )
}

// -- Test modal -----------------------------------------------------------
function TestModal({ onClose }: { onClose: () => void }) {
  const [content, setContent] = useState('')
  const [result, setResult] = useState<MatchResult | null>(null)
  const run = useMutation({
    mutationFn: () => testContent(content),
    onSuccess: (r) => setResult(r),
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Test failed')),
  })
  return (
    <Modal title="Test content against sources" onClose={onClose}>
      <p className="text-sm text-cs-ink-2 mb-3">Paste text to see what it would match. Nothing is stored and no event is created.</p>
      <textarea className="input text-sm" rows={6} value={content} onChange={(e) => setContent(e.target.value)} placeholder="Paste an email body, a record, a document excerpt..." />
      <div className="flex justify-end mt-3">
        <button className="btn btn-primary" disabled={run.isPending || !content.trim()} onClick={() => run.mutate()}>
          {run.isPending ? 'Testing...' : 'Run test'}
        </button>
      </div>
      {result && (
        <div className="mt-4 rounded-cs-sm border border-cs-hair p-3">
          <div className={`font-medium mb-2 ${result.matched ? 'text-cs-crit' : 'text-cs-ok'}`}>
            {result.matched ? `Matched ${result.match_count} source(s)` : 'No match'}
          </div>
          <ul className="space-y-1 text-sm">
            {result.matches.map((m) => (
              <li key={m.source_id} className="flex items-center gap-2">
                <span className="badge badge-info">{m.type === 'edm' ? 'EDM' : 'FP'}</span>
                <span className="font-medium text-cs-ink">{m.name}</span>
                <span className="text-cs-muted text-xs">
                  {m.type === 'edm' ? `${m.matched_rows} record(s)` : `overlap ${m.overlap}, containment ${Math.round((m.containment || 0) * 100)}%`}
                </span>
                <span className="badge badge-danger ml-auto">{m.classification}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Modal>
  )
}

// -- shared bits -----------------------------------------------------------
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="block text-xs font-medium text-cs-ink-2 mb-1">{label}</span>
      {children}
    </label>
  )
}

// Delegates to the shared Modal primitive (src/components/ui/Modal.tsx,
// gap-scan port of CyberSentinel-DLP commit 73f58ec) while keeping this
// file's existing {title, onClose, children} call sites unchanged. The
// previous version here used rounded-cs-card / shadow-card, neither of
// which were ever registered in tailwind.config.cjs -- those classes
// generated no CSS at all, on top of the max-h-[90vh]-on-the-panel
// scroll bug every hand-rolled dialog in the app shared.
function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <SharedModal
      open
      onClose={onClose}
      size="lg"
      label={title}
      header={
        <ModalHeader
          title={
            <span className="flex items-center gap-2">
              <Fingerprint className="h-5 w-5 text-cs-indigo" />
              {title}
            </span>
          }
          onClose={onClose}
        />
      }
    >
      {children}
    </SharedModal>
  )
}
