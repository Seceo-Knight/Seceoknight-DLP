import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Printer, ShieldAlert, Plus, Trash2, Check, Ban, Info } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { extractErrorDetail } from '@/utils/errorUtils'
import {
  listPrinters, approvePrinter, updatePrinter, revokePrinter, setPrinterEnforcement,
  type SanctionedPrinter,
} from '@/lib/printers-api'

// Ported from the CyberSentinel-DLP reference project. NOTE: the Windows
// agent doesn't monitor print jobs yet, so this page manages the allowlist
// ahead of that — the enforcement toggle below reflects an admin's intent
// only, nothing is actually blocked by it today.

const fmt = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')

export default function Printers() {
  const qc = useQueryClient()
  const printersQ = useQuery({ queryKey: ['printers'], queryFn: listPrinters })

  const invalidate = () => qc.invalidateQueries({ queryKey: ['printers'] })

  const enforcement = useMutation({
    mutationFn: (enabled: boolean) => setPrinterEnforcement({ enabled }),
    onSuccess: (r) => { invalidate(); toast.success(r.enforced ? 'Allowlist marked as enforced' : 'Allowlist marked as not enforced') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Failed to update enforcement')),
  })

  if (printersQ.isLoading) return <LoadingSpinner size="lg" />
  if (printersQ.error) return <ErrorMessage message="Failed to load printers" retry={() => printersQ.refetch()} />

  const enforced = printersQ.data?.enforced

  return (
    <div className="space-y-6">
      <div>
        <p className="eyebrow mb-1.5">Device Control</p>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-cs-ink">Printers</h1>
          <span className="badge badge-warning inline-flex items-center gap-1">
            <ShieldAlert className="h-3.5 w-3.5" />{enforced ? 'Marked enforced' : 'Not enforced'}
          </span>
        </div>
        <p className="mt-1 text-sm text-cs-ink-2">
          Sanctioned-printer allowlist by name. This page manages the list ahead of print-job
          monitoring — see the notice below.
        </p>
      </div>

      <div className="card border-warning/30">
        <div className="flex items-start gap-3">
          <Info className="h-5 w-5 text-warning shrink-0 mt-0.5" />
          <p className="text-sm text-cs-ink-2">
            SeceoKnight's Windows agent doesn't monitor print jobs yet, so nothing is actually blocked
            based on this list today. Build out the allowlist now so it's ready the moment print-job
            monitoring ships — the toggle below only records intent.
          </p>
        </div>
      </div>

      <div className="card">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-cs-indigo-faint rounded-cs-sm"><Printer className="h-5 w-5 text-cs-indigo" /></div>
          <div className="flex-1">
            <h3 className="section-title">Enforcement (readiness switch)</h3>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 mt-4">
          <button
            className={enforced ? 'btn btn-primary' : 'btn btn-secondary'}
            disabled={enforcement.isPending}
            onClick={() => enforcement.mutate(true)}
          >
            On
          </button>
          <button
            className={!enforced ? 'btn btn-primary' : 'btn btn-secondary'}
            disabled={enforcement.isPending}
            onClick={() => enforcement.mutate(false)}
          >
            Off
          </button>
        </div>
      </div>

      <ApproveForm onDone={invalidate} />

      <Section title="Sanctioned printers" count={printersQ.data?.count || 0}>
        {(printersQ.data?.printers.length || 0) === 0 ? (
          <Empty text="No printers approved yet. Approve one by name above." />
        ) : (
          <Table headers={['Printer', 'Label', 'Type', 'Status', 'Approved', '']}>
            {printersQ.data!.printers.map((p) => (
              <SanctionedRow key={p.id} p={p} onChange={invalidate} />
            ))}
          </Table>
        )}
      </Section>
    </div>
  )
}

function Section({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  return (
    <div>
      <div className="flex items-baseline gap-2 mb-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-cs-muted">{title}</h2>
        <span className="badge badge-info">{count}</span>
      </div>
      {children}
    </div>
  )
}

function Table({ headers, children }: { headers: string[]; children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-card">
      <table className="table">
        <thead>
          <tr>
            {headers.map((h, i) => <th key={i}>{h}</th>)}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

function Empty({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-border bg-card p-6 text-center text-sm text-cs-muted">
      <Printer className="h-8 w-8 mx-auto mb-2 text-cs-muted-2" />
      {text}
    </div>
  )
}

function SanctionedRow({ p, onChange }: { p: SanctionedPrinter; onChange: () => void }) {
  const toggle = useMutation({
    mutationFn: () => updatePrinter(p.id, { is_enabled: !p.is_enabled }),
    onSuccess: () => { onChange(); toast.success(p.is_enabled ? 'Printer suspended' : 'Printer re-enabled') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Update failed')),
  })
  const revoke = useMutation({
    mutationFn: () => revokePrinter(p.id),
    onSuccess: () => { onChange(); toast.success('Approval revoked') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Revoke failed')),
  })
  return (
    <tr>
      <td className="text-cs-ink break-words">{p.printer_name}</td>
      <td className="text-cs-ink-2">{p.label || '—'}</td>
      <td className="text-cs-ink-2 capitalize">{p.printer_type || '—'}</td>
      <td>
        {p.is_enabled
          ? <span className="badge badge-success">Enabled</span>
          : <span className="badge badge-warning">Suspended</span>}
      </td>
      <td className="text-cs-muted text-xs">{fmt(p.approved_at)}</td>
      <td className="text-right whitespace-nowrap">
        <button className="text-xs text-cs-ink-2 hover:text-cs-ink mr-3 inline-flex items-center gap-1"
          disabled={toggle.isPending} onClick={() => toggle.mutate()}>
          {p.is_enabled ? <><Ban className="h-3.5 w-3.5" />Suspend</> : <><Check className="h-3.5 w-3.5" />Enable</>}
        </button>
        <button className="text-xs text-critical hover:underline inline-flex items-center gap-1"
          disabled={revoke.isPending} onClick={() => revoke.mutate()}>
          <Trash2 className="h-3.5 w-3.5" />Revoke
        </button>
      </td>
    </tr>
  )
}

function ApproveForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState('')
  const [label, setLabel] = useState('')
  const approve = useMutation({
    mutationFn: () => approvePrinter({ printer_name: name.trim(), label: label.trim() || undefined }),
    onSuccess: () => { setName(''); setLabel(''); onDone(); toast.success('Printer approved') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Approve failed')),
  })
  return (
    <div className="card">
      <div className="flex items-center gap-2 text-sm font-semibold text-cs-ink mb-3">
        <Plus className="h-4 w-4 text-cs-indigo" /> Approve a printer by name
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex-1 min-w-[240px]">
          <label className="text-xs text-cs-ink-2 mb-1 block">Printer name</label>
          <input className="input text-sm" value={name} onChange={(e) => setName(e.target.value)}
            placeholder={'e.g. HP LaserJet 400  or  \\\\server\\Reception'} />
        </div>
        <div className="flex-1 min-w-[180px]">
          <label className="text-xs text-cs-ink-2 mb-1 block">Label (optional)</label>
          <input className="input text-sm" value={label} onChange={(e) => setLabel(e.target.value)}
            placeholder="e.g. Finance floor 2" />
        </div>
        <button className="btn btn-primary" disabled={approve.isPending || !name.trim()}
          onClick={() => approve.mutate()}>
          {approve.isPending ? 'Approving…' : 'Approve'}
        </button>
      </div>
    </div>
  )
}
