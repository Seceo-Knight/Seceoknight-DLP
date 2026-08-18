import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Printer, ShieldCheck, ShieldAlert, Plus, Trash2, Check, Ban } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { extractErrorDetail } from '@/utils/errorUtils'
import {
  listPrinters, approvePrinter, updatePrinter, revokePrinter, setPrinterEnforcement,
  type SanctionedPrinter,
} from '@/lib/printers-api'
import { usePagination } from '@/lib/hooks/useTableState'
import { DataPagination } from '@/components/ui/pagination'

// Ported from the CyberSentinel-DLP reference project. Device control (this
// page) and print CONTENT inspection (a separate print_content_prevention
// policy) both have real agent-side enforcement — see ShouldBlockPrinter()
// and EvaluatePrintContent() in agent.cpp.
//
// decision='deny' rows are a sticky, audited "never allow this printer" —
// checked in EVERY enforcement scope (block_all/block_network/block_local/
// allowlist), not just allowlist mode. That's what makes "block this one
// printer, leave the rest of the fleet alone" possible without moving the
// whole estate into allowlist scope, same pattern as USB Devices.

const fmt = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')

export default function Printers() {
  const qc = useQueryClient()
  const printersQ = useQuery({ queryKey: ['printers'], queryFn: listPrinters })

  const invalidate = () => qc.invalidateQueries({ queryKey: ['printers'] })

  const enforcement = useMutation({
    mutationFn: (enabled: boolean) => setPrinterEnforcement({ enabled }),
    onSuccess: (r) => { invalidate(); toast.success(r.enforced ? 'Allowlist enforcement on' : 'Allowlist enforcement off') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Failed to update enforcement')),
  })

  // Must run before the isLoading/error early returns -- see the same note
  // in UsbDevices.tsx (hooks can't be called conditionally).
  const allPrinters = printersQ.data?.printers || []
  const sanctioned = allPrinters.filter((p) => p.decision !== 'deny')
  const disallowed = allPrinters.filter((p) => p.decision === 'deny')
  const sanctionedPg = usePagination(sanctioned, 25)
  const disallowedPg = usePagination(disallowed, 25)

  if (printersQ.isLoading) return <LoadingSpinner size="lg" />
  if (printersQ.error) return <ErrorMessage message="Failed to load printers" retry={() => printersQ.refetch()} />

  const enforced = printersQ.data?.enforced

  return (
    <div className="space-y-6">
      <div>
        <p className="eyebrow mb-1.5">Device Control</p>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-cs-ink">Printers</h1>
          {enforced
            ? <span className="badge badge-success inline-flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" />Allowlist enforcing</span>
            : <span className="badge badge-warning inline-flex items-center gap-1"><ShieldAlert className="h-3.5 w-3.5" />Allowlist off</span>}
        </div>
        <p className="mt-1 text-sm text-cs-ink-2">
          Sanctioned-printer allow/deny registry by name. Disallowed printers below are blocked in
          every printer-control scope, whether or not the allowlist toggle is on — see the Disallowed
          section.
        </p>
      </div>

      <div className="card">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-cs-indigo-faint rounded-cs-sm"><Printer className="h-5 w-5 text-cs-indigo" /></div>
          <div className="flex-1">
            <h3 className="section-title">Allowlist enforcement</h3>
            <p className="text-sm text-cs-muted">
              Turns on scope "allowlist": only printers in Sanctioned below are permitted, everything
              else is blocked. Independent of Disallowed printers, which block regardless of this switch.
            </p>
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

      <Section title="Sanctioned printers" count={sanctioned.length}>
        {sanctioned.length === 0 ? (
          <Empty text="No printers approved yet. Approve one by name above." />
        ) : (
          <>
            <Table headers={['Printer', 'Label', 'Type', 'Status', 'Approved', '']}>
              {sanctionedPg.pageRows.map((p) => (
                <PrinterRow key={p.id} p={p} onChange={invalidate} />
              ))}
            </Table>
            <DataPagination
              page={sanctionedPg.page}
              pageSize={sanctionedPg.pageSize}
              total={sanctioned.length}
              onPageChange={sanctionedPg.setPage}
              onPageSizeChange={sanctionedPg.setPageSize}
            />
          </>
        )}
      </Section>

      <Section
        title="Disallowed printers"
        count={disallowed.length}
        subtitle="Explicitly denied by name — a sticky, audited rejection enforced in every scope, not just allowlist mode."
      >
        {disallowed.length === 0 ? (
          <Empty text="No printers disallowed. Deny one by name above." />
        ) : (
          <>
            <Table headers={['Printer', 'Label', 'Type', 'Status', 'Denied', '']}>
              {disallowedPg.pageRows.map((p) => (
                <PrinterRow key={p.id} p={p} onChange={invalidate} />
              ))}
            </Table>
            <DataPagination
              page={disallowedPg.page}
              pageSize={disallowedPg.pageSize}
              total={disallowed.length}
              onPageChange={disallowedPg.setPage}
              onPageSizeChange={disallowedPg.setPageSize}
            />
          </>
        )}
      </Section>
    </div>
  )
}

function Section({ title, count, subtitle, children }: {
  title: string; count: number; subtitle?: string; children: React.ReactNode
}) {
  return (
    <div>
      <div className="flex items-baseline gap-2 mb-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-cs-muted">{title}</h2>
        <span className="badge badge-info">{count}</span>
      </div>
      {subtitle && <p className="text-xs text-cs-muted mb-2">{subtitle}</p>}
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

function PrinterRow({ p, onChange }: { p: SanctionedPrinter; onChange: () => void }) {
  const toggle = useMutation({
    mutationFn: () => updatePrinter(p.id, { is_enabled: !p.is_enabled }),
    onSuccess: () => { onChange(); toast.success(p.is_enabled ? 'Printer suspended' : 'Printer re-enabled') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Update failed')),
  })
  const flip = useMutation({
    mutationFn: () => updatePrinter(p.id, { decision: p.decision === 'deny' ? 'allow' : 'deny' }),
    onSuccess: () => { onChange(); toast.success(p.decision === 'deny' ? 'Printer moved to Sanctioned' : 'Printer moved to Disallowed') },
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
          disabled={flip.isPending} onClick={() => flip.mutate()}>
          {p.decision === 'deny' ? <><Check className="h-3.5 w-3.5" />Allow</> : <><Ban className="h-3.5 w-3.5" />Disallow</>}
        </button>
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
  const decide = useMutation({
    mutationFn: (decision: 'allow' | 'deny') => approvePrinter({ printer_name: name.trim(), label: label.trim() || undefined, decision }),
    onSuccess: (_r, decision) => { setName(''); setLabel(''); onDone(); toast.success(decision === 'deny' ? `Disallowed ${name.trim()}` : `Approved ${name.trim()}`) },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Failed')),
  })
  return (
    <div className="card">
      <div className="flex items-center gap-2 text-sm font-semibold text-cs-ink mb-3">
        <Plus className="h-4 w-4 text-cs-indigo" /> Approve or disallow a printer by name
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
        <button className="btn btn-secondary inline-flex items-center gap-1"
          disabled={decide.isPending || !name.trim()} onClick={() => decide.mutate('deny')}>
          <Ban className="h-3.5 w-3.5" />Disallow
        </button>
        <button className="btn btn-primary inline-flex items-center gap-1"
          disabled={decide.isPending || !name.trim()} onClick={() => decide.mutate('allow')}>
          <Check className="h-3.5 w-3.5" />{decide.isPending ? 'Working…' : 'Approve'}
        </button>
      </div>
    </div>
  )
}
