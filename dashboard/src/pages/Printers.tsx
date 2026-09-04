import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Printer, ShieldCheck, ShieldAlert, Plus, Trash2, Check, Ban, AlertTriangle } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { extractErrorDetail } from '@/utils/errorUtils'
import { PageHeader } from '@/components/ui/page-header'
import { useConfirm } from '@/components/ui/Modal'
import {
  listPrinters, approvePrinter, updatePrinter, revokePrinter, setPrinterEnforcement,
  type SanctionedPrinter, type PrinterControlScope, type PrinterControlMode,
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
//
// Scope/mode: this page's quick toggle used to only ever be able to write
// scope="allowlist" with implicit "enforce" mode -- block_all/block_network/
// block_local and audit mode were only reachable through the general Policy
// Creator's PrinterControlPolicyForm, even though both surfaces edit the
// SAME printer_control policy row. That meant a button here could silently
// clobber a richer config set up there. Now both control surfaces write and
// read the same two config keys (scope, mode).

const fmt = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')

const SCOPE_LABEL: Record<string, string> = {
  block_all: 'Block all printing',
  block_network: 'Block network printers',
  block_local: 'Block local printers',
  allowlist: 'Allowlist',
}
const SCOPE_STATUS_LABEL: Record<string, string> = {
  block_all: 'Blocking all printing',
  block_network: 'Blocking network printers',
  block_local: 'Blocking local printers',
  allowlist: 'Enforcing allowlist',
}
const SCOPE_HINT: Record<string, string> = {
  block_all: 'No printer — local or network — is allowed.',
  block_network: 'Directly-attached local printers still work; network/shared printers are blocked.',
  block_local: 'Network/shared printers still work; directly-attached local printers are blocked.',
  allowlist: 'Only printers in Sanctioned below are permitted; everything else is blocked.',
}

export default function Printers() {
  const qc = useQueryClient()
  const printersQ = useQuery({ queryKey: ['printers'], queryFn: listPrinters })
  const { confirm, dialog: confirmDialog } = useConfirm()

  const invalidate = () => qc.invalidateQueries({ queryKey: ['printers'] })

  const enforcement = useMutation({
    mutationFn: (body: { enabled: boolean; scope?: PrinterControlScope; mode?: PrinterControlMode }) =>
      setPrinterEnforcement(body as { enabled: boolean; scope?: Exclude<PrinterControlScope, 'none'>; mode?: Exclude<PrinterControlMode, 'off'> }),
    onSuccess: (r) => {
      invalidate()
      toast.success(r.enforced ? `${SCOPE_STATUS_LABEL[r.scope] || 'Enforcing'} (${r.mode})` : 'Printer control off')
    },
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
  // Fall back to sensible defaults when off/unset, so switching scope or
  // mode from an "off" state lands somewhere reasonable instead of sending
  // "none"/"off" back to the server.
  const scope: PrinterControlScope = enforced && printersQ.data?.scope && printersQ.data.scope !== 'none'
    ? printersQ.data.scope : 'allowlist'
  const mode: PrinterControlMode = enforced && printersQ.data?.mode && printersQ.data.mode !== 'off'
    ? printersQ.data.mode : 'enforce'

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Printer}
        eyebrow="Device Control"
        title="Printers"
        badge={
          enforced
            ? <span className="badge badge-success inline-flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" />{SCOPE_STATUS_LABEL[scope] || 'Enforcing'} ({mode})</span>
            : <span className="badge badge-warning inline-flex items-center gap-1"><ShieldAlert className="h-3.5 w-3.5" />Not enforced</span>
        }
        description="Sanctioned-printer allow/deny registry by name. Disallowed printers below are blocked in every printer-control scope, whether or not enforcement is on — see the Disallowed section."
      />

      <div className="card">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-primary/10 rounded-lg"><Printer className="h-5 w-5 text-primary" /></div>
          <div className="flex-1">
            <h3 className="section-title">Enforcement</h3>
            <p className="text-sm text-muted-foreground">
              Same scope/mode options as the Printer Device Control policy type in the Policy Creator —
              this page and that form edit the same policy, so whichever you use last wins.
              {enforced && <> {SCOPE_HINT[scope]}</>}
            </p>
          </div>
        </div>

        <div className="mt-4">
          <label className="text-xs font-medium text-muted-foreground mb-2 block">Scope</label>
          <div className="flex flex-wrap items-center gap-2">
            {(['block_all', 'block_network', 'block_local', 'allowlist'] as const).map((s) => (
              <button
                key={s}
                className={enforced && scope === s ? 'btn btn-primary' : 'btn btn-secondary'}
                disabled={enforcement.isPending}
                onClick={() => enforcement.mutate({ enabled: true, scope: s, mode })}
              >
                {SCOPE_LABEL[s]}
              </button>
            ))}
            <button
              className={!enforced ? 'btn btn-primary' : 'btn btn-secondary'}
              disabled={enforcement.isPending}
              onClick={() => enforcement.mutate({ enabled: false })}
            >
              Off
            </button>
          </div>
        </div>

        {enforced && (
          <div className="mt-4">
            <label className="text-xs font-medium text-muted-foreground mb-2 block">Mode</label>
            <div className="flex flex-wrap items-center gap-2">
              <button
                className={mode === 'enforce' ? 'btn btn-primary' : 'btn btn-secondary'}
                disabled={enforcement.isPending}
                onClick={() => enforcement.mutate({ enabled: true, scope, mode: 'enforce' })}
              >
                Enforce
              </button>
              <button
                className={mode === 'audit' ? 'btn btn-primary' : 'btn btn-secondary'}
                disabled={enforcement.isPending}
                onClick={() => enforcement.mutate({ enabled: true, scope, mode: 'audit' })}
              >
                Audit only
              </button>
            </div>
          </div>
        )}
      </div>

      {enforced && scope !== 'allowlist' && (
        <div className="flex items-start gap-2 rounded-lg border border-info/30 bg-info/10 p-3 text-sm text-info">
          <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
          Scope is "{SCOPE_LABEL[scope]}", not Allowlist — the Sanctioned printers list below isn't
          consulted in this scope. Only Disallowed (deny) rows are still enforced regardless of scope.
        </div>
      )}

      <ApproveForm onDone={invalidate} />

      <Section title="Sanctioned printers" count={sanctioned.length}>
        {sanctioned.length === 0 ? (
          <Empty text="No printers approved yet. Approve one by name above." />
        ) : (
          <>
            <Table headers={['Printer', 'Label', 'Type', 'Status', 'Approved', '']}>
              {sanctionedPg.pageRows.map((p) => (
                <PrinterRow key={p.id} p={p} onChange={invalidate} confirm={confirm} />
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
                <PrinterRow key={p.id} p={p} onChange={invalidate} confirm={confirm} />
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
      {confirmDialog}
    </div>
  )
}

function Section({ title, count, subtitle, children }: {
  title: string; count: number; subtitle?: string; children: React.ReactNode
}) {
  return (
    <div>
      <div className="flex items-baseline gap-2 mb-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">{title}</h2>
        <span className="badge badge-info">{count}</span>
      </div>
      {subtitle && <p className="text-xs text-muted-foreground mb-2">{subtitle}</p>}
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
    <div className="rounded-lg border border-border bg-card p-6 text-center text-sm text-muted-foreground">
      <Printer className="h-8 w-8 mx-auto mb-2 text-muted-foreground/65" />
      {text}
    </div>
  )
}

function PrinterRow({ p, onChange, confirm }: {
  p: SanctionedPrinter
  onChange: () => void
  confirm: ReturnType<typeof useConfirm>['confirm']
}) {
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
      <td className="text-foreground break-words">{p.printer_name}</td>
      <td className="text-foreground/78">{p.label || '—'}</td>
      <td className="text-foreground/78 capitalize">{p.printer_type || '—'}</td>
      <td>
        {p.is_enabled
          ? <span className="badge badge-success">Enabled</span>
          : <span className="badge badge-warning">Suspended</span>}
      </td>
      <td className="text-muted-foreground text-xs">{fmt(p.approved_at)}</td>
      <td className="text-right whitespace-nowrap">
        <button className="text-xs text-foreground/78 hover:text-foreground mr-3 inline-flex items-center gap-1"
          disabled={flip.isPending} onClick={() => flip.mutate()}>
          {p.decision === 'deny' ? <><Check className="h-3.5 w-3.5" />Allow</> : <><Ban className="h-3.5 w-3.5" />Disallow</>}
        </button>
        <button className="text-xs text-foreground/78 hover:text-foreground mr-3 inline-flex items-center gap-1"
          disabled={toggle.isPending} onClick={() => toggle.mutate()}>
          {p.is_enabled ? <><Ban className="h-3.5 w-3.5" />Suspend</> : <><Check className="h-3.5 w-3.5" />Enable</>}
        </button>
        <button className="text-xs text-critical hover:underline inline-flex items-center gap-1"
          disabled={revoke.isPending}
          onClick={async () => {
            const ok = await confirm({
              title: 'Revoke this printer?',
              confirmLabel: 'Revoke approval',
              children: (
                <>
                  This removes <span className="font-medium text-foreground">{p.printer_name}</span> from
                  the registry entirely{p.label ? <> ({p.label})</> : null}. If allowlist scope is
                  enforced, this printer will be blocked the next time it's used.
                </>
              ),
            })
            if (ok) revoke.mutate()
          }}>
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
      <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-3">
        <Plus className="h-4 w-4 text-primary" /> Approve or disallow a printer by name
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex-1 min-w-[240px]">
          <label className="text-xs text-foreground/78 mb-1 block">Printer name</label>
          <input className="input text-sm" value={name} onChange={(e) => setName(e.target.value)}
            placeholder={'e.g. HP LaserJet 400  or  \\\\server\\Reception'} />
        </div>
        <div className="flex-1 min-w-[180px]">
          <label className="text-xs text-foreground/78 mb-1 block">Label (optional)</label>
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
