import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Usb, ShieldCheck, ShieldAlert, Plus, Trash2, Check, Ban, History, Pencil, EyeOff, Undo2 } from 'lucide-react'
import Modal, { ModalHeader } from '@/components/ui/Modal'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { extractErrorDetail } from '@/utils/errorUtils'
import {
  listDevices, seenDevices, approveDevice, updateDevice, revokeDevice, setUsbEnforcement, deviceActivity,
  dismissSeenDevice, restoreSeenDevice,
  type SanctionedDevice, type SeenDevice, type DeviceActivityEvent,
} from '@/lib/usb-devices-api'
import { usePagination } from '@/lib/hooks/useTableState'
import { DataPagination } from '@/components/ui/pagination'

// Ported from the CyberSentinel-DLP reference project (see
// SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md). Strict allowlist: when
// enforcement is on, the Windows agent blocks any USB storage device whose
// serial number isn't approved below. Serial numbers only surface here once
// an agent build with allowlist support has reported at least one connect
// event — see agent.cpp's ExtractUsbSerialFromDeviceId().
//
// decision='deny' rows (added alongside alias/connected/history) are a
// sticky, audited "never allow this serial" — distinct from simply never
// approving it, since a denied serial is excluded from the Seen enrolment
// queue instead of sitting there waiting to be (accidentally) approved.

const fmt = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')
const vidpid = (v?: string | null, p?: string | null) => (v || p ? `${v || '????'}:${p || '????'}` : '—')

export default function UsbDevices() {
  const qc = useQueryClient()
  const devicesQ = useQuery({ queryKey: ['usb-devices'], queryFn: listDevices })
  const [showDismissed, setShowDismissed] = useState(false)
  const seenQ = useQuery({
    queryKey: ['usb-devices-seen', showDismissed],
    queryFn: () => seenDevices(showDismissed),
  })
  const [historySerial, setHistorySerial] = useState<string | null>(null)

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['usb-devices'] })
    qc.invalidateQueries({ queryKey: ['usb-devices-seen'] })
  }

  const enforcement = useMutation({
    mutationFn: (body: { enabled: boolean; mode?: 'enforce' | 'audit' }) => setUsbEnforcement(body),
    onSuccess: (r) => { invalidate(); toast.success(r.enforced ? `Enforcement on (${r.mode})` : 'Enforcement off') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Failed to update enforcement')),
  })

  // These three usePagination calls must run unconditionally on every
  // render, before the isLoading/error early returns below -- calling
  // hooks after a conditional return would change the number of hooks
  // invoked between the loading render and the loaded render, which
  // violates React's rules of hooks. Falls back to empty arrays while
  // devicesQ/seenQ haven't resolved yet.
  const allDevices = devicesQ.data?.devices || []
  const sanctioned = allDevices.filter((d) => d.decision !== 'deny')
  const disallowed = allDevices.filter((d) => d.decision === 'deny')
  const seenDevicesList = seenQ.data?.devices || []

  const sanctionedPg = usePagination(sanctioned, 25)
  const disallowedPg = usePagination(disallowed, 25)
  const seenPg = usePagination(seenDevicesList, 25)

  if (devicesQ.isLoading) return <LoadingSpinner size="lg" />
  if (devicesQ.error) return <ErrorMessage message="Failed to load USB devices" retry={() => devicesQ.refetch()} />

  const enforced = devicesQ.data?.enforced
  const mode = devicesQ.data?.mode || 'off'

  return (
    <div className="space-y-6">
      <div>
        <p className="eyebrow mb-1.5">Device Control</p>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-cs-ink">USB Devices</h1>
          {enforced
            ? <span className="badge badge-success inline-flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5" />Enforcing ({mode})</span>
            : <span className="badge badge-warning inline-flex items-center gap-1"><ShieldAlert className="h-3.5 w-3.5" />Not enforced</span>}
        </div>
        <p className="mt-1 text-sm text-cs-ink-2">
          Strict allowlist by device serial number. When enforcement is on, any USB storage device
          not approved below is blocked the moment it's plugged in — no reliance on file scanning.
        </p>
      </div>

      <div className="card">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-cs-indigo-faint rounded-cs-sm"><Usb className="h-5 w-5 text-cs-indigo" /></div>
          <div className="flex-1">
            <h3 className="section-title">Enforcement</h3>
            <p className="text-sm text-cs-muted">
              Enforce blocks unsanctioned devices immediately. Audit only logs what would have been
              blocked, without actually blocking anything — useful while building out the allowlist.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 mt-4">
          <button
            className={enforced && mode === 'enforce' ? 'btn btn-primary' : 'btn btn-secondary'}
            disabled={enforcement.isPending}
            onClick={() => enforcement.mutate({ enabled: true, mode: 'enforce' })}
          >
            Enforce
          </button>
          <button
            className={enforced && mode === 'audit' ? 'btn btn-primary' : 'btn btn-secondary'}
            disabled={enforcement.isPending}
            onClick={() => enforcement.mutate({ enabled: true, mode: 'audit' })}
          >
            Audit only
          </button>
          <button
            className={!enforced ? 'btn btn-primary' : 'btn btn-secondary'}
            disabled={enforcement.isPending}
            onClick={() => enforcement.mutate({ enabled: false })}
          >
            Off
          </button>
        </div>
      </div>

      <ApproveForm onDone={invalidate} />

      {/* Sanctioned devices */}
      <Section title="Sanctioned devices" count={sanctioned.length}>
        {sanctioned.length === 0 ? (
          <Empty text="No devices approved yet. Approve one by serial above, or from the seen list below." />
        ) : (
          <>
            <Table headers={['', 'Serial', 'Alias', 'Device', 'VID:PID', 'Status', 'Approved', '']}>
              {sanctionedPg.pageRows.map((d) => (
                <SanctionedRow key={d.id} d={d} onChange={invalidate} onHistory={() => setHistorySerial(d.serial_number)} />
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

      {/* Disallowed devices */}
      <Section
        title="Disallowed devices"
        count={disallowed.length}
        subtitle="Explicitly denied serials — a sticky, audited rejection. Excluded from the Seen list below so they don't get accidentally re-approved."
      >
        {disallowed.length === 0 ? (
          <Empty text="No devices disallowed. Deny one from the Seen list below, or by serial above." />
        ) : (
          <>
            <Table headers={['', 'Serial', 'Alias', 'Device', 'VID:PID', 'Status', 'Denied', '']}>
              {disallowedPg.pageRows.map((d) => (
                <SanctionedRow key={d.id} d={d} onChange={invalidate} onHistory={() => setHistorySerial(d.serial_number)} />
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

      {/* Seen but unsanctioned */}
      <Section
        title="Seen on endpoints — not sanctioned"
        count={seenQ.data?.count || 0}
        subtitle="Devices observed connecting to an agent that aren't on the allowlist. Approve to permit them, Disallow to reject, or Dismiss to clear a triage item you've already looked at without deciding (reversible, does not authorize the device)."
      >
        {(seenQ.data?.dismissed_count ?? 0) > 0 && (
          <label className="mb-2 flex items-center gap-2 text-xs text-cs-ink-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showDismissed}
              onChange={(e) => setShowDismissed(e.target.checked)}
              className="h-3.5 w-3.5"
            />
            Show dismissed ({seenQ.data?.dismissed_count})
          </label>
        )}
        {seenQ.isLoading ? (
          <LoadingSpinner />
        ) : seenDevicesList.length === 0 ? (
          <Empty text="No unsanctioned devices have been seen." />
        ) : (
          <>
            <Table headers={['', 'Serial', 'Device', 'VID:PID', 'Last seen', 'Agent', '']}>
              {seenPg.pageRows.map((s) => (
                <SeenRow key={s.serial_number} s={s} onApproved={invalidate} onHistory={() => setHistorySerial(s.serial_number)} />
              ))}
            </Table>
            <DataPagination
              page={seenPg.page}
              pageSize={seenPg.pageSize}
              total={seenDevicesList.length}
              onPageChange={seenPg.setPage}
              onPageSizeChange={seenPg.setPageSize}
            />
          </>
        )}
      </Section>

      {historySerial && (
        <HistoryModal serial={historySerial} onClose={() => setHistorySerial(null)} />
      )}
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
      <Usb className="h-8 w-8 mx-auto mb-2 text-cs-muted-2" />
      {text}
    </div>
  )
}

// Three states, not two (ported from CyberSentinel-DLP commit 7ae4671,
// August 26 2026). A connect event with no matching disconnect does NOT
// prove the device is still attached -- only a running agent emits a
// disconnect, so a machine that was shut down, slept, or had its agent
// stopped leaves its last connect standing forever. `connection_state` is
// the authoritative field; `connected` (legacy boolean) is accepted as a
// fallback for any caller that hasn't been updated to pass it yet.
//   green dot  = connected    -- reporting agent is online and says attached
//   grey dot   = unknown      -- last heard attached, but that agent has gone
//                                quiet, so an unplug could never have been reported
//   grey ring  = disconnected -- an actual unplug was reported (trusted)
function ConnectedDot({
  connectionState,
  connected,
}: {
  connectionState?: 'connected' | 'disconnected' | 'unknown' | null
  connected?: boolean
}) {
  const state = connectionState ?? (connected ? 'connected' : connected === false ? 'disconnected' : null)
  if (state === 'connected') {
    return <span className="inline-block h-2.5 w-2.5 rounded-full bg-success" title="Connected — reporting agent is online" />
  }
  if (state === 'unknown') {
    return (
      <span
        className="inline-block h-2.5 w-2.5 rounded-full bg-warning/70"
        title="Last seen attached, but the reporting agent has gone quiet since — it may or may not still be plugged in"
      />
    )
  }
  if (state === 'disconnected') {
    return <span className="inline-block h-2.5 w-2.5 rounded-full bg-cs-muted-2" title="Disconnected" />
  }
  return <span className="inline-block h-2.5 w-2.5 rounded-full bg-cs-muted-2 opacity-40" title="Not applicable / never seen" />
}

function AliasCell({ d, onChange }: { d: SanctionedDevice; onChange: () => void }) {
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState(d.alias || '')
  const save = useMutation({
    mutationFn: () => updateDevice(d.id, { alias: value.trim() || undefined }),
    onSuccess: () => { setEditing(false); onChange() },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Failed to update alias')),
  })
  if (editing) {
    return (
      <input
        autoFocus
        className="input text-xs py-0.5 px-1.5 w-32"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onBlur={() => save.mutate()}
        onKeyDown={(e) => { if (e.key === 'Enter') save.mutate(); if (e.key === 'Escape') setEditing(false) }}
        disabled={save.isPending}
      />
    )
  }
  return (
    <button
      className="text-xs text-cs-ink-2 hover:text-cs-ink inline-flex items-center gap-1 group"
      onClick={() => { setValue(d.alias || ''); setEditing(true) }}
      title="Click to edit alias"
    >
      {d.alias || <span className="text-cs-muted">—</span>}
      <Pencil className="h-3 w-3 opacity-0 group-hover:opacity-60" />
    </button>
  )
}

function SanctionedRow({ d, onChange, onHistory }: { d: SanctionedDevice; onChange: () => void; onHistory: () => void }) {
  const toggle = useMutation({
    mutationFn: () => updateDevice(d.id, { is_enabled: !d.is_enabled }),
    onSuccess: () => { onChange(); toast.success(d.is_enabled ? 'Device suspended' : 'Device re-enabled') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Update failed')),
  })
  const flip = useMutation({
    mutationFn: () => updateDevice(d.id, { decision: d.decision === 'deny' ? 'allow' : 'deny' }),
    onSuccess: () => { onChange(); toast.success(d.decision === 'deny' ? 'Device moved to Sanctioned' : 'Device moved to Disallowed') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Update failed')),
  })
  const revoke = useMutation({
    mutationFn: () => revokeDevice(d.id),
    onSuccess: () => { onChange(); toast.success('Approval revoked') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Revoke failed')),
  })
  return (
    <tr>
      <td><ConnectedDot connectionState={d.connection_state} connected={d.connected} /></td>
      <td className="num text-cs-ink">{d.serial_number}</td>
      <td><AliasCell d={d} onChange={onChange} /></td>
      <td className="text-cs-ink-2">{d.product_name || '—'}{d.manufacturer ? ` (${d.manufacturer})` : ''}</td>
      <td className="num text-cs-muted">{vidpid(d.vendor_id, d.product_id)}</td>
      <td>
        {d.is_enabled
          ? <span className="badge badge-success">Enabled</span>
          : <span className="badge badge-warning">Suspended</span>}
      </td>
      <td className="text-cs-muted text-xs">{fmt(d.approved_at)}</td>
      <td className="text-right whitespace-nowrap">
        <button className="text-xs text-cs-ink-2 hover:text-cs-ink mr-3 inline-flex items-center gap-1"
          onClick={onHistory} title="View insertion history">
          <History className="h-3.5 w-3.5" />History
        </button>
        <button className="text-xs text-cs-ink-2 hover:text-cs-ink mr-3 inline-flex items-center gap-1"
          disabled={flip.isPending} onClick={() => flip.mutate()}>
          {d.decision === 'deny' ? <><Check className="h-3.5 w-3.5" />Allow</> : <><Ban className="h-3.5 w-3.5" />Disallow</>}
        </button>
        <button className="text-xs text-cs-ink-2 hover:text-cs-ink mr-3 inline-flex items-center gap-1"
          disabled={toggle.isPending} onClick={() => toggle.mutate()}>
          {d.is_enabled ? <><Ban className="h-3.5 w-3.5" />Suspend</> : <><Check className="h-3.5 w-3.5" />Enable</>}
        </button>
        <button className="text-xs text-critical hover:underline inline-flex items-center gap-1"
          disabled={revoke.isPending} onClick={() => revoke.mutate()}>
          <Trash2 className="h-3.5 w-3.5" />Revoke
        </button>
      </td>
    </tr>
  )
}

function SeenRow({ s, onApproved, onHistory }: { s: SeenDevice; onApproved: () => void; onHistory: () => void }) {
  const decide = useMutation({
    mutationFn: (decision: 'allow' | 'deny') => approveDevice({
      serial_number: s.serial_number,
      vendor_id: s.vendor_id || undefined,
      product_id: s.product_id || undefined,
      product_name: s.product_name || undefined,
      decision,
    }),
    onSuccess: (_r, decision) => { onApproved(); toast.success(decision === 'deny' ? `Disallowed ${s.serial_number}` : `Approved ${s.serial_number}`) },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Failed')),
  })
  const dismiss = useMutation({
    mutationFn: () => dismissSeenDevice({
      serial_number: s.serial_number,
      product_name: s.product_name || undefined,
    }),
    onSuccess: () => { onApproved(); toast.success(`Dismissed ${s.serial_number} — not approved, just cleared from the queue`) },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Dismiss failed')),
  })
  const restore = useMutation({
    mutationFn: () => restoreSeenDevice(s.serial_number),
    onSuccess: () => { onApproved(); toast.success(`Restored ${s.serial_number} to the triage queue`) },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Restore failed')),
  })
  return (
    <tr className={s.dismissed ? 'opacity-60' : undefined}>
      <td><ConnectedDot connectionState={s.connection_state} connected={s.connected} /></td>
      <td className="num text-cs-ink">
        {s.serial_number}
        {s.dismissed && <span className="badge badge-info ml-2 text-[10px]">Dismissed</span>}
      </td>
      <td className="text-cs-ink-2">{s.product_name || '—'}</td>
      <td className="num text-cs-muted">{vidpid(s.vendor_id, s.product_id)}</td>
      <td className="text-cs-muted text-xs">{fmt(s.last_seen)}</td>
      <td className="text-cs-muted text-xs">
        {s.agent_name
          ? `${s.agent_name}${s.agent_code ? ` (#${String(s.agent_code).padStart(3, '0')})` : ''}`
          : (s.agent_id ? <span className="num">{s.agent_id}</span> : '—')}
      </td>
      <td className="text-right whitespace-nowrap">
        <button className="text-xs text-cs-ink-2 hover:text-cs-ink mr-3 inline-flex items-center gap-1"
          onClick={onHistory} title="View insertion history">
          <History className="h-3.5 w-3.5" />History
        </button>
        {s.dismissed ? (
          <button className="text-xs text-cs-ink-2 hover:text-cs-ink mr-3 inline-flex items-center gap-1"
            disabled={restore.isPending} onClick={() => restore.mutate()} title="Return to the active triage queue">
            <Undo2 className="h-3.5 w-3.5" />Restore
          </button>
        ) : (
          <button className="text-xs text-cs-ink-2 hover:text-cs-ink mr-3 inline-flex items-center gap-1"
            disabled={dismiss.isPending} onClick={() => dismiss.mutate()}
            title="Clear from the queue without approving or denying it -- reversible">
            <EyeOff className="h-3.5 w-3.5" />Dismiss
          </button>
        )}
        <button className="btn btn-secondary inline-flex items-center gap-1 mr-2"
          disabled={decide.isPending} onClick={() => decide.mutate('deny')}>
          <Ban className="h-3.5 w-3.5" />Disallow
        </button>
        <button className="btn btn-primary inline-flex items-center gap-1"
          disabled={decide.isPending} onClick={() => decide.mutate('allow')}>
          <Check className="h-3.5 w-3.5" />{decide.isPending ? 'Working…' : 'Approve'}
        </button>
      </td>
    </tr>
  )
}

function HistoryModal({ serial, onClose }: { serial: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['usb-device-activity', serial], queryFn: () => deviceActivity(serial) })
  return (
    <Modal
      open
      onClose={onClose}
      size="md"
      label="Insertion history"
      header={
        <ModalHeader
          title="Insertion history"
          hint={<span className="num">{serial}</span>}
          onClose={onClose}
        />
      }
    >
        <div className="text-sm">
          {q.isLoading ? (
            <LoadingSpinner />
          ) : (q.data?.events.length || 0) === 0 ? (
            <p className="text-cs-muted text-center py-6">No connect/disconnect activity recorded for this serial yet.</p>
          ) : (
            <ul className="space-y-2">
              {q.data!.events.map((e: DeviceActivityEvent, i: number) => (
                <li key={i} className="flex items-center justify-between border-b border-border/60 pb-2 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className={`badge ${e.event === 'connect' ? 'badge-success' : 'badge-info'}`}>
                      {e.event === 'connect' ? 'Connected' : 'Disconnected'}
                    </span>
                    <span className="text-cs-ink-2">
                      {e.agent_name
                        ? `${e.agent_name}${e.agent_code ? ` (#${String(e.agent_code).padStart(3, '0')})` : ''}`
                        : (e.agent_id || '—')}
                    </span>
                    {e.drive_letter && <span className="text-xs text-cs-muted num">{e.drive_letter}</span>}
                  </div>
                  <span className="text-xs text-cs-muted">{fmt(e.timestamp)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
    </Modal>
  )
}

function ApproveForm({ onDone }: { onDone: () => void }) {
  const [serial, setSerial] = useState('')
  const [label, setLabel] = useState('')
  const approve = useMutation({
    mutationFn: () => approveDevice({ serial_number: serial.trim(), label: label.trim() || undefined }),
    onSuccess: () => { setSerial(''); setLabel(''); onDone(); toast.success('Device approved') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Approve failed')),
  })
  return (
    <div className="card">
      <div className="flex items-center gap-2 text-sm font-semibold text-cs-ink mb-3">
        <Plus className="h-4 w-4 text-cs-indigo" /> Approve a device by serial
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex-1 min-w-[220px]">
          <label className="text-xs text-cs-ink-2 mb-1 block">Serial number</label>
          <input className="input text-sm num" value={serial} onChange={(e) => setSerial(e.target.value)}
            placeholder="e.g. 0123456789ABCDEF" />
        </div>
        <div className="flex-1 min-w-[180px]">
          <label className="text-xs text-cs-ink-2 mb-1 block">Label (optional)</label>
          <input className="input text-sm" value={label} onChange={(e) => setLabel(e.target.value)}
            placeholder="e.g. Finance dept #3" />
        </div>
        <button className="btn btn-primary" disabled={approve.isPending || !serial.trim()}
          onClick={() => approve.mutate()}>
          {approve.isPending ? 'Approving…' : 'Approve'}
        </button>
      </div>
    </div>
  )
}
