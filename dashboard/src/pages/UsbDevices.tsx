import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Usb, ShieldCheck, ShieldAlert, Plus, Trash2, Check, Ban } from 'lucide-react'
import toast from 'react-hot-toast'
import LoadingSpinner from '@/components/LoadingSpinner'
import ErrorMessage from '@/components/ErrorMessage'
import { extractErrorDetail } from '@/utils/errorUtils'
import {
  listDevices, seenDevices, approveDevice, updateDevice, revokeDevice, setUsbEnforcement,
  type SanctionedDevice, type SeenDevice,
} from '@/lib/usb-devices-api'

// Ported from the CyberSentinel-DLP reference project (see
// SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md). Strict allowlist: when
// enforcement is on, the Windows agent blocks any USB storage device whose
// serial number isn't approved below. Serial numbers only surface here once
// an agent build with allowlist support has reported at least one connect
// event — see agent.cpp's ExtractUsbSerialFromDeviceId().

const fmt = (s?: string | null) => (s ? new Date(s).toLocaleString() : '—')
const vidpid = (v?: string | null, p?: string | null) => (v || p ? `${v || '????'}:${p || '????'}` : '—')

export default function UsbDevices() {
  const qc = useQueryClient()
  const devicesQ = useQuery({ queryKey: ['usb-devices'], queryFn: listDevices })
  const seenQ = useQuery({ queryKey: ['usb-devices-seen'], queryFn: seenDevices })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['usb-devices'] })
    qc.invalidateQueries({ queryKey: ['usb-devices-seen'] })
  }

  const enforcement = useMutation({
    mutationFn: (body: { enabled: boolean; mode?: 'enforce' | 'audit' }) => setUsbEnforcement(body),
    onSuccess: (r) => { invalidate(); toast.success(r.enforced ? `Enforcement on (${r.mode})` : 'Enforcement off') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Failed to update enforcement')),
  })

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
      <Section title="Sanctioned devices" count={devicesQ.data?.count || 0}>
        {(devicesQ.data?.devices.length || 0) === 0 ? (
          <Empty text="No devices approved yet. Approve one by serial above, or from the seen list below." />
        ) : (
          <Table headers={['Serial', 'Label', 'Device', 'VID:PID', 'Status', 'Approved', '']}>
            {devicesQ.data!.devices.map((d) => (
              <SanctionedRow key={d.id} d={d} onChange={invalidate} />
            ))}
          </Table>
        )}
      </Section>

      {/* Seen but unsanctioned */}
      <Section
        title="Seen on endpoints — not sanctioned"
        count={seenQ.data?.count || 0}
        subtitle="Devices observed connecting to an agent that aren't on the allowlist. Approve to permit them."
      >
        {seenQ.isLoading ? (
          <LoadingSpinner />
        ) : (seenQ.data?.devices.length || 0) === 0 ? (
          <Empty text="No unsanctioned devices have been seen." />
        ) : (
          <Table headers={['Serial', 'Device', 'VID:PID', 'Last seen', 'Agent', '']}>
            {seenQ.data!.devices.map((s) => (
              <SeenRow key={s.serial_number} s={s} onApproved={invalidate} />
            ))}
          </Table>
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
      <Usb className="h-8 w-8 mx-auto mb-2 text-cs-muted-2" />
      {text}
    </div>
  )
}

function SanctionedRow({ d, onChange }: { d: SanctionedDevice; onChange: () => void }) {
  const toggle = useMutation({
    mutationFn: () => updateDevice(d.id, { is_enabled: !d.is_enabled }),
    onSuccess: () => { onChange(); toast.success(d.is_enabled ? 'Device suspended' : 'Device re-enabled') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Update failed')),
  })
  const revoke = useMutation({
    mutationFn: () => revokeDevice(d.id),
    onSuccess: () => { onChange(); toast.success('Approval revoked') },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Revoke failed')),
  })
  return (
    <tr>
      <td className="num text-cs-ink">{d.serial_number}</td>
      <td className="text-cs-ink-2">{d.label || '—'}</td>
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

function SeenRow({ s, onApproved }: { s: SeenDevice; onApproved: () => void }) {
  const approve = useMutation({
    mutationFn: () => approveDevice({
      serial_number: s.serial_number,
      vendor_id: s.vendor_id || undefined,
      product_id: s.product_id || undefined,
      product_name: s.product_name || undefined,
    }),
    onSuccess: () => { onApproved(); toast.success(`Approved ${s.serial_number}`) },
    onError: (e: any) => toast.error(extractErrorDetail(e, 'Approve failed')),
  })
  return (
    <tr>
      <td className="num text-cs-ink">{s.serial_number}</td>
      <td className="text-cs-ink-2">{s.product_name || '—'}</td>
      <td className="num text-cs-muted">{vidpid(s.vendor_id, s.product_id)}</td>
      <td className="text-cs-muted text-xs">{fmt(s.last_seen)}</td>
      <td className="text-cs-muted text-xs num">{s.agent_id || '—'}</td>
      <td className="text-right">
        <button className="btn btn-secondary inline-flex items-center gap-1"
          disabled={approve.isPending} onClick={() => approve.mutate()}>
          <Check className="h-3.5 w-3.5" />{approve.isPending ? 'Approving…' : 'Approve'}
        </button>
      </td>
    </tr>
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
