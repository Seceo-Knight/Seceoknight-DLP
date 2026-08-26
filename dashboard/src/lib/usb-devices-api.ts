/**
 * USB Device Control API client
 *
 * Ported from the CyberSentinel-DLP reference project (see
 * SECEOKNIGHT_VS_CYBERSENTINEL_COMPARISON.md). Manages the sanctioned USB
 * device allowlist (strict default-deny by serial number) that the Windows
 * agent enforces locally — see GET /agents/{id}/usb-allowlist in agents.py
 * and HandleUsbDeviceArrival() in agent.cpp.
 */
import apiClient from './api'

export interface SanctionedDevice {
  id: string
  serial_number: string
  label?: string | null
  /** Inline-editable friendly name, separate from ``label``. */
  alias?: string | null
  /** 'allow' (default) or 'deny' — a sticky, audited rejection distinct
   *  from simply never approving the serial. */
  decision: 'allow' | 'deny'
  vendor_id?: string | null
  product_id?: string | null
  product_name?: string | null
  manufacturer?: string | null
  is_enabled: boolean
  notes?: string | null
  approved_at?: string | null
  /** Live status computed server-side from the most recent connect/
   *  disconnect event for this serial, cross-checked against whether the
   *  reporting agent is still online (ported from CyberSentinel-DLP commit
   *  7ae4671, August 26 2026) -- a connect with no disconnect does NOT mean
   *  a device is still plugged in if the agent that reported it has gone
   *  quiet since (shutdown/sleep/stopped agent never emits a disconnect).
   *  Prefer connection_state; `connected` is kept for old call sites and is
   *  true only when connection_state === 'connected'. */
  connected?: boolean
  connection_state?: 'connected' | 'disconnected' | 'unknown' | null
  reporting_agent_online?: boolean | null
  last_activity_at?: string | null
}

export interface SeenDevice {
  serial_number: string
  vendor_id?: string | null
  product_id?: string | null
  product_name?: string | null
  agent_id?: string | null
  // Resolved server-side (batch lookup against the agents collection,
  // same pattern as events.py's _attach_agent_info) — falls back to
  // agent_id itself only if the agent record can't be found (e.g. deleted).
  agent_name?: string | null
  agent_code?: number | null
  last_seen?: string | null
  sanctioned: boolean
  connected?: boolean
  connection_state?: 'connected' | 'disconnected' | 'unknown' | null
  reporting_agent_online?: boolean | null
  last_activity_at?: string | null
}

export interface DeviceListResponse {
  devices: SanctionedDevice[]
  count: number
  enabled_count: number
  allow_count: number
  deny_count: number
  enforced: boolean
  mode: 'enforce' | 'audit' | 'off'
}

export interface ApproveBody {
  serial_number: string
  label?: string
  alias?: string
  decision?: 'allow' | 'deny'
  vendor_id?: string
  product_id?: string
  product_name?: string
  manufacturer?: string
  notes?: string
}

export interface DeviceActivityEvent {
  timestamp: string
  event: 'connect' | 'disconnect'
  action?: string | null
  agent_id?: string | null
  agent_name?: string | null
  agent_code?: number | null
  drive_letter?: string | null
  device_name?: string | null
}

export const listDevices = async (): Promise<DeviceListResponse> => {
  const { data } = await apiClient.get('/usb-devices/')
  return data
}

export const seenDevices = async (): Promise<{ devices: SeenDevice[]; count: number }> => {
  const { data } = await apiClient.get('/usb-devices/seen')
  return data
}

export const deviceActivity = async (
  serialNumber: string,
): Promise<{ serial_number: string; events: DeviceActivityEvent[]; count: number }> => {
  const { data } = await apiClient.get('/usb-devices/activity', { params: { serial_number: serialNumber } })
  return data
}

export const approveDevice = async (body: ApproveBody): Promise<SanctionedDevice> => {
  const { data } = await apiClient.post('/usb-devices/', body)
  return data
}

export const updateDevice = async (
  id: string,
  body: { label?: string; alias?: string; decision?: 'allow' | 'deny'; notes?: string; is_enabled?: boolean },
): Promise<SanctionedDevice> => {
  const { data } = await apiClient.patch(`/usb-devices/${id}`, body)
  return data
}

export const revokeDevice = async (id: string): Promise<void> => {
  await apiClient.delete(`/usb-devices/${id}`)
}

export const setUsbEnforcement = async (
  body: { enabled: boolean; mode?: 'enforce' | 'audit' },
): Promise<{ enforced: boolean; mode: string }> => {
  const { data } = await apiClient.post('/usb-devices/enforcement', body)
  return data
}
