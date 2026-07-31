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
  vendor_id?: string | null
  product_id?: string | null
  product_name?: string | null
  manufacturer?: string | null
  is_enabled: boolean
  notes?: string | null
  approved_at?: string | null
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
}

export interface DeviceListResponse {
  devices: SanctionedDevice[]
  count: number
  enabled_count: number
  enforced: boolean
  mode: 'enforce' | 'audit' | 'off'
}

export interface ApproveBody {
  serial_number: string
  label?: string
  vendor_id?: string
  product_id?: string
  product_name?: string
  manufacturer?: string
  notes?: string
}

export const listDevices = async (): Promise<DeviceListResponse> => {
  const { data } = await apiClient.get('/usb-devices/')
  return data
}

export const seenDevices = async (): Promise<{ devices: SeenDevice[]; count: number }> => {
  const { data } = await apiClient.get('/usb-devices/seen')
  return data
}

export const approveDevice = async (body: ApproveBody): Promise<SanctionedDevice> => {
  const { data } = await apiClient.post('/usb-devices/', body)
  return data
}

export const updateDevice = async (
  id: string,
  body: { label?: string; notes?: string; is_enabled?: boolean },
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
