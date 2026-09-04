/**
 * Printer Control API client
 *
 * Ported from the CyberSentinel-DLP reference project. Manages the
 * sanctioned printer allow/deny registry. "enforced" reflects the
 * printer_control policy's active state and IS acted on by the agent (see
 * the printers.py module docstring — this used to say otherwise, which was
 * stale even before the deny feature landed).
 */
import apiClient from './api'

export interface SanctionedPrinter {
  id: string
  printer_name: string
  label?: string | null
  printer_type?: string | null
  decision: 'allow' | 'deny'
  is_enabled: boolean
  notes?: string | null
  approved_at?: string | null
}

/** Same values as the printer_control policy type in the general Policy
 *  Creator (PrinterControlPolicyForm.tsx) -- this page's quick toggle and
 *  that full form edit the same underlying policy row. */
export type PrinterControlScope = 'block_all' | 'block_network' | 'block_local' | 'allowlist' | 'none'
export type PrinterControlMode = 'enforce' | 'audit' | 'off'

export interface PrinterListResponse {
  printers: SanctionedPrinter[]
  count: number
  enabled_count: number
  allow_count: number
  deny_count: number
  enforced: boolean
  scope: PrinterControlScope
  mode: PrinterControlMode
}

export interface ApprovePrinterBody {
  printer_name: string
  label?: string
  printer_type?: string
  decision?: 'allow' | 'deny'
  notes?: string
}

export const listPrinters = async (): Promise<PrinterListResponse> => {
  const { data } = await apiClient.get('/printers/')
  return data
}

export const approvePrinter = async (body: ApprovePrinterBody): Promise<SanctionedPrinter> => {
  const { data } = await apiClient.post('/printers/', body)
  return data
}

export const updatePrinter = async (
  id: string,
  body: { label?: string; decision?: 'allow' | 'deny'; notes?: string; is_enabled?: boolean },
): Promise<SanctionedPrinter> => {
  const { data } = await apiClient.patch(`/printers/${id}`, body)
  return data
}

export const revokePrinter = async (id: string): Promise<void> => {
  await apiClient.delete(`/printers/${id}`)
}

export const setPrinterEnforcement = async (
  body: { enabled: boolean; scope?: Exclude<PrinterControlScope, 'none'>; mode?: Exclude<PrinterControlMode, 'off'> },
): Promise<{ enforced: boolean; scope: PrinterControlScope; mode: PrinterControlMode }> => {
  const { data } = await apiClient.post('/printers/enforcement', body)
  return data
}
