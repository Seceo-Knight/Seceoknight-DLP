/**
 * Printer Control API client
 *
 * Ported from the CyberSentinel-DLP reference project. Manages the
 * sanctioned printer allowlist. NOTE: SeceoKnight's Windows agent doesn't
 * monitor print jobs yet, so "enforced" here reflects an admin's intent,
 * not an active block — see the printers.py module docstring.
 */
import apiClient from './api'

export interface SanctionedPrinter {
  id: string
  printer_name: string
  label?: string | null
  printer_type?: string | null
  is_enabled: boolean
  notes?: string | null
  approved_at?: string | null
}

export interface PrinterListResponse {
  printers: SanctionedPrinter[]
  count: number
  enabled_count: number
  enforced: boolean
}

export interface ApprovePrinterBody {
  printer_name: string
  label?: string
  printer_type?: string
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
  body: { label?: string; notes?: string; is_enabled?: boolean },
): Promise<SanctionedPrinter> => {
  const { data } = await apiClient.patch(`/printers/${id}`, body)
  return data
}

export const revokePrinter = async (id: string): Promise<void> => {
  await apiClient.delete(`/printers/${id}`)
}

export const setPrinterEnforcement = async (
  body: { enabled: boolean },
): Promise<{ enforced: boolean }> => {
  const { data } = await apiClient.post('/printers/enforcement', body)
  return data
}
