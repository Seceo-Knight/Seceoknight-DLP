/**
 * Data Matching (Exact Data Matching + document fingerprinting) API client.
 *
 * Ported from the CyberSentinel-DLP reference project. The server
 * (server/app/api/v1/data_matching.py) was already ported earlier (task
 * #109) and mounted at /data-matching -- this client just talks to it.
 * Reuses the shared apiClient so auth (token from the Zustand auth store)
 * and the 401-refresh interceptor apply, same as every other *-api.ts file.
 */
import apiClient from './api'

export type SourceType = 'edm' | 'fingerprint'

export interface DataMatchSource {
  id: string
  source_type: SourceType
  name: string
  description?: string | null
  row_count?: number | null
  shingle_count?: number | null
  columns?: string[] | null
  min_fields: number
  min_shingles: number
  min_containment: number
  classification: string
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export interface MatchResult {
  matched: boolean
  match_count: number
  matches: Array<{
    source_id: string
    name: string
    type: SourceType
    classification: string
    matched_rows?: number
    overlap?: number
    containment?: number
  }>
}

export const listSources = async (params?: {
  source_type?: SourceType
  enabled?: boolean
}): Promise<DataMatchSource[]> => {
  const { data } = await apiClient.get('/data-matching/', { params })
  return data
}

export const createEdm = async (body: {
  name: string
  description?: string
  columns?: string[]
  rows?: Record<string, any>[]
  csv_b64?: string
  min_fields: number
  classification: string
}): Promise<DataMatchSource> => {
  const { data } = await apiClient.post('/data-matching/edm', body)
  return data
}

export const createFingerprint = async (body: {
  name: string
  description?: string
  content?: string
  file_b64?: string
  filename?: string
  min_shingles: number
  min_containment: number
  classification: string
}): Promise<DataMatchSource> => {
  const { data } = await apiClient.post('/data-matching/fingerprint', body)
  return data
}

export const updateSource = async (
  id: string,
  body: Partial<Pick<DataMatchSource,
    'name' | 'description' | 'enabled' | 'min_fields' | 'min_shingles' | 'min_containment' | 'classification'>>,
): Promise<DataMatchSource> => {
  const { data } = await apiClient.patch(`/data-matching/${id}`, body)
  return data
}

export const deleteSource = async (id: string): Promise<void> => {
  await apiClient.delete(`/data-matching/${id}`)
}

export const testContent = async (content: string): Promise<MatchResult> => {
  const { data } = await apiClient.post('/data-matching/test', { content })
  return data
}

// Read a File into base64 (no data: prefix), for CSV/document uploads.
export const fileToBase64 = (file: File): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const res = String(reader.result || '')
      resolve(res.includes(',') ? res.split(',')[1] : res)
    }
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
