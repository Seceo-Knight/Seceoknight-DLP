import axios from 'axios'
import { useAuthStore } from './store/auth'
import { API_URL } from './config'

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 second timeout
  maxRedirects: 5, // Follow redirects (default is 5, but explicit is better)
})

// Add auth token to requests
apiClient.interceptors.request.use((config) => {
  // Get token from store (will be hydrated from localStorage by Zustand persist)
  const token = useAuthStore.getState().accessToken
  // Fallback: try to get token directly from localStorage if store hasn't hydrated yet
  let authToken = token
  if (!authToken) {
    try {
      const authData = localStorage.getItem('dlp-auth-v3')
      if (authData) {
        const parsed = JSON.parse(authData)
        authToken = parsed?.state?.accessToken
      }
    } catch (e) {
      // Ignore errors
    }
  }
  if (authToken && config.headers) {
    config.headers['Authorization'] = `Bearer ${authToken}`
  }
  return config
})

// Handle token refresh on 401
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        const refreshToken = useAuthStore.getState().refreshToken
        const response = await axios.post(
          `${API_URL}/auth/refresh`,
          { refresh_token: refreshToken }
        )

        const { access_token, refresh_token } = response.data
        useAuthStore.getState().setTokens(access_token, refresh_token)

        if (originalRequest.headers) {
          originalRequest.headers['Authorization'] = `Bearer ${access_token}`
        }
        return apiClient(originalRequest)
      } catch (refreshError) {
        useAuthStore.getState().logout()
        window.location.href = '/login'
        return Promise.reject(refreshError)
      }
    }

    return Promise.reject(error)
  }
)

// Helper functions for Dashboard
export const getStats = async () => {
  const { data } = await apiClient.get('/dashboard/overview')
  return data
}

export const getEventTimeSeries = async (params?: { interval?: string; hours?: number }) => {
  const { data } = await apiClient.get('/dashboard/timeline', {
    params: params || { hours: 24 },
  })
  return data
}

export const getEventsByType = async () => {
  const { data } = await apiClient.get('/events/stats/by-type')
  return data
}

export const getEventsBySeverity = async () => {
  const { data } = await apiClient.get('/events/stats/by-severity')
  return data
}

// Export individual functions for direct imports
export const getAgents = async (params?: any) => {
  const { data } = await apiClient.get('/agents/', { params })
  return data
}

export const getAllAgents = async () => {
  const { data } = await apiClient.get('/agents/all')
  return data
}

export const deleteAgent = async (agentId: string) => {
  const { data } = await apiClient.delete(`/agents/${agentId}`)
  return data
}

export const decommissionAgent = async (agentId: string) => {
  const { data } = await apiClient.post(`/agents/${agentId}/decommission`)
  return data
}

export const cleanupStaleAgents = async (
  olderThanDays: number,
  dryRun: boolean = true,
) => {
  const { data } = await apiClient.post(
    `/agents/cleanup-stale`,
    null,
    { params: { older_than_days: olderThanDays, dry_run: dryRun } },
  )
  return data
}

// Additional exports for direct imports
export const getAlerts = async () => {
  const { data } = await apiClient.get('/alerts/')
  return data
}

export const searchEvents = async (params?: any) => {
  const { data } = await apiClient.get('/events/', { params })
  return data
}

export const clearAllEvents = async () => {
  const { data } = await apiClient.delete('/events/clear')
  return data
}

export const initiateGoogleDriveConnection = async () => {
  const { data } = await apiClient.post('/google-drive/connect')
  return data as { auth_url: string; state: string }
}

export const getGoogleDriveConnections = async () => {
  const { data } = await apiClient.get('/google-drive/connections')
  return data
}

export const listGoogleDriveFolders = async (
  connectionId: string,
  parentId: string = 'root',
  pageToken?: string
) => {
  const { data } = await apiClient.get(`/google-drive/connections/${connectionId}/folders`, {
    params: {
      parent_id: parentId,
      page_token: pageToken,
    },
  })
  return data
}

export const getGoogleDriveProtectedFolders = async (connectionId: string) => {
  const { data } = await apiClient.get(`/google-drive/connections/${connectionId}/protected-folders`)
  return data
}

export const updateGoogleDriveBaseline = async (
  connectionId: string,
  payload?: { folderIds?: string[]; startTime?: string }
) => {
  const body: Record<string, any> = {}
  if (payload?.folderIds && payload.folderIds.length > 0) {
    body.folder_ids = payload.folderIds
  }
  if (payload?.startTime) {
    body.start_time = payload.startTime
  }
  const { data } = await apiClient.post(`/google-drive/connections/${connectionId}/baseline`, body)
  return data
}

export const triggerGoogleDrivePoll = async () => {
  const { data } = await apiClient.post('/google-drive/poll')
  return data as {
    status: string
    task_id?: string | null
    message?: string
  }
}

// Type exports
export type Agent = {
  id?: string
  agent_id: string
  /** Short numeric ID assigned by the Postgres sequence
   *  ``agent_code_seq``. The UI zero-pads it for display ("001"); the
   *  raw ``agent_id``/UUID stays the source of truth for API calls. */
  agent_code?: number
  name: string
  os: string
  ip_address: string
  last_seen: string
  created_at: string
  version?: string
  hostname?: string
  os_version?: string
  capabilities?: Record<string, boolean>
  /** Legacy boolean — true if heartbeat within ``AGENT_TIMEOUT_SECONDS`` (5s).
   *  Prefer ``lifecycle_status`` for new UI code. */
  is_active?: boolean
  /** Legacy two-state label kept for back-compat with older dashboard
   *  components. ``lifecycle_status`` is the four-tier replacement. */
  status_label?: 'active' | 'disconnected'
  /** Four-tier freshness ladder computed by the backend.
   *  active < 5s, disconnected < 1h, inactive < 7d, stale ≥ 7d. */
  lifecycle_status?: 'active' | 'disconnected' | 'inactive' | 'stale'
  /** Heartbeat age in seconds — handy for "Last seen X ago" without
   *  client-side timezone math. */
  last_seen_seconds_ago?: number | null
  /** Soft-delete flag. Hidden from the default listing; surface with
   *  ``GET /agents/all?include_deleted=true`` when auditing. */
  is_deleted?: boolean
  deleted_at?: string
  deleted_by?: string
  /** "Mark as Decommissioned" — agent stays visible but with a retired
   *  badge. Distinct from is_deleted (which hides it). */
  decommissioned?: boolean
  decommissioned_at?: string
  decommissioned_by?: string
  decommissioned_reason?: string
}

export type Event = {
  id: string
  title?: string
  agent_id: string
  /** Server-enriched from the agents table at read time; absent only when
   *  the agent has been deleted. Pair with ``agent_code`` for display. */
  agent_name?: string
  agent_code?: number
  event_type: string
  event_subtype?: string
  severity: string
  description?: string
  classification_level?: string
  classification_score?: number
  classification_labels?: string[]
  classification_type?: string
  classification?: Array<{ label: string; confidence: number; [key: string]: any }>
  classification_metadata?: Record<string, any>
  classification_category?: string
  classification_rules_matched?: string[]
  detected_content?: string
  file_path?: string
  file_name?: string
  file_id?: string
  mime_type?: string
  folder_id?: string
  folder_name?: string
  folder_path?: string
  timestamp: string | Date
  content?: string
  clipboard_content?: string
  blocked?: boolean
  policy_id?: string | null
  action_taken?: string
  destination?: string | null
  source?: string
  user_email?: string
  matched_policies?: any[]
  metadata?: Record<string, any>
  details?: Record<string, any>
}

export type GoogleDriveProtectedFolderStatus = {
  folder_id: string
  folder_name?: string
  folder_path?: string
  last_seen_timestamp?: string
}

export type GoogleDrivePollResponse = {
  status: string
  task_id?: string | null
  message?: string
}

// OneDrive API functions
export const initiateOneDriveConnection = async () => {
  const { data } = await apiClient.post('/onedrive/connect')
  return data
}

export const getOneDriveConnections = async () => {
  const { data } = await apiClient.get('/onedrive/connections')
  return data
}

export const listOneDriveFolders = async (
  connectionId: string,
  parentId: string = 'root',
  pageToken?: string
) => {
  const { data } = await apiClient.get(`/onedrive/connections/${connectionId}/folders`, {
    params: { parent_id: parentId, page_token: pageToken },
  })
  return data
}

export const getOneDriveProtectedFolders = async (connectionId: string) => {
  const { data } = await apiClient.get(`/onedrive/connections/${connectionId}/protected-folders`)
  return data
}

export const updateOneDriveBaseline = async (
  connectionId: string,
  payload?: { folderIds?: string[]; startTime?: string }
) => {
  const body = payload || {}
  const { data } = await apiClient.post(`/onedrive/connections/${connectionId}/baseline`, body)
  return data
}

export const triggerOneDrivePoll = async () => {
  const { data } = await apiClient.post('/onedrive/poll')
  return data
}

export type OneDriveProtectedFolderStatus = {
  folder_id: string
  folder_name?: string
  folder_path?: string
  last_seen_timestamp?: string
}

export type OneDrivePollResponse = {
  status: string
  task_id?: string | null
  message?: string
}

export const api = {
  // Dashboard
  getDashboardOverview: async () => {
    const { data } = await apiClient.get('/dashboard/overview')
    return data
    },
}

export const getEventTimeline = async (hours: number = 24) => {
  const { data } = await apiClient.get('/dashboard/timeline', {
    params: { hours },
  })
  return data
}

export const getAgentsStats = async () => {
  const { data } = await apiClient.get('/dashboard/stats/agents')
  return data
}

export const getClassificationStats = async () => {
  const { data } = await apiClient.get('/dashboard/stats/classification')
  return data
}

// Stats functions (aliases for backwards compatibility) - removed duplicates, using exports from above

export const getEvent = async (eventId: string) => {
  const { data } = await apiClient.get(`/events/${eventId}`)
  return data
}

export const getEventStats = async () => {
  const { data } = await apiClient.get('/events/stats/summary')
  return data
}

// Classification functions
export const getClassifiedFiles = async (params?: any) => {
  const { data } = await apiClient.get('/classification/files', { params })
  return data
}

export const getClassifiedFile = async (fileId: string) => {
  const { data } = await apiClient.get(`/classification/files/${fileId}`)
  return data
}

export const getClassificationSummary = async () => {
  const { data } = await apiClient.get('/classification/stats/summary')
  return data
}

export const getClassificationByType = async () => {
  const { data } = await apiClient.get('/classification/stats/by-type')
  return data
}

export const getDetectionPatterns = async () => {
  const { data } = await apiClient.get('/classification/patterns')
  return data
}

// Policies functions
export const getPolicies = async (params?: any) => {
  // Use trailing slash to avoid redirect
  const { data } = await apiClient.get('/policies/', { params })
  return data
}

export const getPolicy = async (policyId: string) => {
  const { data } = await apiClient.get(`/policies/${policyId}`)
  return data
}

export const createPolicy = async (policy: any) => {
  const { data } = await apiClient.post('/policies/', policy)
  return data
}

export const updatePolicy = async (policyId: string, policy: any) => {
  const { data } = await apiClient.put(`/policies/${policyId}`, policy)
  return data
}

export const deletePolicy = async (policyId: string) => {
  const { data } = await apiClient.delete(`/policies/${policyId}`)
  return data
}

export const getPolicyStats = async () => {
  const { data } = await apiClient.get('/policies/stats/summary')
  return data
}

export const enablePolicy = async (policyId: string) => {
  const { data } = await apiClient.post(`/policies/${policyId}/enable`)
  return data
}

export const disablePolicy = async (policyId: string) => {
  const { data } = await apiClient.post(`/policies/${policyId}/disable`)
  return data
}

export const refreshPolicyBundles = async () => {
  const { data } = await apiClient.post('/policies/cache/refresh')
  return data
}

// Events helper used by dashboard pages
export const getEvents = async (params?: any) => {
  const { data } = await apiClient.get('/events/', { params })
  // The backend returns a paginated envelope; the dashboard expects a flat list.
  return data.events || []
}

// Users functions
export const getCurrentUser = async () => {
  const { data } = await apiClient.get('/users/me')
  return data
}

export const getUsers = async (params?: any) => {
  const { data } = await apiClient.get('/users/', { params })
  return data
}

export const getUser = async (userId: string) => {
  const { data } = await apiClient.get(`/users/${userId}`)
  return data
}

export const getUserStats = async () => {
  const { data } = await apiClient.get('/users/stats/summary')
  return data
}

// ── Admin User Management ──
// These target the Phase-1 RBAC-enforced admin endpoints on /users.
// Distinct from the legacy `getUsers` / `getUser` helpers above which are
// used by the DLP user-activity monitoring page.

export type AdminUser = {
  id: string
  username: string | null
  email: string
  full_name: string
  role: string
  organization: string
  department: string | null
  clearance_level: number
  is_active: boolean
  created_at: string | null
  /** Effective permission set (role defaults ∪ direct grants), sorted. */
  permissions: string[]
  /** Direct grants only — subset of `permissions`. */
  direct_permissions: string[]
}

export type AdminUserCreateInput = {
  email: string
  password: string
  full_name: string
  role: string
  organization?: string
  username?: string
  department?: string
  clearance_level?: number
  /** Optional direct-grant permissions, unioned with the role defaults. */
  permissions?: string[]
}

export type AdminUserUpdateInput = {
  full_name?: string
  role?: string
  department?: string
  clearance_level?: number
  is_active?: boolean
  /** When present (even []), replaces the user's direct permission grants. */
  permissions?: string[]
}

export type PermissionDef = {
  id: string
  name: string
  description: string
}

export const listAllPermissions = async (): Promise<PermissionDef[]> => {
  const { data } = await apiClient.get('/permissions/')
  return data
}

export const adminListUsers = async (params?: {
  skip?: number
  limit?: number
  role?: string
  is_active?: boolean
}): Promise<AdminUser[]> => {
  const { data } = await apiClient.get('/users/', { params })
  return data
}

export const adminCreateUser = async (
  input: AdminUserCreateInput
): Promise<AdminUser> => {
  const { data } = await apiClient.post('/users/', input)
  return data
}

export const adminUpdateUser = async (
  userId: string,
  input: AdminUserUpdateInput
): Promise<AdminUser> => {
  const { data } = await apiClient.put(`/users/${userId}`, input)
  return data
}

export const adminDeactivateUser = async (userId: string) => {
  const { data } = await apiClient.delete(`/users/${userId}`)
  return data
}

/** Permanently delete a user row. Use with caution — referential cleanup
 *  is CASCADE/SET NULL; historical audit entries remain but lose the
 *  actor linkage. */
export const adminHardDeleteUser = async (userId: string) => {
  const { data } = await apiClient.delete(`/users/${userId}`, {
    params: { hard: true },
  })
  return data
}

// Alerts functions
export const acknowledgeAlert = async (alertId: string) => {
  const { data } = await apiClient.post(`/alerts/${alertId}/acknowledge`)
  return data
}

export const resolveAlert = async (alertId: string) => {
  const { data } = await apiClient.post(`/alerts/${alertId}/resolve`)
  return data
}

export const getAlert = async (alertId: string) => {
  const { data } = await apiClient.get(`/alerts/${alertId}`)
  return data
}

export const changePassword = async (
  username: string,
  currentPassword: string,
  newPassword: string,
  newPasswordConfirm: string
) => {
  const { data } = await apiClient.post('/auth/change-password', {
    username,
    current_password: currentPassword,
    new_password: newPassword,
    new_password_confirm: newPasswordConfirm,
  })
  return data
}

// ── Incident Management ──
export async function getIncidents(params?: { skip?: number; limit?: number; severity?: number; status?: string; assigned_to?: string }) {
  const { data } = await apiClient.get('/incidents/', { params })
  return data
}

export async function getIncident(id: string) {
  const { data } = await apiClient.get(`/incidents/${id}`)
  return data
}

export async function createIncident(payload: { event_id?: string; severity: number; title: string; description?: string }) {
  const { data } = await apiClient.post('/incidents/', payload)
  return data
}

export async function updateIncident(id: string, payload: { status?: string; assigned_to?: string }) {
  const { data } = await apiClient.patch(`/incidents/${id}`, payload)
  return data
}

export async function getIncidentComments(id: string) {
  const { data } = await apiClient.get(`/incidents/${id}/comments`)
  return data
}

export async function addIncidentComment(id: string, comment: string) {
  const { data } = await apiClient.post(`/incidents/${id}/comments`, { comment })
  return data
}

export async function getIncidentStats() {
  const { data } = await apiClient.get('/incidents/statistics')
  return data
}

// ── Auto Incidents (MongoDB-backed) ──
export async function getAutoIncidents(params?: { status?: string; severity?: number; limit?: number }) {
  const { data } = await apiClient.get('/incidents/auto/list', { params })
  return data
}

export async function getAutoIncident(id: string) {
  const { data } = await apiClient.get(`/incidents/auto/${id}`)
  return data
}

export async function updateAutoIncident(id: string, payload: { status?: string; assigned_to?: string }) {
  const { data } = await apiClient.patch(`/incidents/auto/${id}`, payload)
  return data
}

// ── Audit Logs ──
export async function getAuditLogs(params?: { skip?: number; limit?: number; user_id?: string; action?: string; start_date?: string; end_date?: string }) {
  const { data } = await apiClient.get('/audit-logs/', { params })
  return data
}

export async function getAuditActions() {
  const { data } = await apiClient.get('/audit-logs/actions')
  return data
}

// ── Fingerprints ──
export async function getFingerprints(params?: { skip?: number; limit?: number; label_id?: string }) {
  const { data } = await apiClient.get('/fingerprints/', { params })
  return data
}

export async function addFingerprint(payload: { hash: string; file_name?: string; label_id?: string }) {
  const { data } = await apiClient.post('/fingerprints/', payload)
  return data
}

export async function checkFingerprint(hash: string) {
  const { data } = await apiClient.post('/fingerprints/check', { hash })
  return data
}

export async function deleteFingerprint(id: string) {
  const { data } = await apiClient.delete(`/fingerprints/${id}`)
  return data
}

// ── Scan Jobs ──
export async function getScanJobs(params?: { skip?: number; limit?: number; status?: string }) {
  const { data } = await apiClient.get('/scans/', { params })
  return data
}

export async function createScanJob(target: string) {
  const { data } = await apiClient.post('/scans/', { target })
  return data
}

export async function getScanJob(id: string) {
  const { data } = await apiClient.get(`/scans/${id}`)
  return data
}

export async function getScanResults(jobId: string, params?: { skip?: number; limit?: number }) {
  const { data } = await apiClient.get(`/scans/${jobId}/results`, { params })
  return data
}


export default apiClient
