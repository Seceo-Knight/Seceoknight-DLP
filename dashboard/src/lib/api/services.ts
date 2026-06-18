/**
 * API Services for CyberSentinel DLP
 * Service layer for all API endpoints
 */

import apiClient from './client'

// ============================================
// Types & Interfaces
// ============================================

export interface DashboardMetrics {
  events_24h: number
  events_7d: number
  blocked_24h: number
  blocked_7d: number
  critical_24h: number
  critical_7d: number
  active_policies: number
}

export interface DashboardOverview {
  metrics: DashboardMetrics
  top_users: Array<{ email: string; event_count: number }>
  top_violations: Array<{ policy: string; count: number }>
  recent_events: Array<{
    id: string
    timestamp: string
    severity: string
    description: string
    blocked: boolean
  }>
}

export interface TimelineData {
  timeline: Array<{
    timestamp: string
    total_events: number
    blocked_events: number
    critical_events: number
  }>
}

export interface Agent {
  agent_id: string
  name: string
  os: string
  ip_address: string
  version: string
  status: 'online' | 'offline' | 'warning'
  last_seen: string
  created_at: string
}

export interface AgentStats {
  total: number
  online: number
  offline: number
  warning: number
}

export interface DLPEvent {
  event_id: string
  timestamp: string
  event_type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  action: 'log' | 'alert' | 'blocked' | 'quarantine'
  description: string
  user_email: string
  agent_id: string
  policy_name: string
  file_name?: string
  file_path?: string
  destination?: string
  details?: Record<string, any>
}

export interface ClassifiedFile {
  file_id: string
  filename: string
  file_path: string
  file_type: string
  file_size: number
  classification: 'public' | 'internal' | 'confidential' | 'restricted'
  patterns_detected: string[]
  agent_id: string
  user_email: string
  scanned_at: string
  confidence_score: number
}

export interface ClassificationStats {
  total_files: number
  by_classification: {
    public: number
    internal: number
    confidential: number
    restricted: number
  }
  top_patterns: Array<{ pattern: string; count: number }>
}

export interface Policy {
  policy_id: string
  name: string
  description: string
  status: 'active' | 'inactive'
  severity: 'low' | 'medium' | 'high' | 'critical'
  action: 'log' | 'alert' | 'quarantine' | 'block'
  destinations: string[]
  fileTypes: string[]
  patterns: string[]
  violations: number
  created_at: string
  updated_at: string
}

export interface User {
  user_id: string
  email: string
  department: string
  role: string
  violations: number
  risk_score: 'low' | 'medium' | 'high'
  last_activity: string
}

// ============================================
// Dashboard Services
// ============================================

export const dashboardService = {
  /**
   * Get dashboard overview statistics
   */
  getOverview: async (): Promise<DashboardOverview> => {
    return apiClient.get<DashboardOverview>('/dashboard/overview')
  },

  /**
   * Get event timeline data
   */
  getTimeline: async (hours: number = 24): Promise<TimelineData> => {
    return apiClient.get<TimelineData>(`/dashboard/timeline?hours=${hours}`)
  },

  /**
   * Get agent statistics
   */
  getAgentsStats: async (): Promise<AgentStats> => {
    return apiClient.get<AgentStats>('/dashboard/stats/agents')
  },

  /**
   * Get classification statistics
   */
  getClassificationStats: async (): Promise<{
    total: number
    public: number
    internal: number
    confidential: number
    restricted: number
  }> => {
    return apiClient.get('/dashboard/stats/classification')
  },
}

// ============================================
// Agents Services
// ============================================

export const agentsService = {
  /**
   * List all agents
   */
  list: async (params?: { status?: string; os?: string }): Promise<Agent[]> => {
    const query = new URLSearchParams(params as any).toString()
    return apiClient.get<Agent[]>(`/agents${query ? `?${query}` : ''}`)
  },

  /**
   * Get agent by ID
   */
  get: async (agentId: string): Promise<Agent> => {
    return apiClient.get<Agent>(`/agents/${agentId}`)
  },

  /**
   * Register new agent
   */
  create: async (data: {
    name: string
    os: string
    ip_address: string
    version?: string
  }): Promise<Agent> => {
    return apiClient.post<Agent>('/agents', data)
  },

  /**
   * Delete agent
   */
  delete: async (agentId: string): Promise<void> => {
    return apiClient.delete(`/agents/${agentId}`)
  },

  /**
   * Get agent summary statistics
   */
  getStats: async (): Promise<AgentStats> => {
    return apiClient.get<AgentStats>('/agents/stats/summary')
  },
}

// ============================================
// Events Services
// ============================================

export const eventsService = {
  /**
   * List events
   */
  list: async (params?: {
    event_type?: string
    severity?: string
    limit?: number
    skip?: number
  }): Promise<DLPEvent[]> => {
    const query = new URLSearchParams(params as any).toString()
    return apiClient.get<DLPEvent[]>(`/events${query ? `?${query}` : ''}`)
  },

  /**
   * Get event by ID
   */
  get: async (eventId: string): Promise<DLPEvent> => {
    return apiClient.get<DLPEvent>(`/events/${eventId}`)
  },

  /**
   * Create event (used by agents)
   */
  create: async (data: Partial<DLPEvent>): Promise<DLPEvent> => {
    return apiClient.post<DLPEvent>('/events', data)
  },

  /**
   * Get event statistics
   */
  getStats: async (): Promise<{
    total: number
    by_severity: Record<string, number>
    by_type: Record<string, number>
  }> => {
    return apiClient.get('/events/stats/summary')
  },
}

// ============================================
// Classification Services
// ============================================

export const classificationService = {
  /**
   * List classified files
   */
  list: async (params?: {
    classification?: string
    file_type?: string
    limit?: number
    skip?: number
  }): Promise<ClassifiedFile[]> => {
    const query = new URLSearchParams(params as any).toString()
    return apiClient.get<ClassifiedFile[]>(`/classification/files${query ? `?${query}` : ''}`)
  },

  /**
   * Get classified file by ID
   */
  get: async (fileId: string): Promise<ClassifiedFile> => {
    return apiClient.get<ClassifiedFile>(`/classification/files/${fileId}`)
  },

  /**
   * Get classification statistics
   */
  getStats: async (): Promise<ClassificationStats> => {
    return apiClient.get<ClassificationStats>('/classification/stats/summary')
  },

  /**
   * Get classification by file type
   */
  getStatsByType: async (): Promise<{
    file_types: Array<{
      file_type: string
      count: number
      total_size_bytes: number
    }>
  }> => {
    return apiClient.get('/classification/stats/by-type')
  },

  /**
   * Get available detection patterns
   */
  getPatterns: async (): Promise<{
    patterns: Array<{
      id: string
      name: string
      description: string
      example: string
      enabled: boolean
    }>
  }> => {
    return apiClient.get('/classification/patterns')
  },
}

// ============================================
// Policies Services
// ============================================

export const policiesService = {
  /**
   * List all policies
   */
  list: async (params?: { status?: string }): Promise<Policy[]> => {
    const query = new URLSearchParams(params as any).toString()
    return apiClient.get<Policy[]>(`/policies${query ? `?${query}` : ''}`)
  },

  /**
   * Get policy by ID
   */
  get: async (policyId: string): Promise<Policy> => {
    return apiClient.get<Policy>(`/policies/${policyId}`)
  },

  /**
   * Create new policy
   */
  create: async (data: Partial<Policy>): Promise<Policy> => {
    return apiClient.post<Policy>('/policies', data)
  },

  /**
   * Update policy
   */
  update: async (policyId: string, data: Partial<Policy>): Promise<Policy> => {
    return apiClient.put<Policy>(`/policies/${policyId}`, data)
  },

  /**
   * Delete policy
   */
  delete: async (policyId: string): Promise<void> => {
    return apiClient.delete(`/policies/${policyId}`)
  },

  /**
   * Get policy statistics
   */
  getStats: async (): Promise<{
    total: number
    active: number
    violations: number
  }> => {
    return apiClient.get('/policies/stats/summary')
  },
}

// ============================================
// Users Services
// ============================================

export const usersService = {
  /**
   * List all users
   */
  list: async (params?: { risk_score?: string }): Promise<User[]> => {
    const query = new URLSearchParams(params as any).toString()
    return apiClient.get<User[]>(`/users${query ? `?${query}` : ''}`)
  },

  /**
   * Get user by ID
   */
  get: async (userId: string): Promise<User> => {
    return apiClient.get<User>(`/users/${userId}`)
  },

  /**
   * Get user statistics
   */
  getStats: async (): Promise<{
    total: number
    high_risk: number
    medium_risk: number
    low_risk: number
    total_violations: number
  }> => {
    return apiClient.get('/users/stats/summary')
  },
}

// Export all services
export default {
  dashboard: dashboardService,
  agents: agentsService,
  events: eventsService,
  classification: classificationService,
  policies: policiesService,
  users: usersService,
}
