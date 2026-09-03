/**
 * Behavioral risk-scoring API client -- SeceoKnight-original (task #120).
 *
 * Talks to server/app/api/v1/risk_scoring.py. See that module and
 * risk_scoring_service.py for the full rationale: a per-user 0-100 score
 * built from event volume, channel diversity, off-hours activity, block
 * ratio, and severity mix over a rolling window -- something neither
 * SeceoKnight nor CyberSentinel does today (both score single events only).
 */
import apiClient from './api'

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export interface RiskComponents {
  volume: number
  channel_diversity: number
  off_hours: number
  block_ratio: number
  severity_mix: number
}

export interface UserRiskScore {
  id: string
  user_email: string
  username?: string | null
  department?: string | null
  score: number
  risk_level: RiskLevel
  components: RiskComponents | null
  event_count: number
  blocked_count: number
  critical_high_count: number
  distinct_channels: string[] | null
  off_hours_count: number
  score_previous: number | null
  trend: 'rising' | 'stable' | 'falling' | null
  window_days: number
  window_start?: string | null
  window_end?: string | null
  computed_at?: string
}

export interface RiskScoreDetail extends UserRiskScore {
  recent_events: Array<{
    id: string
    event_type: string
    event_subtype?: string | null
    severity: string
    action: string
    channel?: string | null
    file_name?: string | null
    description: string
    timestamp: string
  }>
  // True count of events matching the requested `component` filter across
  // the FULL scoring window -- may exceed recent_events.length, since the
  // backend caps how many it returns for display. Absent/unfiltered
  // requests still return this (equal to recent_events.length up to the cap).
  recent_events_total: number
}

export interface RiskScoreListResponse {
  scores: UserRiskScore[]
  counts_by_level: Record<RiskLevel, number>
}

export const listRiskScores = async (params?: {
  limit?: number
  offset?: number
  min_level?: RiskLevel
}): Promise<RiskScoreListResponse> => {
  const { data } = await apiClient.get('/risk-scoring/users', { params })
  return data
}

export const getRiskScore = async (
  userEmail: string,
  component?: string | null,
): Promise<RiskScoreDetail> => {
  const { data } = await apiClient.get(`/risk-scoring/users/${encodeURIComponent(userEmail)}`, {
    params: component ? { component } : undefined,
  })
  return data
}

export const recomputeRiskScores = async (
  windowDays: number = 14,
): Promise<{ recomputed_users: number; window_days: number; computed_at: string }> => {
  const { data } = await apiClient.post('/risk-scoring/recompute', null, {
    params: { window_days: windowDays },
  })
  return data
}
