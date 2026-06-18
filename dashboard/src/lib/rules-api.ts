/**
 * Rules API Client
 * API functions for rule management
 */

import apiClient from './api'

export interface Rule {
  id: string
  name: string
  description?: string
  enabled: boolean
  type: 'regex' | 'keyword' | 'dictionary'
  pattern?: string
  regex_flags?: string[]
  keywords?: string[]
  case_sensitive?: boolean
  dictionary_path?: string
  dictionary_hash?: string
  threshold: number
  weight: number
  classification_labels?: string[]
  severity?: 'low' | 'medium' | 'high' | 'critical'
  category?: string
  tags?: string[]
  created_by: string
  created_at: string
  updated_at: string
  match_count: number
  last_matched_at?: string
}

export interface RuleCreate {
  name: string
  description?: string
  type: 'regex' | 'keyword' | 'dictionary'
  pattern?: string
  regex_flags?: string[]
  keywords?: string[]
  case_sensitive?: boolean
  dictionary_path?: string
  threshold: number
  weight: number
  classification_labels?: string[]
  severity?: 'low' | 'medium' | 'high' | 'critical'
  category?: string
  tags?: string[]
  enabled: boolean
}

export interface RuleTestRequest {
  content: string
  rule_ids?: string[]
}

export interface RuleTestResponse {
  classification: string
  confidence_score: number
  matched_rules: {
    rule_id: string
    rule_name: string
    rule_type: string
    match_count: number
    weight: number
    classification_labels: string[]
    severity: string
    category: string
  }[]
  total_matches: number
  details: {
    content_length: number
    rules_evaluated: number
    context?: Record<string, any>
  }
}

export interface RuleStatistics {
  total_rules: number
  enabled_rules: number
  disabled_rules: number
  by_type: {
    regex: number
    keyword: number
    dictionary: number
  }
}

// Get all rules
export async function getRules(params?: {
  enabled_only?: boolean
  type?: string
  category?: string
  severity?: string
  skip?: number
  limit?: number
}): Promise<Rule[]> {
  const response = await apiClient.get('/rules/', { params })
  return response.data
}

// Get rule by ID
export async function getRule(id: string): Promise<Rule> {
  const response = await apiClient.get(`/rules/${id}`)
  return response.data
}

// Create new rule
export async function createRule(rule: RuleCreate): Promise<Rule> {
  const response = await apiClient.post('/rules/', rule)
  return response.data
}

// Update rule
export async function updateRule(id: string, updates: Partial<RuleCreate>): Promise<Rule> {
  const response = await apiClient.put(`/rules/${id}`, updates)
  return response.data
}

// Delete rule
export async function deleteRule(id: string): Promise<void> {
  await apiClient.delete(`/rules/${id}`)
}

// Toggle rule enabled state
export async function toggleRule(id: string, enabled: boolean): Promise<Rule> {
  const response = await apiClient.post(`/rules/${id}/toggle`, { enabled })
  return response.data
}

// Get rule statistics
export async function getRuleStatistics(): Promise<RuleStatistics> {
  const response = await apiClient.get('/rules/statistics')
  return response.data
}

// Test rules against content
export async function testRules(request: RuleTestRequest): Promise<RuleTestResponse> {
  const response = await apiClient.post('/rules/test', request)
  return response.data
}

// Bulk import rules
export async function bulkImportRules(rules: RuleCreate[]): Promise<{
  success_count: number
  error_count: number
  created_rules: Rule[]
  errors: { index: number; name: string; error: string }[]
}> {
  const response = await apiClient.post('/rules/bulk-import', rules)
  return response.data
}
