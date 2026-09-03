import { useState } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useMutation } from '@tanstack/react-query'
import { TestTube, AlertTriangle, CheckCircle } from 'lucide-react'
import { testRules, type RuleTestResponse } from '@/lib/rules-api'
import { cn } from '@/lib/utils'
import { tone, type Tone } from '@/lib/tone'
import toast from 'react-hot-toast'
import Modal, { ModalHeader, ModalFooter } from '@/components/ui/Modal'

interface RuleTestModalProps {
  isOpen: boolean
  onClose: () => void
}

export default function RuleTestModal({ isOpen, onClose }: RuleTestModalProps) {
  const [content, setContent] = useState('')
  const [result, setResult] = useState<RuleTestResponse | null>(null)

  const testMutation = useMutation({
    mutationFn: testRules,
    onSuccess: (data) => {
      setResult(data)
    },
    onError: (error: any) => {
      toast.error(extractErrorDetail(error, 'Failed to test rules'))
    },
  })

  const handleTest = () => {
    if (!content.trim()) {
      toast.error('Please enter some content to test')
      return
    }
    testMutation.mutate({ content })
  }

  const handleReset = () => {
    setContent('')
    setResult(null)
  }

  // Same Restricted=red/Confidential=orange/Internal=yellow/Public=green
  // ladder as Events.tsx's EventDetailModal and Log Explorer, instead of
  // an independently-invented 4th scheme.
  const getClassificationColor = (classification: string) => {
    switch (classification) {
      case 'Restricted': return tone('red')
      case 'Confidential': return tone('orange')
      case 'Internal': return tone('yellow')
      case 'Public': return tone('green')
      default: return tone('gray')
    }
  }

  const getConfidenceTone = (score: number): 'red' | 'orange' | 'yellow' | 'green' => {
    if (score >= 0.8) return 'red'
    if (score >= 0.6) return 'orange'
    if (score >= 0.3) return 'yellow'
    return 'green'
  }

  // Same 4-tone severity ladder as Events/Alerts/Risk Scoring/Log
  // Explorer/Rules (critical=red, high=orange, medium=yellow, low=blue).
  const severityTone = (severity?: string | null): Tone => {
    switch ((severity || '').toLowerCase()) {
      case 'critical': return 'red'
      case 'high': return 'orange'
      case 'medium': return 'yellow'
      case 'low': return 'blue'
      default: return 'gray'
    }
  }

  return (
    <Modal
      open={isOpen}
      onClose={onClose}
      size="2xl"
      label="Rule Testing Tool"
      header={
        <ModalHeader
          title={
            <span className="flex items-center gap-3">
              <span className="p-2 bg-primary/10 rounded-lg inline-flex">
                <TestTube className="h-6 w-6 text-primary" />
              </span>
              Rule Testing Tool
            </span>
          }
          hint="Test content against your classification rules"
          onClose={onClose}
        />
      }
      footer={
        <ModalFooter>
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
        </ModalFooter>
      }
    >
        <div className="space-y-6">
          {/* Input */}
          <div>
            <label className="block text-sm font-medium text-foreground/90 mb-2">
              Test Content
            </label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              className="input w-full font-mono text-sm"
              rows={8}
              placeholder="Paste content here to test against classification rules...&#10;&#10;Example:&#10;My SSN is 123-45-6789&#10;Credit Card: 4111-1111-1111-1111&#10;Email: john@example.com"
            />
            <p className="text-xs text-muted-foreground mt-2">
              Enter any text content to see which rules it matches and how it would be classified.
            </p>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleTest}
              disabled={testMutation.isPending || !content.trim()}
              className="btn-primary flex items-center gap-2"
            >
              <TestTube className="h-4 w-4" />
              {testMutation.isPending ? 'Testing...' : 'Test Content'}
            </button>
            <button onClick={handleReset} className="btn-secondary">
              Reset
            </button>
          </div>

          {/* Results */}
          {result && (
            <div className="space-y-6 pt-6 border-t border-border">
              <div>
                <h4 className="text-lg font-semibold text-foreground mb-4">Test Results</h4>

                {/* Classification Overview */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="card">
                    <div className="text-sm text-muted-foreground mb-1">Classification</div>
                    <div
                      className={cn(
                        'inline-flex items-center px-3 py-1.5 rounded-lg border font-semibold text-base',
                        getClassificationColor(result.classification)
                      )}
                    >
                      {result.classification}
                    </div>
                  </div>

                  <div className="card">
                    <div className="text-sm text-muted-foreground mb-1">Confidence Score</div>
                    <div
                      className={cn(
                        'text-3xl font-bold',
                        {
                          red: 'text-critical',
                          orange: 'text-warning',
                          yellow: 'text-warning',
                          green: 'text-success',
                        }[getConfidenceTone(result.confidence_score)],
                      )}
                    >
                      {(result.confidence_score * 100).toFixed(1)}%
                    </div>
                  </div>

                  <div className="card">
                    <div className="text-sm text-muted-foreground mb-1">Matched Rules</div>
                    <div className="text-3xl font-bold text-primary">
                      {result.matched_rules.length}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {result.total_matches} total matches
                    </div>
                  </div>
                </div>

                {/* Matched Rules */}
                {result.matched_rules.length > 0 ? (
                  <div>
                    <h5 className="text-sm font-semibold text-foreground mb-3">
                      Matched Rules ({result.matched_rules.length})
                    </h5>
                    <div className="space-y-3">
                      {result.matched_rules.map((match, index) => (
                        <div
                          key={index}
                          className="rounded-lg border border-primary/30 bg-primary/5 p-4"
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <CheckCircle className="h-4 w-4 text-primary" />
                                <span className="font-semibold text-foreground">
                                  {match.rule_name}
                                </span>
                                <span className={cn('rounded-full border px-2 py-0.5 text-xs capitalize', tone('indigo'))}>
                                  {match.rule_type}
                                </span>
                              </div>
                              {match.category && (
                                <div className="text-sm text-muted-foreground mb-1">
                                  Category: {match.category}
                                </div>
                              )}
                            </div>
                            <div className="text-right">
                              {match.severity && (
                                <div className={cn('mb-1 inline-flex items-center rounded-full border px-2 py-1 text-xs font-medium', tone(severityTone(match.severity)))}>
                                  {match.severity}
                                </div>
                              )}
                              <div className="text-xs text-muted-foreground">
                                Weight: {match.weight.toFixed(2)}
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-4 text-sm">
                            <div className="text-muted-foreground">
                              Matches: <span className="font-medium">{match.match_count}</span>
                            </div>
                            {match.classification_labels &&
                              match.classification_labels.length > 0 && (
                                <div className="flex items-center gap-1">
                                  <span className="text-muted-foreground">Labels:</span>
                                  {match.classification_labels.map((label) => (
                                    <span
                                      key={label}
                                      className={cn('rounded px-2 py-0.5 text-xs', tone('purple'))}
                                    >
                                      {label}
                                    </span>
                                  ))}
                                </div>
                              )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="bg-muted/30 border border-border rounded-lg p-8 text-center">
                    <AlertTriangle className="h-12 w-12 text-muted-foreground/70 mx-auto mb-3" />
                    <p className="text-muted-foreground font-medium">No rules matched</p>
                    <p className="text-sm text-muted-foreground mt-1">
                      The content did not trigger any classification rules
                    </p>
                  </div>
                )}

                {/* Details */}
                <div className="mt-6 p-4 bg-muted/30 rounded-lg border border-border">
                  <h5 className="text-sm font-semibold text-foreground mb-2">Details</h5>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Content Length:</span>{' '}
                      <span className="font-medium">
                        {result.details.content_length} characters
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Rules Evaluated:</span>{' '}
                      <span className="font-medium">{result.details.rules_evaluated}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
    </Modal>
  )
}
