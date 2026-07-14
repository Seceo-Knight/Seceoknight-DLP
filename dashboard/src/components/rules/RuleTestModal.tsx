import { useState } from 'react'
import { extractErrorDetail } from '@/utils/errorUtils'
import { useMutation } from '@tanstack/react-query'
import { X, TestTube, AlertTriangle, CheckCircle } from 'lucide-react'
import { testRules, type RuleTestResponse } from '@/lib/rules-api'
import { cn } from '@/lib/utils'
import toast from 'react-hot-toast'

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

  const getClassificationColor = (classification: string) => {
    switch (classification) {
      case 'Restricted':
        return 'text-red-400 bg-red-500/15 border-red-500/40'
      case 'Confidential':
        return 'text-orange-400 bg-orange-500/15 border-orange-500/40'
      case 'Internal':
        return 'text-yellow-400 bg-yellow-500/15 border-yellow-500/40'
      case 'Public':
        return 'text-green-400 bg-green-500/15 border-green-500/40'
      default:
        return 'text-foreground/90 bg-secondary border-border'
    }
  }

  const getConfidenceColor = (score: number) => {
    if (score >= 0.8) return 'text-red-400'
    if (score >= 0.6) return 'text-orange-400'
    if (score >= 0.3) return 'text-yellow-400'
    return 'text-green-400'
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-6 z-50">
      <div className="bg-card rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/15 rounded-lg">
              <TestTube className="h-6 w-6 text-blue-400" />
            </div>
            <div>
              <h3 className="text-2xl font-bold text-foreground">Rule Testing Tool</h3>
              <p className="text-sm text-muted-foreground mt-1">
                Test content against your classification rules
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-muted-foreground/70 hover:text-foreground transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
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
                        getConfidenceColor(result.confidence_score)
                      )}
                    >
                      {(result.confidence_score * 100).toFixed(1)}%
                    </div>
                  </div>

                  <div className="card">
                    <div className="text-sm text-muted-foreground mb-1">Matched Rules</div>
                    <div className="text-3xl font-bold text-blue-400">
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
                          className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4"
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <CheckCircle className="h-4 w-4 text-blue-400" />
                                <span className="font-semibold text-foreground">
                                  {match.rule_name}
                                </span>
                                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-300">
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
                                <div
                                  className={cn(
                                    'inline-flex items-center px-2 py-1 rounded-full text-xs font-medium mb-1',
                                    match.severity === 'critical'
                                      ? 'bg-red-500/15 text-red-300'
                                      : match.severity === 'high'
                                      ? 'bg-orange-500/15 text-orange-300'
                                      : match.severity === 'medium'
                                      ? 'bg-yellow-500/15 text-yellow-300'
                                      : 'bg-green-500/15 text-green-300'
                                  )}
                                >
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
                                      className="px-2 py-0.5 bg-purple-500/15 text-purple-300 rounded text-xs"
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

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-6 border-t border-border bg-muted/30">
          <button onClick={onClose} className="btn-secondary">
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
