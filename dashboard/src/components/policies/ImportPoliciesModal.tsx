'use client'

import { useState, useRef } from 'react'
import { Upload, FileJson, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import { importPolicies } from '@/lib/api'
import toast from 'react-hot-toast'
import Modal, { ModalHeader, ModalFooter } from '@/components/ui/Modal'

interface ImportPoliciesModalProps {
  isOpen: boolean
  onClose: () => void
  onImported: () => void
}

type ParsedBundle = { version?: number; policies: any[] } | null

type ImportResult = {
  created: { name: string; id: string }[]
  skipped: { name: string; reason: string }[]
  errors: { name: string; reason: string }[]
  summary: string
}

export default function ImportPoliciesModal({ isOpen, onClose, onImported }: ImportPoliciesModalProps) {
  const [bundle, setBundle] = useState<ParsedBundle>(null)
  const [fileName, setFileName] = useState('')
  const [parseError, setParseError] = useState<string | null>(null)
  const [onConflict, setOnConflict] = useState<'skip' | 'rename'>('skip')
  const [importing, setImporting] = useState(false)
  const [result, setResult] = useState<ImportResult | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleClose = () => {
    setBundle(null)
    setFileName('')
    setParseError(null)
    setResult(null)
    onClose()
  }

  const parseAndSet = (text: string, name: string) => {
    try {
      const parsed = JSON.parse(text)
      if (!parsed || !Array.isArray(parsed.policies)) {
        setParseError('File does not look like a SeceoKnight policy export -- expected a "policies" array')
        setBundle(null)
        return
      }
      setBundle(parsed)
      setFileName(name)
      setParseError(null)
    } catch {
      setParseError('Could not parse this file as JSON')
      setBundle(null)
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => parseAndSet(String(reader.result || ''), file.name)
    reader.readAsText(file)
  }

  const handleImport = async () => {
    if (!bundle) return
    setImporting(true)
    try {
      const res = await importPolicies({ version: bundle.version, policies: bundle.policies }, onConflict)
      setResult(res)
      if (res.created.length > 0) {
        toast.success(res.summary)
        onImported()
      } else {
        toast(res.summary, { icon: '⚠️' })
      }
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Failed to import policies')
    } finally {
      setImporting(false)
    }
  }

  return (
    <Modal
      open={isOpen}
      onClose={handleClose}
      size="md"
      className="!bg-gray-800 !border-gray-700"
      label="Import Policies"
      header={<ModalHeader title="Import Policies" onClose={handleClose} />}
      footer={
        <ModalFooter>
          <button
            onClick={handleClose}
            className="px-4 py-2 text-muted-foreground/70 hover:text-white transition-colors"
          >
            {result ? 'Close' : 'Cancel'}
          </button>
          {!result && (
            <button
              onClick={handleImport}
              disabled={!bundle || importing}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-700 disabled:text-muted-foreground text-white rounded-lg transition-colors text-sm font-medium"
            >
              <Upload className="w-4 h-4" />
              {importing ? 'Importing...' : 'Import'}
            </button>
          )}
        </ModalFooter>
      }
    >
        <div className="space-y-4">
          {!result && (
            <>
              <p className="text-sm text-muted-foreground/70">
                Select a JSON file exported from any SeceoKnight deployment&apos;s Export Policies action.
              </p>

              <input
                ref={fileInputRef}
                type="file"
                accept="application/json,.json"
                onChange={handleFileChange}
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="w-full flex flex-col items-center justify-center gap-2 p-8 border-2 border-dashed border-gray-600 rounded-xl hover:border-indigo-500 transition-colors text-muted-foreground/70 hover:text-white"
              >
                <Upload className="w-8 h-8" />
                <span className="text-sm">{fileName || 'Click to choose a .json file'}</span>
              </button>

              {parseError && (
                <div className="flex items-start gap-2 p-3 bg-red-900/20 border border-red-500/30 rounded-lg text-sm text-red-300">
                  <XCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  {parseError}
                </div>
              )}

              {bundle && (
                <div className="p-4 bg-gray-900/50 rounded-lg border border-gray-700 space-y-3">
                  <div className="flex items-center gap-2 text-sm text-white">
                    <FileJson className="w-4 h-4 text-indigo-400" />
                    {bundle.policies.length} polic{bundle.policies.length === 1 ? 'y' : 'ies'} found
                  </div>
                  <div className="max-h-32 overflow-y-auto space-y-1">
                    {bundle.policies.map((p, i) => (
                      <div key={i} className="text-xs text-muted-foreground/70 truncate">
                        • {p.name || '(unnamed)'}
                      </div>
                    ))}
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-gray-200 mb-2">
                      If a policy name already exists:
                    </label>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setOnConflict('skip')}
                        className={`flex-1 px-3 py-2 rounded-lg border-2 text-xs transition-all ${
                          onConflict === 'skip'
                            ? 'border-indigo-500 bg-indigo-900/30 text-white'
                            : 'border-gray-600 bg-gray-900/30 text-muted-foreground/70'
                        }`}
                      >
                        Skip it
                      </button>
                      <button
                        onClick={() => setOnConflict('rename')}
                        className={`flex-1 px-3 py-2 rounded-lg border-2 text-xs transition-all ${
                          onConflict === 'rename'
                            ? 'border-indigo-500 bg-indigo-900/30 text-white'
                            : 'border-gray-600 bg-gray-900/30 text-muted-foreground/70'
                        }`}
                      >
                        Import as copy
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}

          {result && (
            <div className="space-y-3">
              <div className="p-4 bg-gray-900/50 rounded-lg border border-gray-700 text-sm text-white">
                {result.summary}
              </div>

              {result.created.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 text-sm text-green-400 mb-2">
                    <CheckCircle className="w-4 h-4" /> Created
                  </div>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {result.created.map((c) => (
                      <div key={c.id} className="text-xs text-muted-foreground/70">• {c.name}</div>
                    ))}
                  </div>
                </div>
              )}

              {result.skipped.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 text-sm text-amber-400 mb-2">
                    <AlertTriangle className="w-4 h-4" /> Skipped
                  </div>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {result.skipped.map((s, i) => (
                      <div key={i} className="text-xs text-muted-foreground/70">• {s.name} -- {s.reason}</div>
                    ))}
                  </div>
                </div>
              )}

              {result.errors.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 text-sm text-red-400 mb-2">
                    <XCircle className="w-4 h-4" /> Failed
                  </div>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {result.errors.map((e, i) => (
                      <div key={i} className="text-xs text-muted-foreground/70">• {e.name} -- {e.reason}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
    </Modal>
  )
}
