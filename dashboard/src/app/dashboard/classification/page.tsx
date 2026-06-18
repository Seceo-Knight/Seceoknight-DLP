'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import DashboardLayout from '@/components/layout/DashboardLayout'
import { FileText, File, Shield, AlertCircle, CheckCircle, FileSpreadsheet, FileImage, FileCode, Archive, Loader2 } from 'lucide-react'

export default function ClassificationPage() {
  const [filter, setFilter] = useState('all')
  const [selectedFile, setSelectedFile] = useState<any>(null)

  // Fetch classified files from API
  const { data: files = [], isLoading } = useQuery({
    queryKey: ['classified-files'],
    queryFn: () => api.getClassifiedFiles(),
    refetchInterval: 30000,
  })

  // Fetch classification summary stats
  const { data: summary } = useQuery({
    queryKey: ['classification-summary'],
    queryFn: () => api.getClassificationSummary(),
    refetchInterval: 30000,
  })

  const filteredFiles = filter === 'all'
    ? files
    : files.filter((f: any) => f.classification === filter)

  const stats = {
    total: summary?.total_files || 0,
    restricted: summary?.by_classification?.restricted || 0,
    confidential: summary?.by_classification?.confidential || 0,
    internal: summary?.by_classification?.internal || 0,
    public: summary?.by_classification?.public || 0,
  }

  const getClassificationColor = (classification: string) => {
    switch (classification) {
      case 'restricted': return 'text-red-400 bg-red-900/30 border-red-500/50'
      case 'confidential': return 'text-orange-400 bg-orange-900/30 border-orange-500/50'
      case 'internal': return 'text-yellow-400 bg-yellow-900/30 border-yellow-500/50'
      case 'public': return 'text-green-400 bg-green-900/30 border-green-500/50'
      default: return 'text-gray-400 bg-gray-900/30 border-gray-500/50'
    }
  }

  const getFileIcon = (type: string) => {
    const lowerType = type?.toLowerCase() || ''
    if (lowerType.includes('excel') || lowerType.includes('csv') || lowerType.includes('spreadsheet')) {
      return <FileSpreadsheet className="w-5 h-5 text-green-400" />
    } else if (lowerType.includes('word') || lowerType.includes('pdf') || lowerType.includes('document')) {
      return <FileText className="w-5 h-5 text-blue-400" />
    } else if (lowerType.includes('powerpoint') || lowerType.includes('presentation')) {
      return <FileImage className="w-5 h-5 text-orange-400" />
    } else if (lowerType.includes('zip') || lowerType.includes('archive') || lowerType.includes('tar')) {
      return <Archive className="w-5 h-5 text-purple-400" />
    } else if (lowerType.includes('text') || lowerType.includes('code')) {
      return <FileCode className="w-5 h-5 text-gray-400" />
    }
    return <File className="w-5 h-5 text-gray-400" />
  }

  const fileTypes = [
    { name: 'PDF', extension: '.pdf', icon: FileText, count: summary?.by_file_type?.pdf || 0 },
    { name: 'Excel', extension: '.xlsx, .xls', icon: FileSpreadsheet, count: summary?.by_file_type?.excel || 0 },
    { name: 'Word', extension: '.docx, .doc', icon: FileText, count: summary?.by_file_type?.word || 0 },
    { name: 'PowerPoint', extension: '.pptx, .ppt', icon: FileImage, count: summary?.by_file_type?.powerpoint || 0 },
    { name: 'CSV', extension: '.csv', icon: FileSpreadsheet, count: summary?.by_file_type?.csv || 0 },
    { name: 'Archives', extension: '.zip, .rar, .7z', icon: Archive, count: summary?.by_file_type?.archive || 0 },
  ]

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold text-white">Data Classification</h1>
          <p className="text-gray-400 mt-2">Monitor and manage classified documents across your organization</p>
        </div>

        {/* Classification Stats */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-4 border border-gray-700/50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-xs">Total Files</p>
                <p className="text-2xl font-bold text-white mt-1">{stats.total}</p>
              </div>
              <File className="w-10 h-10 text-gray-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-4 border border-red-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-red-400 text-xs">Restricted</p>
                <p className="text-2xl font-bold text-red-400 mt-1">{stats.restricted}</p>
              </div>
              <Shield className="w-10 h-10 text-red-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-4 border border-orange-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-orange-400 text-xs">Confidential</p>
                <p className="text-2xl font-bold text-orange-400 mt-1">{stats.confidential}</p>
              </div>
              <Shield className="w-10 h-10 text-orange-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-4 border border-yellow-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-yellow-400 text-xs">Internal</p>
                <p className="text-2xl font-bold text-yellow-400 mt-1">{stats.internal}</p>
              </div>
              <Shield className="w-10 h-10 text-yellow-400" />
            </div>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl p-4 border border-green-500/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-400 text-xs">Public</p>
                <p className="text-2xl font-bold text-green-400 mt-1">{stats.public}</p>
              </div>
              <CheckCircle className="w-10 h-10 text-green-400" />
            </div>
          </div>
        </div>

        {/* File Type Protection */}
        <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 p-6">
          <h2 className="text-xl font-semibold text-white mb-4">Protected File Types</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {fileTypes.map((type, index) => {
              const Icon = type.icon
              return (
                <div key={index} className="bg-gray-900/50 rounded-lg p-4 border border-gray-700/50">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-gray-800 rounded-lg">
                      <Icon className="w-6 h-6 text-indigo-400" />
                    </div>
                    <div>
                      <p className="text-white font-medium">{type.name}</p>
                      <p className="text-xs text-gray-400">{type.extension}</p>
                    </div>
                    <div className="ml-auto">
                      <span className="text-2xl font-bold text-indigo-400">{type.count}</span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Filters */}
        <div className="flex gap-3">
          <button
            onClick={() => setFilter('all')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              filter === 'all'
                ? 'bg-gradient-to-r from-indigo-600 to-purple-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            All Files
          </button>
          <button
            onClick={() => setFilter('restricted')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              filter === 'restricted'
                ? 'bg-red-900/50 text-red-400 border border-red-500/50'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            Restricted
          </button>
          <button
            onClick={() => setFilter('confidential')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              filter === 'confidential'
                ? 'bg-orange-900/50 text-orange-400 border border-orange-500/50'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            Confidential
          </button>
          <button
            onClick={() => setFilter('internal')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              filter === 'internal'
                ? 'bg-yellow-900/50 text-yellow-400 border border-yellow-500/50'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            Internal
          </button>
          <button
            onClick={() => setFilter('public')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              filter === 'public'
                ? 'bg-green-900/50 text-green-400 border border-green-500/50'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            Public
          </button>
        </div>

        {/* Files List */}
        <div className="bg-gray-800/50 backdrop-blur-xl rounded-xl border border-gray-700/50 overflow-hidden">
          <div className="p-6 border-b border-gray-700">
            <h2 className="text-xl font-semibold text-white">Classified Documents</h2>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center p-12">
              <Loader2 className="w-8 h-8 text-indigo-400 animate-spin" />
            </div>
          ) : filteredFiles.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-12">
              <File className="w-16 h-16 text-gray-600 mb-4" />
              <h3 className="text-lg font-semibold text-white mb-2">No Classified Files Found</h3>
              <p className="text-gray-400 text-center max-w-md">
                {filter === 'all'
                  ? 'No files have been scanned and classified yet. Deploy agents to start monitoring files.'
                  : `No files with "${filter}" classification found. Try selecting a different filter.`
                }
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-900/50">
                  <tr>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">File Name</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Size</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Classification</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">File Path</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Patterns</th>
                    <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Scanned At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredFiles.map((file: any) => (
                    <tr key={file.file_id} className="hover:bg-gray-700/30 transition-colors cursor-pointer" onClick={() => setSelectedFile(file)}>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-3">
                          {getFileIcon(file.file_type)}
                          <span className="text-white font-medium">{file.filename}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-300">{file.file_size || 'N/A'}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-lg border text-xs font-medium uppercase ${getClassificationColor(file.classification)}`}>
                          <Shield className="w-3 h-3" />
                          {file.classification}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-gray-300 max-w-xs truncate">{file.file_path}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {file.patterns_detected && file.patterns_detected.length > 0 ? (
                          <div className="flex gap-1">
                            {file.patterns_detected.slice(0, 2).map((pattern: string, idx: number) => (
                              <span key={idx} className="px-2 py-1 bg-purple-900/30 border border-purple-500/50 rounded text-xs text-purple-400">
                                {pattern}
                              </span>
                            ))}
                            {file.patterns_detected.length > 2 && (
                              <span className="px-2 py-1 bg-gray-700 rounded text-xs text-gray-300">
                                +{file.patterns_detected.length - 2}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-gray-500 text-xs">None</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-gray-400 text-sm">{file.scanned_at || file.created_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* File Details Modal */}
        {selectedFile && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={() => setSelectedFile(null)}>
            <div className="bg-gray-800 rounded-2xl max-w-2xl w-full border border-gray-700" onClick={(e) => e.stopPropagation()}>
              <div className="p-6 border-b border-gray-700">
                <h3 className="text-2xl font-bold text-white">File Details</h3>
              </div>
              <div className="p-6 space-y-4">
                <div>
                  <label className="text-sm text-gray-400">File Name</label>
                  <p className="text-white font-medium">{selectedFile.filename}</p>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm text-gray-400">Size</label>
                    <p className="text-white">{selectedFile.file_size || 'N/A'}</p>
                  </div>
                  <div>
                    <label className="text-sm text-gray-400">Type</label>
                    <p className="text-white capitalize">{selectedFile.file_type}</p>
                  </div>
                </div>
                <div>
                  <label className="text-sm text-gray-400">Classification Level</label>
                  <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg border mt-1 ${getClassificationColor(selectedFile.classification)}`}>
                    <Shield className="w-4 h-4" />
                    <span className="capitalize font-medium">{selectedFile.classification}</span>
                  </div>
                </div>
                <div>
                  <label className="text-sm text-gray-400">File Path</label>
                  <p className="text-white break-all font-mono text-sm">{selectedFile.file_path}</p>
                </div>
                <div>
                  <label className="text-sm text-gray-400">File Hash (SHA256)</label>
                  <p className="text-white break-all font-mono text-xs">{selectedFile.file_hash || 'N/A'}</p>
                </div>
                <div>
                  <label className="text-sm text-gray-400">Detected Sensitive Patterns</label>
                  {selectedFile.patterns_detected && selectedFile.patterns_detected.length > 0 ? (
                    <div className="flex flex-wrap gap-2 mt-2">
                      {selectedFile.patterns_detected.map((pattern: string, idx: number) => (
                        <span key={idx} className="px-3 py-1 bg-purple-900/30 border border-purple-500/50 rounded-lg text-purple-400">
                          {pattern}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-gray-500 mt-1">No sensitive patterns detected</p>
                  )}
                </div>
                <div>
                  <label className="text-sm text-gray-400">Scanned At</label>
                  <p className="text-white">{selectedFile.scanned_at || selectedFile.created_at}</p>
                </div>
                <div className="flex gap-3 pt-4">
                  <button onClick={() => setSelectedFile(null)} className="flex-1 bg-gray-700 hover:bg-gray-600 text-white py-2 rounded-lg transition-colors">
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  )
}
