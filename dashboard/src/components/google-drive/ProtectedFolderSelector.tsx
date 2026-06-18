import React, { useState, useEffect } from 'react'
import { Folder, ChevronRight, Check, Loader2, AlertCircle, Plus } from 'lucide-react'
import { listGoogleDriveFolders } from '@/lib/api'
import { cn } from '@/lib/utils'

interface ProtectedFolderSelectorProps {
  connectionId: string
  selectedFolders: Array<{ id: string; name: string; path?: string }>
  onChange: (folders: Array<{ id: string; name: string; path?: string }>) => void
}

interface DriveFolder {
  id: string
  name: string
  mimeType: string
  iconLink?: string
}

export default function ProtectedFolderSelector({
  connectionId,
  selectedFolders,
  onChange,
}: ProtectedFolderSelectorProps) {
  const [currentPath, setCurrentPath] = useState<Array<{ id: string; name: string }>>([
    { id: 'root', name: 'My Drive' },
  ])
  const [folders, setFolders] = useState<DriveFolder[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const currentFolder = currentPath[currentPath.length - 1]
  const currentFolderId = currentFolder.id

  useEffect(() => {
    loadFolders(currentFolderId)
  }, [currentFolderId, connectionId])

  const loadFolders = async (parentId: string) => {
    if (!connectionId) return

    try {
      setLoading(true)
      setError(null)
      const response = await listGoogleDriveFolders(connectionId, parentId)
      setFolders(response.files || [])
    } catch (err: any) {
      setError('Failed to load folders. Please try again.')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handleNavigate = (folderId: string, folderName: string) => {
    setCurrentPath([...currentPath, { id: folderId, name: folderName }])
  }

  const handleBreadcrumbClick = (index: number) => {
    setCurrentPath(currentPath.slice(0, index + 1))
  }

  const toggleSelection = (folderId: string, folderName: string) => {
    const isSelected = selectedFolders.some((f) => f.id === folderId)
    if (isSelected) {
      onChange(selectedFolders.filter((f) => f.id !== folderId))
    } else {
      // Construct path for display
      let pathString = ''
      
      if (folderId === currentFolderId) {
        // Selecting current folder
        pathString = currentPath.map(p => p.name).join('/')
      } else {
        // Selecting a child folder
        pathString = currentPath.map(p => p.name).join('/') + '/' + folderName
      }
      
      onChange([...selectedFolders, { id: folderId, name: folderName, path: pathString }])
    }
  }

  const isCurrentFolderSelected = selectedFolders.some(f => f.id === currentFolderId)

  if (!connectionId) {
    return (
      <div className="p-8 text-center text-gray-400 border-2 border-dashed border-gray-700 rounded-lg bg-gray-900/30">
        Please select a Google Drive connection first.
      </div>
    )
  }

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden bg-gray-900/50">
      {/* Header with Breadcrumbs & Current Folder Action */}
      <div className="flex items-center justify-between p-3 bg-gray-800/50 border-b border-gray-700">
        <div className="flex items-center gap-2 text-sm overflow-x-auto no-scrollbar flex-1 mr-4">
          {currentPath.map((item, index) => (
            <React.Fragment key={item.id}>
              {index > 0 && <ChevronRight className="h-4 w-4 text-gray-500 flex-shrink-0" />}
              <button
                onClick={() => handleBreadcrumbClick(index)}
                className={cn(
                  'hover:text-indigo-400 whitespace-nowrap transition-colors',
                  index === currentPath.length - 1 ? 'font-semibold text-white' : 'text-gray-400'
                )}
              >
                {item.name}
              </button>
            </React.Fragment>
          ))}
        </div>
        
        {/* Select Current Folder Button */}
        {currentFolderId !== 'root' && (
          <button
            onClick={() => toggleSelection(currentFolderId, currentFolder.name)}
            className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors",
              isCurrentFolderSelected 
                ? "bg-green-900/30 text-green-400 border border-green-500/30 hover:bg-green-900/50"
                : "bg-indigo-600 text-white hover:bg-indigo-700"
            )}
          >
            {isCurrentFolderSelected ? (
              <>
                <Check className="h-3 w-3" />
                Selected
              </>
            ) : (
              <>
                <Plus className="h-3 w-3" />
                Select This Folder
              </>
            )}
          </button>
        )}
      </div>

      {/* Folder List */}
      <div className="h-64 overflow-y-auto relative custom-scrollbar">
        {loading ? (
          <div className="absolute inset-0 flex items-center justify-center bg-gray-900/50 z-10">
            <Loader2 className="h-6 w-6 animate-spin text-indigo-500" />
          </div>
        ) : error ? (
          <div className="p-8 text-center">
            <div className="inline-flex p-3 rounded-full bg-red-900/20 mb-3">
              <AlertCircle className="h-6 w-6 text-red-500" />
            </div>
            <p className="text-red-400 mb-2 text-sm">{error}</p>
            <button
              onClick={() => loadFolders(currentFolderId)}
              className="text-sm text-indigo-400 hover:underline"
            >
              Retry
            </button>
          </div>
        ) : folders.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">
            No subfolders found in this directory.
          </div>
        ) : (
          <ul className="divide-y divide-gray-800">
            {folders.map((folder) => {
              const isSelected = selectedFolders.some((f) => f.id === folder.id)
              return (
                <li
                  key={folder.id}
                  className={cn(
                    "flex items-center justify-between p-2 hover:bg-gray-800/50 group transition-colors",
                    isSelected && "bg-indigo-900/10"
                  )}
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    {/* Selection Checkbox */}
                    <div
                      onClick={(e) => {
                        e.stopPropagation()
                        toggleSelection(folder.id, folder.name)
                      }}
                      className={cn(
                        "w-5 h-5 rounded border flex items-center justify-center cursor-pointer transition-colors flex-shrink-0",
                        isSelected
                          ? "bg-indigo-600 border-indigo-600 text-white"
                          : "border-gray-600 bg-gray-800 hover:border-gray-500"
                      )}
                    >
                      {isSelected && <Check className="h-3 w-3" />}
                    </div>

                    {/* Folder Icon & Name (Navigate on click) */}
                    <div 
                      className="flex items-center gap-3 flex-1 cursor-pointer"
                      onClick={() => handleNavigate(folder.id, folder.name)}
                    >
                      <Folder className={cn(
                        "h-5 w-5 flex-shrink-0 transition-colors",
                        isSelected ? "text-indigo-400" : "text-gray-500 group-hover:text-gray-400"
                      )} />
                      <span className={cn(
                        "truncate text-sm font-medium transition-colors",
                        isSelected ? "text-indigo-300" : "text-gray-300 group-hover:text-white"
                      )}>
                        {folder.name}
                      </span>
                    </div>
                  </div>

                  {/* Navigate Button */}
                  <button
                    onClick={() => handleNavigate(folder.id, folder.name)}
                    className="p-1 text-gray-500 hover:text-indigo-400 hover:bg-gray-700 rounded-full transition-colors ml-2"
                    title="Open folder"
                  >
                    <ChevronRight className="h-5 w-5" />
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </div>

      {/* Selection Summary */}
      <div className="p-3 border-t border-gray-700 bg-gray-800/30 text-xs flex justify-between items-center">
        <span className="text-gray-400">
          {selectedFolders.length} folder{selectedFolders.length !== 1 ? 's' : ''} selected
        </span>
        {selectedFolders.length > 0 && (
          <button
            onClick={() => onChange([])}
            className="text-red-400 hover:text-red-300 font-medium transition-colors hover:underline"
          >
            Clear Selection
          </button>
        )}
      </div>
    </div>
  )
}
