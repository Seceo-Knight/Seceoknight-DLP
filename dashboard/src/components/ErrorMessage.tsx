import { AlertCircle } from 'lucide-react'

interface ErrorMessageProps {
  message: string
  retry?: () => void
}

export default function ErrorMessage({ message, retry }: ErrorMessageProps) {
  return (
    <div className="card border-red-200 bg-red-50">
      <div className="flex items-center gap-3">
        <AlertCircle className="h-5 w-5 text-red-600 flex-shrink-0" />
        <div className="flex-1">
          <p className="text-sm font-medium text-red-800">Error</p>
          <p className="mt-1 text-sm text-red-700">{message}</p>
        </div>
        {retry && (
          <button
            onClick={retry}
            className="px-4 py-2 text-sm font-medium text-red-700 hover:bg-red-100 rounded-lg transition-colors"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  )
}
