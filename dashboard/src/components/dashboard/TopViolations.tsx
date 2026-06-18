import { FileWarning } from 'lucide-react'

interface Violation {
  policy: string
  count: number
}

interface TopViolationsProps {
  violations: Violation[]
}

export default function TopViolations({ violations }: TopViolationsProps) {
  const maxCount = Math.max(...violations.map(v => v.count), 1)

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">Top Policy Violations</h2>

      <div className="space-y-4">
        {violations.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <FileWarning className="w-10 h-10 mx-auto mb-2 text-gray-400" />
            <p className="text-sm">No violations</p>
          </div>
        ) : (
          violations.map((violation, index) => (
            <div key={index} className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-700 font-medium truncate flex-1">
                  {violation.policy}
                </span>
                <span className="text-gray-900 font-bold ml-2">{violation.count}</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-red-500 to-orange-500 h-2 rounded-full transition-all"
                  style={{ width: `${(violation.count / maxCount) * 100}%` }}
                ></div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
