'use client'

import DashboardLayout from '@/components/layout/DashboardLayout'
import Reports from '@/pages/Reports'

export default function ReportsPage() {
  return (
    <DashboardLayout>
      <div className="p-6 h-full">
        <Reports />
      </div>
    </DashboardLayout>
  )
}
