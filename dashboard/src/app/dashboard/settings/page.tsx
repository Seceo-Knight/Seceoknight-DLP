'use client'

/**
 * Next.js App Router route: /dashboard/settings
 * Delegates to the canonical Settings page component — single source of truth.
 */
import DashboardLayout from '@/components/layout/DashboardLayout'
import Settings from '@/pages/Settings'

export default function SettingsPage() {
  return (
    <DashboardLayout>
      <div className="p-6 h-full">
        <Settings />
      </div>
    </DashboardLayout>
  )
}
