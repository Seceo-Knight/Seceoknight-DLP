import { Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { useAuthStore } from './lib/store/auth'
import Layout from './components/Layout'
import Login from './pages/Login'
import SSOCallback from './pages/SSOCallback'
import Dashboard from './pages/Dashboard'
import Agents from './pages/Agents'
import Events from './pages/Events'
import Alerts from './pages/Alerts'
import Rules from './pages/Rules'
import Policies from './app/dashboard/policies/page'
import Settings from './pages/Settings'
import Incidents from './app/dashboard/incidents/page'
import LogExplorer from './app/dashboard/log-explorer/page'
import UserManagement from './pages/UserManagement'

function App() {
  const { isAuthenticated } = useAuthStore()

  return (
    <>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/auth/sso" element={<SSOCallback />} />
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="agents" element={<Agents />} />
          <Route path="events" element={<Events />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="rules" element={<Rules />} />
          <Route path="policies" element={<Policies />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="log-explorer" element={<LogExplorer />} />
          <Route path="admin/users" element={<UserManagement />} />
          <Route path="settings" element={<Settings />} />
        </Route>

        <Route
          path="*"
          element={
            <Navigate to={isAuthenticated ? '/dashboard' : '/login'} replace />
          }
        />
      </Routes>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#111118',
            color: '#D0D0E8',
            border: '0.5px solid #1E1E2E',
          },
          success: {
            duration: 3000,
            iconTheme: { primary: '#34D399', secondary: '#111118' },
          },
          error: {
            duration: 5000,
            iconTheme: { primary: '#F87171', secondary: '#111118' },
          },
        }}
      />
    </>
  )
}

export default App
