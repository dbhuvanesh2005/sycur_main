import { Navigate, Outlet, useLocation } from 'react-router-dom'

import { useAuth } from './useAuth'
import '../pages/Workspace.css'


export default function ProtectedRoute() {
  const { loading, session } = useAuth()
  const location = useLocation()

  if (loading) {
    return (
      <main className="auth-loading" aria-live="polite">
        Restoring your secure session…
      </main>
    )
  }

  if (session === null) {
    return (
      <Navigate
        to="/organization"
        replace
        state={{ from: location.pathname }}
      />
    )
  }

  return <Outlet />
}
