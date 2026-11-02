import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { useAuth } from '../auth/useAuth'
import {
  fetchAuthenticatedUser,
  type BackendIdentity,
} from '../lib/api'
import './Workspace.css'


export default function Workspace() {
  const { session, user, signOut } = useAuth()
  const navigate = useNavigate()
  const [identity, setIdentity] = useState<BackendIdentity | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (session === null) {
      return
    }

    const controller = new AbortController()

    void fetchAuthenticatedUser(
      session.access_token,
      controller.signal,
    )
      .then((authenticatedIdentity) => {
        setIdentity(authenticatedIdentity)
        setError(null)
      })
      .catch((requestError: unknown) => {
        if (!controller.signal.aborted) {
          setIdentity(null)
          setError(
            requestError instanceof Error
              ? requestError.message
              : 'Unable to verify the backend session.',
          )
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false)
        }
      })

    return () => controller.abort()
  }, [session])

  const handleLogout = async () => {
    await signOut()
    navigate('/organization', { replace: true })
  }

  return (
    <main className="workspace-page">
      <header className="workspace-header">
        <div>
          <span className="workspace-kicker">SYCUR DEMO WORKSPACE</span>
          <h1>{identity?.organization_name ?? 'Engineering workspace'}</h1>
        </div>

        <button type="button" onClick={() => void handleLogout()}>
          Sign out
        </button>
      </header>

      <section className="workspace-panel">
        <h2>Authenticated API connection</h2>

        {loading && <p>Verifying your Supabase session with FastAPI…</p>}

        {error && (
          <div className="workspace-status error" role="alert">
            <strong>Backend verification failed</strong>
            <span>{error}</span>
          </div>
        )}

        {identity && (
          <div className="workspace-status success">
            <strong>Session verified</strong>
            <span>FastAPI accepted the Supabase access token.</span>
          </div>
        )}

        <dl>
          <div>
            <dt>Signed-in email</dt>
            <dd>{identity?.email ?? user?.email ?? 'Not available'}</dd>
          </div>
          <div>
            <dt>User ID</dt>
            <dd>{identity?.user_id ?? user?.id ?? 'Not available'}</dd>
          </div>
          <div>
            <dt>Backend transport</dt>
            <dd>HTTPS with bearer-token authentication</dd>
          </div>
        </dl>
      </section>
    </main>
  )
}
