import { useState } from 'react'
import { Link } from 'react-router-dom'
import './OrganizationGateway.css'

type Choice = 'create' | 'existing'

function BuildingIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="7" width="18" height="14" rx="2" />
      <path d="M8 7V3h8v4M8 12h2m4 0h2M8 16h2m4 0h2M12 21v-3" />
    </svg>
  )
}

function UsersIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M20 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  )
}

function ArrowIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M5 12h14m-6-6 6 6-6 6" />
    </svg>
  )
}

export default function OrganizationGateway() {
  const [selected, setSelected] = useState<Choice | null>(null)

  return (
    <main className="org-gateway">
      <header className="gateway-header">
        <Link to="/" className="gateway-brand">
          <img src="/sycur-symbol.png" alt="" />
          <span>
            <strong>SYCUR<span>.</span></strong>
            <small>ENGINEERING INTELLIGENCE</small>
          </span>
        </Link>

        <Link to="/" className="gateway-home">
          <span>←</span> Back to home
        </Link>
      </header>

      <section className="gateway-main">
        <div className="gateway-eyebrow">
          <span className="gateway-dot" />
          ORGANIZATION ACCESS
        </div>

        <h1>
          Your engineering.
          <br />
          Your <span>organization.</span>
        </h1>

        <p className="gateway-description">
          Start your organization's engineering intelligence journey.
          Create a private workspace or access your existing company.
        </p>

        <div className="gateway-cards">

          <article className={`gateway-card create-card ${
            selected === 'create' ? 'is-selected' : ''
          }`}>
            <div className="gateway-card-top">
              <div className="gateway-icon purple-icon">
                <BuildingIcon />
              </div>
              <span className="gateway-card-label">NEW WORKSPACE</span>
            </div>

            <h2>Create an organization</h2>

            <p>
              For company owners and administrators setting up
              a new SYCUR workspace for their organization.
            </p>

            <ul>
              <li>Establish your private workspace</li>
              <li>Configure company information</li>
              <li>Manage policies and team access</li>
            </ul>

            <button
              className="gateway-action primary-action"
              onClick={() => setSelected('create')}
              aria-pressed={selected === 'create'}
            >
              Create organization <ArrowIcon />
            </button>
          </article>

          <article className={`gateway-card existing-card ${
            selected === 'existing' ? 'is-selected' : ''
          }`}>
            <div className="gateway-card-top">
              <div className="gateway-icon teal-icon">
                <UsersIcon />
              </div>
              <span className="gateway-card-label">EXISTING WORKSPACE</span>
            </div>

            <h2>Existing organization</h2>

            <p>
              Already part of a company using SYCUR?
              Access your organization's private engineering workspace.
            </p>

            <ul>
              <li>Access your company workspace</li>
              <li>Continue your engineering workflow</li>
              <li>Join through an organization invitation</li>
            </ul>

            <button
              className="gateway-action secondary-action"
              onClick={() => setSelected('existing')}
              aria-pressed={selected === 'existing'}
            >
              Access organization <ArrowIcon />
            </button>
          </article>
        </div>

        {selected && (
          <div className="gateway-selection" role="status" aria-live="polite">
            <span className="gateway-dot" />
            <div>
              <strong>
                {selected === 'create'
                  ? 'New organization selected'
                  : 'Existing organization selected'}
              </strong>
              <p>
                {selected === 'create'
                  ? 'Next step: Create your account and configure your organization.'
                  : 'Next step: Sign in to access your authorized organization.'}
              </p>
            </div>
          </div>
        )}

        <p className="gateway-help">
          Need help getting started? Contact your organization administrator.
        </p>
      </section>

      <footer className="gateway-footer">
        <div className="gateway-footer-brand">
          <strong>SYCUR<span>.</span></strong>
          <small>Engineering intelligence platform</small>
        </div>

        <div className="gateway-footer-bottom">
          <span>© 2026 SYCUR. All rights reserved.</span>
          <span>
            Developed by <strong>Thought Mobile Technologies</strong>
          </span>
        </div>
      </footer>
    </main>
  )
}
