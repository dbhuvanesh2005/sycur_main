import { useRoutes } from 'react-router-dom'
import OrganizationGateway from './pages/OrganizationGateway'
import Workspace from './pages/Workspace'
import ProtectedRoute from './auth/ProtectedRoute'
import './App.css'

type IconName = 'shield' | 'brain' | 'layers' | 'activity' | 'arrow' | 'check'

function Icon({ name }: { name: IconName }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {name === 'shield' && (
        <>
          <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
          <path d="m9 12 2 2 4-4" />
        </>
      )}
      {name === 'brain' && (
        <>
          <path d="M12 18V5a3 3 0 0 0-5.7-1.3A4 4 0 0 0 4 11a4 4 0 0 0 3 7h5Z" />
          <path d="M12 18V5a3 3 0 0 1 5.7-1.3A4 4 0 0 1 20 11a4 4 0 0 1-3 7h-5Z" />
          <path d="M8 9h.01M16 9h.01M12 13h.01" />
        </>
      )}
      {name === 'layers' && (
        <>
          <path d="m12 3 9 5-9 5-9-5 9-5Z" />
          <path d="m3 12 9 5 9-5M3 16l9 5 9-5" />
        </>
      )}
      {name === 'activity' && (
        <>
          <path d="M3 12h4l3-8 4 16 3-8h4" />
        </>
      )}
      {name === 'arrow' && (
        <>
          <path d="M5 12h14M13 6l6 6-6 6" />
        </>
      )}
      {name === 'check' && (
        <>
          <path d="m5 12 4 4L19 6" />
        </>
      )}
    </svg>
  )
}

const features = [
  {
    number: '01',
    icon: 'shield' as const,
    title: 'Security Intelligence',
    description:
      'Identify security risks and vulnerabilities through automated engineering analysis.',
  },
  {
    number: '02',
    icon: 'brain' as const,
    title: 'Company-Aware Intelligence',
    description:
      'Connect engineering decisions with your organization’s approved policies and standards.',
  },
  {
    number: '03',
    icon: 'layers' as const,
    title: 'Engineering Intelligence',
    description:
      'Bring API, dependency, architecture and code quality analysis into one platform.',
  },
  {
    number: '04',
    icon: 'activity' as const,
    title: 'Evidence-Driven Insights',
    description:
      'Understand findings through technical evidence, relevant policies and clear explanations.',
  },
]

function LandingPage() {
  return (
    <main id="top">
      <header className="site-header">
        <a href="#top" className="brand" aria-label="SYCUR home">
          <img
            src="/sycur-symbol.png"
            alt=""
            className="brand-symbol"
          />
          <span className="brand-copy">
            <span className="brand-name">
              SYCUR<span className="brand-period">.</span>
            </span>
            <span className="brand-caption">
              ENGINEERING INTELLIGENCE
            </span>
          </span>
        </a>

        <nav className="desktop-nav">
          <a href="#platform">Platform</a>
          <a href="#workflow">How it works</a>
          <a href="#footer">About</a>
        </nav>

        <div className="header-actions">
          <a className="signin-link" href="/organization">
            Sign in
          </a>
          <a className="button button-small button-primary" href="/organization">
            Get started <Icon name="arrow" />
          </a>
        </div>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow">
            <span className="pulse-dot" />
            COMPANY-AWARE ENGINEERING INTELLIGENCE
          </div>

          <h1>
            Build with
            <br />
            confidence.
            <br />
            <span className="gradient-text">Ship with clarity.</span>
          </h1>

          <p className="hero-description">
            Your code. Your standards. One intelligent platform.
            Understand engineering risks, apply company policies
            and make better development decisions.
          </p>

          <div className="hero-actions">
            <a href="/organization" className="button button-primary">
              Get started <Icon name="arrow" />
            </a>

            <a href="#platform" className="button button-secondary">
              Explore platform
            </a>
          </div>

          <div className="hero-highlights">
            <span><Icon name="check" /> Developer-first</span>
            <span><Icon name="check" /> Company-aware</span>
            <span><Icon name="check" /> Evidence-driven</span>
          </div>

          <div className="hero-maker">
            <span className="maker-rule" />
            <span className="maker-prefix">A PRODUCT BY</span>
            <span className="maker-name">
              Thought Mobile Technologies
            </span>
          </div>
        </div>

        <div className="hero-visual">
          <img
            src="/sycur-symbol.png"
            alt=""
            aria-hidden="true"
            className="hero-brand-watermark"
          />
          <div className="visual-glow" />

          <div className="engine-card">
            <div className="engine-header">
              <div className="window-dots">
                <span />
                <span />
                <span />
              </div>
              <span className="preview-label">PLATFORM PREVIEW</span>
            </div>

            <div className="engine-content">
              <div className="engine-heading">
                <div>
                  <span className="small-label">SYCUR INTELLIGENCE</span>
                  <h3>Engineering analysis</h3>
                </div>
                <div className="engine-icon">
                  <Icon name="brain" />
                </div>
              </div>

              <div className="analysis-card">
                <div className="analysis-title">
                  <span className="analysis-indicator" />
                  Pull Request Analysis
                </div>

                <div className="analysis-step">
                  <div className="step-number">01</div>
                  <div>
                    <strong>Code Intelligence</strong>
                    <span>Analyze repository changes</span>
                  </div>
                  <Icon name="check" />
                </div>

                <div className="analysis-step">
                  <div className="step-number purple">02</div>
                  <div>
                    <strong>Company Knowledge</strong>
                    <span>Retrieve applicable policies</span>
                  </div>
                  <Icon name="check" />
                </div>

                <div className="analysis-step">
                  <div className="step-number teal">03</div>
                  <div>
                    <strong>Evidence Validation</strong>
                    <span>Verify technical evidence</span>
                  </div>
                  <Icon name="check" />
                </div>
              </div>

              <div className="engine-result">
                <div className="result-icon">
                  <Icon name="shield" />
                </div>
                <div>
                  <strong>One unified engineering report</strong>
                  <span>Clear findings. Grounded explanations.</span>
                </div>
              </div>
            </div>
          </div>

          <div className="floating-tag tag-top">
            <span className="tag-dot purple-dot" />
            Intelligent analysis
          </div>

          <div className="floating-tag tag-bottom">
            <span className="tag-dot teal-dot" />
            Company-aware intelligence
          </div>
        </div>
      </section>

      <section className="trust-strip">
        <span>ONE PLATFORM</span>
        <span className="strip-line" />
        <span>MULTIPLE ENGINEERING CAPABILITIES</span>
        <span className="strip-line" />
        <span>ONE INTELLIGENT WORKFLOW</span>
      </section>

      <section id="platform" className="platform-section">
        <div className="section-heading">
          <span className="section-label">THE SYCUR PLATFORM</span>
          <h2>
            More than security.
            <br />
            <span className="gradient-text">Engineering intelligence.</span>
          </h2>
          <p>
            A unified platform designed to understand your software,
            your engineering standards and the problems that matter.
          </p>
        </div>

        <div className="feature-grid">
          {features.map((feature) => (
            <article className="feature-card" key={feature.number}>
              <div className="feature-top">
                <div className="feature-icon">
                  <Icon name={feature.icon} />
                </div>
                <span>{feature.number}</span>
              </div>

              <h3>{feature.title}</h3>
              <p>{feature.description}</p>

              <div className="feature-line" />
            </article>
          ))}
        </div>
      </section>

      <section id="workflow" className="workflow-section">
        <div className="workflow-heading">
          <span className="section-label">HOW SYCUR WORKS</span>
          <h2>From code to confidence.</h2>
        </div>

        <div className="workflow-grid">
          <div className="workflow-item">
            <span className="workflow-number">01</span>
            <h3>Connect</h3>
            <p>Connect your repositories and engineering environment.</p>
          </div>

          <div className="workflow-item">
            <span className="workflow-number">02</span>
            <h3>Understand</h3>
            <p>Apply technical analysis and your company's knowledge.</p>
          </div>

          <div className="workflow-item">
            <span className="workflow-number">03</span>
            <h3>Improve</h3>
            <p>Receive evidence-backed findings and actionable insights.</p>
          </div>
        </div>
      </section>

      <section id="access" className="access-section">
        <span className="section-label">YOUR ENGINEERING JOURNEY STARTS HERE</span>
        <h2>
          Make every engineering
          <br />
          decision <span className="gradient-text">count.</span>
        </h2>
        <p>
          Bring your development workflow into one intelligent platform.
        </p>
        <a href="/organization" className="button button-primary">
          Set up your organization <Icon name="arrow" />
        </a>
        <span className="access-note">
          Secure workspace access is the next setup step.
        </span>
      </section>

      <footer id="footer" className="site-footer">
        <div className="footer-brand">
          <span className="brand-name">
            SYCUR<span className="brand-period">.</span>
          </span>
          <span>Engineering intelligence platform</span>
        </div>

        <div className="footer-bottom">
          <span>© 2026 SYCUR. All rights reserved.</span>
          <span>
            Developed by <strong>Thought Mobile Technologies</strong>
          </span>
        </div>
      </footer>
    </main>
  )
}

function App() {
  const routes = useRoutes([
    { path: '/', element: <LandingPage /> },
    { path: '/organization', element: <OrganizationGateway /> },
    {
      element: <ProtectedRoute />,
      children: [
        { path: '/workspace', element: <Workspace /> },
      ],
    },
  ])

  return routes ?? <LandingPage />
}

export default App
