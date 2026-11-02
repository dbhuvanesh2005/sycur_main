# SYCUR Platform

SYCUR is an automated pull-request security review platform. It combines
multiple security scanners with finding correlation, evidence retrieval,
policy evaluation, GitHub Check Runs, and developer-facing review reports.

## Architecture

```text
GitHub Pull Request
        |
        v
FastAPI webhook and review queue
        |
        v
Scanner orchestration and finding correlation
        |
        v
Evidence retrieval and policy evaluation
        |
        v
GitHub Check Run, PR comment, and security report
```

The repository is organized as follows:

```text
backend/   Python API, workers, scanners, policy engine, and tests
frontend/  React and TypeScript web application
tools/     Licenses and metadata for externally managed scanner tools
```

Private documents, demonstration repositories, credentials, runtime databases,
scanner executables, generated reports, and build artifacts are intentionally
excluded from source control.

## Technology stack

### Backend

- Python 3.11+
- FastAPI and Uvicorn
- Pydantic settings and domain models
- PostgreSQL with psycopg and pgvector-compatible retrieval
- SQLite for local review queue state
- PyJWT with RSA signing support for GitHub App authentication
- Pytest

### Frontend

- React 19
- TypeScript 5.9
- Vite
- React Router
- ESLint

## Security scanners

SYCUR routes changed files to applicable scanners:

- Gitleaks for secrets
- Semgrep for rule-based static analysis
- Bandit for Python security analysis
- Trivy for dependency and configuration findings
- OSV-Scanner for open-source vulnerability intelligence
- Checkov for infrastructure-as-code analysis

Scanner executables are installed separately and are not committed to this
repository.

## Backend installation

Create and activate a virtual environment from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e "backend[dev]"
cp .env.example .env
```

Edit `.env` with local development values. Never commit `.env`, installation
tokens, webhook secrets, private keys, database credentials, or customer data.

Run the API:

```bash
cd backend
sycur-api
```

The local health endpoint is available at:

```text
http://127.0.0.1:8000/health
```

## Frontend installation

```bash
cd frontend
npm ci
npm run dev
```

Create a production build with:

```bash
npm run lint
npm run build
```

## Testing

Run the backend suite:

```bash
cd backend
PYTHONPATH=src python -m pytest -q
```

Run the frontend verification:

```bash
cd frontend
npm audit
npm run lint
npm run build
```

## Environment configuration

`.env.example` documents the supported configuration groups:

- application environment and logging
- PostgreSQL connection settings
- local model and embedding settings
- retrieval and evidence limits
- queue and worker concurrency
- GitHub App and webhook configuration
- public report URL

Production secrets must be supplied by the deployment environment or an
approved secret manager. They must never be embedded in source code, frontend
assets, logs, reports, or Git history.

## Demo authentication configuration

SYCUR uses Supabase email/password authentication in the browser and verifies
Supabase access tokens in FastAPI with the project's public JWKS signing keys.
The backend does not require a Supabase service-role key.

Configure these values in the root backend `.env`:

```dotenv
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_JWT_AUDIENCE=authenticated
CORS_ALLOWED_ORIGIN=https://your-vercel-project.vercel.app
```

Configure these public browser values in Vercel for the frontend project:

```dotenv
VITE_SUPABASE_URL=https://your-project-ref.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=your-supabase-publishable-key
VITE_API_BASE_URL=https://your-mac-device.your-tailnet.ts.net
```

`VITE_SUPABASE_PUBLISHABLE_KEY` is the Supabase browser-safe publishable key.
Never place the secret/service-role key, JWT signing secret, database password,
GitHub private key, or webhook secret in a `VITE_` variable.

In the Supabase dashboard:

1. Enable email/password authentication.
2. Set the Site URL to the Vercel frontend origin.
3. Add `https://your-vercel-project.vercel.app/workspace` as an allowed
   redirect URL.
4. Use asymmetric JWT signing keys exposed through the project's public JWKS
   endpoint.

The protected workspace sends the current Supabase access token to
`GET /api/v1/auth/me`. FastAPI validates its signature, issuer, audience,
expiry, issued-at time, and subject before returning the authenticated identity.

For the live demo, PostgreSQL, Ollama, security scanners, the review worker,
and FastAPI remain on the Mac. The browser reaches only FastAPI through the
configured Tailscale HTTPS/Funnel URL.

## Optional local tunnel

After starting the API, an authorized Tailscale installation can expose the
local service for webhook testing:

```bash
tailscale_start
```

Review the active Funnel configuration before exposing a local service to the
internet.
