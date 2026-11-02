export type BackendIdentity = {
  user_id: string
  email: string | null
  organization_name: string | null
}

export function buildApiUrl(
  path: string,
  baseUrl = import.meta.env.VITE_API_BASE_URL,
): string {
  if (!baseUrl) {
    throw new Error('VITE_API_BASE_URL must be configured.')
  }

  const parsed = new URL(baseUrl)

  if (
    parsed.protocol !== 'https:'
    && parsed.hostname !== 'localhost'
    && parsed.hostname !== '127.0.0.1'
  ) {
    throw new Error('The remote API URL must use HTTPS.')
  }

  const normalizedBase = `${parsed.origin}/`
  const normalizedPath = path.replace(/^\//, '')

  return new URL(normalizedPath, normalizedBase).toString()
}

export function buildAuthHeaders(accessToken: string): HeadersInit {
  if (!accessToken) {
    throw new Error('An access token is required.')
  }

  return {
    Accept: 'application/json',
    Authorization: `Bearer ${accessToken}`,
  }
}

export async function fetchAuthenticatedUser(
  accessToken: string,
  signal?: AbortSignal,
): Promise<BackendIdentity> {
  const response = await fetch(
    buildApiUrl('/api/v1/auth/me'),
    {
      method: 'GET',
      headers: buildAuthHeaders(accessToken),
      signal,
    },
  )

  if (!response.ok) {
    throw new Error(
      `Backend authentication failed with status ${response.status}.`,
    )
  }

  return response.json() as Promise<BackendIdentity>
}
