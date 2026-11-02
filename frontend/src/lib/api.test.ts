import { describe, expect, it } from 'vitest'

import { buildApiUrl, buildAuthHeaders } from './api'


describe('authenticated API client', () => {
  it('builds the protected endpoint on the configured HTTPS API', () => {
    expect(
      buildApiUrl(
        '/api/v1/auth/me',
        'https://sycur-demo.example.ts.net',
      ),
    ).toBe('https://sycur-demo.example.ts.net/api/v1/auth/me')
  })

  it('rejects insecure remote API URLs', () => {
    expect(() => buildApiUrl('/health', 'http://example.com')).toThrow(
      'The remote API URL must use HTTPS.',
    )
  })

  it('adds the Supabase access token as a bearer credential', () => {
    expect(buildAuthHeaders('demo-token')).toEqual({
      Accept: 'application/json',
      Authorization: 'Bearer demo-token',
    })
  })
})
