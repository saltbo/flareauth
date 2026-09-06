import { createTestDeps } from '@server/http/test-deps'
import { realmrootOrganizationClaim } from '@shared/oauth-token-profile'
import { Hono } from 'hono'
import { expect, it, vi } from 'vitest'
import { authn, type SessionReader } from './authn'

it('leaves explicit authorization credentials for the resource authentication boundary', async () => {
  const getSession = vi.fn().mockResolvedValue(null)
  const app = new Hono()
    .use('*', authn({ api: { getSession } } satisfies SessionReader))
    .get('/api/resource', (c) => c.json({ ok: true }))

  const response = await app.request('/api/resource', {
    headers: { Authorization: 'DPoP access-token' },
  })

  expect(response.status).toBe(200)
  expect(getSession).not.toHaveBeenCalled()
})

it('preserves the verified delegated Organization separately from the Application owner', async () => {
  const deps = createTestDeps()
  vi.mocked(deps.applications.findByClientId).mockResolvedValue({
    id: 'app-1',
    clientId: 'client-1',
    ownerOrganizationId: 'app-owner',
    disabled: false,
  } as never)
  vi.mocked(deps.users.getUser).mockResolvedValue({
    id: 'user-1',
    email: 'user@example.com',
    displayName: 'User',
  } as never)
  let organization: string | undefined = 'delegated-org'
  const auth = {
    api: {
      getSession: vi.fn().mockResolvedValue(null),
      verifyJWT: vi.fn().mockImplementation(async () => ({
        payload: {
          sub: 'user-1',
          client_id: 'client-1',
          scope: 'agents:write',
          [realmrootOrganizationClaim]: organization,
        },
      })),
    },
  } satisfies SessionReader
  const app = new Hono()
    .use('*', async (c, next) => {
      c.set('deps', deps)
      await next()
    })
    .use(
      '*',
      authn(auth, {
        allowApplication: true,
        oauth: {
          issuer: () => 'https://id.test',
          audience: () => 'https://id.test/api',
          resourceRequestUrl: (url) => url,
        },
      }),
    )
    .get('/api', (c) => c.json(c.get('principal')))
  const response = await app.request('/api', { headers: { Authorization: 'Bearer delegated-token' } })
  expect(response.status).toBe(200)
  expect(await response.json()).toMatchObject({
    user: { id: 'user-1' },
    application: { ownerOrganizationId: 'app-owner', delegatedOrganizationId: 'delegated-org' },
  })
  organization = undefined
  const personal = await app.request('/api', { headers: { Authorization: 'Bearer delegated-token' } })
  expect(await personal.json()).toMatchObject({
    application: { ownerOrganizationId: 'app-owner', delegatedOrganizationId: null },
  })
})
