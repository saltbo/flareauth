import { createTestDeps } from '@server/http/test-deps'
import {
  completeResourceConnectionIntent,
  createAccessRequest,
  createAccessRequestCredential,
  createAccountConnection,
  createAgentAccessRequest,
  createAgentPermission,
  createProviderConnectionIntent,
  createResourceConnectionIntent,
  decideAccessRequest,
  decideAgentAccessRequest,
  decideAgentAccessRequestByToken,
  disconnectProviderConnection,
  discoverAgentResources,
  failResourceConnectionIntent,
  getAccessRequest,
  getAccountAccessRequest,
  getAccountAccessRequestByToken,
  getAccountConnection,
  getAgentAccessRequest,
  getAgentPermission,
  getAgentResourceServer,
  getApiResource,
  getControllerAccessRequestByToken,
  getExternalResourceAuthorization,
  issueTargetAccessToken,
  listAccessRequestConnections,
  listAccountAccessRequestAuthorizationDetailCatalog,
  listAccountAccessRequests,
  listAccountConnections,
  listAccountProviderConnections,
  listAccountProviderConnectors,
  listAgentResourceServers as listAgentApiResources,
  listAgentResourceServerAuthorizationDetails as listAgentAuthorizationDetailCatalog,
  listAgentPermissions,
  listApiResources,
  listConnectableExternalResources,
  listControllerAccessRequests,
  listResourceConnections,
  revokeAgentPermission,
  revokeAgentResourceAccess,
  revokeAgentResourceLeasesForBinding,
  revokeResourceConnection,
} from '@server/usecases/external-resources'
import type {
  AgentAccessRequestRecord,
  AgentIdentityAggregate,
  ConnectorRecord,
  ProviderConnectionRecord,
  ProviderCredentialRecord,
  ProviderResourceAuthorizationRecord,
  ResourceConnectionIntentRecord,
  ResourceScopeEntitlementRecord,
} from '@server/usecases/ports'
import { validateExternalResourceConnector } from '@server/usecases/resource-connectors'
import { protectedResourceMetadataUrl } from '@server/usecases/resource-metadata'
import type { ApiResourceResponse } from '@shared/api/authorization'
import type { AuthorizationDetail } from '@shared/api/authorization-details'
import {
  realmrootAgentBindingClaim,
  realmrootCliClientId,
  realmrootOrganizationClaim,
} from '@shared/oauth-token-profile'
import { exportJWK, generateKeyPair, type JWTHeaderParameters, jwtVerify, SignJWT } from 'jose'
import { describe, expect, it, vi } from 'vitest'

const now = new Date('2026-07-29T12:00:00.000Z')
const organizationAuthority = { type: 'realmroot_authority', authority: 'organization', id: 'org-1' }
const userAuthority = { type: 'realmroot_authority', authority: 'user', id: 'user-1' }

describe('external API resource authorization', () => {
  it('[spec: agent-identity/direct-agent-permission] grants before any request and reuses the grant on first Agent access', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.authorization.findResourceByResourceUrl).mockResolvedValue(resource())
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    let saved: ResourceScopeEntitlementRecord | undefined
    deps.authorization.createScopeEntitlement = vi.fn(async (record) => (saved ??= record))
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockImplementation(async () =>
      saved ? [saved] : [],
    )
    const input = {
      resource: resource().resourceUrl,
      scopes: ['projects:read'],
      mode: 'persistent' as const,
    }
    const [permission] = await createAgentPermission(deps, 'identity-1', input, 'user-1')
    expect(permission).toMatchObject({ scope: 'projects:read', mode: 'persistent', sourceAccessRequestId: null })
    expect(deps.externalResources.createAccessRequest).not.toHaveBeenCalled()
    expect((await createAgentPermission(deps, 'identity-1', input, 'user-1'))[0]?.id).toBe(permission!.id)
    vi.mocked(deps.externalResources.createAccessRequest).mockImplementation(async (record) => record)
    const request = await createAgentAccessRequest(
      deps,
      { resourceId: 'resource-1', scopes: ['projects:read'], reason: 'Work', authorizationDetails: [] },
      principal(),
      'https://auth.example.com',
    )
    expect(request.status).toBe('approved')
    expect(saved?.grantedByUserId).toBe('user-1')
  })

  it('[spec: agent-identity/direct-agent-permission] rejects another controller and scopes outside the account', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.authorization.findResourceByResourceUrl).mockResolvedValue(resource())
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    deps.authorization.createScopeEntitlement = vi.fn()
    const input = {
      resource: resource().resourceUrl,
      scopes: ['projects:write'],
      mode: 'persistent' as const,
    }
    await expect(createAgentPermission(deps, 'identity-1', input, 'another-user')).rejects.toThrow('Agent controller')
    await expect(createAgentPermission(deps, 'identity-1', input, 'user-1')).rejects.toThrow('connected account')
    expect(deps.authorization.createScopeEntitlement).not.toHaveBeenCalled()
  })

  it('[spec: agent-identity/direct-agent-permission] resolves the native user or verified Organization Context internally', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.authorization.findResourceByResourceUrl).mockResolvedValue({
      ...nativeResource(),
      scopeRegistry: {
        ...nativeResource().scopeRegistry!,
        scopes: resourceScopeValues.map((value) => ({ value, description: null, grantMode: 'automatic' as const })),
      },
    })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    deps.authorization.createScopeEntitlement = vi.fn(async (record) => record)
    const input = { resource: nativeResource().resourceUrl, scopes: ['projects:read'], mode: 'persistent' as const }
    deps.authorization.findOrganization = vi
      .fn()
      .mockResolvedValue({ id: 'org-1', name: 'Organization', disabled: false })
    const personal = await createAgentPermission(deps, 'identity-1', input, 'user-1')
    expect(personal[0]?.authorizationDetails).toEqual([userAuthority])
    const organization = await createAgentPermission(deps, 'identity-1', input, 'user-1', 'org-1')
    expect(organization[0]?.authorizationDetails).toEqual([organizationAuthority])
    vi.mocked(deps.authorization.findResourceByResourceUrl).mockResolvedValue(null)
    await expect(createAgentPermission(deps, 'identity-1', input, 'user-1')).rejects.toThrow('Resource Server')
  })

  it('[spec: agent-identity/direct-agent-permission] reports a missing connection and inactive Agent without writing', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.authorization.findResourceByResourceUrl).mockResolvedValue(resource())
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    deps.authorization.createScopeEntitlement = vi.fn()
    const input = { resource: resource().resourceUrl, scopes: ['projects:read'], mode: 'persistent' as const }
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(null)
    await expect(createAgentPermission(deps, 'identity-1', input, 'user-1')).rejects.toThrow('must connect')
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    const inactive = identityAggregate()
    inactive.identity.status = 'inactive'
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(inactive)
    await expect(createAgentPermission(deps, 'identity-1', input, 'user-1')).rejects.toThrow('Active Agent')
    expect(deps.authorization.createScopeEntitlement).not.toHaveBeenCalled()
  })

  it('[spec: agent-identity/direct-agent-permission] resolves all catalog pages and validates every Context before writing', async () => {
    const deps = authorizationCatalogDeps({
      grantedScopes: ['projects:read', 'projects:write', 'authorization-details:read'],
    })
    const template = { type: 'project_access', actions: ['read'] }
    const details = Array.from({ length: 101 }, (_, index) => ({ ...template, identifier: `project-${index}` }))
    vi.mocked(deps.authorization.findResourceByResourceUrl).mockResolvedValue({
      ...resource(),
      authorizationDetails: [template],
    })
    const connection = {
      ...connectionRecord(),
      grantedScopes: ['projects:read', 'projects:write', 'authorization-details:read'],
      authorizationDetails: details,
    }
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    let empty = false
    let lastContextScopes = ['projects:read', 'projects:write']
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      const page = Number(new URL(request.url).searchParams.get('page') ?? 1)
      return Response.json({
        items: empty
          ? []
          : details.slice((page - 1) * 100, page * 100).map((authorizationDetail) => ({
              authorizationDetail,
              grantedScopes:
                authorizationDetail.identifier === 'project-100'
                  ? lastContextScopes
                  : ['projects:read', 'projects:write'],
              display: { label: authorizationDetail.identifier },
            })),
        pagination: { page, pageSize: 100, totalItems: empty ? 0 : 101, totalPages: empty ? 0 : 2 },
      })
    })
    deps.authorization.createScopeEntitlement = vi.fn(async (record) => record)
    const input = {
      resource: resource().resourceUrl,
      scopes: ['projects:read', 'projects:write', 'projects:read'],
      mode: 'persistent' as const,
    }
    const result = await createAgentPermission(deps, 'identity-1', input, 'user-1')
    expect(result).toHaveLength(202)
    expect(deps.externalHttp.fetch).toHaveBeenCalledTimes(2)
    expect(result.at(-1)).toMatchObject({ scope: 'projects:write', authorizationDetails: [details[100]] })
    vi.mocked(deps.authorization.createScopeEntitlement).mockClear()
    lastContextScopes = ['projects:read']
    await expect(createAgentPermission(deps, 'identity-1', input, 'user-1')).rejects.toThrow('connected account')
    expect(deps.authorization.createScopeEntitlement).not.toHaveBeenCalled()
    empty = true
    await expect(createAgentPermission(deps, 'identity-1', input, 'user-1')).rejects.toThrow(
      'no available authorization Contexts',
    )
    expect(deps.authorization.createScopeEntitlement).not.toHaveBeenCalled()
  })

  it('[spec: agent-identity/direct-agent-permission] grants a time-limited permission and rejects an already expired lifetime', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.authorization.findResourceByResourceUrl).mockResolvedValue(resource())
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    deps.authorization.createScopeEntitlement = vi.fn(async (record) => record)
    const input = {
      resource: resource().resourceUrl,
      scopes: ['projects:read'],
      mode: 'until' as const,
      expiresAt: '2030-01-01T00:00:00.000Z',
    }
    expect((await createAgentPermission(deps, 'identity-1', input, 'user-1'))[0]).toMatchObject({
      mode: 'until',
      expiresAt: input.expiresAt,
    })
    await expect(
      createAgentPermission(deps, 'identity-1', { ...input, expiresAt: '2020-01-01T00:00:00Z' }, 'user-1'),
    ).rejects.toThrow('future')
  })

  it('rejects a deleted external resource connection intent', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.authorization.findResource).mockResolvedValue(null)

    await expect(
      createResourceConnectionIntent(
        deps,
        'resource-1',
        { owner: { type: 'user' }, scopes: [] },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toThrow('External API resource was not found.')

    vi.mocked(deps.authorization.findResource).mockResolvedValue({ ...resource(), enabled: false })
    await expect(
      createResourceConnectionIntent(
        deps,
        'resource-1',
        { owner: { type: 'user' }, scopes: [] },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Enabled external API resource was not found.')
  })

  it('rejects account connection intents for invalid authorization boundaries', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const input = { owner: { type: 'user' as const }, scopes: ['projects:read'] }

    vi.mocked(deps.authorization.findResource).mockResolvedValue({
      ...resource(),
      authorizationModel: 'native',
      connectorId: null,
    })
    await expect(
      createResourceConnectionIntent(deps, 'resource-1', input, 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('Realmroot-issued access does not use account connections.')

    vi.mocked(deps.authorization.findResource).mockResolvedValue({ ...resource(), connectorId: null })
    await expect(
      createResourceConnectionIntent(deps, 'resource-1', input, 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('External authorization requires a Provider Connector.')

    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord({ resourceAuthorizationEnabled: false }))
    await expect(
      createResourceConnectionIntent(deps, 'resource-1', input, 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('Active external API resource authorization was not found.')

    vi.mocked(deps.connectors.findById)
      .mockReset()
      .mockResolvedValueOnce(connectorRecord())
      .mockResolvedValueOnce(connectorRecord())
      .mockResolvedValueOnce(null)
    await expect(
      createResourceConnectionIntent(deps, 'resource-1', input, 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('Provider Connector does not support resource authorization.')

    vi.mocked(deps.connectors.findById)
      .mockReset()
      .mockResolvedValueOnce(connectorRecord())
      .mockResolvedValueOnce(connectorRecord())
      .mockResolvedValueOnce(connectorRecord({ resourceAuthorizationEndpoint: null }))
    await expect(
      createResourceConnectionIntent(deps, 'resource-1', input, 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('Provider Connector does not support resource authorization.')
  })

  it('validates a reusable OIDC connector when creating an external resource [spec: agent-identity/external-api-resource-registration]', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url === new URL(resource().resourceUrl).toString()) {
        return new Response(null, { headers: { link: '</openapi.json>; rel="service-desc"' } })
      }
      if (request.url === new URL('/openapi.json', resource().resourceUrl).toString()) {
        return Response.json({ openapi: '3.1.0', paths: {} })
      }
      if (request.url.endsWith('/.well-known/oauth-protected-resource/api')) {
        return Response.json({
          resource: 'https://projects.example.com/api',
          authorization_servers: ['https://projects.example.com'],
          scopes_supported: ['projects:read'],
        })
      }
      return new Response(null, { status: 404 })
    })

    await expect(
      validateExternalResourceConnector(deps, 'https://projects.example.com/api', 'connector-1'),
    ).resolves.toMatchObject({ scopesSupported: ['projects:read'] })
  })

  it('rejects a connector whose issuer does not authorize the resource', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url === 'https://projects.example.com/api') {
        return new Response(null, { headers: { link: '</openapi.json>; rel="service-desc"' } })
      }
      if (request.url === 'https://projects.example.com/openapi.json') {
        return Response.json({ openapi: '3.1.0', paths: {} })
      }
      if (request.url.endsWith('/.well-known/oauth-protected-resource/api')) {
        return Response.json({
          resource: 'https://projects.example.com/api',
          authorization_servers: ['https://different.example.com'],
          scopes_supported: ['projects:read'],
        })
      }
      return new Response(null, { status: 404 })
    })

    await expect(
      validateExternalResourceConnector(deps, 'https://projects.example.com/api', 'connector-1'),
    ).rejects.toThrow('authorization server does not match')
  })

  it('connects the user account with authorization code and PKCE [spec: agent-identity/resource-account-connection]', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    let intent: ResourceConnectionIntentRecord | null = null
    vi.mocked(deps.externalResources.createConnectionIntent).mockImplementation(async (record) => {
      intent = record
      return record
    })
    vi.mocked(deps.externalResources.consumeConnectionIntent).mockImplementation(async () => intent)

    const started = await createResourceConnectionIntent(
      deps,
      'resource-1',
      { owner: { type: 'user' }, scopes: ['projects:read'] },
      'user-1',
      'https://auth.example.com',
    )
    const authorizationUrl = new URL(started.authorizationUrl)
    expect(deps.oauthRequests.generateCodeChallenge).toHaveBeenCalledWith(expect.any(String))
    expect(vi.mocked(deps.externalResources.createConnectionIntent).mock.calls[0]![0].clientGeneration).toBe(1)
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256')
    expect(authorizationUrl.searchParams.get('prompt')).toBe('consent')
    expect(authorizationUrl.searchParams.get('resource')).toBe('https://projects.example.com/api')
    vi.mocked(deps.externalResources.createConnectionIntent).mockResolvedValueOnce(null)
    await expect(
      createResourceConnectionIntent(
        deps,
        'resource-1',
        { owner: { type: 'user' }, scopes: ['projects:read'] },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Enabled external API resource was not found.')
    vi.mocked(deps.secrets.seal).mockResolvedValueOnce('v1.encrypted-resource-credential')

    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url.endsWith('/token')) {
        const form = new URLSearchParams(await request.text())
        expect(form.get('code_verifier')).toBeTruthy()
        return Response.json({
          access_token: 'subject-access',
          refresh_token: 'subject-refresh',
          token_type: 'Bearer',
          expires_in: 300,
          scope: 'openid offline_access projects:read',
        })
      }
      if (request.url.endsWith('/userinfo')) {
        expect(request.headers.get('authorization')).toBe('Bearer subject-access')
        return Response.json({ sub: 'target-user-1', name: 'Project Owner' })
      }
      return new Response(null, { status: 404 })
    })

    const connection = await completeResourceConnectionIntent(
      deps,
      { state: authorizationUrl.searchParams.get('state')!, code: 'authorization-code' },
      'https://auth.example.com',
    )
    expect(deps.oauthRequests.createAuthorizationCodeRequest).toHaveBeenCalledWith({
      code: 'authorization-code',
      codeVerifier: intent!.encryptedPkceVerifier.replace(/^sealed:/, ''),
      redirectUri: 'https://auth.example.com/oauth/account-connection/callback',
      clientId: 'realmroot-client',
      clientSecret: 'target-secret',
      authentication: 'basic',
    })
    expect(connection).toMatchObject({
      resourceId: 'resource-1',
      owner: { type: 'user', userId: 'user-1' },
      externalSubject: 'target-user-1',
      displayName: 'Project Owner',
      status: 'active',
    })
    const stored = vi.mocked(deps.externalResources.createResourceAuthorization).mock.calls[0]![0]
    expect(stored.credentials[0]!.clientGeneration).toBe(1)
    expect(stored.credentials[0]!.encryptedTokens).not.toContain('subject-refresh')

    intent = {
      ...intent!,
      id: 'organization-connection',
      ownerUserId: null,
      ownerOrganizationId: 'org-1',
    }
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url.endsWith('/token')) {
        return Response.json({
          access_token: 'organization-access',
          refresh_token: 'organization-refresh',
          token_type: 'Bearer',
        })
      }
      if (request.url.endsWith('/userinfo')) {
        return Response.json({ sub: 'org-subject', preferred_username: 'Organization Owner' })
      }
      return new Response(null, { status: 404 })
    })
    await expect(
      completeResourceConnectionIntent(
        deps,
        { state: 'organization-state', code: 'organization-code' },
        'https://auth.example.com/',
      ),
    ).resolves.toMatchObject({
      owner: { type: 'organization', organizationId: 'org-1' },
      displayName: 'Organization Owner',
      grantedScopes: intent.scopes,
      credentialExpiresAt: null,
    })

    intent = { ...intent!, id: 'subject-fallback-connection', ownerUserId: 'user-1', ownerOrganizationId: null }
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url.endsWith('/token')) {
        return Response.json({
          access_token: 'fallback-access',
          refresh_token: 'fallback-refresh',
          token_type: 'Bearer',
        })
      }
      if (request.url.endsWith('/userinfo')) return Response.json({ sub: 'subject-only' })
      return new Response(null, { status: 404 })
    })
    await expect(
      completeResourceConnectionIntent(
        deps,
        { state: 'subject-fallback-state', code: 'subject-fallback-code' },
        'https://auth.example.com/',
      ),
    ).resolves.toMatchObject({ displayName: 'subject-only' })

    vi.mocked(deps.externalResources.createResourceAuthorization).mockResolvedValueOnce(null)
    await expect(
      completeResourceConnectionIntent(
        deps,
        { state: 'deleted-state', code: 'deleted-code' },
        'https://auth.example.com/',
      ),
    ).rejects.toThrow('deleted while completing the connection')
  })

  it('[spec: agent-identity/adapter-external-resource-authorization] requests an advertised OIDC profile for the connection label', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const providerMetadata = metadata()
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        resourceProviderMetadata: {
          ...providerMetadata,
          scopes_supported: [...providerMetadata.scopes_supported, 'profile'],
        },
      }),
    )

    const started = await createResourceConnectionIntent(
      deps,
      'resource-1',
      { owner: { type: 'user' }, scopes: ['projects:read'] },
      'user-1',
      'https://auth.example.com',
    )

    expect(new URL(started.authorizationUrl).searchParams.get('scope')).toBe(
      'offline_access openid profile projects:read',
    )
    expect(deps.externalResources.createConnectionIntent).toHaveBeenCalledWith(
      expect.objectContaining({ scopes: ['offline_access', 'openid', 'profile', 'projects:read'] }),
    )
  })

  it('fails managed OAuth completion when its driver disappears or identity lookup fails', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const intent: ResourceConnectionIntentRecord = {
      id: 'intent-1',
      stateHash: 'state-hash',
      resourceId: 'resource-1',
      ownerUserId: 'user-1',
      ownerOrganizationId: null,
      initiatedByUserId: 'user-1',
      scopes: ['projects:read'],
      authorizationDetails: [],
      encryptedPkceVerifier: 'sealed:pkce-verifier',
      clientGeneration: 1,
      returnTo: 'account-center',
      status: 'completed',
      expiresAt: new Date(Date.now() + 300_000),
      completedAt: now,
      createdAt: now,
      updatedAt: now,
    }
    vi.mocked(deps.externalResources.consumeConnectionIntent).mockResolvedValue(intent)
    vi.mocked(deps.connectors.findById).mockResolvedValueOnce(connectorRecord()).mockResolvedValueOnce(null)

    await expect(
      completeResourceConnectionIntent(deps, { state: 'state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toThrow('no longer supports resource authorization')

    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) =>
      request.url.endsWith('/token')
        ? Response.json({ access_token: 'access', refresh_token: 'refresh' })
        : new Response(null, { status: 503 }),
    )
    await expect(
      completeResourceConnectionIntent(deps, { state: 'state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toThrow('Provider connection identity request failed')

    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) =>
      request.url.endsWith('/token')
        ? Response.json({ access_token: 'access', refresh_token: 'refresh' })
        : Response.json({ sub: 'provider-user-1', name: 'Provider User' }),
    )
    vi.mocked(deps.authorization.findResource)
      .mockReset()
      .mockResolvedValueOnce(resource())
      .mockResolvedValueOnce({ ...resource(), connectorId: null })
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    await expect(
      completeResourceConnectionIntent(deps, { state: 'state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toThrow('API resource no longer has a Provider Connector')

    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    let connectorReads = 0
    vi.mocked(deps.connectors.findById).mockImplementation(async () => {
      connectorReads += 1
      return connectorReads === 4 ? null : connectorRecord()
    })
    await expect(
      completeResourceConnectionIntent(deps, { state: 'state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toThrow('API resource no longer has a Provider Connector')
  })

  it('[spec: account-center/provider-connections] starts a Provider connection without an Agent request', async () => {
    const deps = createTestDeps()
    const external = {
      ...resource(),
      authorizationModel: 'external' as const,
      connectorId: 'connector-1',
      authorizationDetails: [],
    }
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord({ resourceRegistrationMode: 'manual' }))
    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([external])
    vi.mocked(deps.authorization.findResource).mockResolvedValue(external)
    vi.mocked(deps.externalResources.createConnectionIntent).mockImplementation(async (intent) => intent)
    const signer = { issuer: 'https://auth.example.com/api/auth', sign: vi.fn(async () => 'signed-request-object') }

    const intent = await createProviderConnectionIntent(
      deps,
      'connector-1',
      'user-1',
      'https://auth.example.com',
      signer,
    )

    expect(intent).toMatchObject({ connectorId: 'connector-1' })
    expect(new URL(intent.authorizationUrl).searchParams.get('client_id')).toBe('realmroot-client')
    expect(deps.externalResources.createConnectionIntent).toHaveBeenCalledWith(
      expect.objectContaining({
        ownerUserId: 'user-1',
        resourceId: external.id,
        returnTo: 'account-center',
        scopes: expect.arrayContaining(resourceScopeValues),
      }),
    )
  })

  it('rejects an unavailable or ambiguous Provider connection authority', async () => {
    const deps = createTestDeps()
    vi.mocked(deps.connectors.findById).mockResolvedValue(null)
    await expect(
      createProviderConnectionIntent(deps, 'connector-1', 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('Enabled Provider Connector was not found')
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord({ enabled: false }))
    await expect(
      createProviderConnectionIntent(deps, 'connector-1', 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('Enabled Provider Connector was not found')
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([])

    await expect(
      createProviderConnectionIntent(deps, 'connector-1', 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('does not support direct account connection')

    const external = {
      ...resource(),
      authorizationModel: 'external' as const,
      connectorId: 'connector-1',
    }
    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([external, { ...external, id: 'resource-2' }])
    await expect(
      createProviderConnectionIntent(deps, 'connector-1', 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('more than one account connection authority')

    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([
      { ...external, scopeRegistry: { ...external.scopeRegistry!, scopes: [] } },
    ])
    await expect(
      createProviderConnectionIntent(deps, 'connector-1', 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('does not declare any scopes')

    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([{ ...external, scopeRegistry: null }])
    await expect(
      createProviderConnectionIntent(deps, 'connector-1', 'user-1', 'https://auth.example.com'),
    ).rejects.toThrow('does not declare any scopes')
  })

  it('[spec: account-center/provider-connections] derives Provider capabilities only from enabled Agent resources', async () => {
    const deps = createTestDeps()
    vi.mocked(deps.connectors.listEnabled).mockResolvedValue([
      connectorRecord(),
      connectorRecord({ id: 'connector-sign-in', providerId: 'sign-in', authenticationEnabled: true }),
      connectorRecord({ id: 'connector-broker', providerId: 'broker' }),
    ])
    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([
      {
        ...resource(),
        connectorId: 'connector-1',
        availableToAgents: false,
      },
      {
        ...resource(),
        authorizationModel: 'external',
        connectorId: 'connector-broker',
        scopeRegistry: {
          ...resource().scopeRegistry!,
        },
      },
    ])

    await expect(listAccountProviderConnectors(deps, { limit: 20, offset: 0 })).resolves.toMatchObject({
      items: [
        {
          id: 'connector-1',
          capabilities: {
            agentAccess: { available: false },
            connection: { method: null },
          },
        },
        {
          id: 'connector-sign-in',
          capabilities: {
            agentAccess: { available: false },
            connection: { method: 'sign_in' },
          },
        },
        {
          id: 'connector-broker',
          capabilities: {
            agentAccess: { available: true },
            connection: { method: 'provider_authorization' },
          },
        },
      ],
    })
  })

  it('[spec: account-center/provider-connections] reports active Provider connection capabilities', async () => {
    const deps = createTestDeps()
    const connector = connectorRecord()
    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([
      {
        ...resource(),
        connectorId: connector.id,
        availableToAgents: true,
      },
    ])
    vi.mocked(deps.externalResources.listProviderConnectionsByUser).mockResolvedValue([
      {
        id: 'provider-connection-1',
        connectorId: connector.id,
        ownerUserId: 'user-1',
        ownerOrganizationId: null,
        authenticationAccountId: 'account-1',
        externalSubject: 'provider-user-1',
        displayName: 'Provider User',
        status: 'active',
        createdAt: now,
        updatedAt: now,
        connector,
        resourceAuthorizationCount: 1,
        resourceNames: ['Projects'],
      },
      {
        id: 'provider-connection-2',
        connectorId: connector.id,
        ownerUserId: 'user-1',
        ownerOrganizationId: null,
        authenticationAccountId: null,
        externalSubject: 'provider-user-2',
        displayName: 'Unconfigured Provider User',
        status: 'active',
        createdAt: now,
        updatedAt: now,
        connector,
        resourceAuthorizationCount: 0,
        resourceNames: [],
      },
    ])

    await expect(listAccountProviderConnections(deps, 'user-1', { limit: 20, offset: 0 })).resolves.toMatchObject({
      items: [
        {
          capabilities: {
            signIn: { active: true },
            agentAccess: { active: true, authorizationCount: 1, resourceNames: ['Projects'] },
          },
        },
        {
          capabilities: {
            signIn: { active: false },
            agentAccess: { active: false, authorizationCount: 0, resourceNames: [] },
          },
        },
      ],
      pagination: { totalItems: 2 },
    })
  })

  it('enforces Provider Connection ownership, sign-in safety, and terminal revocation state', async () => {
    const deps = createTestDeps()
    await expect(disconnectProviderConnection(deps, 'missing', 'user-1')).rejects.toThrow('was not found')

    const provider = {
      id: 'provider-connection-1',
      connectorId: 'connector-1',
      ownerUserId: 'other-user',
      ownerOrganizationId: null,
      authenticationAccountId: 'account-provider',
      externalSubject: 'provider-user-1',
      displayName: 'Provider User',
      status: 'active' as const,
      createdAt: now,
      updatedAt: now,
    }
    vi.mocked(deps.externalResources.findProviderConnection).mockResolvedValue(provider)
    await expect(disconnectProviderConnection(deps, provider.id, 'user-1')).rejects.toThrow('was not found')

    provider.ownerUserId = 'user-1'
    vi.mocked(deps.users.listLinkedAccounts).mockResolvedValue({ items: [], total: 1, limit: 2, offset: 0 })
    await expect(disconnectProviderConnection(deps, provider.id, 'user-1')).rejects.toThrow(
      'Add another sign-in method',
    )

    vi.mocked(deps.users.listLinkedAccounts).mockResolvedValue({ items: [], total: 2, limit: 2, offset: 0 })
    const authorization: ProviderResourceAuthorizationRecord = {
      ...connectionRecord(),
      providerConnectionId: provider.id,
      ownerUserId: 'user-1',
    }
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([
      { ...authorization, id: 'revoked-authorization', status: 'revoked' },
      authorization,
    ])
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(authorization)
    vi.mocked(deps.externalResources.listActiveEntitlementsByConnection).mockResolvedValue([])
    vi.mocked(deps.externalResources.revokeConnection).mockResolvedValue(true)
    vi.mocked(deps.externalResources.revokeProviderConnection).mockResolvedValue(false)
    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    vi.mocked(deps.externalHttp.fetch).mockResolvedValue(new Response(null, { status: 200 }))
    await expect(disconnectProviderConnection(deps, provider.id, 'user-1')).rejects.toThrow('already disconnected')

    vi.mocked(deps.externalResources.revokeProviderConnection).mockResolvedValue(true)
    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    await expect(disconnectProviderConnection(deps, provider.id, 'user-1')).resolves.toBeUndefined()

    vi.mocked(deps.authorization.findResource).mockResolvedValue(null)
    await expect(disconnectProviderConnection(deps, provider.id, 'user-1')).rejects.toThrow(
      'Resource Server was not found',
    )

    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    vi.mocked(deps.connectors.findById).mockResolvedValue(null)
    await expect(disconnectProviderConnection(deps, provider.id, 'user-1')).rejects.toThrow(
      'Active external API resource authorization was not found',
    )

    vi.mocked(deps.externalResources.findProviderConnection).mockResolvedValue({
      ...provider,
      authenticationAccountId: null,
    })
    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([{ ...authorization, credentials: [] }])
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue({ ...authorization, credentials: [] })
    vi.mocked(deps.externalResources.revokeConnection).mockResolvedValue(true)
    vi.mocked(deps.externalResources.revokeProviderConnection).mockResolvedValue(true)
    await expect(disconnectProviderConnection(deps, provider.id, 'user-1')).resolves.toBeUndefined()
  })

  it('revokes Provider credentials with the configured client authentication and surfaces network failures', async () => {
    const deps = createTestDeps()
    const connection = {
      ...connectionRecord(),
      ownerUserId: 'user-1',
    }
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listActiveEntitlementsByConnection).mockResolvedValue([])
    vi.mocked(deps.externalResources.revokeConnection).mockResolvedValue(true)
    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerMetadata: {
          ...metadata(),
          token_endpoint_auth_methods_supported: ['client_secret_post'],
        },
      }),
    )
    const requests: Request[] = []
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      requests.push(request)
      return new Response(null, { status: 200 })
    })

    await expect(revokeResourceConnection(deps, connection.id, 'user-1')).resolves.toBeUndefined()
    expect(requests).toHaveLength(2)
    expect(requests[0]!.headers.get('authorization')).toBeNull()
    const form = new URLSearchParams(await requests[0]!.text())
    expect(form.get('client_id')).toBe('realmroot-client')
    expect(form.get('client_secret')).toBe('target-secret')

    vi.mocked(deps.externalHttp.fetch).mockRejectedValueOnce(new Error('offline'))
    await expect(revokeResourceConnection(deps, connection.id, 'user-1')).rejects.toThrow(
      'External authorization server revocation is unavailable.',
    )

    vi.mocked(deps.externalHttp.fetch).mockResolvedValueOnce(new Response(null, { status: 401 }))
    await expect(revokeResourceConnection(deps, connection.id, 'user-1')).rejects.toThrow(
      'External authorization server rejected the revocation request.',
    )
  })

  it('preserves a same-subject connection identity while switching only it to a new client generation', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const existing = connectionWithCredential(connectionRecord(), { clientGeneration: 1 })
    const intent: ResourceConnectionIntentRecord = {
      id: 'intent-generation-2',
      stateHash: 'state-hash',
      resourceId: 'resource-1',
      ownerUserId: 'user-1',
      ownerOrganizationId: null,
      initiatedByUserId: 'user-1',
      scopes: ['offline_access', 'openid', 'projects:read'],
      authorizationDetails: [],
      encryptedPkceVerifier: 'sealed:verifier',
      clientGeneration: 2,
      returnTo: 'account-center',
      status: 'completed',
      expiresAt: new Date(Date.now() + 60_000),
      completedAt: now,
      createdAt: now,
      updatedAt: now,
    }
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord({ resourceClientGeneration: 2 }))
    vi.mocked(deps.externalResources.consumeConnectionIntent).mockResolvedValue(intent)
    vi.mocked(deps.externalResources.findProviderConnectionByOwnerConnector).mockResolvedValue(
      providerConnectionFor(existing),
    )
    vi.mocked(deps.externalResources.findConnectionByProviderResource).mockResolvedValue(existing)
    const coveredGrant = grantRecord()
    const uncoveredGrant = { ...grantRecord(), id: 'grant-write', scope: 'projects:write' }
    vi.mocked(deps.externalResources.listActiveEntitlementsByConnection).mockResolvedValue([
      coveredGrant,
      uncoveredGrant,
    ])
    vi.mocked(deps.externalResources.endEntitlement).mockResolvedValue(true)
    vi.mocked(deps.externalResources.upsertProviderCredential).mockImplementation(async (id, input) =>
      connectionWithCredential({ ...existing, id }, input),
    )
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url.endsWith('/token')) {
        return Response.json({
          access_token: 'generation-2-access',
          refresh_token: 'generation-2-refresh',
          token_type: 'Bearer',
          scope: 'openid offline_access projects:read',
        })
      }
      if (request.url.endsWith('/userinfo')) {
        return Response.json({ sub: existing.externalSubject, name: existing.displayName })
      }
      return new Response(null, { status: 404 })
    })

    await expect(
      completeResourceConnectionIntent(deps, { state: 'state', code: 'code' }, 'https://auth.example.com'),
    ).resolves.toMatchObject({ id: existing.id, externalSubject: existing.externalSubject })
    expect(deps.externalResources.upsertProviderCredential).toHaveBeenCalledWith(
      existing.id,
      expect.objectContaining({ clientGeneration: 2 }),
    )
    expect(deps.externalResources.endEntitlement).not.toHaveBeenCalledWith(coveredGrant.id, 'revoked', expect.any(Date))
    expect(deps.externalResources.endEntitlement).toHaveBeenCalledWith(uncoveredGrant.id, 'revoked', expect.any(Date))
    expect(deps.externalResources.revokeConnection).not.toHaveBeenCalled()
  })

  it('[spec: agent-identity/external-resource-rich-authorization-connection] uses PAR and stores enriched authorization details', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const templates = [{ type: 'project_access', actions: ['read'] }]
    const granted = [
      { type: 'project_access', actions: ['read'], identifier: 'project-1' },
      { identifier: 'project-2', actions: ['read'], type: 'project_access' },
    ]
    vi.mocked(deps.authorization.findResource).mockResolvedValue({ ...resource(), authorizationDetails: templates })
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerMetadata: {
          ...metadata(),
          authorization_details_types_supported: ['project_access'],
          pushed_authorization_request_endpoint: 'https://projects.example.com/par',
          authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
          authorization_details_catalog_scope: 'authorization-details:read',
          authorization_details_catalog_version: 1,
        },
      }),
    )
    const openApiFetch = vi.mocked(deps.externalHttp.fetch).getMockImplementation()!
    let intent: ResourceConnectionIntentRecord | null = null
    let tokenAuthorizationDetails: unknown = granted
    vi.mocked(deps.externalResources.createConnectionIntent).mockImplementation(async (record) => {
      intent = record
      return record
    })
    vi.mocked(deps.externalResources.consumeConnectionIntent).mockImplementation(async () => intent)
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url === resource().resourceUrl || request.url === 'https://projects.example.com/openapi.json') {
        return openApiFetch(request)
      }
      if (request.url === 'https://projects.example.com/par') {
        const form = new URLSearchParams(await request.text())
        expect(request.method).toBe('POST')
        expect(request.headers.get('authorization')).toMatch(/^Basic /)
        expect(JSON.parse(form.get('authorization_details')!)).toEqual(templates)
        expect(form.get('prompt')).toBe('consent')
        expect(form.get('state')).toBeTruthy()
        return Response.json(
          { request_uri: 'urn:ietf:params:oauth:request_uri:rar-1', expires_in: 90 },
          { status: 201 },
        )
      }
      if (request.url.endsWith('/token')) {
        return Response.json({
          access_token: 'subject-access',
          refresh_token: 'subject-refresh',
          token_type: 'Bearer',
          scope: 'openid offline_access projects:read',
          authorization_details: tokenAuthorizationDetails,
        })
      }
      if (request.url.endsWith('/userinfo')) return Response.json({ sub: 'target-user-1', name: 'Project Owner' })
      return new Response(null, { status: 404 })
    })

    const started = await createResourceConnectionIntent(
      deps,
      'resource-1',
      { owner: { type: 'user' }, scopes: ['projects:read'] },
      'user-1',
      'https://auth.example.com',
    )
    const authorizationUrl = new URL(started.authorizationUrl)
    expect([...authorizationUrl.searchParams.keys()].sort()).toEqual(['client_id', 'request_uri'])
    expect(authorizationUrl.searchParams.get('request_uri')).toBe('urn:ietf:params:oauth:request_uri:rar-1')
    expect(new Date(started.expiresAt).getTime() - Date.now()).toBeGreaterThan(9 * 60 * 1000)
    expect(deps.externalResources.createConnectionIntent).toHaveBeenCalledWith(
      expect.objectContaining({ authorizationDetails: templates }),
    )

    await expect(
      completeResourceConnectionIntent(
        deps,
        { state: 'rar-state', code: 'authorization-code' },
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ authorizationDetails: granted })
    expect(deps.externalResources.createResourceAuthorization).toHaveBeenCalledWith(
      expect.objectContaining({
        credentials: [expect.objectContaining({ authorizationDetails: granted })],
      }),
    )

    tokenAuthorizationDetails = [{ type: 'unknown_context', identifier: 'project-1' }]
    await expect(
      completeResourceConnectionIntent(deps, { state: 'unknown-state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })
    tokenAuthorizationDetails = [{ identifier: 'missing-type' }]
    await expect(
      completeResourceConnectionIntent(deps, { state: 'malformed-state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    tokenAuthorizationDetails = []
    await expect(
      completeResourceConnectionIntent(deps, { state: 'empty-state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    tokenAuthorizationDetails = [granted[0], granted[0]]
    await expect(
      completeResourceConnectionIntent(deps, { state: 'duplicate-state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    tokenAuthorizationDetails = templates
    await expect(
      completeResourceConnectionIntent(deps, { state: 'template-state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    tokenAuthorizationDetails = [{ type: 'project_access', identifier: 'project-1', actions: ['write'] }]
    await expect(
      completeResourceConnectionIntent(deps, { state: 'wrong-action-state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    tokenAuthorizationDetails = granted
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        resourceProviderMetadata: {
          ...metadata(),
          token_endpoint_auth_methods_supported: ['client_secret_post'],
        },
      }),
    )
    await expect(
      completeResourceConnectionIntent(deps, { state: 'post-auth-state', code: 'code' }, 'https://auth.example.com'),
    ).resolves.toMatchObject({ authorizationDetails: granted })

    intent = {
      ...intent!,
      authorizationDetails: [...templates, { type: 'organization_access', actions: ['read'] }],
    }
    tokenAuthorizationDetails = [granted[0]]
    await expect(
      completeResourceConnectionIntent(deps, { state: 'partial-state', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })
  })

  it('[spec: agent-identity/external-resource-rar-without-catalog] sends RAR directly when PAR is not advertised', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const templates = [{ type: 'project_access', actions: ['read'] }]
    vi.mocked(deps.authorization.findResource).mockResolvedValue({ ...resource(), authorizationDetails: templates })
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerMetadata: {
          ...metadata(),
          authorization_details_types_supported: ['project_access'],
        },
      }),
    )
    vi.mocked(deps.externalResources.createConnectionIntent).mockImplementation(async (record) => record)

    const started = await createResourceConnectionIntent(
      deps,
      'resource-1',
      { owner: { type: 'user' }, scopes: ['projects:read'] },
      'user-1',
      'https://auth.example.com',
    )

    const authorizationUrl = new URL(started.authorizationUrl)
    expect(authorizationUrl.origin + authorizationUrl.pathname).toBe('https://projects.example.com/authorize')
    expect(JSON.parse(authorizationUrl.searchParams.get('authorization_details') ?? 'null')).toEqual(templates)
    expect(authorizationUrl.searchParams.get('request_uri')).toBeNull()
    expect(deps.externalHttp.fetch).not.toHaveBeenCalledWith(
      expect.objectContaining({ url: 'https://projects.example.com/par' }),
    )
  })

  it('rejects unsupported RAR types and preserves PAR OAuth errors', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const templates = [{ type: 'project_access', actions: ['read'] }]
    vi.mocked(deps.authorization.findResource).mockResolvedValue({ ...resource(), authorizationDetails: templates })

    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerMetadata: {
          ...metadata(),
          authorization_details_types_supported: [],
          pushed_authorization_request_endpoint: 'https://projects.example.com/par',
        },
      }),
    )
    await expect(
      createResourceConnectionIntent(
        deps,
        'resource-1',
        { owner: { type: 'user' }, scopes: ['projects:read'] },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerMetadata: {
          ...metadata(),
          authorization_details_types_supported: ['project_access'],
          pushed_authorization_request_endpoint: 'https://projects.example.com/par',
          authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
          authorization_details_catalog_scope: 'authorization-details:read',
          authorization_details_catalog_version: 1,
        },
      }),
    )
    const openApiFetch = vi.mocked(deps.externalHttp.fetch).getMockImplementation()!
    let parFailure = () =>
      Response.json(
        { error: 'invalid_authorization_details', error_description: 'Unknown project context.' },
        { status: 400 },
      )
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url === resource().resourceUrl || request.url === 'https://projects.example.com/openapi.json') {
        return openApiFetch(request)
      }
      return parFailure()
    })
    await expect(
      createResourceConnectionIntent(
        deps,
        'resource-1',
        { owner: { type: 'user' }, scopes: ['projects:read'] },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toMatchObject({
      error: 'invalid_authorization_details',
      errorDescription: 'Unknown project context.',
    })
    parFailure = () => new Response('not json', { status: 302 })
    await expect(
      createResourceConnectionIntent(
        deps,
        'resource-1',
        { owner: { type: 'user' }, scopes: ['projects:read'] },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toMatchObject({
      status: 400,
      error: 'invalid_request',
      errorDescription: 'External authorization server rejected the pushed authorization request.',
    })
  })

  it(`reauthorizes the same external account without replacing its connection identity
      [spec: agent-identity/resource-account-reauthorization]
      [spec: account-center/provider-identity-ownership]`, async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const intent: ResourceConnectionIntentRecord = {
      id: 'replacement-intent',
      stateHash: 'state-hash',
      resourceId: 'resource-1',
      ownerUserId: 'user-1',
      ownerOrganizationId: null,
      initiatedByUserId: 'user-1',
      scopes: ['offline_access', 'openid', 'projects:read', 'projects:write'],
      authorizationDetails: [],
      encryptedPkceVerifier: 'sealed:pkce-verifier',
      returnTo: 'access-approval',
      status: 'completed',
      expiresAt: new Date(Date.now() + 300_000),
      completedAt: new Date(),
      createdAt: now,
      updatedAt: now,
    }
    const existing = {
      ...connectionRecord(),
      status: 'revoked',
      revokedAt: now,
    }
    vi.mocked(deps.externalResources.consumeConnectionIntent).mockResolvedValue(intent)
    vi.mocked(deps.externalResources.findProviderConnectionByOwnerConnector).mockResolvedValue(
      providerConnectionFor(existing),
    )
    vi.mocked(deps.externalResources.findConnectionByProviderResource).mockResolvedValue(existing)
    vi.mocked(deps.externalResources.upsertProviderCredential).mockImplementation(async (id, input) =>
      connectionWithCredential({ ...existing, id }, input),
    )
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url.endsWith('/token')) {
        return Response.json({
          access_token: 'replacement-access',
          refresh_token: 'replacement-refresh',
          token_type: 'Bearer',
          expires_in: 600,
          scope: 'openid offline_access projects:read projects:write',
        })
      }
      if (request.url.endsWith('/userinfo')) {
        return Response.json({ sub: 'target-user-1', name: 'Renamed Project Owner' })
      }
      return new Response(null, { status: 404 })
    })

    vi.mocked(deps.externalResources.findActiveUserProviderConnectionByProviderSubject).mockResolvedValue({
      ...providerConnectionFor(existing),
      id: 'other-account-provider-connection',
      ownerUserId: 'other-user',
    })
    await expect(
      completeResourceConnectionIntent(
        deps,
        { state: 'replacement-state', code: 'replacement-code' },
        'https://auth.example.com',
      ),
    ).rejects.toThrow('already connected to another Realmroot account')
    vi.mocked(deps.externalResources.findActiveUserProviderConnectionByProviderSubject).mockResolvedValue(null)

    await expect(
      completeResourceConnectionIntent(
        deps,
        { state: 'replacement-state', code: 'replacement-code' },
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      id: 'connection-1',
      displayName: 'Project Owner',
      grantedScopes: ['offline_access', 'openid', 'projects:read', 'projects:write'],
      status: 'active',
      returnTo: 'access-approval',
    })
    expect(deps.externalResources.findConnectionByProviderResource).toHaveBeenCalledWith({
      providerConnectionId: existing.providerConnectionId,
      resourceId: 'resource-1',
    })
    expect(deps.externalResources.upsertProviderConnection).toHaveBeenCalledWith(
      expect.objectContaining({
        id: existing.providerConnectionId,
        externalSubject: 'target-user-1',
        displayName: 'Renamed Project Owner',
        status: 'active',
      }),
    )
    expect(deps.externalResources.upsertProviderCredential).toHaveBeenCalledWith(
      'connection-1',
      expect.objectContaining({
        encryptedTokens: expect.stringContaining('replacement-refresh'),
        grantedScopes: ['offline_access', 'openid', 'projects:read', 'projects:write'],
        status: 'active',
        revokedAt: null,
      }),
    )
    expect(deps.secrets.seal).toHaveBeenCalledWith(
      expect.stringContaining('replacement-refresh'),
      'provider-credential:credential-1:tokens',
    )
    expect(deps.externalResources.createResourceAuthorization).not.toHaveBeenCalled()
  })

  it('[spec: agent-identity/external-resource-rich-authorization-reauthorization] revokes grants no longer covered after reauthorization', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const template = [{ type: 'project_access', actions: ['read'] }]
    const retained = [{ type: 'project_access', identifier: 'project-1', actions: ['read'] }]
    const returnedExtra = [{ type: 'project_access', identifier: 'project-2', actions: ['read'] }]
    const removed = [{ type: 'project_access', identifier: 'project-3', actions: ['read'] }]
    vi.mocked(deps.authorization.findResource).mockResolvedValue({ ...resource(), authorizationDetails: template })
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerMetadata: {
          ...metadata(),
          authorization_details_types_supported: ['project_access'],
          pushed_authorization_request_endpoint: 'https://projects.example.com/par',
        },
      }),
    )
    const intent: ResourceConnectionIntentRecord = {
      id: 'reauthorization-intent',
      stateHash: 'state-hash',
      resourceId: 'resource-1',
      ownerUserId: null,
      ownerOrganizationId: 'org-1',
      initiatedByUserId: 'user-1',
      scopes: ['offline_access', 'openid', 'projects:read'],
      authorizationDetails: retained,
      encryptedPkceVerifier: 'sealed:pkce-verifier',
      returnTo: 'account-center',
      status: 'completed',
      expiresAt: new Date(Date.now() + 300_000),
      completedAt: new Date(),
      createdAt: now,
      updatedAt: now,
    }
    const existing = {
      ...connectionRecord(),
      ownerUserId: null,
      ownerOrganizationId: 'org-1',
      authorizationDetails: [...retained, ...returnedExtra, ...removed],
    }
    const staleGrant = { ...grantRecord(), authorizationDetails: removed }
    const returnedExtraGrant = { ...grantRecord(), id: 'returned-extra-grant', authorizationDetails: returnedExtra }
    const staleScopeGrant = { ...grantRecord(), id: 'stale-scope-grant', scopes: ['projects:write'] }
    const missingContextGrant = { ...grantRecord(), id: 'missing-context-grant', authorizationDetails: [] }
    const retainedGrant = { ...grantRecord(), id: 'retained-grant', authorizationDetails: retained }
    vi.mocked(deps.externalResources.consumeConnectionIntent).mockResolvedValue(intent)
    vi.mocked(deps.externalResources.findProviderConnectionByOwnerConnector).mockResolvedValue(
      providerConnectionFor(existing),
    )
    vi.mocked(deps.externalResources.findConnectionByProviderResource).mockResolvedValue(existing)
    vi.mocked(deps.externalResources.upsertProviderCredential).mockImplementation(async (id, input) =>
      connectionWithCredential({ ...existing, id }, input),
    )
    vi.mocked(deps.externalResources.listActiveEntitlementsByConnection).mockResolvedValue([
      retainedGrant,
      returnedExtraGrant,
      staleGrant,
      staleScopeGrant,
      missingContextGrant,
    ])
    vi.mocked(deps.externalResources.listActiveTokenLeasesByEntitlement).mockResolvedValue([])
    vi.mocked(deps.externalResources.endEntitlement).mockResolvedValue(true)
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url.endsWith('/token')) {
        return Response.json({
          access_token: 'replacement-access',
          refresh_token: 'replacement-refresh',
          token_type: 'Bearer',
          scope: 'openid offline_access projects:read',
          authorization_details: [...retained, ...returnedExtra],
        })
      }
      if (request.url.endsWith('/userinfo')) return Response.json({ sub: 'target-user-1' })
      return new Response(null, { status: 404 })
    })

    await completeResourceConnectionIntent(
      deps,
      { state: 'reauthorization-state', code: 'authorization-code' },
      'https://auth.example.com',
    )
    expect(deps.externalResources.endEntitlement).toHaveBeenCalledWith(staleGrant.id, 'revoked', expect.any(Date))
    expect(deps.externalResources.endEntitlement).toHaveBeenCalledWith(staleScopeGrant.id, 'revoked', expect.any(Date))
    expect(deps.externalResources.endEntitlement).toHaveBeenCalledWith(
      missingContextGrant.id,
      'revoked',
      expect.any(Date),
    )
    expect(deps.externalResources.endEntitlement).not.toHaveBeenCalledWith(
      retainedGrant.id,
      'revoked',
      expect.any(Date),
    )
    expect(deps.externalResources.endEntitlement).not.toHaveBeenCalledWith(
      returnedExtraGrant.id,
      'revoked',
      expect.any(Date),
    )
    expect(deps.externalResources.upsertProviderCredential).toHaveBeenCalledWith(
      existing.id,
      expect.objectContaining({ authorizationDetails: [...retained, ...returnedExtra] }),
    )
    expect(deps.agentAudit.append).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'api_resource.access_revoked',
        ownerUserId: null,
        ownerOrganizationId: 'org-1',
        reasonCode: 'connection_authorization_changed',
        metadata: { authorizationDetails: [{ type: 'project_access', identifier: 'project-3' }] },
      }),
    )
  })

  it('creates the first managed Provider Connection for an external account', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.externalResources.consumeConnectionIntent).mockResolvedValue({
      id: 'replacement-intent',
      stateHash: 'state-hash',
      resourceId: 'resource-1',
      ownerUserId: 'user-1',
      ownerOrganizationId: null,
      initiatedByUserId: 'user-1',
      scopes: ['offline_access', 'openid', 'projects:read'],
      authorizationDetails: [],
      encryptedPkceVerifier: 'sealed:pkce-verifier',
      returnTo: 'access-approval',
      status: 'completed',
      expiresAt: new Date(Date.now() + 300_000),
      completedAt: new Date(),
      createdAt: now,
      updatedAt: now,
    })
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url.endsWith('/token')) {
        return Response.json({
          access_token: 'another-access',
          refresh_token: 'another-refresh',
          token_type: 'Bearer',
          scope: 'openid offline_access projects:read',
        })
      }
      if (request.url.endsWith('/userinfo')) {
        return Response.json({ sub: 'another-target-user', name: 'Another Project Owner' })
      }
      return new Response(null, { status: 404 })
    })

    await expect(
      completeResourceConnectionIntent(
        deps,
        { state: 'replacement-state', code: 'replacement-code' },
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      id: 'replacement-intent',
      externalSubject: 'another-target-user',
      displayName: 'Another Project Owner',
    })
    expect(deps.externalResources.upsertProviderCredential).not.toHaveBeenCalled()
    expect(deps.externalResources.createResourceAuthorization).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'replacement-intent', providerConnectionId: expect.any(String) }),
    )
  })

  it(`creates one access approval before connection and continues OAuth through it
      [spec: agent-identity/external-resource-first-access]`, async () => {
    const deps = authorizationCatalogDeps({
      providerMetadata: {
        ...metadata(),
        pushed_authorization_request_endpoint: 'https://projects.example.com/par',
        authorization_details_types_supported: ['project_access'],
        authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
        authorization_details_catalog_scope: 'authorization-details:read',
        authorization_details_catalog_version: 1,
      },
    })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(null)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])

    const access = await createAgentAccessRequest(
      deps,
      { resourceId: 'resource-1', scopes: ['projects:read'], reason: 'Read one project' },
      principal(),
      'https://auth.example.com',
    )

    expect(access).toMatchObject({
      connectionId: null,
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
      status: 'pending',
    })
    expect(access.approvalUrl).toContain('/agent/access#token=')
    const stored = vi.mocked(deps.externalResources.createAccessRequestWithAudit).mock.calls[0]![0]
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(stored)
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(stored)
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).resolves.toMatchObject({
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
      authorizationDetail: null,
      requiresAccountConnection: true,
    })
    vi.mocked(deps.externalHttp.fetch).mockResolvedValue(
      Response.json(
        { request_uri: 'urn:ietf:params:oauth:request_uri:first-access', expires_in: 300 },
        { status: 201 },
      ),
    )
    await expect(
      createAccountConnection(
        deps,
        { context: 'access-request', accessRequestId: stored.id, approvalToken: 'approval-token' },
        'user-1',
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ status: 'pending_authorization', scopes: ['projects:read'] })
    expect(deps.externalResources.createConnectionIntent).toHaveBeenCalledWith(
      expect.objectContaining({ returnTo: 'access-approval' }),
    )

    const selectedAuthorizationDetails = [{ type: 'project_access', identifier: 'project-1', actions: ['read'] }]
    const connected = {
      ...connectionRecord(),
      grantedScopes: [...connectionRecord().grantedScopes, 'authorization-details:read'],
      authorizationDetails: selectedAuthorizationDetails,
    }
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connected)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connected)
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connected])
    vi.mocked(deps.externalResources.decideAccessRequest).mockImplementation(async (_id, decision) => ({
      ...stored,
      ...decision,
    }))
    vi.mocked(deps.externalHttp.fetch).mockResolvedValue(
      Response.json({
        items: [
          {
            authorizationDetail: selectedAuthorizationDetails[0],
            grantedScopes: ['projects:read'],
            display: { label: 'Project One' },
          },
        ],
        pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 1, totalPages: Math.ceil(1 / 100) },
      }),
    )

    await expect(
      decideAgentAccessRequest(
        deps,
        stored.id,
        {
          decision: 'approve',
          mode: 'persistent',
          authorizationDetails: selectedAuthorizationDetails,
        },
        'user-1',
      ),
    ).resolves.toMatchObject({
      status: 'approved',
      connectionId: connected.id,
      authorizationDetails: selectedAuthorizationDetails,
    })
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenCalledWith(
      expect.any(Array),
      expect.any(Array),
      stored.id,
      expect.objectContaining({
        connectionId: connected.id,
        authorizationDetails: selectedAuthorizationDetails,
      }),
      expect.anything(),
    )
  })

  it('keeps a generic Context requirement when an account is already connected', async () => {
    const deps = authorizationCatalogDeps()
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connectionRecord()])
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])

    await expect(
      createAgentAccessRequest(
        deps,
        { resourceId: 'resource-1', scopes: ['projects:read'], reason: 'Read one project' },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      connectionId: 'connection-1',
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
      status: 'pending',
    })
  })

  it('discovers stored connections without contacting the Provider [spec: agent-identity/agent-resource-discovery]', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    const expiredConnection = {
      ...connectionRecord(),
      credentialExpiresAt: new Date(Date.now() - 60_000),
    }
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([expiredConnection])
    vi.mocked(deps.externalHttp.fetch).mockReturnValue(new Promise<Response>(() => {}))

    await expect(discoverAgentResources(deps, principal())).resolves.toMatchObject({
      items: [{ connection: { status: 'connected' } }],
    })
    expect(deps.authorization.findResource).not.toHaveBeenCalled()
    expect(deps.connectors.findById).not.toHaveBeenCalled()
    expect(deps.connectors.listEnabled).toHaveBeenCalledOnce()
    expect(deps.externalHttp.fetch).not.toHaveBeenCalled()
    expect(deps.externalResources.revokeConnection).not.toHaveBeenCalled()
  })

  it('[spec: agent-identity/resource-account-connection-expansion] preserves active account authority while connection expansion awaits OAuth', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const existingConnection = {
      ...connectionRecord(),
      grantedScopes: ['openid', 'offline_access', 'workspaces:discover', 'projects:read'],
      authorizationDetails: [
        { type: 'project_access', identifier: 'project-1', actions: ['read'] },
        { type: 'project_access', identifier: 'project-2', actions: ['read'] },
      ],
    }
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerMetadata: {
          ...metadata(),
          authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
          authorization_details_catalog_scope: 'workspaces:discover',
          authorization_details_types_supported: ['project_access'],
        },
      }),
    )
    mockResourceOpenApi(deps, resource().resourceUrl, ['projects:read', 'projects:write'])
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(existingConnection)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(existingConnection)
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([existingConnection])
    vi.mocked(deps.externalResources.createConnectionIntent).mockImplementation(async (record) => record)

    await createAgentAccessRequest(
      deps,
      {
        resourceId: 'resource-1',
        scopes: ['projects:write'],
        reason: 'Update projects',
      },
      principal(),
      'https://auth.example.com',
    )
    const request = vi.mocked(deps.externalResources.createAccessRequestWithAudit).mock.calls[0]![0]
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)

    await expect(
      createAccountConnection(
        deps,
        { context: 'access-request', accessRequestId: request.id, approvalToken: 'approval-token' },
        'user-1',
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      scopes: ['projects:read', 'projects:write'],
      status: 'pending_authorization',
    })
    expect(deps.externalResources.createConnectionIntent).toHaveBeenCalledWith(
      expect.objectContaining({
        scopes: ['offline_access', 'openid', 'projects:read', 'projects:write', 'workspaces:discover'],
      }),
    )

    expect(deps.externalResources.upsertProviderCredential).not.toHaveBeenCalled()
    expect(deps.externalResources.endEntitlement).not.toHaveBeenCalled()
  })

  it('reuses only an exactly matching pending native access request', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const native = nativeResource()
    vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({
      id: 'org-1',
      name: 'Organization',
      disabled: false,
    } as never)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    mockResourceOpenApi(deps, native.resourceUrl, ['projects:read'])
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])
    const matching = {
      ...requestRecord(),
      id: 'matching-request',
      connectionId: null,
      scopes: ['projects:read'],
      authorizationDetails: [organizationAuthority],
    }
    vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([
      { ...matching, id: 'wrong-resource', resourceId: 'resource-2' },
      { ...matching, id: 'wrong-connection', connectionId: 'connection-2' },
      { ...matching, id: 'wrong-scopes', scopes: ['projects:write'] },
      { ...matching, id: 'wrong-details', authorizationDetails: [{ type: 'workspace', identifier: 'workspace-1' }] },
      matching,
    ])
    vi.mocked(deps.secrets.open).mockResolvedValue('pending-approval-token')

    await expect(
      createAgentAccessRequest(
        deps,
        { resourceId: native.id, scopes: ['projects:read'], authorizationDetails: [organizationAuthority] },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ id: matching.id, status: 'pending' })
    expect(deps.externalResources.createAccessRequest).not.toHaveBeenCalled()

    vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([])
    vi.mocked(deps.externalResources.createAccessRequest).mockResolvedValue(null)
    await expect(
      createAgentAccessRequest(
        deps,
        { resourceId: native.id, scopes: ['projects:read'], authorizationDetails: [organizationAuthority] },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Enabled Resource Server is required.')
  })

  it('lets the account controller approve an exact request once [spec: agent-identity/agent-resource-approval]', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const request = requestRecord()
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.approveAccessRequestWithEntitlements).mockImplementation(
      async (records, _updates, id, decision) => ({
        entitlements: records,
        request: { ...requestRecord(), id, ...decision },
      }),
    )
    vi.mocked(deps.externalResources.decideAccessRequest).mockImplementation(async (_id, decision) => ({
      ...request,
      ...decision,
    }))
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())

    const decided = await decideAgentAccessRequestByToken(
      deps,
      'approval-token',
      { decision: 'approve', mode: 'once' },
      'user-1',
    )
    expect(decided).toMatchObject({ status: 'approved', hostId: 'host-1', scopes: ['projects:read'] })
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenCalledWith(
      [
        expect.objectContaining({
          connectionId: 'connection-1',
          mode: 'once',
          scope: 'projects:read',
          grantedByUserId: 'user-1',
          grantedByAgentIdentityId: null,
        }),
      ],
      [],
      'request-1',
      expect.objectContaining({ status: 'approved' }),
      expect.objectContaining({ accessRequestId: 'request-1' }),
    )
    const mismatchedIdentity = identityAggregate()
    mismatchedIdentity.identity.ownerUserId = 'user-2'
    vi.mocked(deps.authorization.findMemberByOrganizationUser).mockResolvedValue({
      id: 'member-1',
      organizationId: 'org-1',
      userId: 'user-1',
      roles: ['admin'],
      title: null,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
    })
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue({
      ...connectionRecord(),
      ownerUserId: 'user-1',
    })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(mismatchedIdentity)
    await expect(
      decideAgentAccessRequestByToken(deps, 'approval-token', { decision: 'approve', mode: 'once' }, 'user-1'),
    ).rejects.toThrow('Resource account connection is outside the Agent home space.')

    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.approveAccessRequestWithEntitlements).mockResolvedValueOnce('resource_unavailable')
    await expect(
      decideAgentAccessRequestByToken(deps, 'approval-token', { decision: 'approve', mode: 'once' }, 'user-1'),
    ).rejects.toThrow('deleted before access could be approved')
  })

  it('[spec: agent-identity/external-resource-contextual-delegation] requests and approves exact granted detail sets', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const selected = [{ type: 'project_access', identifier: 'project-1', actions: ['read'] }]
    const connection = {
      ...connectionRecord(),
      authorizationDetails: [selected[0]!, { type: 'project_access', identifier: 'project-2', actions: ['read'] }],
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue({
      ...resource(),
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
    })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connection])
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])
    vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([])
    vi.mocked(deps.externalResources.createAccessRequest).mockImplementation(async (record) => record)

    const created = await createAgentAccessRequest(
      deps,
      {
        resourceId: 'resource-1',
        scopes: ['projects:read'],
        authorizationDetails: [{ actions: ['read'], identifier: 'project-1', type: 'project_access' }],
      },
      principal(),
      'https://auth.example.com',
    )
    expect(created.authorizationDetails).toEqual(selected)
    expect(deps.agentAudit.append).toHaveBeenCalledWith(
      expect.objectContaining({
        metadata: { authorizationDetails: [{ type: 'project_access', identifier: 'project-1' }] },
      }),
    )

    vi.mocked(deps.authorization.findResource).mockResolvedValue({
      ...resource(),
      authorizationModel: 'native',
      connectorId: null,
    })
    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: selected,
        },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: selected,
        },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    vi.mocked(deps.authorization.findResource).mockResolvedValue({
      ...resource(),
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
    })
    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: [],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      status: 'pending',
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
    })

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      status: 'pending',
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
    })

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: connection.authorizationDetails,
        },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ authorizationDetails: connection.authorizationDetails })

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: [selected[0]!, selected[0]!],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: [{ type: 'unknown_context', identifier: 'project-3' }],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    const connectionWithoutDetails = {
      ...connection,
      authorizationDetails: [],
    }
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionWithoutDetails)
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connectionWithoutDetails])
    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: selected,
        },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connection])

    const request = { ...requestRecord(), authorizationDetails: selected }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    vi.mocked(deps.externalResources.approveAccessRequestWithEntitlements).mockImplementation(
      async (records, _updates, id, decision) => ({
        entitlements: records,
        request: { ...requestRecord(), id, ...decision },
      }),
    )
    vi.mocked(deps.externalResources.decideAccessRequest).mockImplementation(async (_id, decision) => ({
      ...request,
      ...decision,
    }))
    const outOfBounds = [{ type: 'project_access', identifier: 'project-3', actions: ['read'] }]
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...request,
      authorizationDetails: outOfBounds,
    })
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        { decision: 'approve', mode: 'persistent', authorizationDetails: outOfBounds },
        'user-1',
      ),
    ).rejects.toThrow('exceed the connected account boundary')
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        {
          decision: 'approve',
          mode: 'persistent',
          authorizationDetails: [{ type: 'project_access', identifier: 'project-2', actions: ['read'] }],
        },
        'user-1',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        {
          decision: 'approve',
          mode: 'persistent',
          authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
        },
        'user-1',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        { decision: 'approve', mode: 'persistent', authorizationDetails: [selected[0]!, selected[0]!] },
        'user-1',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        { decision: 'approve', mode: 'persistent', authorizationDetails: [] },
        'user-1',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })
    await decideAgentAccessRequest(
      deps,
      request.id,
      { decision: 'approve', mode: 'persistent', authorizationDetails: selected },
      'user-1',
    )
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenCalledWith(
      [expect.objectContaining({ authorizationDetails: selected })],
      [],
      request.id,
      expect.objectContaining({ status: 'approved' }),
      expect.any(Object),
    )

    const contextHash = 'FsIE5gcoLMmZV2zpHjBDgpSCXVVV1BmKB-gtZ5AddwA'
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      {
        ...grantRecord(),
        authorizationDetails: selected,
        authorizationContextHash: contextHash,
        mode: 'until',
        expiresAt: new Date('2098-01-01T00:00:00.000Z'),
      },
    ])
    await decideAgentAccessRequest(
      deps,
      request.id,
      {
        decision: 'approve',
        mode: 'until',
        expiresAt: '2099-01-01T00:00:00.000Z',
        authorizationDetails: selected,
      },
      'user-1',
    )
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenLastCalledWith(
      [],
      [expect.objectContaining({ id: 'ent_1', mode: 'until', expiresAt: new Date('2099-01-01T00:00:00.000Z') })],
      request.id,
      expect.objectContaining({ status: 'approved' }),
      expect.any(Object),
    )

    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      {
        ...grantRecord(),
        authorizationDetails: selected,
        authorizationContextHash: contextHash,
        mode: 'until',
        expiresAt: new Date('2099-01-01T00:00:00.000Z'),
      },
    ])
    await decideAgentAccessRequest(
      deps,
      request.id,
      {
        decision: 'approve',
        mode: 'until',
        expiresAt: '2098-01-01T00:00:00.000Z',
        authorizationDetails: selected,
      },
      'user-1',
    )
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenLastCalledWith(
      [],
      [],
      request.id,
      expect.objectContaining({ status: 'approved' }),
      expect.any(Object),
    )

    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      {
        ...grantRecord(),
        authorizationDetails: selected,
        authorizationContextHash: contextHash,
        mode: 'until',
        expiresAt: null,
      },
    ])
    await decideAgentAccessRequest(
      deps,
      request.id,
      {
        decision: 'approve',
        mode: 'until',
        expiresAt: '2099-01-01T00:00:00.000Z',
        authorizationDetails: selected,
      },
      'user-1',
    )
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenLastCalledWith(
      [],
      [expect.objectContaining({ id: 'ent_1', mode: 'until', expiresAt: new Date('2099-01-01T00:00:00.000Z') })],
      request.id,
      expect.objectContaining({ status: 'approved' }),
      expect.any(Object),
    )

    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      {
        ...grantRecord(),
        authorizationDetails: selected,
        authorizationContextHash: contextHash,
        mode: 'once',
      },
    ])
    await decideAgentAccessRequest(
      deps,
      request.id,
      { decision: 'approve', mode: 'persistent', authorizationDetails: selected },
      'user-1',
    )
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenLastCalledWith(
      [],
      [expect.objectContaining({ id: 'ent_1', mode: 'persistent', expiresAt: null })],
      request.id,
      expect.objectContaining({ status: 'approved' }),
      expect.any(Object),
    )

    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      {
        ...grantRecord(),
        authorizationDetails: selected,
        authorizationContextHash: 'stale-context',
        mode: 'persistent',
      },
    ])
    await decideAgentAccessRequest(
      deps,
      request.id,
      { decision: 'approve', mode: 'once', authorizationDetails: selected },
      'user-1',
    )
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenLastCalledWith(
      [],
      [expect.objectContaining({ id: 'ent_1', mode: 'persistent', expiresAt: null })],
      request.id,
      expect.objectContaining({ status: 'approved' }),
      expect.any(Object),
    )

    const multiDetailRequest = { ...request, authorizationDetails: connection.authorizationDetails }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(multiDetailRequest)
    await decideAgentAccessRequest(
      deps,
      multiDetailRequest.id,
      {
        decision: 'approve',
        mode: 'persistent',
        authorizationDetails: connection.authorizationDetails,
      },
      'user-1',
    )
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenLastCalledWith(
      [expect.objectContaining({ authorizationDetails: connection.authorizationDetails })],
      [],
      multiDetailRequest.id,
      expect.objectContaining({ status: 'approved' }),
      expect.any(Object),
    )

    const genericRequest = {
      ...request,
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
    }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(genericRequest)
    await expect(
      decideAgentAccessRequest(
        deps,
        genericRequest.id,
        {
          decision: 'approve',
          mode: 'persistent',
          authorizationDetails: connection.authorizationDetails,
        },
        'user-1',
      ),
    ).rejects.toMatchObject({ error: 'invalid_authorization_details' })
    await expect(
      decideAgentAccessRequest(
        deps,
        genericRequest.id,
        {
          decision: 'approve',
          mode: 'persistent',
          authorizationDetails: [connection.authorizationDetails[0]!],
        },
        'user-1',
      ),
    ).resolves.toMatchObject({
      status: 'approved',
      authorizationDetails: [connection.authorizationDetails[0]],
    })

    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        { decision: 'approve', mode: 'persistent', authorizationDetails: selected },
        'user-1',
      ),
    ).rejects.toThrow('This external API resource does not use authorization details.')

    vi.mocked(deps.authorization.findResource).mockResolvedValue({
      ...resource(),
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
    })
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue({ ...connection, authorizationDetails: [] })
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        { decision: 'approve', mode: 'persistent', authorizationDetails: selected },
        'user-1',
      ),
    ).rejects.toThrow('The resource account must be explicitly reauthorized for authorization details.')

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({ ...request, authorizationDetails: [] })
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        { decision: 'approve', mode: 'persistent', authorizationDetails: [] },
        'user-1',
      ),
    ).rejects.toThrow('Select at least one concrete authorization detail entry.')

    vi.mocked(deps.authorization.findResource).mockResolvedValue(nativeResource())
    mockResourceOpenApi(deps, nativeResource().resourceUrl)
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...request,
      connectionId: null,
      authorizationDetails: selected,
    })
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        { decision: 'approve', mode: 'persistent', authorizationDetails: selected },
        'user-1',
      ),
    ).rejects.toThrow('Select exactly one Realmroot authority Context.')
  })

  it(`[spec: agent-identity/external-resource-contextual-delegation]
      [spec: agent-identity/external-resource-authorization-detail-catalog] lists every account detail with connection and Agent grant state`, async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const template = { type: 'project_access', actions: ['read'] }
    const connectedDetail = { ...template, identifier: 'project-1' }
    const availableDetail = { ...template, identifier: 'project-2' }
    vi.mocked(deps.authorization.findResource).mockResolvedValue({
      ...resource(),
      authorizationDetails: [template],
    })
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerMetadata: {
          ...metadata(),
          authorization_details_types_supported: ['project_access'],
          pushed_authorization_request_endpoint: 'https://projects.example.com/par',
          authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
          authorization_details_catalog_scope: 'authorization-details:read',
          authorization_details_catalog_version: 1,
        },
      }),
    )
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue({
      ...connectionRecord(),
      grantedScopes: [
        ...connectionRecord().grantedScopes,
        'projects:write',
        'projects:create',
        'authorization-details:read',
      ],
      authorizationDetails: [connectedDetail],
    })
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grantRecord(), authorizationDetails: [connectedDetail], scope: 'projects:read' },
      {
        ...grantRecord(),
        id: 'grant-future',
        authorizationDetails: [connectedDetail],
        scope: 'projects:write',
        expiresAt: new Date(Date.now() + 60_000),
      },
      {
        ...grantRecord(),
        id: 'grant-expired',
        authorizationDetails: [connectedDetail],
        expiresAt: new Date(Date.now() - 60_000),
      },
      {
        ...grantRecord(),
        id: 'grant-incompatible',
        authorizationDetails: [connectedDetail],
      },
    ])
    vi.mocked(deps.externalResources.findAccessRequest).mockImplementation(async (entitlementId) => ({
      ...requestRecord(),
      id: `request-${entitlementId}`,
      authorizationDetails: entitlementId === 'grant-incompatible' ? [] : [connectedDetail],
    }))
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (fetchRequest) => {
      if (fetchRequest.url === resource().resourceUrl) {
        return new Response(null, { headers: { link: '</openapi.json>; rel="service-desc"' } })
      }
      if (fetchRequest.url === 'https://projects.example.com/openapi.json') {
        return Response.json({
          openapi: '3.1.0',
          components: {
            securitySchemes: {
              oauth: {
                type: 'oauth2',
                flows: {
                  authorizationCode: {
                    authorizationUrl: 'https://projects.example.com/authorize',
                    tokenUrl: 'https://projects.example.com/token',
                    scopes: {
                      'projects:read': 'Read projects',
                      'projects:write': 'Write projects',
                      'projects:create': 'Create projects',
                    },
                  },
                },
              },
            },
          },
          paths: {
            '/projects': {
              get: {
                security: [{ oauth: ['projects:read', 'projects:write', 'projects:create'] }],
                responses: {},
              },
            },
          },
        })
      }
      expect(fetchRequest.url).toBe('https://projects.example.com/authorization-details?page=1&pageSize=100')
      expect(fetchRequest.headers.get('authorization')).toBe('Bearer subject')
      return Response.json({
        items: [
          {
            id: 'project-1',
            authorizationDetail: connectedDetail,
            display: { label: 'Project One' },
            grantedScopes: ['projects:read', 'projects:create'],
          },
          {
            id: 'project-2',
            authorizationDetail: availableDetail,
            display: { label: 'Project Two', metadata: { region: 'ca-central-1' } },
          },
        ],
        pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 2, totalPages: Math.ceil(2 / 100) },
      })
    })

    await expect(
      listAgentAuthorizationDetailCatalog(deps, 'resource-1', principal(), { limit: 100, offset: 0 }),
    ).resolves.toEqual({
      items: [
        {
          id: 'project-1',
          authorizationDetail: connectedDetail,
          name: 'Project One',
          description: null,
          metadata: {},
          accountAuthorizationStatus: 'authorized',
          authorizedScopes: ['projects:read'],
          requestableScopes: ['projects:create'],
        },
        {
          id: 'project-2',
          authorizationDetail: availableDetail,
          name: 'Project Two',
          description: null,
          metadata: { region: 'ca-central-1' },
          accountAuthorizationStatus: 'authorization_required',
          authorizedScopes: [],
          requestableScopes: [],
        },
      ],
      pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 2, totalPages: Math.ceil(2 / 100) },
    })
  })

  it('rejects unavailable, unauthorized, and invalid authorization detail catalogs', async () => {
    await expect(
      listAgentAuthorizationDetailCatalog(
        authorizationCatalogDeps({ providerMetadata: metadata() }),
        'resource-1',
        principal(),
        { limit: 100, offset: 0 },
      ),
    ).resolves.toMatchObject({ items: [], pagination: { totalItems: 0 } })

    await expect(
      listAgentAuthorizationDetailCatalog(
        authorizationCatalogDeps({ grantedScopes: connectionRecord().grantedScopes }),
        'resource-1',
        principal(),
        { limit: 100, offset: 0 },
      ),
    ).rejects.toThrow('Resource account must be reauthorized for the authorization detail catalog scope.')

    for (const [response, message] of [
      [new Response(null, { status: 502 }), 'Authorization detail catalog request failed.'],
      [new Response('not-json'), 'Authorization detail catalog response is invalid.'],
      [
        Response.json({
          items: [],
          pagination: { page: 2, pageSize: 100, totalItems: 0, totalPages: 0 },
        }),
        'Authorization detail catalog returned mismatched pagination metadata.',
      ],
      [
        Response.json({
          items: [
            { authorizationDetail: { type: 'project_access', identifier: 'project-1' }, display: { label: 'One' } },
          ],
          pagination: { page: 1, pageSize: 100, totalItems: 0, totalPages: 0 },
        }),
        'Authorization detail catalog returned inconsistent pagination metadata.',
      ],
      [
        Response.json({
          items: [
            { authorizationDetail: { type: 'project_access', identifier: 'project-1' }, display: { label: 'One' } },
            {
              authorizationDetail: { type: 'project_access', identifier: 'project-1' },
              display: { label: 'One again' },
            },
          ],
          pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 2, totalPages: Math.ceil(2 / 100) },
        }),
        'Authorization detail catalog contains duplicate details.',
      ],
      [
        Response.json({
          items: [
            { authorizationDetail: { type: 'other_access', identifier: 'other-1' }, display: { label: 'Other' } },
          ],
          pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 1, totalPages: Math.ceil(1 / 100) },
        }),
        'Authorization detail catalog contains a detail outside the resource templates.',
      ],
    ] as const) {
      await expect(
        listAgentAuthorizationDetailCatalog(
          authorizationCatalogDeps({ fetchResponse: response }),
          'resource-1',
          principal(),
          { limit: 100, offset: 0 },
        ),
      ).rejects.toThrow(message)
    }

    await expect(
      listAgentAuthorizationDetailCatalog(
        authorizationCatalogDeps({
          fetchResponse: Response.json({
            items: [
              { authorizationDetail: { type: 'project_access', identifier: 'project-1' }, display: { label: 'One' } },
              { authorizationDetail: { type: 'project_access', identifier: 'project-2' }, display: { label: 'Two' } },
            ],
            pagination: { page: Math.floor(0 / 1) + 1, pageSize: 1, totalItems: 2, totalPages: Math.ceil(2 / 1) },
          }),
        }),
        'resource-1',
        principal(),
        { limit: 1, offset: 0 },
      ),
    ).rejects.toThrow('Authorization detail catalog returned more items than requested.')

    const unreachable = authorizationCatalogDeps()
    vi.mocked(unreachable.externalHttp.fetch).mockRejectedValue(new Error('network unavailable'))
    await expect(
      listAgentAuthorizationDetailCatalog(unreachable, 'resource-1', principal(), { limit: 100, offset: 0 }),
    ).rejects.toThrow('Authorization detail catalog could not be reached.')

    const withoutCredential = authorizationCatalogDeps()
    vi.mocked(withoutCredential.externalResources.findConnectionByOwnerResource).mockResolvedValue({
      ...connectionRecord(),
      credentials: connectionRecord().credentials.map((credential) => ({ ...credential, status: 'revoked' as const })),
    })
    await expect(
      listAgentAuthorizationDetailCatalog(withoutCredential, 'resource-1', principal(), { limit: 100, offset: 0 }),
    ).rejects.toThrow('No active provider credential covers the requested authority.')

    const ambiguousCredential = authorizationCatalogDeps()
    const connection = connectionRecord()
    vi.mocked(ambiguousCredential.externalResources.findConnectionByOwnerResource).mockResolvedValue({
      ...connection,
      credentials: [connection.credentials[0]!, { ...connection.credentials[0]!, id: 'credential-2' }],
    })
    await expect(
      listAgentAuthorizationDetailCatalog(ambiguousCredential, 'resource-1', principal(), { limit: 100, offset: 0 }),
    ).rejects.toThrow('Select an authorization context that identifies one provider credential.')
  })

  it('always exposes the owning User as a native resource context', async () => {
    const nativeAgent = authorizationCatalogDeps()
    vi.mocked(nativeAgent.authorization.findResource).mockResolvedValue(nativeResource())
    await expect(
      listAgentAuthorizationDetailCatalog(nativeAgent, 'resource-1', principal(), { limit: 10, offset: 0 }),
    ).resolves.toMatchObject({
      items: [{ metadata: { authority: 'user', userId: 'user-1' } }],
      pagination: { totalItems: 1 },
    })

    for (const connection of [null, { ...connectionRecord(), status: 'revoked' as const }]) {
      const deps = authorizationCatalogDeps()
      vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connection)
      await expect(
        listAgentAuthorizationDetailCatalog(deps, 'resource-1', principal(), { limit: 10, offset: 0 }),
      ).resolves.toEqual({
        items: [],
        pagination: { page: Math.floor(0 / 10) + 1, pageSize: 10, totalItems: 0, totalPages: Math.ceil(0 / 10) },
      })
    }

    const mismatchedRequest = authorizationCatalogDeps()
    vi.mocked(mismatchedRequest.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(
      requestRecord(),
    )
    await expect(
      listAccountAccessRequestAuthorizationDetailCatalog(
        mismatchedRequest,
        'another-request',
        'approval-token',
        'user-1',
        { limit: 10, offset: 0 },
      ),
    ).rejects.toThrow('Agent access request was not found.')

    const missingIdentity = authorizationCatalogDeps()
    vi.mocked(missingIdentity.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(requestRecord())
    vi.mocked(missingIdentity.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(missingIdentity.agentIdentities.findIdentity).mockResolvedValue(null)
    await expect(
      listAccountAccessRequestAuthorizationDetailCatalog(missingIdentity, 'request-1', 'approval-token', 'user-1', {
        limit: 10,
        offset: 0,
      }),
    ).rejects.toThrow('Active Agent identity was not found.')

    const nativeAccount = authorizationCatalogDeps()
    vi.mocked(nativeAccount.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(requestRecord())
    vi.mocked(nativeAccount.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(nativeAccount.authorization.findResource).mockResolvedValue(nativeResource())
    await expect(
      listAccountAccessRequestAuthorizationDetailCatalog(nativeAccount, 'request-1', 'approval-token', 'user-1', {
        limit: 10,
        offset: 0,
      }),
    ).rejects.toThrow('Native API resources do not have authorization detail catalogs.')

    for (const connection of [null, { ...connectionRecord(), status: 'revoked' as const }]) {
      const deps = authorizationCatalogDeps()
      vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue({
        ...requestRecord(),
        connectionId: null,
      })
      vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connection)
      await expect(
        listAccountAccessRequestAuthorizationDetailCatalog(deps, 'request-1', 'approval-token', 'user-1', {
          limit: 10,
          offset: 0,
        }),
      ).rejects.toThrow('Active resource account connection was not found.')
    }
  })

  it(`exchanges user and Agent authority for a target-issued DPoP token [spec: agent-identity/agent-resource-entitlement-policy]
      [spec: agent-identity/agent-direct-resource-access]
      [spec: agent-identity/agent-audit-chain]`, async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const openApiFetch = vi.mocked(deps.externalHttp.fetch).getMockImplementation()!
    const request = {
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    }
    const grant = {
      ...grantRecord(),
      mode: 'persistent' as const,
      scopes: ['projects:read', 'projects:write'],
    }
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(grant)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([grant])
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(
      connectionWithCredential(connectionRecord(), {
        clientGeneration: 1,
        credentialExpiresAt: new Date(Date.now() - 1),
      }),
    )
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        clientId: 'realmroot-client-new',
        clientSecret: 'target-secret-new',
        clientGeneration: 2,
        retiredClientGenerations: [
          {
            generation: 1,
            clientId: 'realmroot-client',
            encryptedClientSecret: 'sealed:target-secret',
            clientSecretContext: 'connector:connector-1:client-generation:1:client-secret',
            registrationClientUri: null,
            encryptedRegistrationAccessToken: null,
            registrationAccessTokenContext: null,
            registeredScopes: ['openid', 'offline_access', 'projects:read'],
          },
        ],
      }),
    )
    vi.mocked(deps.externalResources.createTokenLease).mockImplementation(async (record) => record)
    vi.mocked(deps.externalResources.consumeAccessRequest).mockResolvedValue(true)
    vi.mocked(deps.externalResources.endEntitlement).mockResolvedValue(true)
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
    const publicJwk = await exportJWK(publicKey)
    const proof = await new SignJWT({
      htm: 'POST',
      htu: 'https://projects.example.com/token',
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
      .sign(privateKey)
    const tokenRequests: URLSearchParams[] = []
    let exchangeResponse: Record<string, unknown> = {
      access_token: 'target-dpop-access',
      token_type: 'DPoP',
      expires_in: 3_600,
    }
    let exchangeStatus = 200
    let exchangeHeaders: Record<string, string> = {}
    let exchangeFailure: 'network' | 'timeout' | 'invalid-json' | null = null
    let notifyTimeoutRequestStarted = () => {}
    const timeoutRequestStarted = new Promise<void>((resolve) => {
      notifyTimeoutRequestStarted = resolve
    })
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (outbound) => {
      if (outbound.url === resource().resourceUrl || outbound.url === 'https://projects.example.com/openapi.json') {
        return openApiFetch(outbound)
      }
      expect(outbound.url).toBe('https://projects.example.com/token')
      expect(outbound.headers.get('authorization')).toBe(`Basic ${btoa('realmroot-client:target-secret')}`)
      const form = new URLSearchParams(await outbound.text())
      tokenRequests.push(form)
      if (form.get('grant_type') === 'refresh_token') {
        return Response.json({
          access_token: 'refreshed-subject',
          token_type: 'Bearer',
          expires_in: 0,
        })
      }
      if (form.get('grant_type') === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
        expect(outbound.headers.get('dpop')).toBeNull()
        expect(form.get('assertion')).toBe('signed-agent-assertion')
        return Response.json({
          access_token: 'target-agent-access',
          token_type: 'Bearer',
          expires_in: 300,
        })
      }
      expect(outbound.headers.get('dpop')).toBe(proof)
      expect(['refreshed-subject', 'subject']).toContain(form.get('subject_token'))
      expect(form.get('actor_token')).toBe('target-agent-access')
      expect(form.get('actor_token_type')).toBe('urn:ietf:params:oauth:token-type:access_token')
      expect(form.get('scope')).toBe('projects:read')
      if (exchangeFailure === 'network') throw new Error('connection reset')
      if (exchangeFailure === 'timeout') {
        notifyTimeoutRequestStarted()
        return new Promise<Response>(() => {})
      }
      if (exchangeFailure === 'invalid-json') return new Response('upstream failure', { status: 502 })
      return Response.json(exchangeResponse, { status: exchangeStatus, headers: exchangeHeaders })
    })

    const sign = vi.fn().mockResolvedValue('signed-agent-assertion')
    const lease = await issueTargetAccessToken(
      deps,
      request.id,
      proof,
      'https://auth.example.com/api/agent/access-requests/request-1/credentials',
      principal(),
      { issuer: 'https://auth.example.com/api/auth', sign },
    )
    expect(deps.oauthRequests.createRefreshTokenRequest).toHaveBeenCalledWith({
      refreshToken: 'refresh',
      clientId: 'realmroot-client',
      clientSecret: 'target-secret',
      authentication: 'basic',
      extraParams: undefined,
    })
    expect(sign).toHaveBeenCalledWith(
      expect.objectContaining({
        iss: 'https://auth.example.com/api/auth',
        sub: 'agt_stable',
        aud: 'https://projects.example.com/token',
        [realmrootAgentBindingClaim]: {
          protocol_agent_id: 'protocol-agent-1',
          host_id: 'host-1',
          runtime: 'codex',
          session_id: 'thread-raw-123',
        },
      }),
      'JWT',
    )
    expect(sign.mock.calls[0]![0]).not.toHaveProperty('act')
    const grantTypes = tokenRequests.map((form) => form.get('grant_type'))
    expect(grantTypes.slice(0, 2)).toEqual(
      expect.arrayContaining(['refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer']),
    )
    expect(grantTypes[2]).toBe('urn:ietf:params:oauth:grant-type:token-exchange')
    expect(lease).toEqual({
      accessToken: 'target-dpop-access',
      tokenType: 'DPoP',
      expiresIn: 3_600,
      expiresAt: expect.any(String),
      scopes: ['projects:read'],
      authorizationDetails: [],
      resourceUrl: 'https://projects.example.com/api',
      dpopNonce: null,
    })
    expect(deps.agentAudit.append).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'api_resource.token_issued',
        agentIdentityId: 'identity-1',
        hostId: 'host-1',
        resourceConnectionId: 'connection-1',
        accessRequestId: 'request-1',
        scopes: ['projects:read'],
      }),
    )

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({ ...request, connectionId: null })
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue({ ...grant, connectionId: null })
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grant, connectionId: null },
    ])
    await expect(
      issueTargetAccessToken(
        deps,
        request.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('Active external API resource grant is required.')
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(grant)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([grant])
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue({
      ...grant,
      expiresAt: new Date(Date.now() + 10_000),
    })
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grant, expiresAt: new Date(Date.now() + 10_000) },
    ])
    exchangeResponse = { access_token: 'beyond-entitlement', token_type: 'DPoP', expires_in: 60 }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('beyond an Entitlement lifetime')
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(grant)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([grant])
    exchangeResponse = { access_token: 'excessive-expiry', token_type: 'DPoP', expires_in: 5_000 }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('excessive lifetime')
    exchangeResponse = { access_token: 'wrong-type', token_type: 'Bearer', expires_in: 60 }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('did not issue a DPoP-bound access token')
    exchangeResponse = {
      access_token: 'wrong-scope',
      token_type: 'DPoP',
      expires_in: 60,
      scope: 'projects:write',
    }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('issued a different scope set')
    exchangeResponse = { access_token: 'invalid-expiry', token_type: 'DPoP', expires_in: 0 }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('invalid expires_in')
    exchangeResponse = { code: 'BAD_REQUEST', message: 'Agent assertion is invalid' }
    exchangeStatus = 400
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('bad_request: Agent assertion is invalid')

    exchangeResponse = { error: 'invalid_grant', error_description: 'The grant expired' }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('invalid_grant: The grant expired')

    exchangeResponse = { error: 'invalid_grant' }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('token request: invalid_grant')

    exchangeResponse = { error: 'invalid_grant', message: 'The provider rejected the grant' }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('invalid_grant: The provider rejected the grant')

    exchangeResponse = { message: 'Unstructured provider failure' }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('External authorization server rejected the token request.')

    exchangeResponse = {
      error: 'use_dpop_nonce',
      error_description: 'Authorization server requires nonce in DPoP proof',
    }
    exchangeHeaders = { 'DPoP-Nonce': 'challenge-nonce' }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toMatchObject({
      status: 400,
      error: 'use_dpop_nonce',
      headers: { 'DPoP-Nonce': 'challenge-nonce' },
    })

    exchangeResponse = { error: 'use_dpop_nonce' }
    exchangeHeaders = {}
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('invalid DPoP nonce challenge')

    exchangeHeaders = { 'DPoP-Nonce': 'fallback-nonce' }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toMatchObject({
      message: 'Authorization server requires nonce in DPoP proof.',
      headers: { 'DPoP-Nonce': 'fallback-nonce' },
    })

    exchangeStatus = 200
    exchangeResponse = { access_token: 'target-dpop-access', token_type: 'DPoP', expires_in: 60 }
    exchangeHeaders = { 'DPoP-Nonce': 'invalid nonce' }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('invalid DPoP nonce')

    exchangeFailure = 'network'
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('External authorization server is unavailable')

    exchangeFailure = 'timeout'
    vi.useFakeTimers()
    try {
      const issue = issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      )
      const result = expect(issue).rejects.toThrow('External authorization server is unavailable')
      await timeoutRequestStarted
      await vi.advanceTimersByTimeAsync(5_000)
      await result
    } finally {
      vi.useRealTimers()
    }

    exchangeFailure = 'invalid-json'
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('External authorization server rejected the token request')

    exchangeFailure = null
    exchangeHeaders = { 'DPoP-Nonce': 'next-nonce' }
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).resolves.toMatchObject({ dpopNonce: 'next-nonce' })

    vi.mocked(deps.connectors.findById).mockResolvedValue(null)
    await expect(
      issueTargetAccessToken(
        deps,
        grant.id,
        proof,
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign },
      ),
    ).rejects.toThrow('Connector not found.')
  })

  it('[spec: agent-identity/external-resource-contextual-delegation] exchanges and leases the exact approved authorization details', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const authorizationDetails = [{ type: 'project_access', identifier: 'project-1', actions: ['read'] }]
    const rarResource = {
      ...resource(),
      authorizationDetails: [{ type: 'project_access', actions: ['read'] }],
    }
    const request = {
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
      authorizationDetails,
    }
    const grant = { ...grantRecord(), authorizationDetails }
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([grant])
    const credentialScopes = ['openid', 'offline_access', 'authorization-details:read']
    const connection = connectionWithCredential(
      { ...connectionRecord(), grantedScopes: credentialScopes, authorizationDetails },
      {
        grantedScopes: credentialScopes,
        authorizationDetails,
        credentialExpiresAt: new Date(Date.now() - 1_000),
      },
    )
    vi.mocked(deps.authorization.findResource).mockResolvedValue(rarResource)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(grant)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.createTokenLease).mockImplementation(async (record) => record)
    vi.mocked(deps.externalResources.consumeAccessRequest).mockResolvedValue(true)
    vi.mocked(deps.externalResources.endEntitlement).mockResolvedValue(true)
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerMetadata: {
          ...metadata(),
          authorization_details_types_supported: ['project_access'],
          authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
          authorization_details_catalog_scope: 'authorization-details:read',
          pushed_authorization_request_endpoint: 'https://projects.example.com/par',
        },
      }),
    )
    const openApiFetch = vi.mocked(deps.externalHttp.fetch).getMockImplementation()!
    let expectedAuthorizationDetails = authorizationDetails
    let issuedAuthorizationDetails: unknown = authorizationDetails
    let refreshedAuthorizationDetails: unknown
    let refreshInvalidGrant = false
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (outbound) => {
      if (outbound.url === rarResource.resourceUrl || outbound.url === 'https://projects.example.com/openapi.json') {
        return openApiFetch(outbound)
      }
      if (outbound.url.startsWith('https://projects.example.com/authorization-details?')) {
        return Response.json({
          items: expectedAuthorizationDetails.map((authorizationDetail, index) => ({
            authorizationDetail,
            grantedScopes: ['projects:read'],
            display: { label: `Project ${index + 1}` },
          })),
          pagination: {
            page: Math.floor(0 / 100) + 1,
            pageSize: 100,
            totalItems: expectedAuthorizationDetails.length,
            totalPages: Math.ceil(expectedAuthorizationDetails.length / 100),
          },
        })
      }
      const form = new URLSearchParams(await outbound.text())
      if (form.get('grant_type') === 'refresh_token') {
        expect(JSON.parse(form.get('authorization_details')!)).toEqual(expectedAuthorizationDetails)
        if (refreshInvalidGrant) {
          return Response.json({ error: 'invalid_grant' }, { status: 400 })
        }
        return Response.json({
          access_token: 'refreshed-subject-token',
          refresh_token: 'rotated-refresh-token',
          token_type: 'Bearer',
          expires_in: 300,
          ...(refreshedAuthorizationDetails === undefined
            ? {}
            : { authorization_details: refreshedAuthorizationDetails }),
        })
      }
      if (form.get('grant_type') === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
        return Response.json({ access_token: 'actor-token', token_type: 'Bearer', expires_in: 300 })
      }
      expect(JSON.parse(form.get('authorization_details')!)).toEqual(expectedAuthorizationDetails)
      return Response.json({
        access_token: 'target-token',
        token_type: 'DPoP',
        expires_in: 300,
        scope: 'projects:read',
        authorization_details: issuedAuthorizationDetails,
      })
    })

    const issue = async () =>
      issueTargetAccessToken(
        deps,
        grant.id,
        await createDpopProof('https://projects.example.com/token'),
        'https://auth.example.com/api/agent/access-requests/request-1/credentials',
        principal(),
        { issuer: principal().issuer, sign: vi.fn().mockResolvedValue('agent-assertion') },
      )
    await expect(issue()).resolves.toMatchObject({ authorizationDetails })
    expect(deps.externalResources.completeProviderCredentialRefresh).toHaveBeenCalledWith(
      connection.credentials[0]!.id,
      expect.objectContaining({ encryptedTokens: expect.stringContaining('rotated-refresh-token') }),
    )
    expect(deps.externalResources.createTokenLease).toHaveBeenCalledWith(
      expect.objectContaining({ authorizationDetails }),
    )

    refreshInvalidGrant = true
    await expect(issue()).rejects.toThrow('Provider refresh token is no longer valid')
    refreshInvalidGrant = false

    refreshedAuthorizationDetails = [{ type: 'project_access', identifier: 'project-2', actions: ['read'] }]
    await expect(issue()).rejects.toThrow('changed authorization details during refresh')
    refreshedAuthorizationDetails = undefined
    issuedAuthorizationDetails = [{ type: 'project_access', identifier: 'project-2', actions: ['read'] }]
    await expect(issue()).rejects.toThrow('issued different authorization details')
    issuedAuthorizationDetails = undefined
    await expect(issue()).rejects.toMatchObject({ error: 'invalid_authorization_details' })

    const legacyAuthorizationDetails = [
      authorizationDetails[0]!,
      { type: 'project_access', identifier: 'project-2', actions: ['read'] },
    ]
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...request,
      authorizationDetails: legacyAuthorizationDetails,
    })
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue({
      ...grant,
      authorizationDetails: legacyAuthorizationDetails,
    })
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grant, authorizationDetails: legacyAuthorizationDetails },
    ])
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(
      connectionWithCredential(connection, { authorizationDetails: legacyAuthorizationDetails }),
    )
    expectedAuthorizationDetails = legacyAuthorizationDetails
    issuedAuthorizationDetails = legacyAuthorizationDetails
    await expect(issue()).resolves.toMatchObject({ authorizationDetails: legacyAuthorizationDetails })
  })

  it('revokes active target token leases [spec: agent-identity/agent-resource-revocation]', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(grantRecord())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(
      connectionWithCredential(connectionRecord(), { clientGeneration: 1 }),
    )
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        clientId: 'realmroot-client-new',
        clientSecret: 'target-secret-new',
        clientGeneration: 2,
        retiredClientGenerations: [
          {
            generation: 1,
            clientId: 'realmroot-client',
            encryptedClientSecret: 'sealed:target-secret',
            clientSecretContext: 'connector:connector-1:client-generation:1:client-secret',
            registrationClientUri: null,
            encryptedRegistrationAccessToken: null,
            registrationAccessTokenContext: null,
            registeredScopes: ['openid', 'offline_access', 'projects:read'],
          },
        ],
      }),
    )
    vi.mocked(deps.externalResources.listActiveTokenLeasesByEntitlement).mockResolvedValue([
      {
        id: 'lease-1',
        entitlementIds: ['ent_1'],
        requestId: 'request-1',
        bindingId: 'binding-1',
        encryptedAccessToken: 'sealed:target-dpop-access',
        tokenHash: 'hash',
        confirmationJkt: 'jkt',
        scopes: ['projects:read'],
        authorizationDetails: [],
        expiresAt: new Date(Date.now() + 300_000),
        revokedAt: null,
        createdAt: now,
      },
    ])
    vi.mocked(deps.externalResources.revokeTokenLease).mockResolvedValue(true)
    vi.mocked(deps.externalResources.endEntitlement).mockResolvedValue(true)
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (outbound) => {
      expect(outbound.url).toBe('https://projects.example.com/revoke')
      expect(outbound.headers.get('authorization')).toBe(`Basic ${btoa('realmroot-client:target-secret')}`)
      expect(new URLSearchParams(await outbound.text()).get('token')).toBe('target-dpop-access')
      return new Response(null, { status: 200 })
    })

    await revokeAgentPermission(deps, 'grant-1', 'user-1')
    expect(deps.externalResources.revokeTokenLease).toHaveBeenCalledWith('lease-1', expect.any(Date))
    expect(deps.externalResources.endEntitlement).toHaveBeenCalledWith('ent_1', 'revoked', expect.any(Date))
  })

  it('records the Agent owner when revoking native Resource access', async () => {
    const deps = createTestDeps()
    const identity = identityAggregate()
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue({
      ...identity,
      identity: { ...identity.identity, ownerUserId: 'user-1' },
    })
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue({ ...grantRecord(), connectionId: null })
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({ ...requestRecord(), connectionId: null })
    vi.mocked(deps.authorization.findResource).mockResolvedValue(nativeResource())
    vi.mocked(deps.externalResources.listActiveTokenLeasesByEntitlement).mockResolvedValue([
      {
        id: 'lease-native',
        entitlementIds: ['ent_1'],
        requestId: 'request-1',
        bindingId: 'binding-1',
        encryptedAccessToken: 'sealed:native',
        tokenHash: 'hash',
        confirmationJkt: 'jkt',
        scopes: ['projects:read'],
        authorizationDetails: [],
        expiresAt: new Date(Date.now() + 30_000),
        revokedAt: null,
        createdAt: now,
      },
    ])
    vi.mocked(deps.externalResources.endEntitlement).mockResolvedValue(true)

    await revokeAgentPermission(deps, 'ent_1', 'user-1')

    expect(deps.agentAudit.append).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'api_resource.access_revoked',
        agentIdentityId: 'identity-1',
        ownerUserId: 'user-1',
      }),
    )
    expect(deps.externalResources.revokeTokenLease).toHaveBeenCalledWith('lease-native', expect.any(Date))
  })

  it('maps management and account resource views', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([
      { ...connectionRecord(), ownerUserId: 'user-1', ownerOrganizationId: null },
      connectionWithCredential(
        {
          ...connectionRecord(),
          id: 'connection-2',
          ownerUserId: null,
          ownerOrganizationId: 'organization-1',
          externalSubject: 'tiny',
        },
        { credentialExpiresAt: null },
      ),
    ])

    await expect(getExternalResourceAuthorization(deps, 'resource-1')).resolves.toMatchObject({
      resourceId: 'resource-1',
      clientSecretConfigured: true,
    })
    await expect(getApiResource(deps, 'resource-1', 'https://auth.example.com')).resolves.toMatchObject({
      id: 'resource-1',
      authorization: { issuer: 'https://projects.example.com' },
    })
    const resources = await listApiResources(deps, { limit: 10, offset: 0 }, 'https://auth.example.com')
    expect(resources.items).toEqual(expect.arrayContaining([expect.objectContaining({ id: 'resource-1' })]))
    await expect(listResourceConnections(deps, 'user-1')).resolves.toMatchObject({
      items: [{ owner: { type: 'user' } }, { owner: { type: 'organization' }, credentialExpiresAt: null }],
    })
    await expect(listAccountConnections(deps, 'user-1', { limit: 1, offset: 1 })).resolves.toMatchObject({
      items: [{ id: 'connection-2', subjectHint: '••••' }],
      pagination: { totalItems: 2 },
    })
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    await expect(getAccountConnection(deps, 'connection-1', 'user-1')).resolves.toMatchObject({
      apiResourceId: 'resource-1',
      subjectHint: '••••er-1',
      scopes: ['projects:read'],
    })
    await expect(listConnectableExternalResources(deps)).resolves.toMatchObject({
      items: [{ id: 'resource-1' }],
    })
  })

  it('defaults optional connector authorization metadata', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        registrationMode: null,
        clientSecretContext: 'connector:connector-1:client-secret',
        providerMetadata: null,
      }),
    )

    await expect(getExternalResourceAuthorization(deps, 'resource-1')).resolves.toMatchObject({
      registrationMode: 'dynamic',
    })
  })

  it('returns managed OAuth authorization without a provider JWKS endpoint', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.authorization.findResource).mockResolvedValue({
      ...resource(),
      authorizationModel: 'native',
      connectorId: 'connector-1',
    })
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        providerType: 'social',
        providerId: 'linear',
        issuer: null,
        jwksEndpoint: null,
      }),
    )

    await expect(getApiResource(deps, 'resource-1', 'https://auth.example.com')).resolves.toMatchObject({
      authorization: null,
    })
  })

  it('creates and revokes account connections, including organization control [spec: agent-identity/connector-backed-connection-revocation]', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    vi.mocked(deps.authorization.findResource).mockResolvedValue({
      ...resource(),
    })
    vi.mocked(deps.externalHttp.fetch).mockResolvedValue(new Response(null, { status: 200 }))
    Object.assign(deps.authorization, {
      findMemberByOrganizationUser: vi.fn().mockResolvedValue({ roles: ['credential_manager'] }),
      listOrganizationRoleScopes: vi
        .fn()
        .mockResolvedValue(
          new Map([['credential_manager', [{ resourceId: 'resource-realmroot', scope: 'agents:write' }]]]),
        ),
    })
    vi.mocked(deps.externalResources.createConnectionIntent).mockImplementation(async (record) => record)

    await expect(
      createAccountConnection(
        deps,
        {
          context: 'resource',
          apiResourceId: 'resource-1',
          owner: { type: 'organization', organizationId: 'organization-1' },
          scopes: ['projects:read'],
        },
        'user-1',
        'https://auth.example.com/',
      ),
    ).resolves.toMatchObject({
      owner: { type: 'organization', organizationId: 'organization-1' },
      status: 'pending_authorization',
      scopes: ['projects:read'],
      authorizationUrl: expect.stringContaining('/authorize?'),
    })

    const organizationConnection = {
      ...connectionRecord(),
      ownerUserId: null,
      ownerOrganizationId: 'organization-1',
    }
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(organizationConnection)
    vi.mocked(deps.externalResources.listActiveEntitlementsByConnection).mockResolvedValue([])
    vi.mocked(deps.externalResources.revokeConnection).mockResolvedValue(true)
    await expect(revokeResourceConnection(deps, 'connection-1', 'user-1')).resolves.toBeUndefined()
    expect(deps.externalResources.revokeConnection).toHaveBeenCalledOnce()

    vi.mocked(deps.externalResources.revokeConnection).mockResolvedValue(false)
    await expect(revokeResourceConnection(deps, 'connection-1', 'user-1')).rejects.toThrow(
      'Resource account connection is already revoked.',
    )
  })

  it('[spec: agent-identity/external-resource-first-access] connects the account with the pending request scopes', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    mockResourceOpenApi(deps, resource().resourceUrl, ['objects:purge', 'projects:read', 'projects:write'])
    const request = {
      ...requestRecord(),
      connectionId: null,
      scopes: ['projects:read'],
    }
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    vi.mocked(deps.externalResources.createConnectionIntent).mockImplementation(async (record) => record)

    await expect(
      createAccountConnection(
        deps,
        {
          context: 'access-request',
          accessRequestId: request.id,
          approvalToken: 'approval-token',
        },
        'user-1',
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      apiResourceId: 'resource-1',
      owner: { type: 'user' },
      scopes: ['projects:read'],
      status: 'pending_authorization',
    })
    expect(deps.externalResources.createConnectionIntent).toHaveBeenCalledWith(
      expect.objectContaining({
        resourceId: 'resource-1',
        ownerUserId: 'user-1',
        scopes: ['offline_access', 'openid', 'projects:read'],
        returnTo: 'access-approval',
      }),
    )

    const personalAccessIdentity = identityAggregate()
    personalAccessIdentity.identity.ownerUserId = 'user-1'
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(personalAccessIdentity)
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(null)
    await expect(
      createAccountConnection(
        deps,
        { context: 'access-request', accessRequestId: request.id, approvalToken: 'approval-token' },
        'user-1',
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ owner: { type: 'user' } })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())

    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([
      {
        ...connectionRecord(),
        grantedScopes: ['openid', 'offline_access', 'projects:read', 'projects:write'],
      },
    ])
    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({
      items: [{ id: 'connection-1' }],
      pagination: { totalItems: 1 },
    })

    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([
      { ...connectionRecord(), grantedScopes: ['projects:read'] },
    ])
    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({
      items: [{ id: 'connection-1', scopes: ['projects:read'] }],
      pagination: { totalItems: 1 },
    })

    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([
      { ...connectionRecord(), status: 'revoked' },
    ])
    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({ items: [], pagination: { totalItems: 0 } })

    const personalIdentity = identityAggregate()
    personalIdentity.identity.ownerUserId = 'user-1'
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(personalIdentity)
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([connectionRecord()])
    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({ items: [{ id: 'connection-1' }], pagination: { totalItems: 1 } })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())

    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([
      connectionRecord(),
      { ...connectionRecord(), id: 'duplicate-connection' },
    ])
    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({
      items: [{ id: 'connection-1' }, { id: 'duplicate-connection' }],
      pagination: { totalItems: 2 },
    })

    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValueOnce(identityAggregate()).mockResolvedValueOnce(null)
    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).rejects.toThrow('Active Agent identity was not found.')

    vi.mocked(deps.authorization.findResource).mockResolvedValue(nativeResource())
    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toEqual({
      items: [],
      pagination: expect.objectContaining({ totalItems: 0 }),
    })
  })

  it('[spec: agent-identity/resource-account-reauthorization] preserves existing scopes while expanding an account', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const template = { type: 'project_access', actions: ['read'] }
    const existingDetail = { ...template, identifier: 'project-1' }
    const request = {
      ...requestRecord(),
      connectionId: null,
      scopes: ['teams:read'],
      authorizationDetails: [{ ...template, identifier: 'project-2' }],
    }
    const existingConnection = {
      ...connectionRecord(),
      grantedScopes: [
        'openid',
        'offline_access',
        'workspaces:discover',
        'objects:create',
        'quota:purchase',
        'shares:create',
      ],
      authorizationDetails: [existingDetail],
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue({
      ...resource(),
      authorizationDetails: [template],
    })
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        registeredScopes: [
          'workspaces:discover',
          'objects:create',
          'offline_access',
          'openid',
          'quota:purchase',
          'shares:create',
          'teams:read',
        ],
        providerMetadata: {
          ...metadata(),
          authorization_details_types_supported: ['project_access'],
          pushed_authorization_request_endpoint: 'https://projects.example.com/par',
          authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
          authorization_details_catalog_scope: 'workspaces:discover',
          authorization_details_catalog_version: 1,
        },
      }),
    )
    mockResourceOpenApi(deps, resource().resourceUrl, [
      'objects:create',
      'quota:purchase',
      'shares:create',
      'teams:read',
    ])
    const openApiFetch = vi.mocked(deps.externalHttp.fetch).getMockImplementation()!
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (fetchRequest) => {
      if (fetchRequest.url === 'https://projects.example.com/par') {
        const form = new URLSearchParams(await fetchRequest.text())
        expect(form.get('scope')?.split(' ')).toEqual(
          [
            'workspaces:discover',
            'objects:create',
            'offline_access',
            'openid',
            'quota:purchase',
            'shares:create',
            'teams:read',
          ].sort(),
        )
        expect(JSON.parse(form.get('authorization_details')!)).toEqual(request.authorizationDetails)
        return Response.json({ request_uri: 'urn:example:par:expanded', expires_in: 300 }, { status: 201 })
      }
      return openApiFetch(fetchRequest)
    })
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(existingConnection)
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([existingConnection])
    vi.mocked(deps.externalResources.createConnectionIntent).mockImplementation(async (record) => record)

    await expect(
      createAccountConnection(
        deps,
        {
          context: 'access-request',
          accessRequestId: request.id,
          approvalToken: 'approval-token',
        },
        'user-1',
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      apiResourceId: 'resource-1',
      scopes: ['objects:create', 'quota:purchase', 'shares:create', 'teams:read'],
      authorizationDetails: request.authorizationDetails,
      status: 'pending_authorization',
    })
    expect(deps.externalResources.createConnectionIntent).toHaveBeenCalledWith(
      expect.objectContaining({
        scopes: [
          'objects:create',
          'offline_access',
          'openid',
          'quota:purchase',
          'shares:create',
          'teams:read',
          'workspaces:discover',
        ],
        authorizationDetails: request.authorizationDetails,
        returnTo: 'access-approval',
      }),
    )
  })

  it('[spec: agent-identity/resource-account-reauthorization] evaluates account scopes for the selected authorization detail', async () => {
    const detail = { type: 'project_access', identifier: 'project-1', actions: ['read'] }
    const deps = authorizationCatalogDeps({
      fetchResponse: Response.json({
        items: [
          {
            authorizationDetail: detail,
            grantedScopes: ['projects:read'],
            display: { label: 'Project One' },
          },
        ],
        pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 1, totalPages: Math.ceil(1 / 100) },
      }),
    })
    const request = {
      ...requestRecord(),
      scopes: ['projects:write'],
      authorizationDetails: [detail],
    }
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    const connection = {
      ...connectionRecord(),
      grantedScopes: [...connectionRecord().grantedScopes, 'authorization-details:read', 'projects:write'],
    }
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([connection])

    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({
      items: [{ id: 'connection-1', scopes: ['projects:read'] }],
    })
  })

  it('[spec: agent-identity/resource-account-reauthorization] intersects contextual scopes across catalog pages', async () => {
    const firstDetail = { type: 'project_access', identifier: 'project-1', actions: ['read'] }
    const secondDetail = { type: 'project_access', identifier: 'project-2', actions: ['read'] }
    const deps = authorizationCatalogDeps()
    vi.mocked(deps.externalHttp.fetch)
      .mockResolvedValueOnce(
        Response.json({
          items: [
            {
              authorizationDetail: firstDetail,
              grantedScopes: ['projects:read', 'projects:write'],
              display: { label: 'Project One' },
            },
            {
              authorizationDetail: { type: 'project_access', identifier: 'project-other', actions: ['read'] },
              grantedScopes: ['projects:read'],
              display: { label: 'Other Project' },
            },
          ],
          pagination: { page: 1, pageSize: 100, totalItems: 101, totalPages: 2 },
        }),
      )
      .mockResolvedValueOnce(
        Response.json({
          items: [
            {
              authorizationDetail: secondDetail,
              grantedScopes: ['projects:read'],
              display: { label: 'Project Two' },
            },
          ],
          pagination: { page: 2, pageSize: 100, totalItems: 101, totalPages: 2 },
        }),
      )
    const request = {
      ...requestRecord(),
      authorizationDetails: [firstDetail, secondDetail],
    }
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    const connection = {
      ...connectionRecord(),
      grantedScopes: [...connectionRecord().grantedScopes, 'authorization-details:read', 'projects:write'],
    }
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([connection])

    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({
      items: [{ id: 'connection-1', scopes: ['projects:read'] }],
    })
  })

  it('[spec: agent-identity/resource-account-reauthorization] preserves account scopes when a catalog cannot report contextual scopes', async () => {
    const detail = { type: 'project_access', identifier: 'project-1', actions: ['read'] }
    const deps = authorizationCatalogDeps({
      fetchResponse: Response.json({
        items: [{ authorizationDetail: detail, display: { label: 'Project One' } }],
        pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 1, totalPages: Math.ceil(1 / 100) },
      }),
    })
    const request = { ...requestRecord(), authorizationDetails: [detail] }
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    const connection = {
      ...connectionRecord(),
      grantedScopes: [...connectionRecord().grantedScopes, 'authorization-details:read'],
    }
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([connection])

    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({
      items: [{ id: 'connection-1', scopes: ['projects:read', 'authorization-details:read'] }],
    })
  })

  it('[spec: agent-identity/resource-account-reauthorization] reports no contextual scopes when the selected detail is absent', async () => {
    const requestedDetail = { type: 'project_access', identifier: 'project-1', actions: ['read'] }
    const deps = authorizationCatalogDeps({
      fetchResponse: Response.json({
        items: [
          {
            authorizationDetail: { type: 'project_access', identifier: 'project-other', actions: ['read'] },
            grantedScopes: ['projects:read'],
            display: { label: 'Other Project' },
          },
        ],
        pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 1, totalPages: Math.ceil(1 / 100) },
      }),
    })
    const request = { ...requestRecord(), authorizationDetails: [requestedDetail] }
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    const connection = {
      ...connectionRecord(),
      grantedScopes: [...connectionRecord().grantedScopes, 'authorization-details:read'],
    }
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([connection])

    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({
      items: [{ id: 'connection-1', scopes: [] }],
    })
  })

  it('[spec: agent-identity/agent-resource-approval] approves scopes granted by the selected account context', async () => {
    const detail = { type: 'project_access', identifier: 'project-1', actions: ['read'] }
    const deps = authorizationCatalogDeps({
      fetchResponse: Response.json({
        items: [
          {
            authorizationDetail: detail,
            grantedScopes: ['projects:write'],
            display: { label: 'Project One' },
          },
        ],
        pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 1, totalPages: Math.ceil(1 / 100) },
      }),
    })
    const request = {
      ...requestRecord(),
      scopes: ['projects:write'],
      authorizationDetails: [detail],
    }
    const connection = {
      ...connectionRecord(),
      grantedScopes: [...connectionRecord().grantedScopes, 'authorization-details:read'],
      authorizationDetails: [detail],
    }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connection])
    vi.mocked(deps.externalResources.approveAccessRequestWithEntitlements).mockImplementation(
      async (records, _updates, id, decision) => ({
        entitlements: records,
        request: { ...request, id, ...decision },
      }),
    )

    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        { decision: 'approve', mode: 'persistent', authorizationDetails: [detail] },
        'user-1',
      ),
    ).resolves.toMatchObject({ status: 'approved', scopes: ['projects:write'] })
  })

  it('enforces first-access connection context boundaries', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const request = { ...requestRecord(), connectionId: null }
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.createConnectionIntent).mockImplementation(async (record) => record)

    await expect(
      createAccountConnection(
        deps,
        { context: 'access-request', accessRequestId: 'another-request', approvalToken: 'approval-token' },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Agent access request was not found')

    const native = { ...nativeResource(), scopeRegistry: null }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
    mockResourceOpenApi(deps, native.resourceUrl)
    await expect(
      createAccountConnection(
        deps,
        { context: 'access-request', accessRequestId: request.id, approvalToken: 'approval-token' },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Native API resources do not use account connections')

    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    mockResourceOpenApi(deps, resource().resourceUrl)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValueOnce(identityAggregate()).mockResolvedValueOnce(null)
    await expect(
      createAccountConnection(
        deps,
        { context: 'access-request', accessRequestId: request.id, approvalToken: 'approval-token' },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Active Agent identity was not found')

    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([
      connectionRecord(),
      { ...connectionRecord(), id: 'wrong-resource', resourceId: 'resource-2' },
      { ...connectionRecord(), id: 'revoked', status: 'revoked' },
    ])
    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({ items: [{ id: 'connection-1' }], pagination: { totalItems: 1 } })

    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([
      connectionRecord(),
      { ...connectionRecord(), id: 'connection-2' },
    ])
    await expect(
      listAccessRequestConnections(deps, 'approval-token', 'user-1', { limit: 20, offset: 0 }),
    ).resolves.toMatchObject({
      items: [{ id: 'connection-1' }, { id: 'connection-2' }],
      pagination: { totalItems: 2 },
    })
  })

  it('rejects invalid internally resolved connections when approving first access', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const request = { ...requestRecord(), connectionId: null }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(request)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())

    await expect(
      decideAgentAccessRequest(deps, request.id, { decision: 'approve', mode: 'once' }, 'user-1'),
    ).rejects.toThrow('An account connection is required')

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(requestRecord())

    vi.mocked(deps.externalResources.findConnection).mockResolvedValue({
      ...connectionRecord(),
      resourceId: 'resource-2',
    })
    await expect(
      decideAgentAccessRequest(deps, request.id, { decision: 'approve', mode: 'once' }, 'user-1'),
    ).rejects.toThrow('does not belong to this API resource')

    vi.mocked(deps.externalResources.findConnection).mockResolvedValue({
      ...connectionRecord(),
      grantedScopes: ['projects:write'],
    })
    await expect(
      decideAgentAccessRequest(deps, request.id, { decision: 'approve', mode: 'once' }, 'user-1'),
    ).rejects.toThrow('connected account boundary')

    const native = nativeResource()
    vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({ id: 'org-1', disabled: false } as never)
    mockResourceOpenApi(deps, native.resourceUrl)
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      authorizationDetails: [organizationAuthority],
    })
    await expect(
      decideAgentAccessRequest(
        deps,
        request.id,
        { decision: 'approve', mode: 'once', authorizationDetails: [organizationAuthority] },
        'user-1',
      ),
    ).rejects.toThrow('Native API resources do not use account connections')
  })

  it('supports native resource discovery and access request wrappers', async () => {
    const deps = createTestDeps()
    const native = nativeResource()
    Object.assign(deps.authorization, {
      findResource: vi.fn().mockResolvedValue(native),
      listResources: vi.fn().mockResolvedValue({
        items: [native],
        pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 1, totalPages: Math.ceil(1 / 100) },
      }),
      listEnabledResources: vi.fn().mockResolvedValue([native]),
      findOrganization: vi.fn().mockResolvedValue({ id: 'org-1', name: 'Organization', disabled: false }),
      listUserMemberships: vi.fn().mockResolvedValue([{ organizationId: 'org-1', roles: [] }]),
    })
    mockResourceOpenApi(deps, native.resourceUrl)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grantRecord(), connectionId: null, authorizationDetails: [organizationAuthority] },
    ])
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      connectionId: null,
      authorizationDetails: [organizationAuthority],
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    vi.mocked(deps.externalResources.createAccessRequest).mockImplementation(async (record) => record)

    await expect(discoverAgentResources(deps, principal())).resolves.toMatchObject({
      items: [{ connection: { status: 'not_required', displayName: null, authorizedScopes: [] } }],
    })
    await expect(
      listAgentApiResources(deps, principal(), { limit: 10, offset: 0 }, 'https://auth.example.com'),
    ).resolves.toMatchObject({
      items: [
        {
          id: 'resource-1',
          scopes: expect.arrayContaining([{ value: 'projects:read', description: 'Read projects' }]),
          availability: { status: 'available' },
          connection: { status: 'not_required', displayName: null, authorizedScopes: [] },
        },
      ],
      pagination: { totalItems: 1 },
    })
    vi.mocked(deps.authorization.findResource).mockResolvedValueOnce({ ...native, scopeRegistry: null })
    await expect(
      listAgentAuthorizationDetailCatalog(deps, native.id, principal(), { limit: 10, offset: 0 }),
    ).resolves.toMatchObject({ pagination: { totalItems: 2 } })
    const personalIdentity = identityAggregate()
    personalIdentity.identity.ownerUserId = 'user-1'
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(personalIdentity)
    await expect(discoverAgentResources(deps, principal())).resolves.toMatchObject({
      items: [{ id: native.id }],
    })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    const created = await createAccessRequest(
      deps,
      {
        resourceServerId: 'resource-1',
        scopes: ['projects:read'],
        authorizationDetails: [organizationAuthority],
        reason: 'Read projects',
      },
      principal(),
      'https://auth.example.com/',
    )
    expect(created).toMatchObject({
      resourceServerId: 'resource-1',
      authorizationDetails: [organizationAuthority],
      status: 'approved',
      interaction: { status: 'completed' },
      credentialOffer: { scopes: ['projects:read'] },
    })
    expect(created).not.toHaveProperty('grantId')
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      id: created.id,
      connectionId: null,
      authorizationDetails: [organizationAuthority],
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    await expect(getAccessRequest(deps, created.id, principal(), 'https://auth.example.com')).resolves.toMatchObject({
      id: created.id,
      status: 'approved',
    })
    await expect(
      createAccessRequest(
        deps,
        {
          resourceServerId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: [organizationAuthority],
        },
        principal(),
        'https://auth.example.com/',
      ),
    ).resolves.toMatchObject({ reason: null })

    vi.mocked(deps.authorization.listActiveUserScopeEntitlements).mockResolvedValue([
      { ...grantRecord(), organizationId: 'org-1' },
    ])
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])
    await expect(
      createAccessRequest(
        deps,
        {
          resourceServerId: 'resource-1',
          scopes: ['projects:read'],
          authorizationDetails: [organizationAuthority],
        },
        principal(),
        'https://auth.example.com/',
      ),
    ).resolves.toMatchObject({
      status: 'pending',
      interaction: {
        status: 'pending',
        url: expect.stringContaining('/agent/access#token='),
        expiresAt: expect.any(String),
      },
    })
    const stored = vi.mocked(deps.externalResources.createAccessRequest).mock.calls[0]![0]
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(stored)
    await expect(getAgentAccessRequest(deps, stored.id, principal())).resolves.toMatchObject({ id: stored.id })
    await expect(getAccessRequest(deps, stored.id, principal(), 'https://auth.example.com')).resolves.toMatchObject({
      resourceServerId: stored.resourceId,
      authorizationDetails: stored.authorizationDetails,
    })
  })

  it("uses a personal Agent controller's active Organization memberships for private Resource Server visibility [spec: agent-identity/agent-private-resource-server-visibility]", async () => {
    const deps = createTestDeps()
    const privateNative = { ...nativeResource(), visibility: 'private' as const }
    const personalIdentity = identityAggregate()
    personalIdentity.identity.ownerUserId = 'user-1'
    Object.assign(deps.authorization, {
      findResource: vi.fn().mockResolvedValue(privateNative),
      listEnabledResources: vi.fn().mockResolvedValue([privateNative]),
      listUserMemberships: vi.fn().mockResolvedValue([
        { organizationId: privateNative.ownerOrganizationId, roles: [] },
        { organizationId: 'org-2', roles: [] },
      ]),
      findOrganization: vi.fn().mockImplementation(async (id: string) => ({
        id,
        name: id === 'org-1' ? 'Owner Organization' : 'Other Active Organization',
        displayName: null,
        disabled: false,
      })),
    })
    vi.mocked(deps.users.getUser).mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      displayName: 'Personal Controller',
    } as never)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(personalIdentity)
    const personalPrincipal = {
      ...principal(),
      identity: personalIdentity.identity,
      binding: personalIdentity.bindings[0]!,
    }

    await expect(discoverAgentResources(deps, personalPrincipal)).resolves.toMatchObject({
      items: [{ id: privateNative.id }],
    })
    await expect(
      listAgentAuthorizationDetailCatalog(deps, privateNative.id, personalPrincipal, { limit: 10, offset: 0 }),
    ).resolves.toMatchObject({
      items: [
        expect.objectContaining({ authorizationDetail: userAuthority }),
        expect.objectContaining({ authorizationDetail: organizationAuthority }),
        expect.objectContaining({
          authorizationDetail: { type: 'realmroot_authority', authority: 'organization', id: 'org-2' },
        }),
      ],
      pagination: { totalItems: 3 },
    })

    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([{ organizationId: 'org-other' }] as never)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({ id: 'org-other', disabled: false } as never)
    await expect(discoverAgentResources(deps, personalPrincipal)).resolves.toEqual({ items: [] })
    await expect(
      listAgentAuthorizationDetailCatalog(deps, privateNative.id, personalPrincipal, { limit: 10, offset: 0 }),
    ).rejects.toThrow('Resource Server is not visible to this Agent.')
  })

  it('discovers a personal external resource before its account is connected', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const agent = principal()
    agent.identity = {
      ...agent.identity,
      ownerUserId: 'user-1',
    }
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([])

    await expect(discoverAgentResources(deps, agent)).resolves.toMatchObject({
      items: [{ connection: { status: 'not_connected', displayName: null, authorizedScopes: [] } }],
    })
    await expect(
      listAgentApiResources(deps, agent, { limit: 10, offset: 0 }, 'https://auth.example.com'),
    ).resolves.toMatchObject({
      items: [{ authorization: { issuer: 'https://projects.example.com' } }],
    })
    expect(deps.externalResources.listConnectionsByUser).toHaveBeenCalledWith('user-1')
  })

  it('exposes Organization and User tenant authority as separate Realmroot Resources [spec: agent-identity/realmroot-built-in-resource-server] [spec: management-api/management-canonical-authority-inventory]', async () => {
    const deps = createTestDeps()
    const builtIn = {
      ...nativeResource(),
      id: 'res_realmroot',
      identifier: 'realmroot',
      name: 'Realmroot',
      resourceUrl: 'https://auth.example.com/api',
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([
      { organizationId: 'org-1', roles: ['owner'] } as never,
    ])
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({
      id: 'org-1',
      name: 'Example Organization',
      displayName: null,
      disabled: false,
    } as never)
    vi.mocked(deps.users.getUser).mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      displayName: 'Example User',
      role: 'admin',
    } as never)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    mockResourceOpenApi(deps, builtIn.resourceUrl)

    const result = await listAgentAuthorizationDetailCatalog(deps, builtIn.id, principal(), { limit: 10, offset: 0 })

    expect(result.pagination.totalItems).toBe(2)
    expect(result.items).toEqual([
      expect.objectContaining({ id: 'user-1', name: 'Example User' }),
      expect.objectContaining({
        id: 'org-1',
        authorizationDetail: expect.objectContaining({ type: 'realmroot_authority' }),
        name: 'Example Organization',
      }),
    ])

    const userPrincipal = principal()
    userPrincipal.identity = {
      ...userPrincipal.identity,
      ownerUserId: 'user-1',
    }
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([
      { organizationId: 'org-1', roles: ['owner'] } as never,
      { organizationId: 'org-1', roles: ['owner'] } as never,
      { organizationId: 'org-disabled', roles: ['owner'] } as never,
    ])
    vi.mocked(deps.authorization.findOrganization).mockImplementation(async (id) =>
      id === 'org-1'
        ? ({ id, name: 'Example Organization', displayName: null, disabled: false } as never)
        : ({ id, name: 'Disabled', displayName: null, disabled: true } as never),
    )
    expect(
      (await listAgentAuthorizationDetailCatalog(deps, builtIn.id, userPrincipal, { limit: 10, offset: 0 })).items,
    ).toEqual([
      expect.objectContaining({ name: 'Example User' }),
      expect.objectContaining({ name: 'Example Organization' }),
    ])

    vi.mocked(deps.authorization.findResource).mockResolvedValue({ ...builtIn, scopeRegistry: null })
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([])
    vi.mocked(deps.users.getUser).mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      displayName: null,
    } as never)
    await expect(
      listAgentAuthorizationDetailCatalog(deps, builtIn.id, userPrincipal, { limit: 10, offset: 1 }),
    ).resolves.toMatchObject({ pagination: { totalItems: 1 }, items: [] })
  })

  it('reads Realmroot Resource Servers and authority Resources without exposing protocol internals', async () => {
    const deps = createTestDeps()
    const builtIn = {
      ...nativeResource(),
      id: 'res_realmroot',
      identifier: 'realmroot',
      name: 'Realmroot',
      resourceUrl: 'https://auth.example.com/api',
    }
    Object.assign(deps.authorization, {
      findResource: vi.fn().mockResolvedValue(builtIn),
      listEnabledResources: vi.fn().mockResolvedValue([builtIn]),
      listUserMemberships: vi.fn().mockResolvedValue([{ organizationId: 'org-1', roles: ['owner'] }]),
    })
    vi.mocked(deps.users.getUser).mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      displayName: null,
      role: 'member',
    } as never)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({
      id: 'org-1',
      name: 'Example Organization',
      displayName: 'Organization Display',
      disabled: false,
    } as never)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    const accountAuthority = { type: 'realmroot_authority', authority: 'organization', id: 'org-1' }
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      {
        ...grantRecord(),
        resourceServerId: builtIn.id,
        connectionId: null,
        authorizationDetails: [accountAuthority],
        scope: 'users:read',
      },
      { ...grantRecord(), id: 'wrong-resource', resourceServerId: 'other', authorizationDetails: [accountAuthority] },
      { ...grantRecord(), id: 'wrong-authority', resourceServerId: builtIn.id, authorizationDetails: [] },
    ])

    await expect(
      getAgentResourceServer(deps, builtIn.id, principal(), 'https://auth.example.com/'),
    ).resolves.toMatchObject({ id: builtIn.id, connection: { status: 'not_required' } })
    const details = await listAgentAuthorizationDetailCatalog(deps, builtIn.id, principal(), { limit: 10, offset: 0 })
    expect(details.items).toHaveLength(2)
    expect(details.items[1]).toMatchObject({
      name: 'Organization Display',
      authorizationDetail: { type: 'realmroot_authority' },
      authorizedScopes: ['users:read'],
    })

    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([])
    await expect(getAgentResourceServer(deps, 'missing', principal(), 'https://auth.example.com')).rejects.toThrow(
      'Resource Server was not found.',
    )
  })

  it('[spec: agent-identity/realmroot-built-in-resource-server] isolates platform bootstrap, direct, and Role scopes by Context', async () => {
    const deps = createTestDeps()
    const scopeValues = [
      'agents:read',
      'agents:write',
      'audit-events:read',
      'organizations:read',
      'connectors:read',
      'applications:read',
      'applications:write',
      'users:read',
      'users:write',
    ]
    const builtIn = {
      ...nativeResource(),
      id: 'res_realmroot',
      identifier: 'realmroot',
      resourceUrl: 'https://auth.example.com/api',
      scopeRegistry: {
        ...nativeResource().scopeRegistry!,
        scopes: scopeValues.map((value) => ({
          value,
          description: null,
          grantMode: value === 'organizations:read' ? ('automatic' as const) : ('assigned' as const),
        })),
      },
    }
    const personalIdentity = identityAggregate()
    personalIdentity.identity = { ...personalIdentity.identity, ownerUserId: 'user-1' }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([
      { organizationId: 'org-1', roles: ['role-1'] } as never,
      { organizationId: 'org-2', roles: ['role-2'] } as never,
    ])
    vi.mocked(deps.authorization.findOrganization).mockImplementation(
      async (id) => ({ id, name: id, displayName: null, disabled: false }) as never,
    )
    vi.mocked(deps.authorization.listActiveUserScopeEntitlements).mockResolvedValue([
      { scope: 'connectors:read', organizationId: null } as never,
      { scope: 'applications:read', organizationId: 'org-1' } as never,
      { scope: 'applications:write', organizationId: 'org-2' } as never,
    ])
    vi.mocked(deps.authorization.listOrganizationRoleScopes).mockImplementation(async (organizationId) =>
      organizationId === 'org-1'
        ? new Map([['role-1', [{ resourceId: builtIn.id, scope: 'users:read' }]]])
        : new Map([['role-2', [{ resourceId: builtIn.id, scope: 'users:write' }]]]),
    )
    vi.mocked(deps.users.getUser).mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      displayName: 'User',
    } as never)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(personalIdentity)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])

    const personalPrincipal = {
      ...principal(),
      identity: personalIdentity.identity,
      binding: personalIdentity.bindings[0]!,
    }
    const catalog = await listAgentAuthorizationDetailCatalog(deps, builtIn.id, personalPrincipal, {
      limit: 10,
      offset: 0,
    })
    const scopesFor = (authority: 'user' | 'organization', id: string) =>
      catalog.items.find(
        (item) => item.authorizationDetail.authority === authority && item.authorizationDetail.id === id,
      )?.requestableScopes

    expect(scopesFor('user', 'user-1')).toEqual([
      'agents:read',
      'agents:write',
      'audit-events:read',
      'connectors:read',
      'organizations:read',
    ])
    expect(scopesFor('organization', 'org-1')).toEqual(['applications:read', 'organizations:read', 'users:read'])
    expect(scopesFor('organization', 'org-2')).toEqual(['applications:write', 'organizations:read', 'users:write'])
  })

  it('[spec: agent-identity/native-api-automatic-agent-permission] automatically approves all-automatic native scopes through persistent Permissions', async () => {
    const { deps, native, personalIdentity, selectedContext } = automaticNativeAccessDeps({
      'projects:read': 'automatic',
      'projects:write': 'automatic',
    })
    let created: AgentAccessRequestRecord | null = null
    vi.mocked(deps.externalResources.createAccessRequestWithAudit).mockImplementation(async (request) => {
      created = request
      return request
    })
    vi.mocked(deps.externalResources.findAccessRequest).mockImplementation(async (id) =>
      created?.id === id ? created : null,
    )
    vi.mocked(deps.externalResources.approveAccessRequestWithEntitlements).mockImplementation(
      async (entitlements, _updates, requestId, decision) => ({
        entitlements,
        request: { ...created!, id: requestId, ...decision },
      }),
    )

    const access = await createAgentAccessRequest(
      deps,
      {
        resourceId: native.id,
        scopes: ['projects:write', 'projects:read'],
        authorizationDetails: [selectedContext],
      },
      { ...principal(), identity: personalIdentity.identity, binding: personalIdentity.bindings[0]! },
      'https://auth.example.com',
    )

    expect(access).toMatchObject({
      status: 'approved',
      approvalUrl: null,
      scopes: ['projects:read', 'projects:write'],
      approvedEntitlements: [
        { scope: 'projects:read', entitlementId: expect.any(String) },
        { scope: 'projects:write', entitlementId: expect.any(String) },
      ],
    })
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenCalledWith(
      [
        expect.objectContaining({
          scope: 'projects:read',
          mode: 'persistent',
          grantedByUserId: 'user-1',
          authorizationDetails: [selectedContext],
        }),
        expect.objectContaining({
          scope: 'projects:write',
          mode: 'persistent',
          grantedByUserId: 'user-1',
          authorizationDetails: [selectedContext],
        }),
      ],
      [],
      created!.id,
      expect.objectContaining({ status: 'approved', authorizationDetails: [selectedContext] }),
      expect.objectContaining({ reasonCode: 'automatic_scope_policy' }),
    )
  })

  it('[spec: agent-identity/native-api-automatic-agent-permission] reuses a concurrent approval of the same automatic request', async () => {
    const { deps, native, personalIdentity, selectedContext } = automaticNativeAccessDeps({
      'projects:read': 'automatic',
    })
    let created: AgentAccessRequestRecord | null = null
    const concurrentEntitlement = {
      ...grantRecord(),
      id: 'entitlement-from-concurrent-request',
      agentIdentityId: personalIdentity.identity.id,
      resourceServerId: native.id,
      connectionId: null,
      scope: 'projects:read',
      authorizationDetails: [selectedContext],
    }
    vi.mocked(deps.externalResources.createAccessRequestWithAudit).mockImplementation(async (request) => {
      created = request
      return request
    })
    vi.mocked(deps.externalResources.findAccessRequest).mockImplementation(async (id) =>
      created?.id === id ? created : null,
    )
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValueOnce([]).mockResolvedValueOnce([])
    vi.mocked(deps.externalResources.approveAccessRequestWithEntitlements).mockImplementationOnce(async () => {
      created = {
        ...created!,
        status: 'approved',
        approvedEntitlements: [{ scope: 'projects:read', entitlementId: concurrentEntitlement.id }],
      }
      return 'entitlements_changed'
    })

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: native.id,
          scopes: ['projects:read'],
          authorizationDetails: [selectedContext],
        },
        { ...principal(), identity: personalIdentity.identity, binding: personalIdentity.bindings[0]! },
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: concurrentEntitlement.id }],
    })
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenCalledOnce()
  })

  it('[spec: agent-identity/native-api-automatic-agent-permission] retries when another request creates the Permission first', async () => {
    const { deps, native, personalIdentity, selectedContext } = automaticNativeAccessDeps({
      'projects:read': 'automatic',
    })
    let created: AgentAccessRequestRecord | null = null
    const concurrentEntitlement = {
      ...grantRecord(),
      id: 'entitlement-from-other-request',
      agentIdentityId: personalIdentity.identity.id,
      resourceServerId: native.id,
      connectionId: null,
      scope: 'projects:read',
      authorizationDetails: [selectedContext],
    }
    vi.mocked(deps.externalResources.createAccessRequestWithAudit).mockImplementation(async (request) => {
      created = request
      return request
    })
    vi.mocked(deps.externalResources.findAccessRequest).mockImplementation(async (id) =>
      created?.id === id ? created : null,
    )
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([concurrentEntitlement])
    vi.mocked(deps.externalResources.approveAccessRequestWithEntitlements)
      .mockResolvedValueOnce('entitlements_changed')
      .mockImplementationOnce(async (_entitlements, _updates, requestId, decision) => ({
        entitlements: [],
        request: { ...created!, id: requestId, ...decision },
      }))

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: native.id,
          scopes: ['projects:read'],
          authorizationDetails: [selectedContext],
        },
        { ...principal(), identity: personalIdentity.identity, binding: personalIdentity.bindings[0]! },
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: concurrentEntitlement.id }],
    })
    expect(deps.externalResources.approveAccessRequestWithEntitlements).toHaveBeenCalledTimes(2)
  })

  it('[spec: agent-identity/native-api-automatic-agent-permission] keeps any assigned native scope pending', async () => {
    const { deps, native, personalIdentity, selectedContext } = automaticNativeAccessDeps({
      'projects:read': 'automatic',
      'projects:write': 'assigned',
    })
    vi.mocked(deps.authorization.listActiveUserScopeEntitlements).mockResolvedValue([
      { ...grantRecord(), scope: 'projects:write', organizationId: null },
    ])

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: native.id,
          scopes: ['projects:read', 'projects:write'],
          authorizationDetails: [selectedContext],
        },
        { ...principal(), identity: personalIdentity.identity, binding: personalIdentity.bindings[0]! },
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ status: 'pending', approvalUrl: expect.stringContaining('/agent/access#token=') })
    expect(deps.externalResources.approveAccessRequestWithEntitlements).not.toHaveBeenCalled()
  })

  it('[spec: agent-identity/native-api-automatic-agent-permission] rejects an unavailable authority Context without granting Permissions', async () => {
    const { deps, native, personalIdentity } = automaticNativeAccessDeps({ 'projects:read': 'automatic' })

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: native.id,
          scopes: ['projects:read'],
          authorizationDetails: [{ type: 'realmroot_authority', authority: 'user', id: 'user-2' }],
        },
        { ...principal(), identity: personalIdentity.identity, binding: personalIdentity.bindings[0]! },
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Realmroot authority Context is not available to this Agent owner.')
    expect(deps.externalResources.createAccessRequestWithAudit).not.toHaveBeenCalled()
    expect(deps.externalResources.approveAccessRequestWithEntitlements).not.toHaveBeenCalled()
  })

  it('rejects ungrantable personal scopes before creating or resuming approval [spec: agent-identity/native-api-resource-access-request]', async () => {
    const deps = createTestDeps()
    const builtIn = {
      ...nativeResource(),
      identifier: 'realmroot',
      scopeRegistry: {
        ...nativeResource().scopeRegistry!,
        scopes: ['applications:read', 'permissions:read', 'agents:read'].map((value) => ({
          value,
          description: null,
          grantMode: 'assigned' as const,
        })),
      },
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])
    vi.mocked(deps.authorization.listActiveUserScopeEntitlements).mockResolvedValue([])
    const authorizationDetails = [{ type: 'realmroot_authority', authority: 'user', id: 'user-1' }]
    vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([
      {
        ...requestRecord(),
        connectionId: null,
        scopes: ['applications:read', 'permissions:read'],
        authorizationDetails,
      },
    ])

    await expect(
      createAgentAccessRequest(
        deps,
        { resourceId: builtIn.id, scopes: ['applications:read', 'permissions:read'], authorizationDetails },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toMatchObject({
      status: 400,
      code: 'bad_request',
      message: expect.stringContaining('No approval request was created.'),
      details: {
        context: { id: 'user-1', type: 'user' },
        scopes: ['applications:read', 'permissions:read'],
      },
    })
    expect(deps.externalResources.createAccessRequestWithAudit).not.toHaveBeenCalled()
    expect(deps.externalResources.approveAccessRequestWithEntitlements).not.toHaveBeenCalled()
  })

  it('validates Realmroot scopes and requires exactly one authority Resource', async () => {
    const deps = createTestDeps()
    const builtIn = {
      ...nativeResource(),
      id: 'res_realmroot',
      identifier: 'realmroot',
      name: 'Realmroot',
      resourceUrl: 'https://auth.example.com/api',
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())

    await expect(
      createAgentAccessRequest(
        deps,
        { resourceId: builtIn.id, scopes: ['unknown:read'], authorizationDetails: [] },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('scope is not declared')
    await expect(
      createAgentAccessRequest(
        deps,
        { resourceId: builtIn.id, scopes: ['users:read'], authorizationDetails: [] },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('exactly one Realmroot authority Context')

    const organizationAuthority = { type: 'realmroot_authority', authority: 'organization', id: 'org-1' }
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue({
      ...identityAggregate(),
      identity: { ...identityAggregate().identity, ownerUserId: 'user-1' },
    })
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      resourceId: builtIn.id,
      connectionId: null,
      scopes: ['users:read'],
      authorizationDetails: [organizationAuthority],
    })
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([
      { organizationId: 'org-1', roles: [] },
    ] as never)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({ id: 'org-1', disabled: false } as never)
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([
      { organizationId: 'org-1', roles: ['owner'] },
    ] as never)
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([
      { organizationId: 'org-1', roles: ['owner'] },
    ] as never)
    await expect(
      decideAgentAccessRequest(
        deps,
        'request-1',
        { decision: 'approve', mode: 'persistent', authorizationDetails: [organizationAuthority] },
        'user-1',
      ),
    ).rejects.toThrow('controller effective scope')

    const otherUserAuthority = { type: 'realmroot_authority', authority: 'user', id: 'user-2' }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      resourceId: builtIn.id,
      connectionId: null,
      scopes: ['users:read'],
      authorizationDetails: [otherUserAuthority],
    })
    await expect(
      decideAgentAccessRequest(
        deps,
        'request-1',
        { decision: 'approve', mode: 'persistent', authorizationDetails: [otherUserAuthority] },
        'user-1',
      ),
    ).rejects.toThrow('Selected Realmroot authority Context is no longer available')
  })

  it('issues a credential from an approved Resource access request', async () => {
    const deps = createTestDeps()
    const builtIn = {
      ...nativeResource(),
      id: 'res_realmroot',
      identifier: 'realmroot',
      name: 'Realmroot',
      resourceUrl: 'https://auth.example.com/api',
    }
    const authority = { type: 'realmroot_authority', authority: 'organization', id: 'org-1' }
    const approved = {
      ...requestRecord(),
      resourceId: builtIn.id,
      connectionId: null,
      scopes: ['users:read'],
      authorizationDetails: [authority],
      status: 'approved' as const,
      approvedEntitlements: [{ scope: 'users:read', entitlementId: 'ent_1' }],
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({ id: 'org-1', disabled: false } as never)
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([
      { organizationId: 'org-1', roles: ['owner'] },
    ] as never)
    Object.assign(deps.authorization, { listTeamNamesForUser: vi.fn().mockResolvedValue([]) })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(approved)
    const entitlement = {
      ...grantRecord(),
      resourceServerId: builtIn.id,
      connectionId: null,
      scope: approved.scopes[0],
      authorizationDetails: [authority],
      mode: 'persistent',
    } as ResourceScopeEntitlementRecord
    const expandedEntitlement = { ...entitlement, id: 'ent_2', scope: 'users:write' }
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(entitlement)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      entitlement,
      expandedEntitlement,
    ])
    const signer = { issuer: principal().issuer, sign: vi.fn().mockResolvedValue('credential-token') }
    const endpoint = `https://auth.example.com/api/agent/access-requests/${approved.id}/credentials`

    await expect(
      createAccessRequestCredential(deps, approved.id, await createDpopProof(endpoint), endpoint, principal(), signer),
    ).resolves.toMatchObject({
      accessToken: 'credential-token',
      scopes: ['users:read', 'users:write'],
      resourceIndicator: builtIn.resourceUrl,
      authorizationDetails: [authority],
    })

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...approved,
      status: 'pending',
      approvedEntitlements: [],
    })
    await expect(
      createAccessRequestCredential(deps, approved.id, 'proof', endpoint, principal(), signer),
    ).rejects.toThrow('Approved Resource access is required.')
  })

  it('uses connected authorization details as the Resource catalog when no catalog endpoint exists', async () => {
    const deps = createTestDeps()
    const detail = { type: 'project_access', project_id: 'project-1', actions: ['read'] }
    const external = { ...resource(), authorizationDetails: [{ type: 'project_access', actions: ['read'] }] }
    const numericDetail = { type: 'project_access', project_id: 2, actions: ['read'] }
    const typeOnlyDetail = { type: 'project_access', actions: ['read'] }
    const connection = {
      ...connectionRecord(),
      authorizationDetails: [detail, numericDetail, typeOnlyDetail],
      grantedScopes: ['openid', 'offline_access', 'projects:read', 'projects:write'],
    }
    authorizationDeps(deps)
    vi.mocked(deps.authorization.findResource).mockResolvedValue(external)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connection])
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grantRecord(), authorizationDetails: [detail], mode: 'persistent' },
      { ...grantRecord(), id: 'wrong-resource', resourceServerId: 'other', authorizationDetails: [detail] },
      { ...grantRecord(), id: 'wrong-connection', connectionId: 'other', authorizationDetails: [detail] },
      {
        ...grantRecord(),
        id: 'revoked',
        endedAt: now,
        endReason: 'revoked',
        authorizationDetails: [detail],
      },
      { ...grantRecord(), id: 'expired', expiresAt: new Date(0), authorizationDetails: [detail] },
      { ...grantRecord(), id: 'other-detail', authorizationDetails: [{ ...detail, project_id: 'project-2' }] },
    ])
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())

    const catalog = await listAgentAuthorizationDetailCatalog(deps, external.id, principal(), { limit: 10, offset: 0 })
    expect(catalog.items[0]).toMatchObject({
      authorizationDetail: detail,
      name: 'project-1',
      metadata: { project_id: 'project-1' },
      accountAuthorizationStatus: 'authorized',
      authorizedScopes: ['projects:read'],
      requestableScopes: ['projects:write'],
    })
    expect(catalog.pagination.totalItems).toBe(3)
    expect(catalog.items[1]).toMatchObject({ name: '2', metadata: { project_id: '2' } })
    expect(catalog.items[2]).toMatchObject({ name: 'project_access', metadata: {} })

    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])
    const created = await createAccessRequest(
      deps,
      { resourceServerId: external.id, scopes: ['projects:read'], authorizationDetails: [detail] },
      principal(),
      'https://auth.example.com',
    )
    expect(created).toMatchObject({ resourceServerId: external.id, authorizationDetails: [detail] })
  })

  it('renders Realmroot authority approval and credential offers', async () => {
    const deps = createTestDeps()
    const builtIn = {
      ...nativeResource(),
      id: 'res_realmroot',
      identifier: 'realmroot',
      name: 'Realmroot',
      resourceUrl: 'https://auth.example.com/api',
    }
    const authority = { type: 'realmroot_authority', authority: 'organization', id: 'org-1' }
    const approved = {
      ...requestRecord(),
      resourceId: builtIn.id,
      connectionId: null,
      scopes: ['users:read'],
      authorizationDetails: [authority],
      status: 'approved' as const,
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({
      id: 'org-1',
      name: 'Organization',
      displayName: 'Organization Display',
      disabled: false,
    } as never)
    vi.mocked(deps.authorization.findMemberByOrganizationUser).mockResolvedValue({
      id: 'member-1',
      organizationId: 'org-1',
      userId: 'user-1',
      roles: ['owner'],
    } as never)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    const pending = { ...approved, status: 'pending' as const, approvedEntitlements: [] }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(pending)
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(pending)

    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).resolves.toMatchObject({
      requiresAccountConnection: false,
      authorizationDetail: { name: 'Organization Display' },
    })
    await expect(getControllerAccessRequestByToken(deps, 'approval-token', 'user-1')).resolves.toMatchObject({
      id: approved.id,
    })

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(approved)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      {
        ...grantRecord(),
        resourceServerId: builtIn.id,
        connectionId: null,
        scope: 'users:read',
        authorizationDetails: [authority],
      },
      {
        ...grantRecord(),
        id: 'ent_2',
        resourceServerId: builtIn.id,
        connectionId: null,
        scope: 'users:write',
        authorizationDetails: [authority],
      },
    ])
    await expect(getAccessRequest(deps, approved.id, principal(), 'https://auth.example.com')).resolves.toMatchObject({
      credentialOffer: {
        type: 'dpop',
        resourceIndicator: builtIn.resourceUrl,
        scopes: ['users:read', 'users:write'],
        endpoint: expect.stringContaining('/credentials'),
      },
    })

    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(approved)
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).rejects.toThrow('not found')

    const serviceRequest = {
      ...pending,
      authorizationDetails: [],
    }
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(serviceRequest)
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(serviceRequest)
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).resolves.toMatchObject({
      authorizationDetail: null,
    })
  })

  it('requires one available authority Context for native Resource Servers', async () => {
    const nativeDeps = createTestDeps()
    const native = nativeResource()
    vi.mocked(nativeDeps.authorization.findResource).mockResolvedValue(native)
    vi.mocked(nativeDeps.authorization.findOrganization).mockImplementation(async (id) =>
      id === 'org-1' ? ({ id, name: 'Organization', disabled: false } as never) : null,
    )
    vi.mocked(nativeDeps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    mockResourceOpenApi(nativeDeps, native.resourceUrl)
    await expect(
      createAccessRequest(
        nativeDeps,
        {
          resourceServerId: native.id,
          scopes: ['projects:read'],
          authorizationDetails: [{ type: 'project_access', project_id: 'project-1' }],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Select exactly one Realmroot authority Context.')
    for (const authorizationDetails of [
      [],
      [organizationAuthority, userAuthority],
      [{ ...organizationAuthority, id: 'org-unavailable' }],
    ]) {
      await expect(
        createAccessRequest(
          nativeDeps,
          { resourceServerId: native.id, scopes: ['projects:read'], authorizationDetails },
          principal(),
          'https://auth.example.com',
        ),
      ).rejects.toMatchObject({ error: 'invalid_authorization_details' })
    }

    const realmrootDeps = createTestDeps()
    const builtIn = {
      ...native,
      id: 'resource-realmroot',
      identifier: 'realmroot',
      resourceUrl: 'https://auth.example.com/api',
    }
    vi.mocked(realmrootDeps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(realmrootDeps.authorization.listUserMemberships).mockResolvedValue([])
    vi.mocked(realmrootDeps.users.getUser).mockResolvedValue({
      id: 'user-1',
      email: 'user@example.com',
      role: 'member',
    } as never)
    vi.mocked(realmrootDeps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    await expect(
      createAccessRequest(
        realmrootDeps,
        { resourceServerId: builtIn.id, scopes: ['users:read'] },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Select exactly one Realmroot authority Context.')

    const externalDeps = createTestDeps()
    authorizationDeps(externalDeps)
    vi.mocked(externalDeps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(externalDeps.externalResources.findConnectionByOwnerResource).mockResolvedValue(null)
    await expect(
      createAccessRequest(
        externalDeps,
        { resourceServerId: resource().id, scopes: ['projects:read'] },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ status: 'pending', interaction: { status: 'pending' } })

    vi.mocked(externalDeps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    await expect(
      createAccessRequest(
        externalDeps,
        {
          resourceServerId: resource().id,
          scopes: ['projects:read'],
          authorizationDetails: [{ type: 'unsupported' }],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('does not use authorization details')
  })

  it('rejects malformed Realmroot authority approval records', async () => {
    const deps = createTestDeps()
    const builtIn = {
      ...nativeResource(),
      id: 'resource-realmroot',
      identifier: 'realmroot',
      resourceUrl: 'https://auth.example.com/api',
    }
    const pending = {
      ...requestRecord(),
      resourceId: builtIn.id,
      connectionId: null,
      authorizationDetails: [{ type: 'realmroot_authority', authority: 'unknown', id: 'bad' }],
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(deps.authorization.findMemberByOrganizationUser).mockResolvedValue({
      id: 'member-1',
      organizationId: 'org-1',
      userId: 'user-1',
      roles: ['owner'],
    } as never)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(pending)
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(pending)

    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).rejects.toThrow(
      'Native Resource authority is invalid.',
    )
  })

  it('represents every Resource access interaction state', async () => {
    const deps = createTestDeps()
    const native = nativeResource()
    vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())

    for (const [status, interaction] of [
      ['pending', 'pending'],
      ['denied', 'denied'],
      ['expired', 'expired'],
      ['consumed', 'completed'],
    ] as const) {
      vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
        ...requestRecord(),
        connectionId: null,
        status,
        approvedEntitlements: status === 'consumed' ? [{ scope: 'projects:read', entitlementId: 'ent_1' }] : [],
      })
      await expect(getAccessRequest(deps, 'request-1', principal(), 'https://auth.example.com')).resolves.toMatchObject(
        {
          status,
          interaction: { status: interaction },
        },
      )
    }
  })

  it('filters unavailable Realmroot authorities and paginates singleton service Resources', async () => {
    const deps = createTestDeps()
    const builtIn = {
      ...nativeResource(),
      id: 'resource-realmroot',
      identifier: 'realmroot',
      resourceUrl: 'https://auth.example.com/api',
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({
      id: 'org-1',
      name: 'Organization',
      displayName: null,
      disabled: false,
    } as never)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    const authorities = await listAgentAuthorizationDetailCatalog(deps, builtIn.id, principal(), {
      limit: 10,
      offset: 0,
    })
    expect(authorities.items).toHaveLength(1)

    const native = nativeResource()
    vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
    mockResourceOpenApi(deps, native.resourceUrl)
    await expect(
      listAgentAuthorizationDetailCatalog(deps, native.id, principal(), { limit: 10, offset: 1 }),
    ).resolves.toMatchObject({ items: [], pagination: { totalItems: 1 } })
  })

  it('derives compact display labels for provider-owned authorization details', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue({
      ...connectionRecord(),
      authorizationDetails: [
        { type: 'project_access', name: 'Named project' },
        { type: 'project_access', project_name: 'Provider project' },
        { type: 'project_access', project_label: 'Labelled project' },
        { type: 'project_access', identifier: 42 },
        { type: 'project_access', attributes: { internal: true } },
      ],
    })

    await expect(
      listAgentAuthorizationDetailCatalog(deps, resource().id, principal(), { limit: 10, offset: 0 }),
    ).resolves.toMatchObject({
      items: [
        { name: 'Named project', metadata: { name: 'Named project' } },
        { name: 'Provider project', metadata: { project_name: 'Provider project' } },
        { name: 'Labelled project', metadata: { project_label: 'Labelled project' } },
        { name: '42', metadata: { identifier: '42' } },
        { name: 'project_access', metadata: {} },
      ],
    })
  })

  it('resolves approval Resources through a paginated external catalog', async () => {
    const deps = authorizationCatalogDeps()
    const catalogConnector = await deps.connectors.findById('connector-1')
    vi.mocked(deps.connectors.findById).mockResolvedValue({
      ...catalogConnector!,
      resourceRegistrationMode: 'manual',
    })
    const requested = { type: 'project_access', project_id: 'project-2', actions: ['read'] }
    const pending = { ...requestRecord(), authorizationDetails: [requested] }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(pending)
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(pending)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue({
      ...connectionRecord(),
      grantedScopes: [...connectionRecord().grantedScopes, 'authorization-details:read'],
    })
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([grantRecord()])
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      const url = new URL(request.url)
      if (url.pathname !== '/authorization-details') return new Response(null, { status: 404 })
      const page = Number(url.searchParams.get('page'))
      if (page === 1) {
        return Response.json({
          items: [
            {
              authorizationDetail: { type: 'project_access', project_id: 'project-1', actions: ['read'] },
              display: { label: 'Project One' },
            },
          ],
          pagination: {
            page: Math.floor(0 / 100) + 1,
            pageSize: 100,
            totalItems: 101,
            totalPages: Math.ceil(101 / 100),
          },
        })
      }
      return Response.json({
        items: [
          {
            authorizationDetail: requested,
            display: { label: 'Project Two', description: 'Second project', metadata: { project: '2' } },
          },
        ],
        pagination: {
          page: Math.floor(100 / 100) + 1,
          pageSize: 100,
          totalItems: 101,
          totalPages: Math.ceil(101 / 100),
        },
      })
    })

    await expect(
      createAgentAccessRequest(
        deps,
        { resourceId: resource().id, scopes: ['projects:read'], authorizationDetails: [requested] },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ authorizationDetails: [requested] })

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: resource().id,
          scopes: ['projects:read'],
          authorizationDetails: [{ ...requested, project_id: 'missing' }],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Authorization detail is not available through this Resource Server connection.')

    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(null)
    await expect(
      createAgentAccessRequest(
        deps,
        { resourceId: resource().id, scopes: ['projects:read'], authorizationDetails: [requested] },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Connect the Resource Server before selecting authorization details.')

    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).resolves.toMatchObject({
      authorizationDetail: {
        name: 'Project Two',
        description: 'Second project',
        metadata: { project: '2' },
      },
    })

    const fallbackDisplay = { ...pending, authorizationDetails: [{ ...requested, project_id: 'project-1' }] }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(fallbackDisplay)
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(fallbackDisplay)
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).resolves.toMatchObject({
      authorizationDetail: { name: 'Project One', description: null, metadata: {} },
    })

    const missing = { ...pending, authorizationDetails: [{ ...requested, project_id: 'missing' }] }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(missing)
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(missing)
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).rejects.toThrow(
      'Authorization detail was not found.',
    )
  })

  it('advertises the external authorization server token endpoint in credential offers', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(
      connectionWithCredential(connectionRecord(), { clientGeneration: 2 }),
    )
    vi.mocked(deps.connectors.findById).mockResolvedValue(
      connectorRecord({
        resourceClientGeneration: 3,
        resourceRetiredClientGenerations: [
          {
            generation: 2,
            clientId: 'old-client',
            encryptedClientSecret: 'sealed:old-secret',
            clientSecretContext: 'connector:connector-1:client-generation:2:client-secret',
            registrationClientUri: null,
            encryptedRegistrationAccessToken: null,
            registrationAccessTokenContext: null,
            registeredScopes: ['projects:read'],
          },
        ],
      }),
    )
    const approved = {
      ...requestRecord(),
      status: 'approved' as const,
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(approved)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([grantRecord()])

    await expect(getAccessRequest(deps, approved.id, principal(), 'https://auth.example.com')).resolves.toMatchObject({
      credentialOffer: { proof: { uri: 'https://projects.example.com/token' } },
    })

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({ ...approved, connectionId: null })
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord({ resourceClientGeneration: undefined }))
    await expect(getAccessRequest(deps, approved.id, principal(), 'https://auth.example.com')).resolves.toMatchObject({
      credentialOffer: null,
      links: { credentials: null },
    })

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(approved)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(
      connectionWithCredential(connectionRecord(), { clientGeneration: 99 }),
    )
    await expect(getAccessRequest(deps, approved.id, principal(), 'https://auth.example.com')).rejects.toThrow(
      'Active external API resource authorization was not found.',
    )
  })

  it('keeps an unbound external approval available while requiring bound connections to remain active', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const detail = { type: 'project_access', project_id: 'project-1', actions: ['read'] }
    const pending = { ...requestRecord(), authorizationDetails: [detail] }
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(pending)
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(pending)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(null)
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).rejects.toThrow(
      'Resource account connection was not found.',
    )

    vi.mocked(deps.externalResources.findConnection).mockResolvedValue({ ...connectionRecord(), status: 'revoked' })
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).rejects.toThrow(
      'Active resource account connection was not found.',
    )

    const unconnected = { ...pending, connectionId: null }
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(unconnected)
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(unconnected)
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).resolves.toMatchObject({
      id: unconnected.id,
      requiresAccountConnection: true,
    })
  })

  it('uses connected authorization details when the optional external catalog is absent', async () => {
    const request = requestRecord()
    const missingCatalog = authorizationCatalogDeps({ providerMetadata: metadata() })
    vi.mocked(missingCatalog.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    const connectedDetail = { type: 'project_access', project_id: 'project-1' }
    vi.mocked(missingCatalog.externalResources.findConnection).mockResolvedValue(
      connectionWithCredential(connectionRecord(), { authorizationDetails: [connectedDetail] }),
    )
    await expect(
      listAccountAccessRequestAuthorizationDetailCatalog(missingCatalog, request.id, 'approval-token', 'user-1', {
        limit: 100,
        offset: 0,
      }),
    ).resolves.toMatchObject({
      items: [{ authorizationDetail: connectedDetail, connectionStatus: 'authorized' }],
      pagination: { totalItems: 1 },
    })

    const mismatched = authorizationCatalogDeps({
      fetchResponse: Response.json({
        items: [],
        pagination: { page: Math.floor(0 / 99) + 1, pageSize: 99, totalItems: 0, totalPages: Math.ceil(0 / 99) },
      }),
    })
    vi.mocked(mismatched.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(request)
    vi.mocked(mismatched.externalResources.findConnection).mockResolvedValue({
      ...connectionRecord(),
      grantedScopes: [...connectionRecord().grantedScopes, 'authorization-details:read'],
    })
    await expect(
      listAccountAccessRequestAuthorizationDetailCatalog(mismatched, request.id, 'approval-token', 'user-1', {
        limit: 100,
        offset: 0,
      }),
    ).rejects.toThrow('mismatched pagination metadata')
  })

  it('rejects duplicate authorization details', async () => {
    const duplicateDeps = createTestDeps()
    authorizationDeps(duplicateDeps)
    vi.mocked(duplicateDeps.authorization.findResource).mockResolvedValue({
      ...resource(),
      authorizationDetails: [{ type: 'project_access' }],
    })
    vi.mocked(duplicateDeps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(duplicateDeps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    const detail = { type: 'project_access', project_id: 'project-1' }
    await expect(
      createAgentAccessRequest(
        duplicateDeps,
        { resourceId: resource().id, scopes: ['projects:read'], authorizationDetails: [detail, detail] },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Requested authorization details contain an unsupported or duplicate entry.')
    await expect(
      createAgentAccessRequest(
        duplicateDeps,
        {
          resourceId: resource().id,
          scopes: ['projects:read'],
          authorizationDetails: [],
        },
        principal(),
        '',
      ),
    ).resolves.toMatchObject({ resourceId: resource().id, status: 'pending' })
  })

  it('discovers enabled resources independently of deleted database history', async () => {
    const deps = createTestDeps()
    const active = nativeResource()
    const managementPage = vi.fn().mockResolvedValue({
      items: Array.from({ length: 100 }, (_, index) => ({
        ...nativeResource(),
        id: `deleted-${index}`,
        deletedAt: now,
        enabled: false,
      })),
      pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 101, totalPages: Math.ceil(101 / 100) },
    })
    Object.assign(deps.authorization, {
      findResource: vi.fn().mockResolvedValue(active),
      listResources: managementPage,
      listEnabledResources: vi.fn().mockResolvedValue([active]),
    })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    mockResourceOpenApi(deps, active.resourceUrl)

    await expect(discoverAgentResources(deps, principal())).resolves.toMatchObject({
      items: [{ id: active.id }],
    })
    expect(managementPage).not.toHaveBeenCalled()
  })

  it('[spec: agent-identity/agent-resource-discovery-isolation] marks one unavailable OpenAPI contract without hiding healthy resources', async () => {
    const deps = createTestDeps()
    const healthy = nativeResource()
    const unavailable = {
      ...nativeResource(),
      id: 'resource-unavailable',
      identifier: 'unavailable',
      resourceUrl: 'https://unavailable.example.com/api',
      scopeRegistry: null,
    }
    Object.assign(deps.authorization, {
      listResources: vi.fn().mockResolvedValue({
        items: [unavailable, healthy],
        pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 2, totalPages: Math.ceil(2 / 100) },
      }),
      listEnabledResources: vi.fn().mockResolvedValue([unavailable, healthy]),
      findResource: vi.fn().mockImplementation(async (id) => {
        if (id === healthy.id) return healthy
        if (id === unavailable.id) return unavailable
        return null
      }),
    })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.connectors.findById).mockResolvedValue(null)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])
    mockResourceOpenApi(deps, healthy.resourceUrl)

    const result = await listAgentApiResources(deps, principal(), { limit: 10, offset: 0 }, 'https://auth.example.com')
    expect(result).toMatchObject({ pagination: { totalItems: 2 } })
    expect(result.items[0]).toMatchObject({ id: unavailable.id, availability: { status: 'unavailable' }, scopes: [] })
    expect(result.items[1]).toMatchObject({ id: healthy.id, availability: { status: 'available' } })
    expect(result.items[1]?.scopes).toEqual(
      expect.arrayContaining([{ value: 'projects:read', description: 'Read projects' }]),
    )
  })

  it('lists, reads, denies, and approves controlled access requests', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    const pendingExternal = requestRecord()
    const pendingNative = { ...requestRecord(), id: 'request-2', connectionId: null }
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connectionRecord()])
    vi.mocked(deps.externalResources.listPendingAccessRequests).mockResolvedValue([pendingExternal, pendingNative])
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(pendingExternal)
    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(pendingExternal)

    await expect(listControllerAccessRequests(deps, 'user-1')).resolves.toMatchObject({
      requests: [{ id: 'request-1' }, { id: 'request-2' }],
    })
    await expect(listAccountAccessRequests(deps, 'user-1', { limit: 1, offset: 1 })).resolves.toMatchObject({
      items: [
        {
          id: 'request-2',
          requiresAccountConnection: true,
          agent: { id: 'identity-1', name: 'Project Agent' },
          authorizationDetail: null,
        },
      ],
      pagination: { totalItems: 2 },
    })
    await expect(getAccountAccessRequest(deps, 'request-1', 'user-1')).resolves.toMatchObject({ id: 'request-1' })
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).resolves.toMatchObject({
      id: 'request-1',
    })

    vi.mocked(deps.externalResources.decideAccessRequest).mockImplementation(async (_id, decision) => ({
      ...pendingExternal,
      ...decision,
    }))
    await expect(decideAgentAccessRequest(deps, 'request-1', { decision: 'deny' }, 'user-1')).resolves.toMatchObject({
      status: 'denied',
    })
    vi.mocked(deps.externalResources.approveAccessRequestWithEntitlements).mockImplementation(
      async (records, _updates, id, decision) => ({
        entitlements: records,
        request: { ...requestRecord(), id, ...decision },
      }),
    )
    await expect(
      decideAccessRequest(
        deps,
        'request-1',
        {
          decision: 'approve',
          mode: 'until',
          expiresAt: new Date(Date.now() + 600_000).toISOString(),
          approvalToken: 'approval-token',
        },
        'user-1',
      ),
    ).resolves.toMatchObject({ status: 'approved' })
  })

  it('lists grants and revokes grants, identities, and binding leases', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.listAgentPermissions).mockResolvedValue({
      items: [
        {
          entitlement: grantRecord(),
          resource: { id: 'resource-1', identifier: 'resource-1', name: 'Resource 1' },
        },
      ],
      total: 1,
      limit: 10,
      offset: 0,
    })
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([grantRecord()])
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(grantRecord())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.endEntitlement).mockResolvedValue(true)

    await expect(
      listAgentPermissions(deps, principal(), {
        page: 1,
        pageSize: 10,
        resourceServerId: 'resource-1',
        status: 'inactive',
      }),
    ).resolves.toMatchObject({
      items: [{ id: 'ent_1', target: { accountConnectionId: 'connection-1' } }],
    })
    expect(deps.externalResources.listAgentPermissions).toHaveBeenCalledWith({
      agentId: 'identity-1',
      limit: 10,
      offset: 0,
      resourceServerId: 'resource-1',
      status: 'inactive',
    })
    await expect(getAgentPermission(deps, 'ent_1', principal())).resolves.toMatchObject({ id: 'ent_1' })
    await revokeAgentResourceAccess(deps, 'identity-1')
    expect(deps.externalResources.endEntitlement).toHaveBeenCalledWith('ent_1', 'revoked', expect.any(Date))

    const lease = {
      id: 'lease-1',
      entitlementIds: ['ent_1'],
      requestId: 'request-1',
      bindingId: 'binding-1',
      encryptedAccessToken: 'sealed:target-token',
      tokenHash: 'hash',
      confirmationJkt: 'jkt',
      scopes: ['projects:read'],
      authorizationDetails: [],
      expiresAt: new Date(Date.now() + 300_000),
      revokedAt: null,
      createdAt: now,
    }
    vi.mocked(deps.externalResources.listActiveTokenLeasesByBinding).mockResolvedValue([
      { ...lease, entitlementIds: ['missing'] },
      lease,
    ])
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValueOnce(null).mockResolvedValueOnce(grantRecord())
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    vi.mocked(deps.externalResources.revokeTokenLease).mockResolvedValue(true)
    vi.mocked(deps.externalHttp.fetch).mockResolvedValue(new Response(null, { status: 200 }))
    await revokeAgentResourceLeasesForBinding(deps, 'binding-1')
    expect(deps.externalResources.revokeTokenLease).toHaveBeenCalledWith('lease-1', expect.any(Date))
  })

  it('enforces identity, resource, connection, and direct grant scope boundaries on requests', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)

    const inactivePrincipal = principal()
    inactivePrincipal.binding = { ...inactivePrincipal.binding, status: 'revoked' }
    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
        },
        inactivePrincipal,
        'https://auth.example.com',
      ),
    ).rejects.toThrow('active Agent identity')

    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.authorization.findResource).mockResolvedValueOnce(null)
    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Enabled Resource Server')

    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(null)
    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ status: 'pending', connectionId: null })

    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue({
      ...connectionRecord(),
      grantedScopes: ['openid'],
    })
    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ status: 'pending', scopes: ['projects:read'] })
  })

  it('[spec: agent-identity/agent-resource-access-without-role] allows an Agent without roles to request advertised scopes', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])
    vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([])
    vi.mocked(deps.externalResources.createAccessRequest).mockImplementation(async (record) => record)

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      status: 'pending',
      scopes: ['projects:read'],
    })
  })

  it('reuses a durable grant that covers a narrower temporary credential request', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const durableGrant = {
      ...grantRecord(),
      mode: 'persistent' as const,
      scopes: ['projects:read', 'projects:write'],
    }
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connectionRecord()])
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([durableGrant])
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: durableGrant.scope, entitlementId: durableGrant.id }],
      scopes: durableGrant.scopes,
    })
    vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([])
    vi.mocked(deps.externalResources.createAccessRequest).mockImplementation(async (record) => record)

    await expect(
      createAgentAccessRequest(
        deps,
        { resourceId: 'resource-1', scopes: ['projects:read'] },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({
      status: 'approved',
      scopes: ['projects:read'],
      approvedEntitlements: [{ scope: durableGrant.scope, entitlementId: durableGrant.id }],
      approvalUrl: null,
    })
  })

  it('[spec: agent-identity/agent-resource-access-ensure] does not reuse an Entitlement outside the current account context', async () => {
    const detail = { type: 'project_access', identifier: 'project-1', actions: ['read'] }
    const deps = authorizationCatalogDeps()
    const connection = {
      ...connectionRecord(),
      grantedScopes: [...connectionRecord().grantedScopes, 'authorization-details:read'],
      authorizationDetails: [detail],
    }
    const providerFetch = vi.mocked(deps.externalHttp.fetch).getMockImplementation()!
    vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
      if (request.url === 'https://projects.example.com/.well-known/openid-configuration') {
        return Response.json(metadata())
      }
      return request.url.startsWith('https://projects.example.com/authorization-details?')
        ? Response.json({
            items: [
              {
                authorizationDetail: detail,
                grantedScopes: ['projects:read'],
                display: { label: 'Project One' },
              },
            ],
            pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 1, totalPages: Math.ceil(1 / 100) },
          })
        : providerFetch(request)
    })
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connection)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grantRecord(), scope: 'projects:write', authorizationDetails: [detail] },
    ])
    vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([])
    vi.mocked(deps.externalResources.createAccessRequest).mockImplementation(async (record) => record)

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:write'],
          authorizationDetails: [detail],
        },
        principal(),
        'https://auth.example.com',
      ),
    ).resolves.toMatchObject({ status: 'pending', approvedEntitlements: [] })
  })

  it('enforces controller ownership and request state boundaries', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())

    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(null)
    await expect(getAccountConnection(deps, 'missing', 'user-1')).rejects.toThrow(
      'Resource account connection was not found.',
    )
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue({
      ...connectionRecord(),
      ownerUserId: 'another-user',
    })
    await expect(getAccountConnection(deps, 'connection-1', 'user-1')).rejects.toThrow(
      'Resource account controller access is required.',
    )
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(null)
    await expect(getAccountAccessRequest(deps, 'missing', 'user-1')).rejects.toThrow(
      'Agent access request was not found.',
    )
    await expect(getAgentAccessRequest(deps, 'missing', principal())).rejects.toThrow(
      'Agent access request was not found.',
    )

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      agentIdentityId: 'another-agent',
    })
    await expect(getAgentAccessRequest(deps, 'request-1', principal())).rejects.toThrow(
      'Agent access request was not found.',
    )
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'approved',
    })
    await expect(decideAgentAccessRequest(deps, 'request-1', { decision: 'deny' }, 'user-1')).rejects.toThrow(
      'Pending Agent access request was not found.',
    )

    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(null)
    await expect(decideAgentAccessRequestByToken(deps, 'bad-token', { decision: 'deny' }, 'user-1')).rejects.toThrow(
      'Pending Agent access request was not found.',
    )
  })

  it('covers missing resource records and inactive discovery entries', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)

    vi.mocked(deps.connectors.findById).mockResolvedValueOnce(null)
    await expect(getExternalResourceAuthorization(deps, 'resource-1')).rejects.toThrow(
      'External API resource authorization was not found.',
    )
    vi.mocked(deps.authorization.findResource).mockResolvedValueOnce(nativeResource())
    await expect(getExternalResourceAuthorization(deps, 'native')).rejects.toThrow(
      'External Resource Server was not found.',
    )
    vi.mocked(deps.authorization.findResource).mockResolvedValueOnce(null)
    await expect(getExternalResourceAuthorization(deps, 'missing')).rejects.toThrow(
      'External Resource Server was not found.',
    )
    vi.mocked(deps.authorization.findResource).mockResolvedValueOnce(null)
    await expect(getApiResource(deps, 'missing', 'https://auth.example.com')).rejects.toThrow(
      'API resource was not found.',
    )
    vi.mocked(deps.connectors.findById).mockResolvedValueOnce(null)
    await expect(getApiResource(deps, 'resource-1', 'https://auth.example.com')).resolves.toMatchObject({
      authorization: null,
    })
    vi.mocked(deps.externalResources.consumeConnectionIntent).mockResolvedValue(null)
    await expect(
      completeResourceConnectionIntent(deps, { state: 'invalid', code: 'code' }, 'https://auth.example.com'),
    ).rejects.toThrow('Resource connection state is invalid')

    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([
      resource(),
      { ...nativeResource(), id: 'native' },
    ])
    vi.mocked(deps.connectors.findById).mockResolvedValue(null)
    await expect(listConnectableExternalResources(deps)).resolves.toEqual({ items: [] })
  })

  it('[spec: agent-identity/external-resource-first-access] consumes a failed OAuth connection attempt', async () => {
    const deps = createTestDeps()
    const intent: ResourceConnectionIntentRecord = {
      id: 'failed-intent',
      stateHash: 'state-hash',
      resourceId: 'resource-1',
      ownerUserId: 'user-1',
      ownerOrganizationId: null,
      initiatedByUserId: 'user-1',
      scopes: ['openid'],
      authorizationDetails: [],
      encryptedPkceVerifier: 'sealed:pkce-verifier',
      returnTo: 'connection-approval',
      status: 'completed',
      expiresAt: new Date(Date.now() + 300_000),
      completedAt: new Date(),
      createdAt: now,
      updatedAt: now,
    }
    vi.mocked(deps.externalResources.consumeConnectionIntent).mockResolvedValue(intent)

    await expect(failResourceConnectionIntent(deps, 'provider-state')).resolves.toEqual({
      returnTo: 'connection-approval',
    })
    expect(deps.externalResources.consumeConnectionIntent).toHaveBeenCalledWith(expect.any(String), expect.any(Date))

    vi.mocked(deps.externalResources.consumeConnectionIntent).mockResolvedValue(null)
    await expect(failResourceConnectionIntent(deps, 'provider-state')).rejects.toThrow(
      'Resource connection state is invalid, expired, or already used.',
    )
  })

  it('discovers resources through the owning User connection while filtering expired grants', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    const organizationIdentity = {
      ...identityAggregate(),
      identity: {
        ...identityAggregate().identity,
        ownerUserId: 'user-1',
      },
    }
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(organizationIdentity)
    vi.mocked(deps.externalResources.listConnectionsByUser).mockResolvedValue([
      {
        ...connectionRecord(),
        grantedScopes: [...connectionRecord().grantedScopes, 'projects:removed'],
        externalSubject: 'abc',
      },
      { ...connectionRecord(), id: 'revoked', status: 'revoked' },
    ])
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grantRecord(), expiresAt: new Date(Date.now() - 1) },
      {
        ...grantRecord(),
        id: 'grant-live',
        expiresAt: new Date(Date.now() + 30_000),
        endedAt: now,
        endReason: 'revoked',
      },
    ])
    vi.mocked(deps.authorization.listEnabledResources).mockResolvedValue([resource()])

    await expect(discoverAgentResources(deps, principal())).resolves.toMatchObject({
      items: [
        {
          connection: {
            status: 'connected',
            displayName: 'Project Owner',
            authorizedScopes: ['projects:read'],
          },
        },
      ],
    })
    await expect(
      listAgentApiResources(deps, principal(), { limit: 10, offset: 0 }, 'https://auth.example.com'),
    ).resolves.toMatchObject({
      items: [
        {
          connection: {
            status: 'connected',
            displayName: 'Project Owner',
            authorizedScopes: ['projects:read'],
          },
        },
      ],
    })
  })

  it('[spec: agent-identity/agent-resource-access-ensure] returns an approved request immediately for an exact active grant', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connectionRecord()])
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grantRecord(), connectionId: 'other-connection' },
      { ...grantRecord(), resourceServerId: 'other-resource' },
      { ...grantRecord(), scope: 'projects:write' },
      { ...grantRecord(), expiresAt: new Date(Date.now() - 1) },
      grantRecord(),
    ])
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([])
    vi.mocked(deps.externalResources.createAccessRequest).mockImplementation(async (record) => record)

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          reason: 'Scheduled synchronization',
        },
        principal(),
        'https://auth.example.com/',
      ),
    ).resolves.toMatchObject({
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
      reason: 'Scheduled synchronization',
      approvalUrl: null,
    })
  })

  it('reuses active Entitlements independently of an older approved request', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connectionRecord())
    vi.mocked(deps.externalResources.listConnectionsByOrganizations).mockResolvedValue([connectionRecord()])
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([grantRecord()])
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
      authorizationDetails: [{ type: 'project_access', identifier: 'project-1' }],
    })
    vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([])
    vi.mocked(deps.externalResources.createAccessRequest).mockImplementation(async (record) => record)

    await expect(
      createAgentAccessRequest(
        deps,
        {
          resourceId: 'resource-1',
          scopes: ['projects:read'],
          reason: 'Scheduled synchronization',
        },
        principal(),
        'https://auth.example.com/',
      ),
    ).resolves.toMatchObject({
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
      approvalUrl: null,
    })
  })

  it('rejects races, missing identities, invalid expiry, and mismatched approval tokens during decisions', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(requestRecord())
    vi.mocked(deps.externalResources.decideAccessRequest).mockResolvedValueOnce(null)
    await expect(decideAgentAccessRequest(deps, 'request-1', { decision: 'deny' }, 'user-1')).rejects.toThrow(
      'already decided',
    )

    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValueOnce(null)
    await expect(
      decideAgentAccessRequest(deps, 'request-1', { decision: 'approve', mode: 'persistent' }, 'user-1'),
    ).rejects.toThrow('Active Agent identity was not found.')

    await expect(
      decideAgentAccessRequest(
        deps,
        'request-1',
        { decision: 'approve', mode: 'until', expiresAt: new Date(Date.now() - 1).toISOString() },
        'user-1',
      ),
    ).rejects.toThrow('Permission expiry must be in the future.')

    vi.mocked(deps.externalResources.approveAccessRequestWithEntitlements).mockResolvedValue('request_changed')
    vi.mocked(deps.externalResources.decideAccessRequest).mockResolvedValue(null)
    await expect(
      decideAgentAccessRequest(deps, 'request-1', { decision: 'approve', mode: 'persistent' }, 'user-1'),
    ).rejects.toThrow('already decided')

    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(requestRecord())
    await expect(
      decideAccessRequest(deps, 'different-request', { decision: 'deny', approvalToken: 'approval-token' }, 'user-1'),
    ).rejects.toThrow('Agent access request was not found.')
    await expect(decideAccessRequest(deps, 'request-1', { decision: 'deny' }, 'user-1')).rejects.toThrow(
      'already decided',
    )
    await expect(getAccountAccessRequest(deps, 'different-request', 'user-1', 'approval-token')).rejects.toThrow(
      'Agent access request was not found.',
    )
  })

  it('rejects invalid grants before issuing a target token', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    const signer = { issuer: principal().issuer, sign: vi.fn().mockResolvedValue('token') }

    await expect(
      issueTargetAccessToken(deps, 'missing', 'proof', 'https://auth.example.com/token', principal(), signer),
    ).rejects.toThrow('Approved Agent access request is required.')

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'proof', 'https://auth.example.com/token', principal(), signer),
    ).rejects.toThrow('no active Permissions')

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(null)
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'proof', 'https://auth.example.com/token', principal(), signer),
    ).rejects.toThrow('Approved Agent access request is required.')

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      agentIdentityId: 'another-agent',
      status: 'approved',
    })
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'proof', 'https://auth.example.com/token', principal(), signer),
    ).rejects.toThrow('Approved Agent access request is required.')
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'denied',
    })
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'proof', 'https://auth.example.com/token', principal(), signer),
    ).rejects.toThrow('Approved Agent access request is required.')

    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([grantRecord()])
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    vi.mocked(deps.authorization.findResource).mockResolvedValueOnce({ ...resource(), enabled: false })
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'proof', 'https://auth.example.com/token', principal(), signer),
    ).rejects.toThrow('Enabled Resource Server is required.')

    vi.mocked(deps.authorization.findResource).mockResolvedValueOnce({
      ...resource(),
      visibility: 'private',
      ownerOrganizationId: 'other-organization',
    })
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'proof', 'https://auth.example.com/token', principal(), signer),
    ).rejects.toThrow('Resource Server is not visible to this Agent.')

    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(
      connectionWithCredential(connectionRecord(), { clientGeneration: 2 }),
    )
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'proof', 'https://auth.example.com/token', principal(), signer),
    ).rejects.toThrow('Active external authorization server is required.')

    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(null)
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'proof', 'https://auth.example.com/token', principal(), signer),
    ).rejects.toThrow('Active external API resource grant is required.')
  })

  it('rejects malformed, misbound, stale, and replayed native DPoP proofs', async () => {
    const deps = createTestDeps()
    const native = nativeResource()
    authorizationDeps(deps)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({ id: 'org-1', disabled: false } as never)
    vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
    mockResourceOpenApi(deps, native.resourceUrl)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    const nativeEntitlement = {
      ...grantRecord(),
      connectionId: null,
      authorizationDetails: [organizationAuthority],
      mode: 'persistent',
    } as ResourceScopeEntitlementRecord
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(nativeEntitlement)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([nativeEntitlement])
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      connectionId: null,
      authorizationDetails: [organizationAuthority],
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    const signer = { issuer: principal().issuer, sign: vi.fn().mockResolvedValue('native-token') }
    const tokenUrl = 'https://auth.example.com/api/agent/access-requests/request-1/credentials'

    vi.mocked(deps.authorization.findResource).mockResolvedValueOnce({
      ...native,
      authorizationModel: 'native',
      connectorId: 'connector-1',
      scopeRegistry: {
        ...native.scopeRegistry!,
      },
    })
    await expect(issueTargetAccessToken(deps, 'request-1', 'proof', tokenUrl, principal(), signer)).rejects.toThrow(
      'DPoP proof is malformed.',
    )

    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValueOnce({
      ...requestRecord(),
      connectionId: 'connection-1',
      authorizationDetails: [organizationAuthority],
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValueOnce({
      ...grantRecord(),
      connectionId: 'connection-1',
      authorizationDetails: [organizationAuthority],
      mode: 'persistent',
    })
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValueOnce([
      { ...nativeEntitlement, connectionId: 'connection-1' },
    ])
    await expect(issueTargetAccessToken(deps, 'request-1', 'proof', tokenUrl, principal(), signer)).rejects.toThrow(
      'Native API resource grants cannot use account connections.',
    )
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'proof', tokenUrl, principal(), {
        ...signer,
        issuer: 'https://other.example.com',
      }),
    ).rejects.toThrow('does not belong to the active OAuth issuer')
    await expect(
      issueTargetAccessToken(deps, 'request-1', 'not-a-jwt', tokenUrl, principal(), signer),
    ).rejects.toThrow()

    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
    const publicJwk = await exportJWK(publicKey)
    const proof = async (
      payload: Record<string, unknown>,
      header: JWTHeaderParameters = { typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk },
    ) => new SignJWT(payload).setProtectedHeader(header).sign(privateKey)

    await expect(
      issueTargetAccessToken(
        deps,
        'grant-1',
        await proof({ htm: 'POST', htu: tokenUrl, jti: 'no-iat' }, { alg: 'ES256', jwk: publicJwk }),
        tokenUrl,
        principal(),
        signer,
      ),
    ).rejects.toThrow('public-key DPoP proof')
    await expect(
      issueTargetAccessToken(
        deps,
        'grant-1',
        await proof({ htm: 'GET', htu: tokenUrl, jti: 'wrong-method', iat: Math.floor(Date.now() / 1000) }),
        tokenUrl,
        principal(),
        signer,
      ),
    ).rejects.toThrow('not bound to the target token endpoint')
    await expect(
      issueTargetAccessToken(
        deps,
        'grant-1',
        await proof({ htm: 'POST', htu: tokenUrl, jti: 'stale', iat: 1 }),
        tokenUrl,
        principal(),
        signer,
      ),
    ).rejects.toThrow('outside the accepted time window')
    const signed = await proof({
      htm: 'POST',
      htu: tokenUrl,
      jti: 'tampered',
      iat: Math.floor(Date.now() / 1000),
    })
    const signedParts = signed.split('.')
    signedParts[2] = `${signedParts[2]!.startsWith('a') ? 'b' : 'a'}${signedParts[2]!.slice(1)}`
    await expect(
      issueTargetAccessToken(deps, 'request-1', signedParts.join('.'), tokenUrl, principal(), signer),
    ).rejects.toThrow('DPoP proof signature is invalid.')

    vi.mocked(deps.agentTokens.consumeDpopJti).mockResolvedValue(false)
    await expect(
      issueTargetAccessToken(
        deps,
        'grant-1',
        await proof({
          htm: 'POST',
          htu: tokenUrl,
          jti: 'replayed',
          iat: Math.floor(Date.now() / 1000),
        }),
        tokenUrl,
        principal(),
        signer,
      ),
    ).rejects.toThrow('already used')

    vi.mocked(deps.agentTokens.consumeDpopJti).mockResolvedValue(true)
    Object.assign(deps.authorization, { listTeamNamesForUser: vi.fn().mockResolvedValue([]) })
    await expect(
      issueTargetAccessToken(
        deps,
        'grant-1',
        await proof({
          htm: 'POST',
          htu: tokenUrl,
          jti: 'valid-user-proof',
          iat: Math.floor(Date.now() / 1000),
        }),
        tokenUrl,
        principal(),
        signer,
      ),
    ).resolves.toMatchObject({ accessToken: 'native-token' })
  })

  it('rejects native approval when the selected Organization Context is no longer current', async () => {
    const deps = createTestDeps()
    const native = {
      ...nativeResource(),
      scopeRegistry: {
        ...nativeResource().scopeRegistry!,
        scopes: [{ value: 'projects:read', description: null, grantMode: 'automatic' as const }],
      },
    }
    const personalIdentity = identityAggregate()
    personalIdentity.identity = { ...personalIdentity.identity, ownerUserId: 'user-1' }
    const pending = {
      ...requestRecord(),
      connectionId: null,
      authorizationDetails: [organizationAuthority],
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([])
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(personalIdentity)
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(pending)

    await expect(
      decideAgentAccessRequest(
        deps,
        pending.id,
        { decision: 'approve', mode: 'persistent', authorizationDetails: [organizationAuthority] },
        'user-1',
      ),
    ).rejects.toMatchObject({ status: 403 })
    expect(deps.externalResources.approveAccessRequestWithEntitlements).not.toHaveBeenCalled()
  })

  it('requires a current Organization Context before native credential issuance', async () => {
    const deps = createTestDeps()
    const native = { ...nativeResource(), visibility: 'public' as const }
    const personalIdentity = identityAggregate()
    personalIdentity.identity = { ...personalIdentity.identity, ownerUserId: 'user-1' }
    const personalPrincipal = {
      ...principal(),
      identity: personalIdentity.identity,
      binding: personalIdentity.bindings[0]!,
    }
    const signer = { issuer: personalPrincipal.issuer, sign: vi.fn().mockResolvedValue('native-token') }
    const tokenUrl = 'https://auth.example.com/api/agent/access-requests/request-1/credentials'
    const setContext = (authorizationDetails: AuthorizationDetail[]) => {
      const entitlement = {
        ...grantRecord(),
        connectionId: null,
        authorizationDetails,
        mode: 'persistent',
      } as ResourceScopeEntitlementRecord
      vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
        ...requestRecord(),
        connectionId: null,
        authorizationDetails,
        status: 'approved',
        approvedEntitlements: [{ scope: 'projects:read', entitlementId: entitlement.id }],
      })
      vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([entitlement])
    }
    vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
    Object.assign(deps.authorization, {
      listTeamNamesForUser: vi.fn().mockResolvedValue([]),
    })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(personalIdentity)
    setContext([organizationAuthority])

    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([])
    await expect(
      issueTargetAccessToken(deps, 'request-1', await createDpopProof(tokenUrl), tokenUrl, personalPrincipal, signer),
    ).rejects.toMatchObject({ status: 403 })
    expect(signer.sign).not.toHaveBeenCalled()
    expect(deps.externalResources.issueTokenLeaseWithAudit).not.toHaveBeenCalled()

    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([
      { organizationId: 'org-1', roles: [] },
    ] as never)
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({ id: 'org-1', disabled: true } as never)
    await expect(
      issueTargetAccessToken(deps, 'request-1', await createDpopProof(tokenUrl), tokenUrl, personalPrincipal, signer),
    ).rejects.toMatchObject({ status: 403 })
    expect(signer.sign).not.toHaveBeenCalled()
    expect(deps.externalResources.issueTokenLeaseWithAudit).not.toHaveBeenCalled()

    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({ id: 'org-1', disabled: false } as never)
    await expect(
      issueTargetAccessToken(deps, 'request-1', await createDpopProof(tokenUrl), tokenUrl, personalPrincipal, signer),
    ).resolves.toMatchObject({ accessToken: 'native-token' })

    signer.sign.mockClear()
    vi.mocked(deps.externalResources.issueTokenLeaseWithAudit).mockClear()
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([])
    setContext([userAuthority])
    await expect(
      issueTargetAccessToken(deps, 'request-1', await createDpopProof(tokenUrl), tokenUrl, personalPrincipal, signer),
    ).resolves.toMatchObject({ accessToken: 'native-token' })
    expect(signer.sign).toHaveBeenCalledOnce()
    expect(deps.externalResources.issueTokenLeaseWithAudit).toHaveBeenCalledOnce()
  })

  it('binds a Realmroot management token to exactly one authority Resource', async () => {
    const deps = createTestDeps()
    const builtIn = {
      ...nativeResource(),
      id: 'res_realmroot',
      identifier: 'realmroot',
      resourceUrl: 'https://auth.example.com/api',
    }
    const authority = { type: 'realmroot_authority', authority: 'organization', id: 'org-1' }
    authorizationDeps(deps)
    Object.assign(deps.authorization, { listTeamNamesForUser: vi.fn().mockResolvedValue([]) })
    vi.mocked(deps.authorization.findOrganization).mockResolvedValue({ id: 'org-1', disabled: false } as never)
    vi.mocked(deps.authorization.findResource).mockResolvedValue(builtIn)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    const realmrootEntitlement = {
      ...grantRecord(),
      resourceServerId: builtIn.id,
      connectionId: null,
      scope: 'users:read',
      authorizationDetails: [authority],
      mode: 'persistent',
    } as ResourceScopeEntitlementRecord
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(realmrootEntitlement)
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([realmrootEntitlement])
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      resourceId: builtIn.id,
      connectionId: null,
      scopes: ['users:read'],
      authorizationDetails: [authority],
      status: 'approved',
      approvedEntitlements: [{ scope: 'users:read', entitlementId: 'ent_1' }],
    })
    const signer = { issuer: principal().issuer, sign: vi.fn().mockResolvedValue('realmroot-token') }
    const tokenUrl = 'https://auth.example.com/api/agent/access-requests/request-1/credentials'

    const result = await issueTargetAccessToken(
      deps,
      'request-1',
      await createDpopProof(tokenUrl),
      tokenUrl,
      principal(),
      signer,
    )

    expect(result).toMatchObject({
      accessToken: 'realmroot-token',
      authorizationDetails: [authority],
      resourceUrl: builtIn.resourceUrl,
    })
    expect(signer.sign).toHaveBeenCalledWith(
      expect.objectContaining({
        sub: 'user-1',
        aud: builtIn.resourceUrl,
        client_id: realmrootCliClientId,
        act: { iss: principal().issuer, sub: principal().subject },
        [realmrootAgentBindingClaim]: {
          protocol_agent_id: 'protocol-agent-1',
          host_id: 'host-1',
          runtime: 'codex',
          session_id: 'thread-raw-123',
        },
        [realmrootOrganizationClaim]: 'org-1',
        groups: [],
        realmroot_authority: authority,
      }),
      'at+jwt',
    )
    const signedScope = String(signer.sign.mock.calls[0]![0].scope).split(' ')
    expect(signedScope).toContain('users:read')
  })

  it('[spec: agent-identity/native-api-resource-token] signs claims only from the selected personal Agent Context', async () => {
    const deps = createTestDeps()
    const native = { ...nativeResource(), visibility: 'public' as const }
    const personalIdentity = identityAggregate()
    personalIdentity.identity = {
      ...personalIdentity.identity,
      ownerUserId: 'user-1',
    }
    const personalPrincipal = {
      ...principal(),
      identity: personalIdentity.identity,
      binding: personalIdentity.bindings[0]!,
    }
    authorizationDeps(deps)
    vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([
      { organizationId: 'org-1', roles: [] },
      { organizationId: 'org-2', roles: [] },
    ] as never)
    vi.mocked(deps.authorization.findOrganization).mockImplementation(async (id) => ({ id, disabled: false }) as never)
    vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
    Object.assign(deps.authorization, {
      listTeamNamesForUser: vi.fn().mockImplementation(async (organizationId: string) => [`team-${organizationId}`]),
    })
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(personalIdentity)
    const signingKeys = await generateKeyPair('RS256')
    const signer = {
      issuer: personalPrincipal.issuer,
      sign: async (claims: Record<string, unknown>, type: string) =>
        new SignJWT(claims)
          .setProtectedHeader({ alg: 'RS256', typ: type })
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(signingKeys.privateKey),
    }
    const tokenUrl = 'https://auth.example.com/api/agent/access-requests/request-1/credentials'
    const contexts = [
      { detail: userAuthority, organizationId: null },
      { detail: organizationAuthority, organizationId: 'org-1' },
      {
        detail: { type: 'realmroot_authority', authority: 'organization', id: 'org-2' },
        organizationId: 'org-2',
      },
    ]

    for (const [index, context] of contexts.entries()) {
      const entitlement = {
        ...grantRecord(),
        id: `ent_${index}`,
        connectionId: null,
        organizationId: context.organizationId,
        authorizationDetails: [context.detail],
        mode: 'persistent',
      } as ResourceScopeEntitlementRecord
      vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(entitlement)
      vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([entitlement])
      vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
        ...requestRecord(),
        connectionId: null,
        authorizationDetails: [context.detail],
        status: 'approved',
        approvedEntitlements: [{ scope: 'projects:read', entitlementId: entitlement.id }],
      })
      const issued = await issueTargetAccessToken(
        deps,
        'request-1',
        await createDpopProof(tokenUrl),
        tokenUrl,
        personalPrincipal,
        signer,
      )
      const { payload } = await jwtVerify(issued.accessToken, signingKeys.publicKey, {
        issuer: personalPrincipal.issuer,
        audience: native.resourceUrl,
      })
      expect(payload).toMatchObject({
        sub: 'user-1',
        client_id: realmrootCliClientId,
        act: { iss: personalPrincipal.issuer, sub: personalPrincipal.subject },
      })
      if (context.organizationId) {
        expect(payload).toMatchObject({
          [realmrootOrganizationClaim]: context.organizationId,
          groups: [`team-${context.organizationId}`],
        })
      } else {
        expect(payload).not.toHaveProperty(realmrootOrganizationClaim)
        expect(payload.groups).toEqual([])
      }
    }
  })

  it('enforces organization controllers and handles revocation error paths', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    Object.assign(deps.authorization, {
      findMemberByOrganizationUser: vi.fn().mockResolvedValue(null),
    })
    await expect(
      createResourceConnectionIntent(
        deps,
        'resource-1',
        { owner: { type: 'organization', organizationId: 'org-1' }, scopes: [] },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Organization credential manager access is required.')

    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord({ enabled: false }))
    await expect(
      createResourceConnectionIntent(
        deps,
        'resource-1',
        { owner: { type: 'user' }, scopes: [] },
        'user-1',
        'https://auth.example.com',
      ),
    ).rejects.toThrow('Active external API resource authorization was not found.')

    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(null)
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      connectionId: null,
    })
    await expect(getAccountAccessRequest(deps, 'request-1', 'user-1')).rejects.toThrow(
      'Agent controller access is required.',
    )

    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(null)
    await expect(revokeAgentPermission(deps, 'missing', 'user-1')).rejects.toThrow('Agent Permission was not found.')
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(grantRecord())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(null)
    await expect(revokeAgentPermission(deps, 'grant-1', 'user-1')).rejects.toThrow(
      'Source Agent access request was not found.',
    )
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue({
      ...grantRecord(),
      sourceAccessRequestId: null,
    })
    await expect(revokeAgentPermission(deps, 'grant-1', 'user-1')).rejects.toThrow(
      'Source Agent access request was not found.',
    )

    vi.mocked(deps.authorization.findResource).mockResolvedValue(nativeResource())
    vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([
      { ...grantRecord(), connectionId: null },
    ])
    vi.mocked(deps.externalResources.listActiveTokenLeasesByEntitlement).mockResolvedValue([
      {
        id: 'lease-native',
        entitlementIds: ['ent_1'],
        requestId: 'request-1',
        bindingId: 'binding-1',
        encryptedAccessToken: 'sealed:native',
        tokenHash: 'hash',
        confirmationJkt: 'jkt',
        scopes: ['projects:read'],
        authorizationDetails: [],
        expiresAt: new Date(Date.now() + 30_000),
        revokedAt: null,
        createdAt: now,
      },
    ])
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue(null)
    await expect(revokeAgentResourceAccess(deps, 'identity-1')).rejects.toThrow(
      'Approved Agent access request was not found.',
    )
    vi.mocked(deps.authorization.findResource).mockResolvedValue(resource())
    vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({ ...requestRecord(), connectionId: null })
    await expect(revokeAgentResourceAccess(deps, 'identity-1')).rejects.toThrow(
      'Resource account connection was not found.',
    )
    vi.mocked(deps.authorization.findResource).mockResolvedValue(nativeResource())
    vi.mocked(deps.externalResources.findAccessRequest).mockResolvedValue({
      ...requestRecord(),
      status: 'approved',
      approvedEntitlements: [{ scope: 'projects:read', entitlementId: 'ent_1' }],
    })
    await revokeAgentResourceAccess(deps, 'identity-1')
    expect(deps.externalResources.revokeTokenLease).toHaveBeenCalledWith('lease-native', expect.any(Date))

    vi.mocked(deps.authorization.findResource).mockResolvedValue(null)
    await expect(revokeAgentResourceAccess(deps, 'identity-1')).rejects.toThrow('API resource was not found.')
  })

  it('rejects unknown grants and missing host bindings in account views', async () => {
    const deps = createTestDeps()
    authorizationDeps(deps)
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue({
      ...grantRecord(),
      agentIdentityId: 'another-agent',
    })
    await expect(getAgentPermission(deps, 'grant-1', principal())).rejects.toThrow('Agent Permission was not found.')
    vi.mocked(deps.externalResources.findEntitlement).mockResolvedValue(grantRecord())
    vi.mocked(deps.authorization.findResource).mockResolvedValue(null)
    await expect(getAgentPermission(deps, 'grant-1', principal())).rejects.toThrow(
      'Agent Permission Resource Server was not found.',
    )

    vi.mocked(deps.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(requestRecord())
    vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue({
      ...identityAggregate(),
      bindings: [],
    })
    vi.mocked(deps.externalResources.findConnection).mockResolvedValue(connectionRecord())
    await expect(getAccountAccessRequestByToken(deps, 'approval-token', 'user-1')).rejects.toThrow(
      'Agent host binding was not found.',
    )

    const uncontrolled = createTestDeps()
    authorizationDeps(uncontrolled)
    vi.mocked(uncontrolled.externalResources.listConnectionsByUser).mockResolvedValue([])
    vi.mocked(uncontrolled.externalResources.listPendingAccessRequests).mockResolvedValue([
      { ...requestRecord(), connectionId: null },
    ])
    vi.mocked(uncontrolled.agentIdentities.findIdentity).mockResolvedValue({
      ...identityAggregate(),
      identity: { ...identityAggregate().identity, ownerUserId: 'another-user' },
    })
    await expect(listControllerAccessRequests(uncontrolled, 'user-1')).resolves.toEqual({ requests: [] })

    const mismatched = createTestDeps()
    authorizationDeps(mismatched)
    vi.mocked(mismatched.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(requestRecord())
    vi.mocked(mismatched.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(mismatched.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    await expect(getAccountAccessRequest(mismatched, 'another-request', 'user-1', 'approval-token')).rejects.toThrow(
      'Agent access request was not found.',
    )

    const missingIdentity = createTestDeps()
    authorizationDeps(missingIdentity)
    vi.mocked(missingIdentity.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(requestRecord())
    vi.mocked(missingIdentity.externalResources.findAccessRequest).mockResolvedValue(requestRecord())
    vi.mocked(missingIdentity.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(missingIdentity.agentIdentities.findIdentity)
      .mockResolvedValueOnce(identityAggregate())
      .mockResolvedValueOnce(null)
    await expect(getAccountAccessRequestByToken(missingIdentity, 'approval-token', 'user-1')).rejects.toThrow(
      'Agent identity was not found.',
    )

    const missingResource = createTestDeps()
    authorizationDeps(missingResource)
    vi.mocked(missingResource.externalResources.findAccessRequestByApprovalTokenHash).mockResolvedValue(requestRecord())
    vi.mocked(missingResource.externalResources.findAccessRequest).mockResolvedValue(requestRecord())
    vi.mocked(missingResource.externalResources.findConnection).mockResolvedValue(connectionRecord())
    vi.mocked(missingResource.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
    vi.mocked(missingResource.authorization.findResource).mockResolvedValue(null)
    await expect(getAccountAccessRequestByToken(missingResource, 'approval-token', 'user-1')).rejects.toThrow(
      'API resource was not found.',
    )
  })
})

function authorizationDeps(deps: ReturnType<typeof createTestDeps>) {
  const realmrootResource = {
    ...resource(),
    id: 'resource-realmroot',
    identifier: 'realmroot',
    name: 'Realmroot',
    resourceUrl: 'https://auth.example.com/api',
    authorizationModel: 'native' as const,
    connectorId: null,
  }
  Object.assign(deps.authorization, {
    findResource: vi
      .fn()
      .mockImplementation(async (id: string) => (id === realmrootResource.id ? realmrootResource : resource())),
    listResources: vi.fn().mockResolvedValue({
      items: [realmrootResource, resource()],
      pagination: { page: Math.floor(0 / 100) + 1, pageSize: 100, totalItems: 2, totalPages: Math.ceil(2 / 100) },
    }),
    listEnabledResources: vi.fn().mockResolvedValue([resource()]),
    listUserMemberships: vi.fn().mockResolvedValue([{ organizationId: 'org-1', roles: ['owner'] }]),
    listActiveUserScopeEntitlements: vi
      .fn()
      .mockResolvedValue([{ scopes: resourceScopeValues, expiresAt: null, revokedAt: null }]),
    listOrganizationRoleScopes: vi.fn().mockResolvedValue(new Map()),
    findMemberByOrganizationUser: vi.fn().mockResolvedValue({
      id: 'member-1',
      organizationId: 'org-1',
      userId: 'user-1',
      roles: ['owner'],
    }),
    updateResource: vi.fn().mockResolvedValue(true),
  })
  vi.mocked(deps.connectors.findById).mockResolvedValue(connectorRecord())
  vi.mocked(deps.connectors.listEnabled).mockResolvedValue([connectorRecord()])
  mockResourceOpenApi(deps, resource().resourceUrl)
}

function resource(): ApiResourceResponse {
  return {
    id: 'resource-1',
    identifier: 'projects',
    name: 'Projects API',
    resourceUrl: 'https://projects.example.com/api',
    authorizationModel: 'external',
    connectorId: 'connector-1',
    authorizationDetails: [],
    description: 'Manage private projects',
    enabled: true,
    ownerOrganizationId: 'org-1',
    visibility: 'public',
    scopeRegistry: {
      discovery: {
        sourceUrl: 'https://projects.example.com/openapi.json',
        etag: null,
        documentHash: 'projects-registry',
        syncedAt: now.toISOString(),
        lastError: null,
      },
      scopes: resourceScopeValues.map((value) => ({
        value,
        description: value === 'projects:read' ? 'Read projects' : `Allows ${value}`,
        grantMode: 'assigned' as const,
      })),
    },
    availableToAgents: true,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  }
}

const resourceScopeValues = [
  'authorization-details:read',
  'objects:create',
  'objects:purge',
  'projects:create',
  'projects:read',
  'projects:write',
  'quota:purchase',
  'shares:create',
  'teams:read',
]

function nativeResource(): ApiResourceResponse {
  return {
    ...resource(),
    authorizationModel: 'native',
    connectorId: null,
    resourceUrl: 'https://auth.example.com/api/projects',
  }
}

function metadata() {
  return {
    issuer: 'https://projects.example.com',
    authorization_endpoint: 'https://projects.example.com/authorize',
    token_endpoint: 'https://projects.example.com/token',
    registration_endpoint: 'https://projects.example.com/register',
    revocation_endpoint: 'https://projects.example.com/revoke',
    jwks_uri: 'https://projects.example.com/jwks',
    userinfo_endpoint: 'https://projects.example.com/userinfo',
    scopes_supported: ['openid', 'offline_access', 'workspaces:discover', ...resourceScopeValues],
    grant_types_supported: [
      'authorization_code',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:jwt-bearer',
      'urn:ietf:params:oauth:grant-type:token-exchange',
    ],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
    dpop_signing_alg_values_supported: ['ES256'],
  }
}

function authorizationCatalogDeps(
  options: { providerMetadata?: Record<string, unknown>; grantedScopes?: string[]; fetchResponse?: Response } = {},
) {
  const deps = createTestDeps()
  authorizationDeps(deps)
  const template = { type: 'project_access', actions: ['read'] }
  vi.mocked(deps.authorization.findResource).mockResolvedValue({
    ...resource(),
    authorizationDetails: [template],
  })
  vi.mocked(deps.connectors.findById).mockResolvedValue(
    connectorRecord({
      providerMetadata:
        options.providerMetadata ??
        ({
          ...metadata(),
          authorization_details_types_supported: ['project_access'],
          authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
          authorization_details_catalog_scope: 'authorization-details:read',
          authorization_details_catalog_version: 1,
        } as ConnectorRecord['providerMetadata']),
    }),
  )
  vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(identityAggregate())
  const connection = {
    ...connectionRecord(),
    grantedScopes: options.grantedScopes ?? [...connectionRecord().grantedScopes, 'authorization-details:read'],
  }
  vi.mocked(deps.externalResources.findConnectionByOwnerResource).mockResolvedValue(connection)
  vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])
  if (options.fetchResponse) vi.mocked(deps.externalHttp.fetch).mockResolvedValue(options.fetchResponse)
  return deps
}

function connectorRecord(overrides: Partial<ConnectorRecord> = {}): ConnectorRecord {
  const providerMetadata: Record<string, unknown> = overrides.providerMetadata ?? metadata()
  const authorizationDetailsCatalogScope =
    typeof providerMetadata.authorization_details_catalog_scope === 'string'
      ? providerMetadata.authorization_details_catalog_scope
      : null
  return {
    id: 'connector-1',
    slug: 'projects',
    providerType: 'generic_oauth',
    providerId: 'projects',
    displayName: 'Projects',
    enabled: true,
    authenticationEnabled: false,
    clientId: 'realmroot-client',
    clientSecret: 'target-secret',
    clientSecretContext: null,
    issuer: 'https://projects.example.com',
    authorizationEndpoint: 'https://projects.example.com/authorize',
    tokenEndpoint: 'https://projects.example.com/token',
    userInfoEndpoint: 'https://projects.example.com/userinfo',
    jwksEndpoint: 'https://projects.example.com/jwks',
    registrationEndpoint: 'https://projects.example.com/register',
    revocationEndpoint: 'https://projects.example.com/revoke',
    registrationMode: 'dynamic',
    registrationClientUri: null,
    registrationAccessToken: null,
    registrationAccessTokenContext: null,
    registeredScopes: [
      'openid',
      'profile',
      'email',
      'offline_access',
      'projects:read',
      'projects:write',
      ...(authorizationDetailsCatalogScope ? [authorizationDetailsCatalogScope] : []),
    ],
    clientGeneration: 1,
    retiredClientGenerations: null,
    scopes: ['openid', 'offline_access'],
    attributeMapping: null,
    providerMetadata,
    resourceAuthorizationEnabled: true,
    resourceClientId: 'realmroot-client',
    resourceClientSecret: 'target-secret',
    resourceClientSecretContext: null,
    resourceIssuer: 'https://projects.example.com',
    resourceAuthorizationEndpoint: 'https://projects.example.com/authorize',
    resourceTokenEndpoint: 'https://projects.example.com/token',
    resourceUserInfoEndpoint: 'https://projects.example.com/userinfo',
    resourceJwksEndpoint: 'https://projects.example.com/jwks',
    resourceRegistrationEndpoint: 'https://projects.example.com/register',
    resourceRevocationEndpoint: 'https://projects.example.com/revoke',
    resourceRegistrationMode: overrides.resourceRegistrationMode ?? overrides.registrationMode ?? 'dynamic',
    resourceRegistrationClientUri: null,
    resourceRegistrationAccessToken: null,
    resourceRegistrationAccessTokenContext: null,
    resourceRegisteredScopes: overrides.resourceRegisteredScopes ??
      overrides.registeredScopes ?? [
        'openid',
        'profile',
        'email',
        'offline_access',
        'projects:read',
        'projects:write',
        ...(authorizationDetailsCatalogScope ? [authorizationDetailsCatalogScope] : []),
      ],
    resourceClientGeneration: 1,
    resourceRetiredClientGenerations: null,
    resourceProviderMetadata: providerMetadata,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  }
}

function mockResourceOpenApi(deps: ReturnType<typeof createTestDeps>, resourceUrl: string, scopes = ['projects:read']) {
  vi.mocked(deps.externalHttp.fetch).mockImplementation(async (request) => {
    if (request.url === 'https://projects.example.com/.well-known/openid-configuration') {
      return Response.json(metadata())
    }
    if (request.url === protectedResourceMetadataUrl(resourceUrl)) {
      return Response.json({ resource: resourceUrl, scopes_supported: scopes })
    }
    if (request.url === resourceUrl) {
      return new Response(null, { headers: { link: '</openapi.json>; rel="service-desc"' } })
    }
    if (request.url === new URL('/openapi.json', resourceUrl).toString()) {
      return Response.json({
        openapi: '3.1.0',
        components: {
          securitySchemes: {
            oauth: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://projects.example.com/authorize',
                  tokenUrl: 'https://projects.example.com/token',
                  scopes: Object.fromEntries(
                    scopes.map((scope) => [scope, scope === 'projects:read' ? 'Read projects' : `Allows ${scope}`]),
                  ),
                },
              },
            },
          },
        },
        paths: {
          '/projects': {
            get: { security: [{ oauth: scopes }], responses: {} },
          },
        },
      })
    }
    return new Response(null, { status: 404 })
  })
}

function connectionRecord(): ProviderResourceAuthorizationRecord {
  const credentialExpiresAt = new Date(Date.now() + 300_000)
  return {
    id: 'connection-1',
    providerConnectionId: 'provider-connection-1',
    resourceId: 'resource-1',
    ownerUserId: 'user-1',
    ownerOrganizationId: null,
    externalSubject: 'target-user-1',
    displayName: 'Project Owner',
    grantedScopes: ['openid', 'offline_access', 'projects:read'],
    authorizationDetails: [],
    credentials: [
      {
        id: 'credential-1',
        providerResourceAuthorizationId: 'connection-1',
        encryptedTokens: 'sealed:{"accessToken":"subject","refreshToken":"refresh"}',
        grantedScopes: ['openid', 'offline_access', 'projects:read'],
        authorizationDetails: [],
        clientGeneration: 1,
        credentialVersion: 1,
        refreshClaimId: null,
        refreshClaimExpiresAt: null,
        status: 'active',
        credentialExpiresAt,
        revokedAt: null,
        createdAt: now,
        updatedAt: now,
      },
    ],
    status: 'active',
    revokedAt: null,
    createdAt: now,
    updatedAt: now,
  }
}

function connectionWithCredential(
  connection: ProviderResourceAuthorizationRecord,
  overrides: Partial<ProviderCredentialRecord>,
): ProviderResourceAuthorizationRecord {
  const credential = { ...connection.credentials[0]!, ...overrides }
  return {
    ...connection,
    credentials: [credential],
    grantedScopes: credential.grantedScopes,
    authorizationDetails: credential.authorizationDetails,
    status: credential.status,
    updatedAt: credential.updatedAt,
  }
}

function automaticNativeAccessDeps(grantModes: Record<string, 'automatic' | 'assigned'>) {
  const deps = createTestDeps()
  const native = {
    ...nativeResource(),
    scopeRegistry: {
      ...nativeResource().scopeRegistry!,
      scopes: Object.entries(grantModes).map(([value, grantMode]) => ({ value, description: null, grantMode })),
    },
  }
  const personalIdentity = identityAggregate()
  personalIdentity.identity = {
    ...personalIdentity.identity,
    ownerUserId: 'user-1',
  }
  const selectedContext = {
    type: 'realmroot_authority' as const,
    authority: 'user' as const,
    id: 'user-1',
  }
  vi.mocked(deps.authorization.findResource).mockResolvedValue(native)
  vi.mocked(deps.authorization.listUserMemberships).mockResolvedValue([])
  vi.mocked(deps.agentIdentities.findIdentity).mockResolvedValue(personalIdentity)
  vi.mocked(deps.externalResources.listActiveEntitlementsByAgent).mockResolvedValue([])
  vi.mocked(deps.externalResources.listPendingAccessRequestsByAgent).mockResolvedValue([])
  return { deps, native, personalIdentity, selectedContext }
}

function providerConnectionFor(connection: ProviderResourceAuthorizationRecord): ProviderConnectionRecord {
  return {
    id: connection.providerConnectionId,
    connectorId: 'connector-1',
    ownerUserId: connection.ownerUserId,
    ownerOrganizationId: connection.ownerOrganizationId,
    authenticationAccountId: null,
    externalSubject: connection.externalSubject,
    displayName: connection.displayName,
    status: 'active',
    createdAt: connection.createdAt,
    updatedAt: connection.updatedAt,
  }
}

function identityAggregate(): AgentIdentityAggregate {
  return {
    identity: {
      id: 'identity-1',
      issuer: 'https://auth.example.com/api/auth',
      subject: 'agt_stable',
      username: 'project-agent.00000000000000000000000000000001',
      name: 'Project Agent',
      ownerUserId: 'user-1',
      status: 'active',
      deletedAt: null,
      createdAt: now,
      updatedAt: now,
    },
    bindings: [
      {
        id: 'binding-1',
        agentIdentityId: 'identity-1',
        protocolAgentId: 'protocol-agent-1',
        hostId: 'host-1',
        status: 'active',
        boundAt: now,
        revokedAt: null,
        createdAt: now,
        updatedAt: now,
      },
    ],
  }
}

function principal() {
  const aggregate = identityAggregate()
  return {
    issuer: 'https://auth.example.com/api/auth',
    subject: 'agt_stable',
    identityId: 'identity-1',
    protocolAgentId: 'protocol-agent-1',
    hostId: 'host-1',
    runtime: 'codex',
    sessionId: 'thread-raw-123',
    identity: aggregate.identity,
    binding: aggregate.bindings[0],
  }
}

async function createDpopProof(tokenEndpoint: string) {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
  const publicJwk = await exportJWK(publicKey)
  return new SignJWT({
    htm: 'POST',
    htu: tokenEndpoint,
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
    .sign(privateKey)
}

function requestRecord(): AgentAccessRequestRecord {
  return {
    id: 'request-1',
    resourceId: 'resource-1',
    connectionId: 'connection-1',
    agentIdentityId: 'identity-1',
    bindingId: 'binding-1',
    scopes: ['projects:read'],
    authorizationDetails: [],
    reason: null,
    status: 'pending',
    approvalTokenHash: 'hash',
    encryptedApprovalToken: 'sealed:approval-token',
    approvedEntitlements: [],
    expiresAt: new Date(Date.now() + 300_000),
    decidedAt: null,
    createdAt: now,
    updatedAt: now,
  }
}

function grantRecord(): ResourceScopeEntitlementRecord {
  return {
    id: 'ent_1',
    userId: null,
    applicationId: null,
    agentIdentityId: 'identity-1',
    organizationId: null,
    resourceServerId: 'resource-1',
    connectionId: 'connection-1',
    authorizationDetails: [],
    authorizationContextHash: 'hash',
    scope: 'projects:read',
    mode: 'once',
    grantedByUserId: 'user-1',
    grantedByAgentIdentityId: null,
    sourceAccessRequestId: 'request-1',
    expiresAt: null,
    endedAt: null,
    endReason: null,
    createdAt: now,
    updatedAt: now,
  }
}
