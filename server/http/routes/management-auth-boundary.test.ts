import { readFileSync } from 'node:fs'
import { notFound } from '@server/domain/errors'
import { createApp } from '@server/http/app'
import { unifiedOpenApi } from '@server/http/openapi/management'
import * as agentIdentitiesUsecase from '@server/usecases/agent-identities'
import { protectedResourceCollectionRoutes } from '@shared/api/management'
import { requiredProtectedScope } from '@shared/authz'
import { realmrootCliClientId } from '@shared/oauth-token-profile'
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { createTestDeps } from '../test-deps'
import {
  assertConstrainedOpenApiSchema,
  createAuthMock,
  createSecurityRepositoryMock,
  createUserRepositoryMock,
  managementOpenApiOperationKey,
  methodsWithJsonRequestBody,
  mountedManagementOperations,
  openApiOperationObjects,
  openApiOperations,
  openApiRecord,
  openApiSchemaObject,
  operationsWithoutRequestBody,
  requestBodyContent,
  schemaReference,
  securityPolicy,
  userHeaders,
} from './management.test-utils'

const operationsWithExplicitSecurity = new Set([
  'GET /agent/access-requests/{param}',
  'GET /resource-servers',
  'GET /resource-servers/{param}',
  'GET /agents/{param}/permissions',
  'POST /agents/{param}/permissions',
  'GET /agents/{param}/permissions/{param}',
  'DELETE /agents/{param}/permissions/{param}',
  'GET /agents/{param}/authorized-resource-servers',
  'GET /users/{param}/permissions',
  'POST /users/{param}/permissions',
  'GET /users/{param}/permissions/{param}',
  'DELETE /users/{param}/permissions/{param}',
  'GET /users/{param}/authorized-resource-servers',
  'GET /applications/{param}/permissions',
  'POST /applications/{param}/permissions',
  'GET /applications/{param}/permissions/{param}',
  'DELETE /applications/{param}/permissions/{param}',
  'GET /applications/{param}/authorized-resource-servers',
])

describe('management routes 1', () => {
  beforeEach(() => {
    vi.spyOn(console, 'info').mockImplementation(() => undefined)
  })

  it('keeps the unified OpenAPI route inventory aligned with mounted routes', () => {
    const app = createApp(
      createAuthMock(),
      createTestDeps({
        users: createUserRepositoryMock(),
        security: createSecurityRepositoryMock(),
      }),
      { securityPolicy: securityPolicy() },
    )

    expect(openApiOperations()).toEqual(mountedManagementOperations(app))

    const operationIds = openApiOperationObjects().map((operation) => operation.operationId)
    expect(operationIds).not.toContain(undefined)
    expect(new Set(operationIds).size).toBe(operationIds.length)
    expect(unifiedOpenApi.security).toBeUndefined()
    expect(unifiedOpenApi.components.securitySchemes).not.toHaveProperty('agentAuth')
    expect(unifiedOpenApi.components.securitySchemes.agentAssertion).toMatchObject({
      type: 'http',
      scheme: 'bearer',
    })
    expect(unifiedOpenApi.components.securitySchemes.oauth2).toMatchObject({
      type: 'oauth2',
    })
    expect(unifiedOpenApi.components.securitySchemes.oauth2).not.toHaveProperty('x-dpop-required')
    expect(unifiedOpenApi.components.securitySchemes.sessionCookie).toMatchObject({ type: 'apiKey', in: 'cookie' })
    expect(unifiedOpenApi.components.securitySchemes).not.toHaveProperty('dpop')
    expect(unifiedOpenApi['x-cli-config']).toEqual({ command_layout: 'tags' })

    for (const operation of openApiOperationObjects()) {
      if (operation.key === managementOpenApiOperationKey) {
        expect(operation.security).toEqual([])
        continue
      }

      if (!Array.isArray(operation.security) || operation.security.length !== 0) {
        expect(operation.responses, operation.key).toHaveProperty('401')
        expect(operation.responses, operation.key).toHaveProperty('403')
      }
      expect(operation.declaredPathParameters, operation.key).toEqual(operation.pathParameters)
      const requiredScope = requiredProtectedScope(operation.method, operation.key.slice(operation.method.length + 1))
      if (
        requiredScope &&
        JSON.stringify(operation.security).includes('sessionCookie') &&
        !operationsWithExplicitSecurity.has(operation.key)
      ) {
        expect(operation.security, operation.key).toEqual([
          { oauth2: [requiredScope] },
          { sessionCookie: [requiredScope] },
        ])
      }

      if (methodsWithJsonRequestBody.has(operation.method) && !operationsWithoutRequestBody.has(operation.key)) {
        expect(requestBodyContent(operation.requestBody), operation.key).toEqual(
          expect.objectContaining({
            schema: expect.any(Object),
          }),
        )
        expect(schemaReference(requestBodyContent(operation.requestBody).schema), operation.key).not.toBe(
          '#/components/schemas/GenericObject',
        )
        expect(() =>
          assertConstrainedOpenApiSchema(requestBodyContent(operation.requestBody).schema, operation.key),
        ).not.toThrow()
      }

      for (const schema of operation.jsonResponseSchemas) {
        expect(schema, operation.key).toEqual(expect.any(Object))
        expect(schemaReference(schema), operation.key).not.toBe('#/components/schemas/GenericObject')
        expect(() => assertConstrainedOpenApiSchema(schema, operation.key)).not.toThrow()
      }
    }
  })

  it('[spec: management-api/management-restish-agent-auth] separates Agent protocol and Resource management credentials', () => {
    const operations = new Map(openApiOperationObjects().map((operation) => [operation.operationId, operation]))

    expect(operations.get('getAgentStatus')?.security).toEqual([{ oauth2: ['agent:read'] }])
    expect(operations.get('createAgentAuthorizationRequest')?.security).toEqual([
      { oauth2: ['access-requests:read', 'access-requests:write'] },
    ])
    expect(operations.get('createResourceServer')?.security).toEqual([
      { oauth2: ['resource-servers:write'] },
      { sessionCookie: ['resource-servers:write'] },
    ])
    expect(operations.get('listResourceServers')?.security).toEqual([
      { oauth2: ['resource-servers:read'] },
      { sessionCookie: ['resource-servers:read'] },
    ])
  })

  it('serves the unified OpenAPI contract with Restish discovery headers [spec: management-api/management-openapi-discovery]', async () => {
    const app = createApp(
      createAuthMock(),
      createTestDeps({
        users: createUserRepositoryMock(),
        security: createSecurityRepositoryMock(),
      }),
      { securityPolicy: securityPolicy() },
    )

    const contract = await app.request('/api/openapi.json')
    const documentation = await app.request('/api/docs')
    const protectedResponse = await app.request('/api/users')

    expect(contract.status).toBe(200)
    expect(contract.headers.get('content-type')).toContain('application/json')
    expect(contract.headers.get('link')).toBeNull()
    await expect(contract.json()).resolves.toEqual(unifiedOpenApi)
    expect(documentation.status).toBe(200)
    expect(documentation.headers.get('content-type')).toContain('text/html')
    const documentationHtml = await documentation.text()
    expect(documentationHtml).toContain('<title>Realmroot API Documentation</title>')
    expect(documentationHtml).toContain('/api/openapi.json')
    expect(documentationHtml).toContain('@scalar/api-reference@1.64.0')

    const declaredTags = new Set(
      ((unifiedOpenApi as { tags?: Array<{ name: string }> }).tags ?? []).map((tag) => tag.name),
    )
    expect(declaredTags.size).toBeGreaterThan(1)
    for (const operation of openApiOperationObjects()) {
      expect(operation.tags, operation.key).toHaveLength(1)
      expect(declaredTags.has(operation.tags?.[0] ?? ''), operation.key).toBe(true)
      const usesPagePagination = operation.parameters?.some((parameter) => {
        const value = openApiRecord(parameter)
        return value.in === 'query' && value.name === 'page'
      })
      if (usesPagePagination) {
        const successResponse = openApiRecord(openApiRecord(operation.responses)['200'])
        expect(openApiRecord(successResponse.headers), operation.key).toHaveProperty('Link')
      }
    }
    for (const operation of openApiOperationObjects().filter(({ key }) => /^\w+ \/realm(?:\/|$)/.test(key))) {
      expect(operation.tags, operation.key).toEqual(['Platform'])
    }
    expect(declaredTags.has('Security')).toBe(false)
    expect(declaredTags.has('Audit Events')).toBe(false)
    expect(unifiedOpenApi.paths).not.toHaveProperty('/onboarding/status')
    expect(unifiedOpenApi.paths).not.toHaveProperty('/onboarding/admin-users')
    expect(unifiedOpenApi.paths).not.toHaveProperty('/health')
    expect(unifiedOpenApi.paths).not.toHaveProperty('/configz')
    expect(unifiedOpenApi.paths).not.toHaveProperty('/oauth/consent')
    expect(unifiedOpenApi.paths).not.toHaveProperty('/account-connections/oauth/callback')
    expect(unifiedOpenApi.paths).not.toHaveProperty('/provider-connection-events/{eventId}')

    const accessRequest = openApiOperationObjects().find((operation) => operation.key === 'POST /agent/access-requests')
    const standaloneRequestSchema = requestBodyContent(accessRequest?.requestBody).schema
    expect(JSON.stringify(standaloneRequestSchema)).not.toContain('#/components/')

    expect(protectedResponse.status).toBe(401)
    expect(protectedResponse.headers.get('link')).toContain('</api/openapi.json>; rel="service-desc"')
  })

  it('publishes the runtime Organization authorization scopes in OpenAPI', () => {
    const expectedScopes = new Map([
      ['DELETE /organizations/{param}', 'organizations:delete'],
      ['GET /organizations/{param}/roles', 'roles:read'],
      ['POST /organizations/{param}/roles', 'roles:write'],
      ['GET /organizations/{param}/members/{param}/roles', 'role-assignments:read'],
      ['PUT /organizations/{param}/members/{param}/roles', 'role-assignments:write'],
    ])

    for (const [key, scope] of expectedScopes) {
      const operation = openApiOperationObjects().find((candidate) => candidate.key === key)
      expect(operation?.security, key).toEqual([{ oauth2: [scope] }, { sessionCookie: [scope] }])
    }
  })

  it('limits generated Restish commands to discovery, approval, and credential workflows [spec: management-api/management-restish-command-surface]', () => {
    const generatedCommands = openApiOperationObjects()
      .filter((operation) => operation.cliHidden !== true)
      .map((operation) => ({
        group: operation.tags?.[0],
        name: operation.cliName,
        operationId: operation.operationId,
      }))

    expect(generatedCommands).toEqual([
      { group: 'Agent', name: 'whoami', operationId: 'getAgentStatus' },
      { group: 'Agent', name: 'access', operationId: 'createAgentAuthorizationRequest' },
      { group: 'Agent', name: 'enroll', operationId: 'createAgentEnrollment' },
    ])
  })

  it('keeps the Realmroot Skill aligned with generated Agent commands [spec: management-api/management-restish-command-surface]', () => {
    const setup = readFileSync(new URL('../../../skills/realmroot/references/setup.md', import.meta.url), 'utf8')
    const commands = readFileSync(
      new URL('../../../skills/realmroot/references/toolbox-commands.md', import.meta.url),
      'utf8',
    )
    const management = readFileSync(
      new URL('../../../skills/realmroot/references/management.md', import.meta.url),
      'utf8',
    )

    expect(setup).toContain('realmroot agent whoami --json')
    expect(setup).toContain('realmroot agent enroll --username mira --nickname "Mira Chen" --json')
    expect(commands).toContain('realmroot agent request')
    expect(commands).toContain('realmroot toolbox <resource-server> context use <context-id>')
    expect(commands).toMatch(/install the\s+task-relevant Skills using the exact commands printed by Toolbox/)
    expect(commands).toContain('continue with operation discovery and help')
    expect(commands).not.toContain('--authorization-detail')
    expect(commands).not.toContain('restish')
    expect(management).not.toContain('/access/consents')

    const accessRequest = openApiOperationObjects().find(
      (operation) => operation.operationId === 'createAgentAuthorizationRequest',
    )
    const schema = openApiSchemaObject(requestBodyContent(accessRequest?.requestBody).schema)
    expect(Object.keys(openApiRecord(schema.properties)).sort()).toEqual([
      'authorizationDetails',
      'reason',
      'resourceServerId',
      'scopes',
    ])
  })

  it('documents application setup fields and Organization Role request bodies', () => {
    const createApplication = openApiOperationObjects().find((operation) => operation.key === 'POST /applications')
    const createApplicationSchema = openApiSchemaObject(requestBodyContent(createApplication?.requestBody).schema)
    const createApplicationProperties = openApiRecord(createApplicationSchema.properties)
    const updateApplication = openApiOperationObjects().find(
      (operation) => operation.key === 'PATCH /applications/{param}',
    )
    const updateApplicationSchema = openApiSchemaObject(requestBodyContent(updateApplication?.requestBody).schema)
    const updateApplicationProperties = openApiRecord(updateApplicationSchema.properties)

    expect(createApplicationProperties).toHaveProperty('ownerOrganizationId')
    expect(createApplicationProperties).toHaveProperty('postLogoutRedirectUris')
    expect(createApplicationProperties).toHaveProperty('corsOrigins')
    expect(createApplicationProperties).not.toHaveProperty('clientId')
    expect(createApplicationProperties).not.toHaveProperty('clientSecret')
    expect(updateApplicationProperties).not.toHaveProperty('ownerOrganizationId')

    const createRole = openApiOperationObjects().find(
      (operation) => operation.key === 'POST /organizations/{param}/roles',
    )
    const createRoleSchema = openApiSchemaObject(requestBodyContent(createRole?.requestBody).schema)
    const createRoleProperties = openApiRecord(createRoleSchema.properties)

    expect(createRoleProperties).toHaveProperty('key')
    expect(createRoleProperties).toHaveProperty('scopes')
    expect(createRole?.responses).toHaveProperty('201')

    const replaceMemberRoles = openApiOperationObjects().find(
      (operation) => operation.key === 'PUT /organizations/{param}/members/{param}/roles',
    )
    const replaceMemberRolesSchema = openApiSchemaObject(requestBodyContent(replaceMemberRoles?.requestBody).schema)
    expect(openApiRecord(replaceMemberRolesSchema.properties)).toHaveProperty('roles')
    expect(replaceMemberRoles?.responses).toHaveProperty('200')

    const deleteApiResource = openApiOperationObjects().find(
      (operation) => operation.key === 'DELETE /resource-servers/{param}',
    )
    expect(deleteApiResource?.responses).toHaveProperty('204')
    expect(openApiOperationObjects().some((operation) => operation.key.includes('/archival'))).toBe(false)
  })

  it('preserves the POST /agents route-specific authorization error over generic defaults', () => {
    const createAgent = openApiOperationObjects().find((operation) => operation.key === 'POST /agents')
    const forbiddenResponse = openApiRecord(openApiRecord(createAgent?.responses)['403'])

    expect(forbiddenResponse.description).toBe(
      'The Application is not acting as a User or lacks agents:write authority.',
    )
    expect(forbiddenResponse.description).not.toBe('Administrator access is required.')
  })

  it('documents UUIDv7 Agent subjects while preserving historical subject references [spec: agent-identity/application-agent-creation]', () => {
    const createAgent = openApiOperationObjects().find((operation) => operation.key === 'POST /agents')
    const createdResponse = openApiRecord(openApiRecord(createAgent?.responses)['201'])
    const content = openApiRecord(openApiRecord(createdResponse.content)['application/json'])
    const schema = openApiSchemaObject(content.schema)
    const properties = openApiRecord(schema.properties)
    const subject = openApiSchemaObject(properties.subject)

    expect(openApiSchemaObject(properties.id).description).toContain('New values are UUIDv7')
    expect(subject.description).toContain('New Agent subjects are UUIDv7')
    expect(subject.type).toBe('string')
  })

  it('mounts the documented management collections behind the admin boundary', async () => {
    const app = createApp(createAuthMock(), createTestDeps({ users: createUserRepositoryMock() }))

    for (const route of protectedResourceCollectionRoutes) {
      const response = await app.request(`/api${route}`)
      expect(response.status, route).toBe(401)
      await expect(response.json()).resolves.toMatchObject({
        error: {
          code: 'unauthorized',
        },
      })
    }
  })

  it('filters Organization collections for sessions without memberships', async () => {
    const response = await createApp(createAuthMock(), createTestDeps({ users: createUserRepositoryMock() })).request(
      '/api/users',
      {
        headers: userHeaders(),
      },
    )

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({ items: [] })
  })

  it('accepts DPoP Agent tokens, rejects Bearer Agent tokens, and uses one Agent principal for management [spec: agent-identity/agent-single-cli-principal] [spec: agent-identity/agent-management-authority] [spec: management-api/management-restish-agent-auth] [spec: management-api/management-restish-user-crud] [spec: agent-identity/agent-public-resource-model]', async () => {
    const auth = createAuthMock()
    const dpop = await createTestDpopKey()
    let scopes = ['agent:read']
    let legacyAgentToken = false
    Object.assign(auth.api, {
      verifyJWT: vi.fn().mockImplementation(async () => ({
        payload: legacyAgentToken
          ? {
              iss: 'http://localhost/api/auth',
              sub: 'agt_1',
              sub_profile: 'ai_agent',
              client_id: 'protocol-agent-1',
              host_id: 'host-1',
              scope: scopes.join(' '),
              cnf: { jkt: dpop.thumbprint },
              realmroot_authority: { type: 'realmroot_authority', authority: 'organization', id: 'org-platform' },
            }
          : {
              iss: 'http://localhost/api/auth',
              sub: 'controller-1',
              client_id: realmrootCliClientId,
              act: { iss: 'http://localhost/api/auth', sub: 'agt_1' },
              scope: scopes.join(' '),
              cnf: { jkt: dpop.thumbprint },
              realmroot_authority: { type: 'realmroot_authority', authority: 'organization', id: 'org-platform' },
            },
      })),
    })
    const now = new Date()
    const identity = {
      identity: {
        id: 'identity-1',
        issuer: 'http://localhost/api/auth',
        subject: 'agt_1',
        username: 'build-agent.00000000000000000000000000000001',
        name: 'Build Agent',
        ownerUserId: 'controller-1',
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
    const users = createUserRepositoryMock()
    const deps = createTestDeps({
      users,
      agentIdentities: {
        findByIssuerSubject: vi.fn().mockResolvedValue(identity.identity),
        findActiveBindingByProtocolAgent: vi.fn().mockResolvedValue({
          identity: identity.identity,
          binding: identity.bindings[0],
        }),
        findActiveByProtocolAgent: vi.fn().mockResolvedValue(identity),
        findIdentity: vi.fn().mockResolvedValue(identity),
      },
      externalResources: {
        findActiveTokenLeaseByTokenHash: vi.fn().mockResolvedValue({ bindingId: 'binding-1' }),
      },
    })
    const app = createApp(auth, deps)
    const headers = (method: string, path: string) => dpop.headers(method, `http://localhost${path}`)

    const agent = await app.request('/api/agent', {
      headers: { ...(await headers('GET', '/api/agent')), 'x-user-id': 'controller-with-browser-session' },
    })
    expect(agent.status).toBe(200)
    await expect(agent.json()).resolves.toMatchObject({
      agent: { issuer: 'http://localhost/api/auth', subject: 'agt_1' },
    })
    const bearerAgent = await app.request('/api/agent', {
      headers: { authorization: 'Bearer test-oauth-access-token' },
    })
    expect(bearerAgent.status).toBe(401)
    legacyAgentToken = true
    const legacyAgent = await app.request('/api/agent', {
      headers: await headers('GET', '/api/agent'),
    })
    expect(legacyAgent.status, await legacyAgent.clone().text()).toBe(200)
    legacyAgentToken = false

    scopes = ['resource-servers:read']
    const discovery = await app.request('/api/resource-servers', {
      headers: await headers('GET', '/api/resource-servers'),
    })
    expect(discovery.status, await discovery.clone().text()).toBe(200)

    const assertionWithBrowserSession = await app.request('/api/resource-servers', {
      headers: {
        authorization: 'Bearer agent-assertion',
        'x-user-id': 'controller-with-browser-session',
      },
    })
    expect(assertionWithBrowserSession.status).toBe(401)

    const denied = await app.request('/api/users', { headers: await headers('GET', '/api/users') })
    expect(denied.status, await denied.clone().text()).toBe(403)
    await expect(denied.json()).resolves.toMatchObject({
      error: { message: 'OAuth scope "users:read" is required.' },
    })

    scopes = ['users:read']
    const allowed = await app.request('/api/users', { headers: await headers('GET', '/api/users') })
    expect(allowed.status).toBe(200)

    scopes = ['users:write']
    const created = await app.request('/api/users', {
      method: 'POST',
      headers: { ...(await headers('POST', '/api/users')), 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'managed@example.com',
        displayName: 'Managed User',
        password: 'Sup3rSecurePass!',
        role: 'user',
      }),
    })
    const updated = await app.request('/api/users/user-1', {
      method: 'PATCH',
      headers: { ...(await headers('PATCH', '/api/users/user-1')), 'content-type': 'application/json' },
      body: JSON.stringify({ displayName: 'Updated User' }),
    })
    const removed = await app.request('/api/users/user-1', {
      method: 'DELETE',
      headers: await headers('DELETE', '/api/users/user-1'),
    })

    expect(created.status, await created.clone().text()).toBe(201)
    expect(updated.status).toBe(200)
    expect(removed.status).toBe(204)
    expect(users.createManagedUser).toHaveBeenCalled()
    expect(users.updateManagedUser).toHaveBeenCalledWith('user-1', { displayName: 'Updated User' })
    expect(users.deleteManagedUser).toHaveBeenCalledWith('user-1')
  })

  it('accepts Bearer Applications, rejects DPoP Applications, and limits Machine authority [spec: management-api/management-machine-application-crud]', async () => {
    const auth = createAuthMock()
    const dpop = await createTestDpopKey()
    let scopes = ['applications:read']
    let confirmation: { jkt: string } | undefined
    Object.assign(auth.api, {
      verifyJWT: vi.fn().mockImplementation(async () => ({
        payload: {
          iss: 'http://localhost/api/auth',
          sub: 'application-1',
          client_id: 'client-1',
          scope: scopes.join(' '),
          ...(confirmation ? { cnf: confirmation } : {}),
        },
      })),
    })
    const deps = createTestDeps()
    vi.mocked(deps.applications.findByClientId).mockResolvedValue({
      id: 'application-1',
      clientId: 'client-1',
      ownerOrganizationId: 'organization-1',
      disabled: false,
    } as never)
    const app = createApp(auth, deps)

    const ownUrl = 'http://localhost/api/applications?ownerOrganizationId=organization-1'
    const own = await app.request(ownUrl, {
      headers: { authorization: 'Bearer application-access-token' },
    })
    expect(own.status).toBe(200)

    confirmation = { jkt: dpop.thumbprint }
    const boundBearerApplication = await app.request(ownUrl, {
      headers: { authorization: 'Bearer application-access-token' },
    })
    expect(boundBearerApplication.status).toBe(401)
    confirmation = undefined

    const dpopApplication = await app.request(ownUrl, {
      headers: await dpop.headers('GET', ownUrl),
    })
    expect(dpopApplication.status).toBe(401)

    scopes = ['applications:write']
    const otherUrl = 'http://localhost/api/applications'
    const other = await app.request(otherUrl, {
      method: 'POST',
      headers: {
        authorization: 'Bearer application-access-token',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Other Organization App',
        clientType: 'public_native',
        ownerOrganizationId: 'organization-2',
        redirectUris: ['com.example:/callback'],
      }),
    })
    expect(other.status).toBe(403)

    scopes = []
    const missingScope = await app.request(ownUrl, {
      headers: { authorization: 'Bearer application-access-token' },
    })
    expect(missingScope.status).toBe(403)
  })

  it('preserves the represented User on authorization-code Application tokens and rejects Application-only Agent creation [spec: agent-identity/application-agent-creation]', async () => {
    const auth = createAuthMock()
    let tokenSubject = 'user-1'
    Object.assign(auth.api, {
      verifyJWT: vi.fn().mockImplementation(async () => ({
        payload: {
          iss: 'http://localhost/api/auth',
          sub: tokenSubject,
          client_id: 'ama-client',
          scope: 'agents:write',
        },
      })),
    })
    const deps = createTestDeps({ users: createUserRepositoryMock() })
    vi.mocked(deps.applications.findByClientId).mockResolvedValue({
      id: 'application-1',
      clientId: 'ama-client',
      ownerOrganizationId: 'org-platform',
      disabled: false,
    } as never)
    vi.spyOn(agentIdentitiesUsecase, 'createAgentWithInstallation').mockResolvedValue({
      replayed: false,
      agent: {
        id: 'agent-1',
        issuer: 'http://localhost/api/auth',
        subject: 'agt_1',
        username: 'ama-worker',
        name: 'AMA Worker',
        runtime: 'ama',
        homeSpace: { type: 'personal', userId: 'user-1' },
        status: 'active',
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
      },
    })
    const app = createApp(auth, deps)
    const request = async () =>
      app.request('/api/agents', {
        method: 'POST',
        headers: {
          authorization: 'Bearer application-access-token',
          'content-type': 'application/json',
          'idempotency-key': 'ama-agent-1',
        },
        body: JSON.stringify({
          username: 'ama-worker',
          name: 'AMA Worker',
          runtime: 'ama',
          installation: {
            agentId: 'ama-protocol-agent-1',
            hostId: 'ama-host-1',
            name: 'AMA Runner',
            kid: 'ama-key-1',
            publicKey: { kty: 'OKP', crv: 'Ed25519', x: 'public', kid: 'ama-key-1' },
          },
        }),
      })

    const delegated = await request()
    expect(delegated.status, await delegated.clone().text()).toBe(201)
    expect(agentIdentitiesUsecase.createAgentWithInstallation).toHaveBeenCalledWith(
      expect.anything(),
      expect.not.objectContaining({ organizationId: expect.anything() }),
      expect.objectContaining({ applicationId: 'application-1', actorUserId: 'user-1' }),
    )

    tokenSubject = 'application-1'
    const applicationOnly = await request()
    expect(applicationOnly.status, await applicationOnly.clone().text()).toBe(403)
    expect(agentIdentitiesUsecase.createAgentWithInstallation).toHaveBeenCalledTimes(1)
  })

  it('denies an unavailable authorization-code User and preserves repository failures', async () => {
    const auth = createAuthMock()
    const tokenSubject = 'user-1'
    Object.assign(auth.api, {
      verifyJWT: vi.fn().mockImplementation(async () => ({
        payload: {
          iss: 'http://localhost/api/auth',
          sub: tokenSubject,
          client_id: 'ama-client',
          scope: 'agents:write',
        },
      })),
    })
    const users = createUserRepositoryMock()
    const deps = createTestDeps({ users })
    vi.mocked(deps.applications.findByClientId).mockResolvedValue({
      id: 'application-1',
      clientId: 'ama-client',
      ownerOrganizationId: 'org-platform',
      disabled: false,
    } as never)
    const app = createApp(auth, deps)
    const request = async (path = '/api/agents') =>
      app.request(path, {
        headers: { authorization: 'Bearer application-access-token' },
      })

    vi.mocked(users.getUser).mockRejectedValueOnce(notFound('User was not found.'))
    const missingUser = await request()
    expect(missingUser.status, await missingUser.clone().text()).toBe(403)

    vi.mocked(users.getUser).mockRejectedValueOnce(new Error('repository unavailable'))
    const repositoryFailure = await request()
    expect(repositoryFailure.status, await repositoryFailure.clone().text()).toBe(500)
  })

  it('intersects authorization-code User authority with the Application token scopes', async () => {
    const auth = createAuthMock()
    Object.assign(auth.api, {
      verifyJWT: vi.fn().mockResolvedValue({
        payload: {
          iss: 'http://localhost/api/auth',
          sub: 'user-1',
          client_id: 'ama-client',
          scope: 'agents:write',
        },
      }),
    })
    const deps = createTestDeps({ users: createUserRepositoryMock() })
    vi.mocked(deps.applications.findByClientId).mockResolvedValue({
      id: 'application-1',
      clientId: 'ama-client',
      ownerOrganizationId: 'org-platform',
      disabled: false,
    } as never)
    const app = createApp(auth, deps)
    const url = 'http://localhost/api/users'

    const response = await app.request(url, {
      method: 'POST',
      headers: { authorization: 'Bearer application-access-token', 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'scope-denied@example.com',
        displayName: 'Scope Denied',
        password: 'Sup3rSecurePass!',
        role: 'user',
      }),
    })

    expect(response.status, await response.clone().text()).toBe(403)
    expect(deps.users.listManagedUsers).not.toHaveBeenCalled()
  })

  it('does not expose the removed capability request resource', async () => {
    const auth = createAuthMock()
    auth.api.getAgentSession.mockResolvedValue(agentSession())
    auth.handler.mockImplementationOnce(async (request) => {
      expect(new URL(request.url).pathname).toBe('/api/auth/agent/request-capability')
      await expect(request.json()).resolves.toEqual({
        capabilities: ['applications:read', 'applications:write'],
        reason: 'Administer this tenant',
        preferred_method: 'device_authorization',
        binding_message: 'Agent requesting applications:read, applications:write',
      })
      return Response.json({
        agent_id: 'protocol-agent-1',
        status: 'pending',
        agent_capability_grants: [
          { capability: 'applications:read', status: 'pending' },
          { capability: 'applications:write', status: 'pending' },
        ],
        approval: {
          method: 'device_authorization',
          device_code: 'approval-1',
          verification_uri: 'https://auth.example.com/agent/enrollments/approve',
          verification_uri_complete:
            'https://auth.example.com/agent/enrollments/approve?agent_id=protocol-agent-1&code=ABCD-1234',
          user_code: 'ABCD-1234',
          expires_in: 600,
          interval: 5,
        },
      })
    })
    const deps = createTestDeps({
      agentIdentities: {
        findActiveByProtocolAgent: vi.fn().mockResolvedValue(agentIdentity()),
      },
    })
    vi.mocked(deps.agents.findApprovalRequest).mockResolvedValue({
      id: 'approval-1',
      method: 'device_authorization',
      agentId: 'protocol-agent-1',
      hostId: 'host-1',
      userId: 'controller-1',
      capabilities: 'applications:read applications:write',
      status: 'pending',
      userCodeHash: 'hash',
      loginHint: null,
      bindingMessage: null,
      clientNotificationToken: null,
      clientNotificationEndpoint: null,
      deliveryMode: null,
      interval: 5,
      lastPolledAt: null,
      expiresAt: new Date('2099-01-01T00:10:00.000Z'),
      createdAt: new Date('2099-01-01T00:00:00.000Z'),
      updatedAt: new Date('2099-01-01T00:00:00.000Z'),
    })
    const app = createApp(auth, deps)

    const response = await app.request('https://auth.example.com/api/capability-requests', {
      method: 'POST',
      headers: {
        authorization: 'Bearer agent-proof',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        capabilities: ['applications:read', 'applications:write'],
        reason: 'Administer this tenant',
      }),
    })

    expect(response.status).toBe(404)
  })
})

async function createTestDpopKey() {
  const accessToken = 'test-oauth-access-token'
  const { privateKey, publicKey } = await generateKeyPair('ES256')
  const jwk = await exportJWK(publicKey)
  const thumbprint = await calculateJwkThumbprint(jwk)
  return {
    thumbprint,
    async headers(method: string, requestUrl: string) {
      const url = new URL(requestUrl)
      url.search = ''
      url.hash = ''
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken))
      const ath = Buffer.from(digest).toString('base64url')
      const proof = await new SignJWT({
        htm: method,
        htu: url.toString(),
        ath,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(),
      })
        .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk })
        .sign(privateKey)
      return { authorization: `DPoP ${accessToken}`, DPoP: proof }
    },
  }
}

function agentSession() {
  return {
    agentId: 'protocol-agent-1',
    agent: { id: 'protocol-agent-1', hostId: 'host-1', mode: 'delegated', capabilityGrants: [] },
    host: { id: 'host-1', userId: 'controller-1', status: 'active' },
  }
}

function agentIdentity() {
  const now = new Date()
  return {
    identity: {
      id: 'identity-1',
      issuer: 'https://auth.example.com/api/auth',
      subject: 'agt_1',
      username: 'build-agent.00000000000000000000000000000001',
      name: 'Build Agent',
      ownerUserId: 'controller-1',
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
