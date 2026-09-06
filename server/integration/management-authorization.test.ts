import { applyD1Migrations, env, reset } from 'cloudflare:test'
import {
  agent,
  agentAccessRequest,
  agentAuditEvent,
  agentHost,
  agentIdentity,
  agentIdentityBinding,
  apiResource,
  application,
  externalTokenLease,
  identityProviderConnector,
  member,
  organizationRole,
  providerConnection,
  providerCredential,
  providerResourceAuthorization,
  resourceConnectionIntent,
  resourceScopeEntitlement,
  user,
} from '@server/db/schema'
import { createResource } from '@server/usecases/authorization'
import { discoverAgentResources } from '@server/usecases/external-resources'
import { encodeRoleScope } from '@shared/organization-access'
import { eq } from 'drizzle-orm'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  createHarness,
  createUser,
  type Harness,
  platformOrganizationId,
  realmrootResourceServerId,
  resourceOpenApiFetch,
  signIn,
  signInAdmin,
} from './harness'

afterEach(async () => {
  await reset()
  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS)
})

async function postJson(harness: Harness, cookie: string, path: string, body: unknown, expected = 201) {
  const response = await harness.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify(body),
  })
  expect(response.status, await response.clone().text()).toBe(expected)
  return response
}

describe('authorization management over real D1', () => {
  let harness: Harness

  beforeEach(async () => {
    harness = await createHarness()
    harness.deps.externalHttp.fetch = resourceOpenApiFetch
  })

  it('[spec: agent-identity/direct-agent-permission-http] creates and reuses permissions with controller boundaries', async () => {
    const adminCookie = await signInAdmin(harness)
    await createUser(harness, adminCookie, {
      email: 'agent-controller@example.com',
      username: 'agent-controller',
      displayName: 'Agent controller',
      password: 'Password123!',
    })
    const cookie = await signIn(harness, 'agent-controller@example.com', 'Password123!')
    const admin = await harness.db.query.user.findFirst({ where: eq(user.email, 'agent-controller@example.com') })
    expect(admin).toBeDefined()
    const now = new Date()
    await harness.db.insert(agentIdentity).values({
      id: 'direct-identity',
      issuer: 'http://localhost/api/auth',
      subject: 'direct-subject',
      username: 'direct-permission-agent',
      name: 'Direct permission Agent',
      ownerUserId: admin!.id,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    })
    const input = {
      resource: 'http://localhost/api',
      scopes: ['agents:read'],
      mode: 'persistent',
    }
    const [first, replay] = await Promise.all([
      postJson(harness, cookie, '/api/agents/direct-identity/permissions', input),
      postJson(harness, cookie, '/api/agents/direct-identity/permissions', input),
    ])
    const {
      items: [permission],
    } = (await first.json()) as { items: { id: string }[] }
    expect(await replay.json()).toMatchObject({
      items: [{ id: permission!.id, sourceAccessRequestId: null, status: 'active' }],
    })
    expect(
      await harness.db
        .select()
        .from(resourceScopeEntitlement)
        .where(eq(resourceScopeEntitlement.agentIdentityId, 'direct-identity')),
    ).toHaveLength(1)
    expect(await harness.db.select().from(agentAccessRequest)).toHaveLength(0)
    const anonymous = await harness.request('/api/agents/direct-identity/permissions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    })
    expect(anonymous.status).toBe(401)
    await postJson(harness, cookie, '/api/agents/direct-identity/permissions', { ...input, mode: 'until' }, 400)
    await createUser(harness, adminCookie, {
      email: 'other-controller@example.com',
      username: 'other-controller',
      displayName: 'Other controller',
      password: 'Password123!',
    })
    const other = await signIn(harness, 'other-controller@example.com', 'Password123!')
    await postJson(harness, other, '/api/agents/direct-identity/permissions', input, 403)
  })

  it('rejects anonymous reads with 401', async () => {
    const response = await harness.request('/api/resource-servers')
    expect(response.status).toBe(401)
  })

  it('[spec: management-api/management-api-resource-soft-delete] reuses deleted keys and keeps delete outcomes atomic', async () => {
    const cookie = await signInAdmin(harness)
    const original = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'reserved-resource',
        resourceUrl: 'https://reserved-resource.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }

    const deleted = await harness.request(`/api/resource-servers/${original.id}`, {
      method: 'DELETE',
      headers: { cookie },
    })
    expect(deleted.status).toBe(204)

    const retry = await harness.request(`/api/resource-servers/${original.id}`, {
      method: 'DELETE',
      headers: { cookie },
    })
    expect(retry.status).toBe(404)
    await expect(retry.json()).resolves.toMatchObject({ error: { code: 'not_found' } })

    const exactReplacement = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'reserved-resource',
        resourceUrl: 'https://reserved-resource.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    expect(exactReplacement.id).not.toBe(original.id)
    expect(
      (
        await harness.request(`/api/resource-servers/${exactReplacement.id}`, {
          method: 'DELETE',
          headers: { cookie },
        })
      ).status,
    ).toBe(204)

    const sameIdentifier = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'reserved-resource',
        resourceUrl: 'https://different-reserved-resource.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    expect(
      (
        await harness.request(`/api/resource-servers/${sameIdentifier.id}`, {
          method: 'DELETE',
          headers: { cookie },
        })
      ).status,
    ).toBe(204)

    const sameUrl = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'different-reserved-resource',
        resourceUrl: 'https://reserved-resource.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    expect(
      (
        await harness.request(`/api/resource-servers/${sameUrl.id}`, {
          method: 'DELETE',
          headers: { cookie },
        })
      ).status,
    ).toBe(204)

    const activeKeyOwner = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'active-key-owner',
        resourceUrl: 'https://active-key-owner.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    const updateTarget = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'update-target-resource',
        resourceUrl: 'https://update-target-resource.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    for (const patch of [
      { identifier: 'active-key-owner' },
      { resourceUrl: 'https://active-key-owner.example.com/api' },
    ]) {
      const response = await harness.request(`/api/resource-servers/${updateTarget.id}`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json', cookie },
        body: JSON.stringify(patch),
      })
      expect(response.status).toBe(409)
      await expect(response.json()).resolves.toMatchObject({ error: { code: 'conflict' } })
    }
    expect(activeKeyOwner.id).toBeTruthy()

    const concurrentBody = JSON.stringify({
      identifier: 'concurrent-resource',
      resourceUrl: 'https://concurrent-resource.example.com/api',
      authorizationModel: 'native',
      ownerOrganizationId: platformOrganizationId,
    })
    const concurrent = await Promise.all(
      [0, 1].map(() =>
        harness.request('/api/resource-servers', {
          method: 'POST',
          headers: { 'content-type': 'application/json', cookie },
          body: concurrentBody,
        }),
      ),
    )
    expect(concurrent.map((response) => response.status).sort()).toEqual([201, 409])
    const conflictResponse = concurrent.find((response) => response.status === 409)!
    await expect(conflictResponse.json()).resolves.toMatchObject({ error: { code: 'conflict' } })

    const rollbackTarget = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'rollback-resource',
        resourceUrl: 'https://rollback-resource.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    const [existingAudit] = await harness.db
      .select()
      .from(agentAuditEvent)
      .where(eq(agentAuditEvent.resourceId, original.id))
    await expect(
      harness.deps.authorization.deleteResource(rollbackTarget.id, new Date(), {
        ...existingAudit!,
        resourceId: rollbackTarget.id,
      }),
    ).rejects.toThrow()
    await expect(harness.deps.authorization.findResource(rollbackTarget.id)).resolves.toMatchObject({
      id: rollbackTarget.id,
      enabled: true,
    })
  })

  it('rejects a signed-in non-admin with 403', async () => {
    const adminCookie = await signInAdmin(harness)
    await createUser(harness, adminCookie, {
      email: 'member@example.com',
      username: 'member',
      displayName: 'Member',
      password: 'member-password-2026',
    })
    const memberCookie = await signIn(harness, 'member@example.com', 'member-password-2026')

    const response = await harness.request('/api/organizations/org-missing/roles', {
      headers: { cookie: memberCookie },
    })
    expect(response.status).toBe(403)
  })

  it('blocks direct Better Auth Role mutations outside the audited facade', async () => {
    const cookie = await signInAdmin(harness)
    for (const path of [
      '/api/auth/organization/create-role',
      '/api/auth/organization/update-role',
      '/api/auth/organization/delete-role',
      '/api/auth/organization/update-member-role',
    ]) {
      const response = await harness.request(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie },
        body: '{}',
      })
      expect(response.status, path).toBe(404)
    }
  })

  it('exposes the platform Organization through ordinary Organization authorization', async () => {
    const cookie = await signInAdmin(harness)
    const listResponse = await harness.request('/api/organizations', { headers: { cookie } })
    expect(listResponse.status).toBe(200)
    expect((await listResponse.json()) as { items: Array<{ id: string }> }).toMatchObject({
      items: expect.arrayContaining([expect.objectContaining({ id: platformOrganizationId })]),
    })
    for (const request of [
      harness.request(`/api/organizations/${platformOrganizationId}`, { headers: { cookie } }),
      harness.request(`/api/organizations/${platformOrganizationId}/members`, { headers: { cookie } }),
    ]) {
      const response = await request
      expect(response.status).toBe(200)
    }
  })

  it('atomically assigns the authenticated creator as Organization Owner [spec: admin-console/admin-create-organization]', async () => {
    const cookie = await signInAdmin(harness)
    const [admin] = await harness.db.select({ id: user.id }).from(user).where(eq(user.role, 'admin')).limit(1)

    const response = await postJson(harness, cookie, '/api/organizations', {
      slug: 'owned-on-create',
      name: 'Owned On Create',
    })
    const created = (await response.json()) as { id: string }
    const memberships = await harness.db.select().from(member).where(eq(member.organizationId, created.id))

    expect(memberships).toHaveLength(1)
    expect(memberships[0]).toMatchObject({ userId: admin.id, role: 'owner' })

    await expect(
      harness.deps.authorization.createOrganization(
        {
          id: 'org-owner-rollback',
          slug: 'owner-rollback',
          name: 'Owner Rollback',
          displayName: null,
          logo: null,
          disabled: false,
          disabledReason: null,
        },
        {
          id: 'member-owner-rollback',
          userId: 'missing-user',
          roles: ['owner'],
          title: null,
        },
      ),
    ).rejects.toThrow()
    await expect(harness.deps.authorization.findOrganization('org-owner-rollback')).resolves.toBeNull()
  })

  it('returns User-owned audit events without an Organization filter', async () => {
    const adminCookie = await signInAdmin(harness)
    const personalUser = await createUser(harness, adminCookie, {
      email: 'personal-audit@example.com',
      username: 'personal-audit',
      displayName: 'Personal Audit',
      password: 'personal-audit-password-2026',
    })
    const auditResource = await createResource(harness.deps, {
      identifier: 'personal-audit-resource',
      resourceUrl: 'https://personal-audit.example.com/api',
      authorizationModel: 'native',
      ownerOrganizationId: platformOrganizationId,
    })
    await harness.db.insert(agentAuditEvent).values({
      id: 'personal-audit-event',
      action: 'agent.identity_enrolled',
      result: 'allowed',
      realmOwned: false,
      ownerUserId: personalUser,
      occurredAt: new Date(),
    })
    await harness.db.insert(agentAuditEvent).values({
      id: 'personal-audit-denied-event',
      action: 'api_resource.access_decided',
      result: 'denied',
      realmOwned: false,
      ownerUserId: personalUser,
      accessRequestId: 'request-denied',
      resourceId: auditResource.id,
      scopes: ['projects:write'],
      occurredAt: new Date(),
    })
    const cookie = await signIn(harness, 'personal-audit@example.com', 'personal-audit-password-2026')

    const response = await harness.request('/api/realm/audit-events', { headers: { cookie } })

    expect(response.status).toBe(200)
    expect(((await response.json()) as { items: { id: string }[] }).items.map((event) => event.id)).toContain(
      'personal-audit-event',
    )

    const filtered = await harness.request(
      '/api/realm/audit-events?action=api_resource.access_decided&result=denied&search=projects%3Awrite',
      { headers: { cookie } },
    )
    await expect(filtered.json()).resolves.toMatchObject({
      items: [
        {
          id: 'personal-audit-denied-event',
          resource: { id: auditResource.id, identifier: 'personal-audit-resource' },
        },
      ],
      pagination: { totalItems: 1 },
    })
    const resourceSearch = await harness.request('/api/realm/audit-events?search=personal-audit-resource', {
      headers: { cookie },
    })
    await expect(resourceSearch.json()).resolves.toMatchObject({
      items: [{ id: 'personal-audit-denied-event' }],
      pagination: { totalItems: 1 },
    })
  })

  it('does not delete a dynamic Role referenced by a pending invitation', async () => {
    const cookie = await signInAdmin(harness)
    const organization = (await (
      await postJson(harness, cookie, '/api/organizations', { slug: 'invited-role', name: 'Invited Role' })
    ).json()) as { id: string }
    await postJson(harness, cookie, `/api/organizations/${organization.id}/roles`, {
      key: 'reviewer',
      displayName: 'Reviewer',
      scopes: [],
    })
    await postJson(harness, cookie, `/api/organizations/${organization.id}/invitations`, {
      email: 'reviewer@example.com',
      roles: ['reviewer'],
    })

    const response = await harness.request(`/api/organizations/${organization.id}/roles/reviewer`, {
      method: 'DELETE',
      headers: { cookie },
    })
    expect(response.status).toBe(409)
    await expect(harness.deps.authorization.findOrganizationRole(organization.id, 'reviewer')).resolves.not.toBeNull()
  })

  it('rolls back a Role write when its audit insert fails', async () => {
    await signInAdmin(harness)
    const [admin] = await harness.db.select({ id: user.id }).from(user).where(eq(user.role, 'admin')).limit(1)
    const organization = await harness.deps.authorization.createOrganization(
      {
        id: 'org-audit',
        slug: 'org-audit',
        name: 'Audit Organization',
        displayName: null,
        logo: null,
        disabled: false,
        disabledReason: null,
      },
      {
        id: 'org-audit-owner',
        userId: admin.id,
        roles: ['owner'],
        title: null,
      },
    )
    const occurredAt = new Date()
    await harness.db.insert(agentAuditEvent).values({
      id: 'duplicate-audit',
      action: 'seed',
      result: 'allowed',
      realmOwned: false,
      ownerOrganizationId: organization.id,
      occurredAt,
    })

    await expect(
      harness.deps.authorization.createOrganizationRole(
        organization.id,
        { key: 'operator', displayName: 'Operator', description: null, scopes: [] },
        { scope: [] },
        {
          id: 'duplicate-audit',
          action: 'organization.role.created',
          result: 'allowed',
          realmOwned: false,
          ownerUserId: null,
          ownerOrganizationId: organization.id,
          controllerUserId: null,
          subjectIssuer: null,
          subject: null,
          agentIdentityId: null,
          hostId: null,
          resourceId: null,
          resourceConnectionId: null,
          accessRequestId: null,
          scopes: null,
          reasonCode: null,
          metadata: null,
          occurredAt,
        },
      ),
    ).rejects.toThrow()
    expect(
      await harness.db.select().from(organizationRole).where(eq(organizationRole.organizationId, organization.id)),
    ).toEqual([])
  })

  it('rolls back an Agent grant decision when its audit insert fails', async () => {
    await signInAdmin(harness)
    const [admin] = await harness.db.select({ id: user.id }).from(user).where(eq(user.email, 'admin@example.com'))
    const now = new Date()
    const resource = await createResource(harness.deps, {
      identifier: 'atomic-agent-api',
      resourceUrl: 'https://atomic-agent.example.com/api',
      authorizationModel: 'native',
      ownerOrganizationId: platformOrganizationId,
    })
    await harness.db.insert(agentHost).values({
      id: 'atomic-host',
      userId: admin.id,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(agent).values({
      id: 'atomic-agent',
      name: 'Atomic Agent',
      userId: admin.id,
      hostId: 'atomic-host',
      status: 'active',
      publicKey: '{}',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(agentIdentity).values({
      id: 'atomic-identity',
      issuer: 'http://localhost/api/auth',
      subject: 'atomic-subject',
      username: 'atomic-identity.00000000000000000000000000000009',
      name: 'Atomic identity',
      ownerUserId: admin.id,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(agentIdentityBinding).values({
      id: 'atomic-binding',
      agentIdentityId: 'atomic-identity',
      protocolAgentId: 'atomic-agent',
      status: 'active',
      boundAt: now,
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(agentAccessRequest).values({
      id: 'atomic-request',
      resourceId: resource.id,
      connectionId: null,
      agentIdentityId: 'atomic-identity',
      bindingId: 'atomic-binding',
      scopes: ['files:read'],
      status: 'pending',
      approvalTokenHash: 'atomic-approval-hash',
      encryptedApprovalToken: 'encrypted-approval',
      expiresAt: new Date(now.getTime() + 60_000),
      createdAt: now,
      updatedAt: now,
    })
    const audit = {
      id: 'duplicate-agent-audit',
      action: 'api_resource.access_decided',
      result: 'allowed',
      realmOwned: false,
      ownerUserId: admin.id,
      ownerOrganizationId: null,
      controllerUserId: admin.id,
      subjectIssuer: null,
      subject: null,
      agentIdentityId: 'atomic-identity',
      hostId: 'atomic-host',
      resourceId: resource.id,
      resourceConnectionId: null,
      accessRequestId: 'atomic-request',
      scopes: ['files:read'],
      reasonCode: null,
      metadata: null,
      occurredAt: now,
    }
    await harness.db.insert(agentAuditEvent).values(audit)

    await expect(
      harness.deps.externalResources.approveAccessRequestWithEntitlements(
        [
          {
            id: 'atomic-entitlement',
            userId: null,
            applicationId: null,
            resourceServerId: resource.id,
            connectionId: null,
            agentIdentityId: 'atomic-identity',
            organizationId: null,
            authorizationContextHash: 'ctx-empty',
            scope: 'files:read',
            authorizationDetails: [],
            mode: 'persistent',
            grantedByUserId: admin.id,
            grantedByAgentIdentityId: null,
            sourceAccessRequestId: 'atomic-request',
            expiresAt: null,
            endedAt: null,
            endReason: null,
            createdAt: now,
            updatedAt: now,
          },
        ],
        [],
        'atomic-request',
        {
          status: 'approved',
          approvedEntitlements: [{ scope: 'files:read', entitlementId: 'atomic-entitlement' }],
          connectionId: null,
          authorizationDetails: [],
          decidedAt: now,
          updatedAt: now,
        },
        audit,
      ),
    ).rejects.toThrow()
    await expect(
      harness.db
        .select({ id: resourceScopeEntitlement.id })
        .from(resourceScopeEntitlement)
        .where(eq(resourceScopeEntitlement.id, 'atomic-entitlement')),
    ).resolves.toEqual([])
    await expect(
      harness.db
        .select({ status: agentAccessRequest.status })
        .from(agentAccessRequest)
        .where(eq(agentAccessRequest.id, 'atomic-request')),
    ).resolves.toEqual([{ status: 'pending' }])

    const deniedAudit = { ...audit, id: 'atomic-denied-audit', result: 'denied', accessRequestId: null }
    await expect(
      harness.deps.externalResources.decideAccessRequestWithAudit(
        'atomic-request',
        { status: 'denied', approvedEntitlements: [], decidedAt: now, updatedAt: now },
        deniedAudit,
      ),
    ).resolves.not.toBeNull()
    await expect(
      harness.deps.externalResources.decideAccessRequestWithAudit(
        'atomic-request',
        { status: 'denied', approvedEntitlements: [], decidedAt: new Date(), updatedAt: new Date() },
        { ...deniedAudit, id: 'atomic-duplicate-denied-audit' },
      ),
    ).resolves.toBeNull()
    await expect(
      harness.db
        .select({ id: agentAuditEvent.id })
        .from(agentAuditEvent)
        .where(eq(agentAuditEvent.id, 'atomic-duplicate-denied-audit')),
    ).resolves.toEqual([])

    await harness.db.insert(resourceScopeEntitlement).values({
      id: 'atomic-revoke-grant',
      resourceServerId: resource.id,
      connectionId: null,
      agentIdentityId: 'atomic-identity',
      authorizationContextHash: 'ctx-empty',
      scope: 'files:read',
      authorizationDetails: [],
      mode: 'persistent',
      grantedByUserId: admin.id,
      createdAt: now,
      updatedAt: now,
    })
    const revokedAudit = {
      ...audit,
      id: 'atomic-revoked-audit',
      action: 'api_resource.access_revoked',
      accessRequestId: 'atomic-revoke-grant',
    }
    await expect(
      harness.deps.externalResources.endEntitlementWithAudit('atomic-revoke-grant', 'revoked', [], now, revokedAudit),
    ).resolves.toBe(true)
    await expect(
      harness.deps.externalResources.endEntitlementWithAudit('atomic-revoke-grant', 'revoked', [], new Date(), {
        ...revokedAudit,
        id: 'atomic-duplicate-revoked-audit',
      }),
    ).resolves.toBe(false)
    await expect(
      harness.db
        .select({ id: agentAuditEvent.id })
        .from(agentAuditEvent)
        .where(eq(agentAuditEvent.id, 'atomic-duplicate-revoked-audit')),
    ).resolves.toEqual([])

    await harness.db.insert(agentAccessRequest).values({
      id: 'atomic-once-request',
      resourceId: resource.id,
      connectionId: null,
      agentIdentityId: 'atomic-identity',
      bindingId: 'atomic-binding',
      scopes: ['files:once'],
      authorizationDetails: [],
      status: 'approved',
      approvalTokenHash: 'atomic-once-approval-hash',
      encryptedApprovalToken: 'atomic-once-approval',
      approvedEntitlements: [{ scope: 'files:once', entitlementId: 'atomic-once-entitlement' }],
      expiresAt: new Date(now.getTime() + 60_000),
      decidedAt: now,
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(resourceScopeEntitlement).values({
      id: 'atomic-once-entitlement',
      resourceServerId: resource.id,
      agentIdentityId: 'atomic-identity',
      authorizationContextHash: 'ctx-empty',
      scope: 'files:once',
      authorizationDetails: [],
      mode: 'once',
      grantedByUserId: admin.id,
      sourceAccessRequestId: 'atomic-once-request',
      createdAt: now,
      updatedAt: now,
    })
    const onceLease = (id: string) => ({
      id,
      entitlementIds: ['atomic-once-entitlement'],
      requestId: 'atomic-once-request',
      bindingId: 'atomic-binding',
      encryptedAccessToken: `sealed-${id}`,
      tokenHash: `hash-${id}`,
      confirmationJkt: 'atomic-jkt',
      scopes: ['files:once'],
      authorizationDetails: [],
      expiresAt: new Date(now.getTime() + 30_000),
      revokedAt: null,
      createdAt: now,
    })
    const onceBoundary = {
      agentIdentityId: 'atomic-identity',
      resourceServerId: resource.id,
      connectionId: null,
      authorizationContextHash: 'ctx-empty',
      scopes: ['files:once'],
    }
    const [firstLease, secondLease] = await Promise.all([
      harness.deps.externalResources.issueTokenLeaseWithAudit(
        onceLease('atomic-once-lease-1'),
        onceBoundary,
        ['atomic-once-entitlement'],
        now,
        { ...audit, id: 'atomic-once-audit-1', accessRequestId: 'atomic-once-request' },
      ),
      harness.deps.externalResources.issueTokenLeaseWithAudit(
        onceLease('atomic-once-lease-2'),
        onceBoundary,
        ['atomic-once-entitlement'],
        now,
        { ...audit, id: 'atomic-once-audit-2', accessRequestId: 'atomic-once-request' },
      ),
    ])
    expect([firstLease, secondLease].filter(Boolean)).toHaveLength(1)
    await expect(
      harness.db.select().from(externalTokenLease).where(eq(externalTokenLease.requestId, 'atomic-once-request')),
    ).resolves.toHaveLength(1)
    await expect(
      harness.db
        .select({ endReason: resourceScopeEntitlement.endReason })
        .from(resourceScopeEntitlement)
        .where(eq(resourceScopeEntitlement.id, 'atomic-once-entitlement')),
    ).resolves.toEqual([{ endReason: 'consumed' }])
  })

  it('allows only one concurrent last-Owner demotion', async () => {
    const cookie = await signInAdmin(harness)
    const organization = (await (
      await postJson(harness, cookie, '/api/organizations', { slug: 'owner-race', name: 'Owner Race' })
    ).json()) as { id: string }
    const creator = (await harness.deps.authorization.listMembers(organization.id, { limit: 10, offset: 0 })).items[0]
    const userId = await createUser(harness, cookie, {
      email: 'one@example.com',
      username: 'owner-one',
      displayName: 'Owner One',
      password: 'owner-one-password-2026',
    })
    const addedOwner = (await (
      await postJson(harness, cookie, `/api/organizations/${organization.id}/members`, {
        userId,
        roles: ['owner'],
      })
    ).json()) as { id: string }
    const members = [creator, addedOwner]

    const responses = await Promise.all(
      members.map((member) =>
        harness.request(`/api/organizations/${organization.id}/members/${member.id}/roles`, {
          method: 'PUT',
          headers: { 'content-type': 'application/json', cookie },
          body: JSON.stringify({ roles: ['member'] }),
        }),
      ),
    )
    expect(responses.map((response) => response.status).sort()).toEqual([200, 412])
    const remaining = await harness.deps.authorization.listMembers(organization.id, { limit: 10, offset: 0 })
    expect(remaining.items.filter((member) => member.roles.includes('owner'))).toHaveLength(1)
  })

  it('allows only one concurrent last-Owner removal', async () => {
    const cookie = await signInAdmin(harness)
    const organization = (await (
      await postJson(harness, cookie, '/api/organizations', { slug: 'owner-delete-race', name: 'Owner Delete Race' })
    ).json()) as { id: string }
    const creator = (await harness.deps.authorization.listMembers(organization.id, { limit: 10, offset: 0 })).items[0]
    const userId = await createUser(harness, cookie, {
      email: 'delete-one@example.com',
      username: 'delete-one',
      displayName: 'Delete One',
      password: 'delete-one-password-2026',
    })
    const addedOwner = (await (
      await postJson(harness, cookie, `/api/organizations/${organization.id}/members`, {
        userId,
        roles: ['owner'],
      })
    ).json()) as { id: string }
    const members = [creator, addedOwner]

    const responses = await Promise.all(
      members.map((member) =>
        harness.request(`/api/organizations/${organization.id}/members/${member.id}`, {
          method: 'DELETE',
          headers: { cookie },
        }),
      ),
    )
    expect(responses.map((response) => response.status).sort()).toEqual([204, 412])
    const remaining = await harness.deps.authorization.listMembers(organization.id, { limit: 10, offset: 0 })
    expect(remaining.items.filter((member) => member.roles.includes('owner'))).toHaveLength(1)
  })

  it('allows an Organization admin with Role assignment authority to assign itself Owner', async () => {
    const ownerCookie = await signInAdmin(harness)
    const organization = (await (
      await postJson(harness, ownerCookie, '/api/organizations', { slug: 'no-self-promotion', name: 'No Promotion' })
    ).json()) as { id: string }
    const userId = await createUser(harness, ownerCookie, {
      email: 'organization-admin@example.com',
      username: 'organization-admin',
      displayName: 'Organization Admin',
      password: 'organization-admin-password-2026',
    })
    const member = (await (
      await postJson(harness, ownerCookie, `/api/organizations/${organization.id}/members`, {
        userId,
        roles: ['admin'],
      })
    ).json()) as { id: string }
    const adminCookie = await signIn(harness, 'organization-admin@example.com', 'organization-admin-password-2026')

    const response = await harness.request(`/api/organizations/${organization.id}/members/${member.id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: adminCookie },
      body: JSON.stringify({ roles: ['owner'] }),
    })
    expect(response.status, await response.clone().text()).toBe(200)
    const updated = await harness.deps.authorization.findMember(member.id)
    expect(updated?.roles).toEqual(['owner'])
  })

  it('rejects an invalid api-resource payload with 400', async () => {
    const cookie = await signInAdmin(harness)
    const response = await harness.request('/api/resource-servers', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'missing identifier' }),
    })
    expect(response.status).toBe(400)
  })

  it('[spec: admin-console/admin-resource-permissions] manages direct Permissions below each subject', async () => {
    const cookie = await signInAdmin(harness)
    const targetUserId = await createUser(harness, cookie, {
      email: 'grant-target@example.com',
      username: 'granttarget',
      displayName: 'Grant Target',
      password: 'grant-target-password-2026',
    })
    const application = (await (
      await postJson(harness, cookie, '/api/applications', {
        name: 'Grant Client',
        slug: 'grant-client',
        clientType: 'machine',
        redirectUris: [],
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    const resource = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'grant-api',
        resourceUrl: 'https://grant.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
        visibility: 'public',
      })
    ).json()) as { id: string }
    await harness.deps.authorization.replaceResourceDiscovery(resource.id, {
      name: 'Grant API',
      description: null,
      scopeRegistry: {
        discovery: {
          sourceUrl: 'https://grant.example.com/openapi.json',
          etag: null,
          documentHash: 'grant-registry',
          syncedAt: new Date().toISOString(),
          lastError: null,
        },
        scopes: [{ value: 'projects:read', description: 'Read projects', grantMode: 'assigned' }],
      },
    })

    const userGrant = (await (
      await postJson(harness, cookie, `/api/users/${targetUserId}/permissions`, {
        resourceServerId: resource.id,
        scope: 'projects:read',
        mode: 'persistent',
      })
    ).json()) as { id: string; userId: string; links: { self: string } }
    expect(userGrant).toMatchObject({ userId: targetUserId })
    expect(userGrant.links.self).toBe(`/api/users/${targetUserId}/permissions/${userGrant.id}`)
    const userGrants = await harness.request(`/api/users/${targetUserId}/permissions`, { headers: { cookie } })
    await expect(userGrants.json()).resolves.toMatchObject({ items: [{ id: userGrant.id }] })
    const userResources = await harness.request(`/api/users/${targetUserId}/authorized-resource-servers?search=grant`, {
      headers: { cookie },
    })
    await expect(userResources.json()).resolves.toMatchObject({
      items: [{ id: resource.id, name: 'Grant API', identifier: 'grant-api', permissionCount: 1 }],
      pagination: { totalItems: 1 },
    })

    const applicationGrant = (await (
      await postJson(harness, cookie, `/api/applications/${application.id}/permissions`, {
        resourceServerId: resource.id,
        scope: 'projects:read',
        mode: 'persistent',
      })
    ).json()) as { id: string; applicationId: string; links: { self: string } }
    expect(applicationGrant).toMatchObject({ applicationId: application.id })
    expect(applicationGrant.links.self).toBe(`/api/applications/${application.id}/permissions/${applicationGrant.id}`)
    const applicationGrants = await harness.request(`/api/applications/${application.id}/permissions`, {
      headers: { cookie },
    })
    await expect(applicationGrants.json()).resolves.toMatchObject({ items: [{ id: applicationGrant.id }] })
    const applicationResources = await harness.request(
      `/api/applications/${application.id}/authorized-resource-servers`,
      { headers: { cookie } },
    )
    await expect(applicationResources.json()).resolves.toMatchObject({
      items: [{ id: resource.id, name: 'Grant API', identifier: 'grant-api', permissionCount: 1 }],
      pagination: { totalItems: 1 },
    })

    expect((await harness.request('/api/users/missing-user/permissions', { headers: { cookie } })).status).toBe(404)
    const userFlowApplication = (await (
      await postJson(harness, cookie, '/api/applications', {
        name: 'User Flow Client',
        slug: 'user-flow-client',
        clientType: 'confidential_web',
        redirectUris: ['http://localhost/user-flow-callback'],
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    expect(
      (
        await postJson(
          harness,
          cookie,
          `/api/applications/${userFlowApplication.id}/permissions`,
          {
            resourceServerId: resource.id,
            scope: 'projects:read',
            mode: 'persistent',
          },
          400,
        )
      ).status,
    ).toBe(400)

    const disabledResource = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ enabled: false }),
    })
    expect(disabledResource.status).toBe(200)
    expect(
      (
        await postJson(
          harness,
          cookie,
          `/api/users/${targetUserId}/permissions`,
          {
            resourceServerId: resource.id,
            scope: 'projects:read',
            mode: 'persistent',
          },
          400,
        )
      ).status,
    ).toBe(400)

    expect(
      (
        await harness.request(userGrant.links.self, {
          method: 'DELETE',
          headers: { cookie },
        })
      ).status,
    ).toBe(204)
    const revokedEntitlement = await harness.request(userGrant.links.self, { headers: { cookie } })
    expect(revokedEntitlement.status).toBe(200)
    await expect(revokedEntitlement.json()).resolves.toMatchObject({ status: 'ended', endReason: 'revoked' })
    const revokedEntitlements = await harness.request(`/api/users/${targetUserId}/permissions?status=inactive`, {
      headers: { cookie },
    })
    await expect(revokedEntitlements.json()).resolves.toMatchObject({ items: [{ id: userGrant.id }] })
    expect(
      (
        await harness.request(`/api/users/${targetUserId}/permissions?status=ended`, {
          headers: { cookie },
        })
      ).status,
    ).toBe(400)
    await expect(
      (
        await harness.request(`/api/users/${targetUserId}/permissions`, {
          headers: { cookie },
        })
      ).json(),
    ).resolves.toMatchObject({ items: [], pagination: { totalItems: 0 } })
    await expect(
      (
        await harness.request(`/api/users/${targetUserId}/authorized-resource-servers`, {
          headers: { cookie },
        })
      ).json(),
    ).resolves.toMatchObject({ items: [], pagination: { totalItems: 0 } })

    await harness.db
      .update(resourceScopeEntitlement)
      .set({ mode: 'until', expiresAt: new Date('2020-01-01T00:00:00.000Z') })
      .where(eq(resourceScopeEntitlement.id, applicationGrant.id))
    await expect(
      (
        await harness.request(`/api/applications/${application.id}/permissions`, {
          headers: { cookie },
        })
      ).json(),
    ).resolves.toMatchObject({ items: [], pagination: { totalItems: 0 } })
    await expect(
      (
        await harness.request(`/api/applications/${application.id}/authorized-resource-servers`, {
          headers: { cookie },
        })
      ).json(),
    ).resolves.toMatchObject({ items: [], pagination: { totalItems: 0 } })
    await expect(
      (
        await harness.request(`/api/applications/${application.id}/permissions?status=inactive`, {
          headers: { cookie },
        })
      ).json(),
    ).resolves.toMatchObject({
      items: [{ id: applicationGrant.id, status: 'ended', endReason: 'expired' }],
      pagination: { totalItems: 1 },
    })
    expect((await harness.request('/api/user-scope-grants', { headers: { cookie } })).status).toBe(404)
    expect((await harness.request('/api/application-scope-grants', { headers: { cookie } })).status).toBe(404)
  })

  it('[spec: agent-identity/external-resource-rich-authorization-connection] persists opaque authorization detail templates through the management API', async () => {
    const cookie = await signInAdmin(harness)
    const now = new Date()
    const connector = await harness.deps.connectors.create({
      id: 'connector-rar-projects',
      slug: 'rar-projects',
      providerType: 'generic_oauth',
      providerId: 'rar-projects',
      displayName: 'RAR Projects',
      enabled: true,
      authenticationEnabled: false,
      clientId: 'rar-projects-client',
      clientSecret: 'rar-projects-secret',
      clientSecretContext: null,
      issuer: 'https://projects.example.com',
      authorizationEndpoint: 'https://projects.example.com/authorize',
      tokenEndpoint: 'https://projects.example.com/token',
      userInfoEndpoint: 'https://projects.example.com/userinfo',
      jwksEndpoint: 'https://projects.example.com/jwks',
      registrationEndpoint: null,
      revocationEndpoint: 'https://projects.example.com/revoke',
      registrationMode: 'manual',
      registrationAccessToken: null,
      registrationAccessTokenContext: null,
      scopes: ['openid', 'offline_access', 'projects:read'],
      attributeMapping: null,
      providerMetadata: {
        grant_types_supported: [
          'authorization_code',
          'refresh_token',
          'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'urn:ietf:params:oauth:grant-type:token-exchange',
        ],
        dpop_signing_alg_values_supported: ['ES256'],
        authorization_details_types_supported: ['project_access'],
        authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
        authorization_details_catalog_scope: 'authorization-details:read',
        authorization_details_catalog_version: 1,
        pushed_authorization_request_endpoint: 'https://projects.example.com/par',
      },
      resourceAuthorizationEnabled: true,
      resourceClientId: 'rar-projects-client',
      resourceClientSecret: 'rar-projects-secret',
      resourceIssuer: 'https://projects.example.com',
      resourceAuthorizationEndpoint: 'https://projects.example.com/authorize',
      resourceTokenEndpoint: 'https://projects.example.com/token',
      resourceUserInfoEndpoint: 'https://projects.example.com/userinfo',
      resourceJwksEndpoint: 'https://projects.example.com/jwks',
      resourceRevocationEndpoint: 'https://projects.example.com/revoke',
      resourceProviderMetadata: {
        grant_types_supported: [
          'authorization_code',
          'refresh_token',
          'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'urn:ietf:params:oauth:grant-type:token-exchange',
        ],
        dpop_signing_alg_values_supported: ['ES256'],
        authorization_details_types_supported: ['project_access'],
        authorization_details_catalog_endpoint: 'https://projects.example.com/authorization-details',
        authorization_details_catalog_scope: 'authorization-details:read',
        authorization_details_catalog_version: 1,
        pushed_authorization_request_endpoint: 'https://projects.example.com/par',
      },
      createdAt: now,
      updatedAt: now,
    })
    harness.deps.externalHttp.fetch = async (request) => {
      if (request.url.endsWith('/.well-known/oauth-protected-resource/api')) {
        return Response.json({
          resource: 'https://projects.example.com/api',
          authorization_servers: [connector.issuer],
          scopes_supported: ['projects:read'],
        })
      }
      return resourceOpenApiFetch(request)
    }
    const authorizationDetails = [
      { type: 'project_access', actions: ['read'], project_id: 'project-1', tenant: { id: 'tenant-1' } },
    ]

    const created = await postJson(harness, cookie, '/api/resource-servers', {
      identifier: 'rar-projects-api',
      resourceUrl: 'https://projects.example.com/api',
      authorizationModel: 'external',
      connectorId: connector.id,
      ownerOrganizationId: platformOrganizationId,
      authorizationDetails,
    })
    const resource = (await created.json()) as { id: string; authorizationDetails: unknown }
    expect(resource.authorizationDetails).toEqual(authorizationDetails)
    await expect(harness.db.select().from(apiResource).where(eq(apiResource.id, resource.id))).resolves.toMatchObject([
      { authorizationDetails },
    ])

    const updatedAuthorizationDetails = [
      { type: 'project_access', actions: ['read', 'comment'], project_id: 'project-1' },
    ]
    const updated = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ authorizationDetails: updatedAuthorizationDetails }),
    })
    expect(updated.status, await updated.clone().text()).toBe(200)
    await expect(updated.json()).resolves.toMatchObject({ authorizationDetails: updatedAuthorizationDetails })

    const unsupported = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ authorizationDetails: [{ type: 'unknown_context' }] }),
    })
    expect(unsupported.status).toBe(400)
  })

  it('rejects an undiscoverable Resource Server even when the requested state is disabled', async () => {
    const cookie = await signInAdmin(harness)
    harness.deps.externalHttp.fetch = async () => new Response('<html></html>')
    const input = {
      identifier: 'projects-api',
      resourceUrl: 'https://projects.example.com/api',
      authorizationModel: 'native' as const,
      ownerOrganizationId: platformOrganizationId,
    }

    const enabled = await harness.request('/api/resource-servers', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify(input),
    })
    expect(enabled.status).toBe(502)

    const disabled = await harness.request('/api/resource-servers', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ ...input, enabled: false }),
    })
    expect(disabled.status).toBe(400)
  })

  it('requires authorization reconfiguration when an external resource URL changes [spec: agent-identity/external-api-resource-reconfiguration]', async () => {
    const cookie = await signInAdmin(harness)
    const now = new Date()
    const connector = await harness.deps.connectors.create({
      id: 'connector-projects',
      slug: 'projects',
      providerType: 'generic_oauth',
      providerId: 'projects',
      displayName: 'Projects OIDC',
      enabled: true,
      authenticationEnabled: false,
      clientId: 'projects-client',
      clientSecret: 'projects-secret',
      clientSecretContext: null,
      issuer: 'https://projects.example.com',
      authorizationEndpoint: 'https://projects.example.com/authorize',
      tokenEndpoint: 'https://projects.example.com/token',
      userInfoEndpoint: 'https://projects.example.com/userinfo',
      jwksEndpoint: 'https://projects.example.com/jwks',
      registrationEndpoint: null,
      revocationEndpoint: 'https://projects.example.com/revoke',
      registrationMode: 'manual',
      registrationAccessToken: null,
      registrationAccessTokenContext: null,
      scopes: ['openid', 'offline_access'],
      attributeMapping: null,
      providerMetadata: {
        grant_types_supported: [
          'authorization_code',
          'refresh_token',
          'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'urn:ietf:params:oauth:grant-type:token-exchange',
        ],
        dpop_signing_alg_values_supported: ['ES256'],
      },
      resourceAuthorizationEnabled: true,
      resourceClientId: 'projects-client',
      resourceClientSecret: 'projects-secret',
      resourceIssuer: 'https://projects.example.com',
      resourceAuthorizationEndpoint: 'https://projects.example.com/authorize',
      resourceTokenEndpoint: 'https://projects.example.com/token',
      resourceUserInfoEndpoint: 'https://projects.example.com/userinfo',
      resourceJwksEndpoint: 'https://projects.example.com/jwks',
      resourceRevocationEndpoint: 'https://projects.example.com/revoke',
      resourceProviderMetadata: {
        grant_types_supported: [
          'authorization_code',
          'refresh_token',
          'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'urn:ietf:params:oauth:grant-type:token-exchange',
        ],
        dpop_signing_alg_values_supported: ['ES256'],
      },
      createdAt: now,
      updatedAt: now,
    })
    harness.deps.externalHttp.fetch = async (request) => {
      if (request.url.endsWith('/.well-known/oauth-protected-resource/api')) {
        return Response.json({
          resource: request.url.includes('new-projects')
            ? 'https://new-projects.example.com/api'
            : 'https://projects.example.com/api',
          authorization_servers: [
            request.url.includes('new-projects') ? 'https://different.example.com' : connector.issuer,
          ],
          scopes_supported: ['projects:read'],
        })
      }
      return resourceOpenApiFetch(request)
    }
    const resource = await createResource(harness.deps, {
      identifier: 'projects-api',
      resourceUrl: 'https://projects.example.com/api',
      authorizationModel: 'external',
      connectorId: connector.id,
      ownerOrganizationId: platformOrganizationId,
    })

    const response = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ resourceUrl: 'https://new-projects.example.com/api' }),
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({
      error: { message: 'External API resource authorization server does not match the selected Provider Connector.' },
    })
  })

  it('runs the API resource lifecycle through real SQL [spec: management-api/management-restish-api-resource-crud]', async () => {
    const cookie = await signInAdmin(harness)

    const resource = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'https://api.example.com',
        resourceUrl: 'https://api.example.com',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }

    const list = await harness.request('/api/resource-servers', { headers: { cookie } })
    expect(((await list.json()) as { items: unknown[] }).items.length).toBe(2)

    const fetched = await harness.request(`/api/resource-servers/${resource.id}`, { headers: { cookie } })
    expect(fetched.status).toBe(200)
    await expect(fetched.json()).resolves.toMatchObject({
      name: 'Test Resource API',
      description: 'Integration test resource',
    })

    harness.deps.externalHttp.fetch = async (request) => {
      if (new URL(request.url).pathname.endsWith('/openapi.json')) {
        return Response.json({
          openapi: '3.1.0',
          info: { title: 'Updated Example API', description: 'Updated by OpenAPI', version: '2.0.0' },
          paths: {},
        })
      }
      return resourceOpenApiFetch(request)
    }
    const synchronized = await harness.request(`/api/resource-servers/${resource.id}/scope-registry`, {
      method: 'PUT',
      headers: { cookie },
    })
    expect(synchronized.status).toBe(200)
    await expect(synchronized.json()).resolves.toMatchObject({
      name: 'Updated Example API',
      description: 'Updated by OpenAPI',
    })

    const rejectedManualName = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Renamed API' }),
    })
    expect(rejectedManualName.status).toBe(400)

    const patched = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ identifier: 'example-api' }),
    })
    expect(((await patched.json()) as { identifier: string }).identifier).toBe('example-api')

    expect(
      (
        await harness.request(`/api/resource-servers/${resource.id}`, {
          method: 'DELETE',
          headers: { cookie },
        })
      ).status,
    ).toBe(204)
  })

  it('[spec: management-api/management-api-resource-soft-delete] soft-deletes resources while preserving history', async () => {
    const cookie = await signInAdmin(harness)
    const resource = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'history-api',
        resourceUrl: 'https://history.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    const retainedResource = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'retained-history-api',
        resourceUrl: 'https://retained-history.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    const configuredApplication = (await (
      await postJson(harness, cookie, '/api/applications', {
        name: 'Deleted Resource Client',
        slug: 'deleted-resource-client',
        clientType: 'confidential_web',
        redirectUris: ['http://localhost/deleted-resource-callback'],
        ownerOrganizationId: platformOrganizationId,
        resourceScopes: [
          { resourceServerId: resource.id, scopes: ['resource:read'] },
          { resourceServerId: retainedResource.id, scopes: ['resource:read'] },
        ],
      })
    ).json()) as { id: string }
    const [admin] = await harness.db.select({ id: user.id }).from(user).where(eq(user.email, 'admin@example.com'))
    const now = new Date()
    await harness.db.insert(organizationRole).values({
      id: 'role-resource-history',
      organizationId: platformOrganizationId,
      role: 'resource-history',
      displayName: 'Resource history',
      permission: {
        scope: [encodeRoleScope(resource.id, 'resource:read'), encodeRoleScope(retainedResource.id, 'resource:read')],
        user: ['read'],
      },
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(identityProviderConnector).values({
      id: 'connector-resource-history',
      slug: 'resource-history',
      providerType: 'generic_oauth',
      providerId: 'resource-history',
      displayName: 'Resource history',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(providerConnection).values({
      id: 'provider-connection-history',
      connectorId: 'connector-resource-history',
      ownerUserId: admin.id,
      externalSubject: 'admin@example.com',
      displayName: 'Admin connection',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(providerResourceAuthorization).values({
      id: 'connection-history',
      providerConnectionId: 'provider-connection-history',
      resourceId: resource.id,
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(providerCredential).values({
      id: 'credential-history',
      providerResourceAuthorizationId: 'connection-history',
      encryptedTokens: 'encrypted-tokens',
      grantedScopes: ['files:read'],
      createdAt: now,
      updatedAt: now,
    })

    const response = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'DELETE',
      headers: { cookie },
    })

    expect(response.status).toBe(204)
    await expect(
      harness.db
        .select({ id: apiResource.id, deletedAt: apiResource.deletedAt })
        .from(apiResource)
        .where(eq(apiResource.id, resource.id)),
    ).resolves.toEqual([{ id: resource.id, deletedAt: expect.any(Date) }])
    await expect(
      harness.db
        .select({ id: providerResourceAuthorization.id, status: providerResourceAuthorization.status })
        .from(providerResourceAuthorization)
        .where(eq(providerResourceAuthorization.id, 'connection-history')),
    ).resolves.toEqual([{ id: 'connection-history', status: 'revoked' }])
    await expect(
      harness.db
        .select({ resourceScopes: application.resourceScopes })
        .from(application)
        .where(eq(application.id, configuredApplication.id)),
    ).resolves.toEqual([{ resourceScopes: [{ resourceServerId: retainedResource.id, scopes: ['resource:read'] }] }])
    await expect(
      harness.db
        .select({ permission: organizationRole.permission })
        .from(organizationRole)
        .where(eq(organizationRole.id, 'role-resource-history')),
    ).resolves.toEqual([
      {
        permission: {
          scope: [encodeRoleScope(retainedResource.id, 'resource:read')],
          user: ['read'],
        },
      },
    ])
    expect((await harness.request(`/api/resource-servers/${resource.id}`, { headers: { cookie } })).status).toBe(404)

    await harness.db
      .update(application)
      .set({ resourceScopes: [{ resourceServerId: resource.id, scopes: ['resource:read'] }] })
      .where(eq(application.id, configuredApplication.id))
    await expect(
      harness.deps.applications.update(configuredApplication.id, {
        resourceScopes: [{ resourceServerId: resource.id, scopes: ['resource:read'] }],
      }),
    ).resolves.toBe('resource_inactive')
    await expect(harness.deps.applications.update('missing-application', {})).resolves.toBe('application_not_found')
    const saved = await harness.request(`/api/applications/${configuredApplication.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ resourceScopes: [{ resourceServerId: resource.id, scopes: ['resource:read'] }] }),
    })
    expect(saved.status).toBe(200)
    await expect(saved.json()).resolves.toMatchObject({ resourceScopes: [] })
    await expect(
      harness.db
        .select({ resourceScopes: application.resourceScopes })
        .from(application)
        .where(eq(application.id, configuredApplication.id)),
    ).resolves.toEqual([{ resourceScopes: [] }])

    const boundedResourceIds = [realmrootResourceServerId]
    for (let index = 0; index < 99; index += 1) {
      const id = `bounded-resource-${index}`
      boundedResourceIds.push(id)
      await harness.db.insert(apiResource).values({
        id,
        identifier: id,
        name: `Bounded resource ${index}`,
        resourceUrl: `https://bounded-${index}.example.com/api`,
        ownerOrganizationId: platformOrganizationId,
        scopeRegistry: null,
        createdAt: now,
        updatedAt: now,
      })
    }
    const boundedSave = await harness.request(`/api/applications/${configuredApplication.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({
        resourceScopes: boundedResourceIds.map((resourceServerId) => ({ resourceServerId, scopes: [] })),
      }),
    })
    expect(boundedSave.status).toBe(200)
    const boundedApplication = (await boundedSave.json()) as { resourceScopes: Array<{ resourceServerId: string }> }
    expect(boundedApplication.resourceScopes).toHaveLength(100)
    await expect(
      harness.db
        .select({ resourceScopes: application.resourceScopes })
        .from(application)
        .where(eq(application.id, configuredApplication.id)),
    ).resolves.toEqual([
      {
        resourceScopes: boundedResourceIds.map((resourceServerId) => ({ resourceServerId, scopes: [] })),
      },
    ])
  })

  it('does not expose a deleted Resource Server for updates [spec: management-api/management-api-resource-soft-delete]', async () => {
    const cookie = await signInAdmin(harness)
    const now = new Date()
    const connector = await harness.deps.connectors.create({
      id: 'connector-conditional',
      slug: 'conditional',
      providerType: 'generic_oauth',
      providerId: 'conditional',
      displayName: 'Conditional OIDC',
      enabled: true,
      authenticationEnabled: false,
      clientId: 'conditional-client',
      clientSecret: 'conditional-secret',
      clientSecretContext: null,
      issuer: 'https://conditional.example.com',
      authorizationEndpoint: 'https://conditional.example.com/authorize',
      tokenEndpoint: 'https://conditional.example.com/token',
      userInfoEndpoint: 'https://conditional.example.com/userinfo',
      jwksEndpoint: 'https://conditional.example.com/jwks',
      registrationEndpoint: null,
      revocationEndpoint: 'https://conditional.example.com/revoke',
      registrationMode: 'manual',
      registrationAccessToken: null,
      registrationAccessTokenContext: null,
      scopes: ['openid', 'offline_access'],
      attributeMapping: null,
      providerMetadata: {
        grant_types_supported: [
          'authorization_code',
          'refresh_token',
          'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'urn:ietf:params:oauth:grant-type:token-exchange',
        ],
        dpop_signing_alg_values_supported: ['ES256'],
      },
      resourceAuthorizationEnabled: true,
      resourceClientId: 'conditional-client',
      resourceClientSecret: 'conditional-secret',
      resourceIssuer: 'https://conditional.example.com',
      resourceAuthorizationEndpoint: 'https://conditional.example.com/authorize',
      resourceTokenEndpoint: 'https://conditional.example.com/token',
      resourceUserInfoEndpoint: 'https://conditional.example.com/userinfo',
      resourceJwksEndpoint: 'https://conditional.example.com/jwks',
      resourceRevocationEndpoint: 'https://conditional.example.com/revoke',
      resourceProviderMetadata: {
        grant_types_supported: [
          'authorization_code',
          'refresh_token',
          'urn:ietf:params:oauth:grant-type:jwt-bearer',
          'urn:ietf:params:oauth:grant-type:token-exchange',
        ],
        dpop_signing_alg_values_supported: ['ES256'],
      },
      createdAt: now,
      updatedAt: now,
    })
    harness.deps.externalHttp.fetch = async (request) => {
      if (request.url.endsWith('/.well-known/oauth-protected-resource/api')) {
        return Response.json({
          resource: 'https://conditional.example.com/api',
          authorization_servers: [connector.issuer],
          scopes_supported: ['projects:read'],
        })
      }
      return resourceOpenApiFetch(request)
    }
    const resource = await createResource(harness.deps, {
      identifier: 'conditional-external',
      resourceUrl: 'https://conditional.example.com/api',
      authorizationModel: 'external',
      connectorId: connector.id,
      ownerOrganizationId: platformOrganizationId,
    })

    const deleted = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'DELETE',
      headers: { cookie },
    })
    expect(deleted.status).toBe(204)
    const lateAssociation = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ connectorId: connector.id }),
    })
    expect(lateAssociation.status).toBe(404)
    await expect(harness.deps.authorization.findResource(resource.id)).resolves.toBeNull()
  })

  it('[spec: management-api/management-api-resource-soft-delete] deletes without losing authorization history', async () => {
    const cookie = await signInAdmin(harness)
    const resource = (await (
      await postJson(harness, cookie, '/api/resource-servers', {
        identifier: 'deleted-api',
        resourceUrl: 'https://deleted.example.com/api',
        authorizationModel: 'native',
        ownerOrganizationId: platformOrganizationId,
      })
    ).json()) as { id: string }
    const [admin] = await harness.db.select({ id: user.id }).from(user).where(eq(user.email, 'admin@example.com'))
    const now = new Date()
    const expiresAt = new Date(now.getTime() + 60_000)
    await harness.db.insert(agentHost).values({
      id: 'deleted-host',
      name: 'Deleted host',
      userId: admin.id,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(agent).values({
      id: 'deleted-agent',
      name: 'Deleted Agent',
      userId: admin.id,
      hostId: 'deleted-host',
      status: 'active',
      publicKey: '{}',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(agentIdentity).values({
      id: 'deleted-identity',
      issuer: 'http://localhost/api/auth',
      subject: 'deleted-subject',
      username: 'deleted-identity.0000000000000000000000000000000a',
      name: 'Deleted identity',
      ownerUserId: admin.id,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(agentIdentityBinding).values({
      id: 'deleted-binding',
      agentIdentityId: 'deleted-identity',
      protocolAgentId: 'deleted-agent',
      status: 'active',
      boundAt: now,
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(identityProviderConnector).values({
      id: 'connector-deleted-history',
      slug: 'deleted-history',
      providerType: 'generic_oauth',
      providerId: 'deleted-history',
      displayName: 'Deleted history',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(providerConnection).values({
      id: 'provider-connection-deleted',
      connectorId: 'connector-deleted-history',
      ownerUserId: admin.id,
      externalSubject: 'admin@example.com',
      displayName: 'Deleted connection',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(providerResourceAuthorization).values({
      id: 'deleted-connection',
      providerConnectionId: 'provider-connection-deleted',
      resourceId: resource.id,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(providerCredential).values({
      id: 'deleted-credential',
      providerResourceAuthorizationId: 'deleted-connection',
      encryptedTokens: 'encrypted-tokens',
      grantedScopes: ['files:read'],
      status: 'active',
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(resourceConnectionIntent).values({
      id: 'deleted-intent',
      stateHash: 'deleted-state',
      resourceId: resource.id,
      ownerUserId: admin.id,
      initiatedByUserId: admin.id,
      scopes: ['files:read'],
      encryptedPkceVerifier: 'encrypted-verifier',
      status: 'pending',
      expiresAt,
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(agentAccessRequest).values({
      id: 'deleted-request',
      resourceId: resource.id,
      connectionId: 'deleted-connection',
      agentIdentityId: 'deleted-identity',
      bindingId: 'deleted-binding',
      scopes: ['files:read'],
      status: 'pending',
      approvalTokenHash: 'deleted-approval-hash',
      encryptedApprovalToken: 'encrypted-approval',
      expiresAt,
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(resourceScopeEntitlement).values({
      id: 'deleted-grant',
      resourceServerId: resource.id,
      connectionId: 'deleted-connection',
      agentIdentityId: 'deleted-identity',
      authorizationContextHash: 'ctx-empty',
      scope: 'files:read',
      authorizationDetails: [],
      mode: 'persistent',
      grantedByUserId: admin.id,
      createdAt: now,
      updatedAt: now,
    })
    await harness.db.insert(externalTokenLease).values({
      id: 'deleted-lease',
      entitlementIds: ['deleted-grant'],
      requestId: 'deleted-request',
      bindingId: 'deleted-binding',
      encryptedAccessToken: 'encrypted-access-token',
      tokenHash: 'deleted-token-hash',
      confirmationJkt: 'deleted-jkt',
      scopes: ['files:read'],
      expiresAt,
      createdAt: now,
    })

    const deleted = await harness.request(`/api/resource-servers/${resource.id}`, {
      method: 'DELETE',
      headers: { cookie },
    })

    expect(deleted.status).toBe(204)
    await Promise.all([
      harness.db
        .update(agentAccessRequest)
        .set({ status: 'pending', decidedAt: null })
        .where(eq(agentAccessRequest.id, 'deleted-request')),
      harness.db
        .update(resourceScopeEntitlement)
        .set({ endedAt: null, endReason: null })
        .where(eq(resourceScopeEntitlement.id, 'deleted-grant')),
    ])
    const agentDetail = await harness.request('/api/agents/deleted-identity', { headers: { cookie } })
    expect(agentDetail.status).toBe(200)
    await expect(agentDetail.json()).resolves.toMatchObject({
      agent: { pendingRequestCount: 0, activeScopeCount: 0 },
    })
    expect(
      (await harness.request('/api/access/requests?agentId=deleted-identity', { headers: { cookie } })).status,
    ).toBe(404)
    expect((await harness.request('/api/access/requests/deleted-request', { headers: { cookie } })).status).toBe(404)
    const grants = await harness.request('/api/agents/deleted-identity/permissions', {
      headers: { cookie },
    })
    expect(grants.status).toBe(200)
    await expect(grants.json()).resolves.toMatchObject({
      items: [],
      pagination: { totalItems: 0 },
    })
    await Promise.all([
      harness.db
        .update(agentAccessRequest)
        .set({ status: 'denied', decidedAt: now })
        .where(eq(agentAccessRequest.id, 'deleted-request')),
      harness.db
        .update(resourceScopeEntitlement)
        .set({ endedAt: now, endReason: 'revoked' })
        .where(eq(resourceScopeEntitlement.id, 'deleted-grant')),
    ])
    await expect(
      discoverAgentResources(harness.deps, {
        issuer: 'http://localhost/api/auth',
        subject: 'deleted-subject',
        identityId: 'deleted-identity',
        protocolAgentId: 'deleted-agent',
        hostId: 'deleted-host',
        identity: {
          id: 'deleted-identity',
          issuer: 'http://localhost/api/auth',
          subject: 'deleted-subject',
          username: 'deleted-identity.0000000000000000000000000000000a',
          name: 'Deleted identity',
          ownerUserId: admin.id,
          status: 'active',
          deletedAt: null,
          createdAt: now,
          updatedAt: now,
        },
        binding: {
          id: 'deleted-binding',
          agentIdentityId: 'deleted-identity',
          protocolAgentId: 'deleted-agent',
          hostId: 'deleted-host',
          status: 'active',
          boundAt: now,
          revokedAt: null,
          createdAt: now,
          updatedAt: now,
        },
      }),
    ).resolves.toMatchObject({
      items: [expect.objectContaining({ id: realmrootResourceServerId, identifier: 'realmroot' })],
    })

    const [[resourceRow], [connection], [intent], [request], [grant], [lease]] = await Promise.all([
      harness.db.select().from(apiResource).where(eq(apiResource.id, resource.id)),
      harness.db
        .select()
        .from(providerResourceAuthorization)
        .where(eq(providerResourceAuthorization.id, 'deleted-connection')),
      harness.db.select().from(resourceConnectionIntent).where(eq(resourceConnectionIntent.id, 'deleted-intent')),
      harness.db.select().from(agentAccessRequest).where(eq(agentAccessRequest.id, 'deleted-request')),
      harness.db.select().from(resourceScopeEntitlement).where(eq(resourceScopeEntitlement.id, 'deleted-grant')),
      harness.db.select().from(externalTokenLease).where(eq(externalTokenLease.id, 'deleted-lease')),
    ])
    expect(resourceRow).toMatchObject({ id: resource.id, enabled: false, deletedAt: expect.any(Date) })
    expect(connection).toMatchObject({ status: 'revoked', revokedAt: expect.any(Date) })
    expect(intent).toMatchObject({ status: 'cancelled', completedAt: expect.any(Date) })
    expect(request).toMatchObject({ status: 'denied', decidedAt: expect.any(Date) })
    expect(grant).toMatchObject({ endReason: 'revoked', endedAt: expect.any(Date) })
    expect(lease).toMatchObject({ revokedAt: expect.any(Date) })
    await Promise.all([
      harness.db
        .update(agentAccessRequest)
        .set({ resourceId: realmrootResourceServerId })
        .where(eq(agentAccessRequest.id, 'deleted-request')),
      harness.db
        .update(agentIdentity)
        .set({ status: 'inactive', deletedAt: now })
        .where(eq(agentIdentity.id, 'deleted-identity')),
    ])
    expect(
      (await harness.request('/api/access/requests?agentId=deleted-identity', { headers: { cookie } })).status,
    ).toBe(404)
    await harness.db
      .update(agentAccessRequest)
      .set({ resourceId: resource.id })
      .where(eq(agentAccessRequest.id, 'deleted-request'))
    await expect(
      harness.db
        .select({ resourceId: agentAccessRequest.resourceId })
        .from(agentAccessRequest)
        .where(eq(agentAccessRequest.id, 'deleted-request')),
    ).resolves.toEqual([{ resourceId: resource.id }])
    const [deletionAudit] = await harness.db
      .select()
      .from(agentAuditEvent)
      .where(eq(agentAuditEvent.resourceId, resource.id))
    expect(deletionAudit).toMatchObject({
      action: 'api_resource.deleted',
      controllerUserId: admin.id,
      metadata: { authorizationRecordsRevoked: true },
    })
    await expect(harness.deps.authorization.updateResource(resource.id, { enabled: true })).resolves.toBe(false)
    await expect(
      harness.deps.externalResources.createConnectionIntent({
        id: 'late-intent',
        stateHash: 'late-state',
        resourceId: resource.id,
        ownerUserId: admin.id,
        ownerOrganizationId: null,
        initiatedByUserId: admin.id,
        scopes: ['files:read'],
        authorizationDetails: [],
        encryptedPkceVerifier: 'late-verifier',
        returnTo: 'account-center',
        status: 'pending',
        expiresAt,
        completedAt: null,
        createdAt: now,
        updatedAt: now,
      }),
    ).resolves.toBeNull()
    await expect(
      harness.deps.externalResources.createAccessRequest({
        id: 'late-request',
        resourceId: resource.id,
        connectionId: null,
        agentIdentityId: 'deleted-identity',
        bindingId: 'deleted-binding',
        scopes: ['files:read'],
        authorizationDetails: [],
        reason: null,
        status: 'pending',
        approvalTokenHash: 'late-approval-hash',
        encryptedApprovalToken: 'late-approval',
        approvedEntitlements: [],
        expiresAt,
        decidedAt: null,
        createdAt: now,
        updatedAt: now,
      }),
    ).resolves.toBeNull()
    await expect(
      harness.deps.externalResources.createTokenLease({
        id: 'late-lease',
        entitlementIds: ['deleted-grant'],
        requestId: 'deleted-request',
        bindingId: 'deleted-binding',
        encryptedAccessToken: 'late-access-token',
        tokenHash: 'late-token-hash',
        confirmationJkt: 'late-jkt',
        scopes: ['files:read'],
        authorizationDetails: [],
        expiresAt,
        revokedAt: null,
        createdAt: now,
      }),
    ).resolves.toBeNull()

    const [preservedConnection] = await harness.db
      .select()
      .from(providerResourceAuthorization)
      .where(eq(providerResourceAuthorization.id, 'deleted-connection'))
    const [preservedGrant] = await harness.db
      .select()
      .from(resourceScopeEntitlement)
      .where(eq(resourceScopeEntitlement.id, 'deleted-grant'))
    expect(preservedConnection.status).toBe('revoked')
    expect(preservedGrant.endReason).toBe('revoked')
    const audits = await harness.db.select().from(agentAuditEvent).where(eq(agentAuditEvent.resourceId, resource.id))
    expect(audits.map((event) => event.action)).toEqual(['api_resource.deleted'])
  })

  it('runs the organization / member / invitation lifecycle through real SQL [spec: management-api/management-restish-organization-crud]', async () => {
    const cookie = await signInAdmin(harness)
    const memberUserId = await createUser(harness, cookie, {
      email: 'org-member@example.com',
      username: 'orgmember',
      displayName: 'Org Member',
      password: 'org-member-password-2026',
    })

    const organization = (await (
      await postJson(harness, cookie, '/api/organizations', { slug: 'acme', name: 'Acme' })
    ).json()) as { id: string }

    const list = await harness.request('/api/organizations', { headers: { cookie } })
    expect(((await list.json()) as { items: Array<{ id: string }> }).items).toContainEqual(
      expect.objectContaining({ id: organization.id }),
    )

    expect((await harness.request(`/api/organizations/${organization.id}`, { headers: { cookie } })).status).toBe(200)

    const patched = await harness.request(`/api/organizations/${organization.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Acme Inc' }),
    })
    expect(((await patched.json()) as { name: string }).name).toBe('Acme Inc')

    const member = (await (
      await postJson(harness, cookie, `/api/organizations/${organization.id}/members`, {
        userId: memberUserId,
        roles: ['member'],
      })
    ).json()) as { id: string }
    const members = await harness.request(`/api/organizations/${organization.id}/members`, {
      headers: { cookie },
    })
    expect(((await members.json()) as { items: unknown[] }).items.length).toBe(2)

    const role = await postJson(harness, cookie, `/api/organizations/${organization.id}/roles`, {
      key: 'org-lead',
      displayName: 'Org Lead',
      description: null,
      scopes: [],
    })
    expect(role.status).toBe(201)

    const patchedMember = await harness.request(`/api/organizations/${organization.id}/members/${member.id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ roles: ['member', 'org-lead'] }),
    })
    expect(((await patchedMember.json()) as { roles: string[] }).roles).toEqual(['member', 'org-lead'])

    const invitation = (await (
      await postJson(harness, cookie, `/api/organizations/${organization.id}/invitations`, {
        email: 'invitee@example.com',
        roles: ['member'],
      })
    ).json()) as { id: string }
    const invitations = await harness.request(`/api/organizations/${organization.id}/invitations`, {
      headers: { cookie },
    })
    expect(((await invitations.json()) as { items: unknown[] }).items.length).toBe(1)

    expect(
      (
        await harness.request(`/api/organizations/${organization.id}/invitations/${invitation.id}`, {
          method: 'DELETE',
          headers: { cookie },
        })
      ).status,
    ).toBe(204)
    expect(
      (
        await harness.request(`/api/organizations/${organization.id}/members/${member.id}`, {
          method: 'DELETE',
          headers: { cookie },
        })
      ).status,
    ).toBe(204)
    expect(
      (
        await harness.request(`/api/organizations/${organization.id}`, {
          method: 'DELETE',
          headers: { cookie },
        })
      ).status,
    ).toBe(204)
  })
})
