import { badRequest, forbidden } from '@server/domain/errors'
import {
  createAgentWithInstallation,
  emergencyActivateAgentIdentity,
  emergencyDeactivateAgentIdentity,
  emergencyDeleteAgentIdentity,
  getAgent,
  getManagementAgent,
  getManagementAgentPermission,
  listAllAgents,
  listManagementAgentAuthorizedResourceServers,
  listManagementAgentInstallations,
  listManagementAgentPermissions,
} from '@server/usecases/agent-identities'
import {
  createAgentPermission,
  getAgentPermission,
  listAgentPermissions,
  revokeAgentPermission,
} from '@server/usecases/external-resources'
import {
  agentAuthorizedResourceServersResponseSchema,
  agentPermissionSchema,
  agentPermissionsResponseSchema,
  agentSchema,
  createAgentPermissionSchema,
  createAgentSchema,
  createdAgentPermissionsResponseSchema,
  listAgentAuditEventsQuerySchema,
  listAgentAuthorizedResourceServersQuerySchema,
  listAgentPermissionsQuerySchema,
  listAgentsQuerySchema,
  managementAgentAuditEventSchema,
  managementAgentInstallationsResponseSchema,
  managementAgentResponseSchema,
  managementAgentsResponseSchema,
} from '@shared/api/agent-api'
import { idempotencyKeySchema } from '@shared/api/idempotency'
import { paginationInput, paginationMetadata, paginationQuerySchema } from '@shared/api/pagination'
import { Hono } from 'hono'
import { getActorUserId, getPrincipal } from '../../middleware/authn'
import { authorizedTenantInventory, authorizeUser, requireAgentScope } from '../../middleware/authz'
import { getDeps } from '../../middleware/deps'
import { readJson, readQuery } from '../validation'

export const managementAgentsRoute = new Hono()

declare module 'hono' {
  interface ContextVariableMap {
    realmrootCanonicalOrigin?: string
  }
}

managementAgentsRoute.post('/agents', async (c) => {
  const principal = getPrincipal(c)
  const application = principal.application
  if (!application) throw forbidden('An OAuth-authenticated Application is required to create an Agent.')
  const actorUserId = getActorUserId(c)
  if (!actorUserId) throw forbidden('The Application must act on behalf of a User to create an Agent.')
  if (!application.scopes.includes('agents:write')) throw forbidden('OAuth scope "agents:write" is required.')
  await authorizeUser(c, actorUserId, 'agents:write')
  const input = await readJson(c, createAgentSchema)
  const parsedKey = idempotencyKeySchema.safeParse(c.req.header('Idempotency-Key'))
  if (!parsedKey.success) throw badRequest('Idempotency-Key header is required and must contain 1 to 200 characters.')
  const result = await createAgentWithInstallation(getDeps(c), input, {
    applicationId: application.id,
    actorUserId,
    issuer: new URL('/api/auth', c.get('realmrootCanonicalOrigin') ?? c.req.url).toString(),
    idempotencyKey: parsedKey.data,
  })
  c.header('Location', `/api/agents/${encodeURIComponent(result.agent.id)}`)
  if (result.replayed) c.header('Idempotency-Replayed', 'true')
  return c.json(agentSchema.parse(result.agent), 201)
})

managementAgentsRoute.get('/agents', async (c) => {
  const query = readQuery(c, listAgentsQuerySchema)
  return c.json(
    managementAgentsResponseSchema.parse(
      await listAllAgents(getDeps(c), paginationInput(query), await agentInventoryScope(c)),
    ),
  )
})

managementAgentsRoute.get('/agents/:agentId', async (c) => {
  const result = await getManagementAgent(getDeps(c), c.req.param('agentId'))
  await requireAgentAccess(c, result.agent)
  return c.json(managementAgentResponseSchema.parse(result))
})

managementAgentsRoute.get('/agents/:agentId/installations', async (c) => {
  await requireAgentByIdConsoleAccess(c, c.req.param('agentId'))
  return c.json(
    managementAgentInstallationsResponseSchema.parse(
      await listManagementAgentInstallations(
        getDeps(c),
        c.req.param('agentId'),
        paginationInput(readQuery(c, paginationQuerySchema)),
      ),
    ),
  )
})

managementAgentsRoute.get('/agents/:agentId/authorized-resource-servers', async (c) => {
  const agentId = c.req.param('agentId')
  const principal = getPrincipal(c).agent
  if (principal) {
    if (principal.identityId !== agentId) return c.notFound()
    requireAgentScope(c, 'permissions:read')
  } else {
    await requireAgentByIdPermissionAccess(c, agentId)
  }
  return c.json(
    agentAuthorizedResourceServersResponseSchema.parse(
      await listManagementAgentAuthorizedResourceServers(
        getDeps(c),
        agentId,
        readQuery(c, listAgentAuthorizedResourceServersQuerySchema),
      ),
    ),
  )
})

managementAgentsRoute.post('/agents/:agentId/permissions', async (c) => {
  const actorUserId = getActorUserId(c)
  if (!actorUserId || getPrincipal(c).agent) throw forbidden('A User controller is required.')
  await requireAgentAccess(c, await getAgent(getDeps(c), c.req.param('agentId')), true)
  const permissions = await createAgentPermission(
    getDeps(c),
    c.req.param('agentId'),
    await readJson(c, createAgentPermissionSchema),
    actorUserId,
    getPrincipal(c).application?.delegatedOrganizationId ??
      getPrincipal(c).session?.session.activeOrganizationId ??
      null,
  )
  return c.json(createdAgentPermissionsResponseSchema.parse({ items: permissions }), 201)
})

managementAgentsRoute.get('/agents/:agentId/permissions', async (c) => {
  const principal = getPrincipal(c).agent
  if (principal) {
    if (principal.identityId !== c.req.param('agentId')) return c.notFound()
    requireAgentScope(c, 'permissions:read')
    return c.json(
      agentPermissionsResponseSchema.parse(
        await listAgentPermissions(getDeps(c), principal, readQuery(c, listAgentPermissionsQuerySchema)),
      ),
    )
  }
  await requireAgentByIdPermissionAccess(c, c.req.param('agentId'))
  const query = readQuery(c, listAgentPermissionsQuerySchema)
  return c.json(
    agentPermissionsResponseSchema.parse(
      await listManagementAgentPermissions(
        getDeps(c),
        { ...query, agentId: c.req.param('agentId') },
        await authorityInventoryScope(c),
      ),
    ),
  )
})

managementAgentsRoute.get('/agents/:agentId/permissions/:permissionId', async (c) => {
  const principal = getPrincipal(c).agent
  if (principal) {
    if (principal.identityId !== c.req.param('agentId')) return c.notFound()
    requireAgentScope(c, 'permissions:read')
    return c.json(
      agentPermissionSchema.parse(await getAgentPermission(getDeps(c), c.req.param('permissionId'), principal)),
    )
  }
  const grant = await getManagementAgentPermission(getDeps(c), c.req.param('permissionId'))
  if (grant.agentId !== c.req.param('agentId')) return c.notFound()
  await requireAgentByIdPermissionAccess(c, grant.agentId)
  return c.json(agentPermissionSchema.parse(grant))
})

managementAgentsRoute.delete('/agents/:agentId/permissions/:permissionId', async (c) => {
  const actorUserId = getActorUserId(c)
  if (!actorUserId) return c.notFound()
  const grant = await getManagementAgentPermission(getDeps(c), c.req.param('permissionId'))
  if (grant.agentId !== c.req.param('agentId')) return c.notFound()
  await requireAgentByIdPermissionAccess(c, grant.agentId, true)
  await revokeAgentPermission(getDeps(c), grant.id, actorUserId)
  return c.body(null, 204)
})

managementAgentsRoute.get('/agents/:agentId/activation', async (c) => {
  const result = await getManagementAgent(getDeps(c), c.req.param('agentId'))
  await requireAgentAccess(c, result.agent)
  return c.json({ agentId: result.agent.id, active: result.agent.status === 'active' })
})

managementAgentsRoute.put('/agents/:agentId/activation', async (c) => {
  const agent = await getAgent(getDeps(c), c.req.param('agentId'))
  await requireAgentAccess(c, agent, true)
  await emergencyActivateAgentIdentity(getDeps(c), c.req.param('agentId'), getActorUserId(c))
  return c.body(null, 204)
})

managementAgentsRoute.delete('/agents/:agentId/activation', async (c) => {
  const agent = await getAgent(getDeps(c), c.req.param('agentId'))
  await requireAgentAccess(c, agent, true)
  await emergencyDeactivateAgentIdentity(getDeps(c), c.req.param('agentId'), getActorUserId(c))
  return c.body(null, 204)
})

managementAgentsRoute.delete('/agents/:agentId', async (c) => {
  const agent = await getAgent(getDeps(c), c.req.param('agentId'))
  await requireAgentAccess(c, agent, true)
  await emergencyDeleteAgentIdentity(getDeps(c), c.req.param('agentId'), getActorUserId(c))
  return c.body(null, 204)
})

managementAgentsRoute.get('/realm/audit-events', async (c) => {
  const query = readQuery(c, listAgentAuditEventsQuerySchema)
  const tenants = await authorizedTenantInventory(c, 'audit-events:read')
  const organizationIds = tenants
    ? tenants.filter((tenant) => tenant.type === 'organization').map((tenant) => tenant.id)
    : query.organizationId
      ? [query.organizationId]
      : undefined
  const selectedOrganizationIds = query.organizationId
    ? organizationIds?.includes(query.organizationId)
      ? [query.organizationId]
      : []
    : organizationIds
  if (query.agentId) {
    const agent = await getAgent(getDeps(c), query.agentId)
    await authorizeUser(c, agent.homeSpace.userId, 'audit-events:read')
  }
  const page = paginationInput(query)
  const result = await getDeps(c).agentAudit.list(page, {
    agentIdentityId: query.agentId,
    action: query.action,
    result: query.result,
    search: query.search,
    ownerUserId: query.organizationId ? undefined : tenants?.find((tenant) => tenant.type === 'user')?.id,
    ownerOrganizationIds: selectedOrganizationIds,
  })
  const resourceIds = [...new Set(result.items.flatMap((event) => (event.resourceId ? [event.resourceId] : [])))]
  const resources = await getDeps(c).authorization.findResources(resourceIds)
  const resourcesById = new Map(resources.map((resource) => [resource.id, resource]))
  return c.json({
    items: result.items.map((event) =>
      managementAgentAuditEventSchema.parse({
        ...event,
        resource: event.resourceId ? (resourcesById.get(event.resourceId) ?? null) : null,
      }),
    ),
    pagination: paginationMetadata({ ...page, total: result.total }),
  })
})

async function requireAgentByIdConsoleAccess(c: Parameters<typeof getDeps>[0], agentId: string) {
  const agent = await getAgent(getDeps(c), agentId)
  await requireAgentAccess(c, agent)
}

async function requireAgentByIdPermissionAccess(c: Parameters<typeof getDeps>[0], agentId: string, write = false) {
  const agent = await getAgent(getDeps(c), agentId)
  const scope = write ? 'permissions:write' : 'permissions:read'
  await authorizeUser(c, agent.homeSpace.userId, scope)
}

async function authorityInventoryScope(c: Parameters<typeof getDeps>[0]) {
  const tenants = await authorizedTenantInventory(c, 'permissions:read')
  if (!tenants) return undefined
  return { ownerUserId: tenants.find((tenant) => tenant.type === 'user')?.id }
}

async function agentInventoryScope(c: Parameters<typeof getDeps>[0]) {
  const tenants = await authorizedTenantInventory(c, 'agents:read')
  if (!tenants) return undefined
  return { ownerUserId: tenants.find((tenant) => tenant.type === 'user')?.id }
}

async function requireAgentAccess(
  c: Parameters<typeof getDeps>[0],
  agent: Awaited<ReturnType<typeof getAgent>>,
  write = false,
) {
  await authorizeUser(c, agent.homeSpace.userId, write ? 'agents:write' : 'agents:read')
}
