import { conflict } from '@server/domain/errors'
import type { IdentifierGenerator } from '@server/usecases/identifier-generator'
import type { AuthorizationRepository, ResourceScopeEntitlementRecord } from '@server/usecases/ports'
import { decodeRoleScope, encodeRoleScope } from '@shared/organization-access'
import { and, asc, count, countDistinct, desc, eq, gt, inArray, isNull, like, notExists, or, sql } from 'drizzle-orm'
import type { BatchItem } from 'drizzle-orm/batch'
import type { Database } from '../../db/client'
import {
  agentAccessRequest,
  agentAuditEvent,
  agentIdentity,
  apiResource,
  application,
  applicationConsent,
  externalTokenLease,
  federatedCredential,
  invitation,
  member,
  oauthRefreshToken,
  organization,
  organizationRole,
  providerResourceAuthorization,
  resourceConnectionIntent,
  resourceScopeEntitlement,
  session,
  team,
  teamMember,
  tokenExchangeAccessToken,
  tokenExchangeRefreshToken,
} from '../../db/schema'
import {
  serializeRoles,
  toInvitation,
  toMember,
  toOrganization,
  toOrganizationRole,
  toPagination,
  toResource,
  withoutUndefined,
} from './authorization-mappers'
import { scopeEntitlementStatusCondition } from './resource-scope-entitlement-filters'

export function createDrizzleAuthorizationRepository(db: Database, ids: IdentifierGenerator): AuthorizationRepository {
  return {
    async createOrganization(input, owner) {
      const now = new Date()
      const { roles, ...ownerRecord } = owner
      await db.batch([
        db.insert(organization).values({ ...input, createdAt: now, updatedAt: now }),
        db.insert(member).values({
          ...ownerRecord,
          organizationId: input.id,
          role: serializeRoles(roles),
          createdAt: now,
          updatedAt: now,
        }),
      ])
      return { ...input, createdAt: now.toISOString(), updatedAt: now.toISOString() }
    },

    async listOrganizations(pagination, organizationIds) {
      if (organizationIds?.length === 0) {
        return { items: [], pagination: toPagination(pagination, 0) }
      }
      const organizationCondition = organizationIds ? inArray(organization.id, organizationIds) : undefined
      const rows = await db
        .select()
        .from(organization)
        .where(organizationCondition)
        .orderBy(desc(organization.createdAt), desc(organization.id))
        .limit(pagination.limit)
        .offset(pagination.offset)
      const totalResult = await db.select({ total: count() }).from(organization).where(organizationCondition)
      const total = totalResult[0]?.total ?? 0
      return { items: rows.map(toOrganization), pagination: toPagination(pagination, total) }
    },

    async findOrganization(id) {
      const rows = await db.select().from(organization).where(eq(organization.id, id)).limit(1)
      return rows[0] ? toOrganization(rows[0]) : null
    },

    async updateOrganization(id, patch) {
      await db
        .update(organization)
        .set({ ...withoutUndefined(patch), updatedAt: new Date() })
        .where(eq(organization.id, id))
    },

    async deleteOrganization(id) {
      await db.delete(organization).where(eq(organization.id, id))
    },

    async addMember(organizationId, input) {
      const now = new Date()
      const { roles, ...record } = input
      await db
        .insert(member)
        .values({ ...record, role: serializeRoles(roles), organizationId, createdAt: now, updatedAt: now })
      return { ...input, organizationId, createdAt: now.toISOString(), updatedAt: now.toISOString() }
    },

    async listMembers(organizationId, pagination) {
      const rows = await db
        .select()
        .from(member)
        .where(eq(member.organizationId, organizationId))
        .orderBy(desc(member.createdAt), desc(member.id))
        .limit(pagination.limit)
        .offset(pagination.offset)
      const total = await totalRows(db, member, eq(member.organizationId, organizationId))
      return { items: rows.map(toMember), pagination: toPagination(pagination, total) }
    },

    async findMember(id) {
      const rows = await db.select().from(member).where(eq(member.id, id)).limit(1)
      return rows[0] ? toMember(rows[0]) : null
    },

    async findMemberByOrganizationUser(organizationId, userId) {
      const rows = await db
        .select()
        .from(member)
        .where(and(eq(member.organizationId, organizationId), eq(member.userId, userId)))
        .limit(1)
      return rows[0] ? toMember(rows[0]) : null
    },

    async listUserMemberships(userId) {
      const rows = await db
        .select()
        .from(member)
        .where(eq(member.userId, userId))
        .orderBy(desc(member.createdAt), desc(member.id))
      return rows.map(toMember)
    },

    async findTeam(id) {
      const rows = await db.select().from(team).where(eq(team.id, id)).limit(1)
      const row = rows[0]
      return row
        ? {
            ...row,
            createdAt: row.createdAt.toISOString(),
            updatedAt: row.updatedAt.toISOString(),
          }
        : null
    },

    async listTeamMembers(teamId, pagination) {
      const rows = await db
        .select()
        .from(teamMember)
        .where(eq(teamMember.teamId, teamId))
        .orderBy(desc(teamMember.createdAt), desc(teamMember.id))
        .limit(pagination.limit)
        .offset(pagination.offset)
      const total = await totalRows(db, teamMember, eq(teamMember.teamId, teamId))
      return {
        items: rows.map((row) => ({ ...row, createdAt: row.createdAt.toISOString() })),
        pagination: toPagination(pagination, total),
      }
    },

    async listTeamNamesForUser(organizationId, userId) {
      const rows = await db
        .select({ name: team.name })
        .from(teamMember)
        .innerJoin(team, eq(team.id, teamMember.teamId))
        .where(and(eq(team.organizationId, organizationId), eq(teamMember.userId, userId)))
        .orderBy(asc(team.name))
      return rows.map((row) => row.name)
    },

    async listMemberUserIds(organizationIds) {
      if (organizationIds.length === 0) return []
      const rows = await db
        .selectDistinct({ userId: member.userId })
        .from(member)
        .where(inArray(member.organizationId, organizationIds))
      return rows.map((row) => row.userId)
    },

    async countMembersByRole(organizationId, roleName) {
      const [result] = await db
        .select({ value: count() })
        .from(member)
        .where(
          and(eq(member.organizationId, organizationId), sql`(',' || ${member.role} || ',') like ${`%,${roleName},%`}`),
        )
      return result?.value ?? 0
    },

    async hasPendingInvitation(email, now) {
      const rows = await db
        .select({ id: invitation.id })
        .from(invitation)
        .where(and(eq(invitation.email, email), eq(invitation.status, 'pending'), gt(invitation.expiresAt, now)))
        .limit(1)
      return rows.length > 0
    },

    async updateMember(id, patch) {
      await db
        .update(member)
        .set({ ...withoutUndefined(patch), updatedAt: new Date() })
        .where(eq(member.id, id))
    },

    async replaceMemberRoles(organizationId, memberId, roles, expectedUpdatedAt, audit) {
      const expected = new Date(expectedUpdatedAt)
      const now = audit.occurredAt
      const lastOwnerGuard = roles.includes('owner')
        ? undefined
        : sql`(
            (',' || ${member.role} || ',') not like '%,owner,%'
            or exists (
              select 1 from ${member} as other
              where other.organization_id = ${organizationId}
                and other.id <> ${memberId}
                and (',' || other.role || ',') like '%,owner,%'
            )
          )`
      const condition = and(
        eq(member.id, memberId),
        eq(member.organizationId, organizationId),
        eq(member.updatedAt, expected),
        lastOwnerGuard,
      )
      const [, updated] = await db.batch([
        db
          .insert(agentAuditEvent)
          .select(db.select(auditSelect(audit, { organizationId, memberId, roles })).from(member).where(condition)),
        db
          .update(member)
          .set({ role: serializeRoles(roles), updatedAt: now })
          .where(condition)
          .returning({ id: member.id }),
      ])
      return updated.length > 0
    },

    async removeMember(organizationId, memberId, expectedUpdatedAt, audit) {
      const expected = new Date(expectedUpdatedAt)
      const condition = and(
        eq(member.id, memberId),
        eq(member.organizationId, organizationId),
        eq(member.updatedAt, expected),
        sql`(
          (',' || ${member.role} || ',') not like '%,owner,%'
          or exists (
            select 1 from ${member} as other
            where other.organization_id = ${organizationId}
              and other.id <> ${memberId}
              and (',' || other.role || ',') like '%,owner,%'
          )
        )`,
      )
      const targetUserIds = db.select({ userId: member.userId }).from(member).where(condition)
      const privateApplicationClientIds = db
        .select({ clientId: application.oauthClientId })
        .from(application)
        .where(and(eq(application.ownerOrganizationId, organizationId), eq(application.visibility, 'private')))
      const organizationTeamIds = db
        .select({ teamId: team.id })
        .from(team)
        .where(eq(team.organizationId, organizationId))
      const now = new Date()
      const [, , , , removed] = await db.batch([
        db
          .insert(agentAuditEvent)
          .select(db.select(auditSelect(audit, { organizationId, memberId })).from(member).where(condition)),
        db
          .delete(teamMember)
          .where(and(inArray(teamMember.userId, targetUserIds), inArray(teamMember.teamId, organizationTeamIds))),
        db
          .update(oauthRefreshToken)
          .set({ revoked: now })
          .where(
            and(
              inArray(oauthRefreshToken.userId, targetUserIds),
              inArray(oauthRefreshToken.clientId, privateApplicationClientIds),
              isNull(oauthRefreshToken.revoked),
            ),
          ),
        db
          .update(session)
          .set({ activeOrganizationId: null, activeTeamId: null })
          .where(and(inArray(session.userId, targetUserIds), eq(session.activeOrganizationId, organizationId))),
        db.delete(member).where(condition).returning({ id: member.id }),
      ])
      return removed.length > 0
    },

    async createInvitation(input) {
      const now = new Date()
      const expiresAt = new Date(input.expiresAt)
      const { roles, ...record } = input
      await db.insert(invitation).values({ ...record, role: serializeRoles(roles), expiresAt, createdAt: now })
      return {
        ...input,
        expiresAt: expiresAt.toISOString(),
        acceptedAt: null,
        revokedAt: null,
        createdAt: now.toISOString(),
      }
    },

    async listInvitations(organizationId, pagination) {
      const rows = await db
        .select()
        .from(invitation)
        .where(eq(invitation.organizationId, organizationId))
        .orderBy(desc(invitation.createdAt), desc(invitation.id))
        .limit(pagination.limit)
        .offset(pagination.offset)
      const total = await totalRows(db, invitation, eq(invitation.organizationId, organizationId))
      return { items: rows.map(toInvitation), pagination: toPagination(pagination, total) }
    },

    async findInvitation(id) {
      const rows = await db.select().from(invitation).where(eq(invitation.id, id)).limit(1)
      return rows[0] ? toInvitation(rows[0]) : null
    },

    async cancelInvitation(id) {
      await db.update(invitation).set({ status: 'canceled', revokedAt: new Date() }).where(eq(invitation.id, id))
    },

    async createResource(input) {
      return resourceKeyWrite(async () => {
        const now = new Date()
        const rows = await db
          .insert(apiResource)
          .values({
            ...input,
            createdAt: now,
            updatedAt: now,
          })
          .returning()
        return toResource(rows[0]!)
      })
    },

    async listResources(pagination, ownerOrganizationIds) {
      if (ownerOrganizationIds?.length === 0) {
        return { items: [], pagination: toPagination(pagination, 0) }
      }
      const ownerCondition = ownerOrganizationIds
        ? and(inArray(apiResource.ownerOrganizationId, ownerOrganizationIds), isNull(apiResource.deletedAt))
        : isNull(apiResource.deletedAt)
      const rows = await db
        .select()
        .from(apiResource)
        .where(ownerCondition)
        .orderBy(desc(apiResource.createdAt), desc(apiResource.id))
        .limit(pagination.limit)
        .offset(pagination.offset)
      const totalResult = await db.select({ total: count() }).from(apiResource).where(ownerCondition)
      const total = totalResult[0]?.total ?? 0
      return {
        items: rows.map(toResource),
        pagination: toPagination(pagination, total),
      }
    },

    async listEnabledResources() {
      const rows = await db
        .select()
        .from(apiResource)
        .where(and(eq(apiResource.enabled, true), isNull(apiResource.deletedAt)))
        .orderBy(desc(apiResource.createdAt), desc(apiResource.id))
      return rows.map(toResource)
    },

    async findResources(ids) {
      const rows = await db
        .select()
        .from(apiResource)
        .where(
          and(
            sql`${apiResource.id} in (select value from json_each(${JSON.stringify(ids)}))`,
            isNull(apiResource.deletedAt),
          ),
        )
      return rows.map(toResource)
    },

    async findResource(id) {
      const rows = await db
        .select()
        .from(apiResource)
        .where(and(eq(apiResource.id, id), isNull(apiResource.deletedAt)))
        .limit(1)
      const row = rows[0]
      if (!row) return null
      return toResource(row)
    },

    async findResourceByResourceUrl(resourceUrl) {
      const rows = await db
        .select()
        .from(apiResource)
        .where(
          and(eq(apiResource.resourceUrl, resourceUrl), eq(apiResource.enabled, true), isNull(apiResource.deletedAt)),
        )
        .limit(1)
      const row = rows[0]
      if (!row) return null
      return toResource(row)
    },

    async updateResource(id, patch) {
      return resourceKeyWrite(async () => {
        const { scopeGrantModes: _, ...storedPatch } = patch
        const now = new Date()
        const update = db
          .update(apiResource)
          .set({
            ...withoutUndefined(storedPatch),
            updatedAt: now,
          })
          .where(and(eq(apiResource.id, id), isNull(apiResource.deletedAt)))
          .returning({ id: apiResource.id })
        if (patch.visibility !== 'private') return (await update).length > 0

        const [resource] = await db.select().from(apiResource).where(eq(apiResource.id, id)).limit(1)
        if (!resource) return false
        const ownerOrganizationId = patch.ownerOrganizationId ?? resource.ownerOrganizationId
        const [members, applications, entitlements, roles, consents, identities] = await Promise.all([
          db.select().from(member).where(eq(member.organizationId, ownerOrganizationId)),
          db.select().from(application),
          db.select().from(resourceScopeEntitlement).where(eq(resourceScopeEntitlement.resourceServerId, id)),
          db.select().from(organizationRole),
          db.select().from(applicationConsent).where(eq(applicationConsent.resourceServerId, id)),
          db.select().from(agentIdentity),
        ])
        const ownerUsers = new Set(members.map((membership) => membership.userId))
        const applicationOwners = new Map(applications.map((app) => [app.id, app.ownerOrganizationId]))
        const identityOwners = new Map(identities.map((identity) => [identity.id, identity.ownerUserId]))
        const statements: [BatchItem<'sqlite'>, ...BatchItem<'sqlite'>[]] = [update]
        for (const app of applications) {
          if (app.ownerOrganizationId === ownerOrganizationId) continue
          const resourceScopes = app.resourceScopes.filter((configuration) => configuration.resourceServerId !== id)
          if (resourceScopes.length !== app.resourceScopes.length) {
            statements.push(
              db.update(application).set({ resourceScopes, updatedAt: now }).where(eq(application.id, app.id)),
            )
          }
        }
        for (const entitlement of entitlements) {
          const remainsVisible = entitlement.userId
            ? ownerUsers.has(entitlement.userId)
            : entitlement.applicationId
              ? applicationOwners.get(entitlement.applicationId) === ownerOrganizationId
              : ownerUsers.has(identityOwners.get(entitlement.agentIdentityId!) ?? '')
          if (!remainsVisible && !entitlement.endedAt) {
            statements.push(
              db
                .update(resourceScopeEntitlement)
                .set({ endedAt: now, endReason: 'revoked', updatedAt: now })
                .where(eq(resourceScopeEntitlement.id, entitlement.id)),
            )
          }
        }
        for (const role of roles) {
          if (role.organizationId === ownerOrganizationId) continue
          const encodedScopes = role.permission.scope ?? []
          const scopes = encodedScopes.filter((value) => decodeRoleScope(value)?.resourceId !== id)
          if (scopes.length !== encodedScopes.length) {
            statements.push(
              db
                .update(organizationRole)
                .set({ permission: { ...role.permission, scope: scopes }, updatedAt: now })
                .where(eq(organizationRole.id, role.id)),
            )
          }
        }
        for (const consent of consents) {
          if (!ownerUsers.has(consent.userId) && !consent.revokedAt) {
            statements.push(
              db.update(applicationConsent).set({ revokedAt: now }).where(eq(applicationConsent.id, consent.id)),
            )
          }
        }
        const [rows] = await db.batch(statements)
        return rows.length > 0
      })
    },

    async replaceResourceDiscovery(id, { name, description, scopeRegistry: registry }) {
      const now = new Date()
      const declared = new Set(registry.scopes.map((scope) => scope.value))
      const assigned = new Set(
        registry.scopes.filter((scope) => scope.grantMode === 'assigned').map((scope) => scope.value),
      )
      const oidcScopes = new Set(['openid', 'profile', 'email', 'offline_access'])
      const [applications, entitlements, roles, consents] = await Promise.all([
        db.select().from(application),
        db.select().from(resourceScopeEntitlement).where(eq(resourceScopeEntitlement.resourceServerId, id)),
        db.select().from(organizationRole),
        db.select().from(applicationConsent).where(eq(applicationConsent.resourceServerId, id)),
      ])
      const statements: [BatchItem<'sqlite'>, ...BatchItem<'sqlite'>[]] = [
        db
          .update(apiResource)
          .set({ name, description, scopeRegistry: registry, updatedAt: now })
          .where(and(eq(apiResource.id, id), isNull(apiResource.deletedAt))),
      ]
      for (const app of applications) {
        const resourceScopes = app.resourceScopes
          .map((configuration) =>
            configuration.resourceServerId === id
              ? { ...configuration, scopes: configuration.scopes.filter((scope) => declared.has(scope)) }
              : configuration,
          )
          .filter((configuration) => configuration.resourceServerId !== id || configuration.scopes.length > 0)
        if (JSON.stringify(resourceScopes) !== JSON.stringify(app.resourceScopes)) {
          statements.push(
            db.update(application).set({ resourceScopes, updatedAt: now }).where(eq(application.id, app.id)),
          )
        }
      }
      for (const entitlement of entitlements) {
        if (!assigned.has(entitlement.scope) && !entitlement.endedAt) {
          statements.push(
            db
              .update(resourceScopeEntitlement)
              .set({ endedAt: now, endReason: 'revoked', updatedAt: now })
              .where(eq(resourceScopeEntitlement.id, entitlement.id)),
          )
        }
      }
      for (const role of roles) {
        const encodedScopes = role.permission.scope ?? []
        const scopes = encodedScopes.flatMap((value) => {
          const decoded = decodeRoleScope(value)
          if (!decoded || decoded.resourceId !== id) return [value]
          return assigned.has(decoded.scope) ? [encodeRoleScope(id, decoded.scope)] : []
        })
        if (scopes.length !== encodedScopes.length) {
          statements.push(
            db
              .update(organizationRole)
              .set({ permission: { ...role.permission, scope: scopes }, updatedAt: now })
              .where(eq(organizationRole.id, role.id)),
          )
        }
      }
      for (const consent of consents) {
        const scopes = consent.scopes.filter((scope) => oidcScopes.has(scope) || declared.has(scope))
        statements.push(
          db
            .update(applicationConsent)
            .set(scopes.length > 0 ? { scopes } : { revokedAt: now })
            .where(eq(applicationConsent.id, consent.id)),
        )
      }
      await db.batch(statements)
      return true
    },

    async createScopeEntitlement(input, now) {
      let [existing] = await db
        .select()
        .from(resourceScopeEntitlement)
        .where(activeEquivalentEntitlement(input))
        .limit(1)
      if (!existing) {
        const [inserted] = await db.insert(resourceScopeEntitlement).values(input).onConflictDoNothing().returning()
        if (inserted) return inserted
        ;[existing] = await db
          .select()
          .from(resourceScopeEntitlement)
          .where(activeEquivalentEntitlement(input))
          .limit(1)
        if (!existing) throw new Error('Equivalent active permission was not found after a concurrent grant.')
      }
      if (existing.expiresAt && existing.expiresAt.getTime() <= now.getTime()) {
        await db.batch([
          db
            .update(resourceScopeEntitlement)
            .set({ endedAt: now, endReason: 'expired', updatedAt: now })
            .where(eq(resourceScopeEntitlement.id, existing.id)),
          db.insert(resourceScopeEntitlement).values(input),
        ])
        return input
      }
      const lifetime = strongerLifetime(existing, input)
      const normalizedHash =
        existing.authorizationContextHash === input.authorizationContextHash ? null : input.authorizationContextHash
      if (!lifetime && !normalizedHash) return existing
      const [updated] = await db
        .update(resourceScopeEntitlement)
        .set({
          ...lifetime,
          authorizationContextHash: normalizedHash ?? existing.authorizationContextHash,
          updatedAt: now,
        })
        .where(eq(resourceScopeEntitlement.id, existing.id))
        .returning()
      return updated!
    },

    async findScopeEntitlement(id) {
      const [row] = await db.select().from(resourceScopeEntitlement).where(eq(resourceScopeEntitlement.id, id)).limit(1)
      return row ?? null
    },

    async listUserPermissions(userId, query, ownerOrganizationIds) {
      const now = new Date()
      const statusCondition = scopeEntitlementStatusCondition(query.status, now)
      const effectiveOwnerOrganizationId = sql<string>`coalesce(${resourceScopeEntitlement.organizationId}, ${apiResource.ownerOrganizationId})`
      const where = and(
        eq(resourceScopeEntitlement.userId, userId),
        query.resourceServerId ? eq(resourceScopeEntitlement.resourceServerId, query.resourceServerId) : undefined,
        ownerOrganizationIds ? inArray(effectiveOwnerOrganizationId, ownerOrganizationIds) : undefined,
        statusCondition,
      )
      const [items, totals] = await Promise.all([
        db
          .select({ entitlement: resourceScopeEntitlement })
          .from(resourceScopeEntitlement)
          .innerJoin(apiResource, eq(resourceScopeEntitlement.resourceServerId, apiResource.id))
          .where(where)
          .orderBy(desc(resourceScopeEntitlement.createdAt), desc(resourceScopeEntitlement.id))
          .limit(query.limit)
          .offset(query.offset),
        db
          .select({ value: count() })
          .from(resourceScopeEntitlement)
          .innerJoin(apiResource, eq(resourceScopeEntitlement.resourceServerId, apiResource.id))
          .where(where),
      ])
      return {
        items: items.map(({ entitlement }) => entitlement),
        pagination: toPagination(query, totals[0]?.value ?? 0),
      }
    },

    async listActiveUserScopeEntitlements(userId, resourceServerId, now) {
      return db
        .select()
        .from(resourceScopeEntitlement)
        .where(
          and(
            eq(resourceScopeEntitlement.userId, userId),
            eq(resourceScopeEntitlement.resourceServerId, resourceServerId),
            isNull(resourceScopeEntitlement.endedAt),
            or(isNull(resourceScopeEntitlement.expiresAt), gt(resourceScopeEntitlement.expiresAt, now)),
          ),
        )
    },

    async listApplicationPermissions(applicationId, query) {
      const now = new Date()
      const statusCondition = scopeEntitlementStatusCondition(query.status, now)
      const where = and(
        eq(resourceScopeEntitlement.applicationId, applicationId),
        query.resourceServerId ? eq(resourceScopeEntitlement.resourceServerId, query.resourceServerId) : undefined,
        statusCondition,
      )
      const [items, totals] = await Promise.all([
        db
          .select()
          .from(resourceScopeEntitlement)
          .where(where)
          .orderBy(desc(resourceScopeEntitlement.createdAt), desc(resourceScopeEntitlement.id))
          .limit(query.limit)
          .offset(query.offset),
        db.select({ value: count() }).from(resourceScopeEntitlement).where(where),
      ])
      return {
        items,
        pagination: toPagination(query, totals[0]?.value ?? 0),
      }
    },

    async listAuthorizedResourceServers(subject, query, now, ownerOrganizationIds) {
      const effectiveOwnerOrganizationId = sql<string>`coalesce(${resourceScopeEntitlement.organizationId}, ${apiResource.ownerOrganizationId})`
      const search = query.search ? `%${query.search}%` : undefined
      const where = and(
        permissionSubjectCondition(subject),
        scopeEntitlementStatusCondition('active', now),
        isNull(apiResource.deletedAt),
        ownerOrganizationIds ? inArray(effectiveOwnerOrganizationId, ownerOrganizationIds) : undefined,
        search ? or(like(apiResource.name, search), like(apiResource.identifier, search)) : undefined,
      )
      const [items, totals] = await Promise.all([
        db
          .select({
            id: apiResource.id,
            name: apiResource.name,
            identifier: apiResource.identifier,
            permissionCount: count(),
          })
          .from(resourceScopeEntitlement)
          .innerJoin(apiResource, eq(resourceScopeEntitlement.resourceServerId, apiResource.id))
          .where(where)
          .groupBy(apiResource.id, apiResource.name, apiResource.identifier)
          .orderBy(asc(apiResource.name), asc(apiResource.id))
          .limit(query.limit)
          .offset(query.offset),
        db
          .select({ value: countDistinct(resourceScopeEntitlement.resourceServerId) })
          .from(resourceScopeEntitlement)
          .innerJoin(apiResource, eq(resourceScopeEntitlement.resourceServerId, apiResource.id))
          .where(where),
      ])
      return { items, pagination: toPagination(query, totals[0]?.value ?? 0) }
    },

    async listActiveApplicationScopeEntitlements(applicationId, resourceServerId, now) {
      return db
        .select()
        .from(resourceScopeEntitlement)
        .where(
          and(
            eq(resourceScopeEntitlement.applicationId, applicationId),
            eq(resourceScopeEntitlement.resourceServerId, resourceServerId),
            isNull(resourceScopeEntitlement.endedAt),
            or(isNull(resourceScopeEntitlement.expiresAt), gt(resourceScopeEntitlement.expiresAt, now)),
          ),
        )
    },

    async endScopeEntitlement(id, reason, now) {
      const rows = await db
        .update(resourceScopeEntitlement)
        .set({ endedAt: now, endReason: reason, updatedAt: now })
        .where(and(eq(resourceScopeEntitlement.id, id), isNull(resourceScopeEntitlement.endedAt)))
        .returning({ id: resourceScopeEntitlement.id })
      return rows.length > 0
    },

    async deleteResource(id, now, audit) {
      const [active] = await db
        .select({ id: apiResource.id })
        .from(apiResource)
        .where(and(eq(apiResource.id, id), isNull(apiResource.deletedAt)))
        .limit(1)
      if (!active) return false
      const encodedRoleScopePrefix = `${encodeURIComponent(id)}/`
      const statements: BatchItem<'sqlite'>[] = [
        db.insert(agentAuditEvent).select(
          db
            .select({
              id: sql<string>`${audit.id}`.as('id'),
              action: sql<string>`${audit.action}`.as('action'),
              result: sql<string>`${audit.result}`.as('result'),
              realmOwned: sql<boolean>`${audit.realmOwned}`.as('realm_owned'),
              ownerUserId: sql<string | null>`${audit.ownerUserId}`.as('owner_user_id'),
              ownerOrganizationId: sql<string | null>`${audit.ownerOrganizationId}`.as('owner_organization_id'),
              controllerUserId: sql<string | null>`${audit.controllerUserId}`.as('controller_user_id'),
              subjectIssuer: sql<string | null>`${audit.subjectIssuer}`.as('subject_issuer'),
              subject: sql<string | null>`${audit.subject}`.as('subject'),
              agentIdentityId: sql<string | null>`${audit.agentIdentityId}`.as('agent_identity_id'),
              hostId: sql<string | null>`${audit.hostId}`.as('host_id'),
              resourceId: apiResource.id,
              resourceConnectionId: sql<string | null>`${audit.resourceConnectionId}`.as('resource_connection_id'),
              accessRequestId: sql<string | null>`${audit.accessRequestId}`.as('access_request_id'),
              scopes: sql<string[] | null>`${audit.scopes === null ? null : JSON.stringify(audit.scopes)}`.as('scopes'),
              reasonCode: sql<string | null>`${audit.reasonCode}`.as('reason_code'),
              metadata: sql<Record<string, unknown> | null>`${
                audit.metadata === null ? null : JSON.stringify(audit.metadata)
              }`.as('metadata'),
              occurredAt: sql<Date>`${audit.occurredAt.getTime()}`.as('occurred_at'),
            })
            .from(apiResource)
            .where(and(eq(apiResource.id, id), isNull(apiResource.deletedAt))),
        ),
        db
          .update(apiResource)
          .set({ enabled: false, deletedAt: now, updatedAt: now })
          .where(and(eq(apiResource.id, id), isNull(apiResource.deletedAt)))
          .returning({ id: apiResource.id }),
        db
          .update(providerResourceAuthorization)
          .set({ status: 'revoked', revokedAt: now, updatedAt: now })
          .where(
            and(eq(providerResourceAuthorization.resourceId, id), eq(providerResourceAuthorization.status, 'active')),
          ),
        db
          .update(resourceConnectionIntent)
          .set({ status: 'cancelled', completedAt: now, updatedAt: now })
          .where(and(eq(resourceConnectionIntent.resourceId, id), eq(resourceConnectionIntent.status, 'pending'))),
        db
          .update(agentAccessRequest)
          .set({ status: 'denied', decidedAt: now, updatedAt: now })
          .where(and(eq(agentAccessRequest.resourceId, id), eq(agentAccessRequest.status, 'pending'))),
        db
          .update(resourceScopeEntitlement)
          .set({ endedAt: now, endReason: 'revoked', updatedAt: now })
          .where(and(eq(resourceScopeEntitlement.resourceServerId, id), isNull(resourceScopeEntitlement.endedAt))),
        db
          .update(applicationConsent)
          .set({ revokedAt: now })
          .where(and(eq(applicationConsent.resourceServerId, id), isNull(applicationConsent.revokedAt))),
        db
          .update(application)
          .set({
            resourceScopes: sql`coalesce(
              (
                select json_group_array(json(resource_scope.value))
                from json_each(${application.resourceScopes}) as resource_scope
                where json_extract(resource_scope.value, '$.resourceServerId') <> ${id}
              ),
              '[]'
            )`,
            updatedAt: now,
          })
          .where(
            sql`exists (
              select 1
              from json_each(${application.resourceScopes}) as resource_scope
              where json_extract(resource_scope.value, '$.resourceServerId') = ${id}
            )`,
          ),
        db
          .update(organizationRole)
          .set({
            permission: sql`json_set(
              ${organizationRole.permission},
              '$.scope',
              json(coalesce(
                (
                  select json_group_array(role_scope.value)
                  from json_each(json_extract(${organizationRole.permission}, '$.scope')) as role_scope
                  where substr(role_scope.value, 1, ${encodedRoleScopePrefix.length}) <> ${encodedRoleScopePrefix}
                ),
                '[]'
              ))
            )`,
            updatedAt: now,
          })
          .where(
            sql`exists (
              select 1
              from json_each(json_extract(${organizationRole.permission}, '$.scope')) as role_scope
              where substr(role_scope.value, 1, ${encodedRoleScopePrefix.length}) = ${encodedRoleScopePrefix}
            )`,
          ),
        db
          .update(federatedCredential)
          .set({ enabled: false, updatedAt: now })
          .where(and(eq(federatedCredential.audienceResourceId, id), eq(federatedCredential.enabled, true))),
        db
          .update(tokenExchangeAccessToken)
          .set({ revokedAt: now })
          .where(
            and(
              isNull(tokenExchangeAccessToken.revokedAt),
              inArray(
                tokenExchangeAccessToken.credentialId,
                db
                  .select({ id: federatedCredential.id })
                  .from(federatedCredential)
                  .where(eq(federatedCredential.audienceResourceId, id)),
              ),
            ),
          ),
        db
          .update(tokenExchangeRefreshToken)
          .set({ revokedAt: now })
          .where(
            and(
              isNull(tokenExchangeRefreshToken.revokedAt),
              inArray(
                tokenExchangeRefreshToken.credentialId,
                db
                  .select({ id: federatedCredential.id })
                  .from(federatedCredential)
                  .where(eq(federatedCredential.audienceResourceId, id)),
              ),
            ),
          ),
        db
          .update(externalTokenLease)
          .set({ revokedAt: now })
          .where(
            and(
              isNull(externalTokenLease.revokedAt),
              inArray(
                externalTokenLease.requestId,
                db
                  .select({ id: agentAccessRequest.id })
                  .from(agentAccessRequest)
                  .where(eq(agentAccessRequest.resourceId, id)),
              ),
            ),
          ),
      ]
      await db.batch(statements as [BatchItem<'sqlite'>, ...BatchItem<'sqlite'>[]])
      return true
    },

    async createOrganizationRole(organizationId, input, permission, audit) {
      const now = audit.occurredAt
      const row = {
        id: ids.generate(),
        organizationId,
        role: input.key,
        permission,
        displayName: input.displayName,
        description: input.description,
        createdAt: now,
        updatedAt: now,
      }
      try {
        await db.batch([db.insert(organizationRole).values(row), db.insert(agentAuditEvent).values(audit)])
      } catch (error) {
        if (isUniqueConstraint(error)) throw conflict(`Role key "${input.key}" is already in use.`)
        throw error
      }
      return { ...input, predefined: false, createdAt: now.toISOString(), updatedAt: now.toISOString() }
    },

    async listOrganizationRoles(organizationId) {
      const rows = await db
        .select()
        .from(organizationRole)
        .where(eq(organizationRole.organizationId, organizationId))
        .orderBy(organizationRole.role)
      return rows.map(toOrganizationRole)
    },

    async findOrganizationRole(organizationId, roleKey) {
      const [row] = await db
        .select()
        .from(organizationRole)
        .where(and(eq(organizationRole.organizationId, organizationId), eq(organizationRole.role, roleKey)))
        .limit(1)
      return row ? toOrganizationRole(row) : null
    },

    async listOrganizationRoleScopes(organizationId) {
      const rows = await db
        .select({ role: organizationRole.role, permission: organizationRole.permission })
        .from(organizationRole)
        .where(eq(organizationRole.organizationId, organizationId))
      return new Map(rows.map((row) => [row.role, decodePermissionScopes(row.permission)]))
    },

    async updateOrganizationRole(organizationId, roleKey, patch, permission, expectedUpdatedAt, audit) {
      const condition = and(
        eq(organizationRole.organizationId, organizationId),
        eq(organizationRole.role, roleKey),
        eq(organizationRole.updatedAt, new Date(expectedUpdatedAt)),
      )
      const [, updated] = await db.batch([
        db
          .insert(agentAuditEvent)
          .select(db.select(auditSelect(audit, { organizationId, roleKey })).from(organizationRole).where(condition)),
        db
          .update(organizationRole)
          .set({
            ...withoutUndefined({
              displayName: patch.displayName,
              description: patch.description,
              permission,
            }),
            updatedAt: audit.occurredAt,
          })
          .where(condition)
          .returning({ id: organizationRole.id }),
      ])
      return updated.length > 0
    },

    async deleteOrganizationRole(organizationId, roleKey, expectedUpdatedAt, audit) {
      const assignedMember = sql`(',' || ${member.role} || ',') like ${`%,${roleKey},%`}`
      const assignedInvitation = sql`(',' || ${invitation.role} || ',') like ${`%,${roleKey},%`}`
      const condition = and(
        eq(organizationRole.organizationId, organizationId),
        eq(organizationRole.role, roleKey),
        eq(organizationRole.updatedAt, new Date(expectedUpdatedAt)),
        notExists(
          db
            .select({ id: member.id })
            .from(member)
            .where(and(eq(member.organizationId, organizationId), assignedMember)),
        ),
        notExists(
          db
            .select({ id: invitation.id })
            .from(invitation)
            .where(
              and(eq(invitation.organizationId, organizationId), eq(invitation.status, 'pending'), assignedInvitation),
            ),
        ),
      )
      const [, deleted] = await db.batch([
        db
          .insert(agentAuditEvent)
          .select(db.select(auditSelect(audit, { organizationId, roleKey })).from(organizationRole).where(condition)),
        db.delete(organizationRole).where(condition).returning({ id: organizationRole.id }),
      ])
      if (deleted.length > 0) return 'deleted'
      const [existing] = await db
        .select({ id: organizationRole.id })
        .from(organizationRole)
        .where(and(eq(organizationRole.organizationId, organizationId), eq(organizationRole.role, roleKey)))
        .limit(1)
      if (!existing) return 'not_found'
      const [assignment] = await db
        .select({ id: member.id })
        .from(member)
        .where(and(eq(member.organizationId, organizationId), assignedMember))
        .limit(1)
      if (assignment) return 'assigned'
      const [pendingInvitation] = await db
        .select({ id: invitation.id })
        .from(invitation)
        .where(and(eq(invitation.organizationId, organizationId), eq(invitation.status, 'pending'), assignedInvitation))
        .limit(1)
      return pendingInvitation ? 'assigned' : 'not_found'
    },
  }
}

function permissionSubjectCondition(subject: import('@server/usecases/ports').PermissionSubject) {
  if (subject.type === 'user') return eq(resourceScopeEntitlement.userId, subject.id)
  if (subject.type === 'application') return eq(resourceScopeEntitlement.applicationId, subject.id)
  return eq(resourceScopeEntitlement.agentIdentityId, subject.id)
}

function isUniqueConstraint(error: unknown) {
  let current = error
  while (current instanceof Error) {
    if (/unique constraint|SQLITE_CONSTRAINT/i.test(current.message)) return true
    current = current.cause
  }
  return false
}

async function resourceKeyWrite<T>(write: () => Promise<T>) {
  try {
    return await write()
  } catch (error) {
    if (!isUniqueConstraint(error)) throw error
    const mapped = conflict('An active Resource Server already uses this identifier or resource URL.')
    mapped.cause = error
    throw mapped
  }
}

function activeEquivalentEntitlement(input: ResourceScopeEntitlementRecord) {
  return and(
    input.userId ? eq(resourceScopeEntitlement.userId, input.userId) : isNull(resourceScopeEntitlement.userId),
    input.applicationId
      ? eq(resourceScopeEntitlement.applicationId, input.applicationId)
      : isNull(resourceScopeEntitlement.applicationId),
    input.agentIdentityId
      ? eq(resourceScopeEntitlement.agentIdentityId, input.agentIdentityId)
      : isNull(resourceScopeEntitlement.agentIdentityId),
    input.organizationId
      ? eq(resourceScopeEntitlement.organizationId, input.organizationId)
      : isNull(resourceScopeEntitlement.organizationId),
    eq(resourceScopeEntitlement.resourceServerId, input.resourceServerId),
    input.connectionId
      ? eq(resourceScopeEntitlement.connectionId, input.connectionId)
      : isNull(resourceScopeEntitlement.connectionId),
    or(
      eq(resourceScopeEntitlement.authorizationContextHash, input.authorizationContextHash),
      sql`${resourceScopeEntitlement.authorizationDetails} = ${JSON.stringify(input.authorizationDetails)}`,
    ),
    eq(resourceScopeEntitlement.scope, input.scope),
    isNull(resourceScopeEntitlement.endedAt),
  )
}

function strongerLifetime(
  current: ResourceScopeEntitlementRecord,
  requested: ResourceScopeEntitlementRecord,
): Pick<ResourceScopeEntitlementRecord, 'mode' | 'expiresAt'> | null {
  if (current.mode === 'persistent' || requested.mode === 'once') return null
  if (requested.mode === 'persistent') return { mode: 'persistent', expiresAt: null }
  if (current.mode === 'once') return { mode: 'until', expiresAt: requested.expiresAt }
  return requested.expiresAt!.getTime() > current.expiresAt!.getTime()
    ? { mode: 'until', expiresAt: requested.expiresAt }
    : null
}

function decodePermissionScopes(permission: Record<string, string[]>) {
  return (permission.scope ?? []).flatMap((value) => {
    const separator = value.indexOf('/')
    if (separator < 1 || separator === value.length - 1) return []
    try {
      return [
        {
          resourceId: decodeURIComponent(value.slice(0, separator)),
          scope: decodeURIComponent(value.slice(separator + 1)),
        },
      ]
    } catch {
      return []
    }
  })
}

function auditSelect(audit: import('@server/usecases/ports').AgentAuditEventRecord, metadata: Record<string, unknown>) {
  return {
    id: sql<string>`${audit.id}`.as('id'),
    action: sql<string>`${audit.action}`.as('action'),
    result: sql<string>`${audit.result}`.as('result'),
    realmOwned: sql<boolean>`${audit.realmOwned}`.as('realm_owned'),
    ownerUserId: sql<string | null>`${audit.ownerUserId}`.as('owner_user_id'),
    ownerOrganizationId: sql<string | null>`${audit.ownerOrganizationId}`.as('owner_organization_id'),
    controllerUserId: sql<string | null>`${audit.controllerUserId}`.as('controller_user_id'),
    subjectIssuer: sql<string | null>`${audit.subjectIssuer}`.as('subject_issuer'),
    subject: sql<string | null>`${audit.subject}`.as('subject'),
    agentIdentityId: sql<string | null>`${audit.agentIdentityId}`.as('agent_identity_id'),
    hostId: sql<string | null>`${audit.hostId}`.as('host_id'),
    resourceId: sql<string | null>`${audit.resourceId}`.as('resource_id'),
    resourceConnectionId: sql<string | null>`${audit.resourceConnectionId}`.as('resource_connection_id'),
    accessRequestId: sql<string | null>`${audit.accessRequestId}`.as('access_request_id'),
    scopes: sql<string[] | null>`${audit.scopes === null ? null : JSON.stringify(audit.scopes)}`.as('scopes'),
    reasonCode: sql<string | null>`${audit.reasonCode}`.as('reason_code'),
    metadata: sql<Record<string, unknown>>`${JSON.stringify({ ...audit.metadata, ...metadata })}`.as('metadata'),
    occurredAt: sql<Date>`${audit.occurredAt.getTime()}`.as('occurred_at'),
  }
}

async function totalRows(
  db: Database,
  table: Parameters<ReturnType<Database['select']>['from']>[0],
  where?: ReturnType<typeof eq> | ReturnType<typeof and>,
) {
  const query = db.select({ total: count() }).from(table)
  const rows = where ? await query.where(where) : await query
  return rows[0]?.total ?? 0
}
