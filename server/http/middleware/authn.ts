import { ApiError, forbidden, unauthorized } from '@server/domain/errors'
import type { MutationActor } from '@server/domain/mutation-actor'
import type { ProtocolAgentSession } from '@server/usecases/agent-session'
import type { Deps } from '@server/usecases/deps'
import { validateDpopResourceProof } from '@server/usecases/dpop'
import type { AgentIdentityBindingRecord, AgentIdentityRecord } from '@server/usecases/ports'
import {
  type RealmrootAgentBindingClaim,
  realmrootCliClientId,
  realmrootOrganizationClaim,
} from '@shared/oauth-token-profile'
import type { Context, MiddlewareHandler } from 'hono'
import { readRealmrootAgentBinding } from '../agent-token-claims'
import { toBoundaryError } from '../routes/auth-api'

export interface AuthUser {
  id: string
  email?: string
  name?: string | null
  username?: string | null
  image?: string | null
  role?: string | null
}

export interface AuthSession {
  id: string
  activeOrganizationId?: string | null
}

export interface AuthSessionResult {
  session: AuthSession
  user?: AuthUser
}

export interface PrincipalContext {
  session: AuthSessionResult | null
  user: AuthUser | null
  application?: {
    id: string
    clientId: string
    ownerOrganizationId: string
    delegatedOrganizationId?: string | null
    scopes: string[]
  } | null
  agent?: {
    issuer: string
    subject: string
    identityId: string
    protocolAgentId: string
    hostId: string
    runtime?: string
    sessionId?: string
    identity: AgentIdentityRecord
    binding: AgentIdentityBindingRecord
    scopes: string[]
    authority: { kind: 'organization'; organizationId: string } | { kind: 'user'; userId: string } | null
  } | null
}

export interface SessionReader {
  api: {
    getSession: (context: { headers: Headers; asResponse: false }) => Promise<AuthSessionResult | null>
    getAgentSession?: (context: { headers: Headers; asResponse: false }) => Promise<ProtocolAgentSession | null>
    verifyJWT?: (context: {
      body: { token: string; issuer?: string; audience?: string | string[] }
      asResponse?: false
    }) => Promise<{ payload: Record<string, unknown> | null }>
  }
}

declare module 'hono' {
  interface ContextVariableMap {
    principal: PrincipalContext
  }
}

interface AuthnOptions {
  allowAgent?: boolean
  allowApplication?: boolean
  oauth?: {
    issuer(requestUrl: string): string
    audience(requestUrl: string): string
    resourceRequestUrl(requestUrl: string): string
  }
  required?: boolean
}

export function authn(auth: SessionReader, options: AuthnOptions = {}): MiddlewareHandler {
  return async (c, next) => {
    const current = c.get('principal')
    const explicitAuthorization = c.req.header('Authorization')
    if (explicitAuthorization && !options.oauth) {
      await next()
      return
    }
    if (explicitAuthorization && options.oauth) {
      if (explicitAuthorization.startsWith('DPoP ') && options.allowAgent) {
        const agent = current?.agent ?? (await authenticateOAuthAgent(auth, c, options.oauth))
        if (agent) {
          c.set('principal', { session: null, user: null, application: null, agent })
          await next()
          return
        }
      }
      if (explicitAuthorization.startsWith('Bearer ') && options.allowApplication) {
        const applicationPrincipal = current?.application
          ? { application: current.application, user: current.user ?? null }
          : await authenticateOAuthApplication(auth, c, options.oauth)
        if (applicationPrincipal) {
          c.set('principal', {
            session: null,
            user: applicationPrincipal.user,
            application: applicationPrincipal.application,
            agent: null,
          })
          await next()
          return
        }
      }
      throw unauthorized('OAuth access token is not valid for this resource.')
    }
    const session =
      current?.session === undefined
        ? await auth.api.getSession({ headers: c.req.raw.headers, asResponse: false })
        : current.session
    const user = current?.user === undefined ? (session?.user ?? null) : current.user

    if (user) {
      c.set('principal', { session, user, application: null, agent: null })
      await next()
      return
    }

    if (options.allowAgent) {
      const agent =
        current?.agent ??
        (options.oauth ? await authenticateOAuthAgent(auth, c, options.oauth) : await authenticateAgent(auth, c))
      if (agent) {
        c.set('principal', { session: null, user: null, application: null, agent })
        await next()
        return
      }
    }

    if (options.allowApplication && options.oauth) {
      const applicationPrincipal = current?.application
        ? { application: current.application, user: current.user ?? null }
        : await authenticateOAuthApplication(auth, c, options.oauth)
      if (applicationPrincipal) {
        c.set('principal', {
          session: null,
          user: applicationPrincipal.user,
          application: applicationPrincipal.application,
          agent: null,
        })
        await next()
        return
      }
    }

    c.set('principal', { session, user: null, application: null, agent: null })
    if (options.required) throw unauthorized()
    await next()
  }
}

async function authenticateOAuthApplication(
  auth: SessionReader,
  c: Context,
  oauth: NonNullable<AuthnOptions['oauth']>,
): Promise<{
  application: NonNullable<PrincipalContext['application']>
  user: AuthUser | null
} | null> {
  const authorization = c.req.header('Authorization')
  if (!authorization?.startsWith('Bearer ')) return null
  if (!auth.api.verifyJWT) throw unauthorized('OAuth access-token verification is unavailable.')
  const accessToken = authorization.slice('Bearer '.length).trim()
  const issuer = oauth.issuer(c.req.url)
  const audience = oauth.audience(c.req.url)
  const verified = await auth.api
    .verifyJWT({ body: { token: accessToken, issuer, audience }, asResponse: false })
    .catch(() => null)
  const payload = verified?.payload
  if (!payload) throw unauthorized('OAuth access token is invalid.')
  const tokenSubject = stringClaim(payload, 'sub')
  const clientId = stringClaim(payload, 'client_id')
  if (clientId === realmrootCliClientId) return null
  if (!tokenSubject || !clientId) throw unauthorized('OAuth access token is missing its Application binding.')
  if (Object.hasOwn(payload, 'cnf')) {
    throw unauthorized('OAuth Application access tokens must be unbound Bearer tokens.')
  }
  const deps = c.get('deps') as Deps
  const application = await deps.applications.findByClientId(clientId)
  if (!application || application.disabled) {
    throw forbidden('The OAuth token does not belong to an active Application.')
  }
  const representedUser = tokenSubject === application.id ? null : await findRepresentedUser(deps, tokenSubject)
  if (representedUser?.banned) throw forbidden('The OAuth token does not represent an active User.')
  return {
    application: {
      id: application.id,
      clientId: application.clientId,
      ownerOrganizationId: application.ownerOrganizationId,
      delegatedOrganizationId: stringClaim(payload, realmrootOrganizationClaim),
      scopes: scopeClaim(payload),
    },
    user: representedUser
      ? {
          id: representedUser.id,
          email: representedUser.email,
          name: representedUser.displayName,
          username: representedUser.username,
          image: representedUser.image,
          role: representedUser.role,
        }
      : null,
  }
}

async function findRepresentedUser(deps: Deps, userId: string) {
  try {
    return await deps.users.getUser(userId)
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      throw forbidden('The OAuth token does not represent an active User.')
    }
    throw error
  }
}

async function authenticateOAuthAgent(
  auth: SessionReader,
  c: Context,
  oauth: NonNullable<AuthnOptions['oauth']>,
): Promise<NonNullable<PrincipalContext['agent']> | null> {
  const authorization = c.req.header('Authorization')
  if (!authorization?.startsWith('DPoP ')) return null
  if (!auth.api.verifyJWT) throw unauthorized('OAuth access-token verification is unavailable.')
  const accessToken = authorization.slice('DPoP '.length).trim()
  const issuer = oauth.issuer(c.req.url)
  const audience = oauth.audience(c.req.url)
  const verified = await auth.api
    .verifyJWT({ body: { token: accessToken, issuer, audience }, asResponse: false })
    .catch(() => null)
  const payload = verified?.payload
  if (!payload) throw unauthorized('OAuth access token is invalid.')
  const clientId = stringClaim(payload, 'client_id')
  if (!clientId) return null
  const legacyAgentToken = clientId !== realmrootCliClientId && stringClaim(payload, 'sub_profile') === 'ai_agent'
  if (clientId !== realmrootCliClientId && !legacyAgentToken) return null
  const tokenSubject = stringClaim(payload, 'sub')
  const confirmationJkt = objectStringClaim(payload, 'cnf', 'jkt')
  const proof = c.req.header('DPoP')
  if (!tokenSubject || !confirmationJkt || !proof) {
    throw unauthorized('OAuth access token is missing its Agent or DPoP binding.')
  }
  const deps = c.get('deps') as Deps
  const actorIssuer = objectStringClaim(payload, 'act', 'iss')
  const actorSubject = objectStringClaim(payload, 'act', 'sub')
  const agentBinding = (() => {
    try {
      return readRealmrootAgentBinding(payload)
    } catch {
      throw unauthorized('OAuth access token has an invalid Agent runtime session binding.')
    }
  })()
  const activeAgent = legacyAgentToken
    ? resolveLegacyAgentToken(deps, issuer, tokenSubject, clientId, stringClaim(payload, 'host_id'))
    : actorIssuer && actorSubject
      ? resolveResourceTokenAgent(deps, accessToken, issuer, tokenSubject, actorIssuer, actorSubject)
      : resolveBootstrapTokenAgent(deps, agentBinding, issuer, tokenSubject)
  const [active] = await Promise.all([
    activeAgent,
    validateDpopResourceProof(deps, {
      proof,
      accessToken,
      method: c.req.method,
      url: oauth.resourceRequestUrl(c.req.url),
      confirmationJkt,
    }).catch((error: unknown) => {
      throw unauthorized(error instanceof Error ? error.message : 'DPoP proof is invalid.')
    }),
  ])
  const scopes = typeof payload.scope === 'string' ? [...new Set(payload.scope.split(/\s+/).filter(Boolean))] : []
  const authority = authorityClaim(payload.realmroot_authority)
  return {
    issuer,
    subject: active.identity.subject,
    identityId: active.identity.id,
    protocolAgentId: active.binding.protocolAgentId,
    hostId: active.binding.hostId,
    runtime: agentBinding?.runtime,
    sessionId: agentBinding?.session_id,
    identity: active.identity,
    binding: active.binding,
    scopes,
    authority,
  }
}

async function resolveLegacyAgentToken(
  deps: Deps,
  issuer: string,
  subject: string,
  protocolAgentId: string,
  hostId: string | null,
) {
  if (!hostId) throw unauthorized('Legacy OAuth access token is missing its Agent Host binding.')
  const active = await deps.agentIdentities.findActiveBindingByProtocolAgent(protocolAgentId)
  if (
    !active ||
    active.binding.hostId !== hostId ||
    active.identity.issuer !== issuer ||
    active.identity.subject !== subject
  ) {
    throw unauthorized('The legacy OAuth token does not belong to an active Agent identity and Host binding.')
  }
  return active
}

async function resolveBootstrapTokenAgent(
  deps: Deps,
  binding: RealmrootAgentBindingClaim | null,
  issuer: string,
  subject: string,
) {
  if (!binding) throw unauthorized('OAuth bootstrap token is missing its Agent binding.')
  const protocolAgentId = binding.protocol_agent_id
  const hostId = binding.host_id
  const active = await deps.agentIdentities.findActiveBindingByProtocolAgent(protocolAgentId)
  if (
    !active ||
    active.binding.hostId !== hostId ||
    active.identity.issuer !== issuer ||
    active.identity.subject !== subject
  ) {
    throw unauthorized('The OAuth token does not belong to an active Agent identity and Host binding.')
  }
  return active
}

async function resolveResourceTokenAgent(
  deps: Deps,
  accessToken: string,
  issuer: string,
  ownerSubject: string,
  actorIssuer: string,
  actorSubject: string,
) {
  if (actorIssuer !== issuer) throw unauthorized('The OAuth actor issuer is invalid.')
  const [identity, lease] = await Promise.all([
    deps.agentIdentities.findByIssuerSubject(actorIssuer, actorSubject),
    deps.externalResources.findActiveTokenLeaseByTokenHash(await sha256(accessToken), new Date()),
  ])
  if (!identity || !lease || identity.ownerUserId !== ownerSubject) {
    throw unauthorized('The OAuth token does not belong to an active Agent resource grant.')
  }
  const aggregate = await deps.agentIdentities.findIdentity(identity.id)
  const binding = aggregate?.bindings.find(
    (candidate) => candidate.id === lease.bindingId && candidate.status === 'active' && !candidate.revokedAt,
  )
  if (!aggregate || aggregate.identity.status !== 'active' || !binding) {
    throw unauthorized('The OAuth token does not belong to an active Agent identity and Host binding.')
  }
  return { identity: aggregate.identity, binding }
}

async function authenticateAgent(
  auth: SessionReader,
  c: Context,
): Promise<NonNullable<PrincipalContext['agent']> | null> {
  if (!auth.api.getAgentSession) return null

  const session = await auth.api
    .getAgentSession({ headers: c.req.raw.headers, asResponse: false })
    .catch((error: unknown) => {
      throw toBoundaryError(error)
    })
  if (!session) return null

  const deps = c.get('deps') as Deps
  const active = await deps.agentIdentities.findActiveBindingByProtocolAgent(session.agent.id)
  if (!active || active.binding.hostId !== session.agent.hostId) {
    throw forbidden('The Agent host is not bound to an active Agent identity.')
  }

  return {
    issuer: active.identity.issuer,
    subject: active.identity.subject,
    identityId: active.identity.id,
    protocolAgentId: session.agent.id,
    hostId: session.agent.hostId,
    identity: active.identity,
    binding: active.binding,
    scopes: [],
    authority: null,
  }
}

function authorityClaim(value: unknown): NonNullable<PrincipalContext['agent']>['authority'] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const detail = value as Record<string, unknown>
  if (detail.type !== 'realmroot_authority' || typeof detail.id !== 'string') return null
  if (detail.authority === 'organization') return { kind: 'organization', organizationId: detail.id }
  if (detail.authority === 'user') return { kind: 'user', userId: detail.id }
  return null
}

function stringClaim(payload: Record<string, unknown>, name: string) {
  return typeof payload[name] === 'string' ? payload[name] : null
}

function objectStringClaim(payload: Record<string, unknown>, objectName: string, memberName: string) {
  const value = payload[objectName]
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const member = (value as Record<string, unknown>)[memberName]
  return typeof member === 'string' ? member : null
}

function scopeClaim(payload: Record<string, unknown>) {
  return typeof payload.scope === 'string' ? [...new Set(payload.scope.split(/\s+/).filter(Boolean))] : []
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return base64Url(new Uint8Array(digest))
}

function base64Url(value: Uint8Array) {
  return btoa(String.fromCharCode(...value))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '')
}

export function getPrincipal(c: Context): PrincipalContext {
  return c.get('principal') ?? { session: null, user: null, application: null, agent: null }
}

export function getActorUserId(c: Context): string | null {
  return getPrincipal(c).user?.id ?? null
}

export function getMutationActor(c: Context): MutationActor {
  const principal = getPrincipal(c)
  return {
    controllerUserId: principal.user?.id ?? null,
    agent: principal.agent
      ? {
          issuer: principal.agent.issuer,
          subject: principal.agent.subject,
          identityId: principal.agent.identityId,
          hostId: principal.agent.hostId,
        }
      : null,
  }
}

export function isAutomationPrincipal(c: Context) {
  return Boolean(getPrincipal(c).agent)
}
