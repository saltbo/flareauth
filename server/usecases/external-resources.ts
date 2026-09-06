import { connectorCapabilities } from '@server/domain/connectors/provider-templates'
import { type ResourceOAuthDriver, resourceOAuthDriver } from '@server/domain/connectors/resource-oauth-driver'
import {
  ApiError,
  badGateway,
  badRequest,
  conflict,
  forbidden,
  notFound,
  OAuthError,
  oauthError,
  unauthorized,
} from '@server/domain/errors'
import { isRealmrootResourceServer } from '@server/domain/realmroot-resource-server'
import type { Deps } from '@server/usecases/deps'
import type {
  AgentAccessRequestRecord,
  AgentIdentityBindingRecord,
  AgentIdentityRecord,
  ConnectorRecord,
  ExternalResourceAuthorizationRecord,
  ProviderCredentialRecord,
  ProviderResourceAuthorizationRecord,
  ResourceScopeEntitlementRecord,
} from '@server/usecases/ports'
import type {
  AccessRequest,
  AccessRequestApproval,
  AccountConnection,
  AgentPermission,
  CreateAccessRequest,
  CreateAccountConnection,
  CreateAgentPermission,
  ListAgentPermissionsQuery,
} from '@shared/api/agent-api'
import type { ApiResourceResponse, ResourceScopeRegistry } from '@shared/api/authorization'
import {
  type AuthorizationDetail,
  authorizationDetailCatalogSchema,
  authorizationDetailsSchema,
} from '@shared/api/authorization-details'
import type {
  CreateAgentAccessRequest,
  CreateResourceConnectionIntentRequest,
  DecideAgentAccessRequest,
} from '@shared/api/external-resources'
import { type PaginationInput, paginationMetadata, repositoryPageQuery } from '@shared/api/pagination'
import { agentBootstrapScopes, realmrootOAuthScopes } from '@shared/authz'
import {
  realmrootAgentBindingClaim,
  realmrootCliClientId,
  realmrootOrganizationClaim,
  toRealmrootAgentBindingClaim,
} from '@shared/oauth-token-profile'
import { realmrootManagementScopes } from '@shared/scope-registry'
import { refreshResourceScopeRegistry } from './authorization'
import { ensureDynamicConnectorScopes, refreshDynamicConnectorMetadata } from './connectors'
import { validateDpopTokenProof } from './dpop'
import { organizationUserHasScope } from './organization-membership-scopes'
import { validateRequestedScopes } from './resource-openapi'
import { resourceScopeEntitlementLifecycle, userEffectiveResourceScopes } from './resource-scope-entitlements'
import { activePublicResource, activeResourceVisibleToOrganization } from './resource-visibility'

const tokenExchangeGrantType = 'urn:ietf:params:oauth:grant-type:token-exchange'
const jwtBearerGrantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
const accessTokenType = 'urn:ietf:params:oauth:token-type:access_token'
const externalAuthorizationTimeoutMs = 5_000
export interface AgentResourcePrincipal {
  issuer: string
  subject: string
  identityId: string
  protocolAgentId: string
  hostId: string
  runtime?: string
  sessionId?: string
  identity: AgentIdentityRecord
  binding: AgentIdentityBindingRecord
}

export interface AgentAssertionSigner {
  issuer: string
  sign(payload: Record<string, unknown>, type: 'JWT' | 'at+jwt'): Promise<string>
}

type ResolvedExternalAuthorization = ExternalResourceAuthorizationRecord

export async function getExternalResourceAuthorization(deps: Deps, resourceId: string) {
  await requireExternalResource(deps, resourceId)
  const authorization = await findExternalAuthorization(deps, resourceId)
  if (!authorization) throw notFound('External API resource authorization was not found.')
  return toExternalAuthorization(authorization)
}

async function getApiResourceConfiguration(deps: Deps, resourceId: string) {
  const resource = await deps.authorization.findResource(resourceId)
  if (!resource) throw notFound('API resource was not found.')
  const authorization = await findExternalAuthorization(deps, resourceId)
  return {
    ...resource,
    authorization: authorization ? omitResourceId(toExternalAuthorization(authorization)) : null,
  }
}

export async function getApiResource(deps: Deps, resourceId: string, apiOrigin: string) {
  return toResourceServer(await getApiResourceConfiguration(deps, resourceId), apiOrigin, null)
}

export async function listApiResources(
  deps: Deps,
  pagination: PaginationInput,
  apiOrigin: string,
  ownerOrganizationIds?: string[],
) {
  const page = await deps.authorization.listResources(pagination, ownerOrganizationIds)
  return {
    items: await Promise.all(page.items.map((resource) => getApiResource(deps, resource.id, apiOrigin))),
    pagination: page.pagination,
  }
}

export async function createResourceConnectionIntent(
  deps: Deps,
  resourceId: string,
  input: CreateResourceConnectionIntentRequest,
  actorUserId: string,
  callbackOrigin: string,
  _signer?: AgentAssertionSigner,
) {
  const candidate = await deps.authorization.findResource(resourceId)
  if (!candidate) throw notFound('External API resource was not found.')
  if (!candidate.enabled) throw notFound('Enabled external API resource was not found.')
  const resource = await requireEnabledResource(deps, resourceId)
  if (!requiresAccountConnection(resource))
    throw badRequest('Realmroot-issued access does not use account connections.')
  if (!resource.connectorId) throw new Error('External authorization requires a Provider Connector.')
  await requireConnectionOwnerControl(deps, input.owner, actorUserId)
  const scopes = input.scopes
  validateRequestedScopes(resource.scopeRegistry, scopes)
  const currentAuthorization = await requireActiveConnectorAuthorization(deps, resourceId)
  const connector = await deps.connectors.findById(resource.connectorId)
  const driver = connector ? resourceOAuthDriver(connector) : null
  if (!connector || !driver) throw badRequest('Provider Connector does not support resource authorization.')
  const requestedScopes = driver.normalizeScopes([
    ...scopes,
    ...(currentAuthorization.authorizationDetailsCatalogScope
      ? [currentAuthorization.authorizationDetailsCatalogScope]
      : []),
  ])
  const clientGeneration = await ensureDynamicConnectorScopes(
    deps,
    resource.connectorId,
    requestedScopes,
    callbackOrigin,
  )
  const authorization = await requireActiveConnectorAuthorization(deps, resourceId, clientGeneration)
  const authorizationDetails = input.authorizationDetails ?? resource.authorizationDetails
  assertAuthorizationDetailsSupported(authorizationDetails, authorization, driver)
  const id = deps.ids.generate()
  const state = randomToken()
  const verifier = randomToken()
  const now = new Date()
  const redirectUri = resourceConnectionCallbackUrl(callbackOrigin)
  const authorizationParameters = {
    response_type: 'code',
    ...driver.authorizationParameters,
    client_id: authorization.clientId,
    redirect_uri: redirectUri,
    scope: requestedScopes.join(driver.scopeSeparator),
    state,
    code_challenge: await deps.oauthRequests.generateCodeChallenge(verifier),
    code_challenge_method: 'S256',
    resource: resource.resourceUrl,
    ...(driver.authorizationDetailsMode === 'provider' && authorizationDetails.length > 0
      ? { authorization_details: JSON.stringify(authorizationDetails) }
      : {}),
  }
  const expiresAt = new Date(now.getTime() + 10 * 60 * 1000)
  let authorizationUrl: string
  if (authorizationDetails.length > 0 && authorization.pushedAuthorizationRequestEndpoint) {
    const pushed = await postPushedAuthorizationRequest(
      deps,
      authorization.pushedAuthorizationRequestEndpoint!,
      authorizationParameters,
      authorization.clientId,
      authorizationClientSecret(authorization),
    )
    const requestUri = requiredString(pushed, 'request_uri', 'Pushed authorization response')
    requiredPositiveInteger(pushed, 'expires_in', 'Pushed authorization response')
    const url = new URL(authorization.authorizationEndpoint)
    url.searchParams.set('client_id', authorization.clientId)
    url.searchParams.set('request_uri', requestUri)
    authorizationUrl = url.toString()
  } else {
    const url = new URL(authorization.authorizationEndpoint)
    for (const [name, value] of Object.entries(authorizationParameters)) url.searchParams.set(name, value)
    authorizationUrl = url.toString()
  }
  const created = await deps.externalResources.createConnectionIntent({
    id,
    stateHash: await sha256(state),
    resourceId,
    ownerUserId: input.owner.type === 'user' ? actorUserId : null,
    ownerOrganizationId: input.owner.type === 'organization' ? input.owner.organizationId : null,
    initiatedByUserId: actorUserId,
    scopes: requestedScopes,
    authorizationDetails,
    encryptedPkceVerifier: await deps.secrets.seal(verifier, connectionIntentContext(id)),
    clientGeneration,
    returnTo: input.returnTo ?? 'account-center',
    status: 'pending',
    expiresAt,
    completedAt: null,
    createdAt: now,
    updatedAt: now,
  })
  if (!created) throw notFound('Enabled external API resource was not found.')
  return {
    id,
    resourceId,
    owner:
      input.owner.type === 'organization'
        ? { type: 'organization' as const, organizationId: input.owner.organizationId }
        : { type: 'user' as const, userId: actorUserId },
    authorizationUrl,
    authorizationDetails,
    expiresAt: expiresAt.toISOString(),
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  }
}

export async function completeResourceConnectionIntent(
  deps: Deps,
  input: { state: string; code: string },
  callbackOrigin: string,
) {
  const now = new Date()
  const intent = await deps.externalResources.consumeConnectionIntent(await sha256(input.state), now)
  if (!intent) throw badRequest('Resource connection state is invalid, expired, or already used.')
  const authorization = await requireActiveConnectorAuthorization(deps, intent.resourceId, intent.clientGeneration ?? 1)
  const connector = await deps.connectors.findById(authorization.connectorId)
  const driver = connector ? resourceOAuthDriver(connector) : null
  if (!driver) throw badRequest('Provider Connector no longer supports resource authorization.')
  const clientSecret = authorizationClientSecret(authorization)
  const verifier = await deps.secrets.open(intent.encryptedPkceVerifier, connectionIntentContext(intent.id))
  const codeRequest = await deps.oauthRequests.createAuthorizationCodeRequest({
    code: input.code,
    codeVerifier: verifier,
    redirectUri: resourceConnectionCallbackUrl(callbackOrigin),
    clientId: authorization.clientId,
    clientSecret,
    authentication: driver.tokenEndpointAuthentication,
  })
  const token = await postForm(
    deps,
    authorization.tokenEndpoint,
    codeRequest.body,
    authorization.clientId,
    clientSecret,
    new Headers(codeRequest.headers),
    false,
    driver.tokenEndpointAuthentication,
  )
  const accessToken = requiredString(token, 'access_token', 'OAuth token response')
  const refreshToken = requiredString(token, 'refresh_token', 'OAuth token response')
  const profileResponse = await deps.externalHttp.fetch(driver.profileRequest(accessToken))
  if (!profileResponse.ok) throw badRequest('Provider connection identity request failed.')
  const profile = driver.parseProfile(await readObject(profileResponse, 'Provider connection identity is invalid.'))
  const { externalSubject, displayName } = profile
  const authorizationDetails =
    driver.authorizationDetails?.(profile) ??
    readAuthorizationDetails(
      token.authorization_details,
      intent.authorizationDetails.length > 0,
      intent.authorizationDetails.map((detail) => detail.type),
      'OAuth token response',
    )
  const resource = await requireEnabledResource(deps, intent.resourceId)
  assertProviderConnectionAuthorizationDetails(
    resource.authorizationDetails,
    intent.authorizationDetails,
    authorizationDetails,
  )
  const expiresAt = tokenExpiry(token, now)
  const provider = await ensureProviderConnection(deps, resource, intent, externalSubject, displayName, now)
  const existing = await deps.externalResources.findConnectionByProviderResource({
    providerConnectionId: provider.id,
    resourceId: intent.resourceId,
  })
  const connectionId = existing?.id ?? intent.id
  const existingCredential = existing?.credentials[0]
  const credentialId = existingCredential?.id ?? deps.ids.generate()
  const grantedScopes = scopeString(token.scope) ?? intent.scopes
  const credentialInput = {
    id: credentialId,
    encryptedTokens: await deps.secrets.seal(
      JSON.stringify({ accessToken, refreshToken, scope: grantedScopes.join(' ') }),
      providerCredentialTokensContext(credentialId, connectionId),
    ),
    grantedScopes,
    authorizationDetails,
    clientGeneration: intent.clientGeneration ?? 1,
    credentialVersion: (existingCredential?.credentialVersion ?? 0) + 1,
    refreshClaimId: null,
    refreshClaimExpiresAt: null,
    status: 'active' as const,
    credentialExpiresAt: expiresAt,
    revokedAt: null,
    createdAt: existingCredential?.createdAt ?? now,
    updatedAt: now,
  }
  const connection = existing
    ? await deps.externalResources.upsertProviderCredential(existing.id, credentialInput)
    : await deps.externalResources.createResourceAuthorization({
        id: connectionId,
        providerConnectionId: provider.id,
        resourceId: intent.resourceId,
        credentials: [{ ...credentialInput, providerResourceAuthorizationId: connectionId }],
        status: 'active',
        revokedAt: null,
        createdAt: now,
        updatedAt: now,
      })
  if (!connection) throw badRequest('The API resource was deleted while completing the connection.')
  if (existing) {
    await revokeUncoveredEntitlements(
      deps,
      connection,
      intent.authorizationDetails.length > 0,
      intent.initiatedByUserId,
      now,
    )
  }
  return {
    ...toResourceConnection(connection),
    returnTo: intent.returnTo,
  }
}

async function ensureProviderConnection(
  deps: Deps,
  resource: ApiResourceResponse,
  intent: import('@server/usecases/ports').ResourceConnectionIntentRecord,
  externalSubject: string,
  displayName: string,
  now: Date,
) {
  const connectorId = resource.connectorId
  if (!connectorId) throw badRequest('API resource no longer has a Provider Connector.')
  const connector = await deps.connectors.findById(connectorId)
  if (!connector) throw badRequest('API resource no longer has a Provider Connector.')
  const claimedIdentity = await deps.externalResources.findActiveUserProviderConnectionByProviderSubject({
    providerId: connector.providerId,
    externalSubject,
  })
  if (claimedIdentity && claimedIdentity.ownerUserId !== intent.ownerUserId) {
    throw conflict('This Provider account is already connected to another Realmroot account.')
  }
  const existing = await deps.externalResources.findProviderConnectionByOwnerConnector({
    connectorId,
    ownerUserId: intent.ownerUserId,
    ownerOrganizationId: intent.ownerOrganizationId,
  })
  if (existing?.status === 'active' && existing.externalSubject !== externalSubject) {
    throw conflict('Disconnect the current Provider account before connecting another account.')
  }
  return deps.externalResources.upsertProviderConnection({
    id: existing?.id ?? deps.ids.generate(),
    connectorId,
    ownerUserId: intent.ownerUserId,
    ownerOrganizationId: intent.ownerOrganizationId,
    authenticationAccountId: existing?.authenticationAccountId ?? null,
    externalSubject,
    displayName,
    status: 'active',
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  })
}

export async function failResourceConnectionIntent(deps: Deps, state: string) {
  const intent = await deps.externalResources.consumeConnectionIntent(await sha256(state), new Date())
  if (!intent) throw badRequest('Resource connection state is invalid, expired, or already used.')
  return { returnTo: intent.returnTo }
}

export async function listResourceConnections(deps: Deps, actorUserId: string) {
  const connections = await deps.externalResources.listConnectionsByUser(actorUserId)
  return { items: connections.map(toResourceConnection) }
}

export async function createAccountConnection(
  deps: Deps,
  input: CreateAccountConnection,
  actorUserId: string,
  callbackOrigin: string,
  signer?: AgentAssertionSigner,
): Promise<AccountConnection> {
  if (input.context === 'access-request') {
    const request = await requirePendingAccessRequestByToken(deps, input.approvalToken)
    if (request.id !== input.accessRequestId) throw notFound('Agent access request was not found.')
    const controlledConnection = await requireControlledRequestTarget(deps, request, actorUserId)
    const resource = await requireEnabledResource(deps, request.resourceId)
    if (!requiresAccountConnection(resource)) {
      throw badRequest('Native API resources do not use account connections.')
    }
    const identity = await deps.agentIdentities.findIdentity(request.agentIdentityId)
    if (!identity) throw notFound('Active Agent identity was not found.')
    const owner = { type: 'user' as const }
    const ownerConnection = await deps.externalResources.findConnectionByOwnerResource({
      resourceId: request.resourceId,
      ownerUserId: identity.identity.ownerUserId,
      ownerOrganizationId: null,
    })
    const connectionScopes = expandedConnectionScopes(
      controlledConnection ?? ownerConnection,
      request.scopes,
      resource.scopeRegistry,
    )
    const pending = await createResourceConnectionIntent(
      deps,
      request.resourceId,
      {
        owner,
        scopes: connectionScopes,
        authorizationDetails: request.authorizationDetails.length > 0 ? request.authorizationDetails : undefined,
        returnTo: 'access-approval',
      },
      actorUserId,
      callbackOrigin,
      signer,
    )
    return toPendingAccountConnection(pending, connectionScopes)
  }
  const pending = await createResourceConnectionIntent(
    deps,
    input.apiResourceId,
    { owner: input.owner, scopes: input.scopes, returnTo: 'account-center' },
    actorUserId,
    callbackOrigin,
    signer,
  )
  return toPendingAccountConnection(pending, input.scopes)
}

function expandedConnectionScopes(
  connection: ProviderResourceAuthorizationRecord | null,
  requestedScopes: string[],
  scopeRegistry: ResourceScopeRegistry | null,
) {
  const declaredScopes = new Set(scopeRegistry?.scopes.map((scope) => scope.value) ?? [])
  const existingScopes =
    connection?.status === 'active' ? connection.grantedScopes.filter((scope) => declaredScopes.has(scope)) : []
  return [...new Set([...existingScopes, ...requestedScopes])].sort()
}

export async function listAccountConnections(deps: Deps, actorUserId: string, pagination: PaginationInput) {
  const connections = (await deps.externalResources.listConnectionsByUser(actorUserId)).map(toAccountConnection)
  return {
    items: connections.slice(pagination.offset, pagination.offset + pagination.limit),
    pagination: paginationMetadata({ ...pagination, total: connections.length }),
  }
}

export async function listAccessRequestConnections(
  deps: Deps,
  approvalToken: string,
  actorUserId: string,
  pagination: PaginationInput,
) {
  const request = await requirePendingAccessRequestByToken(deps, approvalToken)
  await requireControlledRequestTarget(deps, request, actorUserId)
  const resource = await requireEnabledResource(deps, request.resourceId)
  if (!requiresAccountConnection(resource)) {
    return { items: [], pagination: paginationMetadata({ ...pagination, total: 0 }) }
  }
  const identity = await deps.agentIdentities.findIdentity(request.agentIdentityId)
  if (!identity) throw notFound('Active Agent identity was not found.')
  const resourceConnections = (
    await deps.externalResources.listConnectionsByUser(identity.identity.ownerUserId)
  ).filter((connection) => connection.resourceId === request.resourceId && connection.status === 'active')
  const connections = await Promise.all(
    resourceConnections.map(async (connection) => {
      const accountConnection = toAccountConnection(connection)
      if (request.authorizationDetails.length === 0) return accountConnection
      const contextualScopes = await accountScopesForAuthorizationDetails(
        deps,
        resource,
        connection,
        request.agentIdentityId,
        request.authorizationDetails,
      )
      return contextualScopes === null ? accountConnection : { ...accountConnection, scopes: contextualScopes }
    }),
  )
  return {
    items: connections.slice(pagination.offset, pagination.offset + pagination.limit),
    pagination: paginationMetadata({ ...pagination, total: connections.length }),
  }
}

async function accountScopesForAuthorizationDetails(
  deps: Deps,
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  connection: ProviderResourceAuthorizationRecord,
  agentIdentityId: string,
  authorizationDetails: AuthorizationDetail[],
) {
  const requested = new Set(authorizationDetails.map(canonicalJson))
  const grantedByDetail = new Map<string, string[] | undefined>()
  for (let page = 1; ; page += 1) {
    const catalog = await readResourceCatalog(deps, resource, connection, agentIdentityId, {
      limit: 100,
      offset: (page - 1) * 100,
    })
    for (const item of catalog.items) {
      const key = canonicalJson(item.authorizationDetail)
      if (requested.has(key)) grantedByDetail.set(key, item.grantedScopes)
    }
    if (grantedByDetail.size === requested.size || catalog.pagination.page >= catalog.pagination.totalPages) break
  }
  if (grantedByDetail.size !== requested.size) return []
  const contextual = [...grantedByDetail.values()]
  if (contextual.some((scopes) => scopes === undefined)) return null
  const [first = [], ...rest] = contextual as string[][]
  return first.filter((scope) => rest.every((scopes) => scopes.includes(scope))).sort()
}

export async function getAccountConnection(
  deps: Deps,
  connectionId: string,
  actorUserId: string,
): Promise<AccountConnection> {
  return toAccountConnection(await requireControlledConnection(deps, connectionId, actorUserId))
}

export async function listConnectableExternalResources(deps: Deps) {
  const resources = (await deps.authorization.listEnabledResources()).filter(requiresAccountConnection)
  const connectable = []
  for (const resource of resources) {
    const authorization = await findExternalAuthorization(deps, resource.id)
    if (authorization?.status !== 'active') continue
    connectable.push({
      id: resource.id,
      identifier: resource.identifier,
      name: resource.name,
      resourceUrl: authorization.resourceUrl,
    })
  }
  return { items: connectable }
}

export async function listAccountProviderConnectors(deps: Deps, pagination: PaginationInput) {
  const connectors = await deps.connectors.listEnabled()
  const resources = await deps.authorization.listEnabledResources()
  const items = connectors.map((connector) => providerConnectorProjection(connector, resources))
  return {
    items: items.slice(pagination.offset, pagination.offset + pagination.limit),
    pagination: paginationMetadata({ ...pagination, total: items.length }),
  }
}

export async function listAccountProviderConnections(deps: Deps, actorUserId: string, pagination: PaginationInput) {
  const connections = await deps.externalResources.listProviderConnectionsByUser(actorUserId)
  const resources = await deps.authorization.listEnabledResources()
  const items = connections.map((connection) => {
    const connector = providerConnectorProjection(connection.connector, resources)
    return {
      id: connection.id,
      connector,
      displayName: connection.displayName,
      externalSubject: connection.externalSubject,
      capabilities: {
        signIn: {
          available: connector.capabilities.signIn.available,
          active: connection.authenticationAccountId !== null,
        },
        agentAccess: {
          available: connector.capabilities.agentAccess.available,
          active: connection.resourceAuthorizationCount > 0,
          authorizationCount: connection.resourceAuthorizationCount,
          resourceNames: connection.resourceNames,
        },
      },
      createdAt: connection.createdAt.toISOString(),
      updatedAt: connection.updatedAt.toISOString(),
    }
  })
  return {
    items: items.slice(pagination.offset, pagination.offset + pagination.limit),
    pagination: paginationMetadata({ ...pagination, total: items.length }),
  }
}

function providerConnectorProjection(
  connector: import('@server/usecases/ports').ProviderConnectorSummary,
  resources: ApiResourceResponse[],
) {
  const driverCapabilities = connectorCapabilities(
    connector.providerType as import('@shared/api/connectors').ConnectorProviderType,
    connector.providerId,
  )
  const providerResources = resources.filter(
    (resource) =>
      resource.connectorId === connector.id && resource.authorizationModel === 'external' && resource.availableToAgents,
  )
  const providerAuthorizationAvailable = connector.resourceAuthorizationEnabled && providerResources.length > 0
  return {
    id: connector.id,
    slug: connector.slug,
    providerId: connector.providerId,
    providerType: connector.providerType,
    displayName: connector.displayName,
    capabilities: {
      signIn: { available: driverCapabilities.authentication && connector.authenticationEnabled },
      agentAccess: { available: providerResources.length > 0 },
      connection: {
        method: providerAuthorizationAvailable
          ? ('provider_authorization' as const)
          : connector.authenticationEnabled
            ? ('sign_in' as const)
            : null,
      },
    },
  }
}

export async function createProviderConnectionIntent(
  deps: Deps,
  connectorId: string,
  actorUserId: string,
  callbackOrigin: string,
  signer?: AgentAssertionSigner,
) {
  const connector = await deps.connectors.findById(connectorId)
  if (!connector?.enabled) throw notFound('Enabled Provider Connector was not found.')
  const resources = (await deps.authorization.listEnabledResources()).filter(
    (resource) => resource.connectorId === connectorId && resource.authorizationModel === 'external',
  )
  if (resources.length === 0) throw badRequest('Provider Connector does not support direct account connection.')
  if (resources.length > 1) {
    throw badRequest('Provider Connector has more than one account connection authority.')
  }
  const resource = resources[0]!
  const scopes = resource.scopeRegistry?.scopes.map((scope) => scope.value) ?? []
  if (scopes.length === 0) throw badRequest('Provider account connection authority does not declare any scopes.')
  const intent = await createResourceConnectionIntent(
    deps,
    resource.id,
    { owner: { type: 'user' }, scopes, returnTo: 'account-center' },
    actorUserId,
    callbackOrigin,
    signer,
  )
  return {
    id: intent.id,
    connectorId,
    authorizationUrl: intent.authorizationUrl,
    expiresAt: intent.expiresAt,
    createdAt: intent.createdAt,
  }
}

export async function disconnectProviderConnection(
  deps: Deps,
  connectionId: string,
  actorUserId: string,
  _signer?: AgentAssertionSigner,
) {
  const connection = await deps.externalResources.findProviderConnection(connectionId)
  if (!connection || connection.ownerUserId !== actorUserId) throw notFound('Provider Connection was not found.')
  if (connection.authenticationAccountId) {
    const accounts = await deps.users.listLinkedAccounts(actorUserId, { limit: 2, offset: 0 })
    if (accounts.total <= 1) throw badRequest('Add another sign-in method before disconnecting this Provider.')
  }
  const authorizations = (await deps.externalResources.listConnectionsByUser(actorUserId)).filter(
    (authorization) => authorization.providerConnectionId === connectionId && authorization.status === 'active',
  )
  for (const authorization of authorizations) await revokeResourceConnection(deps, authorization.id, actorUserId)
  if (!(await deps.externalResources.revokeProviderConnection(connectionId, actorUserId, new Date()))) {
    throw badRequest('Provider Connection is already disconnected.')
  }
}

export async function revokeResourceConnection(deps: Deps, connectionId: string, actorUserId: string) {
  const connection = await requireControlledConnection(deps, connectionId, actorUserId)
  await revokeRealmrootCustodiedProviderAuthorization(deps, connection)
  const entitlements = await deps.externalResources.listActiveEntitlementsByConnection(connection.id, new Date())
  for (const entitlement of entitlements) await revokeAgentPermission(deps, entitlement.id, actorUserId)
  if (!(await deps.externalResources.revokeConnection(connectionId, new Date()))) {
    throw badRequest('Resource account connection is already revoked.')
  }
}

async function revokeRealmrootCustodiedProviderAuthorization(
  deps: Deps,
  connection: ProviderResourceAuthorizationRecord,
) {
  const credentials = activeProviderCredentials(connection)
  if (credentials.length === 0) return
  const resource = await deps.authorization.findResource(connection.resourceId)
  if (!resource) throw notFound('Resource Server was not found.')
  for (const credential of credentials) {
    const authorization = await connectorOAuthAuthorization(deps, resource, credential.clientGeneration)
    if (!authorization) throw badGateway('Provider authorization configuration is unavailable.')
    const payload = JSON.parse(
      await deps.secrets.open(
        credential.encryptedTokens,
        providerCredentialTokensContext(credential.id, credential.providerResourceAuthorizationId),
      ),
    ) as Record<string, unknown>
    const clientSecret = authorizationClientSecret(authorization)
    await postEmptyForm(
      deps,
      authorization.revocationEndpoint,
      {
        token: requiredString(payload, 'refreshToken', 'Stored resource connection'),
        token_type_hint: 'refresh_token',
      },
      authorization.clientId,
      clientSecret,
      authorization.revocationAuthentication,
    )
    if (authorization.revokeAccessToken) {
      await postEmptyForm(
        deps,
        authorization.revocationEndpoint,
        {
          token: requiredString(payload, 'accessToken', 'Stored resource connection'),
          token_type_hint: 'access_token',
        },
        authorization.clientId,
        clientSecret,
        authorization.revocationAuthentication,
      )
    }
  }
}

export async function discoverAgentResources(deps: Deps, principal: AgentResourcePrincipal) {
  const records = await discoverAgentResourceRecords(deps, principal)
  return { items: records.map((record) => record.summary) }
}

async function discoverAgentResourceRecords(deps: Deps, principal: AgentResourcePrincipal) {
  const identity = await requireActiveIdentityAndBinding(principal)
  const [visibleOrganizationIds, connections, configuredResources, connectors] = await Promise.all([
    activeIdentityOrganizationIds(deps, identity.identity),
    deps.externalResources.listConnectionsByUser(identity.identity.ownerUserId),
    deps.authorization.listEnabledResources(),
    deps.connectors.listEnabled(),
  ])
  const activeConnections = connections.filter((connection) => connection.status === 'active')
  const connectorsById = new Map(connectors.map((connector) => [connector.id, connector]))
  const records = await Promise.all(
    configuredResources.map(async (resource) => {
      const authorization = await resolveExternalAuthorization(
        deps,
        resource,
        resource.connectorId ? connectorsById.get(resource.connectorId) : undefined,
      )
      if (
        !resource.availableToAgents ||
        !activeResourceVisibleToAgent(resource, visibleOrganizationIds) ||
        (resource.authorizationModel === 'external' && authorization?.status !== 'active')
      ) {
        return null
      }
      const scopes = discoverAgentResourceScopes(resource)
      const connection = activeConnections.find((candidate) => candidate.resourceId === resource.id) ?? null
      return {
        resource,
        authorization,
        summary: {
          id: resource.id,
          identifier: resource.identifier,
          name: resource.name,
          description: resource.description,
          availability: {
            status: scopes ? ('available' as const) : ('unavailable' as const),
            checkedAt: new Date().toISOString(),
          },
          scopes: scopes ?? [],
          resourcesAvailable:
            !requiresAccountConnection(resource) ||
            Boolean(
              connection &&
                (authorization?.authorizationDetailsCatalogEndpoint || connection.authorizationDetails.length > 0),
            ),
          connection: !requiresAccountConnection(resource)
            ? { status: 'not_required' as const, displayName: null, authorizedScopes: [] }
            : connection
              ? {
                  status: 'connected' as const,
                  displayName: connection.displayName,
                  authorizedScopes: connection.grantedScopes.filter(
                    (scope) =>
                      scope !== 'openid' &&
                      scope !== 'offline_access' &&
                      scope !== authorization?.authorizationDetailsCatalogScope &&
                      resource.scopeRegistry?.scopes.some((declared) => declared.value === scope),
                  ),
                }
              : { status: 'not_connected' as const, displayName: null, authorizedScopes: [] },
        },
      }
    }),
  )
  return records.filter((record) => record !== null)
}

function discoverAgentResourceScopes(
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
) {
  if (isRealmrootResourceServer(resource)) {
    return realmrootOAuthScopes.map((value) => ({ value, description: null }))
  }
  return resource.scopeRegistry?.scopes.map(({ value, description }) => ({ value, description })) ?? null
}

function validateResourceRequestedScopes(
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  scopes: string[],
) {
  if (isRealmrootResourceServer(resource)) {
    if (scopes.some((scope) => !realmrootOAuthScopes.includes(scope as (typeof realmrootOAuthScopes)[number]))) {
      throw badRequest('Requested scope is not declared by the Realmroot scope registry.')
    }
    return
  }
  validateRequestedScopes(resource.scopeRegistry, scopes)
}

export async function listAgentResourceServers(
  deps: Deps,
  principal: AgentResourcePrincipal,
  pagination: PaginationInput,
  apiOrigin: string,
) {
  const origin = apiOrigin.replace(/\/$/, '')
  const resources = (await discoverAgentResourceRecords(deps, principal)).map(({ resource, authorization, summary }) =>
    toResourceServer(
      { ...resource, authorization: authorization ? omitResourceId(toExternalAuthorization(authorization)) : null },
      origin,
      summary.connection,
    ),
  )
  return {
    items: resources.slice(pagination.offset, pagination.offset + pagination.limit),
    pagination: paginationMetadata({ ...pagination, total: resources.length }),
  }
}

export async function getAgentResourceServer(
  deps: Deps,
  resourceServerId: string,
  principal: AgentResourcePrincipal,
  apiOrigin: string,
) {
  const record = (await discoverAgentResourceRecords(deps, principal)).find(
    (candidate) => candidate.resource.id === resourceServerId,
  )
  if (!record) throw notFound('Resource Server was not found.')
  return toResourceServer(
    {
      ...record.resource,
      authorization: record.authorization ? omitResourceId(toExternalAuthorization(record.authorization)) : null,
    },
    apiOrigin.replace(/\/$/, ''),
    record.summary.connection,
  )
}

export async function listAgentResourceServerAuthorizationDetails(
  deps: Deps,
  resourceServerId: string,
  principal: AgentResourcePrincipal,
  pagination: PaginationInput,
) {
  const identity = await requireActiveIdentityAndBinding(principal)
  const { resource, authorization } = await requireEnabledResourceConfiguration(deps, resourceServerId)
  await requireAgentResourceVisibility(deps, resource, identity.identity)
  if (!requiresAccountConnection(resource)) {
    const items = await nativeAuthorityDetailsCatalog(deps, identity, principal.identityId, resource)
    return {
      items: items.slice(pagination.offset, pagination.offset + pagination.limit),
      pagination: paginationMetadata({ ...pagination, total: items.length }),
    }
  }
  const connection = await deps.externalResources.findConnectionByOwnerResource({
    resourceId: resourceServerId,
    ownerUserId: identity.identity.ownerUserId,
    ownerOrganizationId: null,
  })
  if (!connection || connection.status !== 'active') {
    return { items: [], pagination: paginationMetadata({ ...pagination, total: 0 }) }
  }
  const fallbackAuthorization = await serviceResourceFallbackAuthorization(deps, resource, connection)
  if (fallbackAuthorization) {
    return { items: [], pagination: paginationMetadata({ ...pagination, total: 0 }) }
  }
  const catalog = await readResourceCatalog(deps, resource, connection, principal.identityId, pagination, authorization)
  return {
    items: catalog.items.map(toResourceServerAuthorizationDetail),
    pagination: catalog.pagination,
  }
}

export async function listAccountAccessRequestAuthorizationDetailCatalog(
  deps: Deps,
  requestId: string,
  approvalToken: string,
  actorUserId: string,
  pagination: PaginationInput,
) {
  const request = await requirePendingAccessRequestByToken(deps, approvalToken)
  if (request.id !== requestId) throw notFound('Agent access request was not found.')
  const controlledConnection = await requireControlledRequestTarget(deps, request, actorUserId)
  const identity = await deps.agentIdentities.findIdentity(request.agentIdentityId)
  if (!identity) throw notFound('Active Agent identity was not found.')
  const resource = await requireEnabledResource(deps, request.resourceId)
  if (!requiresAccountConnection(resource)) {
    throw badRequest('Native API resources do not have authorization detail catalogs.')
  }
  const connection =
    controlledConnection ??
    (await deps.externalResources.findConnectionByOwnerResource({
      resourceId: request.resourceId,
      ownerUserId: identity.identity.ownerUserId,
      ownerOrganizationId: null,
    }))
  if (!connection || connection.status !== 'active') {
    throw notFound('Active resource account connection was not found.')
  }
  return readResourceCatalog(deps, resource, connection, request.agentIdentityId, pagination)
}

export async function createAgentAccessRequest(
  deps: Deps,
  input: CreateAgentAccessRequest,
  principal: AgentResourcePrincipal,
  approvalOrigin: string,
) {
  const identity = await requireActiveIdentityAndBinding(principal)
  let resource = await requireEnabledResource(deps, input.resourceId)
  await requireAgentResourceVisibility(deps, resource, identity.identity)
  const connection = requiresAccountConnection(resource)
    ? await deps.externalResources.findConnectionByOwnerResource({
        resourceId: resource.id,
        ownerUserId: identity.identity.ownerUserId,
        ownerOrganizationId: null,
      })
    : null
  if (!requiresAccountConnection(resource)) validateResourceRequestedScopes(resource, input.scopes)
  const authorizationDetails = accessRequestAuthorizationDetails(resource, input.authorizationDetails ?? [])
  const concreteAuthorizationDetails = authorizationDetails.filter(
    (detail) => !resource.authorizationDetails.some((template) => canonicalJson(template) === canonicalJson(detail)),
  )
  if (concreteAuthorizationDetails.length > 0) {
    await resolveRequestedAuthorizationDetails(
      deps,
      resource,
      connection?.status === 'active' ? connection : null,
      concreteAuthorizationDetails,
      identity,
    )
  }
  const scopes = [...new Set(input.scopes)].sort()
  const now = new Date()
  const reusableAccountScopes = requiresAccountConnection(resource)
    ? connection?.status === 'active'
      ? ((concreteAuthorizationDetails.length > 0
          ? await accountScopesForAuthorizationDetails(
              deps,
              resource,
              connection,
              principal.identityId,
              authorizationDetails,
            )
          : null) ?? connection.grantedScopes)
      : []
    : null
  const requiresAccountExpansion =
    reusableAccountScopes !== null && scopes.some((scope) => !reusableAccountScopes.includes(scope))
  if (requiresAccountExpansion) {
    if (resource.connectorId) {
      await refreshDynamicConnectorMetadata(deps, resource.connectorId)
      const connector = await deps.connectors.findById(resource.connectorId)
      const advertisedScopes = metadataStringArray(connector?.resourceProviderMetadata?.scopes_supported)
      if (advertisedScopes.length > 0 && scopes.some((scope) => !advertisedScopes.includes(scope))) {
        throw badRequest('Requested scope is not currently supported by the Resource Server.')
      }
    }
    const registeredScopes = new Set(resource.scopeRegistry?.scopes.map((scope) => scope.value) ?? [])
    if (scopes.some((scope) => !registeredScopes.has(scope))) {
      resource = await refreshResourceScopeRegistry(deps, resource.id)
      validateResourceRequestedScopes(resource, scopes)
    }
  } else {
    validateResourceRequestedScopes(resource, scopes)
  }
  const reusableEntitlements = (
    await deps.externalResources.listActiveEntitlementsByAgent(principal.identityId, now)
  ).filter(
    (entitlement) =>
      entitlement.connectionId === (connection?.id ?? null) &&
      entitlement.resourceServerId === resource.id &&
      (reusableAccountScopes === null || reusableAccountScopes.includes(entitlement.scope)) &&
      exactAuthorizationDetails(entitlement.authorizationDetails, authorizationDetails),
  )
  const approvedEntitlements = scopes.flatMap((scope) => {
    const entitlement = reusableEntitlements.find((candidate) => candidate.scope === scope)
    return entitlement ? [{ scope, entitlementId: entitlement.id }] : []
  })
  const alreadyAuthorized = approvedEntitlements.length === scopes.length
  if (!alreadyAuthorized && !requiresAccountConnection(resource)) {
    const grantorScopes = await nativeAuthorityEffectiveScopes(
      deps,
      identity.identity.ownerUserId,
      resource,
      authorizationDetails[0]!,
    )
    const missing = scopes.filter((scope) => !grantorScopes.includes(scope))
    if (missing.length > 0) {
      const authority = authorizationDetails[0]!
      throw new ApiError(
        400,
        'bad_request',
        `Controller cannot grant the following scopes in Context "${authority.id}" (${authority.authority}): ${missing.join(', ')}. No approval request was created.`,
        { context: { id: authority.id, type: authority.authority }, scopes: missing },
      )
    }
  }
  const automaticControllerUserId = automaticNativeControllerUserId(resource, identity.identity.ownerUserId, scopes)
  const binding = identity.bindings.find(
    (candidate) => candidate.hostId === principal.hostId && candidate.protocolAgentId === principal.protocolAgentId,
  )!
  if (!alreadyAuthorized) {
    const pending = (await deps.externalResources.listPendingAccessRequestsByAgent(principal.identityId, now)).find(
      (request) =>
        request.resourceId === resource.id &&
        request.connectionId === (connection?.id ?? null) &&
        exactScopes(request.scopes, scopes) &&
        exactAuthorizationDetails(request.authorizationDetails, authorizationDetails),
    )
    if (pending) {
      if (automaticControllerUserId) {
        return decideAgentAccessRequest(
          deps,
          pending.id,
          { decision: 'approve', mode: 'persistent', authorizationDetails },
          automaticControllerUserId,
          'automatic_scope_policy',
        )
      }
      const token = await deps.secrets.open(pending.encryptedApprovalToken, accessRequestTokenContext(pending.id))
      return toAgentAccessRequest(pending, principal.hostId, approvalUrl(approvalOrigin, token))
    }
  }
  const expiresAt = new Date(now.getTime() + 10 * 60 * 1000)
  const rawApprovalToken = randomToken()
  const requestId = deps.ids.generate()
  const request: AgentAccessRequestRecord = {
    id: requestId,
    resourceId: resource.id,
    connectionId: connection?.id ?? null,
    agentIdentityId: principal.identityId,
    bindingId: binding.id,
    scopes,
    authorizationDetails,
    reason: input.reason ?? null,
    status: alreadyAuthorized ? 'approved' : 'pending',
    approvalTokenHash: await sha256(rawApprovalToken),
    encryptedApprovalToken: await deps.secrets.seal(rawApprovalToken, accessRequestTokenContext(requestId)),
    approvedEntitlements: alreadyAuthorized ? approvedEntitlements : [],
    expiresAt,
    decidedAt: alreadyAuthorized ? now : null,
    createdAt: now,
    updatedAt: now,
  }
  const audit = await resourceAuditRecord(deps, {
    action: 'api_resource.access_requested',
    result: alreadyAuthorized ? 'allowed' : 'pending',
    principal,
    resourceId: resource.id,
    connection,
    accessRequestId: request.id,
    scopes,
    authorizationDetails,
    reasonCode: null,
  })
  const created = await deps.externalResources.createAccessRequestWithAudit(request, audit)
  if (!created) throw forbidden('Enabled Resource Server is required.')
  if (!alreadyAuthorized && automaticControllerUserId) {
    return decideAgentAccessRequest(
      deps,
      created.id,
      { decision: 'approve', mode: 'persistent', authorizationDetails },
      automaticControllerUserId,
      'automatic_scope_policy',
    )
  }
  return toAgentAccessRequest(
    created,
    principal.hostId,
    alreadyAuthorized ? null : approvalUrl(approvalOrigin, rawApprovalToken),
  )
}

function automaticNativeControllerUserId(
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  controllerUserId: string | null,
  scopes: string[],
) {
  if (!controllerUserId || requiresAccountConnection(resource)) return null
  const modes = new Map(resource.scopeRegistry?.scopes.map((scope) => [scope.value, scope.grantMode]) ?? [])
  return scopes.length > 0 && scopes.every((scope) => modes.get(scope) === 'automatic') ? controllerUserId : null
}

export async function createAccessRequest(
  deps: Deps,
  input: CreateAccessRequest,
  principal: AgentResourcePrincipal,
  approvalOrigin: string,
): Promise<AccessRequest> {
  const request = await createAgentAccessRequest(
    deps,
    {
      resourceId: input.resourceServerId,
      scopes: input.scopes,
      authorizationDetails: input.authorizationDetails,
      reason: input.reason,
    },
    principal,
    approvalOrigin,
  )
  return agentAccessRequestRepresentation(deps, request, approvalOrigin)
}

export async function getAgentAccessRequest(deps: Deps, requestId: string, principal: AgentResourcePrincipal) {
  await requireActiveIdentityAndBinding(principal)
  const request = await deps.externalResources.findAccessRequest(requestId)
  if (!request || request.agentIdentityId !== principal.identityId)
    throw notFound('Agent access request was not found.')
  return toAgentAccessRequest(request, principal.hostId, null)
}

export async function getAccessRequest(
  deps: Deps,
  requestId: string,
  principal: AgentResourcePrincipal,
  apiOrigin: string,
): Promise<AccessRequest> {
  return agentAccessRequestRepresentation(deps, await getAgentAccessRequest(deps, requestId, principal), apiOrigin)
}

export async function listControllerAccessRequests(deps: Deps, actorUserId: string) {
  const now = new Date()
  const memberships = await deps.authorization.listUserMemberships(actorUserId)
  const [userConnections, organizationConnections] = await Promise.all([
    deps.externalResources.listConnectionsByUser(actorUserId),
    deps.externalResources.listConnectionsByOrganizations([
      ...new Set(memberships.map((membership) => membership.organizationId)),
    ]),
  ])
  const connections = [...userConnections, ...organizationConnections]
  const connectionIds = new Set(connections.map((connection) => connection.id))
  const requests = (await deps.externalResources.listPendingAccessRequests(now)).filter(
    (request) => request.connectionId === null || connectionIds.has(request.connectionId),
  )
  const controlledRequests = []
  for (const request of requests) {
    if (request.connectionId || (await controlsAgentIdentity(deps, request.agentIdentityId, actorUserId))) {
      controlledRequests.push(request)
    }
  }
  return {
    requests: await Promise.all(
      controlledRequests.map(async (request) =>
        toAgentAccessRequest(request, await requestHostId(deps, request), null),
      ),
    ),
  }
}

export async function listAccountAccessRequests(deps: Deps, actorUserId: string, pagination: PaginationInput) {
  const requests = (await listControllerAccessRequests(deps, actorUserId)).requests.map((request) =>
    toAccessRequest(request),
  )
  return {
    items: await Promise.all(
      requests
        .slice(pagination.offset, pagination.offset + pagination.limit)
        .map((request) => resolveAccessRequestApproval(deps, request)),
    ),
    pagination: paginationMetadata({ ...pagination, total: requests.length }),
  }
}

export async function getAccountAccessRequest(
  deps: Deps,
  requestId: string,
  actorUserId: string,
  approvalToken?: string,
): Promise<AccessRequest> {
  const request = approvalToken
    ? await getControllerAccessRequestByToken(deps, approvalToken, actorUserId)
    : await requireControlledAccessRequest(deps, requestId, actorUserId)
  if (request.id !== requestId) throw notFound('Agent access request was not found.')
  return toAccessRequest(request)
}

export async function getAccountAccessRequestByToken(
  deps: Deps,
  approvalToken: string,
  actorUserId: string,
): Promise<AccessRequestApproval> {
  const request = toAccessRequest(await getControllerAccessRequestByToken(deps, approvalToken, actorUserId))
  return resolveAccessRequestApproval(deps, request)
}

async function resolveAccessRequestApproval(deps: Deps, request: AccessRequest): Promise<AccessRequestApproval> {
  const record = await deps.externalResources.findAccessRequest(request.id)
  if (!record) throw notFound('Agent access request was not found.')
  const [identity, resource] = await Promise.all([
    deps.agentIdentities.findIdentity(request.agentId),
    deps.authorization.findResource(record.resourceId),
  ])
  if (!identity) throw notFound('Agent identity was not found.')
  if (!resource) throw notFound('API resource was not found.')
  const authorizationDetail = await resolveApprovalAuthorizationDetail(deps, resource, record)
  return {
    ...request,
    authorizationDetails: record.authorizationDetails,
    requiresAccountConnection: requiresAccountConnection(resource),
    agent: { id: identity.identity.id, name: identity.identity.name },
    resourceServer: { id: resource.id, name: resource.name },
    authorizationDetail: authorizationDetail
      ? { ...authorizationDetail, authorizationDetailTemplates: resource.authorizationDetails }
      : null,
  }
}

async function resolveApprovalAuthorizationDetail(
  deps: Deps,
  resourceServer: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  request: AgentAccessRequestRecord,
) {
  const detail = request.authorizationDetails[0]
  if (!detail) return null
  if (!requiresAccountConnection(resourceServer)) {
    const display = await nativeAuthorityDisplay(deps, detail)
    return {
      name: display.label,
      description: display.description,
      metadata: display.metadata,
    }
  }
  if (resourceServer.authorizationDetails.some((template) => canonicalJson(template) === canonicalJson(detail))) {
    return null
  }
  if (!request.connectionId) return null
  const connection = await deps.externalResources.findConnection(request.connectionId)
  if (!connection || connection.status !== 'active') throw notFound('Active resource account connection was not found.')
  for (let page = 1; ; page += 1) {
    const catalog = await readResourceCatalog(deps, resourceServer, connection, request.agentIdentityId, {
      limit: 100,
      offset: (page - 1) * 100,
    })
    const match = catalog.items.find((item) => exactAuthorizationDetails([item.authorizationDetail], [detail]))
    if (match) {
      return {
        name: match.display.label,
        description: match.display.description ?? null,
        metadata: match.display.metadata ?? {},
      }
    }
    if (catalog.pagination.page >= catalog.pagination.totalPages) break
  }
  throw notFound('Authorization detail was not found.')
}

export async function getControllerAccessRequestByToken(deps: Deps, token: string, actorUserId: string) {
  const request = await requirePendingAccessRequestByToken(deps, token)
  await requireControlledRequestTarget(deps, request, actorUserId)
  return toAgentAccessRequest(request, await requestHostId(deps, request), null)
}

export async function decideAgentAccessRequestByToken(
  deps: Deps,
  token: string,
  input: DecideAgentAccessRequest,
  actorUserId: string,
) {
  const request = await requirePendingAccessRequestByToken(deps, token)
  return decideAgentAccessRequest(deps, request.id, input, actorUserId)
}

async function validateAgentPermissionTarget(
  deps: Deps,
  resource: ApiResourceResponse,
  input: { agentIdentityId: string; scopes: string[]; connectionId: string | null },
  authorizationDetails: AuthorizationDetail[],
  actorUserId: string,
) {
  validateResourceRequestedScopes(resource, input.scopes)
  const requestIdentity = await deps.agentIdentities.findIdentity(input.agentIdentityId)
  if (!requestIdentity || requestIdentity.identity.status !== 'active')
    throw notFound('Active Agent identity was not found.')
  await requireAgentResourceVisibility(deps, resource, requestIdentity.identity)
  if (!requiresAccountConnection(resource)) {
    await requireCurrentNativeAuthorityContext(deps, requestIdentity, authorizationDetails)
  }
  const grantorScopes = !requiresAccountConnection(resource)
    ? await nativeAuthorityEffectiveScopes(deps, actorUserId, resource, authorizationDetails[0]!)
    : await userEffectiveResourceScopes(deps, actorUserId, resource)
  assertScopeSubset(input.scopes, grantorScopes, 'controller effective scope')
  let connectionId = input.connectionId
  let connection: ProviderResourceAuthorizationRecord | null = null
  if (requiresAccountConnection(resource)) {
    connection = input.connectionId ? await requireControlledConnection(deps, input.connectionId, actorUserId) : null
    if (!connection) {
      const ownerConnection = await deps.externalResources.findConnectionByOwnerResource({
        resourceId: resource.id,
        ownerUserId: requestIdentity.identity.ownerUserId,
        ownerOrganizationId: null,
      })
      if (ownerConnection) {
        connection = await requireControlledConnection(deps, ownerConnection.id, actorUserId)
      }
    }
    if (!connection) throw badRequest('An account connection is required to approve external API access.')
    connectionId = connection.id
    if (connection.resourceId !== resource.id || connection.status !== 'active') {
      throw badRequest('The selected account connection does not belong to this API resource.')
    }
    assertConnectionInHomeSpace(connection, requestIdentity.identity.ownerUserId)
    assertAuthorizationDetailsSelection(resource, connection, authorizationDetails)
    assertAuthorizationDetailsSubset(authorizationDetails, connection.authorizationDetails, 'connected account')
    const contextualScopes =
      authorizationDetails.length > 0
        ? await accountScopesForAuthorizationDetails(
            deps,
            resource,
            connection,
            input.agentIdentityId,
            authorizationDetails,
          )
        : null
    assertScopeSubset(input.scopes, contextualScopes ?? connection.grantedScopes, 'connected account')
  } else if (connectionId) {
    throw badRequest('Native API resources do not use account connections.')
  } else {
    assertAuthorizationDetailsSelection(resource, null, authorizationDetails)
  }
  return { connection, connectionId }
}

export async function createAgentPermission(
  deps: Deps,
  agentId: string,
  input: CreateAgentPermission,
  actorUserId: string,
  organizationId: string | null = null,
) {
  if (!(await controlsAgentIdentity(deps, agentId, actorUserId)))
    throw forbidden('Agent controller access is required.')
  const resource = await deps.authorization.findResourceByResourceUrl(input.resource)
  if (!resource?.enabled) throw notFound('Enabled Resource Server was not found.')
  const scopes = [...new Set(input.scopes)]
  const now = new Date()
  const expiresAt = input.mode === 'until' ? new Date(input.expiresAt!) : null
  if (expiresAt && expiresAt.getTime() <= now.getTime()) throw badRequest('Permission expiry must be in the future.')
  const selections: AuthorizationDetail[][] = []
  let connectionId: string | null = null
  if (requiresAccountConnection(resource)) {
    const connection = await deps.externalResources.findConnectionByOwnerResource({
      resourceId: resource.id,
      ownerUserId: actorUserId,
      ownerOrganizationId: null,
    })
    if (!connection || connection.status !== 'active')
      throw badRequest('The controller must connect the external resource account before granting Agent permissions.')
    connectionId = connection.id
    if (resource.authorizationDetails.length === 0) {
      selections.push([])
    } else {
      for (let page = 1; ; page += 1) {
        const catalog = await readResourceCatalog(deps, resource, connection, agentId, {
          limit: 100,
          offset: (page - 1) * 100,
        })
        for (const item of catalog.items) selections.push([item.authorizationDetail])
        if (catalog.pagination.page >= catalog.pagination.totalPages) break
      }
      if (selections.length === 0) throw badRequest('The connected account has no available authorization Contexts.')
    }
  } else {
    selections.push([
      {
        type: 'realmroot_authority',
        authority: organizationId ? 'organization' : 'user',
        id: organizationId ?? actorUserId,
      },
    ])
  }
  // Resolve and validate every Context before writing any of this resource's grants.
  for (const details of selections) {
    await validateAgentPermissionTarget(
      deps,
      resource,
      {
        agentIdentityId: agentId,
        scopes,
        connectionId,
      },
      details,
      actorUserId,
    )
  }
  const permissions = []
  for (const authorizationDetails of selections) {
    const authorizationContextHash = await sha256(canonicalJson(authorizationDetails))
    for (const scope of scopes) {
      const entitlement = await deps.authorization.createScopeEntitlement(
        {
          id: deps.ids.generate(),
          userId: null,
          applicationId: null,
          agentIdentityId: agentId,
          organizationId: null,
          resourceServerId: resource.id,
          connectionId,
          authorizationDetails,
          authorizationContextHash,
          scope,
          mode: input.mode,
          grantedByUserId: actorUserId,
          grantedByAgentIdentityId: null,
          sourceAccessRequestId: null,
          expiresAt,
          endedAt: null,
          endReason: null,
          createdAt: now,
          updatedAt: now,
        },
        now,
      )
      permissions.push(toPermission(entitlement, resource))
    }
  }
  return permissions
}

export async function decideAgentAccessRequest(
  deps: Deps,
  requestId: string,
  input: DecideAgentAccessRequest,
  actorUserId: string,
  approvalReasonCode: string | null = null,
  retryEntitlementConflict = true,
) {
  const request = await deps.externalResources.findAccessRequest(requestId)
  if (!request || request.status !== 'pending' || request.expiresAt.getTime() <= Date.now()) {
    throw notFound('Pending Agent access request was not found.')
  }
  const controlledConnection = await requireControlledRequestTarget(deps, request, actorUserId)
  const now = new Date()
  if (input.decision === 'deny') {
    const audit = await resourceAuditRecord(deps, {
      action: 'api_resource.access_decided',
      result: 'denied',
      resourceId: request.resourceId,
      connection: controlledConnection,
      request,
      accessRequestId: request.id,
      controllerUserId: actorUserId,
      scopes: request.scopes,
      authorizationDetails: request.authorizationDetails,
      reasonCode: 'controller_denied',
    })
    const decided = await deps.externalResources.decideAccessRequestWithAudit(
      request.id,
      { status: 'denied', approvedEntitlements: [], decidedAt: now, updatedAt: now },
      audit,
    )
    if (!decided) throw badRequest('Agent access request was already decided.')
    return toAgentAccessRequest(decided, await requestHostId(deps, request), null)
  }

  const resource = await requireEnabledResource(deps, request.resourceId)
  const authorizationDetails = input.authorizationDetails ?? []
  if (!authorizationDetailsMatchRequest(authorizationDetails, request.authorizationDetails)) {
    throw invalidAuthorizationDetails('Approved authorization details do not match the pending access request.')
  }
  const { connection, connectionId } = await validateAgentPermissionTarget(
    deps,
    resource,
    {
      agentIdentityId: request.agentIdentityId,
      scopes: request.scopes,
      connectionId: request.connectionId,
    },
    authorizationDetails,
    actorUserId,
  )
  const expiresAt = input.mode === 'until' ? new Date(input.expiresAt!) : null
  if (expiresAt && expiresAt.getTime() <= now.getTime()) throw badRequest('Permission expiry must be in the future.')
  const contextHash = await sha256(canonicalJson(authorizationDetails))
  const existing = (await deps.externalResources.listActiveEntitlementsByAgent(request.agentIdentityId, now)).filter(
    (entitlement) =>
      entitlement.resourceServerId === request.resourceId &&
      entitlement.connectionId === connectionId &&
      exactAuthorizationDetails(entitlement.authorizationDetails, authorizationDetails),
  )
  const entitlements: ResourceScopeEntitlementRecord[] = []
  const entitlementUpdates: Array<{
    id: string
    mode: ResourceScopeEntitlementRecord['mode']
    expiresAt: Date | null
    authorizationContextHash: string
    updatedAt: Date
  }> = []
  const approvedEntitlements = request.scopes.map((scope) => {
    const current = existing.find((entitlement) => entitlement.scope === scope)
    if (current) {
      const shouldPersist = input.mode === 'persistent' && current.mode !== 'persistent'
      const shouldExtend =
        input.mode === 'until' &&
        current.mode !== 'persistent' &&
        (!current.expiresAt || current.expiresAt.getTime() < expiresAt!.getTime())
      if (shouldPersist || shouldExtend || current.authorizationContextHash !== contextHash) {
        entitlementUpdates.push({
          id: current.id,
          mode: shouldPersist ? 'persistent' : shouldExtend ? 'until' : current.mode,
          expiresAt: shouldPersist ? null : shouldExtend ? expiresAt : current.expiresAt,
          authorizationContextHash: contextHash,
          updatedAt: now,
        })
      }
      return { scope, entitlementId: current.id }
    }
    const entitlement: ResourceScopeEntitlementRecord = {
      id: deps.ids.generate(),
      userId: null,
      applicationId: null,
      agentIdentityId: request.agentIdentityId,
      organizationId: null,
      resourceServerId: request.resourceId,
      connectionId,
      authorizationDetails,
      authorizationContextHash: contextHash,
      scope,
      mode: input.mode!,
      grantedByUserId: actorUserId,
      grantedByAgentIdentityId: null,
      sourceAccessRequestId: request.id,
      expiresAt,
      endedAt: null,
      endReason: null,
      createdAt: now,
      updatedAt: now,
    }
    entitlements.push(entitlement)
    return { scope, entitlementId: entitlement.id }
  })
  const audit = await resourceAuditRecord(deps, {
    action: 'api_resource.access_decided',
    result: 'allowed',
    resourceId: request.resourceId,
    connection,
    request,
    accessRequestId: request.id,
    controllerUserId: actorUserId,
    scopes: request.scopes,
    authorizationDetails,
    reasonCode: approvalReasonCode,
  })
  const approved = await deps.externalResources.approveAccessRequestWithEntitlements(
    entitlements,
    entitlementUpdates,
    request.id,
    {
      status: 'approved',
      approvedEntitlements,
      connectionId,
      authorizationDetails,
      decidedAt: now,
      updatedAt: now,
    },
    audit,
  )
  if (approved === 'resource_unavailable') {
    throw badRequest('The API resource was deleted before access could be approved.')
  }
  if (approved === 'entitlements_changed') {
    const concurrentlyDecided = await deps.externalResources.findAccessRequest(requestId)
    if (concurrentlyDecided?.status === 'approved') {
      return toAgentAccessRequest(concurrentlyDecided, await requestHostId(deps, concurrentlyDecided), null)
    }
    if (!retryEntitlementConflict) throw badRequest('Agent permissions changed while access was being approved.')
    return decideAgentAccessRequest(deps, requestId, input, actorUserId, approvalReasonCode, false)
  }
  if (approved === 'request_changed') throw badRequest('Agent access request was already decided.')
  return toAgentAccessRequest(approved.request, await requestHostId(deps, request), null)
}

export async function decideAccessRequest(
  deps: Deps,
  requestId: string,
  input: DecideAgentAccessRequest & { approvalToken?: string },
  actorUserId: string,
): Promise<AccessRequest> {
  if (input.approvalToken) {
    const request = await getControllerAccessRequestByToken(deps, input.approvalToken, actorUserId)
    if (request.id !== requestId) throw notFound('Agent access request was not found.')
  }
  return toAccessRequest(await decideAgentAccessRequest(deps, requestId, input, actorUserId))
}

export async function issueTargetAccessToken(
  deps: Deps,
  requestId: string,
  dpopProof: string,
  tokenRequestUrl: string,
  principal: AgentResourcePrincipal,
  signer: AgentAssertionSigner,
) {
  const identity = await requireActiveIdentityAndBinding(principal)
  const storedRequest = await deps.externalResources.findAccessRequest(requestId)
  if (
    !storedRequest ||
    storedRequest.agentIdentityId !== principal.identityId ||
    (storedRequest.status !== 'approved' && storedRequest.status !== 'consumed')
  ) {
    throw forbidden('Approved Agent access request is required.')
  }
  const now = new Date()
  const entitlements = await activeContextEntitlements(deps, {
    agentIdentityId: principal.identityId,
    resourceServerId: storedRequest.resourceId,
    connectionId: storedRequest.connectionId,
    authorizationDetails: storedRequest.authorizationDetails,
    now,
  })
  if (entitlements.length === 0) throw forbidden('The selected Resource Context has no active Permissions.')
  const request: AgentAccessRequestRecord = {
    ...storedRequest,
    scopes: entitlements.map((entitlement) => entitlement.scope).sort(),
    approvedEntitlements: entitlements.map((entitlement) => ({
      scope: entitlement.scope,
      entitlementId: entitlement.id,
    })),
  }
  const entitlementIds = entitlements.map((entitlement) => entitlement.id)
  const resource = await deps.authorization.findResource(request.resourceId)
  if (!resource?.enabled) throw forbidden('Enabled Resource Server is required.')
  validateResourceRequestedScopes(resource, request.scopes)
  if (!activeResourceVisibleToAgent(resource, await activeIdentityOrganizationIds(deps, identity.identity))) {
    throw forbidden('Resource Server is not visible to this Agent.')
  }
  if (resource.authorizationModel !== 'external') {
    const connection = request.connectionId ? await deps.externalResources.findConnection(request.connectionId) : null
    assertAuthorizationDetailsSelection(resource, connection, request.authorizationDetails)
    return issueNativeAccessToken(
      deps,
      { entitlements, request, resource, identity },
      dpopProof,
      tokenRequestUrl,
      principal,
      signer,
    )
  }

  const connection = request.connectionId ? await deps.externalResources.findConnection(request.connectionId) : null
  if (!connection || connection.status !== 'active') {
    throw forbidden('Active external API resource grant is required.')
  }
  const contextualScopes =
    request.authorizationDetails.length > 0
      ? await accountScopesForAuthorizationDetails(
          deps,
          resource,
          connection,
          request.agentIdentityId,
          request.authorizationDetails,
        )
      : null
  const providerCredential =
    contextualScopes === null
      ? requireProviderCredential(connection, request.scopes, request.authorizationDetails)
      : requireProviderCredential(connection, [], [])
  const connectionClientGeneration = providerCredential.clientGeneration
  const connectorId = resource.connectorId!
  const connector = await deps.connectors.findById(connectorId)
  if ((connector?.resourceClientGeneration ?? 1) === connectionClientGeneration) {
    const activeClientGeneration = await ensureDynamicConnectorScopes(
      deps,
      connectorId,
      connection.grantedScopes,
      new URL(tokenRequestUrl).origin,
    )
    if (activeClientGeneration !== connectionClientGeneration) {
      throw forbidden('The connected account must be reauthorized after OAuth client rotation.')
    }
  }
  const authorization = await findExternalAuthorization(deps, request.resourceId, connectionClientGeneration)
  if (authorization?.status !== 'active') {
    throw forbidden('Active external authorization server is required.')
  }
  assertScopeSubset(request.scopes, contextualScopes ?? connection.grantedScopes, 'connected account')
  assertAuthorizationDetailsSelection(resource, connection, request.authorizationDetails)
  assertAuthorizationDetailsSubset(request.authorizationDetails, connection.authorizationDetails, 'connected account')
  const confirmationJkt = await validateDpopTokenProof(deps, dpopProof, authorization.tokenEndpoint)
  const nowSeconds = Math.floor(Date.now() / 1000)
  const agentAssertion = await signer.sign(
    {
      iss: principal.issuer,
      sub: principal.subject,
      aud: authorization.tokenEndpoint,
      iat: nowSeconds,
      exp: nowSeconds + 300,
      jti: crypto.randomUUID(),
      [realmrootAgentBindingClaim]: toRealmrootAgentBindingClaim(principal),
    },
    'JWT',
  )
  const clientSecret = authorizationClientSecret(authorization)
  const [subject, actorGrant] = await Promise.all([
    refreshConnectionToken(deps, providerCredential, authorization),
    postForm(
      deps,
      authorization.tokenEndpoint,
      {
        grant_type: jwtBearerGrantType,
        assertion: agentAssertion,
      },
      authorization.clientId,
      clientSecret,
    ),
  ])
  const subjectToken = subject.accessToken
  const actorToken = requiredString(actorGrant, 'access_token', 'RFC 7523 JWT bearer grant response')
  const tokenResponse = await postFormResponse(
    deps,
    authorization.tokenEndpoint,
    {
      grant_type: tokenExchangeGrantType,
      subject_token: subjectToken,
      subject_token_type: accessTokenType,
      actor_token: actorToken,
      actor_token_type: accessTokenType,
      requested_token_type: accessTokenType,
      resource: resource.resourceUrl,
      scope: request.scopes.join(' '),
      ...(request.authorizationDetails.length > 0
        ? { authorization_details: JSON.stringify(request.authorizationDetails) }
        : {}),
    },
    authorization.clientId,
    clientSecret,
    new Headers({ dpop: dpopProof }),
  )
  const token = tokenResponse.body
  const accessToken = requiredString(token, 'access_token', 'Token exchange response')
  if (String(token.token_type).toLowerCase() !== 'dpop') {
    throw unauthorized('Target authorization server did not issue a DPoP-bound access token.')
  }
  const expiresIn = requiredPositiveInteger(token, 'expires_in', 'Token exchange response')
  const expiresAt = new Date(now.getTime() + expiresIn * 1000)
  if (expiresIn > 3600) {
    throw unauthorized('Target authorization server issued an access token with an excessive lifetime.')
  }
  const entitlementExpiry = earliestEntitlementExpiry(entitlements)
  if (entitlementExpiry && expiresAt.getTime() > entitlementExpiry.getTime()) {
    throw unauthorized('Target authorization server issued an access token beyond an Entitlement lifetime.')
  }
  const issuedScope = scopeString(token.scope) ?? request.scopes
  if (!exactScopes(issuedScope, request.scopes)) {
    throw unauthorized('Target authorization server issued a different scope set.')
  }
  const issuedAuthorizationDetails = readAuthorizationDetails(
    token.authorization_details,
    request.authorizationDetails.length > 0,
    request.authorizationDetails.map((detail) => detail.type),
    'Token exchange response',
  )
  if (!exactAuthorizationDetails(issuedAuthorizationDetails, request.authorizationDetails)) {
    throw unauthorized('Target authorization server issued different authorization details.')
  }
  const leaseId = deps.ids.generate()
  const leaseRecord = {
    id: leaseId,
    entitlementIds,
    requestId: request.id,
    bindingId: identity.bindings.find(
      (binding) => binding.protocolAgentId === principal.protocolAgentId && binding.hostId === principal.hostId,
    )!.id,
    encryptedAccessToken: await deps.secrets.seal(accessToken, tokenLeaseContext(leaseId)),
    tokenHash: await sha256(accessToken),
    confirmationJkt,
    scopes: request.scopes,
    authorizationDetails: request.authorizationDetails,
    expiresAt,
    revokedAt: null,
    createdAt: now,
  }
  const audit = await resourceAuditRecord(deps, {
    action: 'api_resource.token_issued',
    result: 'allowed',
    principal,
    resourceId: resource.id,
    connection,
    request,
    accessRequestId: request.id,
    scopes: request.scopes,
    authorizationDetails: request.authorizationDetails,
    reasonCode: null,
  })
  const lease = await deps.externalResources.issueTokenLeaseWithAudit(
    leaseRecord,
    {
      agentIdentityId: request.agentIdentityId,
      resourceServerId: request.resourceId,
      connectionId: request.connectionId,
      authorizationContextHash: await sha256(canonicalJson(request.authorizationDetails)),
      scopes: request.scopes,
    },
    entitlements.filter((entitlement) => entitlement.mode === 'once').map((entitlement) => entitlement.id),
    now,
    audit,
  )
  if (!lease) throw forbidden('Approved Entitlements changed before token issuance.')
  return {
    accessToken,
    tokenType: 'DPoP' as const,
    expiresIn,
    expiresAt: expiresAt.toISOString(),
    scopes: request.scopes,
    authorizationDetails: request.authorizationDetails,
    resourceUrl: resource.resourceUrl,
    dpopNonce: tokenResponse.dpopNonce,
  }
}

export async function createAccessRequestCredential(
  deps: Deps,
  requestId: string,
  dpopProof: string,
  credentialRequestUrl: string,
  principal: AgentResourcePrincipal,
  signer: AgentAssertionSigner,
) {
  const request = await getAgentAccessRequest(deps, requestId, principal)
  if (request.status !== 'approved' && request.status !== 'consumed') {
    throw forbidden('Approved Resource access is required.')
  }
  const token = await issueTargetAccessToken(deps, request.id, dpopProof, credentialRequestUrl, principal, signer)
  return {
    ...token,
    resourceIndicator: token.resourceUrl,
  }
}

async function issueNativeAccessToken(
  deps: Deps,
  context: {
    entitlements: ResourceScopeEntitlementRecord[]
    request: AgentAccessRequestRecord
    resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>
    identity: Awaited<ReturnType<typeof requireActiveIdentityAndBinding>>
  },
  dpopProof: string,
  tokenRequestUrl: string,
  principal: AgentResourcePrincipal,
  signer: AgentAssertionSigner,
) {
  const { entitlements, request, resource, identity } = context
  if (request.connectionId !== null) {
    throw forbidden('Native API resource grants cannot use account connections.')
  }
  if (signer.issuer !== principal.issuer) {
    throw forbidden('Agent identity does not belong to the active OAuth issuer.')
  }
  await requireCurrentNativeAuthorityContext(deps, identity, request.authorizationDetails)
  const confirmationJkt = await validateDpopTokenProof(deps, dpopProof, tokenRequestUrl)
  const now = new Date()
  const maximumExpiresAt = new Date(now.getTime() + 5 * 60 * 1000)
  const entitlementExpiry = earliestEntitlementExpiry(entitlements)
  const expiresAt =
    entitlementExpiry && entitlementExpiry.getTime() < maximumExpiresAt.getTime() ? entitlementExpiry : maximumExpiresAt
  const subject = identity.identity.ownerUserId
  const platformResource = isRealmrootResourceServer(resource)
  const authority = request.authorizationDetails[0]
  assertNativeAuthoritySelection(request.authorizationDetails)
  const issuedScopes = platformResource
    ? [...new Set([...agentBootstrapScopes, ...request.scopes])].sort()
    : request.scopes
  const issuedAuthorizationDetails = request.authorizationDetails
  const tokenOrganizationId =
    authority?.authority === 'organization' && typeof authority.id === 'string' ? authority.id : null
  const groups =
    tokenOrganizationId && identity.identity.ownerUserId
      ? await deps.authorization.listTeamNamesForUser(tokenOrganizationId, identity.identity.ownerUserId)
      : []
  const accessToken = await signer.sign(
    {
      iss: signer.issuer,
      sub: subject,
      aud: resource.resourceUrl,
      jti: createProtocolId('resat'),
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(expiresAt.getTime() / 1000),
      scope: issuedScopes.join(' '),
      groups,
      client_id: realmrootCliClientId,
      ...(tokenOrganizationId ? { [realmrootOrganizationClaim]: tokenOrganizationId } : {}),
      ...(request.authorizationDetails.length > 0 ? { authorization_details: request.authorizationDetails } : {}),
      ...(platformResource ? { realmroot_authority: authority } : {}),
      cnf: { jkt: confirmationJkt },
      act: {
        iss: principal.issuer,
        sub: principal.subject,
      },
      [realmrootAgentBindingClaim]: toRealmrootAgentBindingClaim(principal),
    },
    'at+jwt',
  )
  const leaseId = deps.ids.generate()
  const leaseRecord = {
    id: leaseId,
    entitlementIds: entitlements.map((entitlement) => entitlement.id),
    requestId: request.id,
    bindingId: identity.bindings.find(
      (binding) => binding.protocolAgentId === principal.protocolAgentId && binding.hostId === principal.hostId,
    )!.id,
    encryptedAccessToken: await deps.secrets.seal(accessToken, tokenLeaseContext(leaseId)),
    tokenHash: await sha256(accessToken),
    confirmationJkt,
    scopes: request.scopes,
    authorizationDetails: issuedAuthorizationDetails,
    expiresAt,
    revokedAt: null,
    createdAt: now,
  }
  const audit = await resourceAuditRecord(deps, {
    action: 'api_resource.token_issued',
    result: 'allowed',
    principal,
    resourceId: resource.id,
    connection: null,
    request,
    accessRequestId: request.id,
    scopes: request.scopes,
    authorizationDetails: issuedAuthorizationDetails,
    reasonCode: null,
  })
  const lease = await deps.externalResources.issueTokenLeaseWithAudit(
    leaseRecord,
    {
      agentIdentityId: request.agentIdentityId,
      resourceServerId: request.resourceId,
      connectionId: request.connectionId,
      authorizationContextHash: await sha256(canonicalJson(request.authorizationDetails)),
      scopes: request.scopes,
    },
    entitlements.filter((entitlement) => entitlement.mode === 'once').map((entitlement) => entitlement.id),
    now,
    audit,
  )
  if (!lease) throw forbidden('Approved Entitlements changed before token issuance.')
  return {
    accessToken,
    tokenType: 'DPoP' as const,
    expiresIn: Math.max(1, Math.floor((expiresAt.getTime() - now.getTime()) / 1000)),
    expiresAt: expiresAt.toISOString(),
    scopes: request.scopes,
    authorizationDetails: issuedAuthorizationDetails,
    resourceUrl: resource.resourceUrl,
    dpopNonce: null,
  }
}

export async function listAgentPermissions(
  deps: Deps,
  principal: AgentResourcePrincipal,
  query: ListAgentPermissionsQuery,
) {
  await requireActiveIdentityAndBinding(principal)
  const result = await deps.externalResources.listAgentPermissions(
    repositoryPageQuery({ ...query, agentId: principal.identityId }),
  )
  return {
    items: result.items.map(({ entitlement, resource }) => toPermission(entitlement, resource)),
    pagination: paginationMetadata(result),
  }
}

export async function getAgentPermission(
  deps: Deps,
  entitlementId: string,
  principal: AgentResourcePrincipal,
): Promise<AgentPermission> {
  await requireActiveIdentityAndBinding(principal)
  const entitlement = await deps.externalResources.findEntitlement(entitlementId)
  if (!entitlement || entitlement.agentIdentityId !== principal.identityId) {
    throw notFound('Agent Permission was not found.')
  }
  const resource = await deps.authorization.findResource(entitlement.resourceServerId)
  if (!resource) throw notFound('Agent Permission Resource Server was not found.')
  return toPermission(entitlement, resource)
}

export async function revokeAgentPermission(deps: Deps, entitlementId: string, actorUserId: string) {
  const entitlement = await deps.externalResources.findEntitlement(entitlementId)
  if (!entitlement?.agentIdentityId || entitlement.endedAt) throw notFound('Agent Permission was not found.')
  const request = entitlement.sourceAccessRequestId
    ? await deps.externalResources.findAccessRequest(entitlement.sourceAccessRequestId)
    : null
  if (!request) throw notFound('Source Agent access request was not found.')
  const connection = await requireControlledRequestTarget(deps, request, actorUserId)
  const now = new Date()
  const leaseIds = await revokeEntitlementTokenLeasesAtTarget(deps, entitlement, now)
  const audit = await resourceAuditRecord(deps, {
    action: 'api_resource.access_revoked',
    result: 'allowed',
    request,
    resourceId: entitlement.resourceServerId,
    connection,
    accessRequestId: request.id,
    controllerUserId: actorUserId,
    scopes: [entitlement.scope],
    authorizationDetails: entitlement.authorizationDetails,
    reasonCode: null,
  })
  await deps.externalResources.endEntitlementWithAudit(entitlement.id, 'revoked', leaseIds, now, audit)
}

export async function revokeAgentResourceAccess(deps: Deps, agentIdentityId: string) {
  const now = new Date()
  for (const entitlement of await deps.externalResources.listActiveEntitlementsByAgent(agentIdentityId, now)) {
    await revokeEntitlementTokenLeases(deps, entitlement, now)
    await deps.externalResources.endEntitlement(entitlement.id, 'revoked', now)
  }
}

export async function revokeAgentResourceLeasesForBinding(deps: Deps, bindingId: string) {
  const now = new Date()
  for (const lease of await deps.externalResources.listActiveTokenLeasesByBinding(bindingId, now)) {
    await revokeTokenLeaseAtTarget(deps, lease, now)
  }
}

async function revokeEntitlementTokenLeases(deps: Deps, entitlement: ResourceScopeEntitlementRecord, now: Date) {
  for (const lease of await deps.externalResources.listActiveTokenLeasesByEntitlement(entitlement.id, now)) {
    await revokeTokenLeaseAtTarget(deps, lease, now)
  }
}

async function revokeEntitlementTokenLeasesAtTarget(
  deps: Deps,
  entitlement: ResourceScopeEntitlementRecord,
  now: Date,
) {
  const leases = await deps.externalResources.listActiveTokenLeasesByEntitlement(entitlement.id, now)
  for (const lease of leases) await revokeTokenLeaseAtTarget(deps, lease, now, false)
  return leases.map((lease) => lease.id)
}

async function revokeTokenLeaseAtTarget(
  deps: Deps,
  lease: Awaited<ReturnType<Deps['externalResources']['listActiveTokenLeasesByEntitlement']>>[number],
  now: Date,
  persist = true,
) {
  const request = await deps.externalResources.findAccessRequest(lease.requestId)
  if (!request) throw notFound('Approved Agent access request was not found.')
  const resource = await deps.authorization.findResource(request.resourceId)
  if (!resource) throw notFound('API resource was not found.')
  const connection = request.connectionId ? await deps.externalResources.findConnection(request.connectionId) : null
  const authorization = await externalOAuthAuthorization(
    deps,
    resource,
    connection ? providerCredentialGeneration(connection) : 1,
  )
  if (!authorization) {
    if (persist) await deps.externalResources.revokeTokenLease(lease.id, now)
    return
  }
  if (!connection) throw notFound('Resource account connection was not found.')
  const clientSecret = authorizationClientSecret(authorization)
  const token = await deps.secrets.open(lease.encryptedAccessToken, tokenLeaseContext(lease.id))
  await postEmptyForm(
    deps,
    authorization.revocationEndpoint,
    { token, token_type_hint: 'access_token' },
    authorization.clientId,
    clientSecret,
  )
  if (persist) await deps.externalResources.revokeTokenLease(lease.id, now)
}

async function readAuthorizationDetailCatalog(
  deps: Deps,
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  connection: ProviderResourceAuthorizationRecord,
  agentIdentityId: string,
  pagination: PaginationInput,
  authorization: ResolvedExternalAuthorization,
) {
  const credential = requireProviderCredential(connection, [], [])
  const endpoint = authorization.authorizationDetailsCatalogEndpoint
  const requiredScope = authorization.authorizationDetailsCatalogScope
  if (!endpoint || !requiredScope) {
    throw badRequest('External API resource does not advertise an authorization detail catalog.')
  }
  if (!connection.grantedScopes.includes(requiredScope)) {
    throw badRequest('Resource account must be reauthorized for the authorization detail catalog scope.')
  }
  const accessToken = (await refreshConnectionToken(deps, credential, authorization)).accessToken
  const catalog = await requestAuthorizationDetailCatalog(deps, endpoint, accessToken, resource, pagination)
  const entitlements = (await deps.externalResources.listActiveEntitlementsByAgent(agentIdentityId, new Date())).filter(
    (entitlement) => entitlement.resourceServerId === resource.id && entitlement.connectionId === connection.id,
  )
  const items = catalog.items.map((item) => {
    const connectionAuthorized = connection.authorizationDetails.some((detail) =>
      exactAuthorizationDetails([detail], [item.authorizationDetail]),
    )
    const grantedScopes = new Set(item.grantedScopes ?? connection.grantedScopes)
    const authorizedScopes = new Set(
      entitlements
        .filter((entitlement) =>
          entitlement.authorizationDetails.some((detail) =>
            exactAuthorizationDetails([detail], [item.authorizationDetail]),
          ),
        )
        .map((entitlement) => entitlement.scope)
        .filter((scope) => grantedScopes.has(scope)),
    )
    return {
      ...item,
      connectionStatus: connectionAuthorized ? ('authorized' as const) : ('authorization_required' as const),
      authorizedScopes: connectionAuthorized ? [...authorizedScopes].sort() : [],
      requestableScopes: connectionAuthorized
        ? [...grantedScopes]
            .filter(
              (scope) =>
                scope !== 'openid' &&
                scope !== 'offline_access' &&
                scope !== requiredScope &&
                !authorizedScopes.has(scope),
            )
            .sort()
        : [],
    }
  })
  return {
    items,
    pagination: catalog.pagination,
    connection: { status: 'connected' as const },
  }
}

async function requestAuthorizationDetailCatalog(
  deps: Deps,
  endpoint: string,
  bearer: string,
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  pagination: PaginationInput,
) {
  const catalogUrl = new URL(endpoint)
  const requestedPage = Math.floor(pagination.offset / pagination.limit) + 1
  catalogUrl.searchParams.set('page', String(requestedPage))
  catalogUrl.searchParams.set('pageSize', String(pagination.limit))
  let response: Response
  try {
    response = await deps.externalHttp.fetch(
      new Request(catalogUrl, {
        headers: { accept: 'application/json', authorization: `Bearer ${bearer}` },
      }),
    )
  } catch {
    throw badGateway('Authorization detail catalog could not be reached.', { url: endpoint })
  }
  if (!response.ok) {
    throw badGateway('Authorization detail catalog request failed.', { url: endpoint, status: response.status })
  }
  const parsed = authorizationDetailCatalogSchema.safeParse(await response.json().catch(() => null))
  if (!parsed.success) {
    throw badGateway('Authorization detail catalog response is invalid.', {
      url: endpoint,
      issues: parsed.error.issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message })),
    })
  }
  if (parsed.data.pagination.pageSize !== pagination.limit || parsed.data.pagination.page !== requestedPage) {
    throw badGateway('Authorization detail catalog returned mismatched pagination metadata.', { url: endpoint })
  }
  if (parsed.data.items.length > pagination.limit) {
    throw badGateway('Authorization detail catalog returned more items than requested.', { url: endpoint })
  }
  if (parsed.data.pagination.totalItems < pagination.offset + parsed.data.items.length) {
    throw badGateway('Authorization detail catalog returned inconsistent pagination metadata.', { url: endpoint })
  }
  const catalogKeys = parsed.data.items.map((item) => canonicalJson(item.authorizationDetail))
  if (new Set(catalogKeys).size !== catalogKeys.length) {
    throw badGateway('Authorization detail catalog contains duplicate details.', { url: endpoint })
  }
  if (
    parsed.data.items.some(
      (item) =>
        !resource.authorizationDetails.some((template) =>
          authorizationDetailMatchesTemplate(item.authorizationDetail, template),
        ),
    )
  ) {
    throw badGateway('Authorization detail catalog contains a detail outside the resource templates.', {
      url: endpoint,
    })
  }
  return parsed.data
}

async function readResourceCatalog(
  deps: Deps,
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  connection: ProviderResourceAuthorizationRecord,
  agentIdentityId: string,
  pagination: PaginationInput,
  resolvedAuthorization?: ResolvedExternalAuthorization | null,
) {
  const clientGeneration = providerCredentialGeneration(connection)
  const authorization =
    resolvedAuthorization?.clientGeneration === clientGeneration
      ? resolvedAuthorization
      : await activeConnectorAuthorizationForResource(deps, resource, clientGeneration)
  if (authorization?.authorizationDetailsCatalogEndpoint && authorization.authorizationDetailsCatalogScope) {
    return readAuthorizationDetailCatalog(deps, resource, connection, agentIdentityId, pagination, authorization)
  }
  const details = connection.authorizationDetails.slice(pagination.offset, pagination.offset + pagination.limit)
  const entitlements = (await deps.externalResources.listActiveEntitlementsByAgent(agentIdentityId, new Date())).filter(
    (entitlement) => entitlement.resourceServerId === resource.id && entitlement.connectionId === connection.id,
  )
  return {
    items: details.map((authorizationDetail) => {
      const authorizedScopes = [
        ...new Set(
          entitlements
            .filter((entitlement) =>
              entitlement.authorizationDetails.some((detail) =>
                exactAuthorizationDetails([detail], [authorizationDetail]),
              ),
            )
            .map((entitlement) => entitlement.scope),
        ),
      ].sort()
      return {
        id: null,
        authorizationDetail,
        grantedScopes: undefined,
        display: authorizationDetailDisplay(authorizationDetail),
        connectionStatus: 'authorized' as const,
        authorizedScopes,
        requestableScopes: connection.grantedScopes
          .filter((scope) => scope !== 'openid' && scope !== 'offline_access' && !authorizedScopes.includes(scope))
          .sort(),
      }
    }),
    pagination: paginationMetadata({ ...pagination, total: connection.authorizationDetails.length }),
    connection: { status: 'connected' as const },
  }
}

async function activeResourceScopes(
  deps: Deps,
  agentIdentityId: string,
  resourceServerId: string,
  authorizationDetails: AuthorizationDetail[],
) {
  return [
    ...new Set(
      (await deps.externalResources.listActiveEntitlementsByAgent(agentIdentityId, new Date()))
        .filter(
          (entitlement) =>
            entitlement.resourceServerId === resourceServerId &&
            exactAuthorizationDetails(entitlement.authorizationDetails, authorizationDetails),
        )
        .map((entitlement) => entitlement.scope),
    ),
  ].sort()
}

async function activeContextEntitlements(
  deps: Deps,
  context: {
    agentIdentityId: string
    resourceServerId: string
    connectionId: string | null
    authorizationDetails: AuthorizationDetail[]
    now: Date
  },
) {
  return (await deps.externalResources.listActiveEntitlementsByAgent(context.agentIdentityId, context.now))
    .filter(
      (entitlement) =>
        entitlement.resourceServerId === context.resourceServerId &&
        entitlement.connectionId === context.connectionId &&
        exactAuthorizationDetails(entitlement.authorizationDetails, context.authorizationDetails),
    )
    .sort((left, right) => left.scope.localeCompare(right.scope))
}

async function nativeAuthorityDetailsCatalog(
  deps: Deps,
  identity: Awaited<ReturnType<typeof requireActiveIdentityAndBinding>>,
  agentIdentityId: string,
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
) {
  const details = await nativeAuthorityDetails(deps, identity)
  return Promise.all(
    details.map(async (detail) => {
      const display = await nativeAuthorityDisplay(deps, detail)
      const requestableScopes = await nativeAuthorityEffectiveScopes(
        deps,
        identity.identity.ownerUserId,
        resource,
        detail,
      )
      return toResourceServerAuthorizationDetail({
        id: detail.id,
        authorizationDetail: detail,
        display,
        connectionStatus: 'not_required',
        authorizedScopes: await activeResourceScopes(deps, agentIdentityId, resource.id, [detail]),
        requestableScopes,
      })
    }),
  )
}

async function nativeAuthorityDetails(
  deps: Deps,
  identity: { identity: { ownerUserId: string } },
): Promise<Array<AuthorizationDetail & { id: string }>> {
  const details: Array<AuthorizationDetail & { id: string }> = [
    { type: 'realmroot_authority', authority: 'user', id: identity.identity.ownerUserId },
  ]
  for (const organizationId of [...(await activeIdentityOrganizationIds(deps, identity.identity))].sort()) {
    details.push({
      type: 'realmroot_authority',
      authority: 'organization',
      id: organizationId,
    })
  }
  return details
}

async function nativeAuthorityDisplay(
  deps: Deps,
  detail: AuthorizationDetail,
): Promise<{ label: string; description: string | null; metadata: Record<string, string> }> {
  const authority = detail.authority
  const id = detail.id
  if (authority === 'organization' && typeof id === 'string') {
    const organization = await deps.authorization.findOrganization(id)
    if (!organization) throw notFound('Organization authority was not found.')
    return {
      label: organization.displayName ?? organization.name,
      description: 'Organization-scoped administration authority.',
      metadata: { authority: 'organization', organizationId: id },
    }
  }
  if (authority === 'user' && typeof id === 'string') {
    const user = await deps.users.getUser(id)
    return {
      label: user.displayName || user.email,
      description: 'User-tenant administration authority.',
      metadata: { authority: 'user', userId: id },
    }
  }
  throw badRequest('Native Resource authority is invalid.')
}

async function nativeAuthorityEffectiveScopes(
  deps: Deps,
  controllerUserId: string | null,
  resource: ApiResourceResponse,
  detail: AuthorizationDetail,
) {
  const declared = new Set(discoverAgentResourceScopes(resource)?.map((scope) => scope.value) ?? [])
  const current = (scopes: Iterable<string>) => [...new Set(scopes)].filter((scope) => declared.has(scope)).sort()

  if (!isRealmrootResourceServer(resource)) {
    if (!controllerUserId) return detail.authority === 'organization' ? current(declared) : []
    if (detail.authority === 'organization' && typeof detail.id === 'string') {
      return current(await userEffectiveResourceScopes(deps, controllerUserId, resource, new Date(), detail.id))
    }
    if (detail.authority === 'user' && detail.id === controllerUserId) {
      return current(await userEffectiveResourceScopes(deps, controllerUserId, resource, new Date(), null))
    }
    return []
  }

  if (detail.authority === 'organization' && typeof detail.id === 'string') {
    if (!controllerUserId) return current(realmrootManagementScopes)
    const membership = (await deps.authorization.listUserMemberships(controllerUserId)).find(
      (item) => item.organizationId === detail.id,
    )
    return membership
      ? current(await userEffectiveResourceScopes(deps, controllerUserId, resource, new Date(), detail.id))
      : []
  }
  if (controllerUserId && detail.authority === 'user' && detail.id === controllerUserId) {
    const scopes = new Set([
      'agents:read',
      'agents:write',
      'audit-events:read',
      ...(await userEffectiveResourceScopes(deps, controllerUserId, resource, new Date(), null)),
    ])
    return current(scopes)
  }
  return []
}

function toResourceServerAuthorizationDetail(input: {
  id?: string | null
  authorizationDetail: AuthorizationDetail
  display: {
    label: string
    description?: string | null
    metadata?: Record<string, string>
  }
  connectionStatus: 'authorized' | 'authorization_required' | 'not_required'
  authorizedScopes: string[]
  requestableScopes: string[]
}) {
  return {
    id: input.id ?? null,
    authorizationDetail: input.authorizationDetail,
    name: input.display.label,
    description: input.display.description ?? null,
    metadata: input.display.metadata ?? {},
    accountAuthorizationStatus: input.connectionStatus,
    authorizedScopes: input.authorizedScopes,
    requestableScopes: input.requestableScopes.filter((scope) => !input.authorizedScopes.includes(scope)),
  }
}

function toResourceServer(
  resource: Awaited<ReturnType<typeof getApiResourceConfiguration>>,
  origin: string,
  connection: {
    status: 'connected' | 'not_connected' | 'not_required'
    displayName: string | null
    authorizedScopes: string[]
  } | null,
) {
  const self = `${origin}/api/resource-servers/${encodeURIComponent(resource.id)}`
  return {
    ...resource,
    availability: {
      status:
        resource.scopeRegistry && resource.scopeRegistry.discovery.lastError === null
          ? ('available' as const)
          : ('unavailable' as const),
      checkedAt: resource.scopeRegistry?.discovery.syncedAt ?? resource.updatedAt,
    },
    scopes: resource.scopeRegistry?.scopes.map(({ value, description }) => ({ value, description })) ?? [],
    connection,
    links: {
      self,
      authorizationDetails: `${self}/authorization-details`,
    },
  }
}

async function resolveRequestedAuthorizationDetails(
  deps: Deps,
  resourceServer: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  connection: ProviderResourceAuthorizationRecord | null,
  authorizationDetails: AuthorizationDetail[],
  identity: Awaited<ReturnType<typeof requireActiveIdentityAndBinding>>,
) {
  if (authorizationDetails.length === 0) return []
  if (hasDuplicateAuthorizationDetails(authorizationDetails)) {
    throw invalidAuthorizationDetails('Authorization details contain duplicate entries.')
  }
  if (!requiresAccountConnection(resourceServer)) {
    const available = await nativeAuthorityDetails(deps, identity)
    if (
      !authorizationDetails.every((detail) =>
        available.some((candidate) => exactAuthorizationDetails([candidate], [detail])),
      )
    ) {
      throw invalidAuthorizationDetails('Realmroot authority Context is not available to this Agent owner.')
    }
    return authorizationDetails
  }
  if (!connection)
    throw invalidAuthorizationDetails('Connect the Resource Server before selecting authorization details.')
  if (await serviceResourceFallbackAuthorization(deps, resourceServer, connection)) {
    throw invalidAuthorizationDetails('This Resource Server does not use authorization details.')
  }
  const available: AuthorizationDetail[] = []
  for (let page = 1; ; page += 1) {
    const catalog = await readResourceCatalog(deps, resourceServer, connection, identity.identity.id, {
      limit: 100,
      offset: (page - 1) * 100,
    })
    for (const item of catalog.items) available.push(item.authorizationDetail)
    if (catalog.pagination.page >= catalog.pagination.totalPages) break
  }
  if (
    !authorizationDetails.every((detail) =>
      available.some((candidate) => exactAuthorizationDetails([candidate], [detail])),
    )
  ) {
    throw invalidAuthorizationDetails('Authorization detail is not available through this Resource Server connection.')
  }
  return authorizationDetails
}

async function serviceResourceFallbackAuthorization(
  deps: Deps,
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  connection: ProviderResourceAuthorizationRecord,
) {
  if (connection.authorizationDetails.length > 0) return null
  const authorization = await connectorOAuthAuthorization(deps, resource, providerCredentialGeneration(connection))
  if (!authorization) return { authorizationDetailsCatalogScope: null }
  return authorization.authorizationDetailsCatalogEndpoint ? null : authorization
}

function authorizationDetailDisplay(detail: AuthorizationDetail) {
  const entries = Object.entries(detail).filter(
    ([key, value]) => key !== 'type' && (typeof value === 'string' || typeof value === 'number'),
  )
  const identifier =
    entries.find(([key]) => key === 'name') ??
    entries.find(([key]) => key.endsWith('_name')) ??
    entries.find(([key]) => key === 'label' || key.endsWith('_label')) ??
    entries[0]
  const label = identifier ? String(identifier[1]) : detail.type
  return { label, description: null, metadata: identifier ? { [identifier[0]]: label } : {} }
}

function activeProviderCredentials(connection: ProviderResourceAuthorizationRecord) {
  return connection.credentials.filter((credential) => credential.status === 'active')
}

function requireProviderCredential(
  connection: ProviderResourceAuthorizationRecord,
  scopes: string[],
  authorizationDetails: AuthorizationDetail[],
) {
  const candidates = activeProviderCredentials(connection).filter(
    (credential) =>
      scopes.every((scope) => credential.grantedScopes.includes(scope)) &&
      isAuthorizationDetailsSubset(authorizationDetails, credential.authorizationDetails),
  )
  if (candidates.length === 1) return candidates[0]!
  if (candidates.length === 0) {
    throw forbidden('No active provider credential covers the requested authority.')
  }
  throw badRequest('Select an authorization context that identifies one provider credential.')
}

function providerCredentialGeneration(connection: ProviderResourceAuthorizationRecord) {
  return activeProviderCredentials(connection)[0]?.clientGeneration ?? 1
}

function providerCredentialExpiry(connection: ProviderResourceAuthorizationRecord) {
  const expiries = activeProviderCredentials(connection)
    .map((credential) => credential.credentialExpiresAt)
    .filter((expiresAt): expiresAt is Date => expiresAt !== null)
  return expiries.length > 0 ? new Date(Math.min(...expiries.map((expiresAt) => expiresAt.getTime()))) : null
}

async function refreshConnectionToken(
  deps: Deps,
  credential: ProviderCredentialRecord,
  authorization: ExternalResourceAuthorizationRecord,
) {
  const payload = JSON.parse(
    await deps.secrets.open(
      credential.encryptedTokens,
      providerCredentialTokensContext(credential.id, credential.providerResourceAuthorizationId),
    ),
  ) as Record<string, unknown>
  if (credential.credentialExpiresAt && credential.credentialExpiresAt.getTime() > Date.now() + 30_000) {
    return {
      accessToken: requiredString(payload, 'accessToken', 'Stored resource connection'),
      expiresAt: credential.credentialExpiresAt,
      scopes: credential.grantedScopes,
    }
  }
  const expectedVersion = credential.credentialVersion
  const claimId = deps.ids.generate()
  const now = new Date()
  if (
    !(await deps.externalResources.claimProviderCredentialRefresh({
      id: credential.id,
      expectedVersion,
      claimId,
      now,
      claimExpiresAt: new Date(now.getTime() + 15_000),
    }))
  ) {
    throw oauthError(
      'temporarily_unavailable',
      'Provider credential refresh is already in progress.',
      503,
      {},
      { 'Retry-After': '1' },
    )
  }
  const refreshToken = requiredString(payload, 'refreshToken', 'Stored resource connection')
  const clientSecret = authorizationClientSecret(authorization)
  try {
    const refreshRequest = await deps.oauthRequests.createRefreshTokenRequest({
      refreshToken,
      clientId: authorization.clientId,
      clientSecret,
      authentication: authorization.tokenEndpointAuthentication,
      extraParams:
        authorization.authorizationDetailsMode === 'provider' && credential.authorizationDetails.length > 0
          ? { authorization_details: JSON.stringify(credential.authorizationDetails) }
          : undefined,
    })
    const token = await postForm(
      deps,
      authorization.tokenEndpoint,
      refreshRequest.body,
      authorization.clientId,
      clientSecret,
      new Headers(),
      true,
      authorization.tokenEndpointAuthentication,
    )
    const accessToken = requiredString(token, 'access_token', 'OAuth refresh response')
    const nextRefreshToken = optionalString(token, 'refresh_token') ?? refreshToken
    const scopes = scopeString(token.scope) ?? credential.grantedScopes
    const authorizationDetails =
      token.authorization_details === undefined
        ? credential.authorizationDetails
        : readAuthorizationDetails(
            token.authorization_details,
            credential.authorizationDetails.length > 0,
            credential.authorizationDetails.map((detail) => detail.type),
            'OAuth refresh response',
          )
    if (!exactAuthorizationDetails(authorizationDetails, credential.authorizationDetails)) {
      throw unauthorized('Target authorization server changed authorization details during refresh.')
    }
    const refreshedAt = new Date()
    const expiresAt = tokenExpiry(token, refreshedAt)
    const updated = await deps.externalResources.completeProviderCredentialRefresh(credential.id, {
      expectedVersion,
      claimId,
      encryptedTokens: await deps.secrets.seal(
        JSON.stringify({ accessToken, refreshToken: nextRefreshToken, scope: scopes.join(' ') }),
        providerCredentialTokensContext(credential.id, credential.providerResourceAuthorizationId),
      ),
      credentialExpiresAt: expiresAt,
      updatedAt: refreshedAt,
    })
    if (!updated) {
      throw oauthError('temporarily_unavailable', 'Provider credential refresh changed concurrently.', 503)
    }
    return { accessToken, expiresAt, scopes }
  } catch (error) {
    if (error instanceof OAuthError && error.error === 'invalid_grant') {
      await deps.externalResources.revokeProviderCredential(credential.id, new Date())
      throw error
    }
    await deps.externalResources.releaseProviderCredentialRefresh(credential.id, expectedVersion, claimId, new Date())
    throw error
  }
}

async function requirePendingAccessRequestByToken(deps: Deps, token: string) {
  const request = await deps.externalResources.findAccessRequestByApprovalTokenHash(await sha256(token))
  if (!request || request.status !== 'pending' || request.expiresAt.getTime() <= Date.now()) {
    throw notFound('Pending Agent access request was not found.')
  }
  return request
}

async function requireControlledAccessRequest(deps: Deps, requestId: string, actorUserId: string) {
  const request = await deps.externalResources.findAccessRequest(requestId)
  if (!request) throw notFound('Agent access request was not found.')
  await requireControlledRequestTarget(deps, request, actorUserId)
  return toAgentAccessRequest(request, await requestHostId(deps, request), null)
}

async function requestHostId(deps: Deps, request: AgentAccessRequestRecord) {
  const identity = await deps.agentIdentities.findIdentity(request.agentIdentityId)
  const binding = identity?.bindings.find((candidate) => candidate.id === request.bindingId)
  if (!binding) throw notFound('Agent host binding was not found.')
  return binding.hostId
}

async function requireExternalResource(deps: Deps, resourceId: string) {
  const resource = await deps.authorization.findResource(resourceId)
  if (resource?.authorizationModel !== 'external') throw notFound('External Resource Server was not found.')
  return resource
}

async function requireActiveExternalAuthorization(deps: Deps, resourceId: string, clientGeneration?: number) {
  const resource = await deps.authorization.findResource(resourceId)
  if (resource?.authorizationModel !== 'external') {
    throw notFound('Active external API resource authorization was not found.')
  }
  return requireActiveConnectorAuthorization(deps, resourceId, clientGeneration)
}

async function requireActiveConnectorAuthorization(deps: Deps, resourceId: string, clientGeneration?: number) {
  const authorization = await findExternalAuthorization(deps, resourceId, clientGeneration)
  if (!authorization || authorization.status !== 'active') {
    throw notFound('Active external API resource authorization was not found.')
  }
  return authorization
}

async function findExternalAuthorization(
  deps: Deps,
  resourceId: string,
  clientGeneration?: number,
): Promise<ResolvedExternalAuthorization | null> {
  const resource = await deps.authorization.findResource(resourceId)
  if (!resource?.connectorId || resource.authorizationModel !== 'external') return null
  const connector = await deps.connectors.findById(resource.connectorId)
  return resolveExternalAuthorization(deps, resource, connector ?? undefined, clientGeneration)
}

async function resolveExternalAuthorization(
  deps: Deps,
  resource: ApiResourceResponse,
  connector?: ConnectorRecord,
  clientGeneration?: number,
): Promise<ResolvedExternalAuthorization | null> {
  const driver = connector ? resourceOAuthDriver(connector) : null
  if (
    !connector ||
    !driver ||
    !connector.resourceAuthorizationEnabled ||
    !connector.resourceClientId ||
    !connector.resourceClientSecret ||
    !connector.resourceIssuer ||
    !connector.resourceJwksEndpoint
  ) {
    return null
  }
  const currentGeneration = connector.resourceClientGeneration
  const requestedGeneration = clientGeneration ?? currentGeneration
  const retired = connector.resourceRetiredClientGenerations?.find(
    (candidate) => candidate.generation === requestedGeneration,
  )
  if (requestedGeneration !== currentGeneration && !retired) return null
  const clientId = retired?.clientId ?? connector.resourceClientId
  const clientSecret = retired
    ? await deps.secrets.open(retired.encryptedClientSecret, retired.clientSecretContext)
    : connector.resourceClientSecret
  return {
    resourceId: resource.id,
    connectorId: connector.id,
    resourceUrl: resource.resourceUrl,
    issuer: connector.resourceIssuer,
    authorizationEndpoint: driver.authorizationEndpoint,
    tokenEndpoint: driver.tokenEndpoint,
    pushedAuthorizationRequestEndpoint:
      typeof connector.resourceProviderMetadata?.pushed_authorization_request_endpoint === 'string'
        ? connector.resourceProviderMetadata.pushed_authorization_request_endpoint
        : null,
    authorizationDetailsTypesSupported: metadataStringArray(
      connector.resourceProviderMetadata?.authorization_details_types_supported,
    ),
    authorizationDetailsCatalogEndpoint:
      typeof connector.resourceProviderMetadata?.authorization_details_catalog_endpoint === 'string'
        ? connector.resourceProviderMetadata.authorization_details_catalog_endpoint
        : null,
    authorizationDetailsCatalogScope:
      typeof connector.resourceProviderMetadata?.authorization_details_catalog_scope === 'string'
        ? connector.resourceProviderMetadata.authorization_details_catalog_scope
        : null,
    registrationEndpoint: connector.resourceRegistrationEndpoint,
    revocationEndpoint: driver.revocationEndpoint,
    jwksUri: connector.resourceJwksEndpoint,
    userInfoEndpoint: driver.userInfoEndpoint,
    tokenEndpointAuthentication: driver.tokenEndpointAuthentication,
    revocationAuthentication: driver.revocationAuthentication,
    authorizationDetailsMode: driver.authorizationDetailsMode,
    revokeAccessToken: driver.revokeAccessToken,
    registrationMode: connector.resourceRegistrationMode ?? 'manual',
    clientId,
    clientGeneration: requestedGeneration,
    encryptedClientSecret: clientSecret,
    encryptedRegistrationAccessToken: null,
    metadata: connector.resourceProviderMetadata ?? {},
    status: connector.enabled && connector.resourceAuthorizationEnabled ? 'active' : 'invalid',
    createdAt: connector.createdAt,
    updatedAt: connector.updatedAt,
  }
}

function authorizationClientSecret(authorization: ResolvedExternalAuthorization) {
  return authorization.encryptedClientSecret
}

function requiresAccountConnection(resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>) {
  return resource.authorizationModel === 'external'
}

async function externalOAuthAuthorization(
  deps: Deps,
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  clientGeneration?: number,
) {
  if (resource.authorizationModel !== 'external') return null
  return requireActiveExternalAuthorization(deps, resource.id, clientGeneration)
}

async function connectorOAuthAuthorization(
  deps: Deps,
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  clientGeneration?: number,
) {
  if (!resource.connectorId || resource.authorizationModel !== 'external') return null
  return requireActiveConnectorAuthorization(deps, resource.id, clientGeneration)
}

async function requireEnabledResource(deps: Deps, resourceId: string) {
  return (await requireEnabledResourceConfiguration(deps, resourceId)).resource
}

async function requireEnabledResourceConfiguration(deps: Deps, resourceId: string) {
  const resource = await deps.authorization.findResource(resourceId)
  if (!resource?.enabled) throw notFound('Enabled Resource Server was not found.')
  const authorization = await activeConnectorAuthorizationForResource(deps, resource)
  return { resource, authorization }
}

async function activeConnectorAuthorizationForResource(
  deps: Deps,
  resource: ApiResourceResponse,
  clientGeneration?: number,
) {
  if (!resource.connectorId || resource.authorizationModel !== 'external') return null
  const connector = await deps.connectors.findById(resource.connectorId)
  return resolveExternalAuthorization(deps, resource, connector ?? undefined, clientGeneration)
}

async function requireActiveIdentityAndBinding(principal: AgentResourcePrincipal) {
  if (
    principal.identity.id !== principal.identityId ||
    principal.identity.status !== 'active' ||
    principal.binding.agentIdentityId !== principal.identityId ||
    principal.binding.protocolAgentId !== principal.protocolAgentId ||
    principal.binding.hostId !== principal.hostId ||
    principal.binding.status !== 'active'
  ) {
    throw forbidden('An active Agent identity and host binding are required.')
  }
  return { identity: principal.identity, bindings: [principal.binding] }
}

async function requireControlledConnection(deps: Deps, connectionId: string, actorUserId: string) {
  const connection = await deps.externalResources.findConnection(connectionId)
  if (!connection) throw notFound('Resource account connection was not found.')
  if (connection.ownerUserId === actorUserId) return connection
  if (connection.ownerOrganizationId) {
    if (await organizationUserHasScope(deps, connection.ownerOrganizationId, actorUserId, 'agents:write')) {
      return connection
    }
  }
  throw forbidden('Resource account controller access is required.')
}

async function requireControlledRequestTarget(deps: Deps, request: AgentAccessRequestRecord, actorUserId: string) {
  if (request.connectionId) return requireControlledConnection(deps, request.connectionId, actorUserId)
  if (await controlsAgentIdentity(deps, request.agentIdentityId, actorUserId)) return null
  throw forbidden('Agent controller access is required.')
}

async function controlsAgentIdentity(deps: Deps, identityId: string, actorUserId: string) {
  const identity = await deps.agentIdentities.findIdentity(identityId)
  if (!identity) return false
  return identity.identity.ownerUserId === actorUserId
}

async function requireConnectionOwnerControl(
  deps: Deps,
  owner: CreateResourceConnectionIntentRequest['owner'],
  actorUserId: string,
) {
  if (owner.type === 'user') return
  if (!(await organizationUserHasScope(deps, owner.organizationId, actorUserId, 'agents:write'))) {
    throw forbidden('Organization credential manager access is required.')
  }
}

function assertConnectionInHomeSpace(connection: ProviderResourceAuthorizationRecord, ownerUserId: string) {
  if (connection.ownerUserId === ownerUserId) return
  throw forbidden('Resource account connection is outside the Agent home space.')
}

async function resourceAuditRecord(
  deps: Deps,
  input: {
    action: string
    result: string
    principal?: AgentResourcePrincipal
    request?: AgentAccessRequestRecord
    resourceId: string
    connection: ProviderResourceAuthorizationRecord | null
    accessRequestId: string | null
    controllerUserId?: string
    scopes: string[]
    authorizationDetails?: AuthorizationDetail[]
    reasonCode: string | null
  },
) {
  const tenant = await resolveAuditTenant(deps, input)
  const authorizationDetails =
    input.authorizationDetails ?? input.request?.authorizationDetails ?? input.connection?.authorizationDetails ?? []
  const authorizationDetailProjections = authorizationDetails.map((detail) => ({
    type: detail.type,
    ...(typeof detail.identifier === 'string' ? { identifier: detail.identifier } : {}),
  }))
  return {
    id: deps.ids.generate(),
    action: input.action,
    result: input.result,
    realmOwned: false,
    ownerUserId: tenant.type === 'user' ? tenant.id : null,
    ownerOrganizationId: tenant.type === 'organization' ? tenant.id : null,
    controllerUserId: input.controllerUserId ?? null,
    subjectIssuer: input.principal?.issuer ?? null,
    subject: input.principal?.subject ?? null,
    agentIdentityId: input.principal?.identityId ?? input.request?.agentIdentityId ?? null,
    hostId: input.principal?.hostId ?? null,
    resourceId: input.resourceId,
    resourceConnectionId: input.connection?.id ?? null,
    accessRequestId: input.accessRequestId,
    scopes: input.scopes,
    reasonCode: input.reasonCode,
    metadata:
      authorizationDetailProjections.length > 0 ? { authorizationDetails: authorizationDetailProjections } : null,
    occurredAt: new Date(),
  }
}

async function resolveAuditTenant(
  deps: Deps,
  input: {
    principal?: AgentResourcePrincipal
    request?: AgentAccessRequestRecord
    connection: ProviderResourceAuthorizationRecord | null
  },
) {
  if (input.connection?.ownerUserId) return { type: 'user' as const, id: input.connection.ownerUserId }
  if (input.connection?.ownerOrganizationId) {
    return { type: 'organization' as const, id: input.connection.ownerOrganizationId }
  }
  const identityId = input.principal?.identityId ?? input.request?.agentIdentityId
  if (!identityId) throw new Error('Agent audit event has no tenant-owned resource.')
  const identity = await deps.agentIdentities.findIdentity(identityId)
  if (!identity) throw new Error(`Agent identity ${identityId} was not found while writing its audit event.`)
  return { type: 'user' as const, id: identity.identity.ownerUserId }
}

async function revokeUncoveredEntitlements(
  deps: Deps,
  connection: ProviderResourceAuthorizationRecord,
  authorizationDetailsRequired: boolean,
  controllerUserId: string,
  now: Date,
) {
  for (const entitlement of await deps.externalResources.listActiveEntitlementsByConnection(connection.id, now)) {
    const covered =
      connection.grantedScopes.includes(entitlement.scope) &&
      (!authorizationDetailsRequired || entitlement.authorizationDetails.length > 0) &&
      isAuthorizationDetailsSubset(entitlement.authorizationDetails, connection.authorizationDetails)
    if (covered) continue
    const leaseIds = await revokeEntitlementTokenLeasesAtTarget(deps, entitlement, now)
    const audit = await resourceAuditRecord(deps, {
      action: 'api_resource.access_revoked',
      result: 'allowed',
      resourceId: entitlement.resourceServerId,
      connection,
      accessRequestId: entitlement.sourceAccessRequestId,
      controllerUserId,
      scopes: [entitlement.scope],
      authorizationDetails: entitlement.authorizationDetails,
      reasonCode: 'connection_authorization_changed',
    })
    await deps.externalResources.endEntitlementWithAudit(entitlement.id, 'revoked', leaseIds, now, audit)
  }
}

function assertAuthorizationDetailsSupported(
  authorizationDetails: AuthorizationDetail[],
  authorization: ResolvedExternalAuthorization,
  driver: ResourceOAuthDriver,
) {
  if (authorizationDetails.length === 0) return
  if (driver.authorizationDetailsMode === 'connection') return
  if (authorizationDetails.some((detail) => !authorization.authorizationDetailsTypesSupported.includes(detail.type))) {
    throw invalidAuthorizationDetails(
      'The authorization server does not support every configured authorization detail type.',
    )
  }
}

function assertAuthorizationDetailsSelection(
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  connection: ProviderResourceAuthorizationRecord | null,
  authorizationDetails: AuthorizationDetail[],
) {
  if (!requiresAccountConnection(resource)) {
    assertNativeAuthoritySelection(authorizationDetails)
    return
  }
  const required = resource.authorizationDetails.length > 0
  if (!required && authorizationDetails.length > 0) {
    throw invalidAuthorizationDetails('This external API resource does not use authorization details.')
  }
  if (!required) return
  if (!connection || connection.authorizationDetails.length === 0) {
    throw invalidAuthorizationDetails('The resource account must be explicitly reauthorized for authorization details.')
  }
  if (authorizationDetails.length === 0) {
    throw invalidAuthorizationDetails('Select at least one concrete authorization detail entry.')
  }
  assertConcreteAuthorizationDetails(resource.authorizationDetails, authorizationDetails, 'Selected')
  if (hasDuplicateAuthorizationDetails(authorizationDetails)) {
    throw invalidAuthorizationDetails('Selected authorization details contain duplicate entries.')
  }
}

function assertAccessRequestAuthorizationDetails(
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  authorizationDetails: AuthorizationDetail[],
) {
  if (!requiresAccountConnection(resource)) {
    assertNativeAuthoritySelection(authorizationDetails)
    return
  }
  const supportedTypes = new Set(resource.authorizationDetails.map((detail) => detail.type))
  if (supportedTypes.size === 0) {
    if (authorizationDetails.length > 0) {
      throw invalidAuthorizationDetails('This external API resource does not use authorization details.')
    }
    return
  }
  if (authorizationDetails.length === 0) {
    throw invalidAuthorizationDetails('Select at least one concrete authorization detail entry.')
  }
  if (authorizationDetails.some((detail) => !supportedTypes.has(detail.type))) {
    throw invalidAuthorizationDetails('Requested authorization details contain an unsupported type.')
  }
  assertConcreteAuthorizationDetails(resource.authorizationDetails, authorizationDetails, 'Requested')
  if (hasDuplicateAuthorizationDetails(authorizationDetails)) {
    throw invalidAuthorizationDetails('Requested authorization details contain duplicate entries.')
  }
}

function accessRequestAuthorizationDetails(
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  authorizationDetails: AuthorizationDetail[],
) {
  if (!requiresAccountConnection(resource) || resource.authorizationDetails.length === 0) {
    assertAccessRequestAuthorizationDetails(resource, authorizationDetails)
    return authorizationDetails
  }
  if (authorizationDetails.length === 0) return resource.authorizationDetails
  const templates = resource.authorizationDetails
  if (
    authorizationDetails.some(
      (detail) => !templates.some((template) => authorizationDetailMatchesTemplate(detail, template)),
    ) ||
    hasDuplicateAuthorizationDetails(authorizationDetails)
  ) {
    throw invalidAuthorizationDetails('Requested authorization details contain an unsupported or duplicate entry.')
  }
  const concrete = authorizationDetails.filter(
    (detail) => !templates.some((template) => canonicalJson(template) === canonicalJson(detail)),
  )
  if (concrete.length > 0) assertAccessRequestAuthorizationDetails(resource, concrete)
  return authorizationDetails
}

function assertNativeAuthoritySelection(authorizationDetails: AuthorizationDetail[]) {
  const detail = authorizationDetails[0]
  if (
    authorizationDetails.length !== 1 ||
    detail?.type !== 'realmroot_authority' ||
    !['organization', 'user'].includes(String(detail.authority)) ||
    typeof detail.id !== 'string'
  ) {
    throw invalidAuthorizationDetails('Select exactly one Realmroot authority Context.')
  }
}

async function requireCurrentNativeAuthorityContext(
  deps: Deps,
  identity: { identity: { ownerUserId: string } },
  authorizationDetails: AuthorizationDetail[],
) {
  assertNativeAuthoritySelection(authorizationDetails)
  const selected = authorizationDetails[0]!
  const available = await nativeAuthorityDetails(deps, identity)
  if (!available.some((candidate) => exactAuthorizationDetails([candidate], [selected]))) {
    throw forbidden('Selected Realmroot authority Context is no longer available.')
  }
}

function assertAuthorizationDetailsSubset(
  requested: AuthorizationDetail[],
  allowed: AuthorizationDetail[],
  boundary: string,
) {
  if (!isAuthorizationDetailsSubset(requested, allowed)) {
    throw invalidAuthorizationDetails(`Requested authorization details exceed the ${boundary} boundary.`)
  }
}

function isAuthorizationDetailsSubset(requested: AuthorizationDetail[], allowed: AuthorizationDetail[]) {
  const remaining = allowed.map(canonicalJson)
  for (const detail of requested.map(canonicalJson)) {
    const index = remaining.indexOf(detail)
    if (index === -1) return false
    remaining.splice(index, 1)
  }
  return true
}

function exactAuthorizationDetails(left: AuthorizationDetail[], right: AuthorizationDetail[]) {
  if (left.length !== right.length) return false
  const leftEntries = left.map(canonicalJson).sort()
  const rightEntries = right.map(canonicalJson).sort()
  return leftEntries.every((value, index) => value === rightEntries[index])
}

function authorizationDetailsMatchRequest(approved: AuthorizationDetail[], requested: AuthorizationDetail[]) {
  if (approved.length !== requested.length || new Set(approved.map(canonicalJson)).size !== approved.length)
    return false
  const remaining = [...approved]
  for (const requirement of requested) {
    const index = remaining.findIndex(
      (candidate) =>
        canonicalJson(candidate) === canonicalJson(requirement) ||
        authorizationDetailMatchesTemplate(candidate, requirement),
    )
    if (index === -1) return false
    remaining.splice(index, 1)
  }
  return true
}

function assertConcreteAuthorizationDetails(
  templates: AuthorizationDetail[],
  authorizationDetails: AuthorizationDetail[],
  label: string,
) {
  if (
    authorizationDetails.some(
      (detail) =>
        !templates.some((template) => authorizationDetailMatchesTemplate(detail, template)) ||
        templates.some((template) => canonicalJson(template) === canonicalJson(detail)),
    )
  ) {
    throw invalidAuthorizationDetails(`${label} authorization details must identify concrete resource contexts.`)
  }
}

function assertProviderConnectionAuthorizationDetails(
  configuredTemplates: AuthorizationDetail[],
  requested: AuthorizationDetail[],
  granted: AuthorizationDetail[],
) {
  if (requested.length === 0) return
  if (granted.length === 0 || hasDuplicateAuthorizationDetails(granted)) {
    throw invalidProviderConnectionAuthorizationDetails()
  }
  for (const detail of granted) {
    if (configuredTemplates.some((template) => canonicalJson(template) === canonicalJson(detail))) {
      throw invalidProviderConnectionAuthorizationDetails()
    }
    if (!configuredTemplates.some((template) => authorizationDetailMatchesTemplate(detail, template))) {
      throw invalidProviderConnectionAuthorizationDetails()
    }
  }
  for (const requirement of requested) {
    if (!granted.some((detail) => authorizationDetailMatchesTemplate(detail, requirement))) {
      throw invalidProviderConnectionAuthorizationDetails()
    }
  }
}

function invalidProviderConnectionAuthorizationDetails() {
  return invalidAuthorizationDetails(
    'Provider connection authorization details must identify the requested concrete resource contexts.',
  )
}

function hasDuplicateAuthorizationDetails(authorizationDetails: AuthorizationDetail[]) {
  const entries = authorizationDetails.map(canonicalJson)
  return new Set(entries).size !== entries.length
}

function authorizationDetailMatchesTemplate(detail: AuthorizationDetail, template: AuthorizationDetail) {
  return Object.entries(template).every(([key, value]) => canonicalJson(detail[key]) === canonicalJson(value))
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(',')}}`
  }
  return JSON.stringify(value)!
}

function readAuthorizationDetails(value: unknown, required: boolean, allowedTypes: string[], label: string) {
  if (value === undefined && !required) return []
  const parsed = authorizationDetailsSchema.safeParse(value)
  if (!parsed.success || (required && parsed.data.length === 0)) {
    throw invalidAuthorizationDetails(`${label} has malformed authorization_details.`)
  }
  if (parsed.data.some((detail) => !allowedTypes.includes(detail.type))) {
    throw invalidAuthorizationDetails(`${label} contains an unknown authorization detail type.`)
  }
  return parsed.data
}

function invalidAuthorizationDetails(description: string) {
  return oauthError('invalid_authorization_details', description)
}

function metadataStringArray(value: unknown): string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string') ? [...new Set(value as string[])] : []
}

async function postForm(
  deps: Deps,
  url: string,
  body: Record<string, string>,
  clientId: string,
  clientSecret: string,
  extraHeaders = new Headers(),
  preserveInvalidGrant = false,
  clientAuthentication: 'basic' | 'post' = 'basic',
) {
  return (
    await postFormResponse(
      deps,
      url,
      body,
      clientId,
      clientSecret,
      extraHeaders,
      preserveInvalidGrant,
      clientAuthentication,
    )
  ).body
}

async function postFormResponse(
  deps: Deps,
  url: string,
  body: Record<string, string>,
  clientId: string,
  clientSecret: string,
  extraHeaders = new Headers(),
  preserveInvalidGrant = false,
  clientAuthentication: 'basic' | 'post' = 'basic',
) {
  const headers = new Headers(extraHeaders)
  headers.set('accept', 'application/json')
  if (clientAuthentication === 'basic') headers.set('authorization', `Basic ${base64(`${clientId}:${clientSecret}`)}`)
  headers.set('content-type', 'application/x-www-form-urlencoded')
  let response: Response
  try {
    response = await fetchExternalAuthorization(
      deps,
      new Request(url, { method: 'POST', headers, body: new URLSearchParams(body) }),
    )
  } catch {
    throw badGateway('External authorization server is unavailable.')
  }
  if (!response.ok) {
    const providerError = await readOAuthError(response)
    if (preserveInvalidGrant && providerError?.error === 'invalid_grant') {
      throw oauthError('invalid_grant', 'Provider refresh token is no longer valid.')
    }
    if (providerError?.error === 'use_dpop_nonce') {
      const nonce = response.headers.get('dpop-nonce')
      if (!nonce || !validDpopNonce(nonce)) {
        throw badGateway('External authorization server returned an invalid DPoP nonce challenge.')
      }
      throw oauthError(
        providerError.error,
        providerError.description ?? 'Authorization server requires nonce in DPoP proof.',
        400,
        {},
        { 'DPoP-Nonce': nonce },
      )
    }
    const detail = providerError?.detail ?? null
    throw unauthorized(
      detail
        ? `External authorization server rejected the token request: ${detail}.`
        : 'External authorization server rejected the token request.',
    )
  }
  const dpopNonce = response.headers.get('dpop-nonce')
  if (dpopNonce !== null && !validDpopNonce(dpopNonce)) {
    throw badGateway('External authorization server returned an invalid DPoP nonce.')
  }
  return {
    body: await readObject(response, 'External authorization server response is invalid.'),
    dpopNonce,
  }
}

async function fetchExternalAuthorization(deps: Deps, request: Request) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), externalAuthorizationTimeoutMs)
  try {
    return await Promise.race([
      deps.externalHttp.fetch(new Request(request, { signal: controller.signal })),
      new Promise<never>((_, reject) => {
        controller.signal.addEventListener('abort', () => reject(new Error('external authorization timeout')), {
          once: true,
        })
      }),
    ])
  } finally {
    clearTimeout(timeout)
  }
}

async function readOAuthError(
  response: Response,
): Promise<{ error: string; description: string | null; detail: string } | null> {
  try {
    const body = (await response.json()) as Record<string, unknown>
    const error =
      typeof body.error === 'string' ? body.error : typeof body.code === 'string' ? body.code.toLowerCase() : null
    const description =
      typeof body.error_description === 'string'
        ? body.error_description
        : typeof body.message === 'string'
          ? body.message
          : null
    if (!error) return null
    return { error, description, detail: description ? `${error}: ${description}` : error }
  } catch {
    return null
  }
}

function validDpopNonce(value: string) {
  return value.length <= 4096 && /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(value)
}

async function postPushedAuthorizationRequest(
  deps: Deps,
  url: string,
  body: Record<string, string>,
  clientId: string,
  clientSecret: string,
) {
  const response = await deps.externalHttp.fetch(
    new Request(url, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Basic ${base64(`${clientId}:${clientSecret}`)}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(body),
    }),
  )
  if (response.status !== 201) {
    const error = await response.json().catch(() => null)
    const value = error && typeof error === 'object' && !Array.isArray(error) ? (error as Record<string, unknown>) : {}
    throw oauthError(
      typeof value.error === 'string' ? value.error : 'invalid_request',
      typeof value.error_description === 'string'
        ? value.error_description
        : 'External authorization server rejected the pushed authorization request.',
      response.status >= 400 ? response.status : 400,
    )
  }
  return readObject(response, 'Pushed authorization response is invalid.')
}

async function postEmptyForm(
  deps: Deps,
  url: string,
  body: Record<string, string>,
  clientId: string,
  clientSecret: string,
  clientAuthentication: 'basic' | 'post' | 'none' = 'basic',
) {
  const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' })
  if (clientAuthentication === 'basic') headers.set('authorization', `Basic ${base64(`${clientId}:${clientSecret}`)}`)
  const parameters = {
    ...body,
    ...(clientAuthentication === 'post' ? { client_id: clientId, client_secret: clientSecret } : {}),
  }
  let response: Response
  try {
    response = await deps.externalHttp.fetch(
      new Request(url, { method: 'POST', headers, body: new URLSearchParams(parameters) }),
    )
  } catch {
    throw badGateway('External authorization server revocation is unavailable.')
  }
  if (!response.ok) throw unauthorized('External authorization server rejected the revocation request.')
}

async function readObject(response: Response, message: string) {
  const value = await response.json().catch(() => null)
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw badRequest(message)
  return value as Record<string, unknown>
}

function requiredString(value: Record<string, unknown>, field: string, label: string) {
  const result = value[field]
  if (typeof result !== 'string' || result.length === 0) throw badRequest(`${label} is missing ${field}.`)
  return result
}

function optionalString(value: Record<string, unknown>, field: string) {
  return typeof value[field] === 'string' && value[field].length > 0 ? value[field] : null
}

function requiredPositiveInteger(value: Record<string, unknown>, field: string, label: string) {
  const result = value[field]
  if (typeof result !== 'number' || !Number.isInteger(result) || result <= 0) {
    throw badRequest(`${label} has invalid ${field}.`)
  }
  return result
}

function scopeString(value: unknown) {
  return typeof value === 'string' ? value.split(/\s+/).filter(Boolean).sort() : null
}

function tokenExpiry(token: Record<string, unknown>, now: Date) {
  return typeof token.expires_in === 'number' && Number.isFinite(token.expires_in) && token.expires_in > 0
    ? new Date(now.getTime() + token.expires_in * 1000)
    : null
}

function assertScopeSubset(requested: string[], allowed: string[], boundary: string) {
  const missing = requested.filter((scope) => !allowed.includes(scope))
  if (missing.length > 0) throw badRequest(`Requested scopes exceed the ${boundary} boundary: ${missing.join(', ')}.`)
}

function exactScopes(left: string[], right: string[]) {
  return left.length === right.length && [...left].sort().every((value, index) => value === [...right].sort()[index])
}

function earliestEntitlementExpiry(entitlements: ResourceScopeEntitlementRecord[]) {
  const expiries = entitlements.flatMap((entitlement) => (entitlement.expiresAt ? [entitlement.expiresAt] : []))
  return expiries.length > 0 ? new Date(Math.min(...expiries.map((expiresAt) => expiresAt.getTime()))) : null
}

async function requireAgentResourceVisibility(
  deps: Deps,
  resource: NonNullable<Awaited<ReturnType<Deps['authorization']['findResource']>>>,
  identity: { ownerUserId: string },
) {
  const organizationIds = await activeIdentityOrganizationIds(deps, identity)
  if (!resource.availableToAgents || !activeResourceVisibleToAgent(resource, organizationIds)) {
    throw forbidden('Resource Server is not visible to this Agent.')
  }
}

async function activeIdentityOrganizationIds(deps: Deps, identity: { ownerUserId: string }) {
  const candidateIds = (await deps.authorization.listUserMemberships(identity.ownerUserId)).map(
    (membership) => membership.organizationId,
  )
  const organizations = await Promise.all(
    [...new Set(candidateIds)].map((organizationId) => deps.authorization.findOrganization(organizationId)),
  )
  return new Set(
    organizations.flatMap((organization) => (organization && !organization.disabled ? [organization.id] : [])),
  )
}

function activeResourceVisibleToAgent(resource: ApiResourceResponse, organizationIds: ReadonlySet<string>) {
  if (activePublicResource(resource)) return true
  return [...organizationIds].some((organizationId) => activeResourceVisibleToOrganization(resource, organizationId))
}

function toExternalAuthorization(record: ExternalResourceAuthorizationRecord) {
  return {
    resourceId: record.resourceId,
    connectorId: record.connectorId,
    resourceUrl: record.resourceUrl,
    issuer: record.issuer,
    authorizationEndpoint: record.authorizationEndpoint,
    tokenEndpoint: record.tokenEndpoint,
    pushedAuthorizationRequestEndpoint: record.pushedAuthorizationRequestEndpoint,
    authorizationDetailsTypesSupported: record.authorizationDetailsTypesSupported,
    authorizationDetailsCatalogEndpoint: record.authorizationDetailsCatalogEndpoint,
    authorizationDetailsCatalogScope: record.authorizationDetailsCatalogScope,
    registrationEndpoint: record.registrationEndpoint,
    revocationEndpoint: record.revocationEndpoint,
    jwksUri: record.jwksUri,
    userInfoEndpoint: record.userInfoEndpoint,
    registrationMode: record.registrationMode as 'dynamic' | 'manual',
    clientId: record.clientId,
    clientSecretConfigured: true as const,
    status: record.status as 'pending' | 'active' | 'invalid',
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
  }
}

function omitResourceId(value: ReturnType<typeof toExternalAuthorization>) {
  const { resourceId: _, ...authorization } = value
  return authorization
}

function toResourceConnection(record: ProviderResourceAuthorizationRecord) {
  return {
    id: record.id,
    resourceId: record.resourceId,
    owner: record.ownerUserId
      ? { type: 'user' as const, userId: record.ownerUserId }
      : { type: 'organization' as const, organizationId: record.ownerOrganizationId! },
    externalSubject: record.externalSubject,
    displayName: record.displayName,
    grantedScopes: record.grantedScopes,
    authorizationDetails: record.authorizationDetails,
    status: record.status as 'active' | 'suspended' | 'revoked',
    credentialExpiresAt: providerCredentialExpiry(record)?.toISOString() ?? null,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
  }
}

function toAgentAccessRequest(record: AgentAccessRequestRecord, hostId: string, approvalUrl: string | null) {
  return {
    id: record.id,
    resourceId: record.resourceId,
    connectionId: record.connectionId,
    agentIdentityId: record.agentIdentityId,
    hostId,
    scopes: record.scopes,
    authorizationDetails: record.authorizationDetails,
    reason: record.reason,
    status: record.status as 'pending' | 'approved' | 'denied' | 'consumed' | 'expired',
    approvalUrl,
    approvedEntitlements: record.approvedEntitlements,
    expiresAt: record.expiresAt.toISOString(),
    decidedAt: record.decidedAt?.toISOString() ?? null,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
  }
}

function toAccountConnection(record: ProviderResourceAuthorizationRecord): AccountConnection {
  return {
    id: record.id,
    apiResourceId: record.resourceId,
    owner: record.ownerUserId
      ? { type: 'user', userId: record.ownerUserId }
      : { type: 'organization', organizationId: record.ownerOrganizationId! },
    displayName: record.displayName,
    subjectHint: redactSubject(record.externalSubject),
    scopes: record.grantedScopes.filter((scope) => scope !== 'openid' && scope !== 'offline_access'),
    authorizationDetails: record.authorizationDetails,
    status: record.status as 'active' | 'suspended' | 'revoked',
    credentialExpiresAt: providerCredentialExpiry(record)?.toISOString() ?? null,
    authorizationUrl: null,
    expiresAt: null,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
  }
}

function toPendingAccountConnection(
  pending: Awaited<ReturnType<typeof createResourceConnectionIntent>>,
  scopes: string[],
): AccountConnection {
  return {
    id: pending.id,
    apiResourceId: pending.resourceId,
    owner: pending.owner,
    displayName: null,
    subjectHint: null,
    scopes,
    authorizationDetails: pending.authorizationDetails,
    status: 'pending_authorization',
    credentialExpiresAt: null,
    authorizationUrl: pending.authorizationUrl,
    expiresAt: pending.expiresAt,
    createdAt: pending.createdAt,
    updatedAt: pending.updatedAt,
  }
}

function toAccessRequest(
  request: ReturnType<typeof toAgentAccessRequest> | Awaited<ReturnType<typeof getAgentAccessRequest>>,
  apiOrigin = '',
): AccessRequest {
  const origin = apiOrigin.replace(/\/$/, '')
  const interactionStatus =
    request.status === 'pending'
      ? 'pending'
      : request.status === 'denied'
        ? 'denied'
        : request.status === 'expired'
          ? 'expired'
          : 'completed'
  const self = `${origin}/api/agent/access-requests/${encodeURIComponent(request.id)}`
  return {
    id: request.id,
    agentId: request.agentIdentityId,
    resourceServerId: request.resourceId,
    authorizationDetails: request.authorizationDetails,
    scopes: request.scopes,
    reason: request.reason,
    status: request.status,
    interaction: {
      type: 'user-approval',
      status: interactionStatus,
      url: interactionStatus === 'pending' ? request.approvalUrl : null,
      expiresAt: interactionStatus === 'pending' ? request.expiresAt : null,
    },
    links: {
      self,
      credentials: null,
    },
    credentialOffer: null,
    expiresAt: request.expiresAt,
    decidedAt: request.decidedAt,
    createdAt: request.createdAt,
    updatedAt: request.updatedAt,
  }
}

async function agentAccessRequestRepresentation(
  deps: Deps,
  request: ReturnType<typeof toAgentAccessRequest> | Awaited<ReturnType<typeof getAgentAccessRequest>>,
  apiOrigin: string,
): Promise<AccessRequest> {
  const representation = toAccessRequest(request, apiOrigin)
  if (request.status !== 'approved' && request.status !== 'consumed') {
    return representation
  }
  const entitlements = await activeContextEntitlements(deps, {
    agentIdentityId: request.agentIdentityId,
    resourceServerId: request.resourceId,
    connectionId: request.connectionId,
    authorizationDetails: request.authorizationDetails,
    now: new Date(),
  })
  if (entitlements.length === 0) return { ...representation, links: { ...representation.links, credentials: null } }
  const resourceServer = await requireEnabledResource(deps, request.resourceId)
  const authorization = await externalOAuthAuthorization(
    deps,
    resourceServer,
    request.connectionId
      ? providerCredentialGeneration((await deps.externalResources.findConnection(request.connectionId))!)
      : 1,
  )
  const credentials = `${representation.links.self}/credentials`
  return {
    ...representation,
    links: { ...representation.links, credentials },
    credentialOffer: {
      type: 'dpop',
      resourceIndicator: resourceServer.resourceUrl,
      authorizationDetails: request.authorizationDetails,
      scopes: entitlements.map((entitlement) => entitlement.scope),
      endpoint: credentials,
      proof: {
        algorithm: 'ES256',
        method: 'POST',
        uri: authorization?.tokenEndpoint ?? credentials,
      },
    },
  }
}

function toPermission(
  record: ResourceScopeEntitlementRecord,
  resource: { id: string; identifier: string; name: string },
): AgentPermission {
  return {
    id: record.id,
    agentId: record.agentIdentityId!,
    target: {
      type: 'api-resource',
      apiResourceId: record.resourceServerId,
      ...(record.connectionId ? { accountConnectionId: record.connectionId } : {}),
    },
    resource: { id: resource.id, identifier: resource.identifier, name: resource.name },
    scope: record.scope,
    authorizationDetails: record.authorizationDetails,
    mode: record.mode as AgentPermission['mode'],
    ...resourceScopeEntitlementLifecycle(record),
    sourceAccessRequestId: record.sourceAccessRequestId,
    expiresAt: record.expiresAt?.toISOString() ?? null,
    endedAt: record.endedAt?.toISOString() ?? null,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
    links: {
      self: `/api/agents/${encodeURIComponent(record.agentIdentityId!)}/permissions/${encodeURIComponent(record.id)}`,
    },
  }
}

function redactSubject(subject: string) {
  return subject.length <= 4 ? '••••' : `••••${subject.slice(-4)}`
}

function resourceConnectionCallbackUrl(origin: string) {
  return `${origin.replace(/\/$/, '')}/oauth/account-connection/callback`
}

function connectionIntentContext(intentId: string) {
  return `resource-connection-intent:${intentId}:pkce-verifier`
}

function providerCredentialTokensContext(credentialId: string, authorizationId: string) {
  return credentialId === authorizationId
    ? `resource-connection:${authorizationId}:tokens`
    : `provider-credential:${credentialId}:tokens`
}

function tokenLeaseContext(leaseId: string) {
  return `external-token-lease:${leaseId}:access-token`
}

function accessRequestTokenContext(requestId: string) {
  return `agent-access-request:${requestId}:approval-token`
}

function approvalUrl(origin: string, token: string) {
  return `${origin.replace(/\/$/, '')}/agent/access#token=${token}`
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return base64Url(new Uint8Array(digest))
}

function randomToken() {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)))
}

function base64(value: string) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(value)))
}

function base64Url(value: Uint8Array) {
  return btoa(String.fromCharCode(...value))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '')
}

function createProtocolId(prefix: string) {
  return `${prefix}_${crypto.randomUUID().replaceAll('-', '')}`
}
