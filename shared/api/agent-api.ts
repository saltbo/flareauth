import { z } from 'zod'
import { agentAuditEventSchema, agentHomeSpaceSchema, agentIdentityStatusSchema } from './agents'
import {
  apiResourceResponseSchema,
  authorizedResourceServerSchema,
  createApiResourceRequestSchema,
  listAuthorizedResourceServersQuerySchema,
  permissionListStatusSchema,
  updateApiResourceRequestSchema,
} from './authorization'
import {
  authorizationDetailCatalogItemSchema,
  authorizationDetailSchema,
  authorizationDetailsSchema,
} from './authorization-details'
import {
  agentAccessRequestStatusSchema,
  externalResourceAuthorizationSchema,
  permissionModeSchema,
} from './external-resources'
import { agentUsernameSchema } from './identifiers'
import { paginationMetadataSchema, paginationQuerySchema } from './pagination'

const nonEmptyString = z.string().trim().min(1)
const publicAgentJwkSchema = z
  .object({
    kty: z.literal('OKP'),
    crv: z.literal('Ed25519'),
    x: nonEmptyString,
    use: z.literal('sig').optional(),
    key_ops: z.tuple([z.literal('verify')]).optional(),
    alg: z.literal('EdDSA').optional(),
    kid: nonEmptyString.optional(),
  })
  .strict()
export const agentEnrollmentProfile = 'https://realmroot.dev/profiles/agent-enrollment'
const scopeListSchema = z
  .array(nonEmptyString)
  .min(1)
  .transform((values) => [...new Set(values)].sort())

export const agentSchema = z.object({
  id: z
    .string()
    .describe('Stable Agent resource identifier. New values are UUIDv7; legacy prefixed values remain readable.'),
  issuer: z.url(),
  subject: z
    .string()
    .describe('Stable OIDC subject. New Agent subjects are UUIDv7; historical values remain readable references.'),
  username: agentUsernameSchema.nullable(),
  name: z.string(),
  runtime: z.string().nullable(),
  homeSpace: agentHomeSpaceSchema,
  status: agentIdentityStatusSchema,
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
})

export const agentResponseSchema = z.object({ agent: agentSchema })
export const agentStatusSchema = z.object({
  enrollment: z.object({
    state: z.enum(['unenrolled', 'enrolled']),
    pending: z.null(),
  }),
  agent: agentSchema.nullable(),
  installation: z
    .object({
      id: z.string(),
      status: z.enum(['active', 'revoked']),
    })
    .nullable(),
})

export const createAgentSelfEnrollmentSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('new_identity'),
    username: agentUsernameSchema,
    nickname: z.string().trim().min(1).max(100).optional(),
    runtime: z.string().trim().min(1).max(100),
  }),
  z.object({
    kind: z.literal('additional_installation'),
    agentId: nonEmptyString,
  }),
])
export const createAgentSchema = z
  .object({
    username: agentUsernameSchema,
    name: z.string().trim().min(1).max(100),
    runtime: z.string().trim().min(1).max(100),
    installation: z
      .object({
        agentId: nonEmptyString,
        hostId: nonEmptyString,
        name: z.string().trim().min(1).max(100),
        kid: nonEmptyString,
        publicKey: publicAgentJwkSchema,
      })
      .strict(),
  })
  .strict()
export const managementAgentSchema = agentSchema.extend({
  owner: z.object({
    id: z.string(),
    type: z.literal('user'),
    displayName: z.string(),
  }),
  installationCount: z.number().int().nonnegative(),
  pendingRequestCount: z.number().int().nonnegative(),
  activeResourceCount: z.number().int().nonnegative(),
  activeScopeCount: z.number().int().nonnegative(),
})
export const managementAgentResponseSchema = z.object({ agent: managementAgentSchema })
export const agentsResponseSchema = z.object({
  items: z.array(agentSchema),
  pagination: paginationMetadataSchema,
})
export const managementAgentsResponseSchema = z.object({
  items: z.array(managementAgentSchema),
  pagination: paginationMetadataSchema,
})
export const listAgentsQuerySchema = paginationQuerySchema
export type ListAgentsQuery = z.infer<typeof listAgentsQuerySchema>
export const managementAgentAuditEventSchema = agentAuditEventSchema.extend({
  resource: z
    .object({
      id: z.string(),
      identifier: z.string(),
      name: z.string(),
    })
    .nullable(),
})
export const auditEventsResponseSchema = z.object({
  items: z.array(managementAgentAuditEventSchema),
  pagination: paginationMetadataSchema,
})
export const listAgentAuditEventsQuerySchema = paginationQuerySchema.extend({
  organizationId: nonEmptyString.optional(),
  agentId: nonEmptyString.optional(),
  search: z.string().trim().min(1).max(200).optional(),
  action: nonEmptyString.optional(),
  result: z.enum(['allowed', 'denied', 'pending']).optional(),
})
export type ListAgentAuditEventsQuery = z.infer<typeof listAgentAuditEventsQuerySchema>

export const managementAgentInstallationSchema = z.object({
  id: z.string(),
  name: z.string(),
  status: z.string(),
  credentialType: z.enum(['public_key', 'remote_jwks']),
  boundAt: z.iso.datetime(),
  lastSeenAt: z.iso.datetime().nullable(),
})
export const managementAgentInstallationsResponseSchema = z.object({
  items: z.array(managementAgentInstallationSchema),
  pagination: paginationMetadataSchema,
})

const managementAgentResourceSchema = z.object({
  id: z.string(),
  identifier: z.string(),
  name: z.string(),
})
export const createAgentPermissionSchema = z
  .object({
    resource: z.url(),
    scopes: z.array(nonEmptyString).min(1),
    mode: z.enum(['persistent', 'until']),
    expiresAt: z.iso.datetime().optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if ((value.mode === 'until') !== Boolean(value.expiresAt)) {
      context.addIssue({ code: 'custom', path: ['expiresAt'], message: 'Only until permissions require an expiry.' })
    }
  })
export type CreateAgentPermission = z.infer<typeof createAgentPermissionSchema>

export const agentPermissionSchema = z.object({
  id: z.string(),
  agentId: z.string(),
  target: z.object({
    type: z.literal('api-resource'),
    apiResourceId: z.string(),
    accountConnectionId: z.string().optional(),
  }),
  resource: managementAgentResourceSchema,
  scope: z.string(),
  authorizationDetails: authorizationDetailsSchema,
  mode: permissionModeSchema,
  status: z.enum(['active', 'ended']),
  sourceAccessRequestId: z.string().nullable(),
  endedAt: z.iso.datetime().nullable(),
  endReason: z.enum(['revoked', 'consumed', 'expired', 'merged']).nullable(),
  expiresAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
  links: z.object({ self: z.string() }),
})
export const createdAgentPermissionsResponseSchema = z.object({ items: z.array(agentPermissionSchema) })

export const agentPermissionsResponseSchema = z.object({
  items: z.array(agentPermissionSchema),
  pagination: paginationMetadataSchema,
})
export const listAgentPermissionsQuerySchema = paginationQuerySchema.extend({
  resourceServerId: nonEmptyString.optional(),
  status: permissionListStatusSchema.optional(),
})
export const listAgentAuthorizedResourceServersQuerySchema = listAuthorizedResourceServersQuerySchema
export const agentAuthorizedResourceServersResponseSchema = z.object({
  items: z.array(authorizedResourceServerSchema),
  pagination: paginationMetadataSchema,
})

export const agentEnrollmentStatusSchema = z.enum(['pending', 'approved', 'denied', 'expired', 'cancelled'])
export const agentEnrollmentSchema = z.object({
  id: z.string(),
  agentId: z.string().nullable(),
  nickname: z.string(),
  username: agentUsernameSchema.nullable(),
  runtime: z.string().nullable(),
  kind: z.enum(['new_identity', 'additional_host']),
  homeSpace: agentHomeSpaceSchema,
  status: agentEnrollmentStatusSchema,
  expiresAt: z.iso.datetime(),
  decidedAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
})

export const createAgentEnrollmentSchema = z.object({
  username: agentUsernameSchema,
  nickname: z.string().trim().min(1).max(100).optional(),
  runtime: z.string().trim().min(1).max(100),
})

export const createAgentInstallationEnrollmentSchema = z.object({
  agentId: nonEmptyString,
})

export const agentInstallationEnrollmentSchema = agentEnrollmentSchema.extend({
  kind: z.literal('additional_host'),
})

export const agentInstallationEnrollmentResponseSchema = z.object({
  enrollment: agentInstallationEnrollmentSchema,
  verificationUri: z.url(),
})

export const agentEnrollmentResponseSchema = z.object({
  enrollment: agentEnrollmentSchema,
  verificationUri: z.url(),
})

export const decideAgentEnrollmentSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('identity'),
    decision: z.literal('approve'),
  }),
  z.object({
    kind: z.literal('protocol'),
    decision: z.enum(['approve', 'deny']),
    userCode: nonEmptyString,
  }),
])

export const apiResourceAuthorizationSchema = externalResourceAuthorizationSchema.omit({ resourceId: true })
export const createApiResourceSchema = createApiResourceRequestSchema
export const updateApiResourceSchema = updateApiResourceRequestSchema

export const resourceServerConnectionSummarySchema = z.object({
  status: z.enum(['connected', 'not_connected', 'not_required']),
  displayName: z.string().nullable(),
  authorizedScopes: z.array(z.string()),
})

export const resourceServerSchema = apiResourceResponseSchema.extend({
  authorization: apiResourceAuthorizationSchema.nullable(),
  availability: z.object({
    status: z.enum(['available', 'unavailable']),
    checkedAt: z.iso.datetime(),
  }),
  scopes: z.array(z.object({ value: z.string(), description: z.string().nullable() })),
  connection: resourceServerConnectionSummarySchema.nullable(),
  links: z.object({
    self: z.url(),
    authorizationDetails: z.url(),
  }),
})

export const resourceServersResponseSchema = z.object({
  items: z.array(resourceServerSchema),
  pagination: paginationMetadataSchema,
})

export const apiResourceSchema = resourceServerSchema
export const apiResourcesResponseSchema = resourceServersResponseSchema

export const resourceServerAuthorizationDetailSchema = z.object({
  id: nonEmptyString.nullable(),
  authorizationDetail: authorizationDetailSchema,
  name: nonEmptyString,
  description: z.string().nullable(),
  metadata: z.record(nonEmptyString, z.string()),
  accountAuthorizationStatus: z.enum(['authorized', 'authorization_required', 'not_required']),
  authorizedScopes: z.array(z.string()),
  requestableScopes: z.array(z.string()),
})

export const resourceServerAuthorizationDetailsResponseSchema = z.object({
  items: z.array(resourceServerAuthorizationDetailSchema),
  pagination: paginationMetadataSchema,
})

// Controller-facing approval data keeps the provider protocol payload private
// from Agents while allowing the hosted consent page to submit the exact RAR boundary.
export const authorizationDetailCatalogEntrySchema = authorizationDetailCatalogItemSchema.extend({
  connectionStatus: z.enum(['authorized', 'authorization_required']),
  authorizedScopes: z.array(z.string()),
  requestableScopes: z.array(z.string()),
})
export const authorizationDetailCatalogResponseSchema = z.object({
  items: z.array(authorizationDetailCatalogEntrySchema),
  pagination: paginationMetadataSchema,
  connection: z.object({ status: z.enum(['connected', 'not_connected']) }),
})

export const interactionStatusSchema = z.enum(['pending', 'completed', 'denied', 'expired', 'failed'])
export const interactiveResourceProfile = 'https://realmroot.dev/profiles/interactive-resource'
export const credentialOfferProfile = 'https://realmroot.dev/profiles/resource-credential-offer'

export const interactionSchema = z.object({
  type: z.literal('user-approval'),
  status: interactionStatusSchema,
  url: z.url().nullable(),
  expiresAt: z.iso.datetime().nullable(),
})

export const targetCredentialProofSchema = z.object({
  proof: z.object({ type: z.literal('dpop+jwt'), value: nonEmptyString }),
})

export const dpopNonceErrorResponseSchema = z.object({
  error: z.literal('use_dpop_nonce'),
  error_description: nonEmptyString,
})

export const resourceLinksSchema = z.object({ self: nonEmptyString })

export const capabilityRequestSchema = z.object({
  id: z.string(),
  agentId: z.string(),
  capabilities: z.array(z.object({ value: z.string(), status: z.string() })),
  status: z.enum(['pending', 'completed', 'denied', 'expired', 'failed']),
  interaction: interactionSchema,
  links: resourceLinksSchema,
  createdAt: z.iso.datetime(),
  expiresAt: z.iso.datetime().nullable(),
})

export const connectableApiResourcesResponseSchema = z.object({
  items: z.array(
    z.object({
      id: z.string(),
      identifier: z.string(),
      name: z.string(),
      resourceUrl: z.url(),
    }),
  ),
  pagination: paginationMetadataSchema,
})

export const accountConnectionStatusSchema = z.enum(['pending_authorization', 'active', 'suspended', 'revoked'])
export const accountConnectionSchema = z.object({
  id: z.string(),
  apiResourceId: z.string(),
  owner: z.discriminatedUnion('type', [
    z.object({ type: z.literal('user'), userId: z.string() }),
    z.object({ type: z.literal('organization'), organizationId: z.string() }),
  ]),
  displayName: z.string().nullable(),
  subjectHint: z.string().nullable(),
  scopes: z.array(z.string()),
  authorizationDetails: authorizationDetailsSchema,
  status: accountConnectionStatusSchema,
  credentialExpiresAt: z.iso.datetime().nullable(),
  authorizationUrl: z.url().nullable(),
  expiresAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
})

export const createAccountConnectionSchema = z.discriminatedUnion('context', [
  z
    .object({
      context: z.literal('resource'),
      apiResourceId: nonEmptyString,
      owner: z
        .discriminatedUnion('type', [
          z.object({ type: z.literal('user') }),
          z.object({ type: z.literal('organization'), organizationId: nonEmptyString }),
        ])
        .default({ type: 'user' }),
      scopes: scopeListSchema,
    })
    .strict(),
  z
    .object({
      context: z.literal('access-request'),
      accessRequestId: nonEmptyString,
      approvalToken: nonEmptyString,
    })
    .strict(),
])

export const accountConnectionsResponseSchema = z.object({
  items: z.array(accountConnectionSchema),
  pagination: paginationMetadataSchema,
})

export const createAccessRequestSchema = z
  .object({
    resourceServerId: nonEmptyString,
    scopes: scopeListSchema,
    authorizationDetails: authorizationDetailsSchema.default([]),
    reason: z.string().trim().max(500).nullable().optional(),
  })
  .strict()

export const accessRequestSchema = z.object({
  id: z.string(),
  agentId: z.string(),
  resourceServerId: z.string(),
  authorizationDetails: authorizationDetailsSchema,
  scopes: z.array(z.string()),
  reason: z.string().nullable(),
  status: agentAccessRequestStatusSchema,
  interaction: interactionSchema,
  links: resourceLinksSchema.extend({ credentials: nonEmptyString.nullable() }),
  credentialOffer: z
    .object({
      type: z.literal('dpop'),
      resourceIndicator: z.url(),
      authorizationDetails: authorizationDetailsSchema,
      scopes: scopeListSchema,
      endpoint: z.url(),
      proof: z.object({ algorithm: z.literal('ES256'), method: z.literal('POST'), uri: z.url() }),
    })
    .nullable(),
  expiresAt: z.iso.datetime(),
  decidedAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
})

export const accessRequestsResponseSchema = z.object({
  items: z.array(accessRequestSchema),
  pagination: paginationMetadataSchema,
})

export const accessRequestApprovalSchema = accessRequestSchema.extend({
  requiresAccountConnection: z.boolean(),
  agent: z.object({ id: z.string(), name: z.string() }),
  resourceServer: z.object({ id: z.string(), name: z.string() }),
  authorizationDetail: z
    .object({
      name: z.string(),
      description: z.string().nullable(),
      metadata: z.record(z.string(), z.string()),
      authorizationDetailTemplates: authorizationDetailsSchema,
    })
    .nullable(),
})

export const accessRequestApprovalsResponseSchema = z.object({
  items: z.array(accessRequestApprovalSchema),
  pagination: paginationMetadataSchema,
})

export const decideAccessRequestSchema = z
  .object({
    decision: z.enum(['approve', 'deny']),
    mode: permissionModeSchema.optional(),
    expiresAt: z.iso.datetime().optional(),
    authorizationDetails: authorizationDetailsSchema.default([]),
    approvalToken: nonEmptyString.optional(),
  })
  .superRefine((input, ctx) => {
    if (input.decision === 'approve' && !input.mode) {
      ctx.addIssue({ code: 'custom', path: ['mode'], message: 'Approval mode is required.' })
    }
    if (input.mode === 'until' && !input.expiresAt) {
      ctx.addIssue({ code: 'custom', path: ['expiresAt'], message: 'Limited approval requires expiresAt.' })
    }
  })

export const targetTokenSchema = z.object({
  accessToken: z.string(),
  tokenType: z.literal('DPoP'),
  expiresIn: z.number().int().positive().max(3600),
  expiresAt: z.iso.datetime(),
  scopes: z.array(z.string()),
  authorizationDetails: authorizationDetailsSchema,
  resourceIndicator: z.url(),
})

export type Agent = z.infer<typeof agentSchema>
export type ManagementAgent = z.infer<typeof managementAgentSchema>
export type CreateAgent = z.infer<typeof createAgentSchema>
export type ManagementAgentInstallation = z.infer<typeof managementAgentInstallationSchema>
export type ManagementAgentAuditEvent = z.infer<typeof managementAgentAuditEventSchema>
export type ListAgentPermissionsQuery = z.infer<typeof listAgentPermissionsQuerySchema>
export type AgentEnrollment = z.infer<typeof agentEnrollmentSchema>
export type ApiResource = ResourceServer
export type ConnectableApiResourcesResponse = z.infer<typeof connectableApiResourcesResponseSchema>
export type AccountConnection = z.infer<typeof accountConnectionSchema>
export type AuthorizationDetailCatalogEntry = z.infer<typeof authorizationDetailCatalogEntrySchema>
export type CreateAccountConnection = z.infer<typeof createAccountConnectionSchema>
export type CreateAccessRequest = z.input<typeof createAccessRequestSchema>
export type AccessRequest = z.infer<typeof accessRequestSchema>
export type AccessRequestApproval = z.infer<typeof accessRequestApprovalSchema>
export type DecideAccessRequest = z.input<typeof decideAccessRequestSchema>

export type AgentPermission = z.infer<typeof agentPermissionSchema>
export type ResourceServer = z.infer<typeof resourceServerSchema>
export type ResourceServerAuthorizationDetail = z.infer<typeof resourceServerAuthorizationDetailSchema>
