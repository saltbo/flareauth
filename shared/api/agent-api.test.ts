import { createAgentPermissionSchema, createAgentSchema } from '@shared/api/agent-api'
import { describe, expect, it } from 'vitest'

const installation = {
  agentId: 'protocol-agent-1',
  hostId: 'host-1',
  name: 'Runner',
  kid: 'key-1',
}

function request(publicKey: Record<string, unknown>) {
  return {
    username: 'build-agent',
    name: 'Build Agent',
    runtime: 'ama',
    installation: { ...installation, publicKey },
  }
}

describe('Create Agent public JWK contract', () => {
  it('accepts only the Ed25519 Agent Auth verification-key profile', () => {
    expect(
      createAgentSchema.safeParse(
        request({
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'public-x',
          kid: 'key-1',
          alg: 'EdDSA',
          use: 'sig',
          key_ops: ['verify'],
        }),
      ).success,
    ).toBe(true)
  })

  it.each([
    ['X25519', { kty: 'OKP', crv: 'X25519', x: 'public-x', kid: 'key-1' }],
    ['EC', { kty: 'EC', crv: 'P-256', x: 'public-x', y: 'public-y', kid: 'key-1' }],
    ['RSA', { kty: 'RSA', n: 'public-modulus', e: 'AQAB', kid: 'key-1' }],
  ])('rejects the unsupported %s key profile', (_profile, publicKey) => {
    expect(createAgentSchema.safeParse(request(publicKey)).success).toBe(false)
  })

  it('rejects symmetric keys, private material, and unknown JWK members', () => {
    expect(createAgentSchema.safeParse(request({ kty: 'oct', k: 'secret', kid: 'key-1' })).success).toBe(false)
    expect(
      createAgentSchema.safeParse(request({ kty: 'OKP', crv: 'Ed25519', x: 'public-x', d: 'private', kid: 'key-1' }))
        .success,
    ).toBe(false)
    expect(
      createAgentSchema.safeParse(request({ kty: 'OKP', crv: 'Ed25519', x: 'public-x', kid: 'key-1', unknown: true }))
        .success,
    ).toBe(false)
  })

  it.each([
    ['alg', 'ES256'],
    ['use', 'enc'],
    ['key_ops', ['sign']],
    ['key_ops', ['verify', 'sign']],
  ])('rejects conflicting %s metadata', (member, value) => {
    expect(
      createAgentSchema.safeParse(request({ kty: 'OKP', crv: 'Ed25519', x: 'public-x', kid: 'key-1', [member]: value }))
        .success,
    ).toBe(false)
  })
})

describe('Direct Agent permission lifetime contract', () => {
  const input = { resource: 'https://projects.example.com/api', scopes: ['projects:read'] }
  it('[spec: agent-identity/direct-agent-permission] validates persistent and until lifetimes', () => {
    expect(createAgentPermissionSchema.safeParse({ ...input, mode: 'persistent' }).success).toBe(true)
    expect(createAgentPermissionSchema.safeParse({ ...input, scopes: [], mode: 'persistent' }).success).toBe(false)
    expect(
      createAgentPermissionSchema.safeParse({ ...input, authorizationDetails: [], mode: 'persistent' }).success,
    ).toBe(false)
    expect(
      createAgentPermissionSchema.safeParse({ ...input, mode: 'until', expiresAt: '2030-01-01T00:00:00Z' }).success,
    ).toBe(true)
    expect(createAgentPermissionSchema.safeParse({ ...input, mode: 'until' }).success).toBe(false)
    expect(
      createAgentPermissionSchema.safeParse({ ...input, mode: 'persistent', expiresAt: '2030-01-01T00:00:00Z' })
        .success,
    ).toBe(false)
  })
})
