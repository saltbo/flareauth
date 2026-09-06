Feature: Agent identity and delegated API authorization
  As an Agent controller
  I want Agents to have durable identities and request constrained access to connected API resources
  So that Agents can act independently or by delegation without receiving refresh tokens

  Background:
    Given a first admin exists
    And Agent identity is enabled for the tenant

  Rule: Public APIs expose product resources rather than security implementation records

    @entrypoint:agent-protocol @journey:agent-public-resource-model @proof:unit
    Scenario: API clients manage stable product aggregates
      Given Agent identity uses protocol registrations, host credentials, and identity bindings internally
      And external authorization uses discovery metadata, OAuth clients, connection state, and token leases internally
      When an Agent, controller, or administrator reads the Realmroot API contract
      Then the public resources are Agents, Agent installations, Agent installation enrollments, API resources, account connections, Agent access requests, Permissions, and audit events
      And the authenticated Agent addresses its access requests below `/agent/access-requests`
      And Agent registrations, hosts, identity bindings, connection intents, OAuth integration records, and token leases remain private implementation records
      And each public resource has one canonical URI in its caller boundary
      And Agent installation representations never expose internal Host identifiers

  Rule: Agent identities remain stable across hosts and credentials

    @entrypoint:agent-protocol @journey:agent-identity-enrollment @proof:unit
    Scenario: A new Agent explicitly establishes a stable identity
      Given a new Agent connects Restish to the Realmroot OpenAPI contract
		When the Agent invokes enrollment with an explicit username, optional nickname, and its detected runtime
      Then the Restish authentication adapter registers locally generated host and Agent keys
      And Realmroot preserves the requested username without deriving it from another field
      And an omitted nickname defaults to the detected runtime while the Host is named after its local device
      And enrollment waits while an authorized controller approves the Agent once from the hosted enrollment page
      And the adapter creates a personal stable identity through the approved Agent session
      Then Realmroot creates an Agent with a stable issuer and subject
      And Realmroot assigns the requested immutable username independently of the Agent's nickname
      And the Agent belongs to exactly one concrete User
      And users govern the Agent through explicit Permissions in that space
      And the host registration is bound to that Agent identity
      And the enrollment operation returns the stable Agent enrollment
      And before the enrollment command returns the adapter resolves and durably stores the stable Agent issuer and subject
      And losing that successful response and retrying enrollment returns the same enrollment without creating another identity
      And the hosted approval page replaces the request with a clear completion state that says it can be closed
      And later OpenAPI operations reuse the Agent identity without another login command
      And whoami only reads the already established identity and never completes enrollment as a side effect
      And the adapter requests only the exact bootstrap scopes required by each operation
      And a configured Realmroot Resource credential source delegates published bootstrap scopes to that same Agent identity
      And enrollment alone grants no management or external API resource access
      And an unbound protocol registration cannot exercise Agent identity capabilities

    @entrypoint:restish @journey:application-agent-creation @proof:unit
    Scenario: An authorized Application creates a User-owned Agent directly
      Given an Application acts on behalf of a User and has agents:write authority
      When the Application creates an Agent with its public installation credential
      Then Realmroot creates one active stable Agent and its initial installation
      And the represented User owns and controls the stable Agent and installation
      And Realmroot returns the stable issuer and a UUID version 7 subject
      And every new identity, binding, and audit identifier is an unprefixed UUID version 7
      And no account approval or enrollment decision resource is created
      And retrying the same request with the same idempotency key returns the same Agent
      And a retry first completed before the UUID version 7 rollout returns that historical Agent and records its durable idempotency reservation
      And reusing the idempotency key with different Agent data is rejected
      And historical prefixed Agent identities remain readable without being generated again
      And the original self-enrollment interface and approval behavior are unchanged

    @entrypoint:restish @journey:agent-whoami-requires-enrollment @proof:unit
    Scenario: Agent identity inspection never creates an identity implicitly
      Given Restish has no local Realmroot Agent registration
      When the Agent invokes the generated whoami command
      Then the command fails with guidance to invoke the generated Agent enrollment command
      And Restish does not create keys, open a browser, or create an Agent identity

    @entrypoint:restish @journey:agent-single-cli-principal @proof:unit
    Scenario: Command-line operations always use the Agent principal
      Given an Agent has established a stable identity in Restish
      When the Agent invokes any operation discovered from the Realmroot OpenAPI contract
      Then Realmroot authenticates the request as that Agent identity
      And the Realmroot adapter is the explicit default for Realmroot oauth2 operations unless the caller selects a configured credential override
      And Realmroot never substitutes the approving user's identity for the Agent
      And the controller's browser session is used only to approve enrollment or authority
      And the CLI requests bootstrap authority with the reserved client_id realmroot-cli
      And Realmroot issues an RFC 9068 DPoP-bound bootstrap token with the stable Agent as subject
      And the bootstrap and Resource access tokens carry the runtime's raw session ID in the private Agent binding claim
      And the bootstrap token contains no actor claim or public Host claim
      And previously issued legacy Agent tokens remain accepted only until their existing expiry

    @entrypoint:product-ui @journey:agent-enrollment-denial @proof:unit
    Scenario: A controller can deny Agent enrollment
      Given an Agent enrollment request is pending
      When the authorized controller denies the request
      Then Realmroot resolves the enrollment as denied
      And the hosted approval page clearly says the request was denied and can be closed
      And the waiting Realmroot command exits without receiving an Agent identity

    @entrypoint:product-ui @journey:agent-management-authority @proof:unit
    Scenario: Agent control is established by one authoritative approval
      Given an unowned Agent requests enrollment for the authenticated User
      When that User approves the enrollment
      Then that concrete User becomes the Agent owner
      And only that owner can establish the stable Agent identity
      And later management requests authenticate as the Agent without substituting the controller
      And Realmroot records one authoritative approval outcome

    @entrypoint:agent-protocol @journey:agent-multi-host-continuity @proof:integration
    Scenario: One Agent identity can be used from independently secured hosts
      Given an Agent identity has an active host registration
      When the Agent client requests another enrollment for that stable Agent from a host with a different public key and an idempotency key
      Then Realmroot creates a pending Agent installation enrollment and returns its hosted approval URL
      And the Agent client can poll that installation enrollment through its canonical Agent protocol URI
      And retrying with the same idempotency key returns that same installation enrollment
      When an authorized controller approves the hosted enrollment
      Then both host registrations resolve to the same Agent issuer and subject
      And neither host receives the other host's private key

    @entrypoint:agent-protocol @journey:agent-host-revocation @proof:integration
    Scenario: Revoking one host does not revoke the Agent identity
      Given an Agent identity has two active host registrations
      When a controller revokes one host
      Then that host can no longer authenticate as the Agent
      And the other host and the Agent identity remain active

    @entrypoint:product-ui @journey:agent-identity-recovery @proof:integration
    Scenario: A controller replaces compromised Agent credentials without changing its subject
      Given an Agent's host credentials may be compromised
      When an authorized controller recovers the Agent
      Then every existing host credential and session is revoked
      And external API resource entitlements are frozen
      And the Agent becomes inactive without entering a recovering state
      And the Agent keeps the same issuer and subject

    @entrypoint:product-ui @journey:agent-identity-deletion @proof:integration
    Scenario: A soft-deleted Agent subject is never reassigned
      Given an Agent has a stable issuer and subject
      When an authorized controller deletes the Agent
      Then the Agent can no longer authenticate, receive grants, or be queried through an interface
      And its subject remains reserved for historical audit records
      And its username and installation identifiers remain reserved and return conflict when reused
      And no interface can restore it

    @entrypoint:agent-protocol @journey:agent-stable-issuer @proof:unit
    Scenario: Agent identity uses the deployment's existing OIDC issuer
      Given Realmroot is reached through a non-canonical request origin
      When a controller approves an Agent enrollment
      Then the Agent issuer is the Better Auth OIDC issuer
      And preview or request origins do not change the Agent issuer and subject
      And DPoP request binding and Agent links use only an origin allowed by TRUSTED_ORIGINS
      And hosted Agent approval URLs use the configured deployment origin
      And Realmroot does not publish a second Agent-only OIDC issuer

    @entrypoint:product-ui @journey:public-agent-profile @proof:unit
    Scenario: External visitors resolve a stable public Agent profile
      Given a non-deleted Agent has a stable issuer and subject
      When an external visitor requests the Agent by its stable subject or immutable username
      Then Realmroot returns the Agent's public identity
      And the public identity includes its immutable human-readable username
      And picture resolves to the Realmroot static file "/agent-picture-v1.svg" until the Agent has a custom picture
      And the default summary omits owner and activity
      And the full view includes the public owner, activity overview, annual heatmap, and sanitized recent activity
      And Agent configuration and OAuth authorization-server discovery publish the public Agent Profile URI template keyed by subject
      And browser clients can read issuer-path OAuth and OpenID discovery across origins
      And permits each view to be cached and revalidated independently
      But the public profile never returns Host, role, scope, grant, Resource, or authorization state
      And the public profile is never authoritative for authentication or authorization

  Rule: Resource Servers expose authorization details through one Agent access workflow

    @entrypoint:agent-protocol @journey:realmroot-built-in-resource-server @proof:unit
    Scenario: Realmroot exposes its own API as a system-managed Resource Server
      Given a Realmroot deployment has completed onboarding
      And its persisted system-managed scope registry predates the current Realmroot scope catalog
      When an Agent lists Resource Servers
      Then exactly one enabled native Resource Server represents that deployment's Realmroot API
      And its service URL and OAuth resource indicator use the deployment's canonical API URL
      And Realmroot reconciles its persisted scope registry to the current system-managed catalog
      And agents:write is granted automatically so authorized Applications may create a User's Agent without a direct User permission
      And refreshing that registry returns the same current catalog without an external network dependency
      And its account connection status is not-required
      And it cannot be disabled, soft-deleted, or reassigned through tenant management
      When the Agent lists that Resource Server's authorization details
      Then the built-in platform Organization, ordinary Organization, and personal User details reflect the controller tenant boundaries available for approval
      And the platform Organization detail supplies platform-wide management scopes
      And each Organization or User detail supplies only scopes valid for that tenant boundary
      And every controller can approve scopes only within the selected authorization detail boundary
      And a platform Organization credential retains only the Agent's automatic protocol scopes plus approved management scopes
      And a token for one authorization detail cannot authorize another authorization detail
      When the Agent reads Resource Servers with either bootstrap or resource-bound authority
      Then Realmroot returns the same canonical Resource Server representation
      And the credential authority changes only which Resource Servers the Agent may read or mutate

    @entrypoint:agent-protocol @journey:agent-resource-server-model @proof:unit
    Scenario: An Agent discovers Resource Servers before provider authorization details
      Given Realmroot has registered native and external Resource Servers
      When the Agent lists Resource Servers
      Then each item identifies one protected API service, its service URL, OAuth resource indicator, availability, and account connection status
      And the Agent-facing contract does not call a Resource Server an API Resource
      When the Agent lists one Resource Server's authorization details
      Then each item exposes one RFC 9396 authorization detail, flat safe display metadata, and a stable Context ID when its source defines one
      And each item separately reports account authorization status, Agent-authorized scopes, and requestable scopes
      And an Organization owner may approve current assigned scopes of a Resource Server owned by that Organization
      And native User and Organization Context IDs are their tenant IDs while external Context IDs come from the Resource Server catalog
      And an access request copies the selected authorization detail directly while the Context ID remains only its selector

    @entrypoint:agent-protocol @journey:external-resource-authorization-detail-catalog @proof:unit
    Scenario: An Agent discovers display-safe authorization details from an external Resource Server
      Given an external Resource Server's authorization server advertises an authorization-detail catalog endpoint
      And the Agent's controller has an active external Resource authorization
      When the Agent lists that Resource Server's authorization details
      Then Realmroot authenticates the catalog read with a refreshed external subject token
      And each connected detail uses the Resource Server supplied display name, description, and safe attributes
      And Realmroot reports the Agent's authorized and requestable scopes for that exact detail
      But the external provider credential is never returned to the Agent

    @entrypoint:agent-protocol @journey:agent-private-resource-server-visibility @proof:unit
    Scenario: A private Resource Server stays inside its owner Organization boundary
      Given a private Resource Server is owned by an Organization and available to Agents
      And a personal Agent's controller is an active member of that Organization
      When the Agent lists Resource Servers or that Resource Server's authorization details
      Then the private Resource Server is visible to that Agent
      But it remains hidden from Agents outside the owner Organization
      And discovery grants no Resource scope or credential

    @entrypoint:product-ui @journey:native-api-resource-registration @proof:integration
    Scenario: An administrator registers a native API that trusts Realmroot
      Given a product uses Realmroot as its OIDC provider and OAuth authorization server
      When an administrator creates an API resource with native authorization mode
      Then the administrator configures one protected resource URL
      And Realmroot uses that URL as the OAuth resource identifier and access-token audience
      And without a Provider Connector no external authorization server, OAuth client, or account connection is configured
      And the product API validates Realmroot access tokens with the published issuer and JWKS
      And the protected resource publishes its requestable scopes through RFC 9728 metadata
      And the protected resource advertises its OpenAPI contract with a standard service-desc link
      And Realmroot derives its local scope registry from that protected-resource metadata
      And scope registry refresh first refreshes dynamic connector metadata before validating provider compatibility
      And OpenAPI may add descriptions and maps operations only to advertised scopes
      And advertised scopes remain valid even when no public operation references them
      And Realmroot stores only discovered scope metadata and local grant modes, never either source document

    @entrypoint:product-ui @journey:api-resource-contract-validation @proof:unit
    Scenario: API resources require a discoverable OpenAPI contract
      Given an API resource URL cannot be reached or does not return a successful service-desc response
      When an administrator creates or enables the API resource, including a disabled registration
      Then Realmroot rejects the request without enabling the resource
      And a network failure identifies whether the resource or its OpenAPI document was unreachable
      When the administrator enables an existing draft or changes an enabled resource URL
      Then Realmroot validates the exact resource URL before saving the change

    @entrypoint:agent-protocol @journey:native-api-resource-access-request @proof:unit
    Scenario: An Agent requests access to a native API
      Given an enabled native API resource belongs to the Agent's home space
      When the Agent lists available resources
      Then Realmroot returns that resource and its protected resource URL without requiring an account connection
      When Restish reads the target OpenAPI operation and the Agent requests its Resource Server and exact scope set
      Then Realmroot validates that scope set against the local target scope registry
      And the request selects exactly one realmroot_authority Context for a User or Organization visible to the Agent
      And every visible native Resource lists a personal Agent's User Context and every active Organization Context
      And private Resource visibility is checked before that Context catalog is exposed
      And missing, multiple, malformed, or unavailable Contexts fail closed
      And before creating or resuming a pending request Realmroot verifies the controller currently holds every requested scope inside only the selected Context
      And a scope outside that boundary is rejected without creating an approval request or notification
      And the server returns HTTP 400 with the existing "bad_request" error code, a message, and the selected Context and offending scopes in error details
      And User Context scopes include only automatic scopes and direct Permissions with no Organization
      And Organization Context scopes include only automatic scopes, matching Organization direct Permissions, and matching membership Roles
      And NULL direct Permissions never fall back to the Resource owner Organization
      And direct and Role scopes from another Organization do not cross that Context boundary
      And Realmroot creates the same pending access-request resource used for external APIs
      And it does not require a user-created authority grant or grant identifier
      When an authorized controller approves the request
      Then the approval preserves the exact requested authorization details without an Account Connection
      Then Realmroot creates the same per-scope Permissions used for external APIs

    @entrypoint:agent-protocol @journey:native-api-automatic-agent-permission @proof:unit
    Scenario: A personal Agent requests only automatic scopes from a native API
      Given an enabled native API resource marks every requested scope as automatic
      And the personal Agent selects a current Realmroot authority Context controlled by its owner User
      When the Agent requests that exact scope set
      Then Realmroot approves the access request without controller interaction
      And Realmroot creates persistent per-scope Agent Permissions through the normal approval path
      And any assigned scope keeps the access request pending for controller approval
      But an unavailable Context is rejected without creating a request or Permission

    @entrypoint:agent-protocol @journey:agent-resource-discovery-isolation @proof:unit
    Scenario: An unavailable API resource does not block resource discovery
      Given multiple enabled API resources are visible to an Agent
      And one resource cannot publish its current OpenAPI contract
      When the Agent lists available resources
      Then Realmroot returns the resource with unavailable status and no requestable scopes
      And returns every available resource with available status and its current requestable scopes

  @entrypoint:agent-protocol @journey:agent-resource-access-without-role @proof:unit
    Scenario: An Agent requests resource access without a Role model
      Given an enabled API resource publishes the requested assigned scope in its local registry
      When the Agent requests that exact scope
      Then Realmroot allows the access request to proceed to controller approval
      And the controller may approve only scopes within the controller's effective scope set
      And the approved request stores the exact Permission snapshot without a roles claim

    @entrypoint:agent-protocol @journey:native-api-resource-token @proof:unit
    Scenario: An Agent calls a native API directly
      Given a controller approved an exact native API resource request
      When Restish accepts the approved access request's credential offer
      Then the Realmroot plugin creates and retains a separate DPoP key
      And the plugin sends the DPoP proof in the standard DPoP header
      Then Realmroot issues a short-lived audience-bound JWT access token
      And the token uses the Better Auth issuer and signing keys
      And the token identifies the controller as subject and the stable Agent as the RFC 8693 actor
      And the Agent actor carries only its issuer and stable subject
      And the Realmroot-issued token identifies the presenting CLI with client_id realmroot-cli
      And the Host remains internal credential, binding, revocation, and audit context
      And the approved access request remains an audit record of the scopes approved in that interaction
      And its credential offer exposes the Context's one current cumulative scope set
      And the token carries every currently active Permission for the same Agent, Resource Server, Account Connection, and authorization details
      And a later expansion replaces the client's Context credential instead of creating a selectable historical offer
      And revoking one Permission removes only that scope from subsequently issued tokens
      And an Organization Context token carries only that selected Organization claim and groups
      And the same personal Agent receives different Organization claims when it selects different Organization Contexts
      And a User Context token has no Organization claim, regardless of the Agent home Organization or Resource owner
      And the token does not contain Agent roles
      And the token is bound to the Agent's DPoP key
      And Restish stores but does not print the raw access token
      When the Agent connects Restish to the discovered protected resource URL
      Then Restish discovers the target OpenAPI contract from its standard service-desc link
      When the Agent invokes a generated target operation
      Then the plugin sends the access token and a fresh DPoP proof directly to the product API
      And the product API validates the token type, signature, issuer, audience, expiry, scopes, and DPoP binding

    @entrypoint:agent-protocol @journey:agent-resource-entitlement-policy @proof:unit
    Scenario: Both API authorization modes enforce the same Permissions
      Given an Agent requests a target token for an API resource
      When no active Permissions permit the Agent, resource, scopes, and lifetime
      Then Realmroot denies the request
      And the Agent cannot substitute another account connection or resource
      When active Permissions permit the request
      Then the token issuer is selected only from the API resource authorization mode
      And one-time, limited, persistent, revocation, and audit behavior is consistent across both modes

  Rule: Workload token exchange preserves authorization boundaries

    @entrypoint:agent-protocol @journey:agent-oidc-id-token-exchange @proof:unit
    Scenario: A native Resource Server exchanges an Agent token for an OIDC ID token
      Given a confidential Application has an explicit source Resource Server to target OIDC Application policy
      And the target is an active private OIDC Application in the same Organization
      When the Application exchanges an active Agent access token issued for the configured source Resource Server
      Then Realmroot issues a short-lived ID token for the target Application client ID
      And the token preserves the controller User in sub and the stable Agent in act
      And current Organization Team names are emitted as groups without source Resource scopes or a refresh token
      But an inactive source token, Agent, controller, membership, source, target, or missing policy is rejected and audited

    @entrypoint:agent-protocol @journey:user-resource-token-delegation @proof:unit
    Scenario: A Resource Server exchanges an inbound User token for a narrower downstream token
      Given a confidential Application has an explicit source-to-target Resource Server scope mapping
      And the Application is entitled to the requested scopes on a downstream Resource Server
      And the User is entitled to the mapped scopes on that downstream Resource Server
      When the Application exchanges a valid Realmroot access token whose audience is the configured source Resource Server
      Then Realmroot issues a short-lived access token for the downstream Resource Server
      And its scopes are the intersection of the request, current source mapping, Application Permissions, and User Context Permissions
      And the downstream token preserves the User subject and identifies the authenticated Application as client_id
      And the downstream token contains no act claim and no refresh token is issued
      But an unmapped source or target, an empty scope intersection, or an unavailable target is rejected

    @entrypoint:agent-protocol @journey:agent-resource-token-delegation @proof:unit
    Scenario: A Resource Server exchanges an inbound Agent token without losing its actor chain
      Given a confidential Application has an explicit source-to-native-target Resource Server scope mapping
      And an active Agent token, identity binding, and controller authorize the source Resource Server in a personal or Organization Context
      And the Application and controller are entitled to the requested downstream scopes
      When the Application exchanges that Agent token for the configured downstream Resource Server
      Then Realmroot applies the same request, source mapping, Application Permission, and controller Context intersection
      And the downstream token preserves the controller User in sub and the stable Agent in act
      And the authenticated Application is identified as client_id without issuing a refresh token
      And a short-lived delegated Agent token may continue through another explicitly mapped Application and Resource Server hop
      But an inactive token lease, Agent, binding, controller, Organization membership when present, source, target, external target, or policy is rejected

    @entrypoint:product-ui @journey:connector-backed-connection-revocation @proof:unit
    Scenario: Revoking a connector-backed account connection revokes provider authority first
      Given an active connector-backed account connection has provider access and refresh tokens
      When its controller revokes the connection
      Then Realmroot revokes the provider refresh token and access token before ending Permissions, Token Leases, and local connection state
      But a temporary provider failure leaves the local connection active and returns an explicit retryable failure

    @entrypoint:agent-protocol @journey:workload-token-exchange-claims @proof:unit
    Scenario: Introspection reports only authorization-server controlled security claims
      Given a trusted workload assertion contains untrusted private claims
      When Realmroot exchanges and introspects its RFC 9068 JWT access token
      Then the JWT identifies the trusted external workload as the RFC 8693 subject and the authenticated Application as client_id
      And Realmroot's workload profile accepts no actor_token and the JWT contains no act claim
      And issuer, audience, client, scope, activity, token type, and lifetime come only from Realmroot
      And subject assertion claims cannot override introspection security fields
      And only the confidential client that owns the exchange can introspect the token
      And previously issued opaque exchange access tokens remain introspectable until they expire

    @entrypoint:agent-protocol @journey:workload-refresh-security @proof:unit
    Scenario: Token-exchange refresh tokens are confidential, rotating, and revocable
      Given a confidential client received a token-exchange refresh token
      When it refreshes with valid client authentication and an enabled federated credential
      Then Realmroot rotates the refresh token and invalidates the previous value
      When the old token is replayed or the federated credential is disabled or deleted
      Then Realmroot rejects the refresh with invalid_grant
      And disabling the client or rotating its secret also prevents refresh

  Rule: External API resources use target-issued authorization

    @entrypoint:product-ui @journey:resource-account-connection @proof:unit
    Scenario: A controller connects an external resource account securely
      Given an external Resource Server requires a connected account
      When the controller starts and completes its authorization
      Then Realmroot uses authorization code flow with PKCE and explicit consent
      And the authorization request identifies the exact target Resource Server
      And Realmroot stores the resulting credentials only in encrypted custody
      And an unavailable or mismatched authorization server fails without creating a connection

    @entrypoint:product-ui @journey:linear-managed-workspace-connections @proof:unit
    Scenario: One Linear Connector independently supports sign-in and external resource authorization
      Given the Linear Connector uses Better Auth for authentication and the Linear Adapter as its external authorization issuer
      When a user signs in with Linear and authorizes Linear resource access
      Then sign-in creates only its Better Auth account link
      And resource authorization creates one external connection to the Linear Adapter
      And the Linear Adapter keeps provider credentials outside Realmroot
      And available workspaces are selected through authorization details instead of additional Realmroot connections
      And Realmroot exchanges the connected subject and Agent actor at the Linear Adapter
      And the Linear Adapter issues the final DPoP token used for its Resource Server

    @entrypoint:product-ui @journey:adapter-external-resource-authorization @proof:unit
    Scenario: An Adapter presents a non-standard provider as a standard External Resource Server
      Given the provider cannot issue the Agent token required by Realmroot
      And its Adapter publishes a standard authorization server and protected Resource Server
      When the controller connects the provider through the Connector's resource-authorization facet
      Then the Adapter completes provider authorization without exposing provider credentials to Realmroot
      And Realmroot stores one standard external connection issued by the Adapter
      And Realmroot requests an advertised OIDC profile scope so the connection keeps a readable Provider label
      When an Agent receives access through that connection
      Then Realmroot sends the connected subject, Agent actor, scopes, and authorization details through standard token exchange
      And the Adapter issues a DPoP token bound to the Agent and selected provider authority
      And reconnecting updates the external connection instead of creating another Realmroot connection

    @entrypoint:product-ui @journey:external-api-resource-registration @proof:unit
    Scenario: An administrator creates an external API resource with an OIDC connector
      Given a target resource publishes protected-resource and authorization-server metadata
      And a platform-managed standard OIDC connector exists for its authorization server
      And Realmroot can discover that connector through OIDC or RFC 8414 authorization-server metadata
      When a member with the required platform Organization scopes creates the API resource and selects that connector
      Then Realmroot validates the resource issuer, token exchange, DPoP, and revocation against the connector
      And the external Resource Server is owned by the built-in platform Organization
      And ordinary Organizations cannot register or take ownership of it
      And the resource URL advertises its OpenAPI contract with a standard service-desc link
      And Realmroot derives every requestable scope only from scopes_supported in that protected-resource metadata
      And the OpenAPI contract may add descriptions for advertised scopes
      And Realmroot publishes only operation security alternatives fully supported by those advertised scopes
      And unrelated scoped operations do not prevent resource synchronization
      And authorization-server scopes_supported is not a scope catalog
      And the resource stores only its connector association rather than another OAuth client
      And the resource cannot be enabled for Agents when a required capability is absent
      And the same connector can independently be enabled for Realmroot login

    @entrypoint:restish @journey:external-api-resource-reconfiguration @proof:integration
    Scenario: Changing an external API resource URL revalidates its connector boundary
      Given an external API resource is associated with an active OIDC connector
      When an administrator changes its resource URL or selects another OIDC connector
      Then Realmroot rediscovers the target metadata
      And the resource remains enabled only when its authorization server matches the associated connector
      And the resource cannot remove its connector or become natively authorized

    @entrypoint:restish @journey:external-api-resource-canonical-callback @proof:unit
    Scenario: OIDC connector registration uses the deployment's canonical callbacks
      Given Realmroot is reached through a non-canonical request origin
      When an administrator dynamically registers an OIDC connector
      Then its login and resource-account redirect URIs and JWKS URI use the configured deployment origin
      And a later Account Center authorization request uses that same redirect URI
      And a successful resource-account callback shows completion even when origin-scoped session storage is unavailable

    @entrypoint:agent-protocol @journey:external-resource-dynamic-client-scope-upgrade @proof:unit
    Scenario: A dynamic OIDC connector upgrades its registered scope authority
      Given an authorization server advertises scopes that were not registered by an existing dynamic connector
      When a controller expands an external resource account for one of those scopes
      Then Realmroot updates the existing client through its registration management endpoint when available
      And otherwise Realmroot registers a new client generation without invalidating connections pinned to the previous generation
      And the connection intent is pinned to the new client generation
      And same-subject reauthorization preserves the selected account connection identity and switches only that connection to the new generation

    @entrypoint:product-ui @journey:external-resource-rich-authorization-connection @proof:unit
    Scenario: A controller connects one external subject to multiple target contexts
      Given an authorization server advertises RFC 9396 authorization detail types
      And an external API resource configures opaque connection authorization detail templates using supported types
      When Realmroot dynamically registers its reusable OIDC connector
      Then the registration declares the authorization detail types that the connector can use
      When the controller authorizes the resource account
      Then Realmroot sends the complete authorization request including the configured authorization details
      And uses RFC 9126 pushed authorization requests when the authorization server advertises that optional endpoint
      When the target consent enriches one template into multiple granted contexts
      Then Realmroot requires and stores every returned authorization detail under the single account connection
      And refresh-token rotation preserves the granted authorization details
      And unknown types or malformed authorization details fail with invalid_authorization_details

    @entrypoint:agent-protocol @journey:external-resource-rar-without-catalog @proof:unit
    Scenario: Rich authorization does not require an enumerable resource catalog
      Given an authorization server supports RFC 9396 authorization details
      And it does not advertise Realmroot's optional authorization detail catalog extension
      When an administrator registers an external API resource with supported authorization detail templates
      Then Realmroot accepts the resource without inventing a catalog requirement
      And Agent approval can select the concrete authorization details already returned by that account connection
      And Agents can request exact details already exposed by their connected account

    @entrypoint:agent-protocol @journey:external-resource-contextual-delegation @proof:unit
    Scenario: An Agent delegates an exact external-resource context alongside scopes
      Given one external account connection grants multiple opaque authorization detail entries
      And the authorization server advertises Realmroot authorization detail catalog version 1 with an account-scoped endpoint and required scope
      When the Agent discovers that catalog through Realmroot
      Then Realmroot forwards pagination and returns each available detail with safe display metadata and connection authorization
      And each detail reports only its Agent-authorized and requestable scope sets
      And provider-reported scope reductions immediately remove stale account and Agent authority from that detail
      And Realmroot does not expose account connection identifiers, grant identifiers, grants, or tokens
      When the Agent requests an exact scope subset and one or more concrete connected authorization details
      Then Realmroot preserves that exact authorization boundary through hosted approval
      And rejects missing, generic, duplicate, or unconnected authorization details
      And the pending request and controller approval preserve both authority dimensions
      And an ungranted entry or browser-tampered approval fails with invalid_authorization_details
      When the controller approves the request and the Agent exchanges a token
      Then Realmroot sends the approved scopes and authorization details to the target authorization server
      And requires the target token response to return the exact assigned scopes and authorization details
      And stores both dimensions with the token lease
      And audit events expose only safe authorization detail type and identifier projections

    @entrypoint:product-ui @journey:external-resource-rich-authorization-reauthorization @proof:unit
    Scenario: Reauthorization removes stale contextual authority without changing non-RAR resources
      Given an existing external resource account has active contextual Agent grants
      When reauthorization no longer returns one previously granted authorization detail entry
      Then Realmroot prevents future issuance from every grant containing the removed entry
      And existing connections must be explicitly reauthorized when their resource becomes RAR-required
      And resources without configured authorization details preserve their existing connection, refresh, grant, token exchange, revocation, and audit behavior

    @entrypoint:agent-protocol @journey:external-resource-first-access @proof:unit
    Scenario: An Agent requests first access to an external API resource
      Given an enabled external API resource has active authorization configuration
      And the Agent's home space has no account connection for that resource
      When the Agent discovers every target operation required by the current task
      And requests their combined exact advertised scope set
      Then Realmroot creates one pending Agent access request and one hosted approval URL
      When the controller opens the access approval page
      Then Realmroot requires the controller to connect that resource account in the same approval flow
      And the new account authorization requests the access request's exact scope set
      When OAuth returns after connecting the account
      Then Realmroot returns to the same access approval with that account displayed
      When the authorization server instead returns an OAuth error
      Then Realmroot consumes the failed attempt and returns to the same access approval with the provider error and a retry action
      Then Realmroot records a resource account connection owned by the Agent's home space
      And stores its refresh credential encrypted
      And never exposes the refresh credential through an API, audit event, or error
      And does not create a grant or token before approval
      When the controller selects one connected authorization context when the resource requires one
      And approves the exact Agent scopes and grant lifetime
      Then Realmroot binds the account connection to the exact request and grant
      And the Agent can obtain a DPoP-bound target access token

    @entrypoint:product-ui @journey:resource-account-reauthorization @proof:unit
    Scenario: A controller reauthorizes a connected external resource account
      Given the controller's home space already has an account connection for an external API resource
      And a pending Agent access request requires scopes that its selected authorization detail does not yet cover
      When the controller opens the approval page
      Then Realmroot presents account permission update as the only available action
      And hides Agent approval controls until the account covers every requested scope
      But a failed authorization-detail catalog lookup reports that failure without presenting account permission update
      When the controller reauthorizes that account for the union of its existing scopes and the pending Agent request's exact scope set
      And OAuth returns the same external subject with replacement credentials and scopes
      Then Realmroot preserves the account connection identity
      And replaces its encrypted credentials, scopes, display name, and expiry
      And treats the callback authorization details as authoritative so removed details invalidate uncovered Agent grants
      And restores the connection when it was previously revoked
      And returns to the pending Agent approval so the controller can finish the continuous flow

    @entrypoint:agent-protocol @journey:resource-account-connection-expansion @proof:unit
    Scenario: An Agent requests additional authority from an existing resource account
      Given the Agent's home space has an active resource account connection with covered persistent grants
      When the Agent requests an additional scope for one selected authorization detail
      Then Realmroot leaves the account connection revision, authorization details, and grants unchanged while approval is pending or interrupted
      When the controller starts account reauthorization
      Then Realmroot requests the union of the account's still-advertised resource scopes and the Agent's additional scope
      And sends only the selected authorization detail to the external authorization server
      And Realmroot adds provider protocol scopes only after validating that resource scope union
      And the external authorization server returns the connection's complete current authorization-detail snapshot
      And Realmroot accepts the selected authorization detail as a subset of that snapshot
      And only a successful OAuth callback may replace the account authorization and invalidate grants the complete snapshot no longer covers

    @entrypoint:agent-protocol @journey:agent-resource-discovery @proof:unit
    Scenario: An Agent discovers resource connection and scope status before requesting exact authority
      Given enabled native and externally authorized API resources exist
      When the Agent lists available resources
      Then Realmroot returns enabled resources even when an external resource has no connected account
      And a temporarily unreachable external authorization server does not fail the Resource Server collection or revoke its account connection
      And returns each resource server with its protected URL, available scopes, and one connected, not-connected, or not-required account status
      And a connected account reports only its safe display label and still-advertised connection-authorized scopes
      And Realmroot does not expose Connector, account connection, grant, or token identifiers
      When Restish connects directly to a candidate resource and reads the target OpenAPI operation
      And the Agent requests an account and its exact scope set without an applicable grant
      Then Realmroot validates that scope set against the local target scope registry
      And automatic scopes do not apply to Agents
      And the connected account permits every requested scope
      Then Realmroot creates one pending access request and returns a hosted approval URL
      And it does not require a pre-existing Agent resource grant

    @entrypoint:agent-protocol @journey:agent-resource-access-ensure @proof:unit
    Scenario: An Agent ensures exact resource access without selecting grants or tokens
      Given an Agent names an API resource, exact authorization details, and least-privilege scopes
      When the Agent requests that exact access
      Then Realmroot resolves the unique account connection from the Agent's home space and API resource
      Then Realmroot reuses an exact active grant without controller approval when one exists
      And otherwise creates or resumes one pending controller approval
      And the public access-request contract never exposes grant identifiers or token operations
      And the Restish plugin resolves approved access through a hidden adapter boundary
      And the plugin obtains, protects, and activates a short-lived DPoP target token
      And the Agent never selects a grant or invokes a token operation
      And the plugin returns a safe ready receipt without grant identifiers or token material

    @entrypoint:product-ui @journey:agent-resource-approval @proof:unit
    Scenario: A controller decides an Agent resource request in one step
      Given an Agent resource access request is pending
      When an authorized controller approves it
      Then the controller confirms the named Agent, named resource, displayed resource account, exact scopes, and one-time, limited, or persistent mode
      And the Account Center request queue identifies the named Agent and named resource before the controller opens the decision
      And expired requests do not appear in the Account Center request queue
      And stable Agent and resource identifiers remain visible as supporting information
      And limited access accepts an exact future local date and time while rejecting empty or past values
      And no account-selection control is displayed
      And scope expansion, another account, or another resource requires a new approval
      And a denied request cannot issue a target token
      And an incomplete approval URL shows only a recovery state without inactive authorization controls

    @entrypoint:product-ui @journey:agent-resource-approval-sign-in @proof:unit
    Scenario: A signed-out controller signs in without losing the Agent approval
      Given an Agent resource access request is pending
      And the controller is signed out
      When the Realmroot CLI opens the hosted approval URL
      And the controller signs in
      Then Realmroot returns to the same approval without exposing its token to the server callback URL
      And the controller can approve or deny the request

    @entrypoint:agent-protocol @journey:agent-direct-resource-access @proof:unit
    Scenario: An Agent calls an external API directly with a target-issued token
      Given a controller approved an exact external API resource request
      When the Realmroot CLI completes the Agent's exact access request
      Then the Realmroot CLI creates and retains a separate DPoP key
      And the CLI sends a standard DPoP header bound to the target token endpoint
      Then Realmroot submits a signed Agent assertion with the RFC 7523 JWT bearer grant
      And the target platform issues an Agent access token
      And Realmroot exchanges the connected user's subject token and the target-issued Agent access token with RFC 8693
      And the target platform issues a short-lived DPoP-bound access token
      And the token identifies the target user as subject and the Agent in the RFC 8693 actor claim
      And the target preserves the Agent issuer, subject, and ai_agent subject profile
      And no Realmroot-specific metadata, grant type, token type, or claim is required
      And Realmroot returns no refresh token
      And Restish stores but does not print the raw access token
      When the Agent connects Restish to the discovered protected resource URL
      Then Restish discovers the target OpenAPI contract from its standard service-desc link
      When the Agent invokes a generated target operation
      Then the plugin sends the access token and a fresh DPoP proof directly to the target platform
      And no Realmroot egress or credential injection endpoint exists

    @entrypoint:agent-protocol @journey:agent-resource-revocation @proof:unit
    Scenario: Revocation stops direct external API access
      Given an Agent has an active target token
      When a controller revokes its grant, account connection, credential, or Agent
      Then Realmroot calls the target revocation endpoint for active target tokens
      And subsequent token requests are rejected
      And unrelated Agents, accounts, and grants remain active

  Rule: Controllers and administrators can govern Agent activity

    @entrypoint:product-ui @journey:agent-governance-surfaces @proof:unit
    Scenario: Agent management follows ownership and platform boundaries
      Given User-owned Agents exist
      When an authorized controller opens Agent management
      Then Account Center presents the current User's Agents
      And Organization membership does not grant Agent ownership or control
      And Console presents User-owned inventory, audit, and emergency revocation

    @entrypoint:product-ui @journey:agent-audit-chain @proof:unit
    Scenario: Audit records reconstruct an Agent authorization decision
      Given an Agent host attempts to request external API resource authority
      When Realmroot allows or denies the request
      Then the audit record identifies the controller authority, resource account, Agent, host, grant, scopes, and result
      And it excludes credentials, authorization headers, and complete request or response bodies

    @entrypoint:product-ui @journey:agent-governance-audit @proof:unit
    Scenario: Agent identity and management authority changes remain auditable
      Given an Agent identity is governed by a controller or administrator
      When the Agent is enrolled, recovered, retired, or receives a capability decision
      Then Realmroot records the action, result, controller, stable Agent identity, host, and affected capabilities
      And the audit event contains no host credential, session token, or approval code

  @journey:direct-agent-permission @entrypoint:restish @proof:unit
  Scenario: A controller grants an Agent permission before its first request
    Given an active Agent and a Resource within its controller's authority
    When the controller posts the resource URL, scopes, and a persistent lifetime
    Then Realmroot resolves the controller's connection and authorization Contexts internally
    And Realmroot stores the permissions without creating an access request
    And repeated grants reuse the existing permission
    And a later Agent request reuses that permission without human approval
    And scopes outside the controller or connected account boundary are rejected

  @journey:direct-agent-permission-http @entrypoint:restish @proof:integration
  Scenario: Direct permissions preserve ownership and persistence through HTTP
    Given a user controls an active Agent
    When the user creates the same native permission twice through HTTP
    Then both responses identify the same persistent permission without an access request
    And anonymous and other-user writes are rejected
    And invalid permission bodies are rejected
    And equivalent Contexts reuse existing permissions regardless of JSON object key order
