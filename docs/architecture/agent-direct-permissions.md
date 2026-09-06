# Direct Agent permissions

A User controller can provision permissions before an Agent requests access with
POST `/api/agents/{agentId}/permissions`.

The strict body contains only `resource` (the canonical Resource URL), `scopes`,
`mode` (persistent or until), and `expiresAt` for until grants. It returns an
`items` array of created or reused permissions. Callers do not query or submit
account connections, installation identifiers, or authorization details.

Realmroot resolves the controller-owned external connection and all current
Context catalog pages internally. Each Context receives the requested scopes
within the connection's existing resource boundaries. Native resources use the
verified delegated user token's Organization Context, or the user Context when
no Organization is selected. Browser callers use their current session Context.
No provider-specific semantics are added to Realmroot core.

The operation uses agents:write and verifies the target Agent's controller.
Agent principals cannot grant themselves or another Agent authority. Every
resolved Context is validated against the controller and upstream scopes before
this resource's grants are written. Missing connections, unavailable Contexts,
and insufficient scopes fail explicitly.

The existing resource_scope_entitlement table stores the grants with a null
sourceAccessRequestId. Equivalent active grants reuse their identity and can
extend their lifetime. No new table, synthetic request, or public Context query
endpoint is introduced. Retrying the same POST completes equivalent permissions.
The CLI acquires already granted authority in fresh Sessions without approval.

Acceptance: a non-admin controller posts only a resource URL, scope list and
lifetime; repeat creation reuses permissions, other controllers are rejected,
and a fresh Agent Session uses the permissions without human approval.
