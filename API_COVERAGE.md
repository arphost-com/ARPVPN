# ARPVPN API Coverage

Authoritative snapshot of the API surface implemented in code as of 2026-03-14.

## Summary

ARPVPN exposes a hybrid API under `/api/v1`.

- It is not a pure REST API.
- It is partly resource-oriented and partly action/RPC-oriented.
- It is usable today for auth, tenant/user lifecycle, WireGuard control, mesh control, stats/traffic, themes, TLS, and system/config operations.
- It now includes admin backup/restore, tenant-scoped TLS settings, tenant runtime allocation/status APIs, setup/profile/network/about parity endpoints, mesh diagnostics, and generated SDK artifacts.
- The generated OpenAPI contract currently covers 115 live operations.

## API Style

### Resource-style areas

These follow normal collection/item patterns and are the most REST-like parts of the product:

- `/api/v1/mesh/topologies`
- `/api/v1/mesh/topologies/<uuid>`
- `/api/v1/mesh/links`
- `/api/v1/mesh/links/<uuid>`
- `/api/v1/mesh/routes`
- `/api/v1/mesh/routes/<uuid>`
- `/api/v1/mesh/policies`
- `/api/v1/mesh/policies/<uuid>`
- `/api/v1/tenants`
- `/api/v1/tenants/<tenant_id>`
- `/api/v1/users`
- `/api/v1/users/<user_id>`
- `/api/v1/wireguard/interfaces`
- `/api/v1/wireguard/interfaces/<interface_id>`
- `/api/v1/wireguard/peers`
- `/api/v1/wireguard/peers/<peer_id>`

These support `GET`, `POST`, `PUT`, and `DELETE` in a predictable way.

### Action-style areas

These are valid APIs, but they are RPC/action endpoints rather than strict REST resources:

- `/api/v1/auth/token`
- `/api/v1/auth/refresh`
- `/api/v1/auth/revoke`
- `/api/v1/auth/revoke-all`
- `/api/v1/auth/force-logout/<user_id>`
- `/api/v1/auth/csrf`
- `/api/v1/impersonation/start/<user_id>`
- `/api/v1/impersonation/stop`
- `/api/v1/mesh/dry-run`
- `/api/v1/mesh/plan`
- `/api/v1/mesh/diagnostics`
- `/api/v1/mesh/policy-simulate`
- `/api/v1/mesh/import`
- `/api/v1/tls/mode`
- `/api/v1/tls/self-signed`
- `/api/v1/tls/letsencrypt`
- `/api/v1/system/restore`
- `/api/v1/system/restart`

### Read/report APIs

These are read-focused operational endpoints rather than mutable resources:

- `/api/v1/stats/overview`
- `/api/v1/stats/peers`
- `/api/v1/stats/alerts`
- `/api/v1/stats/statistics`
- `/api/v1/stats/rollups`
- `/api/v1/stats/failures`
- `/api/v1/stats/history/<uuid>`
- `/api/v1/stats/rrd/<uuid>`
- CSV exports under `/api/v1/stats/*.csv`

## Implemented Endpoint Families

### Auth and session control

Implemented:

- `GET /api/v1/auth/modes`
- `GET /api/v1/auth/rbac`
- `GET /api/v1/auth/csrf`
- `POST /api/v1/auth/token`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/revoke`
- `POST /api/v1/auth/revoke-all`
- `POST /api/v1/auth/force-logout/<user_id>`
- `POST /api/v1/impersonation/start/<user_id>`
- `POST /api/v1/impersonation/stop`

Status:

- Usable for browser and external API clients.
- Supports cookie/session auth and bearer token auth.
- Includes rate limiting, lockout handling, revocation, and audit logging.
- Cookie-authenticated API writes require CSRF tokens; bearer-token writes do not.

### Mesh control plane

Implemented:

- `GET /api/v1/mesh/overview`
- `GET /api/v1/mesh/diagnostics`
- Full CRUD for topologies, links, routes, and policies
- `POST /api/v1/mesh/dry-run`
- `GET /api/v1/mesh/export`
- `POST /api/v1/mesh/import`

Status:

- Strongest API surface currently in ARPVPN.
- Includes deterministic mesh planning previews, diagnostics rollups, and policy simulation for rollout validation.
- Mesh event trails are signed and exposed through audit reads and diagnostics summaries.
- Good candidate for external automation today.

### Traffic, usage, and RRD

Implemented:

- `GET /api/v1/stats/overview`
- `GET /api/v1/stats/peers`
- `GET /api/v1/stats/alerts`
- `GET /api/v1/stats/statistics`
- `GET /api/v1/stats/rollups`
- `GET /api/v1/stats/failures`
- `GET /api/v1/stats/history/<uuid>`
- `GET /api/v1/stats/rrd/<uuid>`
- CSV exports for peers, alerts, and rollups

Status:

- Good read-only operational API.
- Suitable for dashboards and reporting.

### Theme and TLS management

Implemented:

- `GET /api/v1/themes`
- `POST /api/v1/themes`
- `GET /api/v1/tls/status`
- `GET /api/v1/tls/certificate`
- `POST /api/v1/tls/mode`
- `POST /api/v1/tls/self-signed`
- `POST /api/v1/tls/letsencrypt`
- `GET /api/v1/tenants/<tenant_id>/tls/status`
- `PUT /api/v1/tenants/<tenant_id>/tls`

Status:

- Enough to automate theme preference and core TLS/certificate workflows.
- Global TLS mutation is now super-admin only.
- Tenant admins can store tenant-scoped TLS intent for their assigned tenant.

### Tenant, user, and invitation management

Implemented:

- `GET /api/v1/tenants`
- `POST /api/v1/tenants`
- `GET /api/v1/tenants/<tenant_id>`
- `PUT /api/v1/tenants/<tenant_id>`
- `DELETE /api/v1/tenants/<tenant_id>`
- `GET /api/v1/users`
- `POST /api/v1/users`
- `GET /api/v1/users/<user_id>`
- `PUT /api/v1/users/<user_id>`
- `DELETE /api/v1/users/<user_id>`
- `GET /api/v1/users/export`
- `POST /api/v1/users/import`
- `GET /api/v1/tenants/<tenant_id>/members`
- `POST /api/v1/tenants/<tenant_id>/members`
- `GET /api/v1/invitations`
- `POST /api/v1/invitations`
- `GET /api/v1/invitations/<invitation_id>`
- `POST /api/v1/invitations/<invitation_id>/resend`
- `POST /api/v1/invitations/<invitation_id>/revoke`
- `POST /api/v1/invitations/<invitation_id>/accept`

Status:

- Admins can manage tenants, tenant-admin accounts, and global user state.
- Support users are restricted to client-user operations.
- Tenant admins are restricted to client-user and invitation operations inside their assigned tenant.
- Tenant admins can also manage tenant-scoped TLS intent and tenant runtime allocation/status for their assigned tenant.
- Bulk import/export APIs are available with role-safe validation and idempotency support.
- Tenant isolation is enforced in API visibility and management helpers and covered by integration tests.

### Tenant runtime control

Implemented:

- `GET /api/v1/tenants/<tenant_id>/runtime`
- `PUT /api/v1/tenants/<tenant_id>/runtime`
- `POST /api/v1/tenants/<tenant_id>/runtime/allocate`
- `POST /api/v1/tenants/<tenant_id>/runtime/<action>`

Status:

- Provides container/runtime planning metadata for separate tenant VPN stacks.
- Allocates unique HTTP/HTTPS/VPN host ports across tenants.
- Stores desired state and status as ARPVPN control-plane intent.
- Does not directly call Docker or Compose; external deployment automation still applies the plan.

### WireGuard control

Implemented:

- `GET /api/v1/wireguard/interfaces`
- `POST /api/v1/wireguard/interfaces`
- `GET /api/v1/wireguard/interfaces/<interface_id>`
- `PUT /api/v1/wireguard/interfaces/<interface_id>`
- `DELETE /api/v1/wireguard/interfaces/<interface_id>`
- `POST /api/v1/wireguard/interfaces/<interface_id>/<action>`
- `GET /api/v1/wireguard/interfaces/<interface_id>/download`
- `GET /api/v1/wireguard/interfaces/<interface_id>/qr`
- `GET /api/v1/wireguard/peers`
- `POST /api/v1/wireguard/peers`
- `GET /api/v1/wireguard/peers/<peer_id>`
- `PUT /api/v1/wireguard/peers/<peer_id>`
- `DELETE /api/v1/wireguard/peers/<peer_id>`
- `GET /api/v1/wireguard/peers/<peer_id>/download`
- `GET /api/v1/wireguard/peers/<peer_id>/qr`
- `GET /api/v1/jobs/<job_id>`

Status:

- Covers interface and peer CRUD plus config download and QR retrieval.
- Includes start/stop/restart operations for interfaces.
- Tenant admins are scoped to their own tenant’s WireGuard objects.
- Clients can only view their own peer/interface state and downloads.
- Long-running operations can be queued and polled through the async job API.

### System, audit, and configuration

Implemented:

- `GET /api/v1/system/version`
- `GET /api/v1/system/health`
- `GET /api/v1/system/diagnostics`
- `GET /api/v1/system/backup`
- `POST /api/v1/system/restore`
- `GET /api/v1/audit/events`
- `GET /api/v1/config/global`
- `PUT /api/v1/config/global`
- `GET /api/v1/tenants/<tenant_id>/config`
- `PUT /api/v1/tenants/<tenant_id>/config`

Status:

- Global config is API-managed for super-admin use.
- Tenant branding/limits/defaults/DNS config is tenant-scoped.
- Admin-only backup export and restore are available, with restore dry-run validation and rollback on failed reload.
- Audit events are readable from structured log entries and now include signature verification metadata.
- Health/version/diagnostics endpoints are available for automation and support workflows.
- API groups can be toggled with feature flags such as `ARPVPN_FEATURE_API_MESH=0` or `ARPVPN_FEATURE_API_WIREGUARD=0`.

## UI Parity Status

Supported operational UI flows now have matching public API endpoints.

- User lifecycle, invitations, theme controls, profile/password updates, setup/bootstrap, network inventory, about/system metadata, restart flows, WireGuard control, mesh control, stats/RRD, TLS, tenant config, and tenant runtime control all have API counterparts.
- HTML pages remain convenience/admin surfaces on top of those APIs rather than unique-only control paths.

## What Needs To Be Added Next

- Host-level mesh application and ACL enforcement remain the next major gap.
- The remaining work is in route install/remove hooks, mesh apply/rollback, per-link host metrics, firewall enforcement, and policy hit accounting rather than API shape.

## OpenAPI Status

The live OpenAPI generator now tracks the implemented route surface used in code.

Current `openapi.v1.yaml` covers the full supported API families, including:

- auth and impersonation
- theme and TLS endpoints
- tenant/user/invitation/runtime flows
- mesh overview, CRUD, plan, diagnostics, dry-run, import/export, and policy simulation
- stats, exports, and system/config operations

That means the implementation is ahead of the published spec. The spec should be expanded before calling the API fully documented.

## Bottom Line

ARPVPN already has a usable API, but today it is best described as:

- versioned
- consistent
- hybrid REST/RPC
- strong for auth, mesh, stats, and TLS
- incomplete for full platform automation

The biggest missing areas are user management, WireGuard control, tenant APIs, and system/config operations.
