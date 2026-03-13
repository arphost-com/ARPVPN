# ARPVPN API Threat Model

Updated: 2026-03-10

Scope reviewed:

- impersonation APIs
- tenant/user management APIs
- WireGuard control APIs
- global and tenant-scoped TLS APIs
- backup/restore APIs

## Primary trust boundaries

1. Browser session cookie vs bearer token clients
2. Super admin/support admin vs tenant admin vs client roles
3. Tenant-owned resources vs global resources
4. Stored WireGuard/private configuration material vs read-only telemetry

## Main risks and controls

### CSRF on cookie-authenticated API writes

Risk:
- A logged-in browser could be tricked into mutating API state.

Control:
- Cookie-authenticated API writes now require a CSRF token from `GET /api/v1/auth/csrf`.
- Bearer-token requests are exempt because they are not ambient browser credentials.

### Tenant boundary violations

Risk:
- Tenant admins or clients read or mutate resources outside their tenant.

Control:
- Tenant visibility and management helpers enforce tenant ownership on users, invitations, interfaces, peers, and tenant TLS/config endpoints.
- Authorization matrix tests cover global vs tenant-scoped access patterns.

### Impersonation abuse

Risk:
- Staff impersonation could hide actor identity or allow lateral movement.

Control:
- Impersonation start/stop events are audit logged.
- Original actor identity is stored in session and restored explicitly.
- Client impersonation remains staff-only.

### WireGuard key material exposure

Risk:
- Private config or peer material leaks through unauthorized API endpoints.

Control:
- Peer/interface downloads and QR endpoints are scoped by role and tenant ownership.
- Backup export is super-admin only.
- Backup restore is super-admin only and audit logged.

### Global TLS misuse

Risk:
- Support or tenant-scoped actors alter global listener state.

Control:
- Global TLS mutation endpoints are super-admin only.
- Tenant admins manage only tenant-scoped TLS intent, stored separately from the global listener config.

### Destructive restore operations

Risk:
- Restore could leave the system in a partially broken state.

Control:
- Restore supports `dry_run`.
- Restore writes are rolled back to the prior on-disk snapshot if reload fails.

## Residual risks

- Backup payloads contain sensitive configuration and must be handled as secrets.
- Separate tenant runtime/container lifecycle is not yet fully API-controlled.
- The OpenAPI document still covers a subset of the full live API surface.

## Follow-up items

- Expand input schema validation across the remaining API families.
- Extend authorization matrix coverage to every endpoint family.
- Add signed audit export for backup/restore and high-impact TLS changes.
