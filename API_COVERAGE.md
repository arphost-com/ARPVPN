# ARPVPN API Coverage

Authoritative snapshot of the API surface implemented in code as of 2026-03-14.

## Summary

ARPVPN exposes a hybrid API under `/api/v1`.

- It is not a pure REST API.
- It is partly resource-oriented and partly action/RPC-oriented.
- It is usable today for auth, tenant/user lifecycle, WireGuard control, stats/traffic, themes, TLS, and system/config operations.
- It includes admin backup/restore, tenant-scoped TLS settings, tenant runtime allocation/status APIs, setup/profile/network/about parity endpoints, and generated SDK artifacts.
- The generated OpenAPI contract currently covers the live operations implemented in code.

## API Style

### Resource-style areas

These follow normal collection/item patterns and are the most REST-like parts of the product:

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

- Theme selection endpoints
- TLS mode update and certificate issuance endpoints

Status:

- Intended for admin and tenant-admin workflows where applicable.

### System and setup

Implemented:

- `GET /api/v1/about`
- `GET /api/v1/network`
- `GET /api/v1/profile`
- `GET /api/v1/setup/status`
- `POST /api/v1/setup/bootstrap`
- `POST /api/v1/system/restart`
- `POST /api/v1/system/restore`

Status:

- Covers runtime, bootstrap, and recovery workflows.

## Coverage Notes

- The API coverage snapshot is generated from the live Flask route map.
- The generated OpenAPI document should be kept in sync with the route surface after any API change.
- API groups can be toggled with feature flags such as `ARPVPN_FEATURE_API_WIREGUARD=0`.
