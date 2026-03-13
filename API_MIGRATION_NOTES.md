# ARPVPN API Migration Notes

Updated: 2026-03-10

This document maps legacy UI flows to the API surface so automation and future UI work can move to API-backed operations without changing behavior blindly.

## Auth and session

- `POST /login` remains the HTML login flow.
- `POST /api/v1/auth/token` is the API login flow for bearer clients.
- `GET /api/v1/auth/csrf` provides the CSRF token required for cookie-authenticated API writes.
- `POST /api/v1/auth/revoke`, `/revoke-all`, and `/force-logout/<user_id>` replace session-only forced logout workflows.

## User and tenant management

- `/users` create/edit/delete flows map to `/api/v1/users` and `/api/v1/users/<user_id>`.
- Tenant membership and invitations map to `/api/v1/tenants/<tenant_id>/members` and `/api/v1/invitations`.
- Bulk onboarding maps to `GET /api/v1/users/export` and `POST /api/v1/users/import`.

## WireGuard

- `/wireguard/interfaces/add` maps to `POST /api/v1/wireguard/interfaces`.
- `/wireguard/interfaces/<uuid>/<action>` maps to `POST /api/v1/wireguard/interfaces/<interface_id>/<action>`.
- `/wireguard/peers/add` maps to `POST /api/v1/wireguard/peers`.
- Peer download and QR actions map to `/api/v1/wireguard/peers/<peer_id>/download` and `/qr`.
- Long-running interface actions are polled with `GET /api/v1/jobs/<job_id>`.

## TLS and configuration

- Global web/TLS settings map to `GET/PUT /api/v1/config/global` and `POST /api/v1/tls/*`.
- Tenant branding/defaults/DNS settings map to `GET/PUT /api/v1/tenants/<tenant_id>/config`.
- Tenant-scoped TLS intent now maps to `GET /api/v1/tenants/<tenant_id>/tls/status` and `PUT /api/v1/tenants/<tenant_id>/tls`.

## Stats and observability

- `/statistics` read paths map to `/api/v1/stats/overview`, `/statistics`, `/rollups`, `/history/<uuid>`, and `/rrd/<uuid>`.
- Audit views map to `GET /api/v1/audit/events`.
- Diagnostics pages map to `GET /api/v1/system/health` and `/diagnostics`.

## Backup and recovery

- New admin-only backup export: `GET /api/v1/system/backup`
- New admin-only restore path: `POST /api/v1/system/restore`
- Use `dry_run=true` before restore to validate content without writing files.

## Release-line guidance

- Land API changes on `codex/multitenant-v2` first when they touch tenant scoping.
- Backport to `main` only after the docker02 validation path is green.
- Keep `main` on the stable image tags and `codex/multitenant-v2` on `v2-*` image tags.
