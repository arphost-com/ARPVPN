# ARPVPN API Control TODO

Goal: provide secure API control for all ARPVPN features (users, tenants, WireGuard, traffic, TLS, monitoring, and operations).

See also: `MESH_ACL_TODO.md` for dedicated site-to-site mesh and IP access-control roadmap.

## Phase 0: API Foundation
- [x] Define API versioning strategy (`/api/v1`, deprecation policy, compatibility guarantees).
- [x] Standardize response envelope (success/error shape, request IDs, pagination metadata).
- [x] Define error model (`code`, `message`, `details`, HTTP mapping).
- [x] Add OpenAPI source of truth and CI validation.
- [x] Add API changelog process per release line (`main` and `codex/multitenant-v2`).

## Phase 1: AuthN/AuthZ and Session Control
- [x] Add token-based auth (access + refresh tokens) for API clients.
- [x] Keep secure cookie/session auth for UI; document both auth modes.
- [x] Implement RBAC matrix for `super_admin`, `support_admin`, `tenant_admin`, `client`.
- [x] Add impersonation API endpoints with strict audit logging.
- [x] Add API rate limiting and lockout controls.
- [x] Add token revocation and forced logout endpoints.

## Phase 2: Tenant and User Management APIs
- [x] CRUD APIs for tenants (name, domain/IP metadata, status).
- [x] CRUD APIs for users per tenant with role assignment.
- [x] Tenant admin APIs for client invitations (create, resend, revoke, accept).
- [x] Bulk user import/export APIs (with role-safe validation).
- [x] Tenant isolation checks at service layer + integration tests.

## Phase 3: WireGuard Control APIs
- [x] Interface APIs (create/list/get/update/delete/start/stop/restart).
- [x] Peer APIs (create/list/get/update/delete/download config/QR retrieval).
- [x] Per-tenant VPN scoping and policy enforcement in all wireguard endpoints.
- [x] Container lifecycle API for separate tenant VPN instances (port allocation/status).
- [x] Safe async job model for long-running operations (apply/restart/regenerate keys).

## Phase 4: Traffic, Usage, and RRD APIs
- [x] Per-connection traffic history API (interface + peer).
- [x] RRD graph URL/API endpoints for admins and clients.
- [x] Bandwidth usage summary APIs (hour/day/week/month windows).
- [x] Alert APIs for offline/stale/high-traffic peers.
- [x] Export APIs (CSV/JSON) with tenant-scoped filtering.

## Phase 5: TLS and Certificate Management APIs
- [x] TLS mode APIs (`http`, `self-signed`, `letsencrypt`, `reverse-proxy`).
- [x] Endpoint to generate self-signed certs for configured hostnames.
- [x] Endpoint to issue/renew Let’s Encrypt certificates.
- [x] Read-only certificate status endpoint (issuer, expiry, SANs).
- [x] Permission gates: super admin global, tenant admin tenant-scoped.

## Phase 6: Configuration and System APIs
- [x] Tenant configuration APIs (branding, limits, defaults, DNS options).
- [x] Super admin global configuration APIs.
- [x] Health/diagnostics APIs (service status, dependency checks, version/commit).
- [x] Audit log APIs (who/what/when/where, immutable event history).
- [x] Backup/restore APIs for config + credentials metadata (role-restricted).

## Phase 7: Security and Hardening
- [x] Idempotency key support for create/update operations.
- [x] CSRF protection policy for cookie-auth API calls.
- [ ] Input validation schemas for every endpoint.
- [x] Structured authorization tests for each role/action combination.
- [x] Threat-model review for impersonation, tenant boundaries, and key material handling.

## Phase 8: Developer Experience and Rollout
- [x] Publish OpenAPI docs with examples by role and tenant scope.
- [x] Add API smoke tests and contract tests in CI.
- [ ] Add SDK/client generation pipeline (optional but recommended).
- [x] Add feature flags to release incrementally per endpoint group.
- [x] Define migration notes for legacy UI flows to API-backed operations.

## Done Criteria
- [ ] Every UI operation has a matching API endpoint.
- [ ] Role and tenant boundaries are enforced and tested end-to-end.
- [ ] API docs and examples are complete and versioned.
- [x] Both release lines have clear backport/cherry-pick guidance for API changes.
