# ARPVPN API Control TODO

Goal: provide secure API control for all ARPVPN features (users, tenants, WireGuard, traffic, TLS, monitoring, and operations).

## Phase 0: API Foundation
- [ ] Define API versioning strategy (`/api/v1`, deprecation policy, compatibility guarantees).
- [ ] Standardize response envelope (success/error shape, request IDs, pagination metadata).
- [ ] Define error model (`code`, `message`, `details`, HTTP mapping).
- [ ] Add OpenAPI source of truth and CI validation.
- [ ] Add API changelog process per release line (`main` and `codex/multitenant-v2`).

## Phase 1: AuthN/AuthZ and Session Control
- [ ] Add token-based auth (access + refresh tokens) for API clients.
- [ ] Keep secure cookie/session auth for UI; document both auth modes.
- [ ] Implement RBAC matrix for `super_admin`, `support_admin`, `tenant_admin`, `client`.
- [ ] Add impersonation API endpoints with strict audit logging.
- [ ] Add API rate limiting and lockout controls.
- [ ] Add token revocation and forced logout endpoints.

## Phase 2: Tenant and User Management APIs
- [ ] CRUD APIs for tenants (name, domain/IP metadata, status).
- [ ] CRUD APIs for users per tenant with role assignment.
- [ ] Tenant admin APIs for client invitations (create, resend, revoke, accept).
- [ ] Bulk user import/export APIs (with role-safe validation).
- [ ] Tenant isolation checks at service layer + integration tests.

## Phase 3: WireGuard Control APIs
- [ ] Interface APIs (create/list/get/update/delete/start/stop/restart).
- [ ] Peer APIs (create/list/get/update/delete/download config/QR retrieval).
- [ ] Per-tenant VPN scoping and policy enforcement in all wireguard endpoints.
- [ ] Container lifecycle API for separate tenant VPN instances (port allocation/status).
- [ ] Safe async job model for long-running operations (apply/restart/regenerate keys).

## Phase 4: Traffic, Usage, and RRD APIs
- [ ] Per-connection traffic history API (interface + peer).
- [ ] RRD graph URL/API endpoints for admins and clients.
- [ ] Bandwidth usage summary APIs (hour/day/week/month windows).
- [ ] Alert APIs for offline/stale/high-traffic peers.
- [ ] Export APIs (CSV/JSON) with tenant-scoped filtering.

## Phase 5: TLS and Certificate Management APIs
- [ ] TLS mode APIs (`http`, `self-signed`, `letsencrypt`, `reverse-proxy`).
- [ ] Endpoint to generate self-signed certs for configured hostnames.
- [ ] Endpoint to issue/renew Let’s Encrypt certificates.
- [ ] Read-only certificate status endpoint (issuer, expiry, SANs).
- [ ] Permission gates: super admin global, tenant admin tenant-scoped.

## Phase 6: Configuration and System APIs
- [ ] Tenant configuration APIs (branding, limits, defaults, DNS options).
- [ ] Super admin global configuration APIs.
- [ ] Health/diagnostics APIs (service status, dependency checks, version/commit).
- [ ] Audit log APIs (who/what/when/where, immutable event history).
- [ ] Backup/restore APIs for config + credentials metadata (role-restricted).

## Phase 7: Security and Hardening
- [ ] Idempotency key support for create/update operations.
- [ ] CSRF protection policy for cookie-auth API calls.
- [ ] Input validation schemas for every endpoint.
- [ ] Structured authorization tests for each role/action combination.
- [ ] Threat-model review for impersonation, tenant boundaries, and key material handling.

## Phase 8: Developer Experience and Rollout
- [ ] Publish OpenAPI docs with examples by role and tenant scope.
- [ ] Add API smoke tests and contract tests in CI.
- [ ] Add SDK/client generation pipeline (optional but recommended).
- [ ] Add feature flags to release incrementally per endpoint group.
- [ ] Define migration notes for legacy UI flows to API-backed operations.

## Done Criteria
- [ ] Every UI operation has a matching API endpoint.
- [ ] Role and tenant boundaries are enforced and tested end-to-end.
- [ ] API docs and examples are complete and versioned.
- [ ] Both release lines have clear backport/cherry-pick guidance for API changes.
