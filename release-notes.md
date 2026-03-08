# Release notes

## What's new

### 1.2.9

* API Added: tenant, user, tenant-member, and invitation endpoints for `/api/v1/tenants`, `/api/v1/users`, and `/api/v1/invitations`.
* API Changed: tenant-admin user management is tenant-scoped, and support users are now blocked from tenant CRUD.
* Docs: added docker02 clean-clone validation guidance and aligned release metadata/docs with the shipped stable line.
* Tests: removed redundant legacy dashboard/login checks while preserving equivalent coverage in the statistics and login suites.
* Validation: fresh end-to-end verification passed on `docker02` on 2026-03-08 for both release lines using clean clones and full signup/setup/auth/tenant/user/invitation flows.
* Known note: a fresh boot without an explicit WireGuard endpoint logs one startup warning while ARPVPN attempts automatic endpoint discovery.

### 1.2.8

* API Added: token auth endpoints (`/api/v1/auth/token`, `/api/v1/auth/refresh`) with access/refresh rotation.
* API Added: token/session control endpoints for revoke, revoke-all, and staff forced logout.
* API Added: impersonation API endpoints with structured audit logging for start/stop events.
* API Added: mesh control-plane endpoints (`/api/v1/mesh/*`) for topology/link/route/policy CRUD.
* API Added: mesh dry-run validation and mesh export/import JSON workflows.
* API Changed: API auth now includes rate-limiting and lockout controls for token issuance.
* Docs: added OpenAPI source (`docs/source/api/openapi.v1.yaml`), versioning/changelog process docs, and CI OpenAPI validation.
* Tests: added API auth and mesh API coverage to the CI hard-gate subset.

### 1.2.7

* Added full user account management in UI for staff roles:
  create, edit, and delete user workflows.
* Added role-safe permission enforcement for user management actions
  (support users limited to client accounts, self-delete blocked, and safety checks for admin accounts).
* Added dedicated edit-user page and expanded users page actions.
* Added/expanded user-management tests and included them in the CI hard-gate subset.

### 1.2.6

* Reduced interface-state log noise by replacing `ip | grep` checks with direct, non-noisy interface probes.
* Hardened WireGuard interface status probing to treat execution failures as `down` for observability views.
* Added regression tests for interface-up checks and WireGuard status behavior under missing/invalid binaries.

### 1.2.5

* Started Phase 1 of mesh/site-to-site expansion with persisted control-plane models:
  `topologies`, `vpn_links`, `route_advertisements`, and `access_policies`.
* Added route conflict detection for duplicate ownership and overlapping CIDRs.
* Extended WireGuard configuration serialization to include mesh control-plane state.
* Added Phase 1 model tests and included them in the CI hard-gate unit subset.

### 1.2.4

* Fixed TLS listener behavior to keep HTTP (`8085`) and HTTPS (`8086`) available together in self-signed/Let's Encrypt modes.
* Fixed HTTP access when HTTPS is enabled without redirect by only forcing secure cookies in strict-HTTPS mode.
* Updated HTTP-to-HTTPS redirect targets to include the configured HTTPS port when it is not `443`.
* Updated setup defaults to start with self-signed TLS and automatic certificate generation.
* Added TLS status metadata for web listener ports and strict-HTTPS mode to the API.

### 1.2.3

* Fixed production RRD graph support by installing `rrdtool` in the packaged runtime dependencies.
* Improved traffic history APIs/graphs to include current session data even when hourly persistence has not run yet.
* Added coverage to ensure history endpoints still return usable points when only session data is available.
* Reworked application footer to remove GitHub links and use ARPHost branding in light/dark themes.
* Expanded the About page with platform overview, ARPHost information, revision/build details, and WireGuard background.

### 1.2.2

* Added scoped statistics APIs for admins/clients including per-connection history and RRD metadata endpoints.
* Added TLS management APIs for mode switching, self-signed generation, Let's Encrypt issue/renew, and certificate status.
* Standardized API error/success envelopes for JSON APIs and added request ID propagation (`X-Request-ID`).
* Expanded tests and CI hard-gate coverage for statistics and TLS API behavior.

### 1.2.1

* Improved theme consistency on the login screen by fixing browser autofill color overrides.
* Added a configurable option to redirect HTTP requests to HTTPS when TLS mode is active.
* Added an expanded top-right theme switcher and settings-page quick theme controls.

### Previous updates

* Ban time is now editable and applies to individual IP addresses instead of globally (which makes much more sense).

## Fixes

* Fixed a bug with the settings page which caused the display of default/last saved settings everytime the page was reloaded, even though the values were actually being stored in the configuration file and applied.

## Docs

* Added entry for ban time.
