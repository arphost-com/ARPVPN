# ARPVPN TODO

This tracks follow-up work for the current ARPVPN feature set. The project already has the main feature surfaces in code and documentation; the remaining work is mostly hardening, UI parity, and deployment validation.

## Multitenant Isolation

- [x] Keep tenant creation restricted to super admins only.
- [x] Let `tenant_admin` users open `/users` and manage only users in their assigned tenant.
- [x] Let `tenant_admin` users create, edit, start, stop, and restart only WireGuard interfaces owned by their tenant.
- [x] Ensure tenant admins never see or select the original unassigned/control-plane WireGuard interface.
- [x] Add tenant selection to admin user creation/edit screens for `tenant_admin` and tenant-scoped `client` accounts.
- [x] Show tenant names in the users table so the super admin can audit account ownership.
- [x] Align UI access checks with existing `/api/v1` tenant checks for users, peers, interfaces, invitations, and runtime settings.

## Invitations And Memberships

- [x] Add browser UI for tenant invitations: create, resend, revoke, and accept.
- [x] Reconcile the SQLite tenancy membership bootstrap with the encrypted YAML tenant/user stores so membership state has one clear source of truth.
- [x] Add regression coverage for tenant invitation acceptance creating the correct role and tenant assignment.

## WireGuard Feature Parity

- [x] Add focused tests for client peers, site-to-site peers, remote subnets, full-tunnel config output, and disabled-peer config generation.
- [x] Add tenant-scoped tests for interface and peer list/detail/download routes.
- [x] Confirm CSV/JSON export endpoints filter traffic/statistics by tenant for tenant admins and clients.
- [x] Add tenant-scoped WireGuard interface and peer inventory exports in CSV and JSON.

## Security And Auth

- [x] Add regression tests for CSRF-protected cookie API writes, bearer-token writes, token refresh/revoke/revoke-all, rate limiting, and auth lockouts.
- [x] Add MFA tests for TOTP setup, recovery-code consumption, and protected client config download.
- [x] Document tenant-admin limits in API auth/RBAC docs.
- [x] Add browser profile UI for API token issue, active-token review, individual revoke, and revoke-all lifecycle actions.

## Deployment

- [x] Deploy this branch to `docker02` for validation after the multitenant UI/access changes are implemented.
- [x] Smoke-test Docker startup, setup, login, tenant creation, tenant-admin login, tenant interface creation, peer download, stats pages, CSV/JSON exports, and API token flow.
- [x] Confirm systemd install docs still match the current config/data layout.
- [x] Add a private GitLab pipeline that tests automatically on docker02 before any production promotion.
- [x] Keep production deployment manual and restricted to protected default-branch pipelines.
- [x] Keep all deployment secrets in private masked/protected CI variables, not in this public repository.
