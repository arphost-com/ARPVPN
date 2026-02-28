# ARPVPN API Changelog Process

This process applies to both release lines:

- `main` (`1.2.x`)
- `codex/multitenant-v2` (`2.x`)

## Required updates per API change

1. Update `docs/source/api/openapi.v1.yaml` (or the v2 OpenAPI document on `codex/multitenant-v2`).
2. Add a release-notes entry in `release-notes.md` with API-specific bullets.
3. Update checklist status in `API_CONTROL_TODO.md` / `MESH_ACL_TODO.md` as applicable.
4. Add/adjust API tests and ensure CI hard-gate passes.

## Backport/cherry-pick guidance

- Changes created on `main` that are needed in v2 should be cherry-picked to `codex/multitenant-v2`.
- v2-only API features must not be merged into `main`.

## Entry format

Use explicit tags in release notes:

- `API Added`
- `API Changed`
- `API Deprecated`
- `API Fixed`

Each entry should include:

- endpoint path(s)
- role/scope impact
- compatibility impact (non-breaking vs breaking)
