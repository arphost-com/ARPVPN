# ARPVPN API Changelog Process

This process applies to the private ARPVPN line in this repository.

## Required updates per API change

1. Update `docs/source/api/openapi.v1.yaml`.
2. Add a release-notes entry in `release-notes.md` with API-specific bullets.
3. Update checklist status in `MESH_ACL_TODO.md` as applicable.
4. Add/adjust API tests and ensure CI hard-gate passes.

## Cross-repo guidance

- If a change also belongs in the public single-tenant repository, cherry-pick it there explicitly.
- Keep this repository's release notes and OpenAPI document accurate even when the same change ships elsewhere.

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
