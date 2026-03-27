# Ops Notes

## Release Line Status

- `main` (public single-tenant line): `1.2.12`

## Image Tags

- stable: `10.10.10.96:5050/arphost/arpvpn:stable`
- compatibility: `10.10.10.96:5050/arphost/arpvpn:1.2.x`

## Deployment Host Notes

- Runtime host for current ARPVPN deployment: `docker03` (`10.10.10.100`)
- GitLab host / registry origin: `docker01` (`10.10.10.96`)

## docker02 ARPVPN Paths

- Keep the public-line working clone at `/home/debian/docker/arpvpn`.
- Do not keep ad-hoc ARPVPN test or stage clones under `/home/debian/docker`.
- If a full validation run needs a clean checkout, delete `/home/debian/docker/arpvpn` and `git clone` a fresh copy back into that path.
- Fresh docker02 public-line validation completed on `2026-03-26`.
- Result: generated OpenAPI validated, the focused hard-gate subset passed, the package build passed, and the Docker image build passed.
- Only observed log warning on fresh boot: `No endpoint specified. Retrieving public IP address...`

### Production Change Policy (`docker03`)

- Treat `docker03` as production and read-only by default.
- Never run mutating commands on `docker03` unless explicitly approved by the user (`approved prod change`).
- Default allowed checks on `docker03`: `docker ps`, `docker logs`, `cat`, `tail`, `grep`, `ls`.
- Build, test, and validate on non-prod first (`docker02`/local), then provide operator command blocks for production execution.
- Always include a rollback command block with production deploy instructions.

### Standard production deploy (operator-run)

```bash
ssh docker03 '
  cd /home/debian/docker/arpvpn &&
  git fetch origin &&
  git checkout main &&
  git reset --hard origin/main &&
  cd docker &&
  docker login http://10.10.10.96:5050 -u <gitlab-user> &&
  docker compose pull arpvpn &&
  docker compose up -d --force-recreate arpvpn &&
  docker compose ps &&
  docker logs --tail 120 vpn1
'
```

### Standard production rollback (operator-run)

```bash
ssh docker03 '
  cd /home/debian/docker/vpn1/docker &&
  sed -i "s|^ARPVPN_IMAGE=.*|ARPVPN_IMAGE=<previous-tag>|" .env &&
  docker compose up -d --force-recreate arpvpn &&
  docker compose ps &&
  docker logs --tail 120 vpn1
'
```

### docker03 ARPVPN paths

- Stable stack path: `/home/debian/docker/arpvpn`
- Stable compose working dir: `/home/debian/docker/arpvpn/docker`
- Stable data path: `/home/debian/docker/arpvpn/docker/data`

### Production guardrail (docker03)

- Do not apply code/config changes directly on `docker03` (production).
- Reproduce and validate fixes on `docker02`, then ship via GitLab image/tag and pull on `docker03`.
- Use read-only diagnostics on `docker03`:
  - `ssh docker03 'docker compose logs --tail=200'`
  - `ssh docker03 'tail -n 200 /home/debian/docker/arpvpn/docker/data/arpvpn.log'`

## Local Service Endpoints (Always Use)

- GitLab (local): `http://10.10.10.96:8929/`
- Registry (local insecure HTTP): `http://10.10.10.93:5353`

## Private Access Policy (All Repos)

- All repositories are private on local GitLab.
- Pull/push for all repos requires authenticated Git access (SSH key or token).
- Container pulls for all private repo images require registry login on each host:
  - `docker login http://10.10.10.96:5050 -u <gitlab-username>`
- For scripted/non-interactive login:
  - `echo "$CI_REGISTRY_PASSWORD" | docker login "http://$CI_REGISTRY" -u "$CI_REGISTRY_USER" --password-stdin`
- If image pull fails with auth errors (`unauthorized` / `denied`), re-run `docker login` first.
