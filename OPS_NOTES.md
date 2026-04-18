# Ops Notes

## Release Line Status

- `main` release line: `2.0.4`

## Image Tags

- latest: `10.10.10.96:5050/arphost/arpvpn:latest`
- compatibility: `10.10.10.96:5050/arphost/arpvpn:2.x`

## Deployment Host Notes

- Runtime host for current ARPVPN deployment: `docker03` (`10.10.10.100`)
- GitLab host / registry origin: `docker01` (`10.10.10.96`)

## docker02 ARPVPN Paths

- Keep the release working clone at `/home/debian/docker/arpvpn`.
- Keep the public-line working clone at `/home/debian/docker/arpvpn`.
- Do not keep ad-hoc ARPVPN test or stage clones under `/home/debian/docker`.
- If a full validation run needs a clean checkout, delete `/home/debian/docker/arpvpn` and `git clone` a fresh copy back into that path.
- Fresh docker02 validation completed on `2026-03-26`.
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
  docker login http://10.10.10.96:5050 -u <gitlab-user> &&
  docker compose pull arpvpn &&
  docker compose up -d --force-recreate arpvpn &&
  docker compose ps &&
  docker logs --tail 120 arpvpn
'
```

### Standard production rollback (operator-run)

```bash
ssh docker03 '
  cd /home/debian/docker/arpvpn &&
  sed -i "s|^ARPVPN_IMAGE=.*|ARPVPN_IMAGE=<previous-tag>|" .env &&
  docker compose up -d --force-recreate arpvpn &&
  docker compose ps &&
  docker logs --tail 120 arpvpn
'
```

### docker03 ARPVPN paths

- Active production stack path: `/home/debian/docker/arpvpn`
- Active compose working dir: `/home/debian/docker/arpvpn`
- Active data path: `/home/debian/docker/arpvpn/data`

### docker03 runtime checks

- Ensure the target container is the active one:
  - `ssh docker03 'docker ps --format "{{.Names}}\t{{.Image}}\t{{.Status}}" | grep -E "^arpvpn\b"'`
- Verify code version inside container:
  - `ssh docker03 'docker exec arpvpn sh -lc "cat /var/www/arpvpn/arpvpn/__version__.py"'`
- Check CSRF/login events:
  - `ssh docker03 'tail -n 200 /home/debian/docker/arpvpn/data/arpvpn.log'`

### Production guardrail (docker03)

- Do not apply code/config changes directly on `docker03` (production).
- Reproduce and validate fixes on `docker02`, then ship via GitLab image/tag and pull on `docker03`.
- Use read-only diagnostics on `docker03`:
  - `ssh docker03 'docker compose logs --tail=200'`
  - `ssh docker03 'tail -n 200 /home/debian/docker/arpvpn/data/arpvpn.log'`

### CSRF troubleshooting (docker03)

- Use one origin consistently during setup/login (`http://<same-host>:1085`).
- Do not switch hostnames/IPs between loading and submitting forms (host-only cookies).
- If `redirect_http_to_https` is enabled later, continue with HTTPS only.

### Multi-stack runtime notes

- Keep these values unique per stack on the same host:
  - `ARPVPN_CONTAINER_NAME`
  - `ARPVPN_COOKIE_SUFFIX` (or explicit cookie names)
  - `DATA_FOLDER`
  - `ARPVPN_HTTP_PORT`
  - `ARPVPN_HTTPS_PORT`
- Compose now auto-creates `DATA_FOLDER` bind paths on first startup (`create_host_path: true`).
- `./docker/up.sh` remains the recommended wrapper because it validates host-path ownership before launch.

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
