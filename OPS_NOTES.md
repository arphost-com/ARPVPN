# Ops Notes

## Release Line Status

- `main` (v1 stable line): `1.2.8`
- `codex/multitenant-v2` (v2 line): `2.x` in-progress

## Image Tags

- v1 stable: `10.10.10.96:5050/arphost/arpvpn:stable`
- v1 compatibility: `10.10.10.96:5050/arphost/arpvpn:1.2.x`
- v2 latest: `10.10.10.96:5050/arphost/arpvpn:v2-latest`

## Deployment Host Notes

- Runtime host for current ARPVPN deployment: `docker03` (`10.10.10.100`)
- GitLab host / registry origin: `docker01` (`10.10.10.96`)

## docker02 ARPVPN Paths

- Multitenant working clone used for validation: `/home/debian/ARPVPN-v2test`
- Historical clone used in prior runs: `/home/debian/ARPVPN`
- Docker workspace clones present: `/home/debian/docker/arpvpn-git` and `/home/debian/docker/arpvpn-clean-test`
- Note: user-reported path was `/home/debian/docker/ARPVPN` (uppercase), but current host path is lowercase `arpvpn-*`.

### docker03 ARPVPN paths

- Legacy/stable stack path: `/home/debian/docker/arpvpn`
- Multitenant test stack path: `/home/debian/docker/vpn1`
- Multitenant compose working dir: `/home/debian/docker/vpn1/docker`
- Multitenant data path: `/home/debian/docker/vpn1/docker/data`

### docker03 multitenant runtime checks

- Ensure the multitenant container is the active one:
  - `ssh docker03 'docker ps --format "{{.Names}}\t{{.Image}}\t{{.Status}}" | grep -E "vpn1|arpvpn"'`
- Verify multitenant code version inside container:
  - `ssh docker03 'docker exec vpn1 sh -lc "cat /var/www/arpvpn/arpvpn/__version__.py"'`
- Check CSRF/login events:
  - `ssh docker03 'tail -n 200 /home/debian/docker/vpn1/docker/data/arpvpn.log'`

### CSRF troubleshooting (docker03 multitenant)

- Use one origin consistently during setup/login (`http://<same-host>:1085`).
- Do not switch hostnames/IPs between loading and submitting forms (host-only cookies).
- If `redirect_http_to_https` is enabled later, continue with HTTPS only.

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
