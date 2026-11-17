#!/usr/bin/env bash
# Purge unused Docker images and build cache on the CI host after a deploy.
#
# Runs once the new ARPVPN container is healthy, so rollback images come from
# the GitLab registry, not the host. Volumes and stopped containers are never
# touched. Cleanup is best effort and never fails the calling job.
set -uo pipefail

report() {
  echo "== Disk usage $1 cleanup"
  df -h / 2>/dev/null | tail -n 1
  docker system df 2>/dev/null || true
}

report before
docker image prune -a -f 2>/dev/null | tail -n 1 || echo "Image prune failed; continuing." >&2
docker builder prune -a -f 2>/dev/null | tail -n 1 || echo "Build cache prune failed; continuing." >&2
report after
exit 0
