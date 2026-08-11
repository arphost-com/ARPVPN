#!/usr/bin/env bash
set -euo pipefail

required=(
  ARPVPN_DEPLOY_PATH
  ARPVPN_DATA_FOLDER
  ARPVPN_DEPLOY_IMAGE
  ARPVPN_CONTAINER_NAME
  ARPVPN_COMPOSE_PROJECT
)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required smoke-test variable: $name" >&2
    exit 1
  fi
done

deploy_user="debian"
service_name="${ARPVPN_SERVICE_NAME:-arpvpn}"
env_file_name="${ARPVPN_ENV_FILE:-.env}"
deploy_path="$(realpath -m -- "$ARPVPN_DEPLOY_PATH")"
data_folder="$(realpath -m -- "$ARPVPN_DATA_FOLDER")"
env_path="$deploy_path/$env_file_name"

show_failure() {
  sudo -n -u "$deploy_user" docker compose -p "$ARPVPN_COMPOSE_PROJECT" \
    -f "$deploy_path/docker-compose.yaml" --env-file "$env_path" \
    logs --tail=120 "$service_name" || true
}
trap show_failure ERR

container_id=""
for attempt in $(seq 1 36); do
  container_id="$(sudo -n -u "$deploy_user" docker compose -p "$ARPVPN_COMPOSE_PROJECT" \
    -f "$deploy_path/docker-compose.yaml" --env-file "$env_path" ps -q "$service_name")"
  if [[ -n "$container_id" ]]; then
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$container_id")"
    if [[ "$status" == "healthy" ]]; then
      break
    fi
    if [[ "$status" == "unhealthy" ]]; then
      echo "Container became unhealthy." >&2
      exit 1
    fi
  fi
  if [[ "$attempt" == "36" ]]; then
    echo "Container did not become healthy before the timeout." >&2
    exit 1
  fi
  sleep 5
done

actual_image="$(docker inspect --format '{{.Config.Image}}' "$container_id")"
if [[ "$actual_image" != "$ARPVPN_DEPLOY_IMAGE" ]]; then
  echo "Running image mismatch: expected $ARPVPN_DEPLOY_IMAGE, got $actual_image" >&2
  exit 1
fi

if [[ -n "${ARPVPN_HEALTH_URL:-}" ]]; then
  case "$ARPVPN_HEALTH_URL" in
    http://127.0.0.1:* | https://127.0.0.1:* | http://localhost:* | https://localhost:*) ;;
    *)
      echo "Health URL must use loopback HTTP or HTTPS." >&2
      exit 1
      ;;
  esac
  curl --fail --silent --show-error --max-time 10 --insecure "$ARPVPN_HEALTH_URL" >/dev/null
fi

if [[ -n "${ARPVPN_RELEASE_VERSION:-}" ]]; then
  observed_version="$(docker exec "$container_id" /bin/bash -lc \
    'cd /var/www/arpvpn && PYTHONPATH=/var/www/arpvpn /var/www/arpvpn/venv/bin/python -c "from arpvpn.__version__ import release; print(release)"' \
    | tail -n1)"
  if [[ "$observed_version" != "$ARPVPN_RELEASE_VERSION" ]]; then
    echo "Running version mismatch: expected $ARPVPN_RELEASE_VERSION, got $observed_version" >&2
    exit 1
  fi
fi

if sudo -n find "$deploy_path" -maxdepth 2 -user gitlab-runner -print -quit | grep -q .; then
  echo "Deployment path contains files owned by gitlab-runner." >&2
  exit 1
fi
if sudo -n find "$data_folder" -maxdepth 2 -user gitlab-runner -print -quit | grep -q .; then
  echo "Runtime data contains files owned by gitlab-runner." >&2
  exit 1
fi

trap - ERR
docker inspect --format '{{.Name}} {{.State.Health.Status}} {{.Config.Image}}' "$container_id"
echo "ARPVPN smoke test passed."
