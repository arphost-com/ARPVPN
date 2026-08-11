#!/usr/bin/env bash
set -euo pipefail

required=(
  ARPVPN_DEPLOY_PATH
  ARPVPN_DATA_FOLDER
  ARPVPN_DEPLOY_IMAGE
  ARPVPN_CONTAINER_NAME
  ARPVPN_COMPOSE_PROJECT
  CI_PROJECT_DIR
  CI_REGISTRY
  CI_REGISTRY_IMAGE
  CI_REGISTRY_USER
  CI_REGISTRY_PASSWORD
)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required deployment variable: $name" >&2
    exit 1
  fi
done

deploy_user="debian"
service_name="${ARPVPN_SERVICE_NAME:-arpvpn}"
env_file_name="${ARPVPN_ENV_FILE:-.env}"
runtime_uid="${ARPVPN_RUNTIME_UID:-1000}"
runtime_gid="${ARPVPN_RUNTIME_GID:-1000}"

if [[ ! "$env_file_name" =~ ^[A-Za-z0-9._-]+$ ]] || [[ "$env_file_name" == "." ]] || [[ "$env_file_name" == ".." ]]; then
  echo "ARPVPN_ENV_FILE must be a plain file name." >&2
  exit 1
fi
if [[ ! "$service_name" =~ ^[A-Za-z0-9._-]+$ ]] || [[ ! "$ARPVPN_CONTAINER_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Invalid service or container name." >&2
  exit 1
fi
if [[ ! "$ARPVPN_COMPOSE_PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "Invalid Docker Compose project name." >&2
  exit 1
fi
if [[ ! "$runtime_uid" =~ ^[0-9]+$ ]] || [[ ! "$runtime_gid" =~ ^[0-9]+$ ]]; then
  echo "Runtime UID and GID must be numeric." >&2
  exit 1
fi

deploy_path="$(realpath -m -- "$ARPVPN_DEPLOY_PATH")"
data_folder="$(realpath -m -- "$ARPVPN_DATA_FOLDER")"
case "$deploy_path" in
  /home/*/docker/* | /srv/* | /opt/*) ;;
  *)
    echo "Deployment path is outside the allowed host prefixes." >&2
    exit 1
    ;;
esac
case "$data_folder/" in
  "$deploy_path"/*) ;;
  *)
    echo "Data folder must be contained by the deployment path." >&2
    exit 1
    ;;
esac
if [[ "$deploy_path" == "/" || "$data_folder" == "/" || "$deploy_path" == "$data_folder" ]]; then
  echo "Refusing an unsafe deployment or data path." >&2
  exit 1
fi

image_prefix="$CI_REGISTRY_IMAGE@sha256:"
if [[ "$ARPVPN_DEPLOY_IMAGE" != "$image_prefix"* ]]; then
  if [[ "${ARPVPN_ALLOW_REGISTRY_ROLLBACK_IMAGE:-0}" != "1" || "$ARPVPN_DEPLOY_IMAGE" != "$CI_REGISTRY/"* ]]; then
    echo "Deployment image must be an immutable digest from this project registry." >&2
    exit 1
  fi
else
  image_digest="${ARPVPN_DEPLOY_IMAGE#"$image_prefix"}"
  if [[ ! "$image_digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Deployment image has an invalid sha256 digest." >&2
    exit 1
  fi
fi
if [[ "$ARPVPN_DEPLOY_IMAGE" =~ [[:space:]] ]]; then
  echo "Deployment image contains whitespace." >&2
  exit 1
fi

for port_name in ARPVPN_HTTP_PORT ARPVPN_HTTPS_PORT; do
  port_value="${!port_name:-}"
  if [[ -n "$port_value" ]] && { [[ ! "$port_value" =~ ^[0-9]+$ ]] || (( port_value < 1 || port_value > 65535 )); }; then
    echo "$port_name must be a valid TCP port." >&2
    exit 1
  fi
done

deploy_uid="$(id -u "$deploy_user")"
deploy_gid="$(id -g "$deploy_user")"
sudo -n install -d -o "$deploy_uid" -g "$deploy_gid" -m 2770 "$deploy_path"
sudo -n install -d -o "$runtime_uid" -g "$runtime_gid" -m 2770 "$data_folder"
sudo -n install -o "$deploy_uid" -g "$deploy_gid" -m 0660 \
  "$CI_PROJECT_DIR/docker/docker-compose.yaml" "$deploy_path/docker-compose.yaml"
sudo -n install -o "$deploy_uid" -g "$deploy_gid" -m 0750 \
  "$CI_PROJECT_DIR/docker/up.sh" "$deploy_path/up.sh"
sudo -n install -o "$deploy_uid" -g "$deploy_gid" -m 0750 \
  "$CI_PROJECT_DIR/scripts/ci/update_env.py" "$deploy_path/update_env.py"

env_path="$deploy_path/$env_file_name"
assignments=(
  "ARPVPN_IMAGE=$ARPVPN_DEPLOY_IMAGE"
  "ARPVPN_RUNTIME_USER=arpvpn"
  "ARPVPN_UID=$runtime_uid"
  "ARPVPN_GID=$runtime_gid"
  "ARPVPN_CONTAINER_NAME=$ARPVPN_CONTAINER_NAME"
  "DATA_FOLDER=$data_folder"
)
[[ -n "${ARPVPN_COOKIE_SUFFIX:-}" ]] && assignments+=("ARPVPN_COOKIE_SUFFIX=$ARPVPN_COOKIE_SUFFIX")
[[ -n "${ARPVPN_HTTP_PORT:-}" ]] && assignments+=("ARPVPN_HTTP_PORT=$ARPVPN_HTTP_PORT")
[[ -n "${ARPVPN_HTTPS_PORT:-}" ]] && assignments+=("ARPVPN_HTTPS_PORT=$ARPVPN_HTTPS_PORT")

previous_image=""
if sudo -n -u "$deploy_user" test -f "$env_path"; then
  previous_image="$(sudo -n -u "$deploy_user" awk -F= '$1 == "ARPVPN_IMAGE" { value=$0; sub(/^[^=]*=/, "", value) } END { print value }' "$env_path")"
fi
sudo -n -u "$deploy_user" python3 "$deploy_path/update_env.py" "$env_path" "${assignments[@]}"
sudo -n find "$data_folder" -type d -exec chmod 2770 {} +
sudo -n find "$data_folder" -type f -exec chmod 0660 {} +
sudo -n chown -R "$runtime_uid:$runtime_gid" "$data_folder"

auth_dir="$(mktemp -d "/tmp/arpvpn-docker-auth-${CI_JOB_ID:-manual}.XXXXXX")"
cleanup() {
  sudo -n rm -rf -- "$auth_dir"
}
trap cleanup EXIT
sudo -n chown "$deploy_uid:$deploy_gid" "$auth_dir"
printf '%s' "$CI_REGISTRY_PASSWORD" | sudo -n -u "$deploy_user" env DOCKER_CONFIG="$auth_dir" \
  docker login "$CI_REGISTRY" -u "$CI_REGISTRY_USER" --password-stdin >/dev/null
sudo -n -u "$deploy_user" env DOCKER_CONFIG="$auth_dir" docker pull "$ARPVPN_DEPLOY_IMAGE"
sudo -n -u "$deploy_user" env DOCKER_CONFIG="$auth_dir" \
  docker compose -p "$ARPVPN_COMPOSE_PROJECT" -f "$deploy_path/docker-compose.yaml" \
  --env-file "$env_path" up -d --no-build --force-recreate "$service_name"

if [[ -n "${ARPVPN_DEPLOY_RESULT_FILE:-}" ]]; then
  case "$(realpath -m -- "$ARPVPN_DEPLOY_RESULT_FILE")" in
    "$CI_PROJECT_DIR"/*) ;;
    *)
      echo "Deployment result file must be inside CI_PROJECT_DIR." >&2
      exit 1
      ;;
  esac
  {
    printf 'ARPVPN_PREVIOUS_IMAGE=%s\n' "$previous_image"
    printf 'ARPVPN_DEPLOYED_IMAGE=%s\n' "$ARPVPN_DEPLOY_IMAGE"
  } > "$ARPVPN_DEPLOY_RESULT_FILE"
fi

echo "Started $ARPVPN_CONTAINER_NAME with the requested registry image."
