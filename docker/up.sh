#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: missing env file: $ENV_FILE"
  echo "Copy $SCRIPT_DIR/.env.example to $SCRIPT_DIR/.env and configure values."
  exit 1
fi

# Load DATA_FOLDER from .env
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

data_folder="${DATA_FOLDER:-./data}"
if [[ "$data_folder" != /* ]]; then
  data_folder="$SCRIPT_DIR/$data_folder"
fi

if [ ! -d "$data_folder" ]; then
  mkdir -p "$data_folder"
fi

if [ ! -w "$data_folder" ]; then
  echo "ERROR: DATA_FOLDER is not writable by host user $(id -u):$(id -g): $data_folder"
  ls -ld "$data_folder" || true
  echo "Fix ownership, then retry:"
  echo "  sudo chown -R $(id -u):$(id -g) '$data_folder'"
  exit 1
fi

if [ "$#" -eq 0 ]; then
  set -- up -d --build --force-recreate arpvpn
fi

exec docker compose -f "$SCRIPT_DIR/docker-compose.yaml" --env-file "$ENV_FILE" "$@"
