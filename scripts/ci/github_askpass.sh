#!/usr/bin/env sh
set -eu

prompt=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')
case "$prompt" in
  *username*) printf '%s\n' "x-access-token" ;;
  *) printf '%s\n' "${GITHUB_PUSH_TOKEN:?}" ;;
esac
