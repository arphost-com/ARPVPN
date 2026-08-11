#!/usr/bin/env sh
case "$1" in
  *Username*) printf '%s\n' "x-access-token" ;;
  *Password*) printf '%s\n' "${GITHUB_PUSH_TOKEN:?}" ;;
  *) exit 1 ;;
esac
