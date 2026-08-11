#!/usr/bin/env bash
set -euo pipefail

: "${ARPVPN_DEPLOY_IMAGE:?}"
: "${ARPVPN_RELEASE_VERSION:?}"
: "${CI_REGISTRY:?}"
: "${CI_REGISTRY_IMAGE:?}"
: "${CI_REGISTRY_USER:?}"
: "${CI_REGISTRY_PASSWORD:?}"
: "${CI_PROJECT_DIR:?}"

expected_prefix="$CI_REGISTRY_IMAGE@sha256:"
[[ "$ARPVPN_DEPLOY_IMAGE" == "$expected_prefix"* ]] || {
  echo "Only an immutable image from this project can be promoted." >&2
  exit 1
}
expected_digest="${ARPVPN_DEPLOY_IMAGE#"$expected_prefix"}"
[[ "$expected_digest" =~ ^[0-9a-f]{64}$ ]] || exit 1

auth_dir="$(mktemp -d "$CI_PROJECT_DIR/.docker-auth-promote.XXXXXX")"
trap 'rm -rf -- "$auth_dir"' EXIT
export DOCKER_CONFIG="$auth_dir"
printf '%s' "$CI_REGISTRY_PASSWORD" | docker login "$CI_REGISTRY" -u "$CI_REGISTRY_USER" --password-stdin >/dev/null

version_tag="$CI_REGISTRY_IMAGE:$ARPVPN_RELEASE_VERSION"
if existing_json="$(docker buildx imagetools inspect "$version_tag" --format '{{json .Manifest.Digest}}' 2>/dev/null)"; then
  existing_digest="${existing_json#\"}"
  existing_digest="${existing_digest%\"}"
  if [[ "$existing_digest" != "sha256:$expected_digest" ]]; then
    echo "Refusing to overwrite $version_tag with a different digest." >&2
    exit 1
  fi
fi

docker pull "$ARPVPN_DEPLOY_IMAGE"
docker tag "$ARPVPN_DEPLOY_IMAGE" "$version_tag"
docker tag "$ARPVPN_DEPLOY_IMAGE" "$CI_REGISTRY_IMAGE:stable"
docker push "$version_tag"
docker push "$CI_REGISTRY_IMAGE:stable"
echo "Promoted sha256:$expected_digest to $ARPVPN_RELEASE_VERSION and stable."
