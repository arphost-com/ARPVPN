#!/usr/bin/env bash
set -euo pipefail

: "${CI_COMMIT_SHA:?}"
: "${CI_COMMIT_BRANCH:?}"
: "${CI_DEFAULT_BRANCH:?}"
: "${CI_PROJECT_DIR:?}"
: "${GITHUB_PAT:?GITHUB_PAT (global GitLab CI variable) is required for GitHub publication}"

if [[ "$CI_COMMIT_BRANCH" != "$CI_DEFAULT_BRANCH" ]]; then
  echo "GitHub publication is restricted to the GitLab default branch." >&2
  exit 1
fi

github_url="https://x-access-token@github.com/arphost-com/ARPVPN.git"
export GIT_ASKPASS="$CI_PROJECT_DIR/scripts/ci/github_askpass.sh"
export GIT_TERMINAL_PROMPT=0

git -c credential.helper= -c credential.interactive=always fetch --no-tags "$github_url" \
  main:refs/remotes/github-publication/main
if ! git merge-base --is-ancestor refs/remotes/github-publication/main "$CI_COMMIT_SHA"; then
  echo "GitHub main is not an ancestor of the validated GitLab commit; refusing publication." >&2
  exit 1
fi

git -c credential.helper= -c credential.interactive=always push \
  "$github_url" "$CI_COMMIT_SHA:refs/heads/main"
echo "Published the validated GitLab commit to the allowlisted GitHub repository."

# Tag the release so installs can find it from Settings > Updates. An existing
# tag is never moved: it must already point at this commit or publication stops.
release="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["tool"]["poetry"]["version"])')"
if [[ ! "$release" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Release version '$release' is not a stable semantic version; refusing to tag." >&2
  exit 1
fi
release_tag="v$release"
existing_tag_sha="$(git -c credential.helper= -c credential.interactive=always ls-remote --tags \
  "$github_url" "refs/tags/$release_tag" | awk '{print $1}')"
if [[ -n "$existing_tag_sha" ]]; then
  if [[ "$existing_tag_sha" != "$CI_COMMIT_SHA" ]]; then
    echo "GitHub tag $release_tag already points at $existing_tag_sha, not $CI_COMMIT_SHA; refusing to move it." >&2
    exit 1
  fi
  echo "GitHub tag $release_tag already points at the validated commit."
else
  git -c credential.helper= -c credential.interactive=always push \
    "$github_url" "$CI_COMMIT_SHA:refs/tags/$release_tag"
  echo "Published release tag $release_tag."
fi
