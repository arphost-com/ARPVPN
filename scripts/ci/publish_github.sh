#!/usr/bin/env bash
set -euo pipefail

: "${CI_COMMIT_SHA:?}"
: "${CI_COMMIT_BRANCH:?}"
: "${CI_DEFAULT_BRANCH:?}"
: "${CI_PROJECT_DIR:?}"
: "${GITHUB_PUSH_TOKEN:?}"

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
