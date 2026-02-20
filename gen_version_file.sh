version_file="arpvpn/__version__.py"

version=$(poetry version -s 2>/dev/null || true)
if [[ -z "$version" && -n "$CI_COMMIT_TAG" ]]; then
    version="${CI_COMMIT_TAG#v}"
fi
if [[ -z "$version" ]]; then
    version="0.0.0-dev"
fi

commit="${CI_COMMIT_SHA:-}"
if [[ -z "$commit" ]]; then
    commit=$(git rev-parse HEAD 2>/dev/null || true)
fi
if [[ -z "$commit" ]]; then
    commit="unknown"
fi

echo -e "release = '$version'\ncommit = '$commit'" > "$version_file"
