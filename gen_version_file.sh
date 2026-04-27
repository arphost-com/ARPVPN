version_file="arpvpn/__version__.py"

version=$(poetry version -s 2>/dev/null || true)
if [[ -z "$version" && "${GITHUB_REF_TYPE:-}" == "tag" && -n "${GITHUB_REF_NAME:-}" ]]; then
    version="${GITHUB_REF_NAME#v}"
fi
if [[ -z "$version" ]]; then
    version="0.0.0-dev"
fi

commit="${GITHUB_SHA:-}"
if [[ -z "$commit" ]]; then
    commit=$(git rev-parse HEAD 2>/dev/null || true)
fi
if [[ -z "$commit" ]]; then
    commit="unknown"
fi

echo -e "release = '$version'\ncommit = '$commit'" > "$version_file"
