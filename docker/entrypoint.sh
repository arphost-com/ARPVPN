#!/bin/bash
set -euo pipefail

runtime_uid="$(id -u)"
runtime_gid="$(id -g)"

function ensure_exported_path_is_writable {
    mkdir -p "$EXPORTED_PATH"
    if [ ! -w "$EXPORTED_PATH" ]; then
        echo "ERROR: '$EXPORTED_PATH' is not writable by UID:GID ${runtime_uid}:${runtime_gid}."
        echo "Fix host path ownership/permissions to match the container user from Dockerfile."
        ls -ld "$EXPORTED_PATH" || true
        exit 1
    fi
}

function install {
    echo "Installing ARPVPN..."
    shopt -s dotglob nullglob
    if [ -d "$DATA_PATH" ]; then
        data_files=("$DATA_PATH"/*)
        if [ ${#data_files[@]} -gt 0 ]; then
            mv "$DATA_PATH"/* "$EXPORTED_PATH"/
        fi
    fi
}

function run {
    echo "Running ARPVPN as UID:GID ${runtime_uid}:${runtime_gid}..."
    rm -rf "$DATA_PATH"
    ln -s "$EXPORTED_PATH" "$DATA_PATH"
    ls -l "$EXPORTED_PATH"
    exec /usr/bin/uwsgi --yaml "$DATA_PATH/uwsgi.yaml"
}

ensure_exported_path_is_writable
flag_file="$EXPORTED_PATH/.times_ran"
count=1
if [ ! -f "$flag_file" ]; then
    install
else
    count="$(cat "$flag_file" 2>/dev/null || echo 0)"
    count=$((count + 1))
fi
echo "$count" > "$flag_file"
run
