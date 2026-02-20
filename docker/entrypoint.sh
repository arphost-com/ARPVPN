#!/bin/bash

function install {
    echo -e "Installing ARPVPN..."
    # Include hidden files (.*)
    shopt -s dotglob
    # Move all files to exported path
    mv "$DATA_PATH"/* "$EXPORTED_PATH"
}

function run {
    echo -e "Running ARPVPN..."
    # Link conf files to install path
    rm -rf "$DATA_PATH"
    ln -s "$EXPORTED_PATH" "$DATA_PATH"
    chown -R arpvpn:arpvpn "$DATA_PATH"
    chown -R arpvpn:arpvpn "$EXPORTED_PATH"
    # Start uwsgi
    ls -l "$EXPORTED_PATH"
    sudo -E -u arpvpn /usr/bin/uwsgi --yaml "$DATA_PATH/uwsgi.yaml"
}

flag_file="$EXPORTED_PATH/.times_ran"
count=1
if [ ! -f "$flag_file" ]; then
    install
else
    count=$(cat "$flag_file")
    let "count++"
fi
echo "$count" > "$flag_file"
run
