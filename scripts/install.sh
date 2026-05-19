#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/log.sh" ]]; then
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/log.sh"
elif [[ -f ./log.sh ]]; then
    # shellcheck disable=SC1090
    source ./log.sh
else
    echo "Unable to locate log.sh."
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
   fatal "This script must be run as superuser! Try using sudo."
   exit 1
fi

if [[ $# -gt 0 ]]; then
  fatal "Invalid arguments."
  info "Usage: $0"
  exit 1
fi

INSTALL_DIR="/var/www/arpvpn"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
WIREGUARD_TOOLS_FROM_SOURCE="${ARPVPN_WIREGUARD_TOOLS_FROM_SOURCE:-1}"
WIREGUARD_TOOLS_VERSION="${ARPVPN_WIREGUARD_TOOLS_VERSION:-1.0.20260223}"
WIREGUARD_TOOLS_SHA256="${ARPVPN_WIREGUARD_TOOLS_SHA256:-af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf}"

install_wireguard_tools_from_source() {
    local version="$WIREGUARD_TOOLS_VERSION"
    local expected_sha256="$WIREGUARD_TOOLS_SHA256"
    local actual_sha256
    local source_url
    local source_dir
    local tarball
    local tmp_dir

    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]{8}$ ]]; then
        fatal "Invalid WireGuard Tools version: $version"
        exit 1
    fi

    if [[ "$version" != "1.0.20260223" && -z "${ARPVPN_WIREGUARD_TOOLS_SHA256:-}" ]]; then
        fatal "ARPVPN_WIREGUARD_TOOLS_SHA256 must be set when overriding ARPVPN_WIREGUARD_TOOLS_VERSION."
        exit 1
    fi

    tmp_dir="$(mktemp -d)"
    tarball="$tmp_dir/wireguard-tools-$version.tar.xz"
    source_dir="$tmp_dir/wireguard-tools-$version"
    source_url="https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-$version.tar.xz"

    debug "Downloading WireGuard Tools $version from $source_url..."
    curl -fsSL "$source_url" -o "$tarball"
    actual_sha256="$(sha256sum "$tarball" | awk '{print $1}')"
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
        rm -rf "$tmp_dir"
        fatal "WireGuard Tools checksum mismatch: expected $expected_sha256, got $actual_sha256."
        exit 1
    fi

    tar -xJf "$tarball" -C "$tmp_dir"
    make -C "$source_dir/src" WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no PREFIX=/usr
    make -C "$source_dir/src" WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no PREFIX=/usr install
    rm -rf "$tmp_dir"
    info "Installed $(wg --version)."
}

if [[ ! -x "$PYTHON_BIN" ]]; then
    PYTHON_BIN="$(command -v python3)"
fi

info "Creating '$INSTALL_DIR'..."

if [[ -d "$INSTALL_DIR" ]]; then
    while true; do
    warn -n "'$INSTALL_DIR' already exists. Shall I overwrite it? [y/n] "
      read yn
        case $yn in
          [Yy]* ) rm -rf "$INSTALL_DIR"; break;;
          [Nn]* )
            info "Aborting...";
            exit;;
          * ) echo "Please answer yes or no.";;
      esac
    done
fi
mkdir -p "$INSTALL_DIR"
cp -a arpvpn "$INSTALL_DIR"
SOURCE_DIR="$INSTALL_DIR/arpvpn"
DATA_DIR="$INSTALL_DIR/data"
mkdir -p "$DATA_DIR"

cp config/uwsgi.sample.yaml "$DATA_DIR/uwsgi.yaml"

cp requirements.txt "$INSTALL_DIR"

info "Installing dependencies..."
debug "Updating packages list..."
export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
apt-get -qq update

dependencies="sudo python3 python3-venv iptables uwsgi uwsgi-plugin-python3 iproute2 openssl rrdtool bash ca-certificates curl"

if [[ "$WIREGUARD_TOOLS_FROM_SOURCE" == "1" ]]; then
    dependencies="$dependencies gcc libc6-dev make pkg-config xz-utils"
else
    dependencies="$dependencies wireguard-tools"
fi

# Debian package names changed across releases (PCRE1 -> PCRE2). Pick
# whichever set is available so container builds keep working on current bases.
has_pkg_candidate() {
    local pkg="$1"
    local candidate
    candidate="$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}')"
    [[ -n "$candidate" && "$candidate" != "(none)" ]]
}

if has_pkg_candidate libpcre3; then
    dependencies="$dependencies libpcre3"
elif has_pkg_candidate libpcre2-8-0; then
    dependencies="$dependencies libpcre2-8-0"
fi

if has_pkg_candidate libpcre3-dev; then
    dependencies="$dependencies libpcre3-dev"
elif has_pkg_candidate libpcre2-dev; then
    dependencies="$dependencies libpcre2-dev"
fi

if has_pkg_candidate certbot; then
    dependencies="$dependencies certbot"
fi

debug "The following packages will be installed: $dependencies"
apt-get -qq install -y --no-install-recommends $dependencies
if [ $? -ne 0 ]; then
    fatal "Unable to install dependencies."
    exit 1
fi
rm -rf /var/lib/apt/lists/*

if [[ "$WIREGUARD_TOOLS_FROM_SOURCE" == "1" ]]; then
    install_wireguard_tools_from_source
fi

info "Setting up virtual environment..."
if [[ ! -x "$PYTHON_BIN" ]]; then
    fatal "Unable to locate python3 for virtualenv creation."
    exit 1
fi
"$PYTHON_BIN" -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
if [ $? -ne 0 ]; then
    fatal "Unable to activate virtual environment."
    exit 1
fi
debug "Upgrading pip..."
python3 -m pip install --upgrade pip
debug "Installing python requirements..."
python3 -m pip install -r "$INSTALL_DIR/requirements.txt"
if [ $? -ne 0 ]; then
    fatal "Unable to install requirements."
    exit 1
fi
deactivate

info "Settings permissions..."
getent group arpvpn >/dev/null || groupadd arpvpn
id -u arpvpn >/dev/null 2>&1 || useradd -g arpvpn arpvpn
chown -R arpvpn:arpvpn "$INSTALL_DIR"
chmod +x -R "$SOURCE_DIR/core/tools"
echo "arpvpn ALL=(ALL) NOPASSWD: /usr/bin/wg" > /etc/sudoers.d/arpvpn
echo "arpvpn ALL=(ALL) NOPASSWD: /usr/bin/wg-quick" >> /etc/sudoers.d/arpvpn
echo "arpvpn ALL=(ALL) NOPASSWD: /usr/bin/certbot" >> /etc/sudoers.d/arpvpn

info "Adding arpvpn service..."
cp systemd/arpvpn.service /etc/systemd/system/
chmod 644 /etc/systemd/system/arpvpn.service

info "All set! Run 'systemctl start arpvpn.service' to get started."
