#!/bin/bash

source ./log.sh

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

info "Creating '$INSTALL_DIR'..."

if [[ -d "$INSTALL_DIR" ]]; then
    while true; do
    warn -n "'$INSTALL_DIR' already exists. Shall I overwrite it? [y/n] "
      read yn
      case $yn in
          [Yy]* ) rm -rf "$INSTALL_DIR"; break;;
          [Nn]* )
            info "Aborting...";
            rm -rf "$ETC_DIR"
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
apt-get -qq update

dependencies="sudo python3 python3-venv wireguard-tools iptables uwsgi uwsgi-plugin-python3 iproute2 openssl rrdtool"

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
apt-get -qq install $dependencies
if [ $? -ne 0 ]; then
    fatal "Unable to install dependencies."
    exit 1
fi

info "Setting up virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
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
