#!/usr/bin/env bash
# Shared Linux CI setup; version and digest come from the workflow's pinned env.
set -euo pipefail
: "${NATS_SERVER_VERSION:?NATS_SERVER_VERSION is required}"
: "${NATS_SERVER_LINUX_AMD64_SHA256:?NATS_SERVER_LINUX_AMD64_SHA256 is required}"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *) echo "install-nats-server: requires Linux x86_64" >&2; exit 2 ;;
esac
install_dir="$(mktemp -d)"
trap 'rm -rf "$install_dir"' EXIT
archive="nats-server-v${NATS_SERVER_VERSION}-linux-amd64.tar.gz"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --max-time 120 \
  "https://github.com/nats-io/nats-server/releases/download/v${NATS_SERVER_VERSION}/${archive}" \
  --output "$install_dir/$archive"
if ! printf '%s  %s\n' "$NATS_SERVER_LINUX_AMD64_SHA256" "$install_dir/$archive" | sha256sum --check --strict -; then
  echo "install-nats-server: checksum verification failed" >&2
  exit 1
fi
tar -xzf "$install_dir/$archive" -C "$install_dir"
binary="$install_dir/nats-server-v${NATS_SERVER_VERSION}-linux-amd64/nats-server"
if [ -n "${NATS_SERVER_INSTALL_DIR:-}" ]; then
  mkdir -p "$NATS_SERVER_INSTALL_DIR"
  install -m 0755 "$binary" "$NATS_SERVER_INSTALL_DIR/nats-server"
  "$NATS_SERVER_INSTALL_DIR/nats-server" --version
else
  sudo install -m 0755 "$binary" /usr/local/bin/nats-server
  nats-server --version
fi
