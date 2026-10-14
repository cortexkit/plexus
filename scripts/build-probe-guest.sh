#!/usr/bin/env bash
# Rebuild the checked-in QuickJS/WASI module consumed by plexus-probe.
#
# Runs on macOS and Linux. Needs network once per checkout: the WASI SDK the C
# half of QuickJS is compiled with is downloaded into the guest's target/
# directory and reused afterwards. On a host without network, set
# WASI_SDK_ARCHIVE to the release archive fetched elsewhere; it is checked
# against the same pinned digest as a download.
#
# The SDK is fetched HERE, verified against a pinned checksum, and handed to the
# build through WASI_SDK. Left to itself, rquickjs-sys's build script downloads
# the same archive with curl and unpacks it with no checksum at all, so the C
# compiler that builds the sandbox's interpreter would be whatever that URL
# served on the day.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
guest_root="$repo_root/crates/plexus-probe/guest"
destination="$repo_root/crates/plexus-probe/assets/plexus-probe-guest.wasm"

# The SDK version rquickjs-sys 0.12.2 is written against (its build.rs pins
# WASI_SDK_VERSION_MAJOR = 24, MINOR = 0). Change both together.
#
# The release (https://github.com/WebAssembly/wasi-sdk/releases/tag/wasi-sdk-24)
# publishes no checksums: its assets predate GitHub's per-asset digests and it
# ships no checksum file. These digests were computed on 2026-10-12 from the
# archives at that release's download URLs and cross-checked against the
# independent pins that exist: x86_64-linux equals the
# `sha256-xsOKq1bl3oit9sHrycOujacviOwrZW+wJO2o1BZ6C8U=` in
# bytecodealliance/javy's flake.nix, and arm64-macos equals the value in
# wasm-oj/forge's THIRD_PARTY_NOTICES.md. No public pin was found for the other
# two.
wasi_sdk_version="24.0"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) wasi_sdk_platform="x86_64-linux"
    wasi_sdk_sha256="c6c38aab56e5de88adf6c1ebc9c3ae8da72f88ec2b656fb024eda8d4167a0bc5" ;;
  Linux-aarch64 | Linux-arm64) wasi_sdk_platform="arm64-linux"
    wasi_sdk_sha256="ae6c1417ea161e54bc54c0a168976af57a0c6e53078857886057a71a0d928646" ;;
  Darwin-arm64) wasi_sdk_platform="arm64-macos"
    wasi_sdk_sha256="aeae999396d5f5caa5ce419f52e83c35869d5fd21d40af80acba2c80f51b0b3a" ;;
  Darwin-x86_64) wasi_sdk_platform="x86_64-macos"
    wasi_sdk_sha256="4bfc274ae8b68c771dd93e32ad4bd695336ca46b585beb3b1260e5602dbc11a2" ;;
  *) echo "build-probe-guest: no pinned WASI SDK for $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

sha256_of() {
  # shasum ships with macOS, sha256sum with GNU coreutils; either prints the
  # digest first.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [ ! -d "$(rustc --print sysroot)/lib/rustlib/wasm32-wasip1" ]; then
  echo "build-probe-guest: the Rust wasm32-wasip1 target is not installed" >&2
  echo "  run: rustup target add wasm32-wasip1" >&2
  exit 2
fi

sdk_cache="$guest_root/target/wasi-sdk"
archive="$sdk_cache/wasi-sdk-$wasi_sdk_version-$wasi_sdk_platform.tar.gz"
sdk_dir="$sdk_cache/wasi-sdk-$wasi_sdk_version-$wasi_sdk_platform"
mkdir -p "$sdk_cache"
if [ ! -f "$archive" ] && [ -n "${WASI_SDK_ARCHIVE:-}" ]; then
  cp "$WASI_SDK_ARCHIVE" "$archive.partial"
  mv "$archive.partial" "$archive"
fi
if [ ! -f "$archive" ]; then
  url="https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${wasi_sdk_version%%.*}/wasi-sdk-$wasi_sdk_version-$wasi_sdk_platform.tar.gz"
  echo "==> downloading $url"
  curl --fail --location --silent --show-error --retry 3 --connect-timeout 15 --max-time 900 \
    --output "$archive.partial" "$url"
  mv "$archive.partial" "$archive"
fi
# Verified on every run, not only after a download: a cached archive is just
# as able to be the wrong bytes.
actual_sha256="$(sha256_of "$archive")"
if [ "$actual_sha256" != "$wasi_sdk_sha256" ]; then
  echo "build-probe-guest: refusing the WASI SDK archive: sha256 $actual_sha256" >&2
  echo "  expected $wasi_sdk_sha256 for wasi-sdk-$wasi_sdk_version-$wasi_sdk_platform" >&2
  echo "  delete $archive to download it again" >&2
  exit 1
fi
if [ ! -x "$sdk_dir/bin/clang" ]; then
  rm -rf "$sdk_dir"
  mkdir -p "$sdk_dir"
  tar -xzf "$archive" -C "$sdk_dir" --strip-components 1
fi
echo "==> WASI SDK $wasi_sdk_version ($wasi_sdk_platform) sha256 $actual_sha256"

# Asked of cargo rather than assumed: CARGO_TARGET_DIR (set on shared build
# hosts) moves generated C sources and the output away from the guest's target/.
target_dir="$(cargo metadata --manifest-path "$guest_root/Cargo.toml" --format-version 1 \
  --no-deps --offline | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
# Panic locations and C file names must not expose the checkout or SDK paths.
# Put nested roots last so the Cargo cache and SDK get their own neutral names.
mkdir -p "${CARGO_HOME:-$HOME/.cargo}"
cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)"
path_maps=("$repo_root=/plexus" "$target_dir=/plexus-target" "$cargo_home=/cargo" "$sdk_dir=/wasi-sdk")
# rquickjs-sys overwrites generic CFLAGS with its sysroot. cc also consumes
# target-specific flags, so add the C path mappings there instead.
export CFLAGS_wasm32_wasip1="${CFLAGS_wasm32_wasip1:-}"
for path_map in "${path_maps[@]}"; do
  if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
    export CARGO_ENCODED_RUSTFLAGS="$CARGO_ENCODED_RUSTFLAGS"$'\x1f'"--remap-path-prefix=$path_map"
  else
    export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$path_map"
  fi
  export CFLAGS_wasm32_wasip1="$CFLAGS_wasm32_wasip1 -ffile-prefix-map=$path_map"
done

WASI_SDK="$sdk_dir" cargo build \
  --manifest-path "$guest_root/Cargo.toml" \
  --locked \
  --release \
  --target wasm32-wasip1
artifact="$target_dir/wasm32-wasip1/release/plexus-probe-guest.wasm"
mkdir -p "$(dirname "$destination")"
install -m 0644 "$artifact" "$destination"
echo "==> $destination sha256 $(sha256_of "$destination")"
