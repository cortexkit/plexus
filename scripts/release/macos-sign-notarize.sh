#!/usr/bin/env bash
# Sign before packaging; the release workflow checksums only the final ZIPs.
set -euo pipefail

source_dir="${1:?usage: $0 <source-dir> <asset-dir> <darwin-target>}"
asset_dir="${2:?asset directory is required}"
target="${3:?darwin target is required}"
case "$target" in
    darwin-arm64|darwin-x64) ;;
    *) echo "not a darwin target: $target" >&2; exit 1 ;;
esac

: "${APP_STORE_CONNECT_API_KEY_PATH:?App Store Connect API key path is required}"
: "${APP_STORE_CONNECT_API_KEY_ID:?App Store Connect API key ID is required}"
: "${APP_STORE_CONNECT_API_ISSUER_ID:?App Store Connect API issuer ID is required}"
[[ -r "$APP_STORE_CONNECT_API_KEY_PATH" ]] || { echo "App Store Connect API key is not readable" >&2; exit 1; }

# Apple Development can sign the file but cannot notarize it. Fail before
# signing if there isn't exactly one valid Developer ID Application identity.
identities=$(security find-identity -v -p codesigning)
identity=$(printf '%s\n' "$identities" | awk -F'"' '$2 ~ /^Developer ID Application:/ { print $2 }')
if [[ -z "$identity" || "$identity" == *$'\n'* ]]; then
    echo "release requires exactly one valid Developer ID Application signing identity" >&2
    exit 1
fi

# No executable-memory entitlement is needed: Pulley interprets probe guests,
# and the admin client does not run guests.
for binary in ck-plexus ck-plexus-admin; do
    codesign --force --options runtime --timestamp --sign "$identity" "$source_dir/$binary"
    codesign --verify --strict --verbose=2 "$source_dir/$binary"
    python "$(dirname "$0")/assets.py" pack "$source_dir" "$asset_dir" "$target" "$binary"
    archive="$asset_dir/$binary-$target.zip"
    result=$(xcrun notarytool submit "$archive" \
        --key "$APP_STORE_CONNECT_API_KEY_PATH" \
        --key-id "$APP_STORE_CONNECT_API_KEY_ID" \
        --issuer "$APP_STORE_CONNECT_API_ISSUER_ID" \
        --output-format json --wait)
    printf '%s\n' "$result"
    if [[ $(printf '%s\n' "$result" | python -c 'import json, sys; print(json.load(sys.stdin)["status"])') != Accepted ]]; then
        echo "notarization was not accepted for $archive" >&2
        exit 1
    fi
    # ZIPs cannot reliably carry stapled tickets. With notarization accepted,
    # Gatekeeper can still look up the ticket online.
    if ! xcrun stapler staple "$archive"; then
        echo "::warning title=staple-pending::$archive is notarized but not stapled"
    fi
done
