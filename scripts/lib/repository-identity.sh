#!/bin/sh
# Maintainer landing safeguard; outside contributors do not need this tool.
# The tracked numeric GitHub repository ID stays the same when that repository
# is renamed and travels with fresh clones. When copying
# this tree into a different GitHub repository, its maintainer must replace
# .github/repository-id with that repository's API-resolved ID before any push.
# Never learn the expected ID from origin: a reused name may hold another repo.

github_repository_slug() (
    url="$1"
    case "$url" in
        git@github.com:*) slug="${url#git@github.com:}" ;;
        https://github.com/*) slug="${url#https://github.com/}" ;;
        ssh://git@github.com/*) slug="${url#ssh://git@github.com/}" ;;
        *) return 1 ;;
    esac
    slug="${slug%.git}"
    case "$slug" in
        *[!a-zA-Z0-9_./-]*|/*|*/|*/*/*) return 1 ;;
        */*) printf '%s\n' "$slug" ;;
        *) return 1 ;;
    esac
)

# Print origin's slug only after checking both its fetch and every push URL.
# The hook also passes Git's actual destination URL. train-push.sh passes its
# REPO=owner/name CI lookup override so successful checks from a different
# repository cannot authorize landing a commit here.
require_github_repository() (
    root="$1"
    gh_cli="$2"
    destination="${3:-}"
    ci_repository="${4:-}"
    identity_file="$root/.github/repository-id"
    expected_id="$(cat "$identity_file" 2>/dev/null)" || {
        echo "repository guard: refusing — cannot read expected repository ID from $identity_file." >&2
        return 1
    }
    case "$expected_id" in
        ''|*[!0-9]*|0*)
            echo "repository guard: refusing — $identity_file must contain one positive numeric repository ID." >&2
            return 1 ;;
    esac
    if ! command -v "$gh_cli" >/dev/null 2>&1; then
        echo "repository guard: refusing — gh is required to resolve origin's repository ID (expected $expected_id); nothing was verified." >&2
        return 1
    fi

    checked_slugs=" "
    check_repository() {
        label="$1"
        slug="$(github_repository_slug "$2")" || {
            echo "repository guard: refusing — $label is not a supported GitHub repository URL: $2 (expected ID $expected_id)." >&2
            return 1
        }
        case "$checked_slugs" in *" $slug "*) return 0 ;; esac
        resolved_id="$("$gh_cli" api "repos/$slug" --hostname github.com --jq '.id' 2>/dev/null)" || {
            echo "repository guard: refusing — cannot resolve $label repository $slug (expected ID $expected_id). Check network access and gh authentication; nothing was verified." >&2
            return 1
        }
        case "$resolved_id" in
            ''|*[!0-9]*|0*)
                echo "repository guard: refusing — API returned no valid repository ID for $label $slug (expected $expected_id); nothing was verified." >&2
                return 1 ;;
        esac
        if [ "$resolved_id" != "$expected_id" ]; then
            echo "repository guard: refusing — $identity_file expects repository ID $expected_id, but $label resolved to $slug (repository ID $resolved_id)." >&2
            echo "  A clone of the old private history belongs to cortexkit/plexus-private; update its origin and push URLs, not the expected ID." >&2
            return 1
        fi
        checked_slugs="$checked_slugs$slug "
    }

    origin_url="$(git -C "$root" remote get-url origin 2>/dev/null)" || {
        echo "repository guard: refusing — cannot read origin's URL (expected repository ID $expected_id)." >&2
        return 1
    }
    check_repository origin "$origin_url" || return 1
    origin_slug="$(github_repository_slug "$origin_url")"
    push_urls="$(git -C "$root" remote get-url --push --all origin 2>/dev/null)" || {
        echo "repository guard: refusing — cannot read origin's push URLs (expected repository ID $expected_id)." >&2
        return 1
    }
    while IFS= read -r push_url; do
        check_repository 'origin push URL' "$push_url" || return 1
    done <<EOF
$push_urls
EOF
    if [ -n "$destination" ]; then
        check_repository 'push destination' "$destination" || return 1
    fi
    if [ -n "$ci_repository" ]; then
        check_repository 'CI repository override' "https://github.com/$ci_repository" || return 1
    fi
    printf '%s\n' "$origin_slug"
)
