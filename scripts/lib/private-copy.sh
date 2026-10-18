# Copy an executable into a new owner-only directory on the internal temp volume.
private_executable_copy() {
    local temp_root=${TMPDIR:-/tmp}
    case "$temp_root" in
        /*) ;;
        *) temp_root=/tmp ;;
    esac
    directory=$(mktemp -d "$temp_root/plexus-exec.XXXXXX") || return 1
    if ! cp "$1" "$directory/ckdev-plexus"; then
        rm -rf "$directory"
        return 1
    fi
    printf '%s\n' "$directory"
}
