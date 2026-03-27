#!/usr/bin/env bash
# bulk-put.sh — Read all files from a directory and store each in Vault via vlt put
#
# Usage:
#   ./scripts/bulk-put.sh <vault-path> <directory> [--recursive] [--kv-mount mount] [--encryption-key key] [--dry-run]
#
# Examples:
#   ./scripts/bulk-put.sh myapp/certs ./certs/
#   ./scripts/bulk-put.sh myapp/certs ./certs/ --recursive
#   ./scripts/bulk-put.sh myapp/certs ./certs/ --recursive --kv-mount home
#   ./scripts/bulk-put.sh myapp/certs ./certs/ --encryption-key mykey
#   ./scripts/bulk-put.sh myapp/certs ./certs/ --dry-run
#
# Each file becomes a key in the Vault path (base64-encoded).
# The key name is the filename (e.g., tls.key, tls.crt, ca.pem).
#
# With --recursive, subdirectories become Vault sub-paths:
#   ./certs/tls.key       → myapp/certs (key: tls.key)
#   ./certs/ca/root.pem   → myapp/certs/ca (key: root.pem)

set -euo pipefail

usage() {
    echo "Usage: $0 <vault-path> <directory> [--recursive] [--kv-mount mount] [--encryption-key key] [--dry-run]"
    echo ""
    echo "Arguments:"
    echo "  vault-path    Vault KV path to store files under (e.g., myapp/certs)"
    echo "  directory     Directory containing files to upload"
    echo ""
    echo "Options:"
    echo "  --recursive       Recurse into subdirectories (sub-paths mirror directory structure)"
    echo "  --kv-mount        KV v2 mount path (default: home)"
    echo "  --encryption-key  Transit encryption key name"
    echo "  --dry-run         Show what would be done without storing"
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

VAULT_PATH="$1"
DIR="$2"
shift 2

KV_MOUNT=""
ENCRYPTION_KEY=""
DRY_RUN=""
RECURSIVE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --recursive|-r)
            RECURSIVE=true
            shift
            ;;
        --kv-mount)
            KV_MOUNT="$2"
            shift 2
            ;;
        --encryption-key)
            ENCRYPTION_KEY="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN="--dry-run"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ ! -d "$DIR" ]]; then
    echo "Error: $DIR is not a directory"
    exit 1
fi

# Normalize DIR to remove trailing slash for consistent path math
DIR="${DIR%/}"

count=0
failed=0

upload_file() {
    local file="$1"
    local vault_path="$2"

    # Build flags per file (vault path varies with subdirs)
    local flags=("--path" "$vault_path")
    [[ -n "$KV_MOUNT" ]] && flags+=("--kv-mount" "$KV_MOUNT")
    [[ -n "$ENCRYPTION_KEY" ]] && flags+=("--encryption-key" "$ENCRYPTION_KEY")
    [[ -n "$DRY_RUN" ]] && flags+=("--dry-run")

    local key
    key="$(basename "$file")"
    echo "Uploading: $file → $vault_path (key: $key)"

    if vlt put "${flags[@]}" --from-file "$file"; then
        ((count++)) || true
    else
        echo "  FAILED: $file"
        ((failed++)) || true
    fi
}

process_dir() {
    local dir="$1"
    local vault_path="$2"

    for entry in "$dir"/*; do
        # Skip hidden files
        [[ "$(basename "$entry")" == .* ]] && continue

        if [[ -f "$entry" ]]; then
            upload_file "$entry" "$vault_path"
        elif [[ -d "$entry" ]] && [[ "$RECURSIVE" == true ]]; then
            local subdir_name
            subdir_name="$(basename "$entry")"
            process_dir "$entry" "$vault_path/$subdir_name"
        fi
    done
}

process_dir "$DIR" "$VAULT_PATH"

echo ""
echo "Done: $count file(s) uploaded, $failed failed"
echo "Retrieve with: vlt get --path $VAULT_PATH --json"
[[ $failed -gt 0 ]] && exit 1
exit 0
