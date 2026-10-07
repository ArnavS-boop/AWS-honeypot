    #!/bin/bash
    set -euo pipefail

    INFRA_ROOT="/opt/.infra"
    PROFILE_DIR="$INFRA_ROOT/profiles"
    CLEAN_DIR="$INFRA_ROOT/clean"

    if [ "$#" -ne 1 ]; then
        echo "Usage: $0 <profile>"
        exit 2
    fi

PROFILE="$1"

if [[ "$PROFILE" == clean/* ]]; then
    CLEAN_PROFILE="${PROFILE#clean/}"
    PROFILE_FILE="$CLEAN_DIR/$CLEAN_PROFILE.json"
else
    PROFILE_FILE="$PROFILE_DIR/$PROFILE.json"
fi

    if [ "$(id -u)" -ne 0 ]; then
        echo "Must run as root."
        exit 1
    fi

    command -v jq >/dev/null 2>&1 || {
        echo "jq is not installed."
        exit 1
    }

    command -v realpath >/dev/null 2>&1 || {
        echo "realpath is not installed."
        exit 1
    }

    if [ ! -f "$PROFILE_FILE" ]; then
        echo "Unknown profile: $PROFILE"
        exit 1
    fi

    if [ "$(stat -c '%U:%G' "$PROFILE_FILE")" != "root:root" ]; then
        echo "Profile ownership check failed."
        exit 1
    fi

    case "$(stat -c '%a' "$PROFILE_FILE")" in
        400|600|640) ;;
        *)
            echo "Unsafe profile permissions."
            exit 1
            ;;
    esac

    if ! jq empty "$PROFILE_FILE" >/dev/null 2>&1; then
        echo "Invalid JSON profile: $PROFILE_FILE"
        exit 1
    fi


    #
    # Entire hierarchies that this profile engine must NEVER modify.
    #
    PROTECTED_ROOTS=(
        "/etc"
        "/usr"
        "/boot"
        "/efi"
        "/dev"
        "/proc"
        "/sys"
        "/run"
        "/root"
        "/bin"
        "/sbin"
        "/lib"
        "/lib64"
        "/opt/.infra"
    )


    #
    # Specific system-critical areas inside otherwise mutable hierarchies.
    #
    PROTECTED_PATHS=(
        "/var/lib/dpkg"
        "/var/lib/apt"
        "/var/lib/systemd"
        "/var/lib/cloud"
        "/var/lib/NetworkManager"
        "/var/lib/ubuntu-release-upgrader"
        "/var/lib/ucf"

        "/var/log/journal"
        "/var/log/private"

        "/var/spool/cron"
        "/var/spool/cron/crontabs"

        "/var/run"
    )


    normalize_path() {
        realpath -m -- "$1"
    }


    path_is_inside() {
        local path="$1"
        local root="$2"

        [ "$path" = "$root" ] || [[ "$path" == "$root/"* ]]
    }


    is_protected_path() {
        local path="$1"
        local root

        for root in "${PROTECTED_ROOTS[@]}"; do
            if path_is_inside "$path" "$root"; then
                return 0
            fi
        done

        for root in "${PROTECTED_PATHS[@]}"; do
            if path_is_inside "$path" "$root"; then
                return 0
            fi
        done

        return 1
    }


    check_path() {
        local raw_path="$1"
        local path

        if [ -z "$raw_path" ]; then
            echo "Rejected empty path."
            return 1
        fi

        if [[ "$raw_path" != /* ]]; then
            echo "Rejected non-absolute path: $raw_path"
            return 1
        fi

        path="$(normalize_path "$raw_path")"

        if [ "$path" = "/" ]; then
            echo "Rejected root filesystem."
            return 1
        fi

        if is_protected_path "$path"; then
            echo "Rejected protected system path: $path"
            return 1
        fi

        printf '%s\n' "$path"
    }


    validate_identity() {
        local owner="$1"
        local group="$2"

        if ! getent passwd "$owner" >/dev/null 2>&1; then
            echo "Unknown owner: $owner"
            return 1
        fi

        if ! getent group "$group" >/dev/null 2>&1; then
            echo "Unknown group: $group"
            return 1
        fi
    }


    validate_mode() {
        local mode="$1"

        if ! [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
            echo "Invalid mode: $mode"
            return 1
        fi
    }


    echo "Applying filesystem profile: $PROFILE"


    #
    # Directories
    #
    while IFS= read -r entry; do
        path="$(jq -r '.path' <<< "$entry")"
        owner="$(jq -r '.owner' <<< "$entry")"
        group="$(jq -r '.group' <<< "$entry")"
        mode="$(jq -r '.mode' <<< "$entry")"

        path="$(check_path "$path")"

        validate_identity "$owner" "$group"
        validate_mode "$mode"

        install -d \
            -o "$owner" \
            -g "$group" \
            -m "$mode" \
            "$path"

    done < <(jq -c '.directories[]?' "$PROFILE_FILE")


    #
    # Files
    #
    while IFS= read -r entry; do
        path="$(jq -r '.path' <<< "$entry")"
        content="$(jq -r '.content' <<< "$entry")"
        owner="$(jq -r '.owner' <<< "$entry")"
        group="$(jq -r '.group' <<< "$entry")"
        mode="$(jq -r '.mode' <<< "$entry")"

        path="$(check_path "$path")"

        validate_identity "$owner" "$group"
        validate_mode "$mode"

        parent="$(dirname "$path")"
        parent="$(check_path "$parent")"

        mkdir -p "$parent"

        #
        # Do not follow an existing symlink when replacing a file.
        #
        if [ -L "$path" ]; then
            echo "Rejected symlink target: $path"
            exit 1
        fi

        printf '%s\n' "$content" > "$path"

        chown "$owner:$group" "$path"
        chmod "$mode" "$path"

    done < <(jq -c '.files[]?' "$PROFILE_FILE")


    #
    # Removals
    #
    while IFS= read -r raw_path; do
        [ -z "$raw_path" ] && continue

        path="$(check_path "$raw_path")"

        if [ "$path" = "$INFRA_ROOT" ] || path_is_inside "$path" "$INFRA_ROOT"; then
            echo "Rejected removal of infrastructure path: $path"
            exit 1
        fi

        rm -rf --one-file-system -- "$path"

    done < <(jq -r '.remove[]?' "$PROFILE_FILE")


    echo "Profile '$PROFILE' applied successfully."