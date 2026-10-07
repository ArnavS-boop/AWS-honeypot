#!/bin/bash
set -euo pipefail

SVCWEB_USER="svc-web"
SVCWEB_HOME="/opt/app/.svc"

COWRIE_HOME="$SVCWEB_HOME"
COWRIE_ENV="$SVCWEB_HOME/SVCWEB-env"
COWRIE_ROOT="$SVCWEB_HOME/var/lib/cowrie"

TWISTD="$COWRIE_ENV/bin/twistd"
FSCTL="$COWRIE_ENV/bin/fsctl"
COWRIE="$COWRIE_ENV/bin/cowrie"

PROFILE_ROOT="$COWRIE_ROOT/profiles"
ACTIVE_ROOT="$COWRIE_ROOT/active"

CFG="$SVCWEB_HOME/etc/cowrie.cfg"

if [ "$(id -u)" -ne 0 ]; then
    echo "Must run as root."
    exit 1
fi

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <baseline|investigation>"
    exit 2
fi

PROFILE="$1"

case "$PROFILE" in
    baseline|investigation)
        ;;
    *)
        echo "Unknown profile: $PROFILE"
        exit 1
        ;;
esac

if ! id "$SVCWEB_USER" >/dev/null 2>&1; then
    echo "User $SVCWEB_USER does not exist."
    exit 1
fi

for REQUIRED in "$FSCTL" "$COWRIE" "$TWISTD"; do
    if [ ! -x "$REQUIRED" ]; then
        echo "Required executable not found: $REQUIRED"
        exit 1
    fi
done

if [ ! -f "$CFG" ]; then
    echo "Cowrie config not found: $CFG"
    exit 1
fi

mkdir -p \
    "$PROFILE_ROOT/baseline" \
    "$PROFILE_ROOT/investigation" \
    "$ACTIVE_ROOT"

chown -R "$SVCWEB_USER:$SVCWEB_USER" \
    "$PROFILE_ROOT" \
    "$ACTIVE_ROOT"

chmod 750 "$PROFILE_ROOT" "$ACTIVE_ROOT"

# ------------------------------------------------------------
# Obtain Cowrie's standard filesystem.
# ------------------------------------------------------------

DEFAULT_FS="$COWRIE_ROOT/fs.pickle"

if [ ! -f "$DEFAULT_FS" ]; then
    echo "Cowrie default fs.pickle not found."

    su - "$SVCWEB_USER" -c "
        cd '$COWRIE_HOME'
        '$COWRIE_ENV/bin/python' -c \"
from cowrie.core.resources import read_data_bytes
with open('$DEFAULT_FS', 'wb') as f:
    f.write(read_data_bytes('fs.pickle'))
\"
    "
fi

# ------------------------------------------------------------
# Build each profile.
# ------------------------------------------------------------

for BUILD_PROFILE in baseline investigation; do

    PROFILE_DIR="$PROFILE_ROOT/$BUILD_PROFILE"
    HONEYFS="$PROFILE_DIR/honeyfs"
    PICKLE="$PROFILE_DIR/fs.pickle"

    echo
    echo "============================================================"
    echo "Building Cowrie filesystem: $BUILD_PROFILE"
    echo "============================================================"

    rm -rf "$HONEYFS"
    rm -f "$PICKLE"

    # --------------------------------------------------------
    # Build physical honeyfs contents.
    # --------------------------------------------------------

    mkdir -p \
        "$HONEYFS/var/www/app/uploads" \
        "$HONEYFS/var/www/app/backups"

    cat > "$HONEYFS/var/www/app/index.html" <<'EOF'
<html>
<head>
<title>Application Portal</title>
</head>
<body>
Application Portal
</body>
</html>
EOF

    cat > "$HONEYFS/var/www/app/config.ini" <<'EOF'
[application]
name=Application Portal
version=1.4.2
EOF

    if [ "$BUILD_PROFILE" = "investigation" ]; then

        mkdir -p \
            "$HONEYFS/var/www/app/logs" \
            "$HONEYFS/var/www/app/uploads/archive"

        cat > "$HONEYFS/var/www/app/.env" <<'EOF'
APP_ENV=production
APP_DEBUG=false
DATABASE_HOST=db.internal
DATABASE_USER=app_user
EOF

        cat > "$HONEYFS/var/www/app/logs/application.log" <<'EOF'
2026-09-05 10:12:03 INFO application started
2026-09-05 10:12:05 INFO database connection established
2026-09-05 10:13:12 INFO user authentication successful
EOF

        cat > "$HONEYFS/var/www/app/backups/database-backup.sql" <<'EOF'
-- Application database backup
-- Generated automatically

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(64),
    role VARCHAR(32)
);

INSERT INTO users VALUES
(1, 'admin', 'administrator'),
(2, 'deploy', 'developer');
EOF

    fi

    chown -R "$SVCWEB_USER:$SVCWEB_USER" "$HONEYFS"

    # --------------------------------------------------------
    # Start from the standard Cowrie filesystem.
    # --------------------------------------------------------

    cp "$DEFAULT_FS" "$PICKLE"

    chown "$SVCWEB_USER:$SVCWEB_USER" "$PICKLE"
    chmod 600 "$PICKLE"

    # --------------------------------------------------------
    # IMPORTANT:
    # Create the filesystem metadata entries first.
    #
    # fsctl embed only embeds contents when a matching
    # virtual filesystem entry already exists.
    # --------------------------------------------------------

    FS_COMMANDS="$PROFILE_DIR/fsctl-commands.txt"

    cat > "$FS_COMMANDS" <<EOF
mkdir /var/www
mkdir /var/www/app
mkdir /var/www/app/uploads
mkdir /var/www/app/backups
touch /var/www/app/index.html 1024
touch /var/www/app/config.ini 256
EOF

    if [ "$BUILD_PROFILE" = "investigation" ]; then
        cat >> "$FS_COMMANDS" <<EOF
mkdir /var/www/app/logs
mkdir /var/www/app/uploads/archive
touch /var/www/app/.env 256
touch /var/www/app/logs/application.log 1024
touch /var/www/app/backups/database-backup.sql 2048
EOF
    fi

    echo "[setup-cowrie] Creating filesystem metadata entries"

    su - "$SVCWEB_USER" -c "
        cd '$COWRIE_HOME'
        {
            cat '$FS_COMMANDS'
            echo 'embed $HONEYFS'
            echo 'exit'
        } | '$FSCTL' '$PICKLE'
    "

    # --------------------------------------------------------
    # Now embed the actual file contents.
    # --------------------------------------------------------

    echo "[setup-cowrie] Embedding file contents"


    rm -f "$FS_COMMANDS"
    rm -rf "$HONEYFS"

    chown "$SVCWEB_USER:$SVCWEB_USER" "$PICKLE"
    chmod 600 "$PICKLE"

    echo "Created: $PICKLE"

done

# ------------------------------------------------------------
# Configure Cowrie to use the active filesystem.
# ------------------------------------------------------------

if grep -qE '^[[:space:]]*filesystem[[:space:]]*=' "$CFG"; then

    sed -i \
        's|^[[:space:]]*filesystem[[:space:]]*=.*|filesystem = var/lib/cowrie/active/fs.pickle|' \
        "$CFG"

else

    sed -i \
        '/^\[shell\]/a filesystem = var/lib/cowrie/active/fs.pickle' \
        "$CFG"

fi

chown "$SVCWEB_USER:$SVCWEB_USER" "$CFG"

# ------------------------------------------------------------
# Activate requested profile.
# ------------------------------------------------------------

SOURCE="$PROFILE_ROOT/$PROFILE/fs.pickle"
ACTIVE="$ACTIVE_ROOT/fs.pickle"

if [ ! -f "$SOURCE" ]; then
    echo "Profile pickle missing: $SOURCE"
    exit 1
fi

cp "$SOURCE" "$ACTIVE"

chown "$SVCWEB_USER:$SVCWEB_USER" "$ACTIVE"
chmod 600 "$ACTIVE"

echo "Activated Cowrie profile: $PROFILE"

# ------------------------------------------------------------
# Restart Cowrie.
# ------------------------------------------------------------

su - "$SVCWEB_USER" -c "
    export COWRIE_HOME='$COWRIE_HOME'
    export COWRIE_ENV='$COWRIE_ENV'
    export PATH='$COWRIE_ENV/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

    cd '$COWRIE_HOME'

    echo '[setup-cowrie] cowrie:'
    command -v cowrie

    echo '[setup-cowrie] twistd:'
    command -v twistd

    if '$COWRIE' status >/dev/null 2>&1; then
        echo '[setup-cowrie] Stopping existing Cowrie'
        '$COWRIE' stop || true
        /bin/sleep 2
    fi

    echo '[setup-cowrie] Starting Cowrie'
    '$COWRIE' start
"

echo "Cowrie profile '$PROFILE' is running."