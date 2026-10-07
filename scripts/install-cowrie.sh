#!/bin/bash
set -euo pipefail

SVCWEB_USER="svc-web"
SVCWEB_HOME="/opt/app/.svc"
COWRIE_ENV="$SVCWEB_HOME/SVCWEB-env"
COWRIE="$COWRIE_ENV/bin/cowrie"
TWISTD="$COWRIE_ENV/bin/twistd"

echo "[svc-web] Starting installation"

# ------------------------------------------------------------
# Create dedicated non-root user
# ------------------------------------------------------------

if ! id "$SVCWEB_USER" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash "$SVCWEB_USER"
fi

# ------------------------------------------------------------
# Create installation directory
# ------------------------------------------------------------

mkdir -p "$SVCWEB_HOME"

chown "$SVCWEB_USER:$SVCWEB_USER" "$SVCWEB_HOME"

# ------------------------------------------------------------
# Create Python virtual environment
# ------------------------------------------------------------

if [ ! -d "$COWRIE_ENV" ]; then
    echo "[svc-web] Creating Python virtual environment"

    su - "$SVCWEB_USER" -c "
        python3 -m venv '$COWRIE_ENV'
    "
fi

# ------------------------------------------------------------
# Install Cowrie and its dependencies
# ------------------------------------------------------------

echo "[svc-web] Installing Cowrie"

su - "$SVCWEB_USER" -c "
    export PATH='$COWRIE_ENV/bin:\$PATH'

    '$COWRIE_ENV/bin/python' -m pip install --upgrade pip
    '$COWRIE_ENV/bin/python' -m pip install --upgrade cowrie
"

# ------------------------------------------------------------
# Verify Cowrie executable
# ------------------------------------------------------------

if [ ! -x "$COWRIE" ]; then
    echo "[svc-web] ERROR: Cowrie executable missing:"
    echo "  $COWRIE"
    exit 1
fi

# ------------------------------------------------------------
# Verify/install Twisted executable
# ------------------------------------------------------------

if [ ! -x "$TWISTD" ]; then
    echo "[svc-web] twistd not found."

    echo "[svc-web] Installing Twisted into Cowrie virtualenv"

    su - "$SVCWEB_USER" -c "
        export PATH='$COWRIE_ENV/bin:\$PATH'
        '$COWRIE_ENV/bin/python' -m pip install --upgrade twisted
    "
fi

# ------------------------------------------------------------
# HARD verification
# ------------------------------------------------------------

if [ ! -x "$TWISTD" ]; then
    echo "[svc-web] ERROR: twistd is still missing:"
    echo "  $TWISTD"
    exit 1
fi

echo "[svc-web] Cowrie: $COWRIE"
echo "[svc-web] twistd: $TWISTD"

su - "$SVCWEB_USER" -c "
    export PATH='$COWRIE_ENV/bin:\$PATH'

    echo '[svc-web] PATH:'
    echo \"\$PATH\"

    echo '[svc-web] cowrie:'
    command -v cowrie

    echo '[svc-web] twistd:'
    command -v twistd

    echo '[svc-web] twistd version:'
    twistd --version
"

# ------------------------------------------------------------
# Initialize Cowrie
# ------------------------------------------------------------

if [ ! -f "$SVCWEB_HOME/etc/cowrie.cfg" ]; then
    echo "[svc-web] Initializing Cowrie"

    su - "$SVCWEB_USER" -c "
        export PATH='$COWRIE_ENV/bin:\$PATH'
        cd '$SVCWEB_HOME'
        '$COWRIE' init
    "
fi

# ------------------------------------------------------------
# Lock down installation
# ------------------------------------------------------------

chown -R "$SVCWEB_USER:$SVCWEB_USER" "$SVCWEB_HOME"

chmod 750 "$SVCWEB_HOME"

# ------------------------------------------------------------
# Persist Cowrie environment for svc-web
# ------------------------------------------------------------

cat > "$SVCWEB_HOME/.cowrie-env" <<EOF
export COWRIE_HOME="$SVCWEB_HOME"
export COWRIE_ENV="$COWRIE_ENV"
export PATH="$COWRIE_ENV/bin:\$PATH"
EOF

chown "$SVCWEB_USER:$SVCWEB_USER" "$SVCWEB_HOME/.cowrie-env"
chmod 640 "$SVCWEB_HOME/.cowrie-env"

echo "[svc-web] Installation complete"