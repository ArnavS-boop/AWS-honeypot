#!/bin/bash

set -e

# Update system
apt-get update

# Install basic dependencies
apt-get install -y \
    git \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    jq

# Create honeypot user
useradd -m -s /bin/bash honeypot || true

# Install/configure Cowrie
# ...

# Install/configure Dionaea
# ...

# Create fake filesystem
mkdir -p /srv/decoy
mkdir -p /srv/decoy/documents
mkdir -p /srv/decoy/backups

# Install Decoy Controller
# ...

# Start initial profile
# ...