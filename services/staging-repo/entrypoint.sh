#!/bin/sh
set -e

# Initialize git repository with leaky commit history
mkdir -p /tmp/seed-repo
cd /tmp/seed-repo
git init -b main
git config user.name "DevOps Bot"
git config user.email "devops@cartbreach.local"

# Commit 1: Initial codebase setup
cat << 'EOF' > package.json
{
  "name": "cartbreach-storefront",
  "version": "1.0.0",
  "main": "server.js"
}
EOF
cat << 'EOF' > server.js
const express = require('express');
const app = express();
app.get('/api/v1/health', (req, res) => res.json({ status: 'ok' }));
app.listen(3000);
EOF
git add package.json server.js
git commit -m "Initial commit: Express storefront scaffold and basic routing"

# Commit 2: Leaked configuration containing staging auth token
cat << 'EOF' > config.staging.env
PORT=3000
NODE_ENV=staging
DB_HOST=postgres-data.cartbreach.local
DB_USER=cart_user
# INTERNAL STAGING TOKEN - DO NOT SHARE
Authorization: Bearer cb_staging_9a8f2c3d4e5f
INTERNAL_API_URL=http://order-inventory-api:8000
EOF

git add config.staging.env
git commit -m "Add staging environment config and internal auth tokens"

# Commit 3 (HEAD): Sanitizing the leak without squashing commit history (Stage 1 flaw)
cat << 'EOF' > config.staging.env
PORT=3000
NODE_ENV=staging
DB_HOST=postgres-data.cartbreach.local
DB_USER=cart_user
# Credentials moved to vault
INTERNAL_API_URL=http://order-inventory-api:8000
EOF

git add config.staging.env
git commit -m "Sanitize configuration and remove dev secrets"

# Expose bare Git repository at /var/git/cartbreach/storefront-web.git
mkdir -p /var/git/cartbreach
rm -rf /var/git/cartbreach/storefront-web.git
git clone --bare /tmp/seed-repo /var/git/cartbreach/storefront-web.git
rm -rf /tmp/seed-repo

# Configure bare repository for HTTP serving
cd /var/git/cartbreach/storefront-web.git
git config http.receivepack false
git config http.uploadpack true
git update-server-info

# Launch Git Smart HTTP daemon on port 3001
exec python3 /server.py
