#!/usr/bin/env bash
# Creates .env from .env.example with random secrets. Refuses to overwrite.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env ]; then echo ".env already exists" >&2; exit 0; fi
umask 077
r() { openssl rand -hex "$1"; }
sed -e "s/^ASI_DB_PASSWORD=.*/ASI_DB_PASSWORD=$(r 16)/" \
    -e "s/^ASI_SECRET_KEY=.*/ASI_SECRET_KEY=$(r 32)/" \
    -e "s/^ASI_SEED_PASSWORD_ADMIN=.*/ASI_SEED_PASSWORD_ADMIN=$(r 8)/" \
    -e "s/^ASI_SEED_PASSWORD_EDITOR=.*/ASI_SEED_PASSWORD_EDITOR=$(r 8)/" \
    -e "s/^ASI_SEED_PASSWORD_ANALYST=.*/ASI_SEED_PASSWORD_ANALYST=$(r 8)/" \
    -e "s/^ASI_SEED_PASSWORD_VIEWER=.*/ASI_SEED_PASSWORD_VIEWER=$(r 8)/" \
    .env.example > .env
echo "created .env (user passwords: grep ASI_SEED_PASSWORD .env)"
