#!/usr/bin/env bash
set -euo pipefail

### Configuration (edit as needed)

# Root of your modified PostgreSQL source
: "${PG_SRC_DIR:=/home/anonymous/mtp/postgres}"

# Where to install this custom PostgreSQL (can override via env)
: "${PG_PREFIX:=${HOME}/pg-auth}"

# Data directory for this instance (can override via env)
: "${PGDATA:=${HOME}/pg-auth-data}"

# Port for this instance
: "${PGPORT:=55432}"

# Cedar Agent base URL (must match your deployment)
: "${CEDAR_URL:=http://localhost:8280}"

# Build directory (Meson)
BUILD_DIR="${PG_SRC_DIR}/builddir"

### Helper functions

log() {
  printf '[pg_auth_setup] %s\n' "$*" >&2
}

die() {
  printf '[pg_auth_setup:ERROR] %s\n' "$*" >&2
  exit 1
}

append_if_missing() {
  # append_if_missing FILE "pattern" "line to append"
  local file="$1"
  local pattern="$2"
  local line="$3"
  if ! grep -qE "$pattern" "$file" 2>/dev/null; then
    echo "$line" >>"$file"
  fi
}

teardown_cluster() {
  log "Tearing down PostgreSQL instance at PGDATA=${PGDATA}"

  if [ -d "${PGDATA}" ]; then
    if command -v pg_ctl >/dev/null 2>&1; then
      log "Stopping server with pg_ctl..."
      pg_ctl -D "${PGDATA}" -w stop || log "pg_ctl stop failed (server may not be running)"
    fi

    log "Removing data directory ${PGDATA}..."
    rm -rf "${PGDATA}"
  else
    log "No data directory found at ${PGDATA}; nothing to tear down."
  fi

  log "Teardown complete."
}

usage() {
  cat <<EOF
Usage: $0 [up|down]

  up   : Build, install, configure, and start PostgreSQL with pg_authorization (default)
  down : Stop PostgreSQL (if running) and remove PGDATA for a clean slate

Environment overrides:
  PG_SRC_DIR   : PostgreSQL source directory (default: ${PG_SRC_DIR})
  PG_PREFIX    : Install prefix (default: ${PG_PREFIX})
  PGDATA       : Data directory (default: ${PGDATA})
  PGPORT       : Port (default: ${PGPORT})
  CEDAR_URL    : Cedar Agent base URL (default: ${CEDAR_URL})
EOF
}

### Mode selection (up / down)

MODE="${1:-up}"

case "${MODE}" in
  up)   ;;  # continue
  down)
    teardown_cluster
    exit 0
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage
    die "Unknown mode: ${MODE}"
    ;;
esac

### 1. Basic checks

command -v meson >/dev/null 2>&1 || die "meson not found in PATH"
command -v ninja >/dev/null 2>&1 || die "ninja not found in PATH"

log "Using PG_SRC_DIR=${PG_SRC_DIR}"
log "Using PG_PREFIX=${PG_PREFIX}"
log "Using PGDATA=${PGDATA}"
log "Using PGPORT=${PGPORT}"
log "Using CEDAR_URL=${CEDAR_URL}"

### 2. Configure with Meson

cd "${PG_SRC_DIR}"

if [ ! -d "${BUILD_DIR}" ]; then
  log "No builddir found, running meson setup..."
  meson setup "${BUILD_DIR}" \
    -Dprefix="${PG_PREFIX}" \
    -Dbuildtype=release
else
  log "Existing builddir found, ensuring prefix=${PG_PREFIX} and reconfiguring..."
  cd "${BUILD_DIR}"
  meson configure -Dprefix="${PG_PREFIX}" -Dtap_tests=enabled
  meson setup --reconfigure ..
  cd "${PG_SRC_DIR}"
fi

### 3. Build PostgreSQL and contrib/pg_authorization

cd "${BUILD_DIR}"
log "Building PostgreSQL and contrib/pg_authorization..."
ninja

# If you want to rebuild just the extension on later runs:
# ninja contrib/pg_authorization/pg_authorization.so

### 4. Install binaries and extension

log "Installing into ${PG_PREFIX}..."
# Truncate ninja install output to keep logs readable, but still fail on errors.
# We rely on 'set -o pipefail' (from set -euo pipefail) so the script exits if ninja fails.
ninja install | tail -20

# Ensure installed binaries are on PATH for the rest of this script
export PATH="${PG_PREFIX}/bin:${PATH}"

command -v postgres >/dev/null 2>&1 || die "postgres not found under ${PG_PREFIX}/bin"
command -v initdb  >/dev/null 2>&1 || die "initdb not found under ${PG_PREFIX}/bin"
command -v pg_ctl  >/dev/null 2>&1 || die "pg_ctl not found under ${PG_PREFIX}/bin"
command -v psql    >/dev/null 2>&1 || die "psql not found under ${PG_PREFIX}/bin"

### 5. Initialize data directory (if needed)

export PGDATA
export PGPORT

if [ ! -d "${PGDATA}" ] || [ ! -f "${PGDATA}/PG_VERSION" ]; then
  log "Initializing new data directory at ${PGDATA}..."
  mkdir -p "${PGDATA}"
  initdb -D "${PGDATA}"
else
  log "Existing data directory found at ${PGDATA}"
fi

### 6. Configure postgresql.conf for pg_authorization + Cedar

POSTGRESQL_CONF="${PGDATA}/postgresql.conf"

log "Configuring ${POSTGRESQL_CONF} for pg_authorization and Cedar..."

# Ensure basic settings are present or updated
# We append only if no existing line matches the setting key
append_if_missing "${POSTGRESQL_CONF}" '^port[[:space:]]*=' \
  "port = ${PGPORT}"

append_if_missing "${POSTGRESQL_CONF}" '^shared_preload_libraries[[:space:]]*=' \
  "shared_preload_libraries = 'pg_authorization'"

append_if_missing "${POSTGRESQL_CONF}" '^pg_authorization.cedar_url[[:space:]]*=' \
  "pg_authorization.cedar_url = '${CEDAR_URL}'"

append_if_missing "${POSTGRESQL_CONF}" '^pg_authorization.cedar_timeout[[:space:]]*=' \
  "pg_authorization.cedar_timeout = 5000  # ms"

append_if_missing "${POSTGRESQL_CONF}" '^pg_authorization.enabled[[:space:]]*=' \
  "pg_authorization.enabled = on"

# Optional: if you added a log level GUC in your extension, uncomment / adjust:
# append_if_missing "${POSTGRESQL_CONF}" '^pg_authorization.log_level[[:space:]]*=' \
#   "pg_authorization.log_level = 'info'"

### 7. Start (or restart) PostgreSQL

log "Starting PostgreSQL on port ${PGPORT} (data=${PGDATA})..."
# If already running, this will restart; otherwise, it will start
pg_ctl -D "${PGDATA}" -l "${PGDATA}/logfile" -w restart || {
  log "Restart failed, trying start..."
  pg_ctl -D "${PGDATA}" -l "${PGDATA}/logfile" -w start
}

log "PostgreSQL is running."

### 8. Create pg_authorization extension in target database

TARGET_DB="postgres"   # change if you want a different DB

log "Creating extension pg_authorization in database ${TARGET_DB} (if not present)..."

# CREATE EXTENSION IF NOT EXISTS is available in modern PostgreSQL
psql -d "${TARGET_DB}" -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'pg_authorization'
    ) THEN
        EXECUTE 'CREATE EXTENSION pg_authorization';
    END IF;
END;
$$ LANGUAGE plpgsql;
SQL

log "Extension pg_authorization is installed."

### 9. Quick verification

log "Verifying shared_preload_libraries..."
psql -d "${TARGET_DB}" -c "SHOW shared_preload_libraries;" || true

log "Checking pg_authorization_is_enabled()..."
psql -d "${TARGET_DB}" -c "SELECT pg_authorization_is_enabled();" || true

log "Setup complete."
log "You can now connect with: PGPORT=${PGPORT} psql -d ${TARGET_DB}"
log "PostgreSQL prefix: ${PG_PREFIX}"
log "Data directory:    ${PGDATA}"
log "Cedar URL:         ${CEDAR_URL}"