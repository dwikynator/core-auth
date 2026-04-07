#!/bin/sh
set -e

echo "Starting database migrations..."

# Construct GOOSE_DBSTRING using libpq key-value format to safely handle special characters (like '/') in the password
export GOOSE_DBSTRING="host=${CORE_AUTH_MIGRATION_HOST} port=${CORE_AUTH_MIGRATION_PORT} user=${CORE_AUTH_MIGRATION_USERNAME} password='${CORE_AUTH_MIGRATION_PASSWORD}' dbname=${CORE_AUTH_MIGRATION_DBNAME} sslmode=disable"
export GOOSE_DRIVER="postgres"

# Execute goose and pass along any arguments (like 'up')
exec goose "$@"
