#!/bin/sh
# Create/update fixed, non-owner runtime roles after the owner-only migration.
# Passwords are passed as psql variables and never rendered in logs or argv.
set -eu

export PGHOST="${PGHOST:-postgres}"
export PGPORT="${PGPORT:-5432}"
export PGUSER="${POSTGRES_USER:?POSTGRES_USER is required}"
export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
database="${POSTGRES_DB:?POSTGRES_DB is required}"
api_password="${PG_API_PASSWORD:?PG_API_PASSWORD is required}"
engine_password="${PG_ENGINE_PASSWORD:?PG_ENGINE_PASSWORD is required}"
mta_password="${PG_MTA_PASSWORD:?PG_MTA_PASSWORD is required}"

if [ "$POSTGRES_PASSWORD" = "$api_password" ] \
    || [ "$POSTGRES_PASSWORD" = "$engine_password" ] \
    || [ "$POSTGRES_PASSWORD" = "$mta_password" ] \
    || [ "$api_password" = "$engine_password" ] \
    || [ "$api_password" = "$mta_password" ] \
    || [ "$engine_password" = "$mta_password" ]; then
    echo "PostgreSQL owner and runtime-role passwords must all differ" >&2
    exit 1
fi

create_or_update_role() {
    role_name="$1"
    role_password="$2"
    psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$database" \
        --set=role_name="$role_name" --set=role_password="$role_password" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', :'role_name')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role_name') \gexec
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L',
    :'role_name', :'role_password'
) \gexec
SQL
}

create_or_update_role vigilyx_api "$api_password"
create_or_update_role vigilyx_engine "$engine_password"
create_or_update_role vigilyx_mta "$mta_password"

psql --no-psqlrc --set=ON_ERROR_STOP=1 --dbname="$database" \
    --set=db_name="$database" --set=owner_name="$POSTGRES_USER" <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO vigilyx_api, vigilyx_engine, vigilyx_mta;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
    TO vigilyx_api, vigilyx_engine, vigilyx_mta;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public
    TO vigilyx_api, vigilyx_engine, vigilyx_mta;

SELECT format('GRANT CONNECT ON DATABASE %I TO vigilyx_api, vigilyx_engine, vigilyx_mta', :'db_name') \gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vigilyx_api, vigilyx_engine, vigilyx_mta',
    :'owner_name'
) \gexec
SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO vigilyx_api, vigilyx_engine, vigilyx_mta',
    :'owner_name'
) \gexec
SQL

echo "PostgreSQL runtime roles are present and non-owner grants are current"
