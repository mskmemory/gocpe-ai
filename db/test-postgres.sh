#!/bin/sh
# Disposable PostgreSQL 16. Requires Go and Docker. No live NVD/OSV/AI calls.
set -eu
cd "$(dirname "$0")/.."
container=$(docker run --detach --rm -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=gocpe_test -p 127.0.0.1::5432 postgres:16-alpine)
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT HUP INT TERM
attempt=0
until docker exec "$container" pg_isready -U postgres -d gocpe_test >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "PostgreSQL did not become ready" >&2
        exit 1
    fi
    sleep 1
done
port=$(docker port "$container" 5432/tcp | sed 's/.*://')
TEST_DATABASE_URL="postgres://postgres@127.0.0.1:$port/gocpe_test?sslmode=disable" go test -race -count=1 ./...
