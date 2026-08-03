#!/usr/bin/env bash
set -euo pipefail

image="postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
container="absolutejs-witness-postgres18-${suffix}"
volume="absolutejs-witness-postgres18-${suffix}"

cleanup() {
  docker rm --force "$container" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker pull "$image" >/dev/null
fi
docker volume create "$volume" >/dev/null

start_postgres() {
  docker run --detach \
    --name "$container" \
    --pull never \
    --env POSTGRES_DB=witness_persistence_test \
    --env POSTGRES_USER=witness_test \
    --env POSTGRES_PASSWORD=synthetic-regression-only \
    --mount "type=volume,source=${volume},target=/var/lib/postgresql" \
    "$image" >/dev/null

  for _ in {1..30}; do
    if docker exec "$container" psql \
      --username witness_test \
      --dbname witness_persistence_test \
      --tuples-only \
      --no-align \
      --set ON_ERROR_STOP=1 \
      --command "SELECT 1;" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done

  docker logs "$container"
  return 1
}

start_postgres
docker exec "$container" psql \
  --username witness_test \
  --dbname witness_persistence_test \
  --set ON_ERROR_STOP=1 \
  --command "CREATE TABLE persistence_canary (value text NOT NULL); INSERT INTO persistence_canary VALUES ('synthetic-canary');" \
  >/dev/null
docker rm --force "$container" >/dev/null

start_postgres
count="$({
  docker exec "$container" psql \
    --username witness_test \
    --dbname witness_persistence_test \
    --tuples-only \
    --no-align \
    --set ON_ERROR_STOP=1 \
    --command "SELECT count(*) FROM persistence_canary WHERE value = 'synthetic-canary';"
} | tr -d '[:space:]')"

test "$count" = "1"
