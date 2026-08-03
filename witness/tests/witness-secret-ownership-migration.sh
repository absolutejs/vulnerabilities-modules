#!/usr/bin/env bash
set -euo pipefail

image=${EVIDENCE_WITNESS_TEST_IMAGE:?exact witness test image is required}
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
volume="absolutejs-witness-secret-migration-${suffix}"
initializer="$(cd "$(dirname "${BASH_SOURCE[0]}")/../deploy/single-host" && pwd)/absolutejs-evidence-witness-secrets-init"

cleanup() {
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$volume" >/dev/null
docker run --rm --network none \
  --user 0:0 \
  --mount "type=volume,source=${volume},target=/var/lib/absolutejs" \
  --entrypoint sh \
  "$image" \
  -ec 'chown 1000:1000 /var/lib/absolutejs'
docker run --rm --network none \
  --user 1000:1000 \
  --mount "type=volume,source=${volume},target=/var/lib/absolutejs" \
  --entrypoint sh \
  "$image" \
  -ec "printf '%s' synthetic-canary > /var/lib/absolutejs/secrets.enc.json && chmod 0600 /var/lib/absolutejs/secrets.enc.json"

docker run --rm --network none \
  --user 0:0 \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add FOWNER \
  --mount "type=volume,source=${volume},target=/var/lib/absolutejs" \
  --mount "type=bind,source=${initializer},target=/usr/local/sbin/absolutejs-evidence-witness-secrets-init,readonly" \
  --entrypoint /usr/local/sbin/absolutejs-evidence-witness-secrets-init \
  "$image"

docker run --rm --network none \
  --user 65532:65532 \
  --mount "type=volume,source=${volume},target=/var/lib/absolutejs,readonly" \
  --entrypoint sh \
  "$image" \
  -ec 'test "$(id -u):$(id -g)" = 65532:65532; test "$(stat -c %u:%g:%a /var/lib/absolutejs/secrets.enc.json)" = 65532:65532:600; test "$(cat /var/lib/absolutejs/secrets.enc.json)" = synthetic-canary'

docker run --rm --network none \
  --user 0:0 \
  --mount "type=volume,source=${volume},target=/var/lib/absolutejs" \
  --entrypoint sh \
  "$image" \
  -ec 'rm /var/lib/absolutejs/secrets.enc.json; ln -s /etc/passwd /var/lib/absolutejs/secrets.enc.json'
if docker run --rm --network none \
  --user 0:0 \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add FOWNER \
  --mount "type=volume,source=${volume},target=/var/lib/absolutejs" \
  --mount "type=bind,source=${initializer},target=/usr/local/sbin/absolutejs-evidence-witness-secrets-init,readonly" \
  --entrypoint /usr/local/sbin/absolutejs-evidence-witness-secrets-init \
  "$image"; then
  echo "initializer accepted a symbolic-link secret state" >&2
  exit 1
fi
