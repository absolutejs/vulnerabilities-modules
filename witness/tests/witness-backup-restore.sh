#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) != 0 ]]; then
	echo "witness backup restore integration test must run as root" >&2
	exit 1
fi

candidate=${EVIDENCE_WITNESS_TEST_IMAGE:?candidate witness image is required}
image=$(docker image inspect --format '{{.Id}}' "${candidate}")
postgres_image=postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15
suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
root=$(mktemp -d /run/absolutejs-witness-backup-integration.XXXXXX)
network="absolutejs-witness-backup-source-${suffix}"
postgres_container="absolutejs-witness-backup-postgres-${suffix}"
witness_container="absolutejs-witness-backup-service-${suffix}"
postgres_volume="absolutejs-witness-backup-postgres-${suffix}"
secrets_volume="absolutejs-witness-backup-secrets-${suffix}"
archive=${root}/backup.tar
verification=${root}/verification.json

cleanup() {
	docker rm --force "${witness_container}" "${postgres_container}" >/dev/null 2>&1 || true
	docker volume rm "${postgres_volume}" "${secrets_volume}" >/dev/null 2>&1 || true
	docker network rm "${network}" >/dev/null 2>&1 || true
	rm -rf "${root}"
}
trap cleanup EXIT HUP INT TERM

bun witness/tests/create-backup-restore-fixture.ts "${root}"
chown 0:0 "${root}" "${root}/witness.env"
chmod 0711 "${root}"
chmod 0600 "${root}/witness.env"
cat >"${root}/deployment.env" <<EOF
EVIDENCE_WITNESS_IMAGE=${image}
WITNESS_RUNTIME_ENV_FILE=${root}/witness.env
EOF
chmod 0600 "${root}/deployment.env"

docker network create --internal "${network}" >/dev/null
docker volume create "${postgres_volume}" >/dev/null
docker volume create "${secrets_volume}" >/dev/null
docker run --rm --network none --user 0:0 \
	--entrypoint sh \
	--mount "type=volume,source=${secrets_volume},target=/var/lib/absolutejs" \
	"${image}" -ceu \
	'install -d -o 65532 -g 65532 -m 0700 /var/lib/absolutejs'
docker run --detach --name "${postgres_container}" --pull never \
	--network "${network}" --network-alias postgres \
	--env-file "${root}/witness.env" \
	--mount "type=volume,source=${postgres_volume},target=/var/lib/postgresql" \
	"${postgres_image}" >/dev/null

for _ in {1..30}; do
	if docker exec "${postgres_container}" sh -ceu \
		'exec psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --tuples-only --no-align --set ON_ERROR_STOP=1 --command "SELECT 1;"' \
		>/dev/null 2>&1; then
		break
	fi
	sleep 1
done

docker run --detach --name "${witness_container}" --pull never \
	--user 65532:65532 --network "${network}" \
	--env-file "${root}/witness.env" --env PORT=3443 \
	--mount "type=volume,source=${secrets_volume},target=/var/lib/absolutejs" \
	"${image}" >/dev/null
for _ in {1..30}; do
	if docker exec "${witness_container}" wget --quiet --output-document=/dev/null \
		http://127.0.0.1:3443/health >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
docker exec "${witness_container}" wget --quiet --output-document=/dev/null \
	http://127.0.0.1:3443/health
docker exec "${postgres_container}" sh -ceu \
	'exec psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 --command "INSERT INTO absolute_vulnerability_evidence_witness_observations (subject, log_size, log_head, observed_at, receipt, witness_key_id) VALUES ('\''synthetic-subject'\'', 1, '\''sha256:synthetic-backup-canary'\'', NOW(), '\''{}'\''::jsonb, '\''synthetic-key'\'');"' \
	>/dev/null

EVIDENCE_WITNESS_DEPLOYMENT_ENVIRONMENT=${root}/deployment.env \
EVIDENCE_WITNESS_CONTAINER=${witness_container} \
EVIDENCE_WITNESS_POSTGRES_CONTAINER=${postgres_container} \
	bash witness/deploy/single-host/absolutejs-evidence-witness-backup-create \
	"${archive}"

EVIDENCE_WITNESS_DEPLOYMENT_ENVIRONMENT=${root}/deployment.env \
EVIDENCE_WITNESS_COMPOSE_FILE=witness/deploy/single-host/compose.yml \
	bash witness/deploy/single-host/absolutejs-evidence-witness-restore-verify \
	"${archive}" >"${verification}"

EVIDENCE_WITNESS_DEPLOYMENT_ENVIRONMENT=${root}/deployment.env \
EVIDENCE_WITNESS_CONTAINER=${witness_container} \
EVIDENCE_WITNESS_SECRETS_VOLUME=${secrets_volume} \
	bash witness/deploy/single-host/absolutejs-evidence-witness-backup-record \
	<"${verification}" >/dev/null

docker exec "${witness_container}" wget --quiet --output-document=- \
	--header 'authorization: Bearer synthetic-backup-token' \
	http://127.0.0.1:3443/v1/status \
	| grep -q 'absolutejs.vulnerability-evidence-witness-backup-verification/v1'

echo witness-backup-restore-ok
