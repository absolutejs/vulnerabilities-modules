#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) != 0 ]]; then
	echo "witness runtime materialization test must run as root" >&2
	exit 1
fi

root=$(mktemp -d /run/absolutejs-witness-materialization.XXXXXX)
trap 'rm -rf "${root}"' EXIT
credentials=${root}/credentials
runtime=${root}/runtime/witness.env
tls=${root}/runtime/tls
materializer=$(cd "$(dirname "${BASH_SOURCE[0]}")/../deploy/single-host" && pwd)/absolutejs-evidence-witness-runtime-materialize
cleanup=$(cd "$(dirname "${BASH_SOURCE[0]}")/../deploy/single-host" && pwd)/absolutejs-evidence-witness-runtime-cleanup

mkdir -m 0700 "${credentials}"
printf '%s\n' 'POSTGRES_PASSWORD=synthetic-canary' >"${credentials}/absolutejs.witness.runtime.env"
printf '%s\n' 'synthetic-certificate' >"${credentials}/absolutejs.witness.tls.crt"
printf '%s\n' 'synthetic-private-key' >"${credentials}/absolutejs.witness.tls.key"

CREDENTIALS_DIRECTORY=${credentials} "${materializer}" "${runtime}" "${tls}"
[[ $(stat -c %U:%G:%a "${runtime}") == root:root:600 ]]
[[ $(stat -c %U:%G:%a "${tls}/tls.crt") == root:root:644 ]]
[[ $(stat -c %u:%g:%a "${tls}/tls.key") == 65532:65532:400 ]]
cmp "${credentials}/absolutejs.witness.runtime.env" "${runtime}"
cmp "${credentials}/absolutejs.witness.tls.crt" "${tls}/tls.crt"
cmp "${credentials}/absolutejs.witness.tls.key" "${tls}/tls.key"

"${cleanup}" "${runtime}" "${tls}"
[[ ! -e ${runtime} ]]
[[ ! -e ${tls}/tls.crt ]]
[[ ! -e ${tls}/tls.key ]]

# Keep the original explicit credential-directory interface compatible for
# non-systemd callers.
"${materializer}" "${credentials}" "${runtime}" "${tls}"
[[ -f ${runtime} ]]
"${cleanup}" "${runtime}" "${tls}"

rm -f "${credentials}/absolutejs.witness.tls.key"
if CREDENTIALS_DIRECTORY=${credentials} "${materializer}" "${runtime}" "${tls}"; then
	echo "partial witness credential set was accepted" >&2
	exit 1
fi
[[ ! -e ${runtime} ]]

empty=${root}/empty
mkdir -m 0700 "${empty}"
CREDENTIALS_DIRECTORY=${empty} "${materializer}" "${runtime}" "${tls}"
[[ ! -e ${runtime} ]]

echo witness-runtime-materialization-ok
