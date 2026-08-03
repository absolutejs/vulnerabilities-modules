#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) != 0 ]]; then
	echo "witness backup upload integration test must run as root" >&2
	exit 1
fi

root=$(mktemp -d /run/absolutejs-witness-upload-test.XXXXXX)
runtime=${root}/runtime
commands=${root}/commands
configuration=${root}/backup.env
credentials=${root}/credentials
gpg_home=${root}/gnupg
aws_log=${root}/aws.log
upload_script=$(cd "$(dirname "${BASH_SOURCE[0]}")/../deploy/single-host" && pwd)/absolutejs-evidence-witness-backup-upload
cleanup() {
	rm -rf "${root}"
}
trap cleanup EXIT HUP INT TERM
install -d -o 0 -g 0 -m 0700 "${runtime}" "${commands}" "${credentials}" "${gpg_home}"

fingerprint=0123456789ABCDEF0123456789ABCDEF01234567
cat >"${configuration}" <<EOF
WITNESS_BACKUP_ID=witness-test
WITNESS_BACKUP_RECIPIENT_FINGERPRINT=${fingerprint}
WITNESS_BACKUP_GNUPGHOME=${gpg_home}
WITNESS_BACKUP_S3_BUCKET=absolutejs-witness-immutable-test
WITNESS_BACKUP_S3_PREFIX=witness-test/
WITNESS_BACKUP_S3_REGION=us-east-1
WITNESS_BACKUP_S3_EXPECTED_OWNER=123456789012
WITNESS_BACKUP_SPACES_BUCKET=absolutejs-witness-versioned-test
WITNESS_BACKUP_SPACES_PREFIX=witness-test/
WITNESS_BACKUP_SPACES_REGION=nyc3
WITNESS_BACKUP_SPACES_ENDPOINT=https://nyc3.digitaloceanspaces.com
EOF
cat >"${credentials}/absolutejs.witness.backup-upload.env" <<'EOF'
WITNESS_BACKUP_S3_ACCESS_KEY_ID=SYNTHETIC_S3_ACCESS
WITNESS_BACKUP_S3_SECRET_ACCESS_KEY=SYNTHETIC_S3_SECRET
WITNESS_BACKUP_SPACES_ACCESS_KEY_ID=SYNTHETIC_SPACES_ACCESS
WITNESS_BACKUP_SPACES_SECRET_ACCESS_KEY=SYNTHETIC_SPACES_SECRET
EOF
chmod 0600 "${configuration}"
# systemd materializes LoadCredentialEncrypted= files read-only for the service.
chmod 0400 "${credentials}/absolutejs.witness.backup-upload.env"

cat >"${commands}/absolutejs-evidence-witness-backup-create" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'synthetic witness backup canary\n' >"${1}"
chmod 0600 "${1}"
EOF
cat >"${commands}/gpg" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ " \$* " == *" --fingerprint "* ]]; then
	printf 'pub:-:3072:1:0000000000000000:0:0::::::e::::::23::0:\\nfpr:::::::::${fingerprint}:\\n'
	exit 0
fi
output=
input=
while (( \$# > 0 )); do
	case \$1 in
		--output)
			output=\$2
			shift 2
			;;
		*)
			input=\$1
			shift
			;;
	esac
done
test -n "\${output}" && test -f "\${input}"
printf 'synthetic encrypted canary\n' >"\${output}"
chmod 0600 "\${output}"
EOF
cat >"${commands}/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
test "${AWS_EC2_METADATA_DISABLED}" = true
test "${AWS_PROFILE}" = absolutejs-witness-backup
test -f "${AWS_SHARED_CREDENTIALS_FILE}"
if [[ " $* " == *" --endpoint-url "* ]]; then
	grep -q '^aws_access_key_id=SYNTHETIC_SPACES_ACCESS$' "${AWS_SHARED_CREDENTIALS_FILE}"
	grep -q '^aws_secret_access_key=SYNTHETIC_SPACES_SECRET$' "${AWS_SHARED_CREDENTIALS_FILE}"
	if [[ ${FAIL_SPACES_UPLOAD:-false} == true ]]; then
		exit 42
	fi
	printf 'spaces %s\n' "$*" >>"${AWS_TEST_LOG}"
else
	grep -q '^aws_access_key_id=SYNTHETIC_S3_ACCESS$' "${AWS_SHARED_CREDENTIALS_FILE}"
	grep -q '^aws_secret_access_key=SYNTHETIC_S3_SECRET$' "${AWS_SHARED_CREDENTIALS_FILE}"
	printf 's3 %s\n' "$*" >>"${AWS_TEST_LOG}"
fi
EOF
cat >"${commands}/openssl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
test "$*" = 'rand -hex 8'
printf '0123456789abcdef\n'
EOF
chmod 0755 "${commands}"/*

run_upload() {
	PATH="${commands}:/usr/sbin:/usr/bin:/sbin:/bin" \
		CREDENTIALS_DIRECTORY="${credentials}" \
		EVIDENCE_WITNESS_BACKUP_CONFIGURATION="${configuration}" \
		EVIDENCE_WITNESS_BACKUP_RUNTIME_DIRECTORY="${runtime}" \
		AWS_TEST_LOG="${aws_log}" \
		"${upload_script}"
}

output=$(run_upload 2>&1)
grep -q '^witness-encrypted-backup-uploaded witness-test-' <<<"${output}"
if grep -q 'SYNTHETIC_.*SECRET' <<<"${output}"; then
	echo "witness backup upload disclosed a writer secret" >&2
	exit 1
fi
test "$(grep -c '^s3 ' "${aws_log}")" = 1
test "$(grep -c '^spaces ' "${aws_log}")" = 1
grep -q -- '--expected-bucket-owner 123456789012' "${aws_log}"
grep -q -- '--checksum-algorithm SHA256' "${aws_log}"
grep -q -- '--endpoint-url https://nyc3.digitaloceanspaces.com' "${aws_log}"
if find "${runtime}" -maxdepth 1 -type f ! -name upload.lock | grep -q .; then
	echo "witness backup upload retained runtime artifacts" >&2
	exit 1
fi

: >"${aws_log}"
if FAIL_SPACES_UPLOAD=true run_upload >/dev/null 2>&1; then
	echo "witness backup upload accepted a failed independent copy" >&2
	exit 1
fi
if find "${runtime}" -maxdepth 1 -type f ! -name upload.lock | grep -q .; then
	echo "failed witness backup upload retained runtime artifacts" >&2
	exit 1
fi

sed -i 's#https://nyc3.digitaloceanspaces.com#https://attacker.invalid#' "${configuration}"
: >"${aws_log}"
if run_upload >/dev/null 2>&1; then
	echo "witness backup upload accepted an untrusted endpoint" >&2
	exit 1
fi
test ! -s "${aws_log}"

echo witness-backup-upload-ok
