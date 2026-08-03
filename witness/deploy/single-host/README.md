# Single-host evidence witness

This reusable host contract runs one evidence witness with native TLS and its
PostgreSQL store. It is one member of a quorum, never the quorum by itself.
Deploy every member under a different administrative account and failure
domain as described by the parent deployment contract.

The contract requires the witness image by immutable digest and refuses to
pull it. Verify and preload the exact signed image before activation. The
official PostgreSQL support image is also digest pinned.

## Secret boundary

`WITNESS_RUNTIME_ENV_FILE` must name a root-owned `0600` file below `/run`.
That tmpfs file contains the database credential, secret-store passphrase,
initial signing state, and subject token. It intentionally disappears at
reboot. A production secret manager must recreate it before the service can
start; the unit fails closed when it is absent or has unsafe ownership or
mode. Do not persist a plaintext copy in `/etc`, cloud-init, instance metadata,
OpenTofu state, a repository, or a machine image.

The initial signing state and token bootstrap the encrypted witness file on
first start. Keep supplying the same runtime credential source after bootstrap:
the passphrase remains necessary to decrypt rotations, while the stored signing
state and token take precedence over their bootstrap values.

## Host installation

Install Docker Engine with its Compose plugin from the provider-supported
repository. Copy this directory to `/opt/absolutejs/evidence-witness`, then
install the unit and helpers:

```sh
install -D -m 0755 absolutejs-evidence-witness-firewall \
  /usr/local/sbin/absolutejs-evidence-witness-firewall
install -D -m 0755 absolutejs-evidence-witness-preflight \
  /usr/local/sbin/absolutejs-evidence-witness-preflight
install -D -m 0755 absolutejs-evidence-witness-runtime-materialize \
  /usr/local/sbin/absolutejs-evidence-witness-runtime-materialize
install -D -m 0755 absolutejs-evidence-witness-runtime-cleanup \
  /usr/local/sbin/absolutejs-evidence-witness-runtime-cleanup
install -D -m 0755 absolutejs-evidence-witness-backup-create \
  /usr/local/sbin/absolutejs-evidence-witness-backup-create
install -D -m 0755 absolutejs-evidence-witness-restore-verify \
  /usr/local/sbin/absolutejs-evidence-witness-restore-verify
install -D -m 0755 absolutejs-evidence-witness-backup-record \
  /usr/local/sbin/absolutejs-evidence-witness-backup-record
install -D -m 0755 absolutejs-evidence-witness-backup-upload \
  /usr/local/sbin/absolutejs-evidence-witness-backup-upload
install -D -m 0644 absolutejs-evidence-witness.service \
  /etc/systemd/system/absolutejs-evidence-witness.service
install -D -m 0644 absolutejs-evidence-witness-backup.service \
  /etc/systemd/system/absolutejs-evidence-witness-backup.service
install -D -m 0644 absolutejs-evidence-witness-backup.timer \
  /etc/systemd/system/absolutejs-evidence-witness-backup.timer
systemctl daemon-reload
```

Create `/etc/absolutejs/evidence-witness/deployment.env` as root-owned `0600`
non-secret configuration:

```text
EVIDENCE_WITNESS_IMAGE=ghcr.io/absolutejs/vulnerabilities-witness@sha256:<verified-digest>
WITNESS_HOSTNAME=witness.example.com
WITNESS_ORIGIN=https://witness.example.com
WITNESS_INGRESS_IPV4_CIDRS=93.184.216.34/32
WITNESS_RUNTIME_ENV_FILE=/run/absolutejs-evidence-witness/witness.env
WITNESS_TLS_DIRECTORY=/run/absolutejs-evidence-witness/tls
```

`WITNESS_INGRESS_IPV4_CIDRS` is a comma-separated allowlist of exact,
publicly routable IPv4 `/32` hosts. Include only stable control-plane egress
addresses and a separately reviewed break-glass source while commissioning.
The host firewall rejects all other new connections to the witness container.
Apply the same allowlist to the provider firewall before activation; the host
rule is defense in depth and does not replace the provider firewall. Remove
the break-glass source after the control plane passes the live quorum drill.

The runtime file must define `DATABASE_URL`, `POSTGRES_DB`,
`POSTGRES_PASSWORD`, `POSTGRES_USER`, `EVIDENCE_WITNESS_SECRETS_PASSPHRASE`,
`EVIDENCE_WITNESS_SIGNING_STATE_JSON`, and
`EVIDENCE_WITNESS_TOKENS_JSON`. Set
`EVIDENCE_WITNESS_SECRETS_PATH=/var/lib/absolutejs/secrets.enc.json` and
`EVIDENCE_WITNESS_ORIGIN` to the same origin as the deployment file.

The secret manager must also inject `tls.crt` and `tls.key` below
`WITNESS_TLS_DIRECTORY`. Make that directory and its immediate parent
root-owned `0711`: the dedicated container identity can traverse the path but
cannot list either directory. The certificate must be root-owned `0644`; the
private key must be owned by the dedicated numeric container UID/GID
`65532:65532` with mode `0400`. Do not reuse a host login UID for this identity.
Private test CAs are acceptable only for a bounded staging drill whose CA
bundle is pinned by PAAS. Public launch requires a publicly trusted certificate
and an automated rotation path.

After the provider secret manager has written the runtime file, start with
`systemctl start absolutejs-evidence-witness`. Verify HTTPS health and keys,
pin the genesis key through an independent channel, then run the PAAS live
quorum drill. A host reboot deliberately leaves this service stopped until the
secret manager reinjects the runtime file.

### Host-bound encrypted reboot recovery

On a host with systemd 254 or newer, the unit can instead import three
encrypted credentials and atomically recreate the runtime files before its
ordinary preflight. This mode remains optional so an external provider secret
manager can continue to populate `/run` directly.

Create the host key once, then encrypt each already-prepared runtime input on
the witness host. Use the exact credential names because systemd authenticates
each name as part of its encrypted envelope:

```sh
systemd-creds setup
install -d -o 0 -g 0 -m 0700 /etc/credstore.encrypted
systemd-creds encrypt --with-key=host \
  --name=absolutejs.witness.runtime.env \
  /run/absolutejs-evidence-witness/witness.env \
  /etc/credstore.encrypted/absolutejs.witness.runtime.env
systemd-creds encrypt --with-key=host \
  --name=absolutejs.witness.tls.crt \
  /run/absolutejs-evidence-witness/tls/tls.crt \
  /etc/credstore.encrypted/absolutejs.witness.tls.crt
systemd-creds encrypt --with-key=host \
  --name=absolutejs.witness.tls.key \
  /run/absolutejs-evidence-witness/tls/tls.key \
  /etc/credstore.encrypted/absolutejs.witness.tls.key
```

After all three encrypted files exist, enable the service. A complete set is
materialized below `/run` before preflight and removed when the service stops;
a missing member fails closed. The ciphertext is bound to that host and cannot
be reused to unlock the other quorum member.

Without a TPM or provider workload identity, host-key encryption protects
credentials from plaintext persistence and from an encrypted blob copied away
without the host key. It does not protect against that host's root operator or
a full disk snapshot containing the systemd host key. A TPM-backed credential
or provider-native workload identity is stronger where available. This mode
must therefore use a different host key, administrative account, SSH identity,
and encrypted credential set for every quorum member.

## Encrypted backups and restore evidence

The host helpers create and verify a portable backup containing a PostgreSQL
custom-format dump, the already-encrypted signing-state file, its derived
public key registry, and a digest manifest. The plaintext archive is permitted
only below `/run`; encrypt it to an offline public-key recipient before upload
and remove the runtime archive immediately afterward. Keep each witness's
encryption recipient and object-store writer credential distinct.

```sh
absolutejs-evidence-witness-backup-create \
  /run/absolutejs-evidence-witness-backup.tar
gpg --batch --yes --trust-model always --encrypt \
  --recipient <offline-backup-key-fingerprint> \
  --output /run/absolutejs-evidence-witness-backup.tar.gpg \
  /run/absolutejs-evidence-witness-backup.tar
rm -f /run/absolutejs-evidence-witness-backup.tar
```

Upload only the encrypted `.gpg` object through a prefix-scoped writer that
cannot read or delete backup objects. Prefer immutable object retention and a
second versioned copy in another provider. The offline private key must not be
installed on a witness for routine backup creation.

The supplied uploader automates that contract every six hours. It requires the
AWS CLI and GnuPG, one public-only `GNUPGHOME`, an S3 bucket with Object Lock
default retention, and a DigitalOcean Spaces bucket with versioning. Configure
`/etc/absolutejs/evidence-witness/backup.env` as root-owned `0600`:

```text
WITNESS_BACKUP_ID=witness-a
WITNESS_BACKUP_RECIPIENT_FINGERPRINT=<exact-offline-public-key-fingerprint>
WITNESS_BACKUP_GNUPGHOME=/etc/absolutejs/evidence-witness/backup-gnupg
WITNESS_BACKUP_S3_BUCKET=<immutable-bucket>
WITNESS_BACKUP_S3_PREFIX=witness-a/
WITNESS_BACKUP_S3_REGION=us-east-1
WITNESS_BACKUP_S3_EXPECTED_OWNER=<12-digit-account-id>
WITNESS_BACKUP_SPACES_BUCKET=<versioned-bucket>
WITNESS_BACKUP_SPACES_PREFIX=witness-a/
WITNESS_BACKUP_SPACES_REGION=nyc3
WITNESS_BACKUP_SPACES_ENDPOINT=https://nyc3.digitaloceanspaces.com
```

Encrypt a distinct, prefix-scoped pair of S3-compatible writer credentials per
witness under the exact systemd credential name
`absolutejs.witness.backup-upload.env`. Its plaintext input has this shape and
must never be persisted after host-bound encryption:

```text
WITNESS_BACKUP_S3_ACCESS_KEY_ID=<write-only-access-key>
WITNESS_BACKUP_S3_SECRET_ACCESS_KEY=<write-only-secret-key>
WITNESS_BACKUP_SPACES_ACCESS_KEY_ID=<bucket-scoped-access-key>
WITNESS_BACKUP_SPACES_SECRET_ACCESS_KEY=<bucket-scoped-secret-key>
```

Import only the matching public key into the configured GnuPG directory, then
enable `absolutejs-evidence-witness-backup.timer`. The uploader disables AWS
metadata credential discovery, validates the fixed Spaces endpoint, pins the
AWS account ID, removes the plaintext before either upload, and removes every
runtime artifact when it exits. A failed independent copy fails the unit and
is retried by operations; it never reports partial success as a completed
backup. Keep the offline private key and its passphrase in independent
operator-controlled recovery storage.

For a restore drill, decrypt on a trusted operator machine and stream the
plaintext archive over SSH directly into a root-owned `0600` file below
`/run`. Then run the no-egress disposable restore and record its validated JSON
result back into the live encrypted secret adapter:

```sh
absolutejs-evidence-witness-restore-verify \
  /run/absolutejs-evidence-witness-backup.tar \
  | absolutejs-evidence-witness-backup-record
rm -f /run/absolutejs-evidence-witness-backup.tar
```

The restore helper verifies every artifact digest, restores the dump into a
new Docker volume, starts the restored witness on an internal-only Docker
network, and compares its public key registry byte-for-byte with the registry
derived at backup time. All disposable containers, networks, volumes, and
plaintext runtime artifacts are removed on exit. A successful record updates
the authenticated `/v1/status` backup posture after briefly pausing that one
witness, serializing the encrypted-file update against key rotation, and
waiting for the same container to become healthy again. Run quorum-member
drills sequentially and verify the other member before each recording step.
