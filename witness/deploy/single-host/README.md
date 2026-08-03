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
install -D -m 0644 absolutejs-evidence-witness.service \
  /etc/systemd/system/absolutejs-evidence-witness.service
systemctl daemon-reload
```

Create `/etc/absolutejs/evidence-witness/deployment.env` as root-owned `0600`
non-secret configuration:

```text
EVIDENCE_WITNESS_IMAGE=ghcr.io/absolutejs/vulnerabilities-witness@sha256:<verified-digest>
WITNESS_HOSTNAME=witness.example.com
WITNESS_ORIGIN=https://witness.example.com
WITNESS_RUNTIME_ENV_FILE=/run/absolutejs-evidence-witness/witness.env
WITNESS_TLS_DIRECTORY=/run/absolutejs-evidence-witness/tls
```

The runtime file must define `DATABASE_URL`, `POSTGRES_DB`,
`POSTGRES_PASSWORD`, `POSTGRES_USER`, `EVIDENCE_WITNESS_SECRETS_PASSPHRASE`,
`EVIDENCE_WITNESS_SIGNING_STATE_JSON`, and
`EVIDENCE_WITNESS_TOKENS_JSON`. Set
`EVIDENCE_WITNESS_SECRETS_PATH=/var/lib/absolutejs/secrets.enc.json` and
`EVIDENCE_WITNESS_ORIGIN` to the same origin as the deployment file.

The secret manager must also inject `tls.crt` and `tls.key` below
`WITNESS_TLS_DIRECTORY`. The certificate must be root-owned `0644`; the private
key must be owned by UID/GID `1000:1000` with mode `0400` so only the
capability-free witness process can read it. Private test CAs are acceptable
only for a bounded staging drill whose CA bundle is pinned by PAAS. Public
launch requires a publicly trusted certificate and an automated rotation path.

After the provider secret manager has written the runtime file, start with
`systemctl start absolutejs-evidence-witness`. Verify HTTPS health and keys,
pin the genesis key through an independent channel, then run the PAAS live
quorum drill. A host reboot deliberately leaves this service stopped until the
secret manager reinjects the runtime file.
