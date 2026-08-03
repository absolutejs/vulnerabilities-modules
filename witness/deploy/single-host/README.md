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
