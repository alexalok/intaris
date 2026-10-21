# Automatic gateway attestation

This optional Linux/systemd service refreshes the trusted Hermes gateway identity
used by [native Telegram approvals](../../../docs/clients/hermes-telegram.md).
It replaces manual PID/start-time updates after gateway restarts. It does not
install the Hermes plugin, configure Telegram destinations, or restart Hermes.

## Requirements and trust

- Python 3.11+ at `/usr/bin/python3`, systemd, and unified cgroup v2.
- Separate `hermes` and `intaris` service users; the Intaris service uses group
  `intaris`. These account names and the paths below are fixed in this helper.
- Hermes runs `hermes-gateway.service` in its user manager, with the actual
  gateway as `MainPID`. A launcher must `exec` the gateway rather than remain
  as a parent process. Supported unit types are `simple`, `exec`, `notify`, and
  `notify-reload`, with `NotifyAccess=none` or `main`.
- The Hermes user manager is available at boot. Enable lingering if gateway
  setup has not already done so: `sudo loginctl enable-linger hermes`.
- Intaris native bridge configuration points to
  `/run/intaris-native/hermes-gateway.pid` and uses the Hermes UID. The socket
  and gateway launch environment are configured as described in the linked guide.

This deployment trusts the gateway, its source, and its user-owned systemd unit.
It does not pin a source revision or defend against deliberately replacing the
gateway. It certifies the process that the trusted user manager identifies as
the gateway. Ordinary tool subprocesses have different PIDs and cannot pass
Intaris's peer-process check or write the protected attestation file.

The helper itself must remain root-owned and outside the Hermes checkout. It
executes only `/usr/bin/systemctl` as the unprivileged Hermes user, with a fixed
unit name, clean environment, and three-second timeout. It never imports Hermes
code, accepts a caller-supplied PID, or reads bot tokens and Intaris credentials.

## Install

Run these commands from the repository root after configuring the native bridge.
Review existing files before replacing an installation. The UID substitution
targets the existing `hermes` account; do not install the `.service.in` template
without rendering it.

```sh
set -eu
hermes_uid="$(id -u hermes)"
test "$hermes_uid" -gt 0
test "$(id -u intaris)" -ne "$hermes_uid"

attest_unit="$(mktemp)"
sed "s/@HERMES_UID@/$hermes_uid/g" \
  integrations/hermes/systemd/intaris-hermes-attestation.service.in > "$attest_unit"

sudo install -o root -g root -m 0755 \
  integrations/hermes/systemd/attest_gateway.py \
  /usr/local/sbin/intaris-attest-hermes
sudo install -o root -g root -m 0644 \
  integrations/hermes/systemd/intaris-native.conf \
  /etc/tmpfiles.d/intaris-native.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/intaris-native.conf
sudo install -o root -g root -m 0644 "$attest_unit" \
  /etc/systemd/system/intaris-hermes-attestation.service
rm -f "$attest_unit"

sudo systemd-analyze verify /etc/systemd/system/intaris-hermes-attestation.service
sudo systemctl daemon-reload
sudo systemctl enable --now intaris-hermes-attestation.service
```

On upgrades, restart the watcher after installing the updated files and
reloading systemd:

```sh
sudo systemctl restart intaris-hermes-attestation.service
```

The runtime directory is `intaris:hermes`, mode `2750`. It must not become
group-writable. The resulting identity file is `root:intaris`, mode `0640`.
The helper uses a protected lock and atomic replacement; Intaris can read the
file while the watcher updates it. No Intaris restart is required.

The service uses filesystem isolation, a read-only home view, Unix sockets
only, and a limited capability set. `AmbientCapabilities=CAP_SETUID` retains
the capability needed to drop to the Hermes user after systemd sandbox setup
with `NoNewPrivileges=yes`; the child loses its permitted, effective, and
ambient capabilities when it changes UID. See
[systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
for capability and sandbox settings.

## Behavior and operations

The watcher polls every two seconds and validates systemd's main PID against
the kernel UID, cgroup and process birth ticks before publishing it. A changed
identity is checked twice. An unchanged identity does not rewrite the file.

A stopped or invalid gateway clears the record. A transient systemd query
failure preserves the existing PID/start-time record and logs the failure;
Intaris continues checking that exact process identity on each connection.
A new process, including a reused PID with different birth ticks, cannot use
the old record. The watcher retries failed checks, and systemd restarts it
after a crash without a permanent start-limit lockout.

```sh
systemctl status intaris-hermes-attestation.service
journalctl -u intaris-hermes-attestation.service --since '-10 minutes'
systemctl is-enabled intaris-hermes-attestation.service
```

After a normal gateway restart, expect `Attested gateway PID=... start=...`
in the watcher journal and matching values in
`/run/intaris-native/hermes-gateway.pid`. Verify Telegram reconnects and the
gateway receives `INTARIS_NATIVE_APPROVAL_SOCKET`. The file tracks process
identity; it is not evidence that the Telegram connection or plugin is healthy.
Native presentation can be unavailable during startup and the next poll;
ordinary Intaris UI approval remains available.

No manual command is needed in normal operation. For an explicit root
diagnostic, `/usr/local/sbin/intaris-attest-hermes --once` performs one refresh;
`--confirm-current` remains a compatibility alias. Do not give the Hermes user
sudo access to this helper or permission to write the attestation directory.

Stopping or disabling the watcher leaves the current record valid until that
gateway process exits. Future gateway processes then need an explicit root
refresh. To revoke the current record as well, stop the watcher before removing
the PID file so it cannot recreate it.

## Verification

The helper has standard-library behavioral tests, included in the normal
repository test discovery:

```sh
python3 -m unittest -v tests.test_hermes_attestation
uv run pytest tests/test_hermes_attestation.py tests/test_hermes_peer.py \
  tests/test_hermes_socket.py -q
```

They cover process identity, UID/cgroup mismatch, stopped gateways, PID reuse,
atomic refresh, unchanged files, transient errors, permissions, and symlink
rejection. Live Linux verification of the deployed helper also covered its
exact service sandbox, a normal gateway restart, successful Intaris reads,
cleared child capabilities, Telegram reconnection, and rejection of a separate
process with the Hermes UID. These checks did not send or click a Telegram
approval. Machine-specific receipts and backups are operator artifacts, not
required runtime files.
