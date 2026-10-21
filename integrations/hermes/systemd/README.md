# Native approval runtime directory

Native Hermes Telegram approvals use a protected Unix socket and operator-owned
UID/profile configuration. See the [native approval guide](../../../docs/clients/hermes-telegram.md)
for the trust boundary and complete setup. No gateway PID attestation, root
watcher, process polling, or restart hook is required.

## Runtime directory setup

The provided tmpfiles entry assumes service user `intaris` and gateway-access
group `hermes`. Adjust these names if the installation differs. It creates
`/run/intaris-native` as `intaris:hermes`, mode `2750`. The setgid bit gives new
socket files the gateway-access group without making the directory writable by
that group. Keep the Intaris and Hermes service UIDs distinct.

Run from the repository root after reviewing any existing installation:

```sh
sudo install -o root -g root -m 0644 \
  integrations/hermes/systemd/intaris-native.conf \
  /etc/tmpfiles.d/intaris-native.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/intaris-native.conf
```

The socket itself is mode `0660`. Set
`INTARIS_NATIVE_APPROVAL_SOCKET=/run/intaris-native/telegram.sock` in the gateway
launch environment and configure `INTARIS_TELEGRAM_BRIDGE` in the Intaris service.
A gateway restart under the same UID requires no Intaris configuration update.

## Migration from the removed watcher

The previous optional `intaris-hermes-attestation.service` and
`intaris-attest-hermes` helper belonged to this Intaris integration, not Hermes.
Removing them changes the trust boundary: **all processes under each configured
Hermes UID, including tool subprocesses, can submit approval actions.** Numeric
Telegram actor and message checks do not isolate the bridge from that trusted
local user. Review the native approval guide before migrating.

1. Back up the current Intaris deployment/config and watcher installation.
2. Remove `pid_file` from every `INTARIS_TELEGRAM_BRIDGE.gateways` entry. Combine
   gateway entries sharing a UID into one entry with all their profiles. Deploy
   the new Intaris version with this config in the same maintenance operation;
   the old version requires `pid_file`, and the new version rejects it.
3. Verify the native listener starts with the intended UID and profile mappings.
   Keep the existing bot, fallback destination, approvers, runtime directory,
   socket permissions, and gateway launch environment.
4. Stop and uninstall the obsolete watcher only after migration succeeds:

```sh
sudo systemctl disable --now intaris-hermes-attestation.service
sudo rm -f /etc/systemd/system/intaris-hermes-attestation.service \
  /usr/local/sbin/intaris-attest-hermes
sudo systemctl daemon-reload
sudo rm -f /run/intaris-native/hermes-gateway.pid \
  /run/intaris-native/.attestation.lock
```

Run watcher-removal commands only on hosts where those files were installed by
this integration. Do not remove `/run/intaris-native`, `telegram.sock`, or the
tmpfiles entry. Do not disable the watcher while the old Intaris version still
requires its identity file. A rollback to that version must restore its
`pid_file` config and watcher/helper, then refresh the identity.

## Verification

```sh
uv run pytest tests/test_hermes_peer.py tests/test_hermes_socket.py \
  tests/test_hermes_bridge.py -q
```

Tests cover UID/profile isolation, rejection of identity fields spoofed in a
request, use by another process with the trusted UID, old-config migration,
protected socket directories, bounded admission, callback binding, and approval
lifecycle behavior. They do not send live Telegram messages.
