# Native Telegram approvals for Hermes

Intaris can present **Approve / Deny** buttons through the existing Hermes
Telegram bot, inline in the originating chat and topic. This is an optional
presentation layer for Intaris decisions. Keep Hermes `approvals.mode: off`;
native LLM approval evaluation is not re-enabled.

No second bot, Telegram token, `getUpdates` consumer, public callback URL, or
laptop tunnel is needed. The plugin registers a namespaced callback handler on
Hermes' existing Telegram application. Buttons approve only one pending Intaris
call, never a session or a permanent tool permission.

## Routing and authorization

The gateway derives an origin from its admitted message source and exact Hermes
session identity. Explicit child-session links may inherit that origin. It does
not inspect tool arguments for routing and never chooses the newest or only
active session. Runtime profile and receiving bot identity remain separate when
one bot serves multiple profiles.

The origin must include an identifiable Telegram actor listed in the Intaris
operator policy. Only that actor can use an origin prompt. When trustworthy
correlation is unavailable, the operator's fallback chat/topic receives the
prompt; its buttons accept the configured approver IDs. Group membership alone
does not grant approval authority. With no usable origin or fallback, the
existing bounded Intaris UI approval wait remains available.

When Telegram explicitly rejects an unavailable origin topic, delivery falls
back once to the operator's configured fallback chat/topic. The same lease and
deadline apply, and only the fallback's configured approvers can act there.
The general chat is used only when explicitly configured as the fallback.
Timeouts and ambiguous sends are not retried, avoiding duplicate prompts.
Missing, identical, or unavailable fallback destinations never approve a call.

## Local trust boundary

The native bridge requires Linux and separate Intaris/gateway service users.
Intaris exposes a private Unix socket. Kernel `SO_PEERCRED` identifies the caller;
Intaris compares its UID, PID and process start time against a protected operator
attestation. Agent tool subprocesses share the gateway UID but have different
PIDs and cannot submit decisions. The bridge has no HTTP route and does not
accept Intaris agent API keys.
Unattested processes are rejected before request framing. At most 32 admitted
connections can wait for or process a request; excess connections are refused.

The gateway process and installed plugin code are trusted host components. This
does not sandbox arbitrary malicious Python already running inside the gateway,
nor protect a gateway that the agent can debug, inject into, replace, or restart
with modified code. Protect gateway code/service files and process-debugging
access with the host's normal security boundary. Keep restricted
`INTARIS_AGENT_API_KEYS` on the agent side; never substitute an administrative
Intaris key.

The socket's parent directories and PID attestation must be root/Intaris-owned,
not writable by the gateway or other users, and must not contain symlinks. The
socket itself is mode `0660`; give the gateway access through a dedicated group.
Profile configuration below belongs only to the isolated Intaris service, not
Hermes `config.yaml`, `.env`, or model-editable files.

## Operator configuration

Set `INTARIS_TELEGRAM_BRIDGE` in the **Intaris service environment** to a JSON
object like this (replace all IDs, paths, and UID):

```json
{
  "socket_path": "/run/intaris-native/telegram.sock",
  "fallback_chat_id": "-1001234567890",
  "fallback_thread_id": "42",
  "gateways": [
    {
      "uid": 1001,
      "pid_file": "/run/intaris-native/hermes-gateway.pid",
      "profiles": {
        "/home/hermes/.hermes": {
          "user_id": "operator",
          "agent_id": "hermes",
          "approver_ids": ["123456789"]
        },
        "/home/hermes/.hermes/profiles/research": {
          "user_id": "operator",
          "agent_id": "hermes-research",
          "approver_ids": ["123456789"],
          "fallback_transport_profile": "/home/hermes/.hermes"
        }
      }
    }
  ]
}
```

`user_id` must match the tenant bound to Hermes' restricted API key.
`agent_id` must match both the session and evaluation agent metadata
(`INTARIS_AGENT_ID`). Use a distinct agent ID for each configured runtime profile.
Profile paths must be absolute resolved Hermes homes. Numeric chat/user/topic IDs
are required; usernames are rejected. The top-level fallback applies to every
profile. A profile can override `fallback_chat_id` and `fallback_thread_id`;
overriding the chat never inherits a topic from the global chat. An explicit
profile `fallback_chat_id: null` disables its fallback. Omit both global fallback
fields to disable fallback globally, or omit only `fallback_thread_id` for an
ordinary fallback chat. The selected existing bot must have access to that chat.
For Telegram's General topic, omit `fallback_thread_id` or set it to `"1"`.
The plugin omits the thread parameter when sending to General and accepts both
Telegram representations of that same topic when binding messages and callbacks.

`fallback_transport_profile` selects the bot-owning profile for background work
without a correlated Telegram session transport. Set it to that profile's
absolute resolved Hermes home, listed under the **same gateway**. In the example,
research webhook and in-process cron approvals use the default profile's existing
Telegram bot and the global fallback chat/topic. The default profile must load
the Intaris native handler on that bot. Every runtime profile retains its own
tenant, agent, approvers, and fallback destination; only the bot connection is
shared. The mapping is direct, not a chain through another profile's fallback.

Omitting `fallback_transport_profile` keeps the runtime profile's own bot as the
fallback transport. The gateway obtains this selection from the peer-authenticated
Intaris socket, not Hermes plugin settings or tool arguments. A missing or
ambiguous bot, disabled fallback, or failed lookup leaves the existing UI wait;
the gateway never guesses another profile's bot. Correlated Telegram sessions
keep their receiving bot, including a fallback after an unavailable origin topic.
This mapping does not change ordinary cron/webhook result delivery settings.

Create `/run/intaris-native` with Intaris ownership, dedicated gateway-access
group, and mode `0750`. The Intaris service must use that group for the socket.
Do not make the directory group-writable. A systemd `RuntimeDirectory` can manage
this directory. Configure only one Intaris process to own this socket.

Set `INTARIS_NATIVE_APPROVAL_SOCKET=/run/intaris-native/telegram.sock` in the
**gateway service launch environment**. The plugin deliberately ignores a
similarly named profile/plugin setting and uses the existing bot client. Leaving
this variable unset disables native presentation. The gateway needs read/traverse
access to the protected directory and read/write access to its socket.
Hermes may start before Intaris: hooks remain registered, and subsequent human
waits can use the bridge once its trusted socket is available. A failed current
presentation is not retried automatically; its ordinary audit wait continues.

After the gateway starts, an operator or privileged service hook must write its
main PID and Linux process birth ticks into the attestation file. The format is:

```text
1234 987654
```

The second value is field 22 of `/proc/1234/stat`, parsed after the final `)`
because process names can contain spaces. For example, run this under the
operator account that owns the protected directory, after obtaining the
gateway's **MainPID** from its actual systemd unit:

```bash
python3 - "$GATEWAY_MAIN_PID" /run/intaris-native/hermes-gateway.pid <<'PY'
import os
import sys
import tempfile
from pathlib import Path

pid = int(sys.argv[1])
target = Path(sys.argv[2])
start = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
fd, temporary = tempfile.mkstemp(dir=target.parent)
with os.fdopen(fd, "w") as output:
    output.write(f"{pid} {start}\n")
os.replace(temporary, target)
PY
```

Never let the gateway write this attestation itself. Refresh it after every
gateway restart; a reused PID with a different start time is rejected. The
bridge reads the file on each request, so re-attestation needs no Intaris
restart. Until valid attestation exists, native presentation is unavailable and
ordinary Intaris UI approval remains available. Normal Intaris shutdown removes
its socket; after a crash, verify no listener remains before removing a stale
socket. Startup never deletes an existing socket automatically.
Startup publishes the configured path only after capturing the socket's inode
and setting permissions. If even the first metadata read fails, an unidentified
private staging socket is left untouched; there are four bounded staging slots.
Exhausting those slots requires operator verification and cleanup before retrying.

## Lifetime and failure behavior

The original Hermes invocation owns the approval deadline. Intaris clamps each
native lease to that remaining budget and a maximum of 600 seconds. One durable
lease exists per tenant/call. Callback identity binds profile, session, call,
random lease, actor, chat, topic, bot connection, and sent message. The callback
only records an Intaris verdict; the existing adapter polling and cancellation
checks decide whether the original invocation can continue.
An idle session or parent does not cancel a pending approval; the invocation's
deadline still applies. Completed, suspended, and terminated sessions or parents
make the buttons non-actionable.

Duplicate taps, moved/forwarded messages, late actions, and callbacks after an
Intaris UI or judge decision cannot override that decision. Cancellation,
expiration, and definite notification failure retire pending leases with a
denial attributed to `resolved_by=integration`; actual button decisions are
attributed to `resolved_by=user` with the numeric Telegram actor in the audit
note. Every leased call has persisted `approval_scope=call`, including resolutions
from the Intaris UI or judge. Its verdict never enters retry approval caches,
human precedent, path learning, session alignment overrides, or intention updates.
It is also excluded from later evaluator and judge model history, including
prior judge outcomes; raw audit records remain available in the UI.
Failed withdrawal writes remain recoverable and are retried by the server sweep.
Settled leases with durable audit verdicts are removed one hour after their
original deadline. The audit verdict remains, so late requests cannot reopen a
settled call. Unfinished or unresolved withdrawals are retained for recovery.

Resolution or withdrawal removes buttons and updates the original message when
Telegram is reachable. If editing fails, the server still rejects stale buttons.
There is no automatic replay of a tool after reconnect/restart, and no retry of
an ambiguous notification send. Native prompt state lost on gateway restart
fails closed; existing leases expire rather than creating duplicate alerts.
Telegram send, edit, and callback acknowledgements use Hermes' wall-clock deadline
primitive with an eight-second cap, including cancellation-shielded requests.
Late sends are retired without buttons; a late button edit triggers another
removal. Profile unload shares its existing teardown deadline across all native
lease closes. Once that budget expires, remaining local callbacks stay inactive
and server leases expire under their original deadline.

The initial integration targets the verified Hermes API contracts at commit
`63d0b94120027d487c9a5235b9ec64b696af1b26`. It needs in-process native handler
registration; Hermes isolated plugin hosts currently do not expose that API.
Separate-process cron workers also cannot use the native bridge: the attestation
authorizes only the gateway process, and workers have neither that peer identity
nor its bot client. They retain the existing Intaris UI/notification path; an
explicit fallback transport mapping does not supply a worker-to-gateway relay.
The guarded native-tool path is supported. The optional Intaris MCP proxy keeps
its existing manual escalation/retry behavior; it does not gain automatic remote
tool replay through this feature.

Judge deferrals and errors now reach configured notification channels under
`JUDGE_NOTIFY_MODE=deny_only`, as documented by that mode. `never` still suppresses
those channel notifications. Native prompts are tied to active Hermes human
waits rather than general notification subscriptions. Existing webhook/Slack/
Pushover subscriptions remain independent; disable redundant subscriptions if
the operator wants only native Telegram prompts.

References: [Telegram callback queries](https://core.telegram.org/bots/api#callbackquery),
[message topics](https://core.telegram.org/bots/api#sendmessage),
[namespaced PTB handlers](https://docs.python-telegram-bot.org/en/stable/telegram.ext.callbackqueryhandler.html).
