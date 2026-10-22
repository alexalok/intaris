# Native Telegram approvals for Hermes

Intaris can present **Approve / Deny** buttons through the existing Hermes
Telegram bot, inline in the originating chat and topic. This is an optional
presentation layer for Intaris decisions. Keep Hermes `approvals.mode: off`;
native LLM approval evaluation is not re-enabled.

No second bot, Telegram token, `getUpdates` consumer, public callback URL, or
laptop tunnel is needed. The plugin registers a namespaced callback handler on
Hermes' existing Telegram application. Buttons approve only one pending Intaris
call, never a session or a permanent tool permission.

## Message layout

Approval prompts use Telegram Rich Messages. The pending card shows the tool,
a short command excerpt, the reason, and the existing Approve / Deny buttons.
**Read more** opens a native, initially collapsed details block with the full
command, nested argument/configuration lists, evaluation reason, and audit IDs.
Strings are displayed as text or code, so commands do not acquire JSON quoting
or escaping. The source remains the redacted audit record.

After approval, denial, cancellation, or expiry, the same message shows only its
status and a short command excerpt. All other details stay behind **Read more**,
and the action buttons are removed. Large or deeply nested records have explicit
truncation notices; the complete record remains in the Intaris audit UI.

This uses Bot API Rich Messages (`sendRichMessage` and `editMessageText` with
`rich_message`), including native `<details>` and nested lists. The Hermes bot's
existing PTB client sends these through its public `do_api_request` method
(PTB 20.8+), so a newer SDK is not required. Telegram Bot API 10.1+ and a client
that displays Rich Messages are required. Upgrade both Intaris and the Hermes
plugin for this layout; an older bridge's text-only response retains the legacy
presentation. Existing prompts already held by an older gateway are not migrated.

References: [Telegram Rich Messages](https://core.telegram.org/bots/features#rich-messages),
[rich HTML details](https://core.telegram.org/bots/api#rich-message-formatting-options),
[PTB API escape hatch](https://docs.python-telegram-bot.org/en/stable/telegram.bot.html#telegram.Bot.do_api_request).

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

Restored legacy sessions without a pinned Telegram transport identity use the
operator's fallback rather than their unverified stored origin. Conflicting
profile or transport identities still block native presentation.

When Telegram explicitly rejects an unavailable origin topic, delivery falls
back once to the operator's configured fallback chat/topic. The same lease and
deadline apply, and only the fallback's configured approvers can act there.
The general chat is used only when explicitly configured as the fallback.
Timeouts and ambiguous sends are not retried, avoiding duplicate prompts.
Missing, identical, or unavailable fallback destinations never approve a call.

## Cron approvals

Current Hermes runs cron agents inside the gateway's canonical session owner.
External scheduler workers submit and observe execution; they do not run the
agent. A profile can use its own Telegram bot, or `fallback_transport_profile`
can select a shared bot under the same gateway. Cron has no admitted
Telegram sender: approval destination and approvers always come from that runtime
profile's operator fallback policy. Job `origin`, model/tool arguments, and session
ID collisions are never routing proof.

Enable the Intaris plugin for that runtime profile in the serving gateway.
Secondary profiles normally require `gateway.multiplex_profiles: true` so the
gateway discovers their plugins. A profile whose cron store is merely ticked,
but whose gateway plugins are not loaded, retains the ordinary Intaris UI wait.
`fallback_transport_profile` selects a transport; it does not discover plugins or
create a bot connection.

This requires the companion Hermes `ctx.cron_approvals` API and this adapter/server
change together. Hermes binds presentation to the original invocation's in-memory
execution scope, actual agent session, runtime profile, and plugin generation.
Presentation uses the existing private Intaris socket and configured UID/profile
authorization. It adds no worker channel or process-attestation requirement.

The adapter selects the cron path using `ctx.current_cron_execution()`, never
`ctx.cron_approvals.available`. Availability can become false during cancellation
or drain; that must not send a cron invocation through interactive routing.
Missing presentation keeps the original bounded audit wait.

The `open_presentation` operation persists an immutable presentation-only marker
in `hermes_approval_presentations`, alongside the existing lease. Callbacks still
resolve one exact call, with the existing actor/bot/chat/topic/message checks.
Closing or expiring this lease retires native buttons and preserves a still-pending
audit. A still-live invocation can continue its original bounded Intaris UI wait
after presentation loss. Terminal leases remain no-replay fences until the audit
settles; restarting either service cannot turn a retired lease into a new prompt.

Older Intaris servers reject `open_presentation` before creating a lease; the adapter
keeps the original audit wait. It never falls back to an ordinary withdrawal lease.
Ordinary interactive native approvals retain their existing withdrawal semantics.
Unloading a plugin or losing one presentation cannot execute or automatically retry
a tool. Only the original invocation's poll and final cancellation checks permit
execution. Gateway restart cannot reconstruct the in-memory presentation authority.

## Local trust boundary

The native bridge requires Linux and separate Intaris/gateway service users.
Intaris exposes a private Unix socket. Kernel `SO_PEERCRED` identifies the
caller's Unix UID; Intaris accepts only configured UIDs and their explicitly
mapped profiles. PID files, process start-time checks, privileged helpers, and
restart attestation are not required. Processes under other UIDs are rejected
before request framing. At most 32 admitted connections can wait for or process
a request; excess connections are refused.

**The configured Hermes Unix user is trusted, including all tool subprocesses
running under that UID.** Such a process can submit native approval actions and
claim an allowed Telegram actor. Actor/message/session/call checks still apply,
but they do not prove a human clicked Telegram when the trusted local user is
malicious. Native audit attribution relies on the local peer's report. This mode
is for deployments that already trust Hermes and its tools;
it is not an isolation boundary against them. Use separate Unix users for
separate gateway trust boundaries. Profiles under one UID share that trust even
though their operator-defined tenant, agent, and routing policies remain distinct.

The bridge has no HTTP route and does not accept Intaris agent API keys.
Keep restricted `INTARIS_AGENT_API_KEYS` on the agent side; never substitute an
administrative Intaris key. No additional decision credential is needed.

The socket's parent directories must be root/Intaris-owned, not writable by the
gateway or other users, and must not contain symlinks. The socket itself is mode
`0660`; give the gateway access through a dedicated group. Profile configuration
below belongs only to the isolated Intaris service, not Hermes `config.yaml`,
`.env`, or model-editable files.

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
Each gateway entry must use a distinct UID. Put all profiles for the same Unix
user in that entry. Profile paths must be absolute resolved Hermes homes.
Numeric chat/user/topic IDs are required; usernames are rejected. The top-level fallback applies to every
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
this directory, or use the [tmpfiles setup](../../integrations/hermes/systemd/README.md).
Configure only one Intaris process to own this socket.

Set `INTARIS_NATIVE_APPROVAL_SOCKET=/run/intaris-native/telegram.sock` in the
**gateway service launch environment**. The plugin deliberately ignores a
similarly named profile/plugin setting and uses the existing bot client. Leaving
this variable unset disables native presentation. The gateway needs read/traverse
access to the protected directory and read/write access to its socket.
Hermes may start before Intaris: hooks remain registered, and subsequent human
waits can use the bridge once its trusted socket is available. A failed current
presentation is not retried automatically; its ordinary audit wait continues.

Gateway restarts require no Intaris-side refresh. The same configured UID can
use the bridge as soon as the gateway reconnects. Normal Intaris shutdown removes
its socket; after a crash, verify no listener remains before removing a stale
socket. Startup never deletes an existing socket automatically.
Startup publishes the configured path only after capturing the socket's inode
and setting permissions. If even the first metadata read fails, an unidentified
private staging socket is left untouched; there are four bounded staging slots.
Exhausting those slots requires operator verification and cleanup before retrying.

## Migration from process attestation

Older deployments configured `gateways[].pid_file` and could run the optional
`intaris-hermes-attestation.service`. These were Intaris integration components,
not Hermes requirements. They have been removed.

Existing `pid_file` configuration is rejected with a migration error rather than
silently changing its trust boundary. After accepting the Unix-user trust model
above, remove `pid_file` from each gateway entry and deploy the new Intaris
version and updated config together. Then remove the obsolete watcher, helper,
and identity file using the [migration guide](../../integrations/hermes/systemd/README.md#migration-from-the-removed-watcher).
Keep the protected runtime directory and existing socket/profile configuration.

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
Intaris UI or judge decision cannot override that decision. Cancellation
and expiration retire pending leases with a denial attributed to
`resolved_by=integration`. Failed or ambiguous Telegram delivery disables the
native presentation while preserving the ordinary Intaris UI wait under its
original deadline. Failed presentations cannot reopen or accept callbacks, and
their deadline/cancellation still retires the invocation. Actual button decisions
are attributed to `resolved_by=user` with the numeric Telegram actor in the audit
note. That generated note carries `user_note_source=system` and is not forwarded
as human guidance. Actual notes entered in the Intaris UI remain available to
the invoking model. Every leased call has persisted `approval_scope=call`,
including resolutions from the Intaris UI or judge. Its verdict never enters retry approval caches,
human precedent, path learning, session alignment overrides, or intention updates.
It is also excluded from later evaluator and judge model history, including
prior judge outcomes; raw audit records remain available in the UI.
Failed withdrawal writes remain recoverable and are retried by the server sweep.
Explicit client expiration also retires native leases, including when it races
with a human or judge verdict. It prevents new prompts and callbacks without
overwriting that audit history. Settled leases with durable audit verdicts or
client expiration are removed one hour after their original deadline. The audit
record remains, so late requests cannot reopen a settled call. Unfinished or
unresolved withdrawals are retained for recovery.

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
Cron presentation additionally requires the canonical-owner API merged in
[Hermes PR #1](https://github.com/alexalok/hermes-agent/pull/1), verified at
`e4ee1687a6f799b7f21f2b173138f910e862ee94`. A compatible Hermes gateway and this
Intaris adapter/server must be installed together. Older versions that execute
cron agents in separate processes retain the existing Intaris UI/notification
path: sharing a configured UID does not provide the gateway's bot client or
native handler API. A fallback transport mapping does not supply that integration.
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
