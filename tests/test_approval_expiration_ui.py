"""Exercise real UI JavaScript and template bindings without browser dependencies."""

from __future__ import annotations

import json
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is required for UI tests")


class _TemplateParser(HTMLParser):
    """Keep the markup tree so tests execute actual visibility/text bindings."""

    def __init__(self) -> None:
        super().__init__()
        self.root = {"tag": "root", "attrs": {}, "children": []}
        self.stack = [self.root]

    def handle_starttag(self, tag: str, attrs: list) -> None:
        node = {"tag": tag, "attrs": dict(attrs), "children": []}
        self.stack[-1]["children"].append(node)
        if tag not in {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }:
            self.stack.append(node)

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data: str) -> None:
        self.stack[-1]["children"].append(data)

    def find(self, attr: str, value: str) -> dict:
        def walk(node: dict) -> dict | None:
            if node["attrs"].get(attr) == value:
                return node
            for child in node["children"]:
                if isinstance(child, dict) and (found := walk(child)):
                    return found
            return None

        found = walk(self.root)
        assert found is not None, (attr, value)
        return found


HARNESS = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const stores = {};
const listeners = new Map();
const timers = new Map();
const intervals = new Map();
let timerId = 0;
let wire;
const requests = [];
const decisions = [];
const clone = value => JSON.parse(JSON.stringify(value));
const record = {
  call_id: 'expired-call', session_id: 'session-1', source: 'evaluation',
  decision: 'escalate', effective_decision: 'approve', user_decision: 'approve',
  resolved_by: 'judge', resolved_at: '2026-10-18T09:00:00Z',
  expired_at: '2026-10-18T09:01:00Z', expiration_reason: 'timeout',
  timestamp: '2026-10-18T08:59:00Z', tool: 'bash', record_type: 'tool_call',
  risk: 'medium', evaluation_path: 'llm', user_note: 'Previously approved',
  args_redacted: {command: 'echo test'}, reasoning: 'Needs approval',
};
const expiry = {
  type: 'expired', call_id: record.call_id, session_id: record.session_id,
  expired_at: record.expired_at, expiration_reason: record.expiration_reason,
};
const lateDecision = {
  type: 'decided', call_id: record.call_id, session_id: record.session_id,
  decision: 'escalate', user_decision: 'approve', resolved_by: 'judge',
};
const api = {
  async listAudit(params) { requests.push(clone(params)); return {items: [], total: 0, pages: 1}; },
  async getAuditRecord() { return clone(record); },
  async resolveDecision(...args) { decisions.push(args); return {}; },
  connectWebSocket(handlers) { wire = handlers; return {close() {}}; },
};
const window = {
  addEventListener(type, fn) {
    if (!listeners.has(type)) listeners.set(type, []);
    listeners.get(type).push(fn);
  },
  dispatchEvent(event) { for (const fn of listeners.get(event.type) || []) fn(event); },
  location: {search: '', hash: '', pathname: '/ui/'},
  Element: class {},
};
let alpineInit;
const sandbox = vm.createContext({
  console, Date, Map, URLSearchParams, IntarisAPI: api, window,
  CustomEvent: class { constructor(type, options = {}) { this.type = type; this.detail = options.detail; } },
  MutationObserver: class {}, queueMicrotask() {},
  document: {createElement() { return {}; }, addEventListener(type, fn) { if (type === 'alpine:init') alpineInit = fn; }},
  localStorage: {getItem() { return null; }, setItem() {}, removeItem() {}},
  Alpine: {store(name, value) { if (value) stores[name] = window.Alpine.reactive(value); return stores[name]; }},
  setTimeout(fn) { timers.set(++timerId, fn); return timerId; },
  clearTimeout(id) { timers.delete(id); },
  setInterval(fn) { intervals.set(++timerId, fn); return timerId; },
  clearInterval(id) { intervals.delete(id); },
});
vm.runInContext(fs.readFileSync('intaris/ui/static/vendor/alpine.min.js', 'utf8'), sandbox);
for (const name of ['app', 'approvals', 'audit', 'sessions']) {
  vm.runInContext(fs.readFileSync(`intaris/ui/static/js/${name}.js`, 'utf8'), sandbox, {filename: name + '.js'});
}
alpineInit();
const nav = stores.nav;
const approvals = window.Alpine.reactive(sandbox.approvalsTab());
const audit = window.Alpine.reactive(sandbox.auditTab());
const sessions = window.Alpine.reactive(sandbox.sessionsTab());
async function settle() { for (let i = 0; i < 30; i++) await Promise.resolve(); }
async function flushTimers() {
  const batch = [...timers.values()]; timers.clear();
  for (const fn of batch) fn();
  await settle();
}
function connect() { stores.auth.authenticated = true; stores.ws.connect(); }
function emit(data) { wire.onMessage(clone(data)); }
function render(node, scope) {
  sandbox._scope = {...scope, $store: stores};
  const evaluate = expression => vm.runInContext(`with (_scope) { (${expression}) }`, sandbox);
  const result = {text: [], actions: [], badges: []};
  function visit(n) {
    if (typeof n === 'string') { result.text.push(n); return; }
    const attrs = n.attrs;
    for (const directive of ['x-if', 'x-show']) {
      if (attrs[directive] && !evaluate(attrs[directive])) return;
    }
    if (n.tag === 'button' && attrs['@click.stop'] && !evaluate(attrs[':disabled'] || 'false')) {
      result.actions.push(attrs['@click.stop']);
    }
    if (attrs['x-text']) {
      const value = String(evaluate(attrs['x-text']) ?? '');
      result.text.push(value);
      if (n.tag === 'span') result.badges.push({text: value, cls: evaluate(attrs[':class'] || JSON.stringify(attrs.class || ''))});
    } else {
      for (const child of n.children) visit(child);
    }
  }
  visit(node);
  result.text = result.text.join(' ').replace(/\s+/g, ' ');
  return result;
}
"""


def _run_js(body: str, data: dict | None = None) -> None:
    result = subprocess.run(
        [
            NODE,
            "-e",
            HARNESS
            + "\n(async () => {\n"
            + body
            + "\n})().catch(error => { console.error(error); process.exitCode = 1; });",
        ],
        cwd=ROOT,
        input=json.dumps(data or {}),
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("field", ["classification", "evaluation_path"])
def test_hard_prohibitions_have_no_approval_actions(field: str) -> None:
    _run_js(
        r"""
const {field} = JSON.parse(fs.readFileSync(0, 'utf8'));
const hard = {...record, expired_at: null, decision: 'deny', user_decision: null,
  resolved_by: null, [field]: 'critical'};
const ordinary = {...hard, classification: 'write', evaluation_path: 'llm', call_id: 'ordinary'};
assert.equal(audit.canOverrideDenial(hard), false);
assert.equal(audit.canOverrideJudge({...hard, resolved_by: 'judge'}), false);
assert.equal(sandbox.canResolveApproval({...hard, decision: 'escalate'}), false);
assert.equal(audit.canOverrideDenial(ordinary), true);
api.listAudit = async () => ({items: [hard, ordinary], total: 2, pages: 1});
await approvals.loadDenials();
assert.deepEqual(approvals.denials.map(r => r.call_id).join(','), 'ordinary');
""",
        {"field": field},
    )


@pytest.mark.parametrize("view", ["approvals", "audit", "sessions", "modal"])
@pytest.mark.parametrize(
    "reason,label",
    [("timeout", "Timed out"), ("cancelled", "Cancelled"), ("abandoned", "Abandoned")],
)
@pytest.mark.parametrize("historical_approval", [False, True])
def test_expired_views_show_reason_time_history_and_no_actions(
    view: str, reason: str, label: str, historical_approval: bool
) -> None:
    parser = _TemplateParser()
    parser.feed((ROOT / "intaris/ui/static/index.html").read_text())
    rows = {
        "approvals": "item in resolved",
        "audit": "r in records",
        "sessions": "r in sessionAudit",
        "modal": "r in $store.nav.sessionModalAudit",
    }
    _run_js(
        r"""
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
record.expiration_reason = input.reason;
if (!input.historical) {
  record.user_decision = null; record.resolved_by = null; record.resolved_at = null;
}
const before = clone(record);
let scope;
if (input.view === 'approvals') {
  approvals.resolved = [record]; approvals.expandedResolvedId = record.call_id;
  approvals.expandedResolvedRecord = record;
  scope = {...approvals, item: record};
} else if (input.view === 'audit') {
  audit.expandedId = record.call_id; audit.expandedRecord = record;
  scope = {...audit, r: record};
} else if (input.view === 'sessions') {
  sessions.expandedAuditId = record.call_id; sessions.expandedAuditRecord = record;
  scope = {...sessions, r: record};
} else {
  nav.sessionModalAuditExpandedId = record.call_id; nav.sessionModalAuditRecord = record;
  scope = {r: record};
}
const shown = render(input.markup, scope);
assert(shown.badges.some(b => b.text === 'Expired' && b.cls.includes('badge-low')), shown.text);
assert(shown.text.includes(input.label), shown.text);
assert(shown.text.includes(new Date(record.expired_at).toLocaleString()), shown.text);
assert(shown.text.includes('Evaluation'), shown.text);
if (input.historical) assert(shown.text.includes('Previous resolution'), shown.text);
assert.deepEqual(shown.actions.filter(a => /^(?:\$store\.nav\.)?(?:resolve|override)\w*\(/.test(a)), []);
assert.deepEqual(record, before, 'Rendering must preserve historical decisions');
""",
        {
            "markup": parser.find("x-for", rows[view]),
            "view": view,
            "reason": reason,
            "label": label,
            "historical": historical_approval,
        },
    )


@pytest.mark.parametrize("action", ["approve", "deny"])
@pytest.mark.parametrize(
    "entry",
    [
        "approval",
        "judge",
        "denial",
        "audit",
        "audit_judge",
        "audit_denial",
        "session",
        "modal",
    ],
)
@pytest.mark.parametrize("expired", [True, False])
def test_action_entry_points_refuse_expired_records(
    entry: str, action: str, expired: bool
) -> None:
    _run_js(
        r"""
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
record.expired_at = input.expired ? record.expired_at : null;
record.timestamp = '2000-01-01T00:00:00Z'; // Age alone must not close an approval.
if (!input.entry.includes('judge')) { record.user_decision = null; record.resolved_by = null; }
if (input.entry.includes('denial')) record.decision = 'deny';
approvals.pending = [record]; approvals.denials = [record]; approvals.resolved = [record];
approvals.expandedResolvedRecord = record;
audit.records = [record]; audit.expandedRecord = record;
sessions.sessionAudit = [record]; sessions.expandedAuditRecord = record;
nav.sessionModalAudit = [record]; nav.sessionModalAuditRecord = record;
const actions = {
  approval: () => approvals.resolve(record.call_id, input.action),
  judge: () => approvals.override(record.call_id, input.action),
  denial: () => approvals.overrideDenial(record.call_id, input.action),
  audit: () => audit.resolveEscalation(record.call_id, input.action),
  audit_judge: () => audit.overrideJudge(record.call_id, input.action),
  audit_denial: () => audit.overrideDenial(record.call_id, input.action),
  session: () => sessions.resolveEscalation(record.call_id, input.action),
  modal: () => nav.resolveModalEscalation(record.call_id, input.action),
};
await actions[input.entry]();
assert.equal(decisions.length, input.expired ? 0 : 1, 'Expired calls must never reach the decision API');
""",
        {"entry": entry, "action": action, "expired": expired},
    )


def test_pending_and_denials_filter_expired_records_without_age_heuristics() -> None:
    _run_js(r"""
const pending = {...record, call_id: 'still-pending', user_decision: null, expired_at: null, timestamp: '2000-01-01T00:00:00Z'};
api.listAudit = async params => ({items: [clone(record), clone(pending)], total: 2, pages: 1});
await approvals.load();
await approvals.loadDenials();
assert.deepEqual(clone(approvals.pending.map(r => r.call_id)), ['still-pending']);
assert.deepEqual(clone(approvals.denials.map(r => r.call_id)), ['still-pending']);
assert.equal(approvals.total, 1);
""")


def test_expired_event_closes_pending_and_loads_closed_history() -> None:
    _run_js(r"""
approvals.init(); approvals._tabActive = true;
const pending = {...record, user_decision: null, resolved_by: null, resolved_at: null, expired_at: null};
approvals.pending = [clone(pending)]; approvals.total = 1;
api.getAuditRecord = async () => ({...pending, ...expiry});
api.listAudit = async params => {
  requests.push(clone(params));
  return {items: params.resolved ? [{...pending, ...expiry}] : [], total: params.resolved ? 1 : 0, pages: 1};
};
connect(); emit(expiry); await flushTimers();
assert.equal(approvals.pending.length, 0);
assert.equal(approvals.total, 0);
assert.equal(nav.pendingApprovals, 0);
assert.equal(approvals.resolved[0]?.expired_at, record.expired_at);
assert.equal(approvals.resolved[0]?.user_decision, null, 'Expiration is not a human denial');
assert(requests.some(p => p.resolved === true), 'Closed history must refresh');
""")


def test_stale_pending_response_cannot_restore_expired_action() -> None:
    _run_js(r"""
let finish;
const pending = {...record, user_decision: null, expired_at: null};
api.listAudit = params => params.limit === 50
  ? new Promise(resolve => { finish = resolve; })
  : Promise.resolve({items: [], total: 0, pages: 1});
const loading = approvals.load();
connect(); emit(expiry);
finish({items: [pending], total: 1, pages: 1}); await loading;
assert.equal(approvals.pending.length, 0);
assert.equal(approvals.total, 0);
""")


def test_late_decision_does_not_double_decrement_count_or_reopen_expired_details() -> (
    None
):
    _run_js(r"""
nav.pendingApprovals = 3; nav.selectedAgent = 'agent-a';
api.listAudit = async params => { requests.push(clone(params)); return {items: [], total: 3, pages: 1}; };
audit.init(); audit.initialized = true; nav.activeTab = 'audit';
audit.records = [{...record, expired_at: null}]; audit.expandedRecord = {...record, expired_at: null};
sessions.init(); sessions.sessionAudit = [{...record, expired_at: null}]; sessions.expandedAuditRecord = {...record, expired_at: null};
nav.sessionModalAudit = [{...record, expired_at: null}]; nav.sessionModalAuditRecord = {...record, expired_at: null};
connect(); emit(expiry); await settle(); emit(lateDecision); await settle();
assert.equal(nav.pendingApprovals, 3, 'Historical approval expiry and late decision must not subtract from unrelated pending calls');
assert(requests.some(p => p.resolved === false && p.agent_id === 'agent-a'));
assert.equal(audit.canOverrideJudge(audit.expandedRecord), false);
await audit.overrideJudge(record.call_id, 'approve');
await sessions.resolveEscalation(record.call_id, 'approve');
await nav.resolveModalEscalation(record.call_id, 'approve');
assert.equal(decisions.length, 0);
for (const item of [audit.records[0], audit.expandedRecord, sessions.sessionAudit[0], sessions.expandedAuditRecord, nav.sessionModalAudit[0], nav.sessionModalAuditRecord]) {
  assert.equal(item.expired_at, record.expired_at);
  assert.equal(item.user_decision, 'approve');
  assert.equal(item.resolved_at, record.resolved_at, 'Expiration must preserve historical resolution time');
}
""")


def test_count_refresh_ignores_out_of_order_rest_responses() -> None:
    _run_js(r"""
const pendingRequests = [];
api.listAudit = params => new Promise(resolve => { pendingRequests.push(resolve); });
connect(); emit({type: 'evaluated', decision: 'escalate', call_id: 'new-call'}); emit(expiry);
assert(pendingRequests.length >= 2, 'Lifecycle events must reconcile the pending count');
pendingRequests.at(-1)({items: [], total: 1}); await settle();
for (const resolve of pendingRequests.slice(0, -1)) resolve({items: [], total: 8});
await settle();
assert.equal(nav.pendingApprovals, 1);
""")


def test_reconnect_refreshes_pending_history_and_badge() -> None:
    _run_js(r"""
approvals.init(); approvals._tabActive = true;
approvals.pending = [{...record, expired_at: null, user_decision: null}]; approvals.total = 1;
nav.pendingApprovals = 1;
api.listAudit = async params => ({items: params.resolved ? [clone(record)] : [], total: params.resolved ? 1 : 0, pages: 1});
connect(); wire.onOpen(); await settle();
assert.equal(approvals.pending.length, 0);
assert.equal(approvals.resolved[0]?.expired_at, record.expired_at);
assert.equal(nav.pendingApprovals, 0);
""")


def test_lifecycle_events_refresh_authoritative_history_and_ignore_older_fetch() -> (
    None
):
    _run_js(r"""
audit.init(); audit.initialized = true; nav.activeTab = 'audit';
sessions.init();
audit.records = [{...record, expired_at: null}]; audit.expandedRecord = {...record, expired_at: null};
sessions.sessionAudit = [{...record, expired_at: null}]; sessions.expandedAuditRecord = {...record, expired_at: null};
nav.sessionModalAudit = [{...record, expired_at: null}]; nav.sessionModalAuditRecord = {...record, expired_at: null};
const fetches = [];
api.getAuditRecord = callId => new Promise(resolve => { assert.equal(callId, record.call_id); fetches.push(resolve); });
connect(); emit(expiry); emit(lateDecision);
assert(fetches.length >= 2, 'Expiration and decision events must refresh the authoritative row');
const authoritative = {...record, user_decision: 'deny', resolved_by: 'user', user_note: 'Final human decision'};
fetches.at(-1)(authoritative); await settle();
for (const resolve of fetches.slice(0, -1)) resolve({...record, expired_at: null});
await settle();
for (const item of [audit.records[0], audit.expandedRecord, sessions.sessionAudit[0], sessions.expandedAuditRecord, nav.sessionModalAudit[0], nav.sessionModalAuditRecord]) {
  assert.equal(item.user_decision, 'deny');
  assert.equal(item.resolved_by, 'user');
  assert.equal(item.expired_at, record.expired_at);
}
""")


@pytest.mark.parametrize("view", ["audit", "sessions", "modal"])
def test_reconnect_refreshes_open_audit_views(view: str) -> None:
    _run_js(
        r"""
const {view} = JSON.parse(fs.readFileSync(0, 'utf8'));
const old = {...record, expired_at: null};
api.listAudit = async params => ({items: params.resolved === false ? [] : [clone(record)], total: params.resolved === false ? 0 : 1, pages: 1});
if (view === 'audit') {
  audit.init(); audit.initialized = true; nav.activeTab = 'audit';
  audit.records = [clone(old)]; audit.expandedRecord = clone(old); audit.expandedId = record.call_id;
} else if (view === 'sessions') {
  sessions.init(); sessions.expandedId = record.session_id;
  sessions.sessionAudit = [clone(old)]; sessions.expandedAuditRecord = clone(old); sessions.expandedAuditId = record.call_id;
} else {
  nav.sessionModal = {session_id: record.session_id};
  nav.sessionModalAudit = [clone(old)]; nav.sessionModalAuditRecord = clone(old); nav.sessionModalAuditExpandedId = record.call_id;
}
connect(); wire.onOpen(); await settle();
const [rows, detail] = view === 'audit' ? [audit.records, audit.expandedRecord]
  : view === 'sessions' ? [sessions.sessionAudit, sessions.expandedAuditRecord]
  : [nav.sessionModalAudit, nav.sessionModalAuditRecord];
assert.equal(rows[0].expired_at, record.expired_at);
assert.equal(detail.expired_at, record.expired_at);
""",
        {"view": view},
    )


@pytest.mark.parametrize("view", ["approvals", "audit", "sessions", "modal"])
def test_failed_decision_refreshes_expiration_without_websocket_event(
    view: str,
) -> None:
    _run_js(
        r"""
const {view} = JSON.parse(fs.readFileSync(0, 'utf8'));
const pending = {...record, expired_at: null, user_decision: null, resolved_by: null, resolved_at: null};
api.resolveDecision = async () => { throw new Error('Approval has expired'); };
api.getAuditRecord = async () => ({...pending, ...expiry});
if (view === 'approvals') {
  approvals.init(); approvals.pending = [clone(pending)]; approvals.total = 1;
  await approvals.resolve(record.call_id, 'approve');
} else if (view === 'audit') {
  audit.init(); audit.records = [clone(pending)]; audit.expandedRecord = clone(pending);
  await audit.resolveEscalation(record.call_id, 'approve');
} else if (view === 'sessions') {
  sessions.init(); sessions.sessionAudit = [clone(pending)]; sessions.expandedAuditRecord = clone(pending);
  await sessions.resolveEscalation(record.call_id, 'approve');
} else {
  nav.sessionModalAudit = [clone(pending)]; nav.sessionModalAuditRecord = clone(pending);
  await nav.resolveModalEscalation(record.call_id, 'approve');
}
await settle();
assert.equal(sandbox.isApprovalExpired({call_id: record.call_id}), true, 'Failed action must reconcile server expiry even when WebSocket is unavailable');
assert.equal(stores.notify.toasts.some(t => t.type === 'success'), false);
""",
        {"view": view},
    )


@pytest.mark.parametrize("view", ["approvals", "audit", "sessions", "modal"])
def test_unexpired_history_retains_evaluation_and_resolution_badges(view: str) -> None:
    parser = _TemplateParser()
    parser.feed((ROOT / "intaris/ui/static/index.html").read_text())
    rows = {
        "approvals": "item in resolved",
        "audit": "r in records",
        "sessions": "r in sessionAudit",
        "modal": "r in $store.nav.sessionModalAudit",
    }
    _run_js(
        r"""
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
record.expired_at = null;
const component = input.view === 'approvals' ? approvals : input.view === 'audit' ? audit : input.view === 'sessions' ? sessions : {};
const shown = render(input.markup, {...component, r: record, item: record});
const labels = shown.badges.map(b => b.text);
assert(labels.includes('escalate'), 'Original evaluation must stay visible');
assert(labels.includes('approve'), 'Historical resolution must stay visible');
assert(!labels.includes('Expired'));
""",
        {"view": view, "markup": parser.find("x-for", rows[view])},
    )


def test_interactive_login_connects_after_startup_auth_poll_stops() -> None:
    _run_js(r"""
stores.auth.loading = false;
for (const fn of [...intervals.values()]) fn();
assert.equal(intervals.size, 0, 'Startup poll has already stopped on the login screen');
api.setKey = () => {};
api.clearKey = () => {};
api.setSelectedUser = () => {};
api.whoami = async () => ({user_id: 'user-1', can_switch_user: false});
await stores.auth.login('test-key', 'user-1');
assert.equal(stores.auth.authenticated, true);
assert(wire, 'First interactive login must establish WebSocket without a page reload');
assert(requests.some(p => p.resolved === false), 'Login must refresh approval badge');
stores.auth.logout();
assert.equal(stores.ws.ws, null);
await stores.auth.login('test-key', 'user-1');
assert(stores.ws.ws, 'Login after logout must reconnect too');
""")


def test_denial_panel_requests_filter_before_result_limit():
    _run_js(r"""
api.listAudit = async params => {
  requests.push(clone(params));
  assert.equal(params.overridable_denials, true);
  assert.equal(params.limit, 20);
  return {items: [{...record, call_id: 'eligible', expired_at: null, user_decision: null, decision: 'deny'}], total: 25, pages: 2};
};
await approvals.loadDenials();
assert.equal(approvals.denials.length, 1);
assert.equal(approvals.denials[0].call_id, 'eligible');
""")
