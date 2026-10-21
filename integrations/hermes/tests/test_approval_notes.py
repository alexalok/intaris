"""Human approval notes reach only the originating model-visible tool result."""

from __future__ import annotations

import ast
import asyncio
import copy
import io
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import hermes_intaris as plugin
import pytest
from hermes_intaris.client import IntarisClient

from . import test_plugin, test_waits
from .test_profiles import Context
from .test_profiles import runtime as profile_runtime

host = test_waits.host
scripted_http = test_plugin.scripted_http
runtime = profile_runtime
NOTE = 'Use staging only.\nСначала проверь "dry run".'


@pytest.fixture
def adapter(host):
    profile = plugin.ProfileRuntime(
        home=plugin._profile_key(),
        cfg=plugin.Config(checkpoint_interval=0, mcp_tools=False),
        client=IntarisClient("http://intaris.test", "test-key"),
    )
    for name in ("A", "B"):
        state = plugin._get_or_create_state(profile, name)
        state.intaris_session_id = f"intaris-{name}"
    executions = []

    def wrap(result, is_async=False):
        def original(args, **kwargs):
            executions.append((args, kwargs))
            return result

        async def async_original(args, **kwargs):
            await asyncio.sleep(0)
            return original(args, **kwargs)

        return plugin._make_guarded_handler(
            profile,
            async_original if is_async else original,
            "terminal",
            "test",
            is_async,
        )

    yield SimpleNamespace(profile=profile, executions=executions, wrap=wrap)
    for state in profile.sessions.values():
        if state._completion is not None:
            plugin._forget_completion_owner(state._completion)


def replies(decision="approve", *, reactivated=False, **audit):
    prefix = []
    if reactivated:
        prefix = [
            {"decision": "deny", "session_status": "suspended", "call_id": "old"},
            {"status": "active"},
        ]
    return [
        *prefix,
        {"decision": "escalate", "call_id": "call-A", "reasoning": "Evaluator reason"},
        {"user_decision": decision, "resolved_by": "user", **audit},
    ]


@pytest.mark.parametrize("reactivated", [False, True])
@pytest.mark.parametrize("is_async", [False, True])
@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_resolution_note_reaches_model_without_replacing_result(
    adapter, scripted_http, reactivated, is_async, decision
):
    scripted_http(*replies(decision, reactivated=reactivated, user_note=NOTE))
    handler = adapter.wrap('{"output": "ok", "exit_code": 0}', is_async)
    result = handler({"command": "pwd"}, session_id="A", task_id="worker")
    if is_async:
        result = asyncio.run(result)
    data = json.loads(result)
    assert data.pop("_intaris_approval") == {
        **({"native_failure_signal": "error"} if decision == "deny" else {}),
        "source": "human",
        "call_id": "call-A",
        "decision": decision,
        "user_note": NOTE,
    }
    if decision == "approve":
        assert data == {"output": "ok", "exit_code": 0}
        assert adapter.executions == [
            ({"command": "pwd"}, {"session_id": "A", "task_id": "worker"})
        ]
        pending = adapter.profile.sessions["A"].pending_tool_results
        assert len(pending) == 1 and pending[0]["call_id"] == "call-A"
    else:
        assert data == {"error": "[intaris] DENIED by user (call-A): Evaluator reason"}
        assert adapter.executions == []
        assert adapter.profile.sessions["A"].pending_tool_results == []


@pytest.mark.parametrize("decision", ["approve", "deny"])
@pytest.mark.parametrize(
    "audit",
    [
        {},
        {"user_note": None},
        {"user_note": ""},
        {"user_note": " \n\t "},
        {"user_note": False},
        {"user_note": {"untrusted": "not text"}},
        {"user_note": "Judge (high confidence)", "resolved_by": "judge"},
        {
            "user_note": "Telegram user 42; native call-specific approval",
            "resolved_by": "user",
            "user_note_source": "system",
        },
        {"user_note": "Unrecognized source", "user_note_source": "unknown"},
    ],
)
def test_missing_or_nonhuman_note_preserves_existing_behavior(
    adapter, scripted_http, decision, audit
):
    scripted_http(*replies(decision, **audit))
    original = '{ "output" : "ok", "exit_code" : 0 }'
    result = adapter.wrap(original)({}, session_id="A")
    if decision == "approve":
        assert result == original
        assert len(adapter.executions) == 1
    else:
        assert json.loads(result) == {
            "error": "[intaris] DENIED by user (call-A): Evaluator reason"
        }
        assert not adapter.executions


@pytest.mark.parametrize("resolved_by", [None, "user"])
@pytest.mark.parametrize("user_note_source", [None, "user"])
def test_pending_note_is_ignored_and_terminal_note_is_used(
    adapter, scripted_http, resolved_by, user_note_source
):
    responses = replies(
        user_note=NOTE, resolved_by=resolved_by, user_note_source=user_note_source
    )
    responses.insert(-1, {"user_decision": None, "user_note": "stale pending note"})
    scripted_http(*responses)
    result = adapter.wrap('{"result": "ok"}')({}, session_id="A")
    assert json.loads(result)["_meta"]["_intaris_approval"]["user_note"] == NOTE
    assert "stale pending note" not in result
    assert len(adapter.executions) == 1


@pytest.mark.parametrize(
    "original",
    [
        {"output": "failed", "exit_code": 7, "error": "native error", "success": False},
        {"_intaris_approval": "native field", "result": "ok"},
    ],
)
def test_json_fields_and_failure_signals_survive_note(adapter, scripted_http, original):
    scripted_http(*replies(user_note=NOTE))
    result = json.loads(adapter.wrap(json.dumps(original))({}, session_id="A"))
    for key, value in original.items():
        assert result.pop(key) == value
    assert len(result) == 1
    assert next(iter(result.values()))["user_note"] == NOTE
    assert len(adapter.executions) == 1


def test_plain_text_result_keeps_output_and_labels_human_note(adapter, scripted_http):
    scripted_http(*replies(user_note=NOTE))
    original = "tool output\n  exact whitespace\n"
    result = adapter.wrap(original)({}, session_id="A")
    assert result.endswith(original)
    addition = result[: -len(original)]
    assert "Intaris human decision note" in addition
    assert json.loads(addition.split("\n", 1)[1])["user_note"] == NOTE
    assert len(adapter.executions) == 1


@pytest.mark.parametrize("original", ['[1, "two"]', '"text"', "null", "7", "false"])
def test_nonobject_json_result_stays_valid_json_with_original_value(
    adapter, scripted_http, original
):
    scripted_http(*replies(user_note=NOTE))
    result = json.loads(adapter.wrap(original)({}, session_id="A"))
    assert result["tool_result"] == json.loads(original)
    assert result["_intaris_approval"]["user_note"] == NOTE


@pytest.mark.parametrize("summary", [None, "", "screen summary"])
@pytest.mark.parametrize("is_async", [False, True])
def test_multimodal_result_keeps_media_and_note_in_text_fallback(
    adapter, scripted_http, summary, is_async
):
    original = {
        "_multimodal": True,
        "content": [
            {"type": "text", "text": "screen output"},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,test"}},
        ],
        "metadata": {"native": True},
    }
    if summary is not None:
        original["text_summary"] = summary
    before = copy.deepcopy(original)
    scripted_http(*replies(user_note=NOTE))
    result = adapter.wrap(original, is_async)({}, session_id="A")
    if is_async:
        result = asyncio.run(result)
    assert original == before  # A provider may reuse its result object.
    assert result["_multimodal"] is True
    assert len(result["content"]) == len(before["content"])
    assert result["content"][1] is original["content"][1]
    assert result["metadata"] == before["metadata"]
    part = result["content"][0]
    assert part["type"] == "text"
    annotation, _, output = part["text"].partition("\n\n")
    assert output == before["content"][0]["text"]
    assert "Intaris human decision note" in annotation
    assert json.loads(annotation.split("\n", 1)[1])["user_note"] == NOTE
    if summary:
        assert result["text_summary"] == annotation + "\n\n" + summary
    elif summary is not None:
        assert result["text_summary"] == summary
    else:
        assert "text_summary" not in result
    assert len(adapter.executions) == 1


def test_image_only_result_gets_note_without_changing_media(adapter, scripted_http):
    image = {"type": "image_url", "image_url": {"url": "data:image/png;base64,test"}}
    original = {"_multimodal": True, "content": [image]}
    scripted_http(*replies(user_note=NOTE))
    result = adapter.wrap(original)({}, session_id="A")
    assert original == {"_multimodal": True, "content": [image]}
    assert result["content"][1] is image
    assert (
        json.loads(result["content"][0]["text"].split("\n", 1)[1])["user_note"] == NOTE
    )
    assert "text_summary" not in result


@pytest.mark.parametrize("same_session", [False, True])
def test_concurrent_notes_stay_with_invocation_and_do_not_leak_to_next_call(
    adapter, monkeypatch, same_session
):
    barrier = threading.Barrier(2)

    def transport(req, **kwargs):
        path = urlsplit(req.full_url).path
        if path.endswith("/evaluate"):
            body = json.loads(req.data)
            name = body["args"]["name"]
            expected_session = "intaris-A" if same_session else f"intaris-{name}"
            assert body["session_id"] == expected_session
            data = {"decision": "escalate", "call_id": f"call-{name}"}
        else:
            name = path.rsplit("-", 1)[-1]
            barrier.wait(timeout=5)
            data = {
                "user_decision": "approve" if name == "A" else "deny",
                "resolved_by": "user",
                "user_note": f"Note for {name}",
            }
        response = io.BytesIO(json.dumps(data).encode())
        response.status = 200
        return response

    monkeypatch.setattr("urllib.request.urlopen", transport)
    handler = adapter.wrap('{"result": "ok"}')
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            name: pool.submit(
                handler, {"name": name}, session_id="A" if same_session else name
            )
            for name in ("A", "B")
        }
        for name, future in futures.items():
            data = json.loads(future.result(timeout=8))
            metadata = data["_meta"] if name == "A" else data
            assert metadata["_intaris_approval"]["user_note"] == f"Note for {name}"
            assert metadata["_intaris_approval"]["call_id"] == f"call-{name}"
    assert adapter.executions == [({"name": "A"}, {"session_id": "A"})]

    def approve(*args, **kwargs):
        response = io.BytesIO(b'{"decision": "approve"}')
        response.status = 200
        return response

    monkeypatch.setattr("urllib.request.urlopen", approve)
    assert handler({}, session_id="B") == '{"result": "ok"}'


def test_invalid_decision_with_note_cannot_approve_or_publish_note(
    adapter, scripted_http
):
    scripted_http(*replies("unexpected", user_note=NOTE))
    result = adapter.wrap('{"result": "ok"}')({}, session_id="A")
    assert "Invalid escalation response" in json.loads(result)["error"]
    assert "_intaris_approval" not in result
    assert not adapter.executions


@pytest.mark.parametrize("decision", ["approve", "deny"])
@pytest.mark.parametrize("reactivated", [False, True])
def test_expired_resolution_discards_historical_human_note(
    adapter, scripted_http, decision, reactivated
):
    scripted_http(
        *replies(
            decision,
            reactivated=reactivated,
            expired_at="2026-10-20T17:00:00Z",
            expiration_reason="timeout",
            user_note=NOTE,
        )
    )
    result = json.loads(adapter.wrap('{"result": "ok"}')({}, session_id="A"))
    assert "APPROVAL EXPIRED" in result["error"]
    assert "_intaris_approval" not in result
    assert not adapter.executions


@pytest.mark.parametrize("stop", ["cancel", "timeout"])
@pytest.mark.parametrize("fail_open", [False, True])
def test_late_resolution_note_is_discarded_after_wait_stops(
    adapter, scripted_http, stop, fail_open
):
    adapter.profile.cfg = replace(adapter.profile.cfg, fail_open=fail_open)
    transport = scripted_http(*replies(user_note=NOTE))
    responses = transport.side_effect

    def respond(req, **kwargs):
        response = next(responses)
        if "/audit/" in req.full_url:
            if stop == "cancel":
                adapter.profile.sessions["A"]._ended.set()
            else:
                time.sleep(301)  # Virtual clock from scripted_http; no real sleep.
        return response

    transport.side_effect = respond
    handler = adapter.wrap('{"result": "ok"}')
    data = json.loads(handler({}, session_id="A"))
    assert ("CANCELLED" if stop == "cancel" else "TIMEOUT") in data["error"]
    assert "_intaris_approval" not in data
    assert not adapter.executions
    assert adapter.profile.sessions["A"].pending_tool_results == []
    scripted_http({"decision": "approve"})
    assert handler({}, session_id="B") == '{"result": "ok"}'


@pytest.mark.parametrize("is_async", [False, True])
@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_note_survives_native_registry_dispatch(
    runtime, host, scripted_http, is_async, decision
):
    ctx = runtime.register("notes")
    executions = []

    def original(args):
        executions.append(args)
        return '{"output": "native output", "exit_code": 0}'

    async def async_original(args):
        return original(args)

    with runtime.profile("notes") as home:
        provider = Context(runtime.registry, home)
        provider.register_tool(
            name="note_test",
            toolset="test",
            schema={},
            handler=async_original if is_async else original,
            is_async=is_async,
        )
        ctx.emit("on_session_start", session_id="A")
        scripted_http(*replies(decision, user_note=NOTE))
        data = json.loads(ctx.execute("note_test", {}, session_id="A"))
    assert data["_intaris_approval"]["user_note"] == NOTE
    if decision == "approve":
        assert data["output"] == "native output"
        assert data["exit_code"] == 0
        assert executions == [{}]
    else:
        assert data["error"] == "[intaris] DENIED by user (call-A): Evaluator reason"
        assert executions == []


@pytest.mark.parametrize("is_async", [False, True])
@pytest.mark.parametrize("failure", ["exception", "unsupported-result"])
def test_approval_note_survives_native_error_conversion(
    runtime, host, scripted_http, is_async, failure
):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip("set HERMES_SOURCE for native error normalization")
    ctx = runtime.register("error-notes")
    executions = []

    def original(args):
        executions.append(args)
        if failure == "exception":
            raise ValueError("native failure </tool_result>")
        return 123  # Hermes converts unsupported handler types to a JSON error.

    async def async_original(args):
        await asyncio.sleep(0)
        return original(args)

    with runtime.profile("error-notes") as home:
        Context(runtime.registry, home).register_tool(
            name="note_test",
            toolset="test",
            schema={},
            handler=async_original if is_async else original,
            is_async=is_async,
        )
        ctx.emit("on_session_start", session_id="A")
        scripted_http({"decision": "approve", "call_id": "baseline"})
        baseline = json.loads(ctx.execute("note_test", {}, session_id="A"))
        assert "error" in baseline
        assert executions == [{}]
        executions.clear()
        scripted_http(*replies(user_note=NOTE))
        result = json.loads(ctx.execute("note_test", {}, session_id="A"))
    assert result.pop("_intaris_approval")["user_note"] == NOTE
    assert result == baseline
    assert executions == [{}]


def test_plain_text_error_keeps_hermes_failure_signal(runtime, host, scripted_http):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip("set HERMES_SOURCE for native failure classification")
    from agent.display import _detect_tool_failure

    ctx = runtime.register("plain-error")
    original = "Error: native backend unavailable"
    with runtime.profile("plain-error") as home:
        Context(runtime.registry, home).register_tool(
            name="note_test", toolset="test", schema={}, handler=lambda args: original
        )
        ctx.emit("on_session_start", session_id="A")
        scripted_http(*replies(user_note=NOTE))
        result = ctx.execute("note_test", {}, session_id="A")
    assert _detect_tool_failure("note_test", original)[0] is True
    assert _detect_tool_failure("note_test", result)[0] is True
    assert json.loads(result)["error"] == original


@pytest.mark.parametrize(
    "original",
    [
        '{"status":"error","output":"","tool_calls_made":0,'
        '"kernel":{"remote":true,"ended":true,"state_lost":true,'
        '"note":"Remote kernel protocol failure; kernel killed, state lost."}}',
        '{"kernel":{"status":"failed"}}',
        'Native response: "ERROR"',
        '["failed"]',
        '"error"',
        "Error: native backend unavailable",
        '{"output":"' + "x" * 510 + '","status":"error"}',
        '{   "output":"' + "x" * 480 + '","status":"error"}',
        '{"status":"err\\u006fr"}',
        '"err\\u006fr"',
        '[{"error":null}]',
        '[{"error":"boom"}]',
        '[{"failed":0}]',
        '["' + "x" * 510 + '","error"]',
        'Native response: "error": null',
        'Native response: "failed": 0',
        "x" * 498 + '"error"',
        '{"output":"ok"}',
    ],
    ids=[
        "kernel-error",
        "nested-failed",
        "plain-error",
        "array",
        "scalar",
        "error-prefix",
        "late-token",
        "whitespace",
        "escaped-status",
        "escaped-scalar",
        "empty-error-array",
        "nonempty-error-array",
        "empty-failed-array",
        "late-array-marker",
        "empty-error-text",
        "empty-failed-text",
        "boundary-text-marker",
        "success",
    ],
)
@pytest.mark.parametrize(
    ("note", "call_id"),
    [
        (NOTE, "call-A"),
        ("Use staging only. " * 40, "call-A"),
        (NOTE, "call-" + "x" * 600),
    ],
    ids=["short", "long-note", "long-call-id"],
)
def test_long_note_preserves_native_failure_detection(
    runtime, host, original, note, call_id
):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip("set HERMES_SOURCE for native failure classification")
    from agent.display import _detect_tool_failure

    result = plugin._with_approval_note(
        original, plugin._HumanPollResult("approve", note), call_id
    )
    # Hermes versions differ in failure parsing; adding guidance must preserve
    # the actual host verdict, including success-shaped payloads with error text.
    failed = _detect_tool_failure("execute_code", original)[0]
    assert _detect_tool_failure("execute_code", result)[0] is failed
    try:
        native = json.loads(original)
    except ValueError:
        if not original.startswith("Error"):
            annotation, _, output = result.partition("\n\n")
            assert output == original
            assert json.loads(annotation.split("\n", 1)[1])["user_note"] == note
            return
        native = {"error": original}
    enriched = json.loads(result)
    assert enriched.pop("_intaris_approval")["user_note"] == note
    if not isinstance(native, dict):
        assert enriched.pop("status", None) == ("error" if failed else None)
    assert enriched == (native if isinstance(native, dict) else {"tool_result": native})


@pytest.mark.parametrize(
    ("tool", "original"),
    [
        ("terminal", '{"exit_code":0,"output":"error"}'),
        ("write_file", '{"bytes_written":1,"error":null}'),
        ("patch", '{"success":true,"status":"failed"}'),
        ("read_file", '{"guardrail_refusal":true,"error":"Do not retry"}'),
    ],
)
def test_native_success_overrides_still_win_with_failure_hint(
    runtime, host, tool, original
):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip("set HERMES_SOURCE for native failure classification")
    from agent.display import _detect_tool_failure

    result = plugin._with_approval_note(
        original, plugin._HumanPollResult("approve", "Guidance. " * 100), "call-A"
    )
    assert _detect_tool_failure(tool, original)[0] is False
    assert _detect_tool_failure(tool, result)[0] is False


@pytest.mark.parametrize(
    "note", ["error", "failed", "ERROR", "FAILED", 'See "error', 'See "FaIlEd']
)
@pytest.mark.parametrize("original", ['{"output": "native output"}', "native output"])
def test_human_note_does_not_turn_native_success_into_failure(
    runtime, host, scripted_http, note, original
):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip("set HERMES_SOURCE for native failure classification")
    from agent.display import _detect_tool_failure

    ctx = runtime.register("note-word")
    with runtime.profile("note-word") as home:
        Context(runtime.registry, home).register_tool(
            name="note_test", toolset="test", schema={}, handler=lambda args: original
        )
        ctx.emit("on_session_start", session_id="A")
        scripted_http(*replies(user_note=note))
        result = ctx.execute("note_test", {}, session_id="A")
    assert _detect_tool_failure("note_test", original)[0] is False
    assert _detect_tool_failure("note_test", result)[0] is False
    if original.startswith("{"):
        assert json.loads(result)["_intaris_approval"]["user_note"] == note
    else:
        annotation, _, output = result.partition("\n\n")
        assert json.loads(annotation.split("\n", 1)[1])["user_note"] == note
        assert output == original


@pytest.mark.parametrize("vision", [False, True])
@pytest.mark.parametrize("multimodal", [False, True])
def test_note_survives_hermes_model_message_conversion(
    runtime, host, scripted_http, vision, multimodal
):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip("set HERMES_SOURCE for the real model-message contract")
    from agent.tool_dispatch_helpers import make_tool_result_message
    from agent.vision_message_prep import VisionMessagePrepMixin

    ctx = runtime.register("model-notes")
    native = (
        {
            "_multimodal": True,
            "content": [
                {"type": "text", "text": "screen output"},
                {
                    "type": "image_url",
                    "image_url": {"url": "data:image/png;base64,test"},
                },
            ],
            "text_summary": "screen summary",
        }
        if multimodal
        else '{"output": "native output", "exit_code": 0}'
    )
    with runtime.profile("model-notes") as home:
        Context(runtime.registry, home).register_tool(
            name="note_test", toolset="test", schema={}, handler=lambda args: native
        )
        ctx.emit("on_session_start", session_id="A")
        scripted_http(*replies(user_note=NOTE))
        result = ctx.execute("note_test", {}, session_id="A")

    model = SimpleNamespace(
        provider="test",
        model="test-model",
        _content_has_image_parts=VisionMessagePrepMixin._content_has_image_parts,
        _model_supports_vision=lambda: vision,
        _provider_supports_vision_tool_messages=lambda: True,
    )
    content = VisionMessagePrepMixin._tool_result_content_for_active_model(
        model, "note_test", result
    )
    message = make_tool_result_message("note_test", content, "hermes-call-A")
    assert message["tool_call_id"] == "hermes-call-A"
    assert message["role"] == "tool"
    if multimodal:
        text = content[0]["text"] if vision else content
        assert "Intaris human decision note" in text
        assert json.dumps(NOTE, ensure_ascii=False) in text
        if vision:
            assert content[1] == native["content"][1]
        else:
            assert "screen summary" in text
    else:
        assert json.loads(content)["_intaris_approval"]["user_note"] == NOTE


@pytest.fixture
def persist_multimodal():
    source = os.environ.get("HERMES_SOURCE")
    if not source:
        pytest.skip("set HERMES_SOURCE for the real output-budget contract")
    from tools.tool_result_storage import maybe_persist_tool_result

    # Compile the pinned executor's budgeting helper verbatim without starting
    # its unrelated agent dependencies (same approach as hermes_runtime.py).
    path = Path(source) / "agent/tool_executor.py"
    tree = ast.parse(path.read_text())
    nodes = [
        n
        for n in tree.body
        if getattr(n, "name", "") == "_persist_multimodal_text_parts"
    ]
    assert len(nodes) == 1
    namespace = {"maybe_persist_tool_result": maybe_persist_tool_result}
    module = ast.Module(
        body=ast.parse("from __future__ import annotations").body + nodes,
        type_ignores=[],
    )
    exec(compile(module, str(path), "exec"), namespace)
    return namespace["_persist_multimodal_text_parts"]


@pytest.mark.parametrize(
    "original",
    [
        '{"result":"native output\\n"}',
        '{"result":"native output\\n","_meta":{"status":"failed"}}',
        '{"result":"native output\\n","_meta":{"status":"err\\u006fr"}}',
    ],
)
def test_mcp_note_preserves_native_failure_detection(runtime, host, original):
    if not os.environ.get("HERMES_SOURCE"):
        pytest.skip("set HERMES_SOURCE for native failure classification")
    from agent.display import _detect_tool_failure
    from tools.tool_result_storage import _pageable_text

    note = "Use staging. " * 40 + "error"
    result = plugin._with_approval_note(
        original, plugin._HumanPollResult("approve", note), "call-A"
    )
    # Hermes versions differ in failure parsing; adding guidance must preserve
    # the actual host verdict, including success-shaped payloads with error text.
    failed = _detect_tool_failure("mcp_document", original)[0]
    assert _detect_tool_failure("mcp_document", result)[0] is failed
    data = json.loads(result)
    assert data["_meta"].pop("_intaris_approval")["user_note"] == note
    assert data["_meta"] == json.loads(original).get("_meta", {})
    assert data["result"].endswith("native output\n")
    assert "native output\n" in _pageable_text(result)


@pytest.mark.parametrize("kind", ["json", "text", "multimodal", "mcp"])
@pytest.mark.parametrize("budget_stage", ["result", "turn"])
def test_human_note_stays_visible_when_hermes_spills_large_output(
    runtime, host, scripted_http, persist_multimodal, kind, budget_stage
):
    from agent.tool_dispatch_helpers import make_tool_result_message
    from agent.vision_message_prep import VisionMessagePrepMixin
    from tools.budget_config import BudgetConfig
    from tools.tool_result_storage import (
        _pageable_text,
        enforce_turn_budget,
        maybe_persist_tool_result,
    )

    output = "native output\n" * 9000
    native = (
        json.dumps({"output": output, "exit_code": 0}) if kind == "json" else output
    )
    if kind == "mcp":
        native = json.dumps(
            {
                "result": output,
                "structuredContent": {"page": 1},
                "_meta": {"origin": "native", "_intaris_approval": "provider field"},
            }
        )
    if kind == "multimodal":
        native = {
            "_multimodal": True,
            "content": [
                {"type": "text", "text": "small header"},
                {"type": "text", "text": output},
                {
                    "type": "image_url",
                    "image_url": {"url": "data:image/png;base64,test"},
                },
            ],
            "text_summary": "native summary\n" * 9000,
        }
    budget = (
        BudgetConfig()
        if budget_stage == "result"
        else BudgetConfig(default_result_size=1_000_000, turn_budget=1000)
    )
    ctx = runtime.register("budget-notes")
    with runtime.profile("budget-notes") as home:
        Context(runtime.registry, home).register_tool(
            name="note_test", toolset="test", schema={}, handler=lambda args: native
        )
        ctx.emit("on_session_start", session_id="A")
        scripted_http(*replies(user_note=NOTE))
        result = ctx.execute("note_test", {}, session_id="A")
        if kind == "mcp":
            pageable = _pageable_text(result)
            assert output in pageable
            assert len(pageable.splitlines()) > 9000
            enriched = json.loads(result)
            assert enriched["result"].endswith(output)
            assert enriched["structuredContent"] == {"page": 1}
            assert enriched["_meta"]["origin"] == "native"
            assert enriched["_meta"]["_intaris_approval"] == "provider field"
        if kind == "multimodal":
            result = persist_multimodal(result, "note_test", "hermes-A", None, budget)
        else:
            result = maybe_persist_tool_result(
                result, "note_test", "hermes-A", config=budget
            )
        model = SimpleNamespace(
            provider="test",
            model="text-model",
            _content_has_image_parts=VisionMessagePrepMixin._content_has_image_parts,
            _model_supports_vision=lambda: False,
        )
        content = VisionMessagePrepMixin._tool_result_content_for_active_model(
            model, "note_test", result
        )
        messages = [make_tool_result_message("note_test", content, "hermes-A")]
        enforce_turn_budget(messages, config=budget)
    delivered = messages[0]["content"]
    assert "persisted-output" in delivered
    assert json.dumps(NOTE, ensure_ascii=False) in delivered
    assert "call-A" in delivered
    expected = (
        "native summary"
        if kind == "multimodal" and budget_stage == "turn"
        else "native output"
    )
    assert expected in delivered


def test_multimodal_note_keeps_short_summary_bounded(
    runtime, host, scripted_http, persist_multimodal
):
    from agent.tool_dispatch_helpers import make_tool_result_message
    from agent.vision_message_prep import VisionMessagePrepMixin
    from tools.budget_config import BudgetConfig
    from tools.tool_result_storage import enforce_turn_budget

    summary = "Bounded native summary."
    native = {
        "_multimodal": True,
        "content": [
            {"type": "text", "text": "x" * size}
            for size in (100_001, 60_000, 60_000, 60_000, 60_000)
        ]
        + [{"type": "image_url", "image_url": {"url": "data:image/png;base64,test"}}],
        "text_summary": summary,
    }
    budget = BudgetConfig()
    model = SimpleNamespace(
        provider="test",
        model="text-model",
        _content_has_image_parts=VisionMessagePrepMixin._content_has_image_parts,
        _model_supports_vision=lambda: False,
    )
    ctx = runtime.register("bounded-summary")
    with runtime.profile("bounded-summary") as home:
        Context(runtime.registry, home).register_tool(
            name="note_test", toolset="test", schema={}, handler=lambda args: native
        )
        ctx.emit("on_session_start", session_id="A")
        scripted_http(*replies(user_note=NOTE))
        result = ctx.execute("note_test", {}, session_id="A")
        result = persist_multimodal(result, "note_test", "hermes-A", None, budget)
        content = VisionMessagePrepMixin._tool_result_content_for_active_model(
            model, "note_test", result
        )
        messages = [make_tool_result_message("note_test", content, "hermes-A")]
        enforce_turn_budget(messages, config=budget)
    delivered = messages[0]["content"]
    assert len(delivered) < 1000
    assert delivered.endswith(summary)
    assert json.dumps(NOTE, ensure_ascii=False) in delivered
