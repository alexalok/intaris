"""Decision-model provider and input-boundary regression tests."""

from __future__ import annotations

import json

import httpx
import pytest

from intaris.config import Config, JevConfig, LLMConfig
from intaris.jev import DecisionInputTooLarge, JevClient


def _config(**overrides) -> JevConfig:
    settings = dict(
        enabled=True,
        model="cloudflare/clef",
        base_url="https://openrouter.ai/api",
        api_key="test-only-key",
        openrouter_providers=["deepinfra"],
        max_input_bytes=60000,
    )
    return JevConfig(**(settings | overrides))


def _reply(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    questions = body["questions"]
    answers = {}
    for name, question in questions.items():
        if question["type"] == "noul":
            answers[name] = {"type": "noul", "noul": 0.99}
        else:
            options = list(question["criteria"])
            probabilities = dict.fromkeys(options, 0.0)
            probabilities[options[0]] = 1.0
            answers[name] = {
                "type": "choice",
                "choice": options[0],
                "probabilities": probabilities,
                "confidence": 1.0,
            }
    return httpx.Response(
        200,
        json={
            "model": body["model"],
            "provider": "DeepInfra",
            "answers": answers,
            "usage": {"input_tokens": 100, "output_tokens": 0},
        },
    )


def test_clef_requests_pin_provider_for_tools_and_alignment() -> None:
    requests = []

    def respond(request):
        requests.append(json.loads(request.content))
        return _reply(request)

    client = JevClient(_config(), transport=httpx.MockTransport(respond))
    try:
        result = client.evaluate_tool_call(
            state={"tool": "write", "arguments": {"path": "README.md"}},
            evaluation_rules="Only authorized documentation edits.",
        )
        aligned, _ = client.check_alignment(
            parent_intention="Update docs",
            child_intention="Update README",
            evaluation_rules="Child must stay within parent scope.",
        )
    finally:
        client.close()
    assert result.decision == "approve"
    assert aligned
    assert len(requests) == 2
    for body in requests:
        assert body["model"] == "cloudflare/clef"
        assert body["provider"] == {"only": ["deepinfra"], "allow_fallbacks": False}


@pytest.mark.parametrize("operation", ["tool", "alignment"])
def test_oversized_input_requires_review_without_sending_request(operation) -> None:
    requests = []

    def respond(request):
        requests.append(request)
        return _reply(request)

    client = JevClient(
        _config(max_input_bytes=100), transport=httpx.MockTransport(respond)
    )
    try:
        if operation == "tool":
            result = client.evaluate_tool_call(
                state={"tool": "write", "arguments": {"content": "private" * 100}},
                evaluation_rules="Check scope.",
            )
            assert result.decision == "escalate"
            reason = result.reasoning
        else:
            aligned, reason = client.check_alignment(
                parent_intention="private" * 100,
                child_intention="Update docs",
                evaluation_rules="Check scope.",
            )
            assert not aligned
        assert "input" in reason.lower() and "limit" in reason.lower()
        assert "private" not in reason
        assert requests == []
    finally:
        client.close()


@pytest.mark.parametrize(
    "budget, state, expected",
    [
        (3000, {"content": "界" * 700}, "escalate"),
        (3000, {"content": "a" * 700}, "approve"),
        (100, {}, "escalate"),
    ],
)
def test_input_limit_counts_utf8_bytes_and_questions(budget, state, expected) -> None:
    requests = []

    def respond(request):
        requests.append(request)
        return _reply(request)

    client = JevClient(
        _config(max_input_bytes=budget), transport=httpx.MockTransport(respond)
    )
    try:
        result = client.evaluate_tool_call(
            state=state,
            evaluation_rules="",
        )
        assert result.decision == expected
        assert len(requests) == (1 if expected == "approve" else 0)
    finally:
        client.close()


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"openrouter_providers": []}, "JEV_OPENROUTER_PROVIDERS"),
        ({"max_input_bytes": 0}, "JEV_MAX_INPUT_BYTES"),
        ({"max_input_bytes": -1}, "JEV_MAX_INPUT_BYTES"),
        ({"base_url": "https://api.typesafe.ai"}, "OpenRouter"),
    ],
)
def test_clef_configuration_rejects_unbounded_or_unpinned_requests(
    overrides, match
) -> None:
    config = Config(llm=LLMConfig(api_key="test-key"), jev=_config(**overrides))
    with pytest.raises(ValueError, match=match):
        config.validate()


def test_clef_environment_loads_explicit_provider_and_budget(monkeypatch) -> None:
    monkeypatch.setenv("JEV_OPENROUTER_PROVIDERS", " deepinfra , primeintellect ")
    monkeypatch.setenv("JEV_MAX_INPUT_BYTES", "60000")
    config = JevConfig()
    assert getattr(config, "openrouter_providers", None) == [
        "deepinfra",
        "primeintellect",
    ]
    assert getattr(config, "max_input_bytes", None) == 60000


def test_input_limit_allows_exact_boundary() -> None:
    requests = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={})

    # {"state":{},"questions":{}} is 27 UTF-8 bytes, before routing metadata.
    client = JevClient(
        _config(max_input_bytes=27), transport=httpx.MockTransport(respond)
    )
    try:
        client._request(state={}, questions={})
        assert len(requests) == 1
        with pytest.raises(DecisionInputTooLarge):
            client._request(state={"x": ""}, questions={})
        assert len(requests) == 1
    finally:
        client.close()


def test_native_jev_keeps_original_transport_without_routing_fields() -> None:
    requests = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return _reply(request)

    client = JevClient(
        JevConfig(api_key="test-key", max_input_bytes=0, openrouter_providers=[]),
        transport=httpx.MockTransport(respond),
    )
    try:
        result = client.evaluate_tool_call(state={}, evaluation_rules="Allow.")
        assert result.decision == "approve"
        assert set(requests[0]) == {"state", "model", "questions"}
    finally:
        client.close()


def test_direct_clef_client_cannot_skip_transport_validation() -> None:
    with pytest.raises(ValueError, match="JEV_OPENROUTER_PROVIDERS"):
        JevClient(_config(openrouter_providers=[]))
