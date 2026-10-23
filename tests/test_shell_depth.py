"""Bound inspection without treating exhausted proof as permission or prohibition."""

import shlex

import pytest

from intaris.classifier import Classification, classify


def _nested(payload: str, levels: int, kind: str) -> str:
    for level in range(levels):
        if kind == "shell":
            payload = "sh -c " + shlex.quote(payload)
        elif kind == "runner":
            payload = "sudo " + payload
        elif kind == "substitution":
            payload = "echo $(" + payload + ")"
        else:
            payload = f"sh <<'DEPTH{level}'\n{payload}\nDEPTH{level}"
    return payload


@pytest.mark.parametrize("kind", ["shell", "heredoc"])
@pytest.mark.parametrize(
    "levels,leaf,expected",
    [
        (8, "echo safe", Classification.WRITE),
        (9, "echo safe", Classification.WRITE),
        (8, "rm -rf /", Classification.CRITICAL),
        (9, "rm -rf /", Classification.WRITE),
    ],
)
def test_executable_nesting_limit(kind, levels, leaf, expected):
    result = classify(
        "terminal",
        {"command": _nested(leaf, levels, kind)},
        session_policy={"allow_commands": ["*"]},
    )
    assert result == expected


@pytest.mark.parametrize("kind", ["shell", "runner", "substitution", "heredoc"])
def test_deep_quoted_examples_are_data(kind):
    command = "printf '%s' " + shlex.quote(_nested("rm -rf /", 10, kind))
    assert classify("terminal", {"command": command}) != Classification.CRITICAL


@pytest.mark.parametrize("kind", ["runner", "substitution"])
@pytest.mark.parametrize("leaf,blocked", [("echo safe", False), ("rm -rf /", True)])
def test_iteratively_inspected_prefixes_do_not_consume_recursion_limit(
    kind, leaf, blocked
):
    # Transparent prefixes and unquoted substitution segments are inspected
    # iteratively; their benign leaf is fully visible without recursive descent.
    result = classify(
        "terminal",
        {"command": _nested(leaf, 30, kind)},
        session_policy={"allow_commands": ["*"]},
    )
    assert (result == Classification.CRITICAL) is blocked
