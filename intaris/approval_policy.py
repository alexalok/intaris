"""Current deterministic policy checks for pending approval resolution."""

from __future__ import annotations

import os
from typing import Any

from intaris.classifier import (
    Classification,
    _check_deny_paths,
    _extract_bash_command,
    _extract_mcp_paths,
    classify,
    extract_apply_patch_paths,
    extract_paths,
    resolve_tool_paths,
)
from intaris.policy import policy_for_session


def effective_working_directory(
    tool: str,
    args: dict[str, Any],
    context: dict[str, Any] | None,
    session_details: dict[str, Any],
) -> str | None:
    """Resolve the directory that applies to this specific tool call."""

    context = context or {}
    executor_environment = context.get("executor_environment")
    executor_metadata_present = isinstance(executor_environment, dict)
    candidates = [
        context.get("working_directory"),
        (executor_environment.get("cwd") if executor_metadata_present else None),
    ]
    if not executor_metadata_present:
        candidates.append(session_details.get("working_directory"))
    base_directory = next(
        (
            os.path.normpath(value)
            for value in candidates
            if isinstance(value, str) and os.path.isabs(value)
        ),
        None,
    )
    if tool in {"bash", "terminal"}:
        tool_workdir = args.get("workdir")
        if isinstance(tool_workdir, str) and tool_workdir:
            if os.path.isabs(tool_workdir):
                return os.path.normpath(tool_workdir)
            if base_directory:
                return os.path.normpath(os.path.join(base_directory, tool_workdir))
    return base_directory


def validate_approval_policy(
    record: dict[str, Any], session: dict[str, Any], agent_policy: dict[str, Any] | None
) -> None:
    """Refuse grants that violate current hard rules or cannot be rechecked.

    Audit arguments are redacted and can be compacted. When a current rule
    depends on missing argument text, require a new evaluation; never infer
    that the hidden original could not match a prohibition.
    """
    policy = policy_for_session(session, agent_policy) or {}
    args = dict(record.get("args_redacted") or {})
    context = args.pop("__intaris_context", None)
    if isinstance(context, dict) and args.get("context") == context:
        args.pop("context", None)
    if not isinstance(context, dict):
        context = None
    tool = record.get("tool") or ""
    # This value is evaluator-owned and already includes tool workdir. Do not
    # apply a relative workdir twice or use mutable current session details.
    snapshot = "__intaris_evaluation_directory"
    if snapshot in (context or {}):
        directory = context[snapshot]
        if not isinstance(directory, str) or not os.path.isabs(directory):
            directory = None
    else:
        path_policy = (context or {}).get("path_policy")
        directory = (
            path_policy.get("working_directory")
            if isinstance(path_policy, dict)
            else None
        )
        if not isinstance(directory, str) or not os.path.isabs(directory):
            directory = effective_working_directory(tool, args, context, {})
    critical = classify(tool, args, session_policy=policy, working_directory=directory)
    paths = resolve_tool_paths(tool, args, directory or "")
    # Absolute deny targets remain checkable without executor cwd metadata.
    if critical == Classification.CRITICAL or _check_deny_paths(paths, policy):
        raise ValueError(
            "Hard prohibition cannot be approved; change the rule and evaluate again"
        )
    relevant_text = []
    if tool in {"bash", "terminal"} and policy.get("deny_commands"):
        relevant_text.append(_extract_bash_command(args))
    if policy.get("deny_paths"):
        relevant_text.extend(
            _extract_mcp_paths(args) if ":" in tool else extract_paths(args)
        )
        if tool in {"bash", "terminal"}:
            relevant_text.append(_extract_bash_command(args))
            relevant_text.append(args.get("workdir"))
        if tool == "apply_patch" and isinstance(args.get("patchText"), str):
            patch = args["patchText"]
            relevant_text.extend(extract_apply_patch_paths(patch))
            # Compaction can hide entire file headers. Redacted body contents
            # cannot, so ordinary secret-content patches remain reviewable.
            if (
                "<long string truncated for safety evaluation:" in patch
                or "<long string omitted for safety evaluation:" in patch
            ):
                relevant_text.append(patch)
        # Only directory metadata can affect target resolution. Redacted tool
        # output, file contents, tokens, and commentary are not path inputs.
        relevant_text.append(directory)
        if snapshot in (context or {}):
            relevant_text.append(context[snapshot])
        else:
            relevant_text.append((context or {}).get("working_directory"))
            env = (context or {}).get("executor_environment")
            if isinstance(env, dict):
                relevant_text.append(env.get("cwd"))
            policy_context = (context or {}).get("path_policy")
            if isinstance(policy_context, dict):
                relevant_text.append(policy_context.get("working_directory"))
    markers = (
        "[REDACTED:",
        "<long string truncated for safety evaluation:",
        "<long string omitted for safety evaluation:",
    )
    if any(
        isinstance(text, str) and any(marker in text for marker in markers)
        for text in relevant_text
    ):
        raise ValueError(
            "Current hard policy cannot be checked against incomplete audit arguments; "
            "evaluate the original call again"
        )
    if policy.get("deny_paths") and any(not os.path.isabs(path) for path in paths):
        raise ValueError(
            "Current path policy requires an executor working directory; evaluate again"
        )
