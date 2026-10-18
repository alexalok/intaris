"""Opt-in exact Python script allowances for literal POSIX shell invocations."""

from __future__ import annotations

import posixpath
import shlex
from typing import Any


def is_literal_script_path(path: str) -> bool:
    """Require a normalized absolute POSIX path, without glob patterns."""
    return (
        path.startswith("/")
        and not path.startswith("//")
        and path != "/"
        and posixpath.normpath(path) == path
        and not any(char in path for char in "*?[]")
        and not any(ord(char) < 32 or ord(char) == 127 for char in path)
    )


def match_allowed_script(
    tool: str, args: dict[str, Any], policy: dict[str, Any] | None
) -> str | None:
    """Return the explicitly trusted script in a single literal invocation.

    This trusts the script, its arguments, imports and interpreter environment;
    it does not verify file contents or impose a filesystem sandbox.
    """
    if tool not in {"bash", "terminal"} or not policy:
        return None
    scripts = policy.get("allow_scripts")
    if not isinstance(scripts, list) or not scripts:
        return None
    command = args.get("command") or args.get("cmd")
    if not isinstance(command, str):
        return None
    words = _literal_shell_words(command)
    if len(words) < 2 or words[0] not in {"python", "python3"}:
        return None
    script = words[1]
    if is_literal_script_path(script) and script in scripts:
        return script
    return None


def _literal_shell_words(command: str) -> list[str]:
    """Parse quotes only after excluding shell operators and expansions.

    shlex alone removes quoting but does not identify executable substitutions.
    Reject unsupported syntax before tokenizing; quoted/escaped data is safe.
    """
    if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in command):
        return []
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            # shlex preserves these backslashes inside double quotes while a
            # POSIX shell removes them. Do not approve mismatched argv.
            if quote == '"' and char in "$`":
                return []
            escaped = False
            continue
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if char == "\\":
            escaped = True
        elif char in "$`":
            return []
        elif quote == '"':
            if char == '"':
                quote = None
        elif char in "'\"":
            quote = char
        elif char in ";&|<>()*?[]{}~#!":
            return []
    if escaped or quote is not None:
        return []
    try:
        return shlex.split(command, comments=False, posix=True)
    except ValueError:
        return []


def script_path_candidates(command: str) -> list[str]:
    """Keep intact literal operands when checking an allowed script's path denies.

    A generic script has no known argument schema, so every positional operand
    and attached option value is conservatively treated as a possible path.
    """
    candidates = []
    for word in _literal_shell_words(command)[1:]:
        if word.startswith("-"):
            _, separator, word = word.partition("=")
            if not separator:
                continue
        if word:
            candidates.append(word)
    return candidates
