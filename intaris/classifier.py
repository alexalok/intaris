"""Tool call classifier for intaris.

Classifies tool calls into READ, WRITE, CRITICAL, or ESCALATE categories
using an explicit read-only allowlist, critical pattern detection,
optional per-tool preference overrides, and filesystem path policy.

Security model: default-deny. Everything not explicitly allowlisted
as read-only goes through LLM evaluation. Unknown tools, third-party
MCP tools, and unrecognized bash commands are all classified as WRITE.

Classification priority (deny always wins):
1.   Session policy deny (deny_tools, deny_commands) → CRITICAL
1.5. Session policy deny_paths (fnmatch on resolved paths) → CRITICAL
2.   Tool preference deny → CRITICAL
2.5. Critical command detection (bash/terminal) → CRITICAL
3.   Tool preference escalate → ESCALATE
4.   Session policy allow (allow_tools, allow_commands, allow_scripts) → READ
5.   Tool preference auto-approve → READ
7.   Built-in read-only allowlist → READ
7.5. Path outside project (not in allow_paths) → WRITE
8.   Default → WRITE
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import shlex
from enum import Enum
from typing import Any

from intaris.script_policy import match_allowed_script, script_path_candidates

logger = logging.getLogger(__name__)


class Classification(Enum):
    """Tool call classification result."""

    READ = "read"
    WRITE = "write"
    CRITICAL = "critical"
    ESCALATE = "escalate"


# ── Read-Only Allowlist ───────────────────────────────────────────────
# Conservative: only tools/commands that cannot modify state.

# Built-in tools that are always read-only.
_READ_ONLY_TOOLS: set[str] = {
    "read",
    "glob",
    "grep",
    "search",
    "find",
    "list",
    "get",
    "view",
    "show",
    "describe",
    "explain",
    "help",
    "info",
    "status",
    "whoami",
    "version",
    # Task management tools (metadata only, no side effects)
    "todoread",
    "todowrite",
}

# Bash commands that are read-only (no arguments needed for classification).
_READ_ONLY_BASH_COMMANDS: set[str] = {
    "ls",
    "cat",
    "head",
    "tail",
    "find",
    "tree",
    "wc",
    "grep",
    "rg",
    "fd",
    "pwd",
    "echo",
    "which",
    "type",
    "file",
    "stat",
    "du",
    "df",
    "env",
    "printenv",
    "uname",
    "hostname",
    "whoami",
    "id",
    "date",
    "uptime",
    "free",
    "ps",
    "top",
    "less",
    "more",
    "diff",
    "sort",
    "uniq",
    "cut",
    "tr",
    "awk",
    "sed",  # Note: sed is read-only only without -i flag
    "jq",
    "yq",
    "python",  # Classified as WRITE by default; see _is_read_only_bash
    "node",
}

# Git subcommands that are always read-only (no argument checks needed).
_READ_ONLY_GIT_SUBCOMMANDS: set[str] = {
    "status",
    "log",
    "diff",
    "show",
    "describe",
    "rev-parse",
    "rev-list",
    "ls-files",
    "ls-tree",
    "cat-file",
    "name-rev",
    "shortlog",
    "blame",
}

# Git subcommands that require argument-aware checks.
# These are handled in _is_git_subcommand_read_only().
_GIT_SUBCOMMANDS_WITH_CHECKS: set[str] = {
    "branch",
    "remote",
    "tag",
    "stash",
    "config",
}

# MCP tools that are read-only (from Mnemory and common MCP servers).
# For namespaced tools, the base tool name is matched after stripping
# the server prefix (colon or double-underscore conventions).
# The OpenCode single-underscore format (server_tool) is ambiguous,
# so known full names are listed explicitly.
_READ_ONLY_MCP_TOOLS: set[str] = {
    # Mnemory tools (agent memory infrastructure — not project-modifying)
    "initialize_memory",
    "add_memory",
    "add_memories",
    "search_memories",
    "find_memories",
    "ask_memories",
    "get_core_memories",
    "get_recent_memories",
    "list_memories",
    "list_categories",
    "update_memory",
    "delete_memory",
    "delete_memories",
    "delete_all_memories",
    "save_artifact",
    "get_artifact",
    "get_artifact_url",
    "list_artifacts",
    "delete_artifact",
    # Thinking / reasoning tools (no side effects)
    "sequentialthinking",
    "sequentialthinking_sequentialthinking",  # OpenCode: server_tool format
}

# ── Path Policy ───────────────────────────────────────────────────────
# Filesystem path awareness for tool call classification.

# Known argument keys that contain file paths.
PATH_ARG_KEYS: tuple[str, ...] = (
    "filePath",
    "file_path",
    "path",
    "directory",
    "dir",
    "folder",
    "filename",
    "canonicalPath",
    "canonical_path",
    "realPath",
    "real_path",
    "resolvedPath",
    "resolved_path",
)

# Regex to extract absolute paths from bash command strings.
# Matches sequences starting with / followed by path characters.
# Intentionally simple — catches obvious cases like "cat /etc/shadow"
# without trying to handle all shell constructs.
_BASH_ABSOLUTE_PATH_RE = re.compile(r"(?<![a-zA-Z0-9_:])(/[a-zA-Z0-9_./-]+)")

# Read-only shell commands whose non-option operands commonly name files.
# Commands such as ``echo`` are excluded because filename-like tokens are data.
_BASH_FILE_OPERAND_COMMANDS: set[str] = {
    "awk",
    "cat",
    "cut",
    "diff",
    "du",
    "file",
    "grep",
    "head",
    "less",
    "ls",
    "more",
    "rg",
    "sort",
    "stat",
    "sed",
    "tail",
    "tree",
    "uniq",
    "wc",
}

_BASH_COMMAND_WRAPPERS: set[str] = {
    "command",
    "env",
    "time",
}

_SENSITIVE_LITERAL_BASENAMES: set[str] = {
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "id_rsa",
    "id_ed25519",
}

_BENIGN_TEMPLATE_BASENAMES: set[str] = {
    ".env.example",
    ".env.sample",
    ".env.template",
}

_SENSITIVE_BASENAME_GLOBS: tuple[str, ...] = (
    ".env",
    ".env*",
    ".env.*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "id_rsa",
    "id_ed25519",
    "*.key",
    "*private*.pem",
    "*privkey*.pem",
    "*-key.pem",
    "*_key.pem",
    "*.key.pem",
)

_SENSITIVE_SUFFIXES: tuple[str, ...] = (".key",)

_ENV_OPTIONS_WITH_SEPARATE_VALUES: set[str] = {
    "-u",
    "--unset",
    "-C",
    "--chdir",
    "-a",
    "--argv0",
}

_ENV_OPTIONS_WITH_ATTACHED_VALUES: tuple[str, ...] = (
    "-u",
    "-C",
    "-a",
    "--unset=",
    "--chdir=",
    "--argv0=",
)

# apply_patch envelope headers that introduce filesystem targets.
_APPLY_PATCH_PATH_RE = re.compile(
    r"^\*\*\* (?:Add|Update|Delete) File: (?P<path>.+)$", re.MULTILINE
)
_APPLY_PATCH_MOVE_RE = re.compile(r"^\*\*\* Move to: (?P<path>.+)$", re.MULTILINE)
_UNIFIED_DIFF_PATH_RE = re.compile(r"^(?:---|\+\+\+) (?P<path>.+)$", re.MULTILINE)


def extract_paths(args: dict[str, Any]) -> list[str]:
    """Extract file paths from tool arguments.

    Scans known argument keys for string values that look like file paths.

    Args:
        args: Tool arguments dict.

    Returns:
        List of path strings found in args (may be empty).
    """
    paths: list[str] = []
    for key in PATH_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val:
            paths.append(val)
    return paths


def _extract_mcp_paths(args: dict[str, Any]) -> list[str]:
    """Include nested and multi-path arguments in generic MCP path policy."""
    keys = (
        set(PATH_ARG_KEYS)
        | {f"{key}s" for key in PATH_ARG_KEYS}
        | {
            "directories",
            "files",
        }
    )
    paths: list[str] = []
    pending: list[Any] = [args]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if key in keys:
                    if isinstance(child, str) and child:
                        paths.append(child)
                    elif isinstance(child, list):
                        paths.extend(
                            item for item in child if isinstance(item, str) and item
                        )
                if isinstance(child, (dict, list)):
                    pending.append(child)
        elif isinstance(value, list):
            pending.extend(item for item in value if isinstance(item, (dict, list)))
    return paths


def extract_apply_patch_paths(patch_text: str) -> list[str]:
    """Extract target paths from apply_patch input.

    Parses only structural patch headers, not arbitrary diff body content. For
    move/rename and unified diff patches, both old and new paths are targets.
    """
    paths: list[str] = []
    for match in _APPLY_PATCH_PATH_RE.finditer(patch_text):
        path = match.group("path").strip()
        if path:
            paths.append(path)
    for match in _APPLY_PATCH_MOVE_RE.finditer(patch_text):
        path = match.group("path").strip()
        if path:
            paths.append(path)
    for match in _UNIFIED_DIFF_PATH_RE.finditer(patch_text):
        path = _normalize_unified_diff_path(match.group("path"))
        if path and path not in paths:
            paths.append(path)
    return paths


def _normalize_unified_diff_path(path_header: str) -> str | None:
    """Normalize a unified diff ---/+++ path header."""
    path = path_header.strip().split("\t", 1)[0].strip()
    if not path or path == "/dev/null":
        return None
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def extract_bash_paths(command: str) -> list[str]:
    """Extract absolute shell paths, preserving quoted filesystem operands.

    Known file commands use operand-aware tokenization; quoted search patterns
    and literal output are not paths. This does not expand shell syntax.
    """
    return _extract_bash_file_paths(command, include_relative=False)


def _is_sensitive_path(path: str) -> bool:
    """Return whether a path conventionally contains project secrets."""
    normalized = path.replace("\\", "/").rstrip("/").lower()
    basename = normalized.rsplit("/", 1)[-1]
    if any(char in basename for char in "*?["):
        if any(
            fnmatch.fnmatchcase(literal, basename)
            for literal in _SENSITIVE_LITERAL_BASENAMES
        ):
            return True
        return any(
            fnmatch.fnmatchcase(basename, pattern)
            for pattern in _SENSITIVE_BASENAME_GLOBS
        )
    if _is_benign_env_template(basename):
        return False
    return (
        basename in _SENSITIVE_LITERAL_BASENAMES
        or (basename.startswith(".env.") and not _is_benign_env_template(basename))
        or basename.endswith(_SENSITIVE_SUFFIXES)
        or (
            basename.endswith(".pem")
            and (
                "private" in basename
                or "privkey" in basename
                or basename.endswith(("-key.pem", "_key.pem", ".key.pem"))
            )
        )
        or normalized == "config/database.yml"
        or normalized.endswith("/config/database.yml")
    )


def _is_benign_env_template(basename: str) -> bool:
    """Return True for committed env templates that should stay cheap reads."""
    return basename in _BENIGN_TEMPLATE_BASENAMES or basename.endswith(
        (".example", ".sample", ".template")
    )


def extract_sensitive_bash_paths(command: str) -> list[str]:
    """Extract sensitive relative or absolute file operands from shell text."""
    return [
        path for path in _extract_bash_file_paths(command) if _is_sensitive_path(path)
    ]


def _extract_bash_file_paths(
    command: str, *, include_relative: bool = True
) -> list[str]:
    """Extract literal operands without discarding quotes or expanding shell text."""
    paths: list[str] = []
    for segment in re.split(r"\|\||&&|[|;&]", command):
        # Keep existing unquoted-path coverage, including unknown option forms.
        paths.extend(_BASH_ABSOLUTE_PATH_RE.findall(_strip_quoted_strings(segment)))
        try:
            tokens = _unwrap_read_command(shlex.split(segment))
        except ValueError:
            tokens = []
        if tokens and tokens[0] in _BASH_FILE_OPERAND_COMMANDS:
            paths.extend(
                path
                for path in _file_operands_for_command(tokens)
                if path and (include_relative or os.path.isabs(path))
            )
        elif tokens and tokens[0] not in {"echo", "printf", "tr", "date"}:
            # Other path-looking arguments are conservative targets; literal
            # output operands are data, not files.
            paths.extend(
                token
                for token in tokens[1:]
                if os.path.isabs(token)
                or (include_relative and token.startswith(("./", "../")))
            )
    return list(dict.fromkeys(paths))


def _unwrap_read_command(tokens: list[str]) -> list[str]:
    """Remove harmless command wrappers before path-sensitive inspection."""
    remaining = list(tokens)
    while remaining and remaining[0] in _BASH_COMMAND_WRAPPERS:
        wrapper = remaining.pop(0)
        if wrapper == "env":
            while remaining:
                token = remaining[0]
                if token == "--":
                    remaining.pop(0)
                    break
                if token in {"-S", "--split-string"}:
                    remaining.pop(0)
                    if remaining:
                        split_value = remaining.pop(0)
                        remaining = _split_env_split_string(split_value) + remaining
                    continue
                if token.startswith("--split-string="):
                    split_value = token.split("=", 1)[1]
                    remaining.pop(0)
                    remaining = _split_env_split_string(split_value) + remaining
                    continue
                if token.startswith("-S") and token != "-S":
                    split_value = token[2:]
                    remaining.pop(0)
                    remaining = _split_env_split_string(split_value) + remaining
                    continue
                if token in _ENV_OPTIONS_WITH_SEPARATE_VALUES:
                    remaining.pop(0)
                    if remaining:
                        remaining.pop(0)
                    continue
                if any(
                    token.startswith(prefix) and token != prefix
                    for prefix in _ENV_OPTIONS_WITH_ATTACHED_VALUES
                ):
                    remaining.pop(0)
                    continue
                if token.startswith("-"):
                    remaining.pop(0)
                    continue
                if _looks_like_env_assignment(token):
                    remaining.pop(0)
                    continue
                break
    return remaining


def _split_env_split_string(value: str) -> list[str]:
    """Parse GNU env -S/--split-string command text into shell tokens."""
    try:
        return shlex.split(value)
    except ValueError:
        return []


def _looks_like_env_assignment(token: str) -> bool:
    """Return True for VAR=value prefixes used before env-wrapped commands."""
    if "=" not in token:
        return False
    name, _ = token.split("=", 1)
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))


def _file_operands_for_command(tokens: list[str]) -> list[str]:
    """Return likely filesystem operands for read-only shell commands."""
    command = tokens[0]
    args = tokens[1:]
    if command in {"grep", "rg"}:
        return _parse_search_arguments(command, args)[0]
    if command == "sed":
        return _sed_file_operands(args)
    if command == "awk":
        return _awk_file_operands(args)
    return _generic_file_operands(command, args)


def _generic_file_operands(command: str, args: list[str]) -> list[str]:
    """Return file operands, skipping only command-specific data option values."""
    # A flag such as cat -n or ls -d takes no value: never discard its file.
    value_options = {
        "cut": {
            "-b",
            "-c",
            "-d",
            "-f",
            "--bytes",
            "--characters",
            "--delimiter",
            "--fields",
            "--output-delimiter",
        },
        "head": {"-n", "-c", "--lines", "--bytes"},
        "tail": {"-n", "-c", "--lines", "--bytes"},
        "diff": {"--label", "-L"},
        "du": {"-d", "--max-depth"},
        "stat": {"-c", "--format", "--printf"},
    }.get(command, set())
    operands: list[str] = []
    skip_next = False
    for index, token in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if token == "--":
            operands.extend(arg for arg in args[index + 1 :] if arg)
            break
        if token.startswith("-"):
            if command == "stat" and not token.startswith("--"):
                # -c consumes the cluster's remainder or the next argument.
                # Flags such as -L/-f/-t do not consume file operands.
                for offset, flag in enumerate(token[1:], start=2):
                    if flag == "c":
                        skip_next = offset == len(token)
                        break
                continue
            if token in value_options:
                skip_next = True
            option, separator, value = token.partition("=")
            if (
                separator
                and option not in value_options
                and value.startswith(("/", "./", "../"))
            ):
                operands.append(value)
            continue
        operands.append(token)
    return operands


# Bounded GNU grep roles: unknown spellings are evaluated, not inferred from
# arbitrary prefixes. Optional color values are attached-only under getopt_long.
_GREP_LONG_OPTION_ROLES: dict[str, str] = {
    "--regexp": "pattern",
    "--file": "file",
    "--exclude-from": "auxiliary_file",
    **dict.fromkeys(
        (
            "--after-context",
            "--before-context",
            "--context",
            "--max-count",
            "--binary-files",
            "--devices",
            "--directories",
            "--exclude",
            "--exclude-dir",
            "--include",
            "--label",
            "--group-separator",
        ),
        "option",
    ),
    **dict.fromkeys(("--color", "--colour"), "optional"),
    **dict.fromkeys(
        (
            "--basic-regexp",
            "--extended-regexp",
            "--fixed-regexp",
            "--fixed-strings",
            "--perl-regexp",
            "--byte-offset",
            "--count",
            "--files-with-matches",
            "--files-without-match",
            "--help",
            "--ignore-case",
            "--no-ignore-case",
            "--initial-tab",
            "--line-buffered",
            "--line-number",
            "--line-regexp",
            "--no-filename",
            "--no-group-separator",
            "--no-messages",
            "--null",
            "--null-data",
            "--only-matching",
            "--quiet",
            "--recursive",
            "--dereference-recursive",
            "--invert-match",
            "--silent",
            "--text",
            "--binary",
            "--version",
            "--with-filename",
            "--word-regexp",
        ),
        "flag",
    ),
}


def _parse_search_arguments(command: str, args: list[str]) -> tuple[list[str], bool]:
    """Return file operands and whether GNU grep long-option parsing is uncertain."""
    # Keep the positional slot for a lone "-" until pattern inference. Neither
    # that pattern nor stdin is a filesystem path, so represent it with None.
    operands: list[str | None] = []
    first_positional: int | None = None
    pattern_seen = False
    patternless = False
    pending_value: str | None = None
    short_values = {"f": "file", "e": "pattern"}
    short_values.update(dict.fromkeys("mABC", "option"))
    short_values.update(dict.fromkeys("gtrTjEM" if command == "rg" else "dD", "option"))
    unknown_options = False
    for index, token in enumerate(args):
        if pending_value is not None:
            if pending_value in {"file", "auxiliary_file"}:
                is_stdin = token == "-" and (
                    pending_value == "file" or command == "grep"
                )
                operands.append(None if is_stdin else token)
            if pending_value in {"file", "pattern"}:
                pattern_seen = True
            pending_value = None
            continue
        if token == "--":
            remaining = args[index + 1 :]
            if first_positional is None and remaining:
                first_positional = len(operands)
            operands.extend(None if arg == "-" else arg for arg in remaining)
            break
        option, separator, value = token.partition("=")
        if command == "grep" and token.startswith("--"):
            role = _GREP_LONG_OPTION_ROLES.get(option)
            if option.startswith("--exclude-f") and "--exclude-from".startswith(option):
                role = "auxiliary_file"
            if role is None or (role == "flag" and separator):
                unknown_options = True
            elif role == "flag" or (role == "optional" and not separator):
                pass
            elif separator:
                if role in {"file", "auxiliary_file"}:
                    operands.append(None if value == "-" else value)
                if role in {"file", "pattern"}:
                    pattern_seen = True
            else:
                pending_value = role
            continue
        # Remaining long-option handling is for ripgrep.
        if command == "rg" and token in {"--files", "--type-list"}:
            patternless = True
            continue
        if option == "--ignore-file":
            if separator:
                operands.append(value)
            else:
                pending_value = "auxiliary_file"
            continue
        if token == "--file":
            pending_value = "file"
            continue
        if token.startswith("--file="):
            operands.append(None if value == "-" else value)
            pattern_seen = True
            continue
        if token == "--regexp":
            pending_value = "pattern"
            continue
        if token.startswith("--regexp="):
            pattern_seen = True
            continue
        if token in {
            "--exclude",
            "--include",
            "--exclude-dir",
            "--include-dir",
            "--label",
            "--binary-files",
            "--devices",
            "--directories",
        }:
            pending_value = "option"
            continue
        if command == "rg" and token in {
            "--glob",
            "--iglob",
            "--type",
            "--type-not",
            "--type-add",
            "--type-clear",
            "--encoding",
            "--threads",
            "--max-columns",
            "--replace",
            "--sort",
            "--sortr",
            "--path-separator",
            "--max-depth",
            "--max-filesize",
        }:
            pending_value = "option"
            continue
        if token != "-" and token.startswith("-") and not token.startswith("--"):
            # In a short-option cluster, the first value-taking option consumes
            # the remainder (or the next token): -nf PATH and -nfPATH both read PATH.
            for offset, option in enumerate(token[1:], start=2):
                kind = short_values.get(option)
                if kind is None:
                    continue
                value = token[offset:]
                if not value:
                    pending_value = kind
                else:
                    if kind == "file":
                        operands.append(None if value == "-" else value)
                    if kind in {"file", "pattern"}:
                        pattern_seen = True
                break
            continue
        if token.startswith("--"):
            continue
        if first_positional is None:
            first_positional = len(operands)
        operands.append(None if token == "-" else token)
    if command == "grep" and pending_value is not None:
        unknown_options = True
    if unknown_options:
        # Unknown roles invalidate positional-pattern inference, even when the
        # unknown option appears last. Retain all literals and attached values
        # as possible paths, including values otherwise parsed as pattern/data.
        operands.extend(arg for arg in args if arg != "--")
        operands.extend(
            arg.partition("=")[2] for arg in args if arg.startswith("--") and "=" in arg
        )
    elif not pattern_seen and not patternless and first_positional is not None:
        # -e/-f may appear after positional operands. Infer a positional pattern
        # only after all known options have been considered.
        del operands[first_positional]
    return list(
        dict.fromkeys(arg for arg in operands if arg is not None)
    ), unknown_options


def _sed_file_operands(args: list[str]) -> list[str]:
    """Return sed input file operands while skipping scripts and options."""
    operands: list[str] = []
    script_seen = False
    pending_value: str | None = None
    for index, token in enumerate(args):
        if pending_value is not None:
            if pending_value == "file":
                operands.append(token)
            script_seen = True
            pending_value = None
            continue
        if token == "--":
            remaining = args[index + 1 :]
            if not script_seen and remaining:
                remaining = remaining[1:]
            operands.extend(arg for arg in remaining if arg)
            break
        if token in {"-f", "--file"}:
            pending_value = "file"
            continue
        attached_file = _attached_option_value(token, "-f", "--file")
        if attached_file is not None:
            if attached_file:
                operands.append(attached_file)
                script_seen = True
            continue
        if token in {"-e", "--expression"}:
            pending_value = "script"
            continue
        if _attached_option_value(token, "-e", "--expression") is not None:
            script_seen = True
            continue
        if token.startswith("-"):
            continue
        if not script_seen:
            script_seen = True
            continue
        operands.append(token)
    return operands


def _awk_file_operands(args: list[str]) -> list[str]:
    """Return awk file operands while skipping the program and option values."""
    operands: list[str] = []
    program_seen = False
    pending_value: str | None = None
    for index, token in enumerate(args):
        if pending_value is not None:
            if pending_value == "file":
                operands.append(token)
                program_seen = True
            pending_value = None
            continue
        if token == "--":
            remaining = args[index + 1 :]
            if not program_seen and remaining:
                remaining = remaining[1:]
            operands.extend(arg for arg in remaining if arg)
            break
        if token == "-f":
            pending_value = "file"
            continue
        attached_file = _attached_option_value(token, "-f")
        if attached_file is not None:
            if attached_file:
                operands.append(attached_file)
                program_seen = True
            continue
        if token == "-v":
            pending_value = "var"
            continue
        if token.startswith("-"):
            continue
        if not program_seen:
            program_seen = True
            continue
        if _looks_like_env_assignment(token):
            continue
        operands.append(token)
    return operands


def _attached_option_value(
    token: str,
    short_option: str,
    long_option: str | None = None,
) -> str | None:
    """Return an attached option value such as ``-f.env`` or ``--file=.env``."""
    if long_option and token.startswith(f"{long_option}="):
        return token.split("=", 1)[1]
    if token.startswith(short_option) and token != short_option:
        return token[len(short_option) :]
    return None


def resolve_path(path: str, working_directory: str) -> str:
    """Resolve a file path against a working directory.

    Absolute paths are normalized in place. Relative paths are joined
    with the working directory first. Uses ``os.path.normpath`` to
    collapse ``..`` components (prevents traversal bypasses).

    Note: does NOT resolve symlinks (would require filesystem access).

    Args:
        path: File path (absolute or relative).
        working_directory: Session's working directory.

    Returns:
        Normalized absolute path string.
    """
    if os.path.isabs(path):
        return os.path.normpath(path)
    return os.path.normpath(os.path.join(working_directory, path))


def is_path_within(resolved_path: str, directory: str) -> bool:
    """Check if a resolved path is within a directory.

    Both paths should already be normalized (via ``os.path.normpath``).
    Uses string prefix matching with a trailing separator to avoid
    false positives (e.g., ``/home/user2`` is not within ``/home/user``).

    Args:
        resolved_path: Normalized absolute path.
        directory: Normalized absolute directory path.

    Returns:
        True if resolved_path is within or equal to directory.
    """
    norm_dir = os.path.normpath(directory)
    norm_path = os.path.normpath(resolved_path)
    # Exact match (path IS the directory)
    if norm_path == norm_dir:
        return True
    # Prefix match with separator
    return norm_path.startswith(norm_dir + os.sep)


def _check_deny_paths(
    resolved_paths: list[str],
    policy: dict[str, Any],
) -> bool:
    """Check if any resolved path matches deny_paths patterns.

    Args:
        resolved_paths: List of normalized absolute paths.
        policy: Session policy dict.

    Returns:
        True if any path matches a deny_paths pattern.
    """
    deny_paths = policy.get("deny_paths", [])
    if not deny_paths:
        return False

    for rp in resolved_paths:
        for pattern in deny_paths:
            if isinstance(pattern, str) and fnmatch.fnmatch(rp, pattern):
                return True
    return False


def _check_allow_paths(
    resolved_paths: list[str],
    policy: dict[str, Any],
) -> bool:
    """Check if ALL resolved paths match allow_paths patterns.

    Args:
        resolved_paths: List of normalized absolute paths.
        policy: Session policy dict.

    Returns:
        True if every path matches at least one allow_paths pattern.
    """
    allow_paths = policy.get("allow_paths", [])
    if not allow_paths:
        return False

    for rp in resolved_paths:
        matched = False
        for pattern in allow_paths:
            if isinstance(pattern, str) and fnmatch.fnmatch(rp, pattern):
                matched = True
                break
        if not matched:
            return False
    return True


def _check_path_policy(
    resolved_paths: list[str],
    working_directory: str,
    policy: dict[str, Any],
) -> Classification | None:
    """Check resolved paths against path policy and project boundary.

    Priority:
    1. deny_paths match → CRITICAL
    2. allow_paths match (all paths) → None (no override)
    3. Any path outside working_directory → WRITE
    4. All paths within project → None (no override)

    Args:
        resolved_paths: List of normalized absolute paths.
        working_directory: Session's working directory.
        policy: Session policy dict (may contain allow_paths, deny_paths).

    Returns:
        Classification override, or None if no policy applies.
    """
    if not resolved_paths:
        return None

    # 1. deny_paths always wins
    if _check_deny_paths(resolved_paths, policy):
        return Classification.CRITICAL

    # Secret-bearing paths still require evaluator review, even when they are
    # inside the project or covered by an allow_paths boundary.
    if any(_is_sensitive_path(path) for path in resolved_paths):
        return Classification.WRITE

    # 2. allow_paths exempts from out-of-project override
    if _check_allow_paths(resolved_paths, policy):
        return None

    # 3. Check if any path is outside the project
    for rp in resolved_paths:
        if not is_path_within(rp, working_directory):
            return Classification.WRITE

    # 4. All paths within project
    return None


def classify(
    tool: str,
    args: dict[str, Any],
    *,
    session_policy: dict[str, Any] | None = None,
    tool_preferences: dict[str, str] | None = None,
    working_directory: str | None = None,
    trusted_readonly: bool = False,
) -> Classification:
    """Classify a tool call as READ, WRITE, CRITICAL, or ESCALATE.

    Classification priority (deny always wins):
    1.   Session policy deny (deny_tools, deny_commands) → CRITICAL
    1.5. Session policy deny_paths (fnmatch on resolved paths) → CRITICAL
    2.   Tool preference deny → CRITICAL
    2.5. Critical command detection (bash/terminal) → CRITICAL
    3.   Tool preference escalate → ESCALATE
    4.   Session policy allow (allow_tools, allow_commands, allow_scripts) → READ
    5.   Tool preference auto-approve → READ
    7.   Built-in read-only allowlist or trusted MCP metadata → READ
    7.5. Path outside project (not in allow_paths) → WRITE
    8.   Default → WRITE (goes to LLM evaluation)

    Args:
        tool: Tool name (e.g., "bash", "edit", "read", "mcp:add_memory").
        args: Tool arguments.
        session_policy: Optional per-session policy with custom rules.
        tool_preferences: Optional per-tool preference overrides mapping
            'server:tool' or 'tool' → preference string.
        working_directory: Optional session working directory for path
            policy enforcement. When set, file paths in tool args are
            resolved against this directory and checked against path
            policy (deny_paths, allow_paths) and project boundary.
        trusted_readonly: Internal proxy evidence from the exact upstream
            connection, not a caller-provided claim. Explicit evaluate
            preferences disable this shortcut. Native tools are excluded.

    Returns:
        Classification enum value.
    """
    if tool == "skill_view_raw":
        return _classify_raw_skill_read(args, session_policy, tool_preferences)

    metadata_readonly = trusted_readonly is True and ":" in tool
    allowed_script = match_allowed_script(tool, args, session_policy)
    script_paths_known = True

    # Step 1: Session policy deny rules (highest priority deny)
    if session_policy:
        deny_override = _check_session_policy_deny(tool, args, session_policy)
        if deny_override is not None:
            return deny_override

    # Step 1.5: Session policy deny_paths (resolved path matching)
    if (working_directory or metadata_readonly or allowed_script) and session_policy:
        resolved = resolve_tool_paths(tool, args, working_directory or "")
        if allowed_script:
            # The generic shell extractor splits at raw delimiters, including
            # quoted ones. Use intact literal argv for this narrower fast path.
            candidates, options_known = script_path_candidates(
                _extract_bash_command(args)
            )
            resolved.extend(
                resolve_path(path, working_directory or "")
                for path in candidates
                if working_directory or os.path.isabs(path)
            )
            if session_policy.get("deny_paths"):
                script_paths_known = (
                    options_known
                    and all(
                        not path.startswith(("//", "~"))
                        and (working_directory or os.path.isabs(path))
                        for path in candidates
                    )
                    and all(
                        # Relative operands can inherit a double-leading slash
                        # from cwd, so validate resolved paths as well as argv.
                        os.path.isabs(path) and not path.startswith("//")
                        for path in resolved
                    )
                )
        if resolved and _check_deny_paths(resolved, session_policy):
            return Classification.CRITICAL

    # Step 2: Tool preference deny
    pref = _get_tool_preference(tool, tool_preferences)
    if pref == "deny":
        return Classification.CRITICAL

    # Hard prohibitions precede every allow/escalation shortcut.
    if tool in {"bash", "terminal"}:
        command = _extract_bash_command(args)
        if command and _is_critical(command):
            return Classification.CRITICAL

    # Step 3: Tool preference escalate
    if pref == "escalate":
        return Classification.ESCALATE

    # Step 4: Session policy allow rules
    if session_policy:
        allow_override = _check_session_policy_allow(
            tool, args, session_policy, script_paths_known=script_paths_known
        )
        if allow_override is not None:
            return allow_override

    # Step 5: Tool preference auto-approve
    if pref == "auto-approve":
        return Classification.READ

    # Step 7: Check read-only allowlist
    if is_read_only(tool, args) or (metadata_readonly and pref != "evaluate"):
        if metadata_readonly and any(
            not os.path.isabs(path) for path in _extract_mcp_paths(args)
        ):
            # MCP tools can resolve relative paths against an upstream cwd or
            # logical root unrelated to the agent's session directory. A
            # readonly hint does not establish that execution context.
            return Classification.WRITE
        # Step 7.5: Path policy check for read-only tools.
        # If the tool would be READ but targets paths outside the project
        # directory, reclassify as WRITE to force LLM evaluation.
        if working_directory or metadata_readonly:
            resolved = resolve_tool_paths(tool, args, working_directory or "")
            if resolved:
                path_override = _check_path_policy(
                    resolved, working_directory or "", session_policy or {}
                )
                if path_override is not None:
                    return path_override
        return Classification.READ

    # Step 8: Default to WRITE (goes to LLM evaluation)
    return Classification.WRITE


def _classify_raw_skill_read(
    args: dict[str, Any],
    policy: dict[str, Any] | None,
    preferences: dict[str, str] | None,
) -> Classification:
    """Classify the adapter's raw reader, preserving model-facing tool rules.

    Native skill_view remains WRITE: Hermes' loader may execute shell, install
    dependencies, or expose credentials. Only the adapter-owned raw operation
    carries this identity, with its resolved absolute target. Keep it out of
    is_read_only() so the path approval cache cannot bypass review preferences.
    """
    policy = policy or {}
    names = ("skill_view_raw", "skill_view")
    if any(_check_session_policy_deny(name, args, policy) for name in names):
        return Classification.CRITICAL
    prefs = {_get_tool_preference(name, preferences) for name in names}
    if "deny" in prefs:
        return Classification.CRITICAL
    path = args.get("path")
    known = isinstance(path, str) and os.path.isabs(path) and not path.startswith("//")
    if known:
        path = resolve_path(path, "")
        if _check_deny_paths([path], policy):
            return Classification.CRITICAL
    if "escalate" in prefs:
        return Classification.ESCALATE
    # Raw inspection is allowed by default in model policy, regardless of the
    # skill's topic. Current user/parent restrictions (including the initial
    # intention) still need interpretation. Generated facts cannot prove their
    # absence and must not become a deterministic grant.
    return Classification.WRITE


def resolve_tool_paths(
    tool: str, args: dict[str, Any], working_directory: str
) -> list[str]:
    """Extract and resolve file paths from tool arguments.

    For structured tools (Read, Edit, etc.), extracts paths from known
    argument keys. For shell commands, also extracts literal filesystem
    operands from the command string.

    Args:
        tool: Tool name.
        args: Tool arguments.
        working_directory: Session's working directory for resolution.

    Returns:
        List of resolved (normalized absolute) paths.
    """
    raw_paths = _extract_mcp_paths(args) if ":" in tool else extract_paths(args)

    # apply_patch stores target paths inside the patch envelope rather than
    # in a conventional file_path/path argument.
    if tool == "apply_patch":
        patch_text = args.get("patchText")
        if isinstance(patch_text, str) and patch_text:
            raw_paths.extend(extract_apply_patch_paths(patch_text))

    # Shell file operands retain quotes, spaces, and relative path components.
    if tool in {"bash", "terminal"}:
        command = _extract_bash_command(args)
        if command:
            raw_paths.extend(_extract_bash_file_paths(command))

    if not raw_paths:
        return []

    return [resolve_path(p, working_directory) for p in raw_paths]


def _get_tool_preference(tool: str, preferences: dict[str, str] | None) -> str | None:
    """Look up tool preference with fallback.

    Tries exact match first (e.g., 'server:tool'), then just the
    tool name part after the colon.
    """
    if not preferences:
        return None

    # Exact match (e.g., "tavily:search")
    if tool in preferences:
        return preferences[tool]

    # Fallback: just the tool name after colon (e.g., "search")
    if ":" in tool:
        tool_name = tool.split(":", 1)[1]
        if tool_name in preferences:
            return preferences[tool_name]

    return None


def _extract_bash_command(args: dict[str, Any]) -> str:
    """Extract the command string from bash tool args."""
    # OpenCode/Claude Code use "command" key
    command = args.get("command", "")
    if not command:
        # Some tools use "cmd" key
        command = args.get("cmd", "")
    return str(command).strip()


# Regex to match single-quoted or double-quoted strings.
# Handles escaped quotes inside double-quoted strings (\").
# Single-quoted strings have no escape mechanism in bash.
_QUOTED_STRING_RE = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*\"""")


def _strip_quoted_strings(command: str) -> str:
    """Remove quoted string content from a command.

    Replaces single-quoted and double-quoted strings with empty
    placeholders to prevent their content from triggering pattern
    matches. Used before critical pattern detection to avoid false
    positives from keywords appearing in arguments (e.g., "shutdown"
    in a git commit message).
    """
    return _QUOTED_STRING_RE.sub('""', command)


def _is_critical(command: str, _depth: int = 0) -> bool:
    """Recognize prohibited execution, preserving quoted operands and prose.

    This is a bounded literal shell recognizer, not a shell interpreter.
    Dynamic/unknown commands still take the ordinary WRITE evaluation path.
    """
    if _depth > 8:
        return False
    raw_segments, heredocs = _shell_segments(command)
    executable_text = "".join(raw + separator for raw, separator in raw_segments)
    if re.search(
        r":\(\)\s*\{\s*:\|:&\s*\}\s*;", _strip_quoted_strings(executable_text)
    ):
        # The fork-bomb form is shell syntax rather than an external command.
        return True
    for body, expands, executes in heredocs:
        nested_commands = (
            [body]
            if executes
            else _shell_substitutions(body, literal_quotes=True)
            if expands
            else []
        )
        if any(_is_critical(nested, _depth + 1) for nested in nested_commands):
            return True
    segments: list[tuple[list[str], str]] = []
    for raw, separator in raw_segments:
        if any(
            _is_critical(nested, _depth + 1) for nested in _shell_substitutions(raw)
        ):
            return True
        words = _critical_command_words(raw)
        segments.append((words, separator))
        if not words:
            continue
        head = os.path.basename(words[0])
        operands = words[1:]
        if head in {"sh", "bash", "zsh", "dash", "ksh"}:
            for index, arg in enumerate(operands[:-1]):
                if arg.startswith("-") and not arg.startswith("--") and "c" in arg:
                    if _is_critical(operands[index + 1], _depth + 1):
                        return True
        if head == "eval" and _is_critical(" ".join(operands), _depth + 1):
            return True
        if head == "rm":
            recursive = False
            targets = []
            options = True
            for arg in operands:
                if options and arg == "--":
                    options = False
                elif options and arg.startswith("-"):
                    recursive |= arg == "--recursive" or (
                        not arg.startswith("--") and bool(set(arg[1:]) & {"r", "R"})
                    )
                else:
                    targets.append(arg)
            protected = {
                "/",
                "/etc",
                "/usr",
                "/var",
                "/home",
                "/Users",
                "/System",
                "/bin",
                "/sbin",
                "/lib",
                "/lib64",
                "/boot",
                "/root",
                "/opt",
                "/dev",
                "/tmp",
                "~",
                "$HOME",
                "${HOME}",
            }
            if recursive and any(
                os.path.normpath(t) in protected or t in {"*", "/*"} for t in targets
            ):
                return True
        # Only match executable names. Words in echo/grep/commit arguments
        # (including unquoted filenames) must never become hard prohibitions.
        if head in {
            "shutdown",
            "reboot",
            "halt",
            "poweroff",
            "insmod",
            "rmmod",
            "modprobe",
            "fdisk",
            "parted",
        } or head.startswith("mkfs"):
            return True
        if head == "init" and operands and operands[0] in {"0", "6"}:
            return True
        if head == "dd" and any(
            arg in {"if=/dev/zero", "if=/dev/random", "if=/dev/urandom"}
            for arg in operands
        ):
            return True
        if head == "iptables" and "-F" in operands:
            return True
        if (
            head in {"chmod", "chown"}
            and operands
            and os.path.normpath(operands[-1]) == "/"
        ):
            if head == "chown" or "777" in operands:
                return True
    # A pipe into an actual shell is execution; a hash utility is not.
    for (left, separator), (right, _) in zip(segments, segments[1:]):
        if (
            separator in {"|", "|&"}
            and left
            and right
            and os.path.basename(left[0]) in {"curl", "wget"}
            and os.path.basename(right[0]) in {"sh", "bash"}
        ):
            return True
    return False


def _critical_command_words(command: str) -> list[str]:
    """Unwrap literal execution prefixes without promoting argument text."""
    command = re.sub(
        r"^(?:(?:if|then|elif|else|do|while|until|!|\{)\s+)+", "", command.lstrip()
    )
    try:
        words = shlex.split(command, comments=True)
    except ValueError:
        return []
    option_values = {
        "sudo": {
            "-u",
            "-g",
            "-h",
            "-p",
            "-C",
            "-T",
            "-D",
            "-R",
            "-r",
            "-t",
            "--user",
            "--group",
            "--host",
            "--prompt",
            "--close-from",
            "--command-timeout",
            "--chdir",
            "--chroot",
            "--role",
            "--type",
        },
        "nice": {"-n", "--adjustment"},
        "exec": {"-a"},
        "command": set(),
        "nohup": set(),
        "busybox": set(),
        "timeout": {"-s", "--signal", "-k", "--kill-after"},
        "gtimeout": {"-s", "--signal", "-k", "--kill-after"},
        "setsid": set(),
        "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
        "gstdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    }
    while words:
        head = os.path.basename(words[0])
        if _looks_like_env_assignment(words[0]):
            words = words[1:]
        elif head == "env":
            words = _unwrap_read_command(["env", *words[1:]])
        elif head in option_values:
            words = words[1:]
            while words and words[0].startswith("-"):
                option, words = words[0], words[1:]
                if option == "--":
                    break
                if head == "command" and option in {"-v", "-V"}:
                    return []  # Lookup, not execution.
                if head in {"timeout", "gtimeout", "setsid", "stdbuf", "gstdbuf"}:
                    if option in {"--help", "--version"} or (
                        head == "setsid" and option in {"-h", "-V"}
                    ):
                        return []  # Runner exits without executing its operands.
                if option in option_values[head] and words:
                    words = words[1:]
            if head in {"timeout", "gtimeout"}:
                # DURATION is an operand of timeout, not the command to run.
                words = words[1:]
        else:
            break
    return words


def _shell_segments(
    command: str,
) -> tuple[list[tuple[str, str]], list[tuple[str, bool, bool]]]:
    """Split unquoted shell operators, preserving literals and heredoc bodies.

    Each segment retains its following operator, so sequence is not confused
    with a pipe. Heredocs are data unless fed to a shell; unquoted bodies still
    execute substitutions. This recognizes literal syntax, not shell expansion.
    """
    segments, heredocs, pending = [], [], []
    start = index = 0
    quote = ""
    while index < len(command):
        char = command[index]
        if char == "\\" and quote != "'":
            index += 2
            continue
        if char in {"'", '"'} and (not quote or quote == char):
            quote = "" if quote else char
        elif (
            not quote
            and char == "#"
            and (index == start or command[index - 1].isspace())
        ):
            # Comments cannot introduce executable commands or heredocs.
            end = command.find("\n", index)
            end = len(command) if end < 0 else end
            command = command[:index] + " " * (end - index) + command[end:]
            index = end
            continue
        elif (
            not quote
            and command.startswith("<<", index)
            and not command.startswith("<<<", index)
        ):
            match = re.match(
                r"""<<(-?)[ \t]*((?:\\.|'[^']*'|"(?:\\.|[^"\\])*"|[^\s;&|()<>])+)(?=\s|[;&|()<>]|$)""",
                command[index:],
            )
            if match:
                raw_delimiter = match[2]
                try:
                    delimiter = shlex.split(raw_delimiter)[0]
                except (ValueError, IndexError):
                    return segments, heredocs
                words = _critical_command_words(command[start:index])
                executes = bool(
                    words
                    and os.path.basename(words[0])
                    in {"sh", "bash", "zsh", "dash", "ksh"}
                )
                pending.append(
                    (delimiter, match[1] == "-", raw_delimiter == delimiter, executes)
                )
                index += match.end()
                continue
        elif not quote and char in ";&|()\n":
            end = index + 1
            if command[index : end + 1] in {"&&", "||", "|&", ";;", ";&"}:
                end += 1
            separator = command[index:end]
            segments.append((command[start:index], separator))
            if char == "\n" and pending:
                for delimiter, strip_tabs, expands, executes in pending:
                    body_start = end
                    while end < len(command):
                        line_end = command.find("\n", end)
                        line_end = len(command) if line_end < 0 else line_end
                        line = command[end:line_end]
                        if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                            heredocs.append(
                                (command[body_start:end], expands, executes)
                            )
                            end = min(line_end + 1, len(command))
                            break
                        end = min(line_end + 1, len(command))
                    else:
                        # An unterminated document is still input, not commands.
                        heredocs.append((command[body_start:], expands, executes))
                pending.clear()
            start = index = end
            continue
        index += 1
    segments.append((command[start:], ""))
    return segments, heredocs


def _shell_substitutions(command: str, *, literal_quotes: bool = False) -> list[str]:
    """Extract executed substitutions without treating single-quoted text as code."""
    result: list[str] = []
    quote = ""
    index = 0
    while index < len(command):
        char = command[index]
        if char == "\\" and quote != "'":
            index += 2
            continue
        if not literal_quotes and char in {"'", '"'} and (not quote or quote == char):
            quote = "" if quote else char
            index += 1
            continue
        if quote != "'" and command.startswith("$(", index):
            start = index + 2
            end, depth = start, 1
            inner_quote = ""
            while end < len(command) and depth:
                inner = command[end]
                if inner == "\\" and inner_quote != "'":
                    end += 2
                    continue
                if inner in {"'", '"', "`"} and (
                    not inner_quote or inner_quote == inner
                ):
                    inner_quote = "" if inner_quote else inner
                elif not inner_quote:
                    depth += (inner == "(") - (inner == ")")
                end += 1
            if depth == 0:
                result.append(command[start : end - 1])
                index = end
                continue
        if quote != "'" and char == "`":
            end = command.find("`", index + 1)
            if end != -1:
                result.append(command[index + 1 : end])
                index = end + 1
                continue
        index += 1
    return result


def is_read_only(tool: str, args: dict[str, Any]) -> bool:
    """Check if a tool call is read-only.

    Checks the tool name against the built-in read-only allowlist.
    For bash commands, also checks the command string for read-only
    commands and git subcommands. Compound shell syntax requires evaluation.

    This is a pure classification check — it does NOT consider session
    policy, tool preferences, or path policy. Use ``classify()`` for
    the full classification pipeline.

    Args:
        tool: Tool name.
        args: Tool arguments.

    Returns:
        True if the tool call is read-only by its nature.
    """
    # Built-in read-only tools (case-insensitive to handle both
    # OpenCode lowercase and Claude Code capitalized conventions)
    if tool.lower() in _READ_ONLY_TOOLS:
        return True

    # MCP tools (may be prefixed with server name)
    tool_name = tool.split(":")[-1] if ":" in tool else tool
    if tool_name in _READ_ONLY_MCP_TOOLS:
        return True

    # Handle Claude Code double-underscore convention: mcp__server__tool → tool
    if tool.startswith("mcp__") and "__" in tool[5:]:
        tool_name = tool.rsplit("__", 1)[-1]
        if tool_name in _READ_ONLY_MCP_TOOLS:
            return True

    # Handle OpenCode single-underscore convention: server_tool → tool
    # Try progressively shorter suffixes to handle tool names that
    # themselves contain underscores (e.g., "mnemory_get_core_memories"
    # → try "get_core_memories", then "core_memories", etc.)
    if "_" in tool and not tool.startswith("mcp__"):
        parts = tool.split("_")
        for i in range(1, len(parts)):
            candidate = "_".join(parts[i:])
            if candidate in _READ_ONLY_MCP_TOOLS:
                return True

    # Bash commands (case-sensitive — "bash" is always lowercase)
    if tool in {"bash", "terminal"}:
        return _is_read_only_bash(args)

    return False


def _is_read_only_bash(args: dict[str, Any]) -> bool:
    """Check if a bash command is read-only.

    Parses the command to extract the base command and checks against
    the read-only allowlist. Compound syntax, executable scripts, and
    state-changing options require evaluation.
    """
    command = _extract_bash_command(args)
    if not command:
        return False

    # Fast paths cover simple commands only. Shell control flow, expansion,
    # and redirection require evaluation even when the first command is safe.
    # Brace/pathname expansion can synthesize write/exec options that
    # shlex misses. Reject glob syntax (including extglob parentheses),
    # braces, and quoted/escaped forms conservatively.
    if any(char in command for char in ";&|\n\r`${}*?[]()"):
        return False

    return _is_single_command_read_only(command)


# Shell redirection operators that indicate a write operation.
_REDIRECT_OPS: set[str] = {">", ">>", "2>", "2>>", "&>", "&>>", "<", "<<"}


def _is_single_command_read_only(command: str) -> bool:
    """Check if a single (non-piped, non-chained) command is read-only."""
    # Mixed/remaining shell control syntax is not a simple command.
    if any(char in command for char in ";&|\n\r`${}*?[]()"):
        return False

    # Check for shell redirection BEFORE shlex.split, since shlex treats
    # > as a regular token. We scan the raw command for redirect operators.
    if _has_shell_redirect(command):
        return False

    try:
        tokens = shlex.split(command)
    except ValueError:
        # Malformed command — treat as write for safety
        return False

    if not tokens:
        return False

    # Tilde prefixes depend on the client shell/user, never the server host.
    # shlex strips quoting, so quoted/escaped prefixes are conservative too.
    # Mid-token tildes (HEAD~1, file~suffix) are literal and remain eligible.
    if any(token.startswith("~") for token in tokens):
        return False

    base_cmd = tokens[0]
    if base_cmd == "grep" and _parse_search_arguments(base_cmd, tokens[1:])[1]:
        return False

    # Script interpreters, pagers, and interactive tools can execute programs
    # or write files. Route them through evaluation instead of a prefix allow.
    if base_cmd in {"awk", "sed", "yq", "less", "more", "top", "fd"}:
        return False
    if base_cmd == "env" and len(tokens) != 1:
        return False
    if base_cmd == "find" and any(
        t.startswith(("-exec", "-ok", "-delete", "-fprint", "-fls")) for t in tokens[1:]
    ):
        return False
    if base_cmd == "rg" and any(
        t.startswith(("--pre", "--hostname-bin")) for t in tokens[1:]
    ):
        return False
    # These utilities have output-file/command options (including abbreviated
    # long options). Only plain operands are eligible for the fast path.
    if base_cmd in {"sort", "tree", "file", "uniq"}:
        if any(t.startswith("-") and t != "-" for t in tokens[1:]):
            return False
        if base_cmd == "uniq" and len(tokens) > 2:
            return False
    if base_cmd == "date" and not (
        len(tokens) == 1 or (len(tokens) == 2 and tokens[1].startswith("+"))
    ):
        return False
    if base_cmd == "hostname" and len(tokens) != 1:
        return False

    # Git: check subcommand
    if base_cmd == "git" and len(tokens) > 1:
        subcommand = tokens[1]
        unsafe_options = (
            "--output",
            "--ext-diff",
            "--textconv",
            "--filters",
            "--open-files-in-pager",
        )
        if any(
            t.startswith("--")
            and len(t) > 2
            and any(option.startswith(t.split("=", 1)[0]) for option in unsafe_options)
            for t in tokens[2:]
        ):
            return False
        if subcommand in _READ_ONLY_GIT_SUBCOMMANDS:
            return True
        if subcommand in _GIT_SUBCOMMANDS_WITH_CHECKS:
            return _is_git_subcommand_read_only(subcommand, tokens[2:])
        return False

    # python/node are not read-only by default (can execute arbitrary code)
    if base_cmd in ("python", "python3", "node"):
        return False

    # Check against read-only bash commands
    return base_cmd in _READ_ONLY_BASH_COMMANDS


def _has_shell_redirect(command: str) -> bool:
    """Conservatively reject redirection, including adjacent quoted operands."""
    return "<" in command or ">" in command


def _is_git_subcommand_read_only(subcommand: str, remaining: list[str]) -> bool:
    """Check if a git subcommand with specific arguments is read-only.

    Handles git subcommands that can be either read or write depending
    on their arguments (branch, tag, remote, stash, config).

    Args:
        subcommand: The git subcommand (e.g., "branch", "tag").
        remaining: Tokens after the subcommand.
    """
    if subcommand == "stash":
        # Only 'git stash list' and 'git stash show' are read-only
        if remaining and remaining[0] in ("list", "show"):
            return True
        return False

    if subcommand == "config":
        # Only --get, --get-all, --list, -l are read-only
        config_args = set(remaining)
        read_flags = {"--get", "--get-all", "--list", "-l"}
        if config_args & read_flags:
            safe_flags = read_flags | {
                "--show-origin",
                "--show-scope",
                "--global",
                "--local",
                "--system",
                "--null",
                "-z",
            }
            return all(
                not arg.startswith("-") or arg in safe_flags for arg in remaining
            )
        return False

    if subcommand == "branch":
        # 'git branch' (no args) → list branches (read)
        # 'git branch -a', '-r', '--list' → list branches (read)
        # 'git branch -v', '-vv' → list with verbose (read)
        # 'git branch <name>' → create branch (write)
        # 'git branch -d/-D <name>' → delete branch (write)
        # 'git branch -m/-M <old> <new>' → rename branch (write)
        if not remaining:
            return True
        read_flags = {
            "-a",
            "-r",
            "--list",
            "-v",
            "-vv",
            "--merged",
            "--no-merged",
            "--contains",
            "--no-contains",
            "--sort",
            "--format",
            "--color",
            "--no-color",
            "--column",
            "--no-column",
        }
        # All remaining args must be read-only flags or their values
        for arg in remaining:
            if arg.startswith("-") and arg not in read_flags:
                return False
            if not arg.startswith("-"):
                # Positional argument = branch name = write operation
                return False
        return True

    if subcommand == "tag":
        # 'git tag' (no args) → list tags (read)
        # 'git tag -l', '--list' → list tags (read)
        # 'git tag -l "pattern"' → list with pattern (read)
        # 'git tag <name>' → create tag (write)
        # 'git tag -d <name>' → delete tag (write)
        if not remaining:
            return True
        if remaining[0] in ("-l", "--list"):
            return all(
                not arg.startswith("-") or arg in {"-l", "--list", "-n"}
                for arg in remaining
            )
        return False

    if subcommand == "remote":
        # 'git remote' (no args) → list remotes (read)
        # 'git remote -v' → list with URLs (read)
        # 'git remote show <name>' → show remote details (read)
        # 'git remote get-url <name>' → get URL (read)
        # 'git remote add/remove/rename/set-url → write
        if not remaining:
            return True
        if remaining[0] in ("-v", "--verbose"):
            return len(remaining) == 1
        if remaining[0] in ("show", "get-url"):
            return True
        return False

    return False


def _check_session_policy(
    tool: str,
    args: dict[str, Any],
    policy: dict[str, Any],
) -> Classification | None:
    """Check session policy for tool classification overrides.

    Policy format:
    {
        "allow_tools": ["tool_name", ...],     # Force READ classification
        "deny_tools": ["tool_name", ...],      # Force CRITICAL classification
        "allow_commands": ["pattern", ...],     # Glob patterns for bash
        "allow_scripts": ["/path/script.py"],   # Exact Python script paths
        "deny_commands": ["pattern", ...],     # Glob patterns for bash
        "allow_paths": ["pattern", ...],       # Exempt paths from project boundary
        "deny_paths": ["pattern", ...]         # Always deny (fnmatch on resolved)
    }

    Deny rules take priority over allow rules.
    Patterns use simple glob matching (fnmatch), NOT regex.

    Returns:
        Classification override, or None if no policy match.
    """
    deny = _check_session_policy_deny(tool, args, policy)
    if deny is not None:
        return deny
    return _check_session_policy_allow(tool, args, policy)


def _check_session_policy_deny(
    tool: str,
    args: dict[str, Any],
    policy: dict[str, Any],
) -> Classification | None:
    """Check session policy deny rules only."""
    deny_tools = policy.get("deny_tools", [])
    if tool in deny_tools:
        return Classification.CRITICAL

    if tool in {"bash", "terminal"}:
        command = _extract_bash_command(args)
        deny_commands = policy.get("deny_commands", [])
        for pattern in deny_commands:
            if isinstance(pattern, str) and fnmatch.fnmatch(command, pattern):
                return Classification.CRITICAL

    return None


def _check_session_policy_allow(
    tool: str,
    args: dict[str, Any],
    policy: dict[str, Any],
    *,
    script_paths_known: bool = True,
) -> Classification | None:
    """Check session policy allow rules only."""
    allow_tools = policy.get("allow_tools", [])
    if tool in allow_tools:
        return Classification.READ

    if script_paths_known and match_allowed_script(tool, args, policy) is not None:
        return Classification.READ

    if tool in {"bash", "terminal"}:
        command = _extract_bash_command(args)
        allow_commands = policy.get("allow_commands", [])
        for pattern in allow_commands:
            if isinstance(pattern, str) and fnmatch.fnmatch(command, pattern):
                return Classification.READ

    return None
