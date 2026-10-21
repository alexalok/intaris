"""Bounded, escaped Rich Message cards built only from redacted audit data."""

from __future__ import annotations

import json
from html import escape
from typing import Any


def _excerpt(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class _Details:
    """Bound text, breadth and depth without ever slicing generated markup."""

    def __init__(self) -> None:
        # Count JSON-escaped HTML bytes, matching the native socket's encoding.
        # Two cards plus the legacy response must fit its 64 KiB frame.
        self.remaining = 8000
        self.nodes = 96
        self.truncated = False

    def text(self, value: str) -> str:
        candidate = value[: self.remaining]
        escaped = escape(candidate, quote=False)
        if len(json.dumps(escaped)) - 2 > self.remaining:
            low, high = 0, len(candidate)
            while low < high:
                mid = (low + high + 1) // 2
                if (
                    len(json.dumps(escape(candidate[:mid], quote=False))) - 2
                    <= self.remaining
                ):
                    low = mid
                else:
                    high = mid - 1
            candidate = candidate[:low]
            escaped = escape(candidate, quote=False)
        self.remaining -= len(json.dumps(escaped)) - 2
        if len(candidate) < len(value):
            self.truncated = True
            escaped += "…"
        return escaped

    def render(self, value: Any, depth: int = 1) -> str:
        # The outer disclosure already contributes one level. Containers add
        # ul/li plus a label or leaf; Telegram permits at most 16 HTML levels.
        levels = 3 if isinstance(value, (dict, list)) else 1
        if self.nodes <= 0 or self.remaining <= 0 or depth + levels > 16:
            self.truncated = True
            return "<i>[truncated]</i>"
        self.nodes -= 1
        if isinstance(value, (dict, list)):
            if not value:
                return (
                    "<code>{}</code>" if isinstance(value, dict) else "<code>[]</code>"
                )
            items = (
                value.items() if isinstance(value, dict) else ((None, v) for v in value)
            )
            rendered = []
            for key, child in items:
                if self.nodes <= 0 or self.remaining <= 0:
                    self.truncated = True
                    rendered.append("<li><i>[truncated]</i></li>")
                    break
                label = f"<b>{self.text(str(key))}:</b> " if key is not None else ""
                rendered.append(f"<li>{label}{self.render(child, depth + 2)}</li>")
            return "<ul>" + "".join(rendered) + "</ul>"
        if isinstance(value, str):
            # Preformatted strings preserve shell quoting/newlines without JSON
            # backslashes and keep paths or URLs from becoming active links.
            return f"<pre>{self.text(value)}</pre>" if value else '<code>""</code>'
        scalar = (
            "null"
            if value is None
            else str(value).lower()
            if isinstance(value, bool)
            else str(value)
        )
        return f"<code>{self.text(scalar)}</code>"


def approval_presentation(record: dict[str, Any]) -> dict[str, str]:
    """Return pending and retired HTML, with all audit details collapsed."""
    arguments = record.get("args_redacted")
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except (ValueError, RecursionError):
            pass  # A legacy/plain argument remains readable as a bounded string.
    if arguments is None:
        arguments = {}
    tool = str(record.get("tool") or "Tool call")
    reason = str(record.get("judge_reasoning") or record.get("reasoning") or "")
    command = ""
    if isinstance(arguments, dict):
        for key in ("command", "cmd", "code", "path", "file_path", "url", "query"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                command = value
                break
    summary = escape(_excerpt(command or tool, 140), quote=False)
    renderer = _Details()
    details = renderer.render(
        {
            "Tool": tool,
            "Call": record.get("call_id", ""),
            "Session": record.get("session_id", ""),
            "Risk": record.get("risk", ""),
            "Reason": reason,
            "Arguments": arguments,
        }
    )
    if renderer.truncated:
        details += (
            "<p><i>Details truncated; full record available in Intaris audit.</i></p>"
        )
    disclosure = f"<details><summary>Read more</summary>{details}</details>"
    return {
        "pending": (
            "<p><b>Intaris approval required</b></p>"
            f"<p><b>Tool:</b> {escape(_excerpt(tool, 80), quote=False)}</p>"
            f"<pre>{summary}</pre>"
            f"<p><b>Reason:</b> {escape(_excerpt(reason, 240), quote=False)}</p>"
            f"{disclosure}"
            "<p>Approve applies only to this pending call. Silence does not approve.</p>"
        ),
        # The gateway prefixes the authoritative final status after lease close.
        "retired": f"<pre>{summary}</pre>{disclosure}",
    }
