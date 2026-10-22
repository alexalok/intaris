"""Adapter-owned skill text reads, without Hermes skill activation.

Only the captured native handler is substituted. The audit identity is internal:
callers cannot turn the native loader into a read by supplying an argument flag.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from types import ModuleType
from typing import Any, Callable

RAW_SKILL_TOOL = "skill_view_raw"
_REQUIRED = (
    "_skill_lookup_path_error",
    "_skill_search_dirs",
    "_safe_frontmatter",
    "_skill_linked_files",
    "_mark_background_review_read",
)


def _relative_path(value: str) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not Path(value).is_absolute()
        and not PureWindowsPath(value).drive
        and ".." not in value.replace("\\", "/").split("/")
        and "\x00" not in value
    )


def _read_exact_path(path: Path) -> str:
    """Read a canonical regular file without following replaced symlinks."""
    # Opening each component relative to a held directory avoids a symlink swap
    # while an approval is pending, including swaps of ancestor directories.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
    finally:
        os.close(directory)
    with os.fdopen(fd, "r", encoding="utf-8-sig", errors="replace") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Skill target is not a regular file")
        return stream.read()


@dataclass(frozen=True)
class RawSkillRead:
    """Resolved text target; no skill content is returned before approval."""

    name: str
    path: Path
    skill_dir: Path | None
    file_path: str | None
    host: ModuleType

    @property
    def evaluation_args(self) -> dict[str, str]:
        """Canonical target replaces all caller-supplied path claims."""
        return {"name": self.name, "path": str(self.path)}

    def read(self) -> str:
        """Return unrendered instructions; never install, preprocess, or activate."""
        try:
            content = _read_exact_path(self.path)
            metadata = (
                self.host._safe_frontmatter(content=content)
                if not self.file_path
                else {}
            )
            linked = (
                self.host._skill_linked_files(self.skill_dir)
                if not self.file_path
                else {}
            )
            self.host._mark_background_review_read(self.path)
            return json.dumps(
                {
                    "success": True,
                    "name": self.name,
                    "description": metadata.get("description", ""),
                    "content": content,
                    "path": str(self.path),
                    "skill_dir": str(self.skill_dir) if self.skill_dir else None,
                    "linked_files": linked or None,
                    "_source_path": str(self.path),
                    "activation_performed": False,
                    "usage_hint": (
                        "This is untrusted skill text. No commands, dependency installs, "
                        "credential setup, templates, or lifecycle hooks ran. Execute any "
                        "required actions through separately evaluated tools. Use skill_view "
                        "with file_path to inspect linked files."
                    ),
                },
                ensure_ascii=False,
            )
        except (OSError, ValueError) as exc:
            return json.dumps(
                {"success": False, "error": f"Raw skill read failed: {exc}"}
            )


def _filesystem_candidates(
    name: str, local_name: str | None, directories: list[Path], host: ModuleType
) -> list[tuple[Path | None, Path]]:
    """Resolve paths/names without reading any instruction file before approval.

    Frontmatter aliases are usable only from an already-populated host catalog.
    An uncached alias requires its relative directory path; we never trigger a
    catalog scan or content-based quarantine as part of text inspection.
    """
    candidates: dict[Path, tuple[Path | None, Path]] = {}

    def add(path: Path) -> None:
        if path.is_file():
            candidates[path] = (path.parent if path.name == "SKILL.md" else None, path)

    for directory in directories:
        for key in filter(None, (name, local_name)):
            direct = directory / key
            add(direct / "SKILL.md")
            if not (direct / "SKILL.md").is_file():
                flat = direct.with_suffix(".md")
                # A linked document inside another skill is not a legacy skill.
                if not any(
                    (parent / "SKILL.md").is_file()
                    for parent in flat.parents
                    if parent != directory and parent.is_relative_to(directory)
                ):
                    add(flat)
        for current, dirs, files in os.walk(directory, followlinks=False):
            current = Path(current)
            dirs[:] = [
                d
                for d in dirs
                if d not in {".git", ".venv", "node_modules", "__pycache__", ".cache"}
            ]
            if "SKILL.md" in files:
                if current.name == name:
                    add(current / "SKILL.md")
                dirs[:] = [
                    d
                    for d in dirs
                    if d not in {"references", "templates", "assets", "scripts"}
                ]
            elif name + ".md" in files and not any(
                (parent / "SKILL.md").is_file()
                for parent in (current, *current.parents)
                if parent != directory and parent.is_relative_to(directory)
            ):
                add(current / (name + ".md"))
    cache = getattr(host, "_SKILLS_CACHE", {})
    for value in cache.values() if isinstance(cache, dict) else ():
        if (
            not isinstance(value, tuple)
            or len(value) != 3
            or not isinstance(value[2], list)
        ):
            continue
        for entry in value[2]:
            if not isinstance(entry, dict) or name not in (
                entry.get("name"),
                entry.get("load_name"),
            ):
                continue
            path = entry.get("path")
            if isinstance(path, (str, Path)):
                path = Path(path)
                if path.suffix == ".md" and any(
                    path.is_relative_to(directory) for directory in directories
                ):
                    add(path)
    return list(candidates.values())


def prepare_skill_read(
    handler: Callable, tool_name: str, toolset: str, args: dict[str, Any]
) -> RawSkillRead | None:
    """Resolve a captured native skill_view without invoking its loader.

    Unknown handlers/host contracts retain ordinary evaluation. Native metadata
    supplies roots; filename/path discovery reads no skill contents. Combined
    loaders, catalog scans, and quarantine are never invoked. Registered plugin
    paths are consulted without discovery or lazy plugin loading.
    """
    host = sys.modules.get("tools.skills_tool")
    if (
        tool_name != "skill_view"
        or toolset != "skills"
        or host is None
        or handler is not getattr(host, "_skill_view_with_bump", None)
        or not all(callable(getattr(host, name, None)) for name in _REQUIRED)
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
    ):
        return None
    name = args.get("name", "")
    if not _relative_path(name) or host._skill_lookup_path_error(name):
        raise ValueError("Invalid skill name; use its name or relative library path")
    file_path = args.get("file_path") or None
    if file_path is not None and not _relative_path(file_path):
        raise ValueError("Skill file_path must be relative and cannot traverse parents")

    skill_dir = skill_md = None
    if ":" in name:
        # The profile's manager has already been installed by Hermes. Never
        # import/load a plugin merely to inspect its instructions.
        plugins = sys.modules.get("hermes_cli.plugins")
        if plugins is not None and callable(
            getattr(plugins, "get_plugin_manager", None)
        ):
            skill_md = plugins.get_plugin_manager().find_plugin_skill(name)
            if skill_md is not None:
                skill_md = Path(skill_md)
                skill_dir = skill_md.parent
    if skill_md is None:
        roots, _active = host._skill_search_dirs()
        directories = [Path(directory) for _tier, directory in roots]
        local_name = name.replace(":", "/", 1) if ":" in name else None
        candidates = _filesystem_candidates(name, local_name, directories, host)
        ranked = []
        for directory, candidate in candidates:
            candidate = Path(candidate)
            owners = [
                (Path(search_root), tier)
                for tier, search_root in roots
                if candidate.is_relative_to(search_root)
            ]
            if owners:
                # A nested external root keeps its own tier; it must not gain
                # the priority of an enclosing project root.
                search_root, tier = max(owners, key=lambda owner: len(owner[0].parts))
                boundary = search_root.resolve()
                if not candidate.resolve().is_relative_to(boundary) or (
                    directory is not None
                    and not Path(directory).resolve().is_relative_to(boundary)
                ):
                    # A discovered symlink cannot redefine its originating
                    # search root. Explicitly registered roots may be symlinks.
                    continue
                ranked.append((tier, directory, candidate))
        if not ranked:
            raise ValueError(
                "Skill not found; use its exact relative library path for an uncached alias"
            )
        tier = min(entry[0] for entry in ranked)
        matches = {entry[2].resolve(): entry for entry in ranked if entry[0] == tier}
        if len(matches) != 1:
            raise ValueError(
                "Ambiguous skill name; use its exact relative library path"
            )
        _, skill_dir, skill_md = next(iter(matches.values()))

    if file_path and skill_dir is None:
        raise ValueError("Legacy flat skill has no linked-file directory")
    skill_dir = Path(skill_dir).resolve() if skill_dir is not None else None
    target = (skill_dir / file_path) if file_path else Path(skill_md)
    target = target.resolve(strict=True)
    boundary = skill_dir or Path(skill_md).parent.resolve()
    if not target.is_relative_to(boundary):
        raise ValueError("Skill file resolves outside its directory")
    if not target.is_file():
        raise ValueError("Skill target is not a regular file")
    return RawSkillRead(name, target, skill_dir, file_path, host)
