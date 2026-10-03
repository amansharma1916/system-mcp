"""The ``browse_files`` tool: a read-only directory listing inside the allowlist.

The tool never reads file contents, never follows symlinks, and never returns a
path outside the configured allowed directories. Entries are reported with
``lstat`` metadata, so a symlink pointing at ``/etc`` is *described* (and
flagged as escaping the allowlist) without the target ever being opened.
"""

from __future__ import annotations

import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config, DirectoryPolicy
from linux_mcp.errors import DirectoryReadError, LinuxMCPError
from linux_mcp.guard import GuardContext
from linux_mcp.logging_setup import get_logger
from linux_mcp.security import (
    Allowlist,
    canonicalize_directory,
    is_symlink_escape,
    read_symlink_target,
)

logger = get_logger("tools.filesystem")

EntryType = Literal["directory", "file", "symlink", "other"]
"""How an entry is classified. Symlinks are never resolved."""

_SCAN_SAFETY_LIMIT = 200_000
"""Stop counting entries after this many, so a pathological directory cannot hang."""

_TYPE_ORDER: dict[str, int] = {"directory": 0, "symlink": 1, "file": 2, "other": 3}


class FileEntry(BaseModel):
    """One entry inside a browsed directory."""

    name: str = Field(description="Entry name, relative to the browsed directory.")
    path: str = Field(description="Absolute path of the entry.")
    type: EntryType = Field(
        description=(
            "directory or file for normal entries; symlink when the entry is a "
            "symbolic link (its target is never followed); other for devices, "
            "sockets, and pipes."
        )
    )
    size_bytes: int | None = Field(
        default=None,
        description="Size in bytes for regular files; null for directories and symlinks.",
    )
    modified: str | None = Field(
        default=None, description="Last modification time, ISO 8601 in UTC."
    )
    hidden: bool = Field(default=False, description="True when the name starts with a dot.")
    is_symlink: bool = Field(
        default=False, description="True when the entry itself is a symbolic link."
    )
    symlink_target: str | None = Field(
        default=None,
        description="Raw link target for symlinks; null otherwise. Never resolved.",
    )
    escapes_allowed_directories: bool = Field(
        default=False,
        description=(
            "For symlinks: true when the target resolves outside every allowed "
            "directory, which means trying to browse through it would be refused."
        ),
    )


class BrowseResult(BaseModel):
    """The result of a successful ``browse_files`` call."""

    requested_path: str = Field(description="The path exactly as the caller sent it.")
    path: str = Field(description="The fully resolved directory that was listed.")
    parent: str | None = Field(
        default=None, description="Parent directory, or null if the browsed directory is /."
    )
    allowed_directories: list[str] = Field(
        description="Every directory browse_files is allowed to read."
    )
    entries: list[FileEntry] = Field(
        description="Directory contents: directories first, then symlinks, then files."
    )
    total_entries: int = Field(
        description="How many entries the directory actually holds, before truncation."
    )
    truncated: bool = Field(
        description=(
            "True when the directory holds more entries than were returned; raise "
            "'directories.max_entries' in the configuration to see more."
        )
    )


def list_directory(path: str, *, policy: DirectoryPolicy) -> BrowseResult:
    """List *path*, or raise a :class:`~linux_mcp.errors.LinuxMCPError`.

    Kept free of MCP imports so the security behaviour can be tested directly,
    without going through a client connection.
    """
    allowlist = policy.allowlist()
    resolved = canonicalize_directory(path, allowlist)
    entries, total_entries, truncated = _read_entries(resolved, allowlist, policy.max_entries)
    parent = None if resolved == resolved.parent else str(resolved.parent)
    return BrowseResult(
        requested_path=path,
        path=str(resolved),
        parent=parent,
        allowed_directories=[str(root) for root in allowlist.roots],
        entries=entries,
        total_entries=total_entries,
        truncated=truncated,
    )


def _read_entries(
    directory: Path,
    allowlist: Allowlist,
    max_entries: int,
) -> tuple[list[FileEntry], int, bool]:
    entries: list[FileEntry] = []
    total_entries = 0
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                total_entries += 1
                if len(entries) < max_entries:
                    described = _describe_entry(entry, allowlist)
                    if described is not None:
                        entries.append(described)
                if total_entries >= _SCAN_SAFETY_LIMIT:
                    break
    except PermissionError as exc:
        raise DirectoryReadError(
            f"Permission denied reading directory: {directory}."
        ) from exc
    except NotADirectoryError as exc:
        raise DirectoryReadError(f"Not a directory: {directory}.") from exc
    except OSError as exc:
        raise DirectoryReadError(
            f"Could not read directory {directory}: {exc.strerror or exc}."
        ) from exc

    entries.sort(key=lambda item: (_TYPE_ORDER[item.type], item.name.lower()))
    return entries, total_entries, total_entries > len(entries)


def _describe_entry(entry: os.DirEntry[str], allowlist: Allowlist) -> FileEntry | None:
    """Describe one entry using ``lstat`` only, or ``None`` if it vanished mid-scan."""
    path = Path(entry.path)
    try:
        info = entry.stat(follow_symlinks=False)
    except OSError:
        # Removed between scandir() and stat(); skip it silently.
        logger.debug("Entry disappeared while listing: %s", path)
        return None

    name = _safe_text(entry.name)
    modified = datetime.fromtimestamp(info.st_mtime, tz=timezone.utc).isoformat(
        timespec="seconds"
    )

    if entry.is_symlink():
        target = read_symlink_target(path)
        return FileEntry(
            name=name,
            path=_safe_text(entry.path),
            type="symlink",
            size_bytes=None,
            modified=modified,
            hidden=name.startswith("."),
            is_symlink=True,
            symlink_target=_safe_text(target) if target is not None else None,
            escapes_allowed_directories=is_symlink_escape(path, allowlist),
        )

    if stat.S_ISDIR(info.st_mode):
        entry_type: EntryType = "directory"
        size: int | None = None
    elif stat.S_ISREG(info.st_mode):
        entry_type = "file"
        size = info.st_size
    else:
        entry_type = "other"
        size = None

    return FileEntry(
        name=name,
        path=_safe_text(entry.path),
        type=entry_type,
        size_bytes=size,
        modified=modified,
        hidden=name.startswith("."),
    )


def _safe_text(value: str) -> str:
    """Return *value* as text that can always be serialised to JSON.

    Filenames on Linux are arbitrary byte strings. ``os.scandir`` decodes
    undecodable bytes with the ``surrogateescape`` handler, and those lone
    surrogates are not valid JSON, so replace them rather than failing the whole
    call because one file has an unusual name.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return value


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the ``browse_files`` tool on *server*."""
    policy = config.directories
    # Built at registration time so the model sees the real allowlist in the
    # tool description. It is passed as a decorator argument rather than written
    # into the signature: the SDK re-evaluates annotation strings in module
    # globals, where local names such as `policy` do not exist.
    description = (
        "List files and directories inside an allowed Linux directory. "
        "This tool does not read file contents. "
        "Allowed directories: "
        f"{', '.join(str(root) for root in config.directories.allow)}."
    )

    @server.tool(
        title="Browse files and directories",
        description=description,
        annotations=ToolAnnotations(
            read_only_hint=True,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def browse_files(
        path: Annotated[
            str,
            Field(
                description=(
                    "Absolute path of a directory inside the allowed directories, "
                    "for example /home/aman/Downloads. A leading '~' is expanded to "
                    "the user's home directory. Only directories can be listed."
                ),
            ),
        ],
    ) -> BrowseResult:
        """List files and directories inside an allowed Linux directory.

        This tool does not read file contents. Use it to see what exists in a
        directory, or to tell whether a path is a file or a directory. Anything
        outside the configured allowed directories is refused with a permission
        error, and every reply repeats the allowed directories so you can stay
        inside them.
        """
        logger.info("browse_files(path=%r)", path)
        try:
            result = list_directory(path, policy=policy)
        except LinuxMCPError as exc:
            logger.warning("browse_files refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc
        logger.info(
            "browse_files(%s) returned %d of %d entries",
            result.path,
            len(result.entries),
            result.total_entries,
        )
        return result