"""Read-only filesystem tools: read_file, file_info, checksum, search, list_tree.

Everything here is tier ``readonly``: it can inspect the allowed directories but
never changes anything, and every call is audited by :func:`linux_mcp.guard.guarded`.
The core functions are SDK-free and take an :class:`~linux_mcp.security.Allowlist`
so the security behaviour is testable without a client connection.
"""

from __future__ import annotations

import fnmatch
import grp
import hashlib
import mimetypes
import os
import pwd
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config
from linux_mcp.errors import (
    DirectoryReadError,
    InvalidPathError,
    LinuxMCPError,
    OutputLimitError,
)
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.security import (
    Allowlist,
    canonicalize_read_path,
)
from linux_mcp.tools._common import safe_text

logger = get_logger("tools.filesystem_read")

MAX_SEARCH_FILES = 5_000
"""Stop walking after this many candidate files so a huge tree cannot hang."""

_ALLOWED_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


class ReadFileResult(BaseModel):
    """The result of a successful ``read_file`` call."""

    path: str = Field(description="The fully resolved file that was read.")
    content: str = Field(description="The file contents, decoded as UTF-8.")
    size_bytes: int = Field(description="Total size of the file in bytes.")
    bytes_read: int = Field(description="How many bytes this call returned.")
    offset: int = Field(description="Byte offset the read started at.")
    truncated: bool = Field(
        description="True when the file is longer than the bytes returned."
    )


class FileInfoResult(BaseModel):
    """The result of a successful ``file_info`` call."""

    path: str = Field(description="The fully resolved path.")
    name: str = Field(description="Base name of the entry.")
    type: Literal["file", "directory", "other"] = Field(description="Entry kind.")
    size_bytes: int = Field(description="Size in bytes.")
    mode: str = Field(description="Permission bits, for example -rw-r--r--.")
    owner: str = Field(description="Owner user name, or the numeric uid.")
    group: str = Field(description="Group name, or the numeric gid.")
    modified: str = Field(description="Last modification time, ISO 8601 UTC.")
    accessed: str = Field(description="Last access time, ISO 8601 UTC.")
    mime_type: str | None = Field(
        default=None, description="Guessed MIME type, or null when unknown."
    )


class ChecksumResult(BaseModel):
    """The result of a successful ``checksum`` call."""

    path: str = Field(description="The fully resolved file that was hashed.")
    algorithm: str = Field(description="Hash algorithm used.")
    digest: str = Field(description="Hex-encoded digest.")
    size_bytes: int = Field(description="How many bytes were hashed.")


class SearchFilesResult(BaseModel):
    """The result of a successful ``search_files`` call."""

    root: str = Field(description="The fully resolved directory searched.")
    pattern: str = Field(description="The glob pattern that was matched.")
    matches: list[str] = Field(description="Absolute paths of matching entries.")
    total_matches: int = Field(description="How many matches were found.")
    truncated: bool = Field(
        description="True when more matches existed than were returned."
    )


class ContentMatch(BaseModel):
    """One matching line inside one file."""

    path: str = Field(description="Absolute path of the file containing the match.")
    line_number: int = Field(description="1-based line number of the match.")
    line: str = Field(description="The matching line, truncated if very long.")


class SearchContentResult(BaseModel):
    """The result of a successful ``search_content`` call."""

    root: str = Field(description="The fully resolved directory searched.")
    pattern: str = Field(description="The regular expression that was matched.")
    matches: list[ContentMatch] = Field(description="Matching lines.")
    files_scanned: int = Field(description="How many files were read.")
    total_matches: int = Field(description="How many matches were found.")
    truncated: bool = Field(
        description="True when more matches existed than were returned."
    )


class TreeEntry(BaseModel):
    """One entry in a recursive listing."""

    path: str = Field(description="Absolute path of the entry.")
    name: str = Field(description="Base name of the entry.")
    type: Literal["file", "directory", "symlink", "other"] = Field(
        description="Entry kind. Symlinks are never followed."
    )
    depth: int = Field(description="Depth below the root; 1 is a direct child.")


class TreeResult(BaseModel):
    """The result of a successful ``list_tree`` call."""

    root: str = Field(description="The fully resolved directory listed.")
    entries: list[TreeEntry] = Field(description="Entries, directories before files.")
    total_entries: int = Field(description="How many entries were returned.")
    truncated: bool = Field(
        description="True when the tree was cut off at max_depth or max_entries."
    )


# --------------------------------------------------------------------------- #
# SDK-free core
# --------------------------------------------------------------------------- #


def read_text_file(
    raw_path: str,
    *,
    allowlist: Allowlist,
    max_bytes: int,
    offset: int = 0,
    limit_bytes: int | None = None,
) -> ReadFileResult:
    """Read *raw_path* as text, capped at *max_bytes* from *offset*."""
    if offset < 0:
        raise InvalidPathError("offset must be zero or greater.")
    resolved = canonicalize_read_path(raw_path, allowlist)
    if resolved.is_dir():
        raise DirectoryReadError(
            f"Not a file: {resolved}. Use browse_files or list_tree to list a directory."
        )
    if not resolved.is_file():
        raise DirectoryReadError(
            f"Not a regular file: {resolved}. Named pipes, devices, and sockets "
            "cannot be read safely."
        )

    size_bytes = resolved.stat().st_size
    wanted = max_bytes if limit_bytes is None else min(limit_bytes, max_bytes)
    if wanted <= 0:
        raise OutputLimitError("The read limit must be greater than zero bytes.")

    try:
        with resolved.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(wanted)
    except OSError as exc:
        raise DirectoryReadError(f"Could not read {resolved}: {exc.strerror or exc}.") from exc

    return ReadFileResult(
        path=safe_text(str(resolved)),
        content=data.decode("utf-8", "replace"),
        size_bytes=size_bytes,
        bytes_read=len(data),
        offset=offset,
        truncated=(offset + len(data)) < size_bytes,
    )


def describe_file(raw_path: str, *, allowlist: Allowlist) -> FileInfoResult:
    """Return metadata for *raw_path* without following a final symlink."""
    resolved = canonicalize_read_path(raw_path, allowlist)
    try:
        info = resolved.stat()
    except OSError as exc:
        raise DirectoryReadError(
            f"Could not stat {resolved}: {exc.strerror or exc}."
        ) from exc

    if stat.S_ISDIR(info.st_mode):
        kind: Literal["file", "directory", "other"] = "directory"
    elif stat.S_ISREG(info.st_mode):
        kind = "file"
    else:
        kind = "other"

    mime_type, _ = mimetypes.guess_type(resolved.name, strict=False)
    return FileInfoResult(
        path=safe_text(str(resolved)),
        name=safe_text(resolved.name),
        type=kind,
        size_bytes=info.st_size,
        mode=stat.filemode(info.st_mode),
        owner=_user_name(info.st_uid),
        group=_group_name(info.st_gid),
        modified=_iso(info.st_mtime),
        accessed=_iso(info.st_atime),
        mime_type=mime_type,
    )


def compute_checksum(
    raw_path: str, *, allowlist: Allowlist, algorithm: str = "sha256"
) -> ChecksumResult:
    """Hash one file, streaming so large files do not exhaust memory."""
    if algorithm not in _ALLOWED_ALGORITHMS:
        raise InvalidPathError(
            f"Unsupported algorithm {algorithm!r}. Choose one of: "
            f"{', '.join(_ALLOWED_ALGORITHMS)}."
        )
    resolved = canonicalize_read_path(raw_path, allowlist)
    if not resolved.is_file():
        raise DirectoryReadError(f"Not a regular file: {resolved}.")

    digest = hashlib.new(algorithm)
    size = 0
    try:
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise DirectoryReadError(
            f"Could not read {resolved}: {exc.strerror or exc}."
        ) from exc

    return ChecksumResult(
        path=safe_text(str(resolved)),
        algorithm=algorithm,
        digest=digest.hexdigest(),
        size_bytes=size,
    )


def find_files(
    raw_root: str,
    *,
    allowlist: Allowlist,
    pattern: str,
    max_results: int = 200,
    include_hidden: bool = False,
) -> SearchFilesResult:
    """Find entries whose base name matches a glob *pattern* under *raw_root*."""
    root = _require_directory(raw_root, allowlist)
    matches: list[str] = []
    truncated = False

    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        if not include_hidden:
            subdirectories[:] = [name for name in subdirectories if not name.startswith(".")]
        for name in sorted(subdirectories + filenames):
            if not include_hidden and name.startswith("."):
                continue
            if fnmatch.fnmatch(name, pattern):
                matches.append(safe_text(str(Path(directory) / name)))
                if len(matches) >= max_results:
                    truncated = True
                    break
        if truncated:
            break

    return SearchFilesResult(
        root=safe_text(str(root)),
        pattern=pattern,
        matches=matches,
        total_matches=len(matches),
        truncated=truncated,
    )


def grep_files(
    raw_root: str,
    *,
    allowlist: Allowlist,
    pattern: str,
    glob: str | None = None,
    max_results: int = 200,
    max_file_bytes: int = 1_000_000,
) -> SearchContentResult:
    """Search file contents under *raw_root* for a regular expression."""
    root = _require_directory(raw_root, allowlist)
    try:
        expression = re.compile(pattern)
    except re.error as exc:
        raise InvalidPathError(
            f"Invalid regular expression {pattern!r}: {exc}."
        ) from exc

    matches: list[ContentMatch] = []
    files_scanned = 0
    truncated = False

    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        subdirectories[:] = [name for name in subdirectories if name != ".git"]
        for name in sorted(filenames):
            if glob is not None and not fnmatch.fnmatch(name, glob):
                continue
            path = Path(directory) / name
            try:
                if path.stat().st_size > max_file_bytes:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:8192]:
                continue
            files_scanned += 1
            if files_scanned > MAX_SEARCH_FILES:
                truncated = True
                break
            text = data.decode("utf-8", "replace")
            for number, line in enumerate(text.splitlines(), start=1):
                if expression.search(line):
                    matches.append(
                        ContentMatch(
                            path=safe_text(str(path)),
                            line_number=number,
                            line=line[:500],
                        )
                    )
                    if len(matches) >= max_results:
                        truncated = True
                        break
            if truncated:
                break
        if truncated:
            break

    return SearchContentResult(
        root=safe_text(str(root)),
        pattern=pattern,
        matches=matches,
        files_scanned=files_scanned,
        total_matches=len(matches),
        truncated=truncated,
    )


def walk_tree(
    raw_root: str,
    *,
    allowlist: Allowlist,
    max_depth: int = 2,
    max_entries: int = 200,
) -> TreeResult:
    """Return a recursive listing of *raw_root*, never following symlinks."""
    root = _require_directory(raw_root, allowlist)
    entries: list[TreeEntry] = []
    truncated = False

    def visit(directory: Path, depth: int) -> None:
        nonlocal truncated
        try:
            children = list(directory.iterdir())
        except OSError:
            return
        children.sort(key=lambda item: (item.is_symlink(), not item.is_dir(), item.name.lower()))
        for child in children:
            if len(entries) >= max_entries:
                truncated = True
                return
            if child.is_symlink():
                kind: Literal["file", "directory", "symlink", "other"] = "symlink"
            elif child.is_dir():
                kind = "directory"
            elif child.is_file():
                kind = "file"
            else:
                kind = "other"
            entries.append(
                TreeEntry(
                    path=safe_text(str(child)),
                    name=safe_text(child.name),
                    type=kind,
                    depth=depth,
                )
            )
            if kind == "directory" and depth < max_depth:
                visit(child, depth + 1)

    visit(root, 1)
    if len(entries) >= max_entries:
        truncated = True

    return TreeResult(
        root=safe_text(str(root)),
        entries=entries,
        total_entries=len(entries),
        truncated=truncated,
    )


def _require_directory(raw_root: str, allowlist: Allowlist) -> Path:
    resolved = canonicalize_read_path(raw_root, allowlist)
    if not resolved.is_dir():
        raise DirectoryReadError(
            f"Not a directory: {resolved}. This tool walks a directory tree."
        )
    return resolved


def _user_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# MCP registration
# --------------------------------------------------------------------------- #


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the read-only filesystem tools on *server*."""
    read_allowlist = config.read_allowlist()
    limits = config.policy.limits
    allowed = ", ".join(str(root) for root in read_allowlist.roots)

    @server.tool(
        title="Read a text file",
        description=(
            "Read the contents of a text file inside the allowed directories. "
            f"Allowed directories: {allowed}. Reads are capped at "
            f"{limits.max_read_bytes} bytes by default."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def read_file(
        path: Annotated[str, Field(description="Absolute path of the file to read.")],
        offset: Annotated[
            int, Field(ge=0, description="Byte offset to start reading from.")
        ] = 0,
        limit_bytes: Annotated[
            int | None,
            Field(gt=0, description="Maximum bytes to return; defaults to the configured cap."),
        ] = None,
    ) -> ReadFileResult:
        """Read a text file inside the allowed directories."""
        logger.info("read_file(path=%r, offset=%d)", path, offset)
        try:
            return guarded(
                context,
                tool="read_file",
                arguments={"path": path, "offset": offset, "limit_bytes": limit_bytes},
                action=lambda: read_text_file(
                    path,
                    allowlist=read_allowlist,
                    max_bytes=limits.max_read_bytes,
                    offset=offset,
                    limit_bytes=limit_bytes,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("read_file refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Describe a file or directory",
        description=(
            "Return metadata (type, size, permissions, owner, timestamps) for a "
            f"path inside the allowed directories. Allowed directories: {allowed}."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def file_info(
        path: Annotated[str, Field(description="Absolute path to describe.")],
    ) -> FileInfoResult:
        """Return metadata for a path inside the allowed directories."""
        logger.info("file_info(path=%r)", path)
        try:
            return guarded(
                context,
                tool="file_info",
                arguments={"path": path},
                action=lambda: describe_file(path, allowlist=read_allowlist),
            )
        except LinuxMCPError as exc:
            logger.warning("file_info refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Hash a file",
        description=(
            "Compute a checksum (md5, sha1, sha256, or sha512) of a file inside "
            f"the allowed directories. Allowed directories: {allowed}."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def checksum(
        path: Annotated[str, Field(description="Absolute path of the file to hash.")],
        algorithm: Annotated[
            str, Field(description="md5, sha1, sha256 (default), or sha512.")
        ] = "sha256",
    ) -> ChecksumResult:
        """Hash a file inside the allowed directories."""
        logger.info("checksum(path=%r, algorithm=%r)", path, algorithm)
        try:
            return guarded(
                context,
                tool="checksum",
                arguments={"path": path, "algorithm": algorithm},
                action=lambda: compute_checksum(
                    path, allowlist=read_allowlist, algorithm=algorithm
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("checksum refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Find files by name",
        description=(
            "Find files and directories whose name matches a glob pattern (for "
            "example '*.py') anywhere under a directory in the allowed "
            f"directories. Allowed directories: {allowed}."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def search_files(
        root: Annotated[str, Field(description="Absolute directory to search under.")],
        pattern: Annotated[str, Field(description="Glob for the name, e.g. '*.txt'.")],
        max_results: Annotated[int, Field(gt=0, le=5000)] = 200,
        include_hidden: Annotated[bool, Field(description="Include dotfiles.")] = False,
    ) -> SearchFilesResult:
        """Find files by name under an allowed directory."""
        logger.info("search_files(root=%r, pattern=%r)", root, pattern)
        try:
            return guarded(
                context,
                tool="search_files",
                arguments={"root": root, "pattern": pattern},
                action=lambda: find_files(
                    root,
                    allowlist=read_allowlist,
                    pattern=pattern,
                    max_results=max_results,
                    include_hidden=include_hidden,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("search_files refused %r: %s", root, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Search file contents",
        description=(
            "Search the contents of files under a directory in the allowed "
            "directories using a regular expression, optionally limited to files "
            f"matching a glob. Allowed directories: {allowed}."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def search_content(
        root: Annotated[str, Field(description="Absolute directory to search under.")],
        pattern: Annotated[str, Field(description="Python regular expression to match.")],
        glob: Annotated[
            str | None,
            Field(description="Only search files whose name matches this glob."),
        ] = None,
        max_results: Annotated[int, Field(gt=0, le=5000)] = 200,
    ) -> SearchContentResult:
        """Search file contents under an allowed directory."""
        logger.info("search_content(root=%r, pattern=%r)", root, pattern)
        try:
            return guarded(
                context,
                tool="search_content",
                arguments={"root": root, "pattern": pattern, "glob": glob},
                action=lambda: grep_files(
                    root,
                    allowlist=read_allowlist,
                    pattern=pattern,
                    glob=glob,
                    max_results=max_results,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("search_content refused %r: %s", root, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="List a directory tree",
        description=(
            "Recursively list a directory inside the allowed directories, up to a "
            f"depth and entry limit. Symlinks are described but never followed. "
            f"Allowed directories: {allowed}."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def list_tree(
        path: Annotated[str, Field(description="Absolute directory to list.")],
        max_depth: Annotated[int, Field(ge=0, le=10)] = 2,
        max_entries: Annotated[int, Field(gt=0, le=5000)] = 200,
    ) -> TreeResult:
        """Recursively list a directory inside the allowed directories."""
        logger.info("list_tree(path=%r, max_depth=%d)", path, max_depth)
        try:
            return guarded(
                context,
                tool="list_tree",
                arguments={"path": path, "max_depth": max_depth},
                action=lambda: walk_tree(
                    path,
                    allowlist=read_allowlist,
                    max_depth=max_depth,
                    max_entries=max_entries,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("list_tree refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc
