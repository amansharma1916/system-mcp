"""Write-side filesystem tools: write_file, edit_file, create_directory,
move_path, copy_path, trash_path, and the destructive delete_path.

Every target is resolved and proven to live inside the configured **write**
directories before anything is touched, using
:func:`linux_mcp.security.canonicalize_write_path`. ``trash_path`` is tier
``write`` because it is reversible; ``delete_path`` is tier ``destructive``
because it is not.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config
from linux_mcp.errors import (
    LinuxMCPError,
    OperationRefusedError,
    PathDoesNotExistError,
)
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.security import (
    Allowlist,
    canonicalize_read_path,
    canonicalize_write_path,
)
from linux_mcp.tools._common import safe_text

logger = get_logger("tools.filesystem_write")


def default_trash_directory() -> Path:
    """The XDG trash directory for the current user."""
    data_home = os.environ.get("XDG_DATA_HOME") or "~/.local/share"
    return Path(os.path.expanduser(data_home)) / "Trash"


class WriteResult(BaseModel):
    """The result of a successful ``write_file`` call."""

    path: str = Field(description="The fully resolved file that was written.")
    bytes_written: int = Field(description="How many bytes were written.")
    created: bool = Field(description="True when the file did not exist before.")
    overwritten: bool = Field(description="True when an existing file was replaced.")


class EditResult(BaseModel):
    """The result of a successful ``edit_file`` call."""

    path: str = Field(description="The fully resolved file that was edited.")
    replacements: int = Field(description="How many occurrences were replaced.")
    size_before: int = Field(description="File size before the edit, in bytes.")
    size_after: int = Field(description="File size after the edit, in bytes.")


class CreateDirectoryResult(BaseModel):
    """The result of a successful ``create_directory`` call."""

    path: str = Field(description="The fully resolved directory.")
    created: bool = Field(description="False when the directory already existed.")


class MoveResult(BaseModel):
    """The result of a successful ``move_path`` call."""

    source: str = Field(description="The fully resolved original path.")
    destination: str = Field(description="The fully resolved new path.")


class CopyResult(BaseModel):
    """The result of a successful ``copy_path`` call."""

    source: str = Field(description="The fully resolved path that was copied.")
    destination: str = Field(description="The fully resolved copy.")
    entries_copied: int = Field(description="How many entries were copied.")


class TrashResult(BaseModel):
    """The result of a successful ``trash_path`` call."""

    path: str = Field(description="The original path, now moved to the trash.")
    trashed_to: str = Field(description="Where it now lives inside the trash directory.")
    restore_hint: str = Field(description="How to restore it.")


class DeleteResult(BaseModel):
    """The result of a successful ``delete_path`` call."""

    path: str = Field(description="The path that was permanently deleted.")
    recursive: bool = Field(description="True when a directory tree was removed.")
    entries_deleted: int = Field(description="How many entries were removed.")


# --------------------------------------------------------------------------- #
# SDK-free core
# --------------------------------------------------------------------------- #


def write_text_file(
    raw_path: str,
    *,
    write_allowlist: Allowlist,
    content: str,
    overwrite: bool = False,
    create_parents: bool = False,
) -> WriteResult:
    """Write *content* to *raw_path*, atomically, after policy checks."""
    target = canonicalize_write_path(raw_path, write_allowlist)
    _refuse_allowlist_root(target, write_allowlist, verb="write to")

    if target.is_dir():
        raise OperationRefusedError(
            f"{target} is a directory; write_file writes files only."
        )

    existed = target.exists()
    if existed and not overwrite:
        raise OperationRefusedError(
            f"{target} already exists. Pass overwrite=true to replace it, or "
            "choose a different name."
        )

    if not target.parent.is_dir():
        if not create_parents:
            raise OperationRefusedError(
                f"The parent directory {target.parent} does not exist. Pass "
                "create_parents=true, or call create_directory first."
            )
        target.parent.mkdir(parents=True, exist_ok=True)

    data = content.encode("utf-8")
    temp = target.with_name(f".{target.name}.linux-mcp-tmp")
    try:
        temp.write_bytes(data)
        os.replace(temp, target)
    except OSError as exc:
        temp.unlink(missing_ok=True)
        raise OperationRefusedError(
            f"Could not write {target}: {exc.strerror or exc}."
        ) from exc

    return WriteResult(
        path=safe_text(str(target)),
        bytes_written=len(data),
        created=not existed,
        overwritten=existed,
    )


def edit_text_file(
    raw_path: str,
    *,
    read_allowlist: Allowlist,
    write_allowlist: Allowlist,
    old_text: str,
    new_text: str,
    replace_all: bool = False,
) -> EditResult:
    """Replace *old_text* with *new_text* in an existing file."""
    if not old_text:
        raise OperationRefusedError("old_text must not be empty.")
    source = canonicalize_read_path(raw_path, read_allowlist)
    target = canonicalize_write_path(str(source), write_allowlist)
    _refuse_allowlist_root(target, write_allowlist, verb="edit")

    if not target.is_file():
        raise OperationRefusedError(f"Not a regular file: {target}.")

    try:
        before = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise OperationRefusedError(
            f"Could not read {target} as UTF-8 text: {exc}."
        ) from exc

    occurrences = before.count(old_text)
    if occurrences == 0:
        raise OperationRefusedError(
            "old_text was not found in the file. Read the file first and copy the "
            "exact text, including whitespace."
        )
    if not replace_all and occurrences > 1:
        raise OperationRefusedError(
            f"old_text occurs {occurrences} times. Include more surrounding text "
            "to make it unique, or pass replace_all=true."
        )

    after = before.replace(old_text, new_text) if replace_all else before.replace(
        old_text, new_text, 1
    )
    try:
        target.write_text(after, encoding="utf-8")
    except OSError as exc:
        raise OperationRefusedError(
            f"Could not write {target}: {exc.strerror or exc}."
        ) from exc

    return EditResult(
        path=safe_text(str(target)),
        replacements=occurrences if replace_all else 1,
        size_before=len(before.encode("utf-8")),
        size_after=len(after.encode("utf-8")),
    )


def make_directory(
    raw_path: str, *, write_allowlist: Allowlist, parents: bool = True
) -> CreateDirectoryResult:
    """Create a directory inside the write directories."""
    target = canonicalize_write_path(raw_path, write_allowlist)
    _refuse_allowlist_root(target, write_allowlist, verb="create")

    if target.exists():
        if target.is_dir():
            return CreateDirectoryResult(path=safe_text(str(target)), created=False)
        raise OperationRefusedError(
            f"{target} exists and is not a directory."
        )

    try:
        target.mkdir(parents=parents, exist_ok=parents)
    except FileNotFoundError as exc:
        raise OperationRefusedError(
            f"The parent directory {target.parent} does not exist. Pass "
            "parents=true, or create the parent first."
        ) from exc
    except OSError as exc:
        raise OperationRefusedError(
            f"Could not create {target}: {exc.strerror or exc}."
        ) from exc

    return CreateDirectoryResult(path=safe_text(str(target)), created=True)


def move_entry(
    raw_source: str,
    raw_destination: str,
    *,
    write_allowlist: Allowlist,
    overwrite: bool = False,
) -> MoveResult:
    """Move or rename an entry, staying inside the write directories."""
    source = _existing_writable(raw_source, write_allowlist)
    destination = canonicalize_write_path(raw_destination, write_allowlist)
    _refuse_allowlist_root(source, write_allowlist, verb="move")
    _refuse_allowlist_root(destination, write_allowlist, verb="move onto")

    if destination.exists() or destination.is_symlink():
        if not overwrite:
            raise OperationRefusedError(
                f"{destination} already exists. Pass overwrite=true to replace a "
                "file (directories are never replaced)."
            )
        if destination.is_dir() and not destination.is_symlink():
            raise OperationRefusedError(
                f"{destination} is a directory; refusing to replace it."
            )
        destination.unlink()

    try:
        shutil.move(str(source), str(destination))
    except OSError as exc:
        raise OperationRefusedError(
            f"Could not move {source} to {destination}: {exc.strerror or exc}."
        ) from exc

    return MoveResult(
        source=safe_text(str(source)), destination=safe_text(str(destination))
    )


def copy_entry(
    raw_source: str,
    raw_destination: str,
    *,
    read_allowlist: Allowlist,
    write_allowlist: Allowlist,
    overwrite: bool = False,
) -> CopyResult:
    """Copy an entry from the read directories into the write directories."""
    source = canonicalize_read_path(raw_source, read_allowlist)
    destination = canonicalize_write_path(raw_destination, write_allowlist)
    _refuse_allowlist_root(destination, write_allowlist, verb="copy onto")

    if destination.exists() and not overwrite:
        raise OperationRefusedError(
            f"{destination} already exists. Pass overwrite=true to merge into it."
        )

    try:
        if source.is_dir() and not source.is_symlink():
            shutil.copytree(source, destination, dirs_exist_ok=overwrite)
            entries = sum(len(files) + len(dirs) for _, dirs, files in os.walk(destination))
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination, follow_symlinks=False)
            entries = 1
    except OSError as exc:
        raise OperationRefusedError(
            f"Could not copy {source} to {destination}: {exc.strerror or exc}."
        ) from exc

    return CopyResult(
        source=safe_text(str(source)),
        destination=safe_text(str(destination)),
        entries_copied=entries,
    )


def trash_entry(
    raw_path: str,
    *,
    write_allowlist: Allowlist,
    trash_directory: Path | None = None,
) -> TrashResult:
    """Move an entry to the XDG trash so the action can be undone by hand."""
    target = _existing_writable(raw_path, write_allowlist)
    _refuse_allowlist_root(target, write_allowlist, verb="trash")

    trash = trash_directory if trash_directory is not None else default_trash_directory()
    files_dir = trash / "files"
    info_dir = trash / "info"
    try:
        files_dir.mkdir(parents=True, exist_ok=True)
        info_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OperationRefusedError(
            f"Could not create the trash directory {trash}: {exc.strerror or exc}."
        ) from exc

    name = target.name
    candidate = name
    counter = 1
    while (files_dir / candidate).exists():
        candidate = f"{name}.{counter}"
        counter += 1

    destination = files_dir / candidate
    try:
        shutil.move(str(target), str(destination))
    except OSError as exc:
        raise OperationRefusedError(
            f"Could not move {target} to the trash: {exc.strerror or exc}."
        ) from exc

    stamp = datetime.now(tz=timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S")
    info_file = info_dir / f"{candidate}.trashinfo"
    info_file.write_text(
        f"[Trash Info]\nPath={target}\nDeletionDate={stamp}\n", encoding="utf-8"
    )

    return TrashResult(
        path=safe_text(str(target)),
        trashed_to=safe_text(str(destination)),
        restore_hint=(
            f"Restore with: mv {destination} {target} "
            f"(metadata in {info_file})"
        ),
    )


def delete_entry(
    raw_path: str, *, write_allowlist: Allowlist, recursive: bool = False
) -> DeleteResult:
    """Permanently delete an entry inside the write directories."""
    target = _existing_writable(raw_path, write_allowlist)
    _refuse_allowlist_root(target, write_allowlist, verb="delete")

    is_directory = target.is_dir() and not target.is_symlink()
    if is_directory:
        if not recursive:
            raise OperationRefusedError(
                f"{target} is a directory. Pass recursive=true to delete it and "
                "everything inside, or use trash_path for a reversible removal."
            )
        entries = sum(len(files) + len(dirs) for _, dirs, files in os.walk(target))
        try:
            shutil.rmtree(target)
        except OSError as exc:
            raise OperationRefusedError(
                f"Could not delete {target}: {exc.strerror or exc}."
            ) from exc
        return DeleteResult(
            path=safe_text(str(target)), recursive=True, entries_deleted=entries
        )

    try:
        target.unlink()
    except OSError as exc:
        raise OperationRefusedError(
            f"Could not delete {target}: {exc.strerror or exc}."
        ) from exc
    return DeleteResult(path=safe_text(str(target)), recursive=False, entries_deleted=1)


def _existing_writable(raw_path: str, write_allowlist: Allowlist) -> Path:
    """Resolve a path that must exist and be inside the write directories."""
    candidate = canonicalize_write_path(raw_path, write_allowlist)
    if not candidate.exists() and not candidate.is_symlink():
        raise PathDoesNotExistError(f"Path does not exist: {candidate}.")
    return candidate


def _refuse_allowlist_root(target: Path, allowlist: Allowlist, *, verb: str) -> None:
    """Refuse operating on an allowlist root itself, which would be catastrophic."""
    if any(target == root for root in allowlist.roots):
        raise OperationRefusedError(
            f"Refusing to {verb} {target}: it is a configured write directory "
            "root. Operate on something inside it instead."
        )


# --------------------------------------------------------------------------- #
# MCP registration
# --------------------------------------------------------------------------- #


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the write-side filesystem tools on *server*."""
    read_allowlist = config.read_allowlist()
    write_allowlist = config.write_allowlist()
    writable = ", ".join(str(root) for root in write_allowlist.roots)

    @server.tool(
        title="Write a text file",
        description=(
            "Create or replace a text file inside the writable directories. "
            f"Writable directories: {writable}. Refuses to overwrite unless "
            "overwrite=true."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def write_file(
        path: Annotated[str, Field(description="Absolute path of the file to write.")],
        content: Annotated[str, Field(description="Text to write, encoded as UTF-8.")],
        overwrite: Annotated[
            bool, Field(description="Replace the file if it already exists.")
        ] = False,
        create_parents: Annotated[
            bool, Field(description="Create missing parent directories.")
        ] = False,
    ) -> WriteResult:
        """Create or replace a text file inside the writable directories."""
        logger.info("write_file(path=%r, bytes=%d)", path, len(content))
        try:
            return guarded(
                context,
                tool="write_file",
                arguments={"path": path, "bytes": len(content), "overwrite": overwrite},
                action=lambda: write_text_file(
                    path,
                    write_allowlist=write_allowlist,
                    content=content,
                    overwrite=overwrite,
                    create_parents=create_parents,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("write_file refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Edit a text file",
        description=(
            "Replace an exact snippet of text in a file. old_text must match "
            "exactly and, unless replace_all is true, must appear exactly once. "
            f"Writable directories: {writable}."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def edit_file(
        path: Annotated[str, Field(description="Absolute path of the file to edit.")],
        old_text: Annotated[str, Field(description="Exact text to replace.")],
        new_text: Annotated[str, Field(description="Replacement text.")],
        replace_all: Annotated[
            bool, Field(description="Replace every occurrence instead of requiring one.")
        ] = False,
    ) -> EditResult:
        """Replace an exact snippet of text in a file."""
        logger.info("edit_file(path=%r)", path)
        try:
            return guarded(
                context,
                tool="edit_file",
                arguments={"path": path, "replace_all": replace_all},
                action=lambda: edit_text_file(
                    path,
                    read_allowlist=read_allowlist,
                    write_allowlist=write_allowlist,
                    old_text=old_text,
                    new_text=new_text,
                    replace_all=replace_all,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("edit_file refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Create a directory",
        description=f"Create a directory inside the writable directories: {writable}.",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def create_directory(
        path: Annotated[str, Field(description="Absolute path of the directory.")],
        parents: Annotated[
            bool, Field(description="Create missing parent directories too.")
        ] = True,
    ) -> CreateDirectoryResult:
        """Create a directory inside the writable directories."""
        logger.info("create_directory(path=%r)", path)
        try:
            return guarded(
                context,
                tool="create_directory",
                arguments={"path": path, "parents": parents},
                action=lambda: make_directory(
                    path, write_allowlist=write_allowlist, parents=parents
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("create_directory refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Move or rename a path",
        description=(
            "Move or rename a file or directory, staying inside the writable "
            f"directories: {writable}."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def move_path(
        source: Annotated[str, Field(description="Absolute path to move.")],
        destination: Annotated[str, Field(description="Absolute destination path.")],
        overwrite: Annotated[
            bool, Field(description="Replace an existing file at the destination.")
        ] = False,
    ) -> MoveResult:
        """Move or rename a file or directory."""
        logger.info("move_path(source=%r, destination=%r)", source, destination)
        try:
            return guarded(
                context,
                tool="move_path",
                arguments={"source": source, "destination": destination},
                action=lambda: move_entry(
                    source,
                    destination,
                    write_allowlist=write_allowlist,
                    overwrite=overwrite,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("move_path refused %r: %s", source, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Copy a path",
        description=(
            "Copy a file or directory from the allowed directories into the "
            f"writable directories: {writable}."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def copy_path(
        source: Annotated[str, Field(description="Absolute path to copy from.")],
        destination: Annotated[str, Field(description="Absolute path to copy to.")],
        overwrite: Annotated[
            bool, Field(description="Merge into an existing destination.")
        ] = False,
    ) -> CopyResult:
        """Copy a file or directory into the writable directories."""
        logger.info("copy_path(source=%r, destination=%r)", source, destination)
        try:
            return guarded(
                context,
                tool="copy_path",
                arguments={"source": source, "destination": destination},
                action=lambda: copy_entry(
                    source,
                    destination,
                    read_allowlist=read_allowlist,
                    write_allowlist=write_allowlist,
                    overwrite=overwrite,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("copy_path refused %r: %s", source, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Move a path to the trash",
        description=(
            "Reversibly move a file or directory to the XDG trash. Prefer this "
            "over delete_path when you might need the data back."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def trash_path(
        path: Annotated[str, Field(description="Absolute path to trash.")],
    ) -> TrashResult:
        """Reversibly move a file or directory to the trash."""
        logger.info("trash_path(path=%r)", path)
        try:
            return guarded(
                context,
                tool="trash_path",
                arguments={"path": path},
                action=lambda: trash_entry(path, write_allowlist=write_allowlist),
            )
        except LinuxMCPError as exc:
            logger.warning("trash_path refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Permanently delete a path",
        description=(
            "PERMANENTLY delete a file or directory. This cannot be undone. "
            "Requires approval. Use trash_path instead when unsure."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def delete_path(
        path: Annotated[str, Field(description="Absolute path to delete permanently.")],
        recursive: Annotated[
            bool, Field(description="Required to delete a directory and its contents.")
        ] = False,
    ) -> DeleteResult:
        """Permanently delete a file or directory. Requires approval."""
        logger.info("delete_path(path=%r, recursive=%s)", path, recursive)
        try:
            return guarded(
                context,
                tool="delete_path",
                arguments={"path": path, "recursive": recursive},
                summary=f"Permanently delete {path}",
                details=f"rm -rf {path}" if recursive else f"rm {path}",
                action=lambda: delete_entry(
                    path, write_allowlist=write_allowlist, recursive=recursive
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("delete_path refused %r: %s", path, exc)
            raise ToolError(str(exc)) from exc
