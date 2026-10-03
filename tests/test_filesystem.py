"""Tests for the ``browse_files`` tool.

Two layers are covered: :func:`linux_mcp.tools.filesystem.list_directory` for the
listing contract, and the registered MCP tool through an in-process client for
the schema, the description, and the ``ToolError`` mapping.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from linux_mcp.config import Config, DirectoryPolicy
from linux_mcp.errors import (
    PathDoesNotExistError,
    PathNotDirectoryError,
    PathOutsideAllowlistError,
)
from linux_mcp.tools.filesystem import list_directory
from tests.conftest import Workspace

LIST_ENTRY_NAMES = {"nested", "alpha.txt", ".hidden", "escape", "inside", "broken"}


def test_lists_files_directories_and_symlinks(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    result = list_directory(str(workspace.allowed), policy=make_config().directories)

    assert result.requested_path == str(workspace.allowed)
    assert result.path == str(workspace.allowed)
    assert result.parent == str(workspace.root)
    assert result.allowed_directories == [str(workspace.allowed)]
    assert result.total_entries == 6
    assert result.truncated is False
    assert {entry.name for entry in result.entries} == LIST_ENTRY_NAMES


def test_entry_types_distinguish_files_directories_and_symlinks(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    result = list_directory(str(workspace.allowed), policy=make_config().directories)
    types = {entry.name: entry.type for entry in result.entries}

    assert types["nested"] == "directory"
    assert types["alpha.txt"] == "file"
    assert types[".hidden"] == "file"
    assert types["escape"] == "symlink"
    assert types["inside"] == "symlink"
    assert types["broken"] == "symlink"


def test_entries_are_sorted_directories_symlinks_then_files(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    result = list_directory(str(workspace.allowed), policy=make_config().directories)
    assert [entry.type for entry in result.entries] == [
        "directory",
        "symlink",
        "symlink",
        "symlink",
        "file",
        "file",
    ]
    assert [entry.name for entry in result.entries] == [
        "nested",
        "broken",
        "escape",
        "inside",
        ".hidden",
        "alpha.txt",
    ]


def test_sizes_and_timestamps_are_reported(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    result = list_directory(str(workspace.allowed), policy=make_config().directories)
    entries = {entry.name: entry for entry in result.entries}

    assert entries["alpha.txt"].size_bytes == len("alpha")
    assert entries[".hidden"].size_bytes == len("hidden file")
    assert entries["nested"].size_bytes is None  # no size for directories
    assert entries["escape"].size_bytes is None  # and none for symlinks
    assert entries["alpha.txt"].modified is not None
    assert entries["alpha.txt"].modified.endswith("+00:00")  # ISO 8601 UTC


def test_hidden_entries_are_flagged_but_still_listed(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    result = list_directory(str(workspace.allowed), policy=make_config().directories)
    entries = {entry.name: entry for entry in result.entries}

    assert entries[".hidden"].hidden is True
    assert entries["alpha.txt"].hidden is False


def test_symlinks_are_described_but_never_followed(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    result = list_directory(str(workspace.allowed), policy=make_config().directories)
    entries = {entry.name: entry for entry in result.entries}

    escaping = entries["escape"]
    assert escaping.is_symlink is True
    assert escaping.symlink_target == str(workspace.outside)
    assert escaping.escapes_allowed_directories is True

    inside = entries["inside"]
    assert inside.symlink_target == str(workspace.nested)
    assert inside.escapes_allowed_directories is False

    dangling = entries["broken"]
    assert dangling.is_symlink is True
    assert dangling.escapes_allowed_directories is False


def test_listing_succeeds_even_when_a_link_target_is_unreachable(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    """Proves the target is never opened: listing works with it locked down."""
    workspace.outside.chmod(0o000)
    try:
        result = list_directory(str(workspace.allowed), policy=make_config().directories)
    finally:
        workspace.outside.chmod(0o755)

    assert {entry.name for entry in result.entries} == LIST_ENTRY_NAMES


def test_nested_directory_can_be_listed(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    result = list_directory(str(workspace.nested), policy=make_config().directories)
    assert [entry.name for entry in result.entries] == ["inner.txt"]


def test_entries_are_limited_by_max_entries(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    policy = make_config(max_entries=2).directories
    result = list_directory(str(workspace.allowed), policy=policy)

    assert len(result.entries) == 2
    assert result.total_entries == 6
    assert result.truncated is True


def test_root_directory_has_no_parent(make_config: Callable[..., Config]) -> None:
    policy = DirectoryPolicy(allow=(Path("/"),), max_entries=5)
    result = list_directory("/", policy=policy)

    assert result.path == "/"
    assert result.parent is None


def test_outside_allowlist_is_refused_at_tool_level(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        list_directory(str(workspace.outside), policy=make_config().directories)


def test_traversal_is_refused_at_tool_level(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        list_directory(f"{workspace.allowed}/{'../' * 20}etc", policy=make_config().directories)


def test_symlink_escape_is_refused_at_tool_level(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        list_directory(str(workspace.symlink_escape), policy=make_config().directories)


def test_file_is_not_a_directory_at_tool_level(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    with pytest.raises(PathNotDirectoryError):
        list_directory(str(workspace.alpha), policy=make_config().directories)


def test_missing_directory_is_reported_at_tool_level(
    workspace: Workspace, make_config: Callable[..., Config]
) -> None:
    config = make_config(allow=[workspace.outside])
    with pytest.raises(PathDoesNotExistError):
        list_directory(str(workspace.outside / "ghost"), policy=config.directories)


def text_of(result) -> str:
    """Concatenate every text block of a CallToolResult."""
    return "\n".join(block.text for block in result.content if block.type == "text")


@pytest.mark.anyio
async def test_tool_is_registered_with_a_model_friendly_schema(
    make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config()) as client:
        tools = await client.list_tools()

    tool = next(item for item in tools.tools if item.name == "browse_files")
    assert tool.description.startswith(
        "List files and directories inside an allowed Linux directory."
    )
    assert "does not read file contents" in tool.description
    assert "Allowed directories:" in tool.description
    assert tool.input_schema["required"] == ["path"]
    assert tool.input_schema["properties"]["path"]["type"] == "string"
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.open_world_hint is False


@pytest.mark.anyio
async def test_tool_returns_structured_entries(
    workspace: Workspace, make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config()) as client:
        result = await client.call_tool("browse_files", {"path": str(workspace.allowed)})

    assert result.is_error is False
    payload = result.structured_content
    assert payload["path"] == str(workspace.allowed)
    assert payload["allowed_directories"] == [str(workspace.allowed)]
    assert payload["total_entries"] == 6
    assert {entry["name"] for entry in payload["entries"]} == LIST_ENTRY_NAMES

    # The text block mirrors the structured payload, so plain-text-only clients
    # still get usable output.
    rendered = text_of(result)
    assert json.loads(rendered)["path"] == str(workspace.allowed)
    assert "alpha.txt" in rendered


@pytest.mark.anyio
async def test_tool_denies_outside_paths(
    workspace: Workspace, make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config()) as client:
        result = await client.call_tool("browse_files", {"path": str(workspace.outside)})

    assert result.is_error is True
    message = text_of(result)
    assert "Permission denied" in message
    assert "outside the configured allowed directories" in message
    assert str(workspace.allowed) in message
    assert result.structured_content is None


@pytest.mark.anyio
async def test_tool_denies_traversal_and_symlink_escapes(
    workspace: Workspace, make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config()) as client:
        traversal = await client.call_tool(
            "browse_files", {"path": f"{workspace.allowed}/{'../' * 20}etc"}
        )
        link = await client.call_tool("browse_files", {"path": str(workspace.symlink_escape)})

    for result in (traversal, link):
        assert result.is_error is True
        assert "Permission denied" in text_of(result)


@pytest.mark.anyio
async def test_tool_explains_invalid_and_missing_paths(
    workspace: Workspace, make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config()) as client:
        relative = await client.call_tool("browse_files", {"path": "Downloads"})
        missing = await client.call_tool(
            "browse_files", {"path": str(workspace.allowed / "ghost")}
        )
        a_file = await client.call_tool("browse_files", {"path": str(workspace.alpha)})

    assert relative.is_error is True
    assert "must be absolute" in text_of(relative)

    assert missing.is_error is True
    assert "does not exist" in text_of(missing)

    assert a_file.is_error is True
    assert "Not a directory" in text_of(a_file)


@pytest.mark.anyio
async def test_tool_rejects_a_missing_argument(
    make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config()) as client:
        result = await client.call_tool("browse_files", {})

    assert result.is_error is True
    assert "validation error" in text_of(result)


@pytest.mark.anyio
async def test_tool_rejects_a_wrong_argument_type(
    make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config()) as client:
        result = await client.call_tool("browse_files", {"path": 42})

    assert result.is_error is True
    assert "validation error" in text_of(result)