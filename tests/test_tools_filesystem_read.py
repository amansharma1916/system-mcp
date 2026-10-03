"""Read-only filesystem tools: reading, metadata, hashing, and search."""

from __future__ import annotations

import hashlib

import pytest

from linux_mcp.errors import (
    DirectoryReadError,
    InvalidPathError,
    PathOutsideAllowlistError,
)
from linux_mcp.security import Allowlist
from linux_mcp.tools.filesystem_read import (
    compute_checksum,
    describe_file,
    find_files,
    grep_files,
    read_text_file,
    walk_tree,
)


@pytest.fixture
def allowlist(workspace) -> Allowlist:
    return Allowlist([workspace.allowed])


# --------------------------------------------------------------------------- #
# read_file
# --------------------------------------------------------------------------- #


def test_read_file_returns_content(allowlist, workspace) -> None:
    result = read_text_file(str(workspace.alpha), allowlist=allowlist, max_bytes=1000)
    assert result.content == "alpha"
    assert result.size_bytes == 5
    assert result.bytes_read == 5
    assert result.truncated is False


def test_read_file_honours_offset_and_limit(allowlist, workspace) -> None:
    result = read_text_file(
        str(workspace.alpha), allowlist=allowlist, max_bytes=1000, offset=1, limit_bytes=2
    )
    assert result.content == "lp"
    assert result.truncated is True


def test_read_file_caps_at_max_bytes(allowlist, workspace) -> None:
    (workspace.allowed / "big.txt").write_text("x" * 5000, encoding="utf-8")
    result = read_text_file(
        str(workspace.allowed / "big.txt"), allowlist=allowlist, max_bytes=100
    )
    assert result.bytes_read == 100
    assert result.truncated is True


def test_read_file_refuses_a_directory(allowlist, workspace) -> None:
    with pytest.raises(DirectoryReadError):
        read_text_file(str(workspace.nested), allowlist=allowlist, max_bytes=100)


def test_read_file_refuses_outside_the_allowlist(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        read_text_file(str(workspace.outside / "secret.txt"), allowlist=allowlist, max_bytes=100)


def test_read_file_refuses_a_negative_offset(allowlist, workspace) -> None:
    with pytest.raises(InvalidPathError):
        read_text_file(
            str(workspace.alpha), allowlist=allowlist, max_bytes=100, offset=-1
        )


# --------------------------------------------------------------------------- #
# file_info
# --------------------------------------------------------------------------- #


def test_file_info_describes_a_file(allowlist, workspace) -> None:
    info = describe_file(str(workspace.alpha), allowlist=allowlist)
    assert info.type == "file"
    assert info.size_bytes == 5
    assert info.mode.startswith("-")
    assert info.owner
    assert info.group
    assert info.mime_type == "text/plain"


def test_file_info_describes_a_directory(allowlist, workspace) -> None:
    info = describe_file(str(workspace.nested), allowlist=allowlist)
    assert info.type == "directory"
    assert info.mode.startswith("d")


def test_file_info_refuses_outside_the_allowlist(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        describe_file(str(workspace.outside), allowlist=allowlist)


# --------------------------------------------------------------------------- #
# checksum
# --------------------------------------------------------------------------- #


def test_checksum_matches_hashlib(allowlist, workspace) -> None:
    result = compute_checksum(str(workspace.alpha), allowlist=allowlist)
    assert result.algorithm == "sha256"
    assert result.digest == hashlib.sha256(b"alpha").hexdigest()
    assert result.size_bytes == 5


def test_checksum_supports_other_algorithms(allowlist, workspace) -> None:
    result = compute_checksum(str(workspace.alpha), allowlist=allowlist, algorithm="md5")
    assert result.digest == hashlib.md5(b"alpha").hexdigest()


def test_checksum_refuses_an_unknown_algorithm(allowlist, workspace) -> None:
    with pytest.raises(InvalidPathError):
        compute_checksum(str(workspace.alpha), allowlist=allowlist, algorithm="crc32")


def test_checksum_refuses_a_directory(allowlist, workspace) -> None:
    with pytest.raises(DirectoryReadError):
        compute_checksum(str(workspace.nested), allowlist=allowlist)


# --------------------------------------------------------------------------- #
# search_files
# --------------------------------------------------------------------------- #


def test_search_files_matches_a_glob(allowlist, workspace) -> None:
    result = find_files(str(workspace.allowed), allowlist=allowlist, pattern="*.txt")
    assert sorted(result.matches) == sorted(
        [str(workspace.alpha), str(workspace.nested / "inner.txt")]
    )
    assert result.truncated is False


def test_search_files_skips_hidden_by_default(allowlist, workspace) -> None:
    result = find_files(str(workspace.allowed), allowlist=allowlist, pattern="*")
    assert not any(".hidden" in match for match in result.matches)
    included = find_files(
        str(workspace.allowed), allowlist=allowlist, pattern="*", include_hidden=True
    )
    assert any(".hidden" in match for match in included.matches)


def test_search_files_truncates_at_max_results(allowlist, workspace) -> None:
    result = find_files(
        str(workspace.allowed), allowlist=allowlist, pattern="*.txt", max_results=1
    )
    assert len(result.matches) == 1
    assert result.truncated is True


def test_search_files_refuses_outside_the_allowlist(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        find_files(str(workspace.outside), allowlist=allowlist, pattern="*")


# --------------------------------------------------------------------------- #
# search_content
# --------------------------------------------------------------------------- #


def test_search_content_finds_a_line(allowlist, workspace) -> None:
    result = grep_files(str(workspace.allowed), allowlist=allowlist, pattern="alpha")
    assert len(result.matches) == 1
    assert result.matches[0].line == "alpha"
    assert result.matches[0].line_number == 1
    assert result.matches[0].path == str(workspace.alpha)


def test_search_content_honours_a_glob(allowlist, workspace) -> None:
    result = grep_files(
        str(workspace.allowed), allowlist=allowlist, pattern="inner", glob="*.md"
    )
    assert result.matches == []


def test_search_content_refuses_an_invalid_regex(allowlist, workspace) -> None:
    with pytest.raises(InvalidPathError):
        grep_files(str(workspace.allowed), allowlist=allowlist, pattern="[")


def test_search_content_skips_binary_files(allowlist, workspace) -> None:
    (workspace.allowed / "blob.bin").write_bytes(b"\x00\x01alpha\x00")
    result = grep_files(str(workspace.allowed), allowlist=allowlist, pattern="alpha")
    assert all(not match.path.endswith("blob.bin") for match in result.matches)


# --------------------------------------------------------------------------- #
# list_tree
# --------------------------------------------------------------------------- #


def test_list_tree_lists_children_and_respects_depth(allowlist, workspace) -> None:
    result = walk_tree(str(workspace.allowed), allowlist=allowlist, max_depth=1)
    names = {entry.name for entry in result.entries}
    assert "alpha.txt" in names
    assert "nested" in names
    # max_depth=1 means children of "nested" are not listed.
    assert "inner.txt" not in names


def test_list_tree_descends_when_depth_allows(allowlist, workspace) -> None:
    result = walk_tree(str(workspace.allowed), allowlist=allowlist, max_depth=3)
    assert "inner.txt" in {entry.name for entry in result.entries}


def test_list_tree_describes_symlinks_without_following(allowlist, workspace) -> None:
    result = walk_tree(str(workspace.allowed), allowlist=allowlist, max_depth=3)
    kinds = {entry.name: entry.type for entry in result.entries}
    assert kinds["escape"] == "symlink"
    assert kinds["inside"] == "symlink"
    # The escape symlink points outside the allowlist; its contents must not appear.
    assert "secret.txt" not in kinds


def test_list_tree_truncates_at_max_entries(allowlist, workspace) -> None:
    result = walk_tree(
        str(workspace.allowed), allowlist=allowlist, max_depth=3, max_entries=2
    )
    assert len(result.entries) == 2
    assert result.truncated is True


def test_list_tree_refuses_a_file(allowlist, workspace) -> None:
    with pytest.raises(DirectoryReadError):
        walk_tree(str(workspace.alpha), allowlist=allowlist)
