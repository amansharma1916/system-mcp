"""Write-path policy: creation targets are as strictly checked as reads."""

from __future__ import annotations

import pytest

from linux_mcp.errors import InvalidPathError, PathOutsideAllowlistError
from linux_mcp.security import Allowlist, canonicalize_write_path


@pytest.fixture
def allowlist(workspace) -> Allowlist:
    return Allowlist([workspace.allowed])


def test_existing_file_inside_allowlist_is_returned(allowlist, workspace) -> None:
    assert canonicalize_write_path(str(workspace.alpha), allowlist) == workspace.alpha


def test_new_file_inside_allowlist_is_allowed(allowlist, workspace) -> None:
    target = workspace.allowed / "brand-new.txt"
    assert canonicalize_write_path(str(target), allowlist) == target


def test_new_file_in_new_subdirectory_is_allowed(allowlist, workspace) -> None:
    target = workspace.allowed / "newdir" / "file.txt"
    assert canonicalize_write_path(str(target), allowlist) == target


def test_write_outside_allowlist_is_refused(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_write_path(str(workspace.outside / "evil.txt"), allowlist)


def test_traversal_escape_is_refused(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_write_path(str(workspace.allowed / ".." / "outside" / "x"), allowlist)


def test_traversal_past_nonexistent_directory_is_refused(allowlist, workspace) -> None:
    sneaky = workspace.allowed / "newdir" / ".." / ".." / "outside" / "x"
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_write_path(str(sneaky), allowlist)


def test_symlinked_parent_escaping_is_refused(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_write_path(str(workspace.symlink_escape / "x.txt"), allowlist)


def test_existing_symlink_escaping_is_refused(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_write_path(str(workspace.symlink_escape), allowlist)


def test_symlink_staying_inside_is_allowed(allowlist, workspace) -> None:
    target = workspace.symlink_inside / "new.txt"
    assert canonicalize_write_path(str(target), allowlist) == workspace.nested / "new.txt"


def test_relative_path_is_refused(allowlist) -> None:
    with pytest.raises(InvalidPathError):
        canonicalize_write_path("relative.txt", allowlist)
