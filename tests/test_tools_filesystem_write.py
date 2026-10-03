"""Write-side filesystem tools: writing, editing, moving, trashing, deleting."""

from __future__ import annotations

from pathlib import Path

import pytest

from linux_mcp.errors import (
    OperationRefusedError,
    PathDoesNotExistError,
    PathOutsideAllowlistError,
)
from linux_mcp.security import Allowlist
from linux_mcp.tools.filesystem_write import (
    copy_entry,
    delete_entry,
    edit_text_file,
    make_directory,
    move_entry,
    trash_entry,
    write_text_file,
)


@pytest.fixture
def allowlist(workspace) -> Allowlist:
    return Allowlist([workspace.allowed])


# --------------------------------------------------------------------------- #
# write_file
# --------------------------------------------------------------------------- #


def test_write_creates_a_new_file(allowlist, workspace) -> None:
    target = workspace.allowed / "new.txt"
    result = write_text_file(str(target), write_allowlist=allowlist, content="hello")
    assert result.created is True
    assert result.overwritten is False
    assert target.read_text(encoding="utf-8") == "hello"
    assert result.bytes_written == 5


def test_write_refuses_to_overwrite_without_the_flag(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        write_text_file(
            str(workspace.alpha), write_allowlist=allowlist, content="clobber"
        )
    assert workspace.alpha.read_text(encoding="utf-8") == "alpha"


def test_write_overwrites_when_asked(allowlist, workspace) -> None:
    result = write_text_file(
        str(workspace.alpha), write_allowlist=allowlist, content="replaced", overwrite=True
    )
    assert result.overwritten is True
    assert workspace.alpha.read_text(encoding="utf-8") == "replaced"


def test_write_creates_parents_when_asked(allowlist, workspace) -> None:
    target = workspace.allowed / "deep" / "nested" / "file.txt"
    write_text_file(
        str(target),
        write_allowlist=allowlist,
        content="deep",
        create_parents=True,
    )
    assert target.read_text(encoding="utf-8") == "deep"


def test_write_refuses_missing_parent_without_the_flag(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        write_text_file(
            str(workspace.allowed / "missing" / "file.txt"),
            write_allowlist=allowlist,
            content="x",
        )


def test_write_refuses_outside_the_allowlist(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        write_text_file(
            str(workspace.outside / "evil.txt"), write_allowlist=allowlist, content="x"
        )


def test_write_refuses_the_allowlist_root_itself(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        write_text_file(
            str(workspace.allowed), write_allowlist=allowlist, content="x", overwrite=True
        )


# --------------------------------------------------------------------------- #
# edit_file
# --------------------------------------------------------------------------- #


def test_edit_replaces_a_unique_snippet(allowlist, workspace) -> None:
    result = edit_text_file(
        str(workspace.alpha),
        read_allowlist=allowlist,
        write_allowlist=allowlist,
        old_text="alpha",
        new_text="omega",
    )
    assert result.replacements == 1
    assert workspace.alpha.read_text(encoding="utf-8") == "omega"


def test_edit_refuses_when_text_is_absent(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        edit_text_file(
            str(workspace.alpha),
            read_allowlist=allowlist,
            write_allowlist=allowlist,
            old_text="not-there",
            new_text="x",
        )


def test_edit_refuses_an_ambiguous_match(allowlist, workspace) -> None:
    (workspace.allowed / "dupes.txt").write_text("a a a", encoding="utf-8")
    with pytest.raises(OperationRefusedError):
        edit_text_file(
            str(workspace.allowed / "dupes.txt"),
            read_allowlist=allowlist,
            write_allowlist=allowlist,
            old_text="a",
            new_text="b",
        )


def test_edit_replace_all_handles_ambiguity(allowlist, workspace) -> None:
    target = workspace.allowed / "dupes.txt"
    target.write_text("a a a", encoding="utf-8")
    result = edit_text_file(
        str(target),
        read_allowlist=allowlist,
        write_allowlist=allowlist,
        old_text="a",
        new_text="b",
        replace_all=True,
    )
    assert result.replacements == 3
    assert target.read_text(encoding="utf-8") == "b b b"


def test_edit_refuses_a_file_outside_the_write_allowlist(workspace) -> None:
    read = Allowlist([workspace.allowed])
    write = Allowlist([workspace.nested])
    with pytest.raises(PathOutsideAllowlistError):
        edit_text_file(
            str(workspace.alpha),
            read_allowlist=read,
            write_allowlist=write,
            old_text="alpha",
            new_text="x",
        )


def test_edit_refuses_an_empty_old_text(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        edit_text_file(
            str(workspace.alpha),
            read_allowlist=allowlist,
            write_allowlist=allowlist,
            old_text="",
            new_text="x",
        )


# --------------------------------------------------------------------------- #
# create_directory
# --------------------------------------------------------------------------- #


def test_create_directory_makes_nested_paths(allowlist, workspace) -> None:
    target = workspace.allowed / "a" / "b" / "c"
    result = make_directory(str(target), write_allowlist=allowlist)
    assert result.created is True
    assert target.is_dir()


def test_create_directory_reports_an_existing_directory(allowlist, workspace) -> None:
    result = make_directory(str(workspace.nested), write_allowlist=allowlist)
    assert result.created is False


def test_create_directory_refuses_to_replace_a_file(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        make_directory(str(workspace.alpha), write_allowlist=allowlist)


# --------------------------------------------------------------------------- #
# move / copy
# --------------------------------------------------------------------------- #


def test_move_renames_within_the_allowlist(allowlist, workspace) -> None:
    destination = workspace.allowed / "renamed.txt"
    move_entry(str(workspace.alpha), str(destination), write_allowlist=allowlist)
    assert destination.read_text(encoding="utf-8") == "alpha"
    assert not workspace.alpha.exists()


def test_move_refuses_an_existing_destination(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        move_entry(str(workspace.alpha), str(workspace.hidden), write_allowlist=allowlist)


def test_move_refuses_a_missing_source(allowlist, workspace) -> None:
    with pytest.raises(PathDoesNotExistError):
        move_entry(
            str(workspace.allowed / "nope.txt"),
            str(workspace.allowed / "x.txt"),
            write_allowlist=allowlist,
        )


def test_copy_duplicates_a_file(allowlist, workspace) -> None:
    destination = workspace.allowed / "copy.txt"
    result = copy_entry(
        str(workspace.alpha),
        str(destination),
        read_allowlist=allowlist,
        write_allowlist=allowlist,
    )
    assert destination.read_text(encoding="utf-8") == "alpha"
    assert workspace.alpha.exists()
    assert result.entries_copied == 1


def test_copy_refuses_an_existing_destination(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        copy_entry(
            str(workspace.alpha),
            str(workspace.hidden),
            read_allowlist=allowlist,
            write_allowlist=allowlist,
        )


def test_copy_refuses_a_source_outside_the_read_allowlist(workspace) -> None:
    read = Allowlist([workspace.allowed])
    write = Allowlist([workspace.allowed])
    with pytest.raises(PathOutsideAllowlistError):
        copy_entry(
            str(workspace.outside / "secret.txt"),
            str(workspace.allowed / "stolen.txt"),
            read_allowlist=read,
            write_allowlist=write,
        )


# --------------------------------------------------------------------------- #
# trash_path
# --------------------------------------------------------------------------- #


def test_trash_moves_the_file_into_the_trash(allowlist, workspace) -> None:
    trash = workspace.root / "Trash"
    result = trash_entry(str(workspace.alpha), write_allowlist=allowlist, trash_directory=trash)
    assert not workspace.alpha.exists()
    assert Path(result.trashed_to).exists()
    assert Path(result.trashed_to).read_text(encoding="utf-8") == "alpha"
    info = trash / "info" / (Path(result.trashed_to).name + ".trashinfo")
    assert "Path=" in info.read_text(encoding="utf-8")


def test_trash_avoids_name_collisions(allowlist, workspace) -> None:
    trash = workspace.root / "Trash"
    (workspace.allowed / "one.txt").write_text("1", encoding="utf-8")
    (workspace.allowed / "two.txt").write_text("2", encoding="utf-8")
    first = trash_entry(
        str(workspace.allowed / "one.txt"), write_allowlist=allowlist, trash_directory=trash
    )
    second = trash_entry(
        str(workspace.allowed / "two.txt"), write_allowlist=allowlist, trash_directory=trash
    )
    assert first.trashed_to != second.trashed_to


def test_trash_refuses_a_missing_path(allowlist, workspace) -> None:
    with pytest.raises(PathDoesNotExistError):
        trash_entry(
            str(workspace.allowed / "gone.txt"),
            write_allowlist=allowlist,
            trash_directory=workspace.root / "Trash",
        )


# --------------------------------------------------------------------------- #
# delete_path (destructive)
# --------------------------------------------------------------------------- #


def test_delete_removes_a_file(allowlist, workspace) -> None:
    result = delete_entry(str(workspace.alpha), write_allowlist=allowlist)
    assert not workspace.alpha.exists()
    assert result.recursive is False
    assert result.entries_deleted == 1


def test_delete_refuses_a_directory_without_recursive(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        delete_entry(str(workspace.nested), write_allowlist=allowlist)
    assert workspace.nested.exists()


def test_delete_removes_a_directory_tree_when_recursive(allowlist, workspace) -> None:
    result = delete_entry(str(workspace.nested), write_allowlist=allowlist, recursive=True)
    assert not workspace.nested.exists()
    assert result.recursive is True


def test_delete_refuses_the_allowlist_root(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        delete_entry(str(workspace.allowed), write_allowlist=allowlist, recursive=True)
    assert workspace.allowed.exists()
