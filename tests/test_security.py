"""Tests for the filesystem security policy.

These are the tests that matter most: if any of them fails, the server can read
something the user did not allow. They call :mod:`linux_mcp.security` directly,
so no MCP machinery is involved.
"""

from __future__ import annotations

import pytest

from linux_mcp.errors import (
    ConfigError,
    InvalidPathError,
    LinuxMCPError,
    PathDoesNotExistError,
    PathNotDirectoryError,
    PathOutsideAllowlistError,
)
from linux_mcp.security import (
    Allowlist,
    canonicalize_configured_directory,
    canonicalize_directory,
    contains_shell_metacharacters,
    expand_variables,
    is_symlink_escape,
    read_symlink_target,
    validate_command_arguments,
    validate_command_name,
)
from tests.conftest import Workspace


@pytest.fixture
def allowlist(workspace: Workspace) -> Allowlist:
    return Allowlist((workspace.allowed,))


def test_allowed_directory_is_returned_resolved(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    assert canonicalize_directory(str(workspace.allowed), allowlist) == workspace.allowed


def test_subdirectory_of_an_allowed_directory_is_allowed(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    assert canonicalize_directory(str(workspace.nested), allowlist) == workspace.nested


def test_tilde_is_expanded_for_the_model(
    workspace: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(workspace.root))
    allowlist = Allowlist((workspace.root,))
    assert canonicalize_directory("~/allowed", allowlist) == workspace.allowed


def test_directory_outside_the_allowlist_is_refused(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    with pytest.raises(PathOutsideAllowlistError) as excinfo:
        canonicalize_directory(str(workspace.outside), allowlist)
    message = str(excinfo.value)
    assert "Permission denied" in message
    assert "outside the configured allowed directories" in message
    assert str(workspace.allowed) in message  # tells the model what is allowed


def test_neighbouring_directory_with_a_shared_prefix_is_refused(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    """``allowed_evil`` starts with ``allowed`` but is a different directory."""
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_directory(str(workspace.sibling), allowlist)


@pytest.mark.parametrize("escape", ["..", "../..", "../../..", "nested/../..", "./../outside"])
def test_traversal_cannot_escape_the_allowlist(
    workspace: Workspace, allowlist: Allowlist, escape: str
) -> None:
    requested = f"{workspace.allowed}/{escape}"
    with pytest.raises(LinuxMCPError) as excinfo:
        canonicalize_directory(requested, allowlist)
    assert isinstance(excinfo.value, (PathOutsideAllowlistError, PathDoesNotExistError))


def test_traversal_to_a_real_directory_is_refused(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    """The example from the specification: /home/aman/Downloads/../../etc.

    The number of ``..`` components is deliberately larger than the tree depth,
    so the requested path lands on the real ``/etc`` rather than on a
    non-existent temporary directory.
    """
    requested = f"{workspace.allowed}/{'../' * 20}etc"
    with pytest.raises(PathOutsideAllowlistError) as excinfo:
        canonicalize_directory(requested, allowlist)
    message = str(excinfo.value)
    assert "Permission denied" in message
    assert "It resolves to /etc" in message


def test_symlink_pointing_outside_the_allowlist_is_refused(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    with pytest.raises(PathOutsideAllowlistError) as excinfo:
        canonicalize_directory(str(workspace.symlink_escape), allowlist)
    message = str(excinfo.value)
    assert "It resolves to" in message  # explains that the link left the allowlist
    assert str(workspace.outside) in message


def test_symlink_staying_inside_the_allowlist_is_browsable(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    assert canonicalize_directory(str(workspace.symlink_inside), allowlist) == workspace.nested


def test_dangling_symlink_is_reported_as_missing(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    with pytest.raises(PathDoesNotExistError):
        canonicalize_directory(str(workspace.symlink_broken), allowlist)


def test_nonexistent_directory_is_reported(workspace: Workspace, allowlist: Allowlist) -> None:
    with pytest.raises(PathDoesNotExistError) as excinfo:
        canonicalize_directory(str(workspace.allowed / "ghost"), allowlist)
    assert "does not exist" in str(excinfo.value)


def test_file_inside_the_allowlist_is_not_a_directory(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    with pytest.raises(PathNotDirectoryError) as excinfo:
        canonicalize_directory(str(workspace.alpha), allowlist)
    assert "Not a directory" in str(excinfo.value)


def test_path_below_a_file_is_refused(workspace: Workspace, allowlist: Allowlist) -> None:
    with pytest.raises(PathNotDirectoryError):
        canonicalize_directory(str(workspace.alpha / "child"), allowlist)


def test_symlink_escape_helper_flags_links_and_ignores_regular_files(
    workspace: Workspace, allowlist: Allowlist
) -> None:
    assert is_symlink_escape(workspace.alpha, allowlist) is False
    assert is_symlink_escape(workspace.symlink_escape, allowlist) is True
    assert is_symlink_escape(workspace.symlink_inside, allowlist) is False


def test_read_symlink_target_returns_none_for_regular_files(workspace: Workspace) -> None:
    assert read_symlink_target(workspace.symlink_escape) == str(workspace.outside)
    assert read_symlink_target(workspace.alpha) is None


def test_allowlist_requires_at_least_one_root() -> None:
    with pytest.raises(ConfigError):
        Allowlist([])


def test_allowlist_deduplicates_and_sorts(workspace: Workspace) -> None:
    allowlist = Allowlist([workspace.allowed, workspace.allowed, workspace.nested])
    assert allowlist.roots == tuple(sorted({workspace.allowed, workspace.nested}, key=str))
    assert str(workspace.allowed) in allowlist.describe()


def test_configured_directory_expands_variables(workspace: Workspace) -> None:
    env = {"MY_ALLOWED_DIR": str(workspace.nested)}
    assert canonicalize_configured_directory("${MY_ALLOWED_DIR}", env=env) == workspace.nested
    assert canonicalize_configured_directory("$MY_ALLOWED_DIR/..", env=env) == workspace.allowed


def test_configured_directory_may_follow_a_symlink(workspace: Workspace) -> None:
    """The user's own configuration is the trust anchor, so links are resolved."""
    assert canonicalize_configured_directory(str(workspace.symlink_inside)) == workspace.nested


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "Downloads", "./Downloads", "Documents/../Downloads"],
)
def test_relative_and_empty_paths_are_refused(raw: str, allowlist: Allowlist) -> None:
    with pytest.raises(InvalidPathError):
        canonicalize_directory(raw, allowlist)


@pytest.mark.parametrize("raw", ["/tmp/\x00etc", "/tmp/a\nb", "/tmp/a\rb"])
def test_control_characters_are_refused(raw: str, allowlist: Allowlist) -> None:
    with pytest.raises(InvalidPathError):
        canonicalize_directory(raw, allowlist)


@pytest.mark.parametrize("raw", [None, 42, b"/tmp", ["/tmp"], {"path": "/tmp"}])
def test_non_string_paths_are_refused(raw: object, allowlist: Allowlist) -> None:
    with pytest.raises(InvalidPathError):
        canonicalize_directory(raw, allowlist)  # type: ignore[arg-type]


def test_environment_variables_are_not_expanded_for_the_model(
    monkeypatch: pytest.MonkeyPatch, workspace: Workspace
) -> None:
    """Only ``~`` is expanded for model input; ``$VAR`` stays literal and fails."""
    monkeypatch.setenv("SECRET_DIR", str(workspace.allowed))
    with pytest.raises(InvalidPathError):
        canonicalize_directory("$SECRET_DIR", Allowlist((workspace.allowed,)))


@pytest.mark.parametrize(
    "name",
    ["code", "gnome-terminal", "my_app-2", "python3.14", "org.gnome.Terminal"],
)
def test_valid_bare_command_names_are_accepted(name: str) -> None:
    validate_command_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "foo bar",
        "foo;rm -rf /",
        "foo/bar",
        "/usr/bin/foo",
        "foo|bar",
        "foo&bar",
        "foo$(id)",
        "foo`id`",
        "foo>out",
        "foo\nbar",
    ],
)
def test_bare_command_names_with_shell_syntax_are_rejected(name: str) -> None:
    with pytest.raises(ConfigError):
        validate_command_name(name)


def test_command_arguments_reject_non_strings_and_control_characters() -> None:
    validate_command_arguments(["--window", "--working-directory=/tmp"])
    for bad in ([1], ["a\x00b"], ["a\nb"], ["a\rb"]):
        with pytest.raises(ConfigError):
            validate_command_arguments(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("gnome-terminal", False),
        ("/usr/bin/code", False),
        ("code; rm -rf /", True),
        ("code && whoami", True),
        ("$(id)", True),
        ("`id`", True),
        ("code | tee out", True),
        ("code > out", True),
        ("code\nwhoami", True),
    ],
)
def test_shell_metacharacter_detection(value: str, expected: bool) -> None:
    assert contains_shell_metacharacters(value) is expected


def test_undefined_variable_in_configuration_is_an_error() -> None:
    with pytest.raises(ConfigError) as excinfo:
        expand_variables("${NOT_SET_ANYWHERE}/Documents", {})
    assert "Undefined variable" in str(excinfo.value)


def test_variables_can_be_left_literal_when_not_strict() -> None:
    assert expand_variables("$NOT_SET/Downloads", {}, strict=False) == "$NOT_SET/Downloads"


def test_variables_expand_in_both_forms() -> None:
    env = {"DIR": "/srv/data"}
    assert expand_variables("$DIR/x", env) == "/srv/data/x"
    assert expand_variables("${DIR}/x", env) == "/srv/data/x"