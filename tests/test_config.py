"""Tests for configuration loading and validation.

Configuration is the user's trust anchor, so it is validated strictly: a typo,
an unknown key, or a policy in which every directory is missing must stop the
server rather than start it with something broader than intended.
"""

from __future__ import annotations

import logging
import shutil
import textwrap
from pathlib import Path

import pytest

from linux_mcp.config import (
    CONFIG_PATH_ENV,
    DEFAULT_MAX_ENTRIES,
    MAX_MAX_ENTRIES,
    Config,
    build_application_spec,
    load_config,
    parse_config,
    resolve_config_path,
)
from linux_mcp.errors import ConfigError
from tests.conftest import Workspace

EXAMPLE_CONFIG = Path(__file__).resolve().parents[1] / "config" / "config.example.yaml"


def write_config(tmp_path: Path, text: str, name: str = "config.yaml") -> Path:
    """Write a dedented YAML configuration file and return its path."""
    path = tmp_path / name
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return path


def test_loads_a_valid_configuration(workspace: Workspace, tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
            - {workspace.nested}
          max_entries: 25
        applications:
          allow:
            code: code
        """,
    )
    config = load_config(path)

    assert config.source == path
    assert config.directories.allow == tuple(sorted((workspace.allowed, workspace.nested), key=str))
    assert config.directories.max_entries == 25


def test_nested_allowed_directory_is_kept_separately(
    workspace: Workspace, tmp_path: Path
) -> None:
    """A nested entry is redundant but harmless; both are stored as given."""
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
            - {workspace.nested}
        """,
    )
    config = load_config(path)
    assert workspace.nested in config.directories.allow
    assert config.directories.allowlist().contains(workspace.nested)


def test_duplicate_directories_are_deduplicated(workspace: Workspace, tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
            - {workspace.allowed}/
            - {workspace.allowed}
        """,
    )
    config = load_config(path)
    assert config.directories.allow == (workspace.allowed,)


def test_tilde_and_variables_are_expanded(
    workspace: Workspace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(workspace.root))
    monkeypatch.setenv("ALLOWED_FROM_ENV", str(workspace.nested))
    path = write_config(
        tmp_path,
        """
        directories:
          allow:
            - ~/allowed
            - $ALLOWED_FROM_ENV
        """,
    )
    config = load_config(path)
    assert set(config.directories.allow) == {workspace.allowed, workspace.nested}


def test_undefined_variable_is_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        """
        directories:
          allow:
            - $SOME_UNDEFINED_VARIABLE_XYZ/Documents
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "Undefined variable" in str(excinfo.value)


def test_missing_directory_is_skipped_with_a_warning(
    workspace: Workspace, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed / "does-not-exist"}
            - {workspace.allowed}
        """,
    )
    with caplog.at_level(logging.WARNING, logger="linux_mcp.config"):
        config = load_config(path)

    assert config.directories.allow == (workspace.allowed,)
    assert "Ignoring configured directory" in caplog.text


def test_configuration_where_every_directory_is_missing_is_fatal(
    workspace: Workspace, tmp_path: Path
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed / "nope-1"}
            - {workspace.allowed / "nope-2"}
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "None of the configured directories" in str(excinfo.value)


def test_root_directory_is_allowed_but_warned_about(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = write_config(
        tmp_path,
        """
        directories:
          allow:
            - /
        """,
    )
    with caplog.at_level(logging.WARNING, logger="linux_mcp.config"):
        config = load_config(path)

    assert config.directories.allow == (Path("/"),)
    assert "almost the whole filesystem" in caplog.text


def test_max_entries_defaults(workspace: Workspace, tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        """,
    )
    assert load_config(path).directories.max_entries == DEFAULT_MAX_ENTRIES


@pytest.mark.parametrize("value", ["0", "-5", "many", "true", "1.5", str(MAX_MAX_ENTRIES + 1)])
def test_invalid_max_entries_are_rejected(
    workspace: Workspace, tmp_path: Path, value: str
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
          max_entries: {value}
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "max_entries" in str(excinfo.value)


def test_unknown_top_level_key_is_rejected(workspace: Workspace, tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        directory:
          allow:
            - {workspace.allowed}
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "Unknown configuration key" in str(excinfo.value)


def test_unknown_key_under_directories_is_rejected(workspace: Workspace, tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allowdirs:
            - {workspace.allowed}
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "Unknown key(s) under 'directories'" in str(excinfo.value)


def test_missing_directories_section_is_rejected(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        """
        applications:
          allow:
            code: code
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "'directories' is required" in str(excinfo.value)


@pytest.mark.parametrize(
    "content",
    ["directories: {allow: ~/Downloads}", "directories:\n  allow: ~/Downloads", "directories:\n  allow: []"],
)
def test_invalid_directories_section_is_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(content + "\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


@pytest.mark.parametrize("content", ["", "[]", "- a\n- b", "just a string"])
def test_non_mapping_documents_are_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_invalid_yaml_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("directories: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "Invalid YAML" in str(excinfo.value)


def test_explicitly_requested_missing_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path / "absent.yaml")
    assert "not found" in str(excinfo.value)


def test_environment_variable_selects_the_configuration_file(
    workspace: Workspace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        """,
    )
    monkeypatch.setenv(CONFIG_PATH_ENV, str(path))
    assert load_config().source == path


def test_environment_variable_pointing_at_a_missing_file_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CONFIG_PATH_ENV, str(tmp_path / "absent.yaml"))
    with pytest.raises(ConfigError) as excinfo:
        load_config()
    assert CONFIG_PATH_ENV in str(excinfo.value)


def test_missing_configuration_explains_how_to_create_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clear_mcp_env: None
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(ConfigError) as excinfo:
        load_config()
    message = str(excinfo.value)
    assert "No configuration file found" in message
    assert "config.example.yaml" in message


def test_example_configuration_file_is_valid(
    workspace: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The shipped example must always load, so documented copy-paste works."""
    for name in ("Documents", "Downloads", "Projects"):
        (workspace.root / name).mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(workspace.root))

    config = load_config(EXAMPLE_CONFIG)

    assert set(config.applications) == {"code", "brave", "firefox", "terminal", "files"}
    assert config.directories.max_entries == DEFAULT_MAX_ENTRIES
    assert {path.name for path in config.directories.allow} == {
        "Documents",
        "Downloads",
        "Projects",
    }


TRUE = shutil.which("true")
"""A harmless executable that exists on every Linux system, used as a stand-in."""


def test_application_shorthand_mapping_and_list_forms(
    workspace: Workspace, tmp_path: Path
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            short: "true"
            long:
              command: "true"
              description: A stand-in application
            withargs: ["true", --flag]
        """,
    )
    config = load_config(path)

    assert config.applications["short"].command == (TRUE,)
    assert config.applications["short"].description == ""
    assert config.applications["short"].available is True
    assert config.applications["long"].description == "A stand-in application"
    assert config.applications["withargs"].command == (TRUE, "--flag")
    assert config.available_application_names() == ("long", "short", "withargs")


def test_application_names_are_normalized_to_lowercase(
    workspace: Workspace, tmp_path: Path
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            "  Code  ": "true"
        """,
    )
    assert tuple(load_config(path).applications) == ("code",)


@pytest.mark.parametrize("name", ["my app", "code!", "two/words", "", "-dash-first", "Ünicode"])
def test_invalid_application_names_are_rejected(
    workspace: Workspace, tmp_path: Path, name: str
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            "{name}": "true"
        """,
    )
    with pytest.raises(ConfigError):
        load_config(path)


def test_command_with_whitespace_must_use_the_list_form(
    workspace: Workspace, tmp_path: Path
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            code: "code --new-window"
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "list form" in str(excinfo.value)


def test_absolute_command_with_shell_syntax_is_rejected(
    workspace: Workspace, tmp_path: Path
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            evil: "/usr/bin/true;rm"
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "metacharacters" in str(excinfo.value)


def test_command_containing_whitespace_is_rejected_before_metacharacters(
    workspace: Workspace, tmp_path: Path
) -> None:
    """A string command with a space is almost always an argument-smuggling typo."""
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            evil: "/usr/bin/true; rm -rf /"
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "whitespace" in str(excinfo.value)


def test_unquoted_yaml_boolean_command_is_rejected_with_a_hint(
    workspace: Workspace, tmp_path: Path
) -> None:
    """`code: yes` is a YAML boolean, so the error must explain quoting."""
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            code: yes
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    message = str(excinfo.value)
    assert "boolean" in message
    assert "quote" in message


def test_unknown_application_key_is_rejected(workspace: Workspace, tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            code:
              command: true
              args: [--flag]
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "Unknown key(s) for application" in str(excinfo.value)


def test_missing_executable_is_kept_but_marked_unavailable(
    workspace: Workspace, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            ghost: definitely-not-a-real-executable-xyz
        """,
    )
    with caplog.at_level(logging.WARNING, logger="linux_mcp.config"):
        config = load_config(path)

    ghost = config.applications["ghost"]
    assert ghost.available is False
    assert "not found on PATH" in (ghost.unavailable_reason or "")
    assert config.application_names() == ("ghost",)
    assert config.available_application_names() == ()
    assert "unavailable" in caplog.text


def test_missing_absolute_executable_is_marked_unavailable(
    workspace: Workspace, tmp_path: Path
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            ghost: /nonexistent/bin/ghost
        """,
    )
    ghost = load_config(path).applications["ghost"]
    assert ghost.available is False
    assert "not an executable file" in (ghost.unavailable_reason or "")


def test_disabled_application_is_unavailable(workspace: Workspace, tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            editor:
              command: "true"
              enabled: false
        """,
    )
    editor = load_config(path).applications["editor"]
    assert editor.available is False
    assert editor.unavailable_reason == "disabled in the configuration file"


def test_missing_applications_section_is_allowed_with_a_warning(
    workspace: Workspace, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        """,
    )
    with caplog.at_level(logging.WARNING, logger="linux_mcp.config"):
        config = load_config(path)

    assert config.applications == {}
    assert "open_application will refuse" in caplog.text


def test_applications_allow_must_be_a_mapping(workspace: Workspace, tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        f"""
        directories:
          allow:
            - {workspace.allowed}
        applications:
          allow:
            - code
        """,
    )
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert "must be a mapping" in str(excinfo.value)


def test_build_application_spec_resolves_bare_names_and_keeps_arguments() -> None:
    spec = build_application_spec("term", ["true", "--window", "--dir=/tmp"])
    assert spec.executable == TRUE
    assert spec.command == (TRUE, "--window", "--dir=/tmp")
    assert spec.available is True

    absolute = build_application_spec("abs", "/usr/bin/true")
    assert absolute.command == ("/usr/bin/true",)


def test_parse_config_accepts_pre_parsed_mappings(workspace: Workspace) -> None:
    config = parse_config(
        {
            "directories": {"allow": [str(workspace.allowed)]},
            "applications": {"allow": {"code": "true"}},
        },
        source=workspace.root / "in-memory.yaml",
    )
    assert isinstance(config, Config)
    assert config.applications["code"].command == (TRUE,)


def test_resolve_config_path_prefers_an_explicit_argument(
    workspace: Workspace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit = write_config(tmp_path, "directories:\n  allow:\n    - /tmp\n", "explicit.yaml")
    monkeypatch.setenv(CONFIG_PATH_ENV, str(tmp_path / "other.yaml"))
    assert resolve_config_path(explicit) == explicit