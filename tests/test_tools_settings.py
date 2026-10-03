"""Desktop settings tools: validation, reads, and writes."""

from __future__ import annotations

import pytest

from linux_mcp.errors import InvalidPathError, OperationRefusedError
from linux_mcp.tools import settings as settings_module
from linux_mcp.tools.settings import (
    collect_settings,
    read_setting,
    write_setting,
)


@pytest.fixture
def fake_gsettings(monkeypatch):
    """Capture the argv passed to gsettings and return canned output."""
    calls: list[list[str]] = []
    responses: list[str] = []

    def fake_run(argv, *, purpose, timeout_seconds=15.0):
        calls.append(list(argv))
        return responses.pop(0) if responses else ""

    monkeypatch.setattr(
        settings_module, "require_program", lambda name, purpose: "/usr/bin/gsettings"
    )
    monkeypatch.setattr(settings_module, "run_program", fake_run)
    return calls, responses


def test_read_setting_strips_the_gvariant_output(fake_gsettings) -> None:
    calls, responses = fake_gsettings
    responses.append("'prefer-dark'\n")
    result = read_setting("org.gnome.desktop.interface", "color-scheme")
    assert result.value == "'prefer-dark'"
    assert calls[0] == [
        "/usr/bin/gsettings",
        "get",
        "org.gnome.desktop.interface",
        "color-scheme",
    ]


def test_write_setting_sets_then_reads_back(fake_gsettings) -> None:
    calls, responses = fake_gsettings
    responses.extend(["", "'dark'\n"])
    result = write_setting("org.gnome.desktop.interface", "color-scheme", "'dark'")
    assert result.value == "'dark'"
    assert calls[0] == [
        "/usr/bin/gsettings",
        "set",
        "org.gnome.desktop.interface",
        "color-scheme",
        "'dark'",
    ]
    assert calls[1][1] == "get"


def test_list_settings_lists_schemas_when_no_schema_given(fake_gsettings) -> None:
    calls, responses = fake_gsettings
    responses.append("org.gnome.desktop.interface\norg.gnome.shell\n")
    result = collect_settings()
    assert result.scope == "schemas"
    assert result.entries == ["org.gnome.desktop.interface", "org.gnome.shell"]
    assert calls[0][1] == "list-schemas"


def test_list_settings_lists_keys_for_a_schema(fake_gsettings) -> None:
    calls, responses = fake_gsettings
    responses.append("color-scheme\ngtk-theme\n")
    result = collect_settings("org.gnome.desktop.interface")
    assert result.scope == "org.gnome.desktop.interface"
    assert result.total == 2
    assert calls[0][1] == "list-keys"


def test_schema_names_are_validated(fake_gsettings) -> None:
    for bad in ("-oops", "with space", "", "a/b", "a;b"):
        with pytest.raises(InvalidPathError):
            read_setting(bad, "color-scheme")


def test_key_names_are_validated(fake_gsettings) -> None:
    for bad in ("--flag", "with space", ""):
        with pytest.raises(InvalidPathError):
            read_setting("org.gnome.desktop.interface", bad)


def test_write_rejects_a_value_that_looks_like_a_flag(fake_gsettings) -> None:
    with pytest.raises(InvalidPathError):
        write_setting("org.gnome.desktop.interface", "color-scheme", "--default")


def test_write_rejects_a_value_with_a_newline(fake_gsettings) -> None:
    with pytest.raises(InvalidPathError):
        write_setting("org.gnome.desktop.interface", "color-scheme", "'a\nb'")


def test_missing_gsettings_is_reported_clearly(monkeypatch) -> None:
    def explode(name, *, purpose):
        raise OperationRefusedError(f"{purpose} requires the program {name!r}")

    monkeypatch.setattr(settings_module, "require_program", explode)
    with pytest.raises(OperationRefusedError):
        read_setting("org.gnome.desktop.interface", "color-scheme")


def test_real_gsettings_can_read_a_safe_key() -> None:
    """Integration check against the real gsettings, read-only and harmless."""
    result = read_setting("org.gnome.desktop.interface", "color-scheme")
    assert result.value
    assert result.schema_name == "org.gnome.desktop.interface"
