"""Redaction: nothing secret may reach the audit log."""

from __future__ import annotations

from linux_mcp.redaction import (
    REDACTED,
    is_secret_key,
    redact_any,
    redact_mapping,
    redact_value,
)


def test_secret_keys_are_recognised_case_insensitively() -> None:
    for name in ("API_KEY", "github_token", "Password", "db_secret", "CREDENTIAL"):
        assert is_secret_key(name), name


def test_ordinary_keys_are_not_secret() -> None:
    for name in ("path", "argv", "cwd", "count", "monkey"):
        assert not is_secret_key(name), name


def test_redact_mapping_replaces_secret_keyed_values() -> None:
    result = redact_mapping({"path": "/tmp/x", "api_key": "whatever", "TOKEN": "abc"})
    assert result["path"] == "/tmp/x"
    assert result["api_key"] == REDACTED
    assert result["TOKEN"] == REDACTED


def test_redact_value_masks_known_token_shapes() -> None:
    assert "ghp_" not in redact_value("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    assert "sk-" not in redact_value("key sk-abcdefghijklmnopqrstuvwxyz")
    assert "AKIA" not in redact_value("aws AKIAIOSFODNN7EXAMPLE")
    assert "BEGIN RSA PRIVATE KEY" not in redact_value(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n"
    )


def test_redact_value_masks_password_assignments_and_bearer_tokens() -> None:
    assert REDACTED in redact_value("password=hunter2")
    assert REDACTED in redact_value("Authorization: Bearer abcdefghijklmnopqrstuv")


def test_redact_value_leaves_ordinary_text_alone() -> None:
    assert redact_value("ls -la /home/aman") == "ls -la /home/aman"


def test_redact_any_walks_nested_structures() -> None:
    data = {"outer": [{"api_key": "k"}, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"]}
    result = redact_any(data)
    assert result["outer"][0]["api_key"] == REDACTED
    assert REDACTED in result["outer"][1]


def test_redact_any_passes_through_non_strings() -> None:
    assert redact_any(5) == 5
    assert redact_any(None) is None
    assert redact_any(True) is True
