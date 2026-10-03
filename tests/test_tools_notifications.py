"""Notification tool: argv construction, validation, and missing-program errors."""

from __future__ import annotations

import pytest

from linux_mcp.errors import InvalidPathError, OperationRefusedError
from linux_mcp.tools import notifications as notifications_module
from linux_mcp.tools.notifications import notify


@pytest.fixture
def fake_notify(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(argv, *, purpose, timeout_seconds=15.0):
        calls.append(list(argv))
        return ""

    monkeypatch.setattr(
        notifications_module, "require_program", lambda name, purpose: "/usr/bin/notify-send"
    )
    monkeypatch.setattr(notifications_module, "run_program", fake_run)
    return calls


def test_notification_separates_text_from_options(fake_notify) -> None:
    result = notify("Build finished", "42 tests passed")
    assert result.sent is True
    assert result.urgency == "normal"
    # The '--' guard keeps a leading dash in the body from becoming an option.
    assert fake_notify[0] == [
        "/usr/bin/notify-send",
        "--urgency",
        "normal",
        "--",
        "Build finished",
        "42 tests passed",
    ]


def test_urgency_and_expiry_are_forwarded(fake_notify) -> None:
    notify("Danger", "disk full", urgency="critical", expire_ms=5000)
    argv = fake_notify[0]
    assert "--urgency" in argv
    assert "critical" in argv
    assert "--expire-time" in argv
    assert "5000" in argv


def test_an_empty_summary_is_refused(fake_notify) -> None:
    with pytest.raises(InvalidPathError):
        notify("   ")


def test_an_unknown_urgency_is_refused(fake_notify) -> None:
    with pytest.raises(InvalidPathError):
        notify("hi", urgency="urgent")


def test_a_negative_expiry_is_refused(fake_notify) -> None:
    with pytest.raises(InvalidPathError):
        notify("hi", expire_ms=-1)


def test_overlong_text_is_refused(fake_notify) -> None:
    with pytest.raises(InvalidPathError):
        notify("x" * 5000)


def test_missing_notify_send_is_reported_clearly(monkeypatch) -> None:
    def explode(name, *, purpose):
        raise OperationRefusedError(f"{purpose} requires the program {name!r}")

    monkeypatch.setattr(notifications_module, "require_program", explode)
    with pytest.raises(OperationRefusedError):
        notify("hello")
