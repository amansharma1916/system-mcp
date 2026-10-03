"""Power tools. Nothing is executed: shutting down a test machine would be rude."""

from __future__ import annotations

import pytest

from linux_mcp.config import PowerConfig
from linux_mcp.errors import OperationRefusedError
from linux_mcp.tools import power as power_module
from linux_mcp.tools.power import lock, logout, system_action

EVERYTHING = PowerConfig(
    allow=frozenset({"lock", "logout", "suspend", "hibernate", "shutdown", "reboot"})
)


@pytest.fixture
def fake_power(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(argv, *, purpose, timeout_seconds=15.0, use_pkexec=False, stdin_data=None):
        calls.append(list(argv))
        return ""

    monkeypatch.setattr(power_module, "run_program", fake_run)
    monkeypatch.setattr(
        power_module, "require_program", lambda name, purpose: f"/usr/bin/{name}"
    )
    monkeypatch.setattr(
        power_module.shutil, "which", lambda name: f"/usr/bin/{name}"
    )
    return calls


def test_a_disallowed_action_is_refused_before_running(fake_power) -> None:
    strict = PowerConfig(allow=frozenset({"lock"}))
    with pytest.raises(OperationRefusedError) as excinfo:
        system_action(strict, "shutdown")
    message = str(excinfo.value)
    assert "power.allow" in message
    assert "shutdown" in message
    assert fake_power == [], "nothing may run when the action is not permitted"


def test_every_action_is_checked_against_the_allowlist(fake_power) -> None:
    empty = PowerConfig(allow=frozenset())
    for action in ("lock", "suspend", "hibernate", "shutdown", "reboot"):
        with pytest.raises(OperationRefusedError):
            system_action(empty, action)
    with pytest.raises(OperationRefusedError):
        logout(empty)


def test_lock_uses_loginctl(fake_power) -> None:
    result = lock(EVERYTHING)
    assert fake_power[0] == ["/usr/bin/loginctl", "lock-session"]
    assert result.action == "lock"


def test_shutdown_maps_to_poweroff(fake_power) -> None:
    result = system_action(EVERYTHING, "shutdown")
    assert fake_power[0] == ["/usr/bin/systemctl", "poweroff"]
    assert result.action == "shutdown"


def test_reboot_maps_to_reboot(fake_power) -> None:
    system_action(EVERYTHING, "reboot")
    assert fake_power[0] == ["/usr/bin/systemctl", "reboot"]


def test_suspend_maps_to_suspend(fake_power) -> None:
    system_action(EVERYTHING, "suspend")
    assert fake_power[0] == ["/usr/bin/systemctl", "suspend"]


def test_hibernate_maps_to_hibernate(fake_power) -> None:
    system_action(EVERYTHING, "hibernate")
    assert fake_power[0] == ["/usr/bin/systemctl", "hibernate"]


def test_logout_prefers_gnome_session_quit(fake_power) -> None:
    logout(EVERYTHING)
    assert fake_power[0] == ["/usr/bin/gnome-session-quit", "--logout", "--no-prompt"]


def test_logout_falls_back_to_loginctl(monkeypatch, fake_power) -> None:
    monkeypatch.setattr(
        power_module.shutil,
        "which",
        lambda name: None if name == "gnome-session-quit" else f"/usr/bin/{name}",
    )
    monkeypatch.setenv("XDG_SESSION_ID", "7")
    logout(EVERYTHING)
    assert fake_power[0] == ["/usr/bin/loginctl", "terminate-session", "7"]


def test_logout_without_any_mechanism_is_refused(monkeypatch, fake_power) -> None:
    monkeypatch.setattr(power_module.shutil, "which", lambda name: None)
    monkeypatch.delenv("XDG_SESSION_ID", raising=False)
    with pytest.raises(OperationRefusedError):
        logout(EVERYTHING)
