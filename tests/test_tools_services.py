"""Service tools. systemctl is always mocked: no test restarts a real service."""

from __future__ import annotations

import pytest

from linux_mcp.config import CommandsConfig
from linux_mcp.errors import InvalidPathError, OperationRefusedError
from linux_mcp.tools import services as services_module
from linux_mcp.tools.services import control_unit, list_units, unit_status

LIST_OUTPUT = """\
gdm.service                 loaded active running GNOME Display Manager
sshd.service                loaded inactive dead    OpenSSH Daemon
not-found.service           not-found inactive dead    not-found.service
"""


@pytest.fixture
def fake_systemctl(monkeypatch):
    calls: list[list[str]] = []
    responses: list[str] = []
    escalations: list[bool] = []

    def fake_run(argv, *, purpose, timeout_seconds=15.0, use_pkexec=False, stdin_data=None):
        calls.append(list(argv))
        escalations.append(use_pkexec)
        return responses.pop(0) if responses else ""

    def fake_capture(argv, *, timeout_seconds=15.0, use_pkexec=False, stdin_data=None):
        calls.append(list(argv))
        return 3, "inactive (dead)"

    monkeypatch.setattr(services_module, "run_program", fake_run)
    monkeypatch.setattr(services_module, "capture_program", fake_capture)
    monkeypatch.setattr(
        services_module, "require_program", lambda name, purpose: f"/usr/bin/{name}"
    )
    return calls, responses, escalations


def test_list_units_parses_systemctl_output(fake_systemctl) -> None:
    calls, responses, _ = fake_systemctl
    responses.append(LIST_OUTPUT)
    result = list_units(scope="user")
    # systemctl's own ordering is preserved, not re-sorted.
    assert [entry.unit for entry in result.services] == [
        "gdm.service",
        "sshd.service",
        "not-found.service",
    ]
    assert result.services[0].active == "active"
    assert result.services[0].description == "GNOME Display Manager"
    assert "--user" in calls[0]


def test_list_units_system_scope_omits_user_flag(fake_systemctl) -> None:
    calls, responses, _ = fake_systemctl
    responses.append(LIST_OUTPUT)
    list_units(scope="system")
    assert "--user" not in calls[0]


def test_list_units_filters(fake_systemctl) -> None:
    _calls, responses, _ = fake_systemctl
    responses.append(LIST_OUTPUT)
    result = list_units(name_filter="ssh")
    assert [entry.unit for entry in result.services] == ["sshd.service"]


def test_list_units_truncates(fake_systemctl) -> None:
    _calls, responses, _ = fake_systemctl
    responses.append(LIST_OUTPUT)
    result = list_units(limit=1)
    assert len(result.services) == 1
    assert result.truncated is True


def test_an_invalid_scope_is_refused(fake_systemctl) -> None:
    with pytest.raises(InvalidPathError):
        list_units(scope="global")


@pytest.mark.parametrize(
    "bad", ["--all", "-H", "", "with space", ";rm -rf /", "a/b", "ends.with.dot?"]
)
def test_invalid_unit_names_are_refused(fake_systemctl, bad) -> None:
    with pytest.raises(InvalidPathError):
        unit_status(unit=bad)


def test_status_tolerates_a_nonzero_exit(fake_systemctl) -> None:
    result = unit_status(unit="sshd.service")
    assert result.exit_code == 3
    assert result.output


def test_user_scope_control_does_not_escalate(fake_systemctl) -> None:
    calls, responses, escalations = fake_systemctl
    responses.append("")
    result = control_unit(
        unit="app.service",
        action="restart",
        scope="user",
        commands=CommandsConfig(allow_pkexec=True),
    )
    assert result.escalated is False
    assert escalations == [False]
    assert calls[0] == ["systemctl", "--user", "restart", "app.service"]


def test_system_scope_control_escalates_when_allowed(fake_systemctl) -> None:
    calls, responses, escalations = fake_systemctl
    responses.append("")
    result = control_unit(
        unit="sshd.service",
        action="start",
        scope="system",
        commands=CommandsConfig(allow_pkexec=True),
    )
    assert result.escalated is True
    assert escalations == [True]
    assert calls[0] == ["systemctl", "start", "sshd.service"]


def test_system_scope_control_refuses_when_escalation_is_disabled(fake_systemctl) -> None:
    with pytest.raises(OperationRefusedError) as excinfo:
        control_unit(
            unit="sshd.service",
            action="stop",
            scope="system",
            commands=CommandsConfig(allow_pkexec=False),
        )
    assert "commands.allow_pkexec" in str(excinfo.value)


def test_an_unknown_action_is_refused(fake_systemctl) -> None:
    with pytest.raises(InvalidPathError):
        control_unit(
            unit="app.service",
            action="mask",
            scope="user",
            commands=CommandsConfig(),
        )
