"""Approval gate: the single most important control. It must never fail open."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping

from linux_mcp.approval import ApprovalGate, ApprovalRequest

REQUEST = ApprovalRequest(
    tool="run_command",
    tier="destructive",
    summary="Run a command",
    details="argv: ['ls', '-la']",
)


def gate(
    *,
    runner,
    timeout: float = 60.0,
    which=lambda name: "/usr/bin/zenity",
    environ: Mapping[str, str] | None = None,
) -> ApprovalGate:
    return ApprovalGate(
        timeout_seconds=timeout,
        runner=runner,
        which=which,
        environ={"WAYLAND_DISPLAY": "wayland-0"} if environ is None else environ,
    )


def test_allow_when_the_dialog_exits_zero() -> None:
    decision = gate(runner=lambda argv, timeout: 0).request(REQUEST)
    assert decision.allowed is True
    assert decision.mechanism == "zenity"
    assert decision.reason == "allow"
    assert decision.elapsed_seconds >= 0


def test_deny_when_the_dialog_exits_one() -> None:
    decision = gate(runner=lambda argv, timeout: 1).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "deny"
    assert decision.mechanism == "zenity"


def test_timeout_exit_status_is_a_denial() -> None:
    decision = gate(runner=lambda argv, timeout: 5).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "timeout"


def test_runner_exception_is_unavailable_and_denied() -> None:
    def exploding(argv, timeout):
        raise OSError("no display")

    decision = gate(runner=exploding).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "unavailable"
    assert decision.mechanism is None


def test_runner_timeout_expiry_is_a_denial() -> None:
    def slow(argv, timeout):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    decision = gate(runner=slow).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "timeout"


def test_missing_zenity_is_unavailable() -> None:
    decision = gate(runner=lambda argv, timeout: 0, which=lambda name: None).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "unavailable"


def test_no_display_is_unavailable_even_if_zenity_exists() -> None:
    decision = gate(runner=lambda argv, timeout: 0, environ={}).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "unavailable"


def test_unexpected_exit_status_is_unavailable() -> None:
    decision = gate(runner=lambda argv, timeout: 3).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "unavailable"


def test_dialog_argv_carries_the_exact_action_and_defaults_to_deny() -> None:
    captured: list[list[str]] = []

    def capture(argv, timeout):
        captured.append(argv)
        return 1

    gate(runner=capture).request(REQUEST)
    argv = captured[0]
    joined = " ".join(argv)
    assert argv[0] == "/usr/bin/zenity"
    assert "--question" in argv
    assert "--default-cancel" in argv
    assert "run_command" in joined
    assert "ls" in joined
    assert "--ok-label=Allow" in argv
    assert "--cancel-label=Deny" in argv


def test_dialog_shows_the_exact_action_separately_from_the_model_reason() -> None:
    captured: list[list[str]] = []

    def capture(argv, timeout):
        captured.append(argv)
        return 1

    gate(runner=capture).request(REQUEST)
    text = next(part for part in captured[0] if part.startswith("--text="))
    assert "Exact action:" in text
    assert "argv: ['ls', '-la']" in text
    assert "untrusted" in text
