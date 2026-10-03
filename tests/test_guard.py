"""Guard: tier gate -> approval -> action -> audit, in that order, always."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from linux_mcp.approval import ApprovalDecision, ApprovalRequest
from linux_mcp.audit import AuditLog
from linux_mcp.config import (
    AuditConfig,
    Config,
    DirectoryPolicy,
    LimitsConfig,
    PolicyConfig,
)
from linux_mcp.errors import (
    ApprovalDeniedError,
    ApprovalUnavailableError,
    TierDisabledError,
    UndeclaredToolError,
)
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.policy import Policy, Tier


class FakeGate:
    def __init__(self, decision: ApprovalDecision) -> None:
        self.decision = decision
        self.requests: list[ApprovalRequest] = []

    def request(self, request: ApprovalRequest) -> ApprovalDecision:
        self.requests.append(request)
        return self.decision


def allow() -> ApprovalDecision:
    return ApprovalDecision(True, "zenity", "allow", 0.1)


def deny(reason: str = "deny") -> ApprovalDecision:
    mechanism = None if reason == "unavailable" else "zenity"
    return ApprovalDecision(False, mechanism, reason, 0.1)


def context(tmp_path: Path, *, gate, enabled=None, confirm=None) -> GuardContext:
    policy = Policy(
        enabled_tiers=frozenset(
            enabled if enabled is not None else {Tier.READONLY, Tier.WRITE}
        ),
        confirm_tiers=frozenset(confirm if confirm is not None else set()),
    )
    return GuardContext(
        policy=policy,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        approval=gate,
        limits=LimitsConfig(),
    )


def records(ctx: GuardContext) -> list[dict]:
    if not ctx.audit.path.exists():
        return []
    return [
        json.loads(line)
        for line in ctx.audit.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_readonly_action_runs_without_approval_and_is_audited(tmp_path: Path) -> None:
    gate = FakeGate(allow())
    ctx = context(tmp_path, gate=gate)
    result = guarded(
        ctx,
        tool="read_file",
        arguments={"path": "/tmp/x"},
        action=lambda: "content",
    )
    assert result == "content"
    assert gate.requests == []
    assert records(ctx)[0]["decision"] == "auto"
    assert records(ctx)[0]["outcome"] == "ok"


def test_disabled_tier_raises_before_the_action_runs(tmp_path: Path) -> None:
    ctx = context(tmp_path, gate=FakeGate(allow()), enabled={Tier.READONLY})
    called = False

    def action() -> None:
        nonlocal called
        called = True

    with pytest.raises(TierDisabledError):
        guarded(ctx, tool="run_command", arguments={}, action=action)
    assert called is False
    assert records(ctx) == []


def test_confirmed_action_runs_when_allowed(tmp_path: Path) -> None:
    gate = FakeGate(allow())
    ctx = context(
        tmp_path, gate=gate, enabled={Tier.DESTRUCTIVE}, confirm={Tier.DESTRUCTIVE}
    )
    result = guarded(
        ctx, tool="run_command", arguments={"argv": ["ls"]}, action=lambda: 42
    )
    assert result == 42
    assert len(gate.requests) == 1
    assert records(ctx)[0]["decision"] == "approved"
    assert records(ctx)[0]["mechanism"] == "zenity"


def test_confirmed_action_raises_when_denied_and_audits_denial(tmp_path: Path) -> None:
    gate = FakeGate(deny())
    ctx = context(
        tmp_path, gate=gate, enabled={Tier.DESTRUCTIVE}, confirm={Tier.DESTRUCTIVE}
    )
    called = False

    def action() -> None:
        nonlocal called
        called = True

    with pytest.raises(ApprovalDeniedError):
        guarded(ctx, tool="run_command", arguments={}, action=action)
    assert called is False
    assert records(ctx)[0]["decision"] == "deny"
    assert records(ctx)[0]["outcome"] == "denied"


def test_unavailable_approval_raises_approval_unavailable(tmp_path: Path) -> None:
    ctx = context(
        tmp_path,
        gate=FakeGate(deny("unavailable")),
        enabled={Tier.DESTRUCTIVE},
        confirm={Tier.DESTRUCTIVE},
    )
    with pytest.raises(ApprovalUnavailableError):
        guarded(ctx, tool="run_command", arguments={}, action=lambda: None)
    assert records(ctx)[0]["decision"] == "unavailable"


def test_action_failure_is_audited_and_reraised(tmp_path: Path) -> None:
    ctx = context(tmp_path, gate=FakeGate(allow()))

    def explode() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError):
        guarded(ctx, tool="read_file", arguments={"path": "/tmp/x"}, action=explode)
    assert records(ctx)[0]["outcome"] == "error"
    assert "boom" in records(ctx)[0]["error"]


def test_arguments_are_redacted_in_the_audit_record(tmp_path: Path) -> None:
    ctx = context(tmp_path, gate=FakeGate(allow()))
    guarded(
        ctx,
        tool="read_file",
        arguments={"path": "/tmp/x", "api_key": "secret"},
        action=lambda: "ok",
    )
    assert records(ctx)[0]["arguments"]["api_key"] == "[redacted]"


def test_undeclared_tool_is_refused(tmp_path: Path) -> None:
    ctx = context(tmp_path, gate=FakeGate(allow()))
    with pytest.raises(UndeclaredToolError):
        guarded(ctx, tool="not_a_tool", arguments={}, action=lambda: None)


def test_from_config_builds_working_context(tmp_path: Path) -> None:
    """from_config must read the audit path and tier settings from the config."""
    config = Config(
        source=tmp_path / "config.yaml",
        directories=DirectoryPolicy(allow=(tmp_path,)),
        applications={},
        policy=PolicyConfig(
            audit=AuditConfig(path=tmp_path / "audit.jsonl"),
            enabled_tiers=frozenset({Tier.READONLY, Tier.WRITE, Tier.DESTRUCTIVE}),
            confirm_tiers=frozenset({Tier.DESTRUCTIVE}),
        ),
    )
    ctx = GuardContext.from_config(config)
    assert ctx.audit.path == tmp_path / "audit.jsonl"
    assert ctx.policy.is_enabled(Tier.DESTRUCTIVE) is True
    assert ctx.policy.requires_confirmation(Tier.DESTRUCTIVE) is True
