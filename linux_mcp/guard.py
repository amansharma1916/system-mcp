"""The one place a tool's permission decision is made.

Every tool calls :func:`guarded` and nothing else. That keeps the order of
operations identical everywhere: resolve the tier, refuse if disabled, ask a
human if the tier requires it, run the action, and write exactly one audit
record before returning. Tools contain no policy logic of their own.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from linux_mcp.approval import ApprovalGate, ApprovalRequest
from linux_mcp.audit import AuditLog
from linux_mcp.config import Config, LimitsConfig
from linux_mcp.errors import ApprovalDeniedError, ApprovalUnavailableError
from linux_mcp.logging_setup import get_logger
from linux_mcp.policy import TIER_ORDER, Policy

logger = get_logger("guard")

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class GuardContext:
    """Everything a tool needs to run one guarded action."""

    policy: Policy
    audit: AuditLog
    approval: ApprovalGate
    limits: LimitsConfig

    @classmethod
    def from_config(cls, config: Config) -> GuardContext:
        """Build a context from a validated configuration."""
        return cls(
            policy=config.policy.policy(),
            audit=AuditLog(
                Path(config.policy.audit.path).expanduser(),
                enabled=config.policy.audit.enabled,
                max_bytes=config.policy.audit.max_bytes,
            ),
            approval=ApprovalGate(
                timeout_seconds=config.policy.approval.timeout_seconds,
            ),
            limits=config.policy.limits,
        )


def guarded(
    context: GuardContext,
    *,
    tool: str,
    arguments: Mapping[str, object],
    action: Callable[[], T],
    summary: str = "",
    details: str = "",
) -> T:
    """Run *action* under *tool*'s policy, auditing the outcome either way."""
    tier = context.policy.require_enabled(tool)

    decision = "auto"
    mechanism: str | None = None

    if context.policy.requires_confirmation(tier):
        request = ApprovalRequest(
            tool=tool,
            tier=tier.value,
            summary=summary or f"Run {tool}",
            details=details or _describe(arguments),
        )
        outcome = context.approval.request(request)
        if not outcome.allowed:
            context.audit.record(
                tool=tool,
                tier=tier.value,
                decision=outcome.reason,
                mechanism=outcome.mechanism,
                arguments=dict(arguments),
                outcome="denied",
                error=f"approval {outcome.reason}",
            )
            if outcome.reason == "unavailable":
                raise ApprovalUnavailableError(
                    f"{tool} requires human approval, but no approval dialog could "
                    "be shown, so the action was refused. Enable a graphical "
                    "session, or lower this tool's tier in policy.confirm_tiers."
                )
            raise ApprovalDeniedError(
                f"The user did not approve {tool} ({outcome.reason}), so nothing "
                "was run. Do not retry without the user's explicit request."
            )
        decision = "approved"
        mechanism = outcome.mechanism

    started = time.monotonic()
    try:
        result = action()
    except Exception as exc:
        context.audit.record(
            tool=tool,
            tier=tier.value,
            decision=decision,
            mechanism=mechanism,
            arguments=dict(arguments),
            outcome="error",
            error=str(exc),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        raise

    context.audit.record(
        tool=tool,
        tier=tier.value,
        decision=decision,
        mechanism=mechanism,
        arguments=dict(arguments),
        outcome="ok",
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return result


def _describe(arguments: Mapping[str, object]) -> str:
    lines = [f"{key}: {value!r}" for key, value in arguments.items()]
    return "\n".join(lines) if lines else "(no arguments)"


def describe_tiers(policy: Policy) -> str:
    """One-line summary of tier status, for embedding in tool descriptions."""
    parts: list[str] = []
    for tier in TIER_ORDER:
        if not policy.is_enabled(tier):
            status = "disabled"
        elif policy.requires_confirmation(tier):
            status = "requires approval"
        else:
            status = "allowed"
        parts.append(f"{tier.value}={status}")
    return ", ".join(parts)
