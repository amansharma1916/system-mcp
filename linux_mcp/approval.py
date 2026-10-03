"""Human approval for dangerous actions, via a native desktop dialog.

Fail-closed by construction: every uncertain outcome (no ``zenity``, no display,
timeout, an unexpected exit status, an exception) is reported as
``reason="unavailable"`` with ``allowed=False``. There is deliberately no code
path that returns ``allowed=True`` other than the dialog's own "Allow" button.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from linux_mcp.logging_setup import get_logger

logger = get_logger("approval")

MECHANISM = "zenity"

DEFAULT_TIMEOUT_SECONDS = 60.0
"""How long a dialog may stay unanswered before the action is denied."""

_RUNNER_GRACE_SECONDS = 5.0
"""Extra time over the zenity timeout before we stop waiting on the process."""

_EXIT_ALLOW = 0
_EXIT_DENY = 1
_EXIT_TIMEOUT = 5


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """What the human is being asked to authorise."""

    tool: str
    tier: str
    summary: str
    details: str


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """The outcome of asking a human."""

    allowed: bool
    mechanism: str | None
    reason: str
    elapsed_seconds: float


DialogRunner = Callable[[list[str], float], int]
"""Run the dialog argv with a timeout and return its exit status."""


def _default_runner(argv: list[str], timeout: float) -> int:
    completed = subprocess.run(
        argv,
        timeout=timeout,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return int(completed.returncode)


class ApprovalGate:
    """Ask a human to allow or deny an action, failing closed on any doubt."""

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        runner: DialogRunner | None = None,
        which: Callable[[str], str | None] = shutil.which,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._runner = runner if runner is not None else _default_runner
        self._which = which
        self._environ = os.environ if environ is None else environ

    def request(self, request: ApprovalRequest) -> ApprovalDecision:
        """Ask for approval; never trust anything but an explicit "Allow"."""
        started = time.monotonic()

        if not (self._environ.get("DISPLAY") or self._environ.get("WAYLAND_DISPLAY")):
            logger.warning(
                "Approval needed for %s but no display is available; denying.",
                request.tool,
            )
            return self._unavailable(started)

        zenity = self._which(MECHANISM)
        if zenity is None:
            logger.warning(
                "Approval needed for %s but %s is not installed; denying.",
                request.tool,
                MECHANISM,
            )
            return self._unavailable(started)

        argv = [
            zenity,
            "--question",
            "--title=linux-mcp approval required",
            f"--text={self._render(request)}",
            "--ok-label=Allow",
            "--cancel-label=Deny",
            "--default-cancel",
            f"--timeout={int(self._timeout_seconds)}",
            "--width=520",
        ]

        try:
            status = self._runner(argv, self._timeout_seconds + _RUNNER_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            logger.warning("Approval dialog for %s timed out; denying.", request.tool)
            return self._deny(started, reason="timeout", mechanism=MECHANISM)
        except OSError as exc:
            logger.warning("Approval dialog for %s failed to run: %s", request.tool, exc)
            return self._unavailable(started)

        if status == _EXIT_ALLOW:
            logger.info("Approved %s via %s.", request.tool, MECHANISM)
            return ApprovalDecision(True, MECHANISM, "allow", time.monotonic() - started)
        if status == _EXIT_DENY:
            logger.info("Denied %s by the user.", request.tool)
            return self._deny(started, reason="deny", mechanism=MECHANISM)
        if status == _EXIT_TIMEOUT:
            logger.warning("Approval dialog for %s timed out; denying.", request.tool)
            return self._deny(started, reason="timeout", mechanism=MECHANISM)

        logger.warning(
            "Approval dialog for %s returned unexpected status %s; denying.",
            request.tool,
            status,
        )
        return self._unavailable(started)

    def _render(self, request: ApprovalRequest) -> str:
        # The model's own words are labelled untrusted; the exact action is shown
        # verbatim so the human approves what will actually run, not what the model
        # claims it will do.
        parts = [
            f"<b>{request.tool}</b> (tier: {request.tier})",
            "",
            "Exact action:",
            request.details,
        ]
        if request.summary:
            parts += ["", "Model's stated reason (untrusted):", request.summary]
        return "\n".join(parts)

    @staticmethod
    def _deny(started: float, *, reason: str, mechanism: str | None) -> ApprovalDecision:
        return ApprovalDecision(False, mechanism, reason, time.monotonic() - started)

    @staticmethod
    def _unavailable(started: float) -> ApprovalDecision:
        return ApprovalDecision(False, None, "unavailable", time.monotonic() - started)
