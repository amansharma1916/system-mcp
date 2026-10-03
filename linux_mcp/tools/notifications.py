"""Desktop notifications through ``notify-send``.

Tier ``write``: a notification is a visible but benign and reversible side
effect, so it runs without an approval prompt. It is still audited.
"""

from __future__ import annotations

from typing import Annotated, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config
from linux_mcp.errors import InvalidPathError, LinuxMCPError
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.tools._common import require_program, run_program

logger = get_logger("tools.notifications")

MAX_TEXT = 4000


class NotificationResult(BaseModel):
    """The result of a successful ``send_notification`` call."""

    summary: str = Field(description="The notification title that was shown.")
    urgency: str = Field(description="Urgency level that was used.")
    sent: bool = Field(description="True when notify-send accepted the notification.")


def notify(
    summary: str,
    body: str = "",
    *,
    urgency: str = "normal",
    expire_ms: int | None = None,
) -> NotificationResult:
    """Show a desktop notification."""
    if not summary.strip():
        raise InvalidPathError("summary must not be empty.")
    if len(summary) > MAX_TEXT or len(body) > MAX_TEXT:
        raise InvalidPathError(f"Notification text must be under {MAX_TEXT} characters.")
    if urgency not in ("low", "normal", "critical"):
        raise InvalidPathError(
            f"urgency must be low, normal, or critical, got {urgency!r}."
        )
    if expire_ms is not None and (isinstance(expire_ms, bool) or expire_ms < 0):
        raise InvalidPathError("expire_ms must be zero or greater.")

    notify_send = require_program("notify-send", purpose="Sending a desktop notification")
    argv = [notify_send, "--urgency", urgency]
    if expire_ms is not None:
        argv += ["--expire-time", str(int(expire_ms))]
    # A leading dash in the body would be read as an option, so separate it.
    argv += ["--", summary, body]
    run_program(argv, purpose="notify-send")
    return NotificationResult(summary=summary, urgency=urgency, sent=True)


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the notification tool on *server*."""

    @server.tool(
        title="Send a desktop notification",
        description=(
            "Show a desktop notification. Use it to report that a long task "
            "finished, or to hand a decision back to the human."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def send_notification(
        summary: Annotated[str, Field(description="Notification title.")],
        body: Annotated[str, Field(description="Body text.")] = "",
        urgency: Annotated[
            Literal["low", "normal", "critical"],
            Field(description="Urgency level."),
        ] = "normal",
        expire_ms: Annotated[
            int | None,
            Field(ge=0, description="Milliseconds before it disappears; omit for the default."),
        ] = None,
    ) -> NotificationResult:
        """Show a desktop notification."""
        logger.info("send_notification(summary=%r)", summary)
        try:
            return guarded(
                context,
                tool="send_notification",
                arguments={"summary": summary, "urgency": urgency, "expire_ms": expire_ms},
                action=lambda: notify(summary, body, urgency=urgency, expire_ms=expire_ms),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc
