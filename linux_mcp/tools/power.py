"""Power and session actions: lock, logout, suspend, hibernate, poweroff, reboot.

Locking, logging out, and suspending are tier ``system``. Shutting down,
rebooting, and hibernating are tier ``destructive``: they end everything the
user has open, and an unsaved document is gone for good.

Which actions are permitted at all is governed by ``power.allow``, separately
from the tier gate, so a user can allow locking while refusing shutdown.
"""

from __future__ import annotations

import os
import shutil

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config, PowerConfig
from linux_mcp.errors import LinuxMCPError, OperationRefusedError
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.tools._common import require_program, run_program

logger = get_logger("tools.power")

ALL_ACTIONS = ("lock", "logout", "suspend", "hibernate", "shutdown", "reboot")


class PowerResult(BaseModel):
    """The result of a power or session action."""

    action: str = Field(description="The action that was performed.")
    command: str = Field(description="The command that was run.")


def _require_allowed(power: PowerConfig, action: str) -> None:
    if action not in power.allow:
        allowed = ", ".join(sorted(power.allow)) or "none"
        raise OperationRefusedError(
            f"The {action!r} action is not permitted by this configuration. "
            f"Allowed power actions: {allowed}. Add {action!r} to power.allow to "
            "enable it."
        )


def lock(power: PowerConfig) -> PowerResult:
    """Lock the current session."""
    _require_allowed(power, "lock")
    loginctl = require_program("loginctl", purpose="Locking the session")
    run_program([loginctl, "lock-session"], purpose="loginctl lock-session")
    return PowerResult(action="lock", command="loginctl lock-session")


def logout(power: PowerConfig) -> PowerResult:
    """End the current desktop session."""
    _require_allowed(power, "logout")
    gnome = shutil.which("gnome-session-quit")
    if gnome:
        argv = [gnome, "--logout", "--no-prompt"]
    else:
        session_id = os.environ.get("XDG_SESSION_ID")
        if not session_id:
            raise OperationRefusedError(
                "Logging out needs either gnome-session-quit or XDG_SESSION_ID, "
                "and neither is available. Log out from the desktop directly."
            )
        loginctl = require_program("loginctl", purpose="Logging out")
        argv = [loginctl, "terminate-session", session_id]
    run_program(argv, purpose="Logging out")
    return PowerResult(action="logout", command=" ".join(argv))


def system_action(power: PowerConfig, action: str) -> PowerResult:
    """Run a systemctl system power action (suspend, hibernate, poweroff, reboot)."""
    _require_allowed(power, action)
    systemctl = require_program("systemctl", purpose=f"Running systemctl {action}")
    verb = {
        "suspend": "suspend",
        "hibernate": "hibernate",
        "shutdown": "poweroff",
        "reboot": "reboot",
    }[action]
    run_program([systemctl, verb], purpose=f"systemctl {verb}")
    return PowerResult(action=action, command=f"systemctl {verb}")


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the power and session tools on *server*."""
    power = config.power

    def _run(tool: str, action: str, call) -> PowerResult:
        try:
            return guarded(
                context,
                tool=tool,
                arguments={},
                summary=f"{action.capitalize()} this computer's session",
                details=action,
                action=call,
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Lock the screen",
        description="Lock the current desktop session immediately.",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def lock_screen() -> PowerResult:
        """Lock the current session. Requires approval."""
        logger.info("lock_screen()")
        return _run("lock_screen", "lock", lambda: lock(power))

    @server.tool(
        title="Log out",
        description=(
            "End the current desktop session. Unsaved work in GUI applications "
            "will be lost. Requires approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def end_session() -> PowerResult:
        """Log out of the desktop session. Requires approval."""
        logger.info("end_session()")
        return _run("end_session", "logout", lambda: logout(power))

    @server.tool(
        title="Suspend",
        description="Suspend the machine to RAM. Requires approval.",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def suspend_system() -> PowerResult:
        """Suspend to RAM. Requires approval."""
        logger.info("suspend_system()")
        return _run("suspend_system", "suspend", lambda: system_action(power, "suspend"))

    @server.tool(
        title="Hibernate",
        description=(
            "Hibernate the machine to disk. Requires a configured swap partition "
            "or file and approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def hibernate_system() -> PowerResult:
        """Hibernate to disk. Requires approval."""
        logger.info("hibernate_system()")
        return _run(
            "hibernate_system", "hibernate", lambda: system_action(power, "hibernate")
        )

    @server.tool(
        title="Shut down",
        description=(
            "Power the machine off. Everything running is terminated and unsaved "
            "work is lost. Requires approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def shutdown_system() -> PowerResult:
        """Power off the machine. Requires approval."""
        logger.info("shutdown_system()")
        return _run("shutdown_system", "shutdown", lambda: system_action(power, "shutdown"))

    @server.tool(
        title="Reboot",
        description=(
            "Restart the machine. Everything running is terminated and unsaved "
            "work is lost. Requires approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def reboot_system() -> PowerResult:
        """Restart the machine. Requires approval."""
        logger.info("reboot_system()")
        return _run("reboot_system", "reboot", lambda: system_action(power, "reboot"))
