"""Screenshots through ``grim`` (Wayland), ``scrot``, or ``maim`` (X11).

Tier ``write``: a screenshot creates a file, so the destination must be inside
the configured write directories, but it does not change or destroy anything.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config
from linux_mcp.errors import LinuxMCPError, OperationRefusedError
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.security import Allowlist, canonicalize_write_path
from linux_mcp.tools._common import run_program

logger = get_logger("tools.screenshots")

CAPTURE_TIMEOUT = 30.0


class ScreenshotResult(BaseModel):
    """The result of a successful ``take_screenshot`` call."""

    path: str = Field(description="Absolute path of the saved screenshot.")
    bytes_written: int = Field(description="Size of the image in bytes.")
    tool: str = Field(description="Which capture program was used.")


def _is_gnome_wayland() -> bool:
    """True when running under GNOME on Wayland, where capture is restricted."""
    if not os.environ.get("WAYLAND_DISPLAY"):
        return False
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "")
    return "gnome" in desktop.lower()


def _capture_tool() -> str:
    """Pick a screenshot program for the current session, or explain the gap."""
    if _is_gnome_wayland():
        # Mutter implements neither wlr-screencopy (so grim cannot work) nor an
        # unrestricted org.gnome.Shell.Screenshot (GNOME denies it to non-shell
        # clients). Failing with a precise explanation is better than a cryptic
        # protocol error from grim.
        raise OperationRefusedError(
            "Screen capture is not available under GNOME on Wayland: Mutter does "
            "not implement the wlr-screencopy protocol grim needs, and GNOME "
            "denies org.gnome.Shell.Screenshot to clients that are not the shell "
            "itself. Take the screenshot with the desktop's own shortcut "
            "(usually Print Screen), or run this server under a compositor that "
            "permits programmatic capture."
        )
    if os.environ.get("WAYLAND_DISPLAY"):
        grim = shutil.which("grim")
        if grim:
            return grim
    for candidate in ("grim", "scrot", "maim"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    if os.environ.get("WAYLAND_DISPLAY"):
        raise OperationRefusedError(
            "Taking a screenshot on Wayland requires 'grim', which is not "
            "installed. Install grim and restart the MCP server."
        )
    raise OperationRefusedError(
        "Taking a screenshot requires 'grim' (Wayland), 'scrot', or 'maim' (X11), "
        "and none is installed. Install one and restart the MCP server."
    )


def default_destination(write_allowlist: Allowlist) -> str:
    """A timestamped filename inside the first writable directory."""
    root = write_allowlist.roots[0]
    stamp = datetime.now(tz=timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
    return str(root / f"screenshot-{stamp}.png")


def capture_screenshot(
    raw_path: str | None, *, write_allowlist: Allowlist
) -> ScreenshotResult:
    """Capture the screen to a file inside the write directories."""
    tool = _capture_tool()
    target = canonicalize_write_path(
        raw_path if raw_path else default_destination(write_allowlist),
        write_allowlist,
    )
    if target.exists():
        raise OperationRefusedError(
            f"{target} already exists; choose another name so nothing is overwritten."
        )
    if not target.parent.is_dir():
        raise OperationRefusedError(f"The parent directory {target.parent} does not exist.")

    run_program(
        [tool, str(target)],
        purpose=f"Taking a screenshot with {tool}",
        timeout_seconds=CAPTURE_TIMEOUT,
    )
    if not target.is_file():
        raise OperationRefusedError(
            f"{tool} reported success but {target} was not created."
        )
    return ScreenshotResult(
        path=str(target), bytes_written=target.stat().st_size, tool=os.path.basename(tool)
    )


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the screenshot tool on *server*."""
    write_allowlist = config.write_allowlist()

    @server.tool(
        title="Take a screenshot",
        description=(
            "Capture the screen to a PNG inside the writable directories. Omit "
            "'path' for a timestamped name in the first writable directory. "
            "Refuses to overwrite an existing file."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def take_screenshot(
        path: Annotated[
            str | None,
            Field(description="Destination PNG inside the writable directories."),
        ] = None,
    ) -> ScreenshotResult:
        """Capture the screen to a PNG."""
        logger.info("take_screenshot(path=%r)", path)
        try:
            return guarded(
                context,
                tool="take_screenshot",
                arguments={"path": path},
                action=lambda: capture_screenshot(path, write_allowlist=write_allowlist),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc
