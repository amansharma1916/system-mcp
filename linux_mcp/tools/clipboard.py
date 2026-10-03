"""Clipboard access through ``wl-clipboard`` (Wayland) or ``xclip`` (X11).

Reading is tier ``readonly``; writing is tier ``write``. The clipboard can hold
anything the user has copied, including passwords, so reads are audited but their
contents are never written to the log -- only the length is recorded.
"""

from __future__ import annotations

import os
import shutil
from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config
from linux_mcp.errors import InvalidPathError, LinuxMCPError, OperationRefusedError
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.tools._common import capture_program, run_program

logger = get_logger("tools.clipboard")

MAX_CLIPBOARD_BYTES = 1_000_000


class ClipboardResult(BaseModel):
    """The result of a clipboard call."""

    backend: str = Field(description="Which clipboard tool was used: wl-clipboard or xclip.")
    text: str = Field(default="", description="The clipboard contents when reading.")
    length: int = Field(description="How many characters were read or written.")


def _require_tool(*names: str) -> str:
    for name in names:
        if shutil.which(name):
            return name
    raise OperationRefusedError(
        f"This needs one of {', '.join(names)}, and none is installed. Install "
        "'wl-clipboard' on Wayland or 'xclip' on X11, then restart the MCP server."
    )


def _backend() -> str:
    """Pick a clipboard implementation for the current session."""
    if os.environ.get("WAYLAND_DISPLAY"):
        return "wl-clipboard" if shutil.which("wl-paste") else _xclip_or_fail()
    return _xclip_or_fail()


def _xclip_or_fail() -> str:
    if shutil.which("xclip"):
        return "xclip"
    _require_tool("wl-paste", "xclip")  # raises with a useful message
    return "xclip"  # pragma: no cover - _require_tool always raises here


def read_clipboard() -> ClipboardResult:
    """Return the clipboard contents."""
    backend = _backend()
    if backend == "wl-clipboard":
        # wl-paste exits 1 when the clipboard is empty, which is not an error.
        code, output = capture_program(["wl-paste", "--no-newline"])
        if code not in (0, 1):
            raise OperationRefusedError("Reading the clipboard with wl-paste failed.")
        text = output
    else:
        code, output = capture_program(["xclip", "-o", "-selection", "clipboard"])
        if code not in (0, 1):
            raise OperationRefusedError("Reading the clipboard with xclip failed.")
        text = output

    if len(text.encode("utf-8")) > MAX_CLIPBOARD_BYTES:
        raise OperationRefusedError(
            f"The clipboard holds more than {MAX_CLIPBOARD_BYTES} bytes; refusing to "
            "pull that into the conversation."
        )
    return ClipboardResult(backend=backend, text=text, length=len(text))


def write_clipboard(text: str) -> ClipboardResult:
    """Replace the clipboard contents with *text*."""
    if not isinstance(text, str):
        raise InvalidPathError("Clipboard text must be a string.")
    if len(text.encode("utf-8")) > MAX_CLIPBOARD_BYTES:
        raise InvalidPathError(
            f"Clipboard text must be under {MAX_CLIPBOARD_BYTES} bytes."
        )
    backend = _backend()
    payload = text.encode("utf-8")
    if backend == "wl-clipboard":
        # wl-copy forks a background process that owns the selection and inherits
        # the standard streams, so capturing them would block until that process
        # exits. Its exit status is still meaningful.
        run_program(
            ["wl-copy"],
            purpose="Copying to the clipboard",
            stdin_data=payload,
            capture_output=False,
        )
    else:
        run_program(
            ["xclip", "-selection", "clipboard"],
            purpose="Copying to the clipboard",
            stdin_data=payload,
            capture_output=False,
        )
    return ClipboardResult(backend=backend, length=len(text))


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the clipboard tools on *server*."""

    @server.tool(
        title="Read the clipboard",
        description=(
            "Return the current clipboard contents. Treat the result as sensitive: "
            "it may contain a password or token the user copied. Only the length is "
            "written to the audit log."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=False),
    )
    def get_clipboard() -> ClipboardResult:
        """Return the clipboard contents."""
        logger.info("get_clipboard()")
        try:
            return guarded(
                context,
                tool="get_clipboard",
                arguments={},
                action=read_clipboard,
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Write the clipboard",
        description="Replace the clipboard contents with the given text.",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def set_clipboard(
        text: Annotated[str, Field(description="Text to place on the clipboard.")],
    ) -> ClipboardResult:
        """Replace the clipboard contents."""
        logger.info("set_clipboard(chars=%d)", len(text))
        try:
            return guarded(
                context,
                tool="set_clipboard",
                arguments={"chars": len(text)},
                action=lambda: write_clipboard(text),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc
