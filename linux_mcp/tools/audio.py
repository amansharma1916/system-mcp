"""Audio volume control through ``wpctl`` (PipeWire) or ``pactl`` (PulseAudio).

Reading the volume is tier ``readonly``. Changing it is tier ``system`` and
requires approval: blasting the volume to 100% at 3am is a real, audible action.
"""

from __future__ import annotations

import re
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
from linux_mcp.tools._common import run_program

logger = get_logger("tools.audio")

SINK = "@DEFAULT_AUDIO_SINK@"
PACTL_SINK = "@DEFAULT_SINK@"

MIN_VOLUME_PERCENT = 0
MAX_VOLUME_PERCENT = 150
"""Above 100% is amplification; PulseAudio and PipeWire both allow it."""

_WPCTL_VOLUME = re.compile(r"Volume:\s*([0-9.]+)")
_PACTL_PERCENT = re.compile(r"(\d+)%")


class VolumeResult(BaseModel):
    """The result of a volume call."""

    backend: str = Field(description="Which mixer was used: wpctl or pactl.")
    percent: int = Field(description="Current volume as a percentage (100 = normal).")
    muted: bool = Field(description="True when the default sink is muted.")


def _backend() -> str:
    """Pick a mixer, preferring PipeWire's wpctl and falling back to pactl."""
    if shutil.which("wpctl"):
        return "wpctl"
    if shutil.which("pactl"):
        return "pactl"
    raise OperationRefusedError(
        "Reading or changing the volume requires either 'wpctl' (PipeWire) or "
        "'pactl' (PulseAudio), and neither is installed. Install pipewire or "
        "pulseaudio, then restart the MCP server."
    )


def read_volume() -> VolumeResult:
    """Read the default sink's volume and mute state."""
    backend = _backend()
    if backend == "wpctl":
        output = run_program(["wpctl", "get-volume", SINK], purpose="wpctl get-volume")
        match = _WPCTL_VOLUME.search(output)
        if match is None:
            raise OperationRefusedError(
                f"Could not parse the volume from wpctl output: {output.strip()!r}."
            )
        percent = round(float(match.group(1)) * 100)
        return VolumeResult(backend=backend, percent=percent, muted="[MUTED]" in output)

    volume_output = run_program(
        ["pactl", "get-sink-volume", PACTL_SINK], purpose="pactl get-sink-volume"
    )
    match = _PACTL_PERCENT.search(volume_output)
    if match is None:
        raise OperationRefusedError(
            f"Could not parse the volume from pactl output: {volume_output.strip()!r}."
        )
    mute_output = run_program(
        ["pactl", "get-sink-mute", PACTL_SINK], purpose="pactl get-sink-mute"
    )
    return VolumeResult(
        backend=backend,
        percent=int(match.group(1)),
        muted="yes" in mute_output.lower(),
    )


def change_volume(percent: int) -> VolumeResult:
    """Set the default sink's volume to *percent*."""
    if isinstance(percent, bool) or not isinstance(percent, int):
        raise InvalidPathError(f"Volume must be a whole number, got {percent!r}.")
    if not MIN_VOLUME_PERCENT <= percent <= MAX_VOLUME_PERCENT:
        raise InvalidPathError(
            f"Volume must be between {MIN_VOLUME_PERCENT} and "
            f"{MAX_VOLUME_PERCENT} percent, got {percent}."
        )
    backend = _backend()
    spec = f"{percent}%"
    if backend == "wpctl":
        run_program(["wpctl", "set-volume", SINK, spec], purpose="wpctl set-volume")
    else:
        run_program(["pactl", "set-sink-volume", PACTL_SINK, spec], purpose="pactl set-sink-volume")
    return read_volume()


def change_mute(muted: bool | None) -> VolumeResult:
    """Mute, unmute, or toggle the default sink."""
    backend = _backend()
    flag = "toggle" if muted is None else ("1" if muted else "0")
    if backend == "wpctl":
        run_program(["wpctl", "set-mute", SINK, flag], purpose="wpctl set-mute")
    else:
        run_program(["pactl", "set-sink-mute", PACTL_SINK, flag], purpose="pactl set-sink-mute")
    return read_volume()


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the audio tools on *server*."""

    @server.tool(
        title="Get the volume",
        description="Report the default audio sink's volume percentage and mute state.",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def get_volume() -> VolumeResult:
        """Report the current volume and mute state."""
        logger.info("get_volume()")
        try:
            return guarded(
                context, tool="get_volume", arguments={}, action=read_volume
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Set the volume",
        description=(
            "Set the default audio sink's volume. 100 is normal, above 100 "
            "amplifies and may distort. Requires approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def set_volume(
        percent: Annotated[
            int, Field(ge=0, le=150, description="Volume percentage, 0 to 150.")
        ],
    ) -> VolumeResult:
        """Set the volume. Requires approval."""
        logger.info("set_volume(percent=%s)", percent)
        try:
            return guarded(
                context,
                tool="set_volume",
                arguments={"percent": percent},
                summary=f"Set volume to {percent}%",
                details=f"set default sink volume to {percent}%",
                action=lambda: change_volume(percent),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Mute or unmute audio",
        description=(
            "Mute or unmute the default audio sink. Omit 'muted' to toggle. "
            "Requires approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def mute_audio(
        muted: Annotated[
            bool | None, Field(description="True to mute, false to unmute, omit to toggle.")
        ] = None,
    ) -> VolumeResult:
        """Mute, unmute, or toggle audio. Requires approval."""
        logger.info("mute_audio(muted=%s)", muted)
        verb = "Toggle" if muted is None else ("Mute" if muted else "Unmute")
        try:
            return guarded(
                context,
                tool="mute_audio",
                arguments={"muted": muted},
                summary=f"{verb} the default audio sink",
                details=f"{verb.lower()} default sink",
                action=lambda: change_mute(muted),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc
