"""System information, resource usage, and process tools.

``get_system_info``, ``get_resource_usage``, and ``list_processes`` are tier
``readonly``. ``kill_process`` sends SIGTERM and is tier ``system``.
``force_kill_process`` sends SIGKILL and is tier ``destructive``, because a
SIGKILL cannot be caught and the target gets no chance to save state.

Signals can only be sent to processes owned by the user running the server.
"""

from __future__ import annotations

import os
import signal
import time
from pathlib import Path
from typing import Annotated, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config
from linux_mcp.errors import (
    InvalidPathError,
    LinuxMCPError,
    OperationRefusedError,
    PathDoesNotExistError,
)
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.tools._common import safe_text

logger = get_logger("tools.system")

_PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
_TERMINAL_STATES = frozenset({"Z", "X", "x"})

_SIGNAL_NAMES = (
    "SIGTERM",
    "SIGINT",
    "SIGHUP",
    "SIGQUIT",
    "SIGUSR1",
    "SIGUSR2",
)


class SystemInfoResult(BaseModel):
    """The result of a successful ``get_system_info`` call."""

    hostname: str = Field(description="Machine hostname.")
    os_name: str = Field(description="Distribution name, for example EndeavourOS.")
    os_id: str = Field(description="Distribution identifier, for example endeavouros.")
    kernel: str = Field(description="Kernel release.")
    architecture: str = Field(description="Machine hardware name.")
    python_version: str = Field(description="Python version running the server.")
    cpu_count: int = Field(description="Number of logical CPUs.")
    uptime_seconds: float = Field(description="Seconds since boot.")
    boot_time: str = Field(description="Boot time, ISO 8601 UTC.")
    load_average: list[float] = Field(description="1, 5, and 15 minute load averages.")
    current_user: str = Field(description="User the server runs as.")
    uid: int = Field(description="UID the server runs as.")


class ProcessInfo(BaseModel):
    """One process."""

    pid: int = Field(description="Process id.")
    name: str = Field(description="Executable name from the kernel.")
    user: str = Field(description="Owner user name, or the numeric uid.")
    state: str = Field(description="Single-letter process state.")
    rss_bytes: int = Field(description="Resident set size in bytes.")
    command: str = Field(description="Full command line, NULs replaced by spaces.")


class ProcessListResult(BaseModel):
    """The result of a successful ``list_processes`` call."""

    processes: list[ProcessInfo] = Field(description="Processes, largest first.")
    total_visible: int = Field(description="How many processes were available to list.")
    returned: int = Field(description="How many processes were returned.")
    truncated: bool = Field(description="True when more processes exist than returned.")


class ResourceUsageResult(BaseModel):
    """The result of a successful ``get_resource_usage`` call."""

    load_average: list[float] = Field(description="1, 5, and 15 minute load averages.")
    cpu_count: int = Field(description="Number of logical CPUs.")
    memory_total_bytes: int = Field(description="Total RAM in bytes.")
    memory_available_bytes: int = Field(description="Available RAM in bytes.")
    memory_used_percent: float = Field(description="Used RAM as a percentage.")
    swap_total_bytes: int = Field(description="Total swap in bytes.")
    swap_free_bytes: int = Field(description="Free swap in bytes.")
    disk_total_bytes: int = Field(description="Size of the filesystem holding /.")
    disk_free_bytes: int = Field(description="Free space on /.")
    disk_used_percent: float = Field(description="Used space on / as a percentage.")
    top_processes: list[ProcessInfo] = Field(
        description="The five processes using the most memory."
    )


class KillResult(BaseModel):
    """The result of a successful ``kill_process`` call."""

    pid: int = Field(description="The process that was signalled.")
    name: str = Field(description="Executable name of the process.")
    signal: str = Field(description="The signal name that was sent.")
    still_running: bool = Field(
        description="True when the process was still present shortly after signalling."
    )


# --------------------------------------------------------------------------- #
# SDK-free core
# --------------------------------------------------------------------------- #


def system_information() -> SystemInfoResult:
    """Collect a snapshot of static system information."""
    uname = os.uname()
    os_name, os_id = _os_release()
    uptime = _uptime_seconds()
    now = time.time()

    try:
        load = list(os.getloadavg())
    except OSError:  # pragma: no cover - only on platforms without loadavg
        load = [0.0, 0.0, 0.0]

    return SystemInfoResult(
        hostname=uname.nodename,
        os_name=os_name,
        os_id=os_id,
        kernel=uname.release,
        architecture=uname.machine,
        python_version=os.sys.version.split()[0],
        cpu_count=os.cpu_count() or 1,
        uptime_seconds=round(uptime, 1),
        boot_time=_iso(now - uptime),
        load_average=[round(value, 2) for value in load],
        current_user=_current_user(),
        uid=os.getuid(),
    )


def resource_usage(*, top_count: int = 5) -> ResourceUsageResult:
    """Collect current CPU load, memory, swap, and disk usage."""
    memory = _meminfo()
    total = memory.get("MemTotal", 0)
    available = memory.get("MemAvailable", 0)
    swap_total = memory.get("SwapTotal", 0)
    swap_free = memory.get("SwapFree", 0)

    disk_total, disk_free = _disk_usage("/")
    used_percent = round((total - available) / total * 100, 1) if total else 0.0
    disk_used_percent = (
        round((disk_total - disk_free) / disk_total * 100, 1) if disk_total else 0.0
    )

    try:
        load = list(os.getloadavg())
    except OSError:  # pragma: no cover
        load = [0.0, 0.0, 0.0]

    return ResourceUsageResult(
        load_average=[round(value, 2) for value in load],
        cpu_count=os.cpu_count() or 1,
        memory_total_bytes=total,
        memory_available_bytes=available,
        memory_used_percent=used_percent,
        swap_total_bytes=swap_total,
        swap_free_bytes=swap_free,
        disk_total_bytes=disk_total,
        disk_free_bytes=disk_free,
        disk_used_percent=disk_used_percent,
        top_processes=collect_processes(limit=top_count).processes,
    )


def collect_processes(
    *,
    name_filter: str | None = None,
    limit: int = 50,
    include_zombies: bool = False,
) -> ProcessListResult:
    """List processes visible to this user, largest resident memory first."""
    processes: list[ProcessInfo] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        described = _describe_process(int(entry.name))
        if described is None:
            continue
        if not include_zombies and described.state in _TERMINAL_STATES:
            continue
        if name_filter and name_filter.lower() not in described.name.lower() and (
            name_filter.lower() not in described.command.lower()
        ):
            continue
        processes.append(described)

    processes.sort(key=lambda item: item.rss_bytes, reverse=True)
    visible = len(processes)
    return ProcessListResult(
        processes=processes[:limit],
        total_visible=visible,
        returned=min(visible, limit),
        truncated=visible > limit,
    )


def signal_process(pid: int, *, signal_name: str = "SIGTERM") -> KillResult:
    """Send *signal_name* to *pid*, refusing anything we do not own."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise InvalidPathError(f"pid must be a positive integer, got {pid!r}.")
    if pid == os.getpid():
        raise OperationRefusedError(
            "Refusing to signal the MCP server's own process. If you need to "
            "stop the server, ask the human to do it."
        )
    if signal_name not in _SIGNAL_NAMES:
        raise InvalidPathError(
            f"Unsupported signal {signal_name!r}. Choose one of: "
            f"{', '.join(_SIGNAL_NAMES)}."
        )

    try:
        owner = os.stat(f"/proc/{pid}").st_uid
    except FileNotFoundError as exc:
        raise PathDoesNotExistError(
            f"No such process: pid {pid} does not exist."
        ) from exc
    except OSError as exc:
        raise OperationRefusedError(
            f"Could not inspect pid {pid}: {exc.strerror or exc}."
        ) from exc

    if owner != os.getuid():
        raise OperationRefusedError(
            f"Refusing to signal pid {pid}: it is owned by uid {owner}, not by "
            f"you (uid {os.getuid()}). The server never escalates privileges for "
            "signals."
        )

    described = _describe_process(pid)
    name = described.name if described is not None else "unknown"

    try:
        os.kill(pid, getattr(signal, signal_name))
    except ProcessLookupError as exc:
        raise PathDoesNotExistError(f"No such process: pid {pid}.") from exc
    except PermissionError as exc:
        raise OperationRefusedError(
            f"Permission denied signalling pid {pid}."
        ) from exc

    return KillResult(
        pid=pid,
        name=name,
        signal=signal_name,
        still_running=_process_exists(pid),
    )


def _process_exists(pid: int) -> bool:
    time.sleep(0.05)
    return Path(f"/proc/{pid}").exists()


def _describe_process(pid: int) -> ProcessInfo | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None

    open_paren = raw.find("(")
    close_paren = raw.rfind(")")
    if open_paren == -1 or close_paren == -1 or close_paren < open_paren:
        return None
    name = raw[open_paren + 1 : close_paren]
    fields = raw[close_paren + 2 :].split()
    if len(fields) < 22:
        return None

    state = fields[0]
    try:
        rss_bytes = int(fields[21]) * _PAGE_SIZE
    except ValueError:
        return None

    try:
        uid = os.stat(f"/proc/{pid}").st_uid
    except OSError:
        return None

    return ProcessInfo(
        pid=pid,
        name=safe_text(name),
        user=_user_name(uid),
        state=state,
        rss_bytes=rss_bytes,
        command=_command_line(pid),
    )


def _command_line(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    text = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    return safe_text(text[:500])


def _os_release() -> tuple[str, str]:
    path = Path("/etc/os-release")
    name = "Linux"
    identifier = "linux"
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("NAME="):
                name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("ID="):
                identifier = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return name, identifier


def _uptime_seconds() -> float:
    try:
        return float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def _meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts:
                try:
                    values[key] = int(parts[0]) * 1024
                except ValueError:
                    continue
    except OSError:
        pass
    return values


def _disk_usage(path: str) -> tuple[int, int]:
    try:
        usage = os.statvfs(path)
    except OSError:  # pragma: no cover
        return 0, 0
    total = usage.f_blocks * usage.f_frsize
    free = usage.f_bavail * usage.f_frsize
    return total, free


def _current_user() -> str:
    return _user_name(os.getuid())


def _user_name(uid: int) -> str:
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):  # pragma: no cover
        return str(uid)


def _iso(timestamp: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(
        timespec="seconds"
    )


# --------------------------------------------------------------------------- #
# MCP registration
# --------------------------------------------------------------------------- #


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the system and process tools on *server*."""

    @server.tool(
        title="Get system information",
        description=(
            "Report static facts about this machine: distribution, kernel, "
            "architecture, CPU count, uptime, and current user."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def get_system_info() -> SystemInfoResult:
        """Report static facts about this machine."""
        logger.info("get_system_info()")
        try:
            return guarded(
                context,
                tool="get_system_info",
                arguments={},
                action=system_information,
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Get resource usage",
        description=(
            "Report live CPU load, memory, swap, and disk usage, plus the "
            "processes using the most memory."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=False),
    )
    def get_resource_usage() -> ResourceUsageResult:
        """Report live CPU, memory, swap, and disk usage."""
        logger.info("get_resource_usage()")
        try:
            return guarded(
                context,
                tool="get_resource_usage",
                arguments={},
                action=resource_usage,
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="List running processes",
        description=(
            "List processes visible to this user, largest memory first. Optionally "
            "filter by a substring of the process name or command line."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=False),
    )
    def list_processes(
        name_filter: Annotated[
            str | None,
            Field(description="Only include processes whose name or command contains this."),
        ] = None,
        limit: Annotated[int, Field(gt=0, le=1000)] = 50,
        include_zombies: Annotated[
            bool, Field(description="Include zombie and dead processes.")
        ] = False,
    ) -> ProcessListResult:
        """List processes visible to this user."""
        logger.info("list_processes(name_filter=%r)", name_filter)
        try:
            return guarded(
                context,
                tool="list_processes",
                arguments={"name_filter": name_filter, "limit": limit},
                action=lambda: collect_processes(
                    name_filter=name_filter,
                    limit=limit,
                    include_zombies=include_zombies,
                ),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Ask a process to stop",
        description=(
            "Send SIGTERM (or another catchable signal) to a process you own. The "
            "process can clean up and may ignore the signal. Use force_kill_process "
            "only if it does not stop."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def kill_process(
        pid: Annotated[int, Field(gt=0, description="Process id to signal.")],
        signal_name: Annotated[
            Literal["SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT", "SIGUSR1", "SIGUSR2"],
            Field(description="Signal to send. Defaults to SIGTERM."),
        ] = "SIGTERM",
    ) -> KillResult:
        """Send a catchable signal to a process you own."""
        logger.info("kill_process(pid=%s, signal=%s)", pid, signal_name)
        try:
            return guarded(
                context,
                tool="kill_process",
                arguments={"pid": pid, "signal": signal_name},
                summary=f"Send {signal_name} to pid {pid}",
                details=f"kill -{signal_name} {pid}",
                action=lambda: signal_process(pid, signal_name=signal_name),
            )
        except LinuxMCPError as exc:
            logger.warning("kill_process refused %s: %s", pid, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Force kill a process",
        description=(
            "Send SIGKILL to a process you own. The process cannot clean up and "
            "will not save state. Requires approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def force_kill_process(
        pid: Annotated[int, Field(gt=0, description="Process id to kill.")],
    ) -> KillResult:
        """Send SIGKILL to a process you own. Requires approval."""
        logger.info("force_kill_process(pid=%s)", pid)
        try:
            return guarded(
                context,
                tool="force_kill_process",
                arguments={"pid": pid},
                summary=f"Force kill pid {pid}",
                details=f"kill -9 {pid}",
                action=lambda: signal_process(pid, signal_name="SIGKILL"),
            )
        except LinuxMCPError as exc:
            logger.warning("force_kill_process refused %s: %s", pid, exc)
            raise ToolError(str(exc)) from exc
