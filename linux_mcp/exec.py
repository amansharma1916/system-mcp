"""Run an external command safely: no shell, bounded time, bounded output.

This is the only module in the project that spawns a subprocess on behalf of the
model. It always passes an explicit argv with ``shell=False``; ``run_shell`` in
the command tools is built on top of it as ``["bash", "-lc", script]``, so even
the shell is an argv and never a string interpolated into one.

On timeout the whole process *group* is signalled, not just the direct child, so
a command cannot leave background children behind.

``capture_output=False`` sends stdout and stderr to ``/dev/null`` instead of
pipes. That matters for programs which fork a daemon that inherits the standard
streams (``wl-copy`` is the motivating case): a captured pipe stays open in the
child, so reading until EOF would block long after the command itself finished.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from linux_mcp.containment import (
    DEFAULT_CPU_QUOTA,
    DEFAULT_MEMORY_MAX_BYTES,
    ContainmentMode,
    build_wrapper,
)
from linux_mcp.errors import CommandFailedError, PrivilegeEscalationError
from linux_mcp.logging_setup import get_logger

logger = get_logger("exec")

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_OUTPUT_BYTES = 100_000
DEFAULT_KILL_GRACE_SECONDS = 3.0

_PKEXEC = "pkexec"


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Everything a tool needs to report about one execution."""

    argv: list[str]
    cwd: str | None
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_ms: int
    timed_out: bool


def build_command(
    argv: Sequence[str],
    *,
    contain: ContainmentMode = "none",
    use_pkexec: bool = False,
    memory_max_bytes: int = DEFAULT_MEMORY_MAX_BYTES,
    cpu_quota: str = DEFAULT_CPU_QUOTA,
    which: Callable[[str], str | None] | None = None,
) -> list[str]:
    """Assemble the final argv: containment outermost, escalation innermost."""
    resolver = shutil.which if which is None else which
    command = [str(part) for part in argv]

    if use_pkexec:
        pkexec = resolver(_PKEXEC)
        if pkexec is None:
            raise PrivilegeEscalationError(
                f"Privilege escalation was requested but {_PKEXEC!r} is not "
                "installed, so the action cannot be run. Either install polkit, or "
                "set commands.allow_pkexec to false to disable escalation entirely."
            )
        command = [pkexec, *command]

    wrapper = build_wrapper(
        contain,
        memory_max_bytes=memory_max_bytes,
        cpu_quota=cpu_quota,
        which=resolver,
    )
    if wrapper is not None:
        command = [*wrapper, *command]
    return command


def run_argv(
    argv: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    contain: ContainmentMode = "none",
    use_pkexec: bool = False,
    kill_grace_seconds: float = DEFAULT_KILL_GRACE_SECONDS,
    memory_max_bytes: int = DEFAULT_MEMORY_MAX_BYTES,
    cpu_quota: str = DEFAULT_CPU_QUOTA,
    check: bool = False,
    which: Callable[[str], str | None] | None = None,
    stdin_data: bytes | None = None,
    capture_output: bool = True,
) -> CommandResult:
    """Run *argv* with no shell, returning captured output and status."""
    command = build_command(
        argv,
        contain=contain,
        use_pkexec=use_pkexec,
        memory_max_bytes=memory_max_bytes,
        cpu_quota=cpu_quota,
        which=which,
    )

    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            shell=False,
            cwd=None if cwd is None else str(cwd),
            env=None if env is None else dict(env),
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        raise CommandFailedError(
            f"Could not start command {command[0]!r}: {exc}."
        ) from exc

    timed_out = False
    try:
        stdout_bytes, stderr_bytes = process.communicate(
            input=stdin_data, timeout=timeout_seconds
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_group(process, kill_grace_seconds)
        stdout_bytes, stderr_bytes = process.communicate()

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout, stdout_truncated = _decode_truncated(stdout_bytes or b"", max_output_bytes)
    stderr, stderr_truncated = _decode_truncated(stderr_bytes or b"", max_output_bytes)

    result = CommandResult(
        argv=command,
        cwd=str(cwd) if cwd is not None else None,
        exit_code=None if timed_out else process.returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        duration_ms=duration_ms,
        timed_out=timed_out,
    )

    if timed_out:
        logger.warning("Command timed out after %.1fs: %s", timeout_seconds, command[0])
    logger.info(
        "Ran %s (exit=%s, %dms, timed_out=%s)",
        command[0],
        result.exit_code,
        duration_ms,
        timed_out,
    )

    if check and not timed_out and result.exit_code not in (0, None):
        raise CommandFailedError(
            f"Command {command[0]!r} exited with status {result.exit_code}. "
            f"stderr: {stderr.strip()[:500] or '(empty)'}"
        )
    return result


def _terminate_group(process: subprocess.Popen, grace_seconds: float) -> None:
    """SIGTERM the process group, then SIGKILL it if it does not go quietly."""
    try:
        group = os.getpgid(process.pid)
    except (ProcessLookupError, PermissionError):
        return
    try:
        os.killpg(group, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _decode_truncated(data: bytes, limit: int) -> tuple[str, bool]:
    """Decode *data*, cutting at *limit* bytes on a UTF-8 boundary."""
    truncated = len(data) > limit
    if not truncated:
        return data.decode("utf-8", "replace"), False

    cut = data[:limit]
    # Drop a partial multi-byte sequence so the decoded text has no U+FFFD.
    while cut and (cut[-1] & 0xC0) == 0x80:
        cut = cut[:-1]
    if cut and (cut[-1] & 0x80):
        cut = cut[:-1]
    return cut.decode("utf-8", "replace"), True
