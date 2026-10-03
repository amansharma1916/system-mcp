"""Small helpers shared by the tool modules."""

from __future__ import annotations

import shutil
from collections.abc import Sequence

from linux_mcp.errors import OperationRefusedError
from linux_mcp.exec import run_argv

DEFAULT_PROGRAM_TIMEOUT = 15.0


def safe_text(value: str) -> str:
    """Return *value* as text that can always be serialised to JSON.

    Filenames on Linux are arbitrary byte strings; ``os.scandir`` decodes
    undecodable bytes with the ``surrogateescape`` handler, and those lone
    surrogates are not valid JSON. Replace them rather than failing a whole call
    because one file has an unusual name.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    return value


def human_bytes(count: int) -> str:
    """A short human-readable size such as ``18.4 MiB``."""
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"  # pragma: no cover - unreachable, loop returns


def require_program(name: str, *, purpose: str) -> str:
    """Return the absolute path of *name*, or explain that it is not installed.

    Phase 2 and 3 features depend on desktop helpers that are not present on
    every system. Failing with a precise message is far more useful than a
    ``FileNotFoundError`` traceback or a tool that silently does nothing.
    """
    path = shutil.which(name)
    if path is None:
        raise OperationRefusedError(
            f"{purpose} requires the program {name!r}, which is not installed. "
            f"Install {name} (for example with your package manager) and restart "
            "the MCP server, or use a different approach."
        )
    return path


def capture_program(
    argv: Sequence[str],
    *,
    timeout_seconds: float = DEFAULT_PROGRAM_TIMEOUT,
    use_pkexec: bool = False,
    stdin_data: bytes | None = None,
) -> tuple[int | None, str]:
    """Run a fixed command and return ``(exit_code, combined_output)``.

    Unlike :func:`run_program` a non-zero exit is *not* an error, because some
    status commands (``systemctl status`` on an inactive unit, for instance)
    report normal states that way. Spawn failures and timeouts still raise.
    """
    result = run_argv(
        list(argv),
        timeout_seconds=timeout_seconds,
        max_output_bytes=200_000,
        use_pkexec=use_pkexec,
        stdin_data=stdin_data,
    )
    if result.timed_out:
        raise OperationRefusedError(
            f"{argv[0]} did not finish within {timeout_seconds:g}s and was stopped."
        )
    combined = result.stdout
    if result.stderr:
        combined = f"{combined}\n{result.stderr}".strip()
    return result.exit_code, combined


def run_program(
    argv: Sequence[str],
    *,
    purpose: str,
    timeout_seconds: float = DEFAULT_PROGRAM_TIMEOUT,
    use_pkexec: bool = False,
    stdin_data: bytes | None = None,
    capture_output: bool = True,
) -> str:
    """Run one of the server's *own* fixed commands and return its stdout.

    This is for capabilities like ``gsettings`` or ``pactl`` where the argv is
    built entirely from validated inputs, not for model-supplied commands (those
    go through the guarded ``run_command`` tool). A non-zero exit becomes a
    typed error carrying whatever the program said.

    With *use_pkexec*, the command runs through ``pkexec``, which raises a real
    polkit authorization prompt. The server never sees or stores a password.
    """
    result = run_argv(
        list(argv),
        timeout_seconds=timeout_seconds,
        max_output_bytes=200_000,
        use_pkexec=use_pkexec,
        stdin_data=stdin_data,
        capture_output=capture_output,
    )
    if result.timed_out:
        raise OperationRefusedError(
            f"{purpose} did not finish within {timeout_seconds:g}s and was stopped."
        )
    if result.exit_code != 0:
        detail = (result.stderr or result.stdout).strip()
        raise OperationRefusedError(
            f"{purpose} failed (exit status {result.exit_code}): "
            f"{detail[:400] or 'no output'}"
        )
    return result.stdout
