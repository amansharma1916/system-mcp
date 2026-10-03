"""Optional execution containment: run a command in its own user scope.

``systemd-run --user --scope`` gives the command its own cgroup with memory and
CPU caps and guarantees the whole process tree is killed with it. If the wrapper
is requested but unavailable, this fails closed rather than silently running the
command uncontained.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from typing import Literal

from linux_mcp.errors import ContainmentUnavailableError

ContainmentMode = Literal["none", "systemd-scope"]

DEFAULT_MEMORY_MAX_BYTES = 2_147_483_648
"""2 GiB, comfortable for ordinary commands while bounding runaway allocation."""

DEFAULT_CPU_QUOTA = "200%"
"""Two cores; enough for builds while preventing a spin from owning the machine."""

_SYSTEMD_RUN = "systemd-run"


def build_wrapper(
    mode: ContainmentMode,
    *,
    memory_max_bytes: int = DEFAULT_MEMORY_MAX_BYTES,
    cpu_quota: str = DEFAULT_CPU_QUOTA,
    which: Callable[[str], str | None] = shutil.which,
) -> list[str] | None:
    """Return the argv prefix that wraps a command, or ``None`` for no wrapper."""
    if mode == "none":
        return None
    if mode != "systemd-scope":
        raise ContainmentUnavailableError(
            f"Unknown containment mode {mode!r}. Supported modes: none, systemd-scope."
        )

    executable = which(_SYSTEMD_RUN)
    if executable is None:
        raise ContainmentUnavailableError(
            f"Containment mode 'systemd-scope' was requested but {_SYSTEMD_RUN!r} "
            "is not installed. Install systemd, or set "
            "commands.containment to 'none' to accept uncontained execution."
        )

    return [
        executable,
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "-p",
        f"MemoryMax={memory_max_bytes}",
        "-p",
        f"CPUQuota={cpu_quota}",
        "--",
    ]
