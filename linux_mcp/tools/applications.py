"""The ``open_application`` tool: launch allowlisted desktop applications.

Security properties, in order of importance:

1. The only model-supplied value is an application *name*. It is looked up in
   the allowlist and never concatenated into a command, so no argument can
   change what runs.
2. ``subprocess.Popen`` is called with an argv list and ``shell=False``
   (implicit - a list never goes through a shell). No pipes, redirects, ``sudo``,
   or command substitution are possible.
3. The child gets ``DEVNULL`` on all three standard streams, so an application
   can never write into this process's stdout, which is the MCP wire.
4. ``start_new_session=True`` detaches the application from this server, so it
   survives the server exiting and never receives signals aimed at us.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping
from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import ApplicationSpec, Config
from linux_mcp.errors import (
    ApplicationLaunchError,
    ApplicationNotAllowedError,
    ApplicationUnavailableError,
    LinuxMCPError,
)
from linux_mcp.guard import GuardContext
from linux_mcp.logging_setup import get_logger

logger = get_logger("tools.applications")

LAUNCH_PROBE_SECONDS = 0.5
"""How long to watch a freshly launched application before reporting success.

Catches the common "it started and died immediately" case (a broken launcher, a
missing display server) so the model gets a real error instead of a cheerful
"launched". Never waits for well-behaved applications, which keep running.
"""


class LaunchResult(BaseModel):
    """The result of a successful ``open_application`` call."""

    name: str = Field(description="The allowlist key that was requested.")
    executable: str = Field(description="Absolute path of the executable that was run.")
    argv: list[str] = Field(
        description="The exact argument vector passed to the process (never a shell)."
    )
    pid: int | None = Field(
        default=None,
        description="Process id of the launched application, or null if it had already exited.",
    )
    launched: bool = Field(description="True when the application was started successfully.")
    message: str = Field(description="Human-readable summary of what happened.")


def normalize_application_name(value: str) -> str:
    """Normalize a requested name the same way configuration keys are normalized."""
    if not isinstance(value, str):
        raise ApplicationNotAllowedError(
            f"Application name must be a string, got {type(value).__name__}."
        )
    return value.strip().lower()


def launch_application(
    name: str,
    *,
    applications: Mapping[str, ApplicationSpec],
    probe_seconds: float = LAUNCH_PROBE_SECONDS,
) -> LaunchResult:
    """Launch an allowlisted application, or raise a typed error.

    Free of MCP imports on purpose, so the allowlist behaviour can be tested
    without a client connection.
    """
    key = normalize_application_name(name)
    if not key:
        raise ApplicationNotAllowedError("Application name must not be empty.")

    spec = applications.get(key)
    if spec is None:
        allowed = ", ".join(sorted(applications)) or "none configured"
        raise ApplicationNotAllowedError(
            f"Permission denied: {name!r} is not in the application allowlist. "
            f"Allowed applications: {allowed}. Arbitrary commands, arguments, and "
            "shell syntax are not supported; only these allowlisted names can be "
            "launched."
        )

    if not spec.available or not _is_executable(spec.executable):
        reason = spec.unavailable_reason or (
            f"the configured executable {spec.executable!r} is missing or not executable"
        )
        raise ApplicationUnavailableError(
            f"Application {key!r} is allowlisted but cannot be launched: {reason}. "
            "Fix its 'command' in the configuration file, or pick another "
            "application."
        )

    argv = list(spec.command)
    try:
        # Fixed argv from the allowlist, no shell, no interpolation of model input.
        process = subprocess.Popen(
            argv,
            shell=False,
            close_fds=True,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:
        raise ApplicationLaunchError(
            f"Failed to launch {key!r} ({spec.executable}): {exc}."
        ) from exc

    logger.info(
        "open_application(%r) started %s as pid %s", key, spec.executable, process.pid
    )

    try:
        status = process.wait(timeout=probe_seconds)
    except subprocess.TimeoutExpired:
        return LaunchResult(
            name=key,
            executable=spec.executable,
            argv=argv,
            pid=process.pid,
            launched=True,
            message=f"{key} is running as pid {process.pid}.",
        )

    if status != 0:
        logger.error(
            "open_application(%r) failed: %s exited immediately with status %s",
            key,
            spec.executable,
            status,
        )
        raise ApplicationLaunchError(
            f"{key!r} exited immediately with status {status}, so it did not start "
            f"correctly ({spec.executable}). Check that the configured command is "
            "correct, and that a graphical session (DISPLAY or WAYLAND_DISPLAY) is "
            "available to this server."
        )

    logger.info("open_application(%r) launcher exited with status 0", key)
    return LaunchResult(
        name=key,
        executable=spec.executable,
        argv=argv,
        pid=process.pid,
        launched=True,
        message=(
            f"{key} started and its launcher exited immediately with status 0, which "
            "is normal for applications that hand off to an already running instance."
        ),
    )


def _is_executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the ``open_application`` tool on *server*."""
    applications = config.applications
    # Built at registration time so the model sees the real allowlist. Passed as a
    # decorator argument because the SDK re-evaluates annotation strings in module
    # globals, where the local name `applications` does not exist.
    description = (
        "Launch an approved Linux desktop application from the configured "
        "application allowlist. Arbitrary commands are not supported. "
        "Allowed application names: "
        f"{', '.join(sorted(applications)) or 'none configured'}."
    )

    @server.tool(
        title="Open an approved application",
        description=description,
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        ),
    )
    def open_application(
        name: Annotated[
            str,
            Field(
                description=(
                    "Name of an application from the configured allowlist, for "
                    "example 'code', 'firefox', or 'terminal'. Unknown names and "
                    "command strings are refused."
                ),
            ),
        ],
    ) -> LaunchResult:
        """Launch an approved Linux desktop application from the configured application allowlist.

        Arbitrary commands are not supported: this tool accepts only an
        application name that the user has allowlisted, and it never uses a
        shell. Use it when the user asks to open, start, or launch an
        application.
        """
        logger.info("open_application(name=%r)", name)
        try:
            result = launch_application(name, applications=applications)
        except LinuxMCPError as exc:
            logger.warning("open_application refused %r: %s", name, exc)
            raise ToolError(str(exc)) from exc
        return result