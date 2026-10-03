"""Raw command execution: ``run_command`` and ``run_shell``.

Both are tier ``destructive`` and therefore require human approval by default.
They sit behind their own configuration switches and run inside the configured
containment wrapper. Arguments are passed as an explicit argv with
``shell=False``; ``run_shell`` builds ``["bash", "-lc", script]`` so even the
shell is an argv rather than a string interpolated into one.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import CommandsConfig, Config, LimitsConfig
from linux_mcp.errors import (
    CommandFailedError,
    InvalidPathError,
    LinuxMCPError,
    OperationRefusedError,
)
from linux_mcp.exec import run_argv
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.security import Allowlist, canonicalize_read_path

logger = get_logger("tools.commands")

MAX_ARGS = 1000


class CommandOutcome(BaseModel):
    """The result of running a command."""

    argv: list[str] = Field(
        description="The exact argument vector that was executed (never a shell string)."
    )
    cwd: str | None = Field(description="Working directory, or null for the default.")
    exit_code: int | None = Field(
        default=None, description="Exit status, or null when the command timed out."
    )
    stdout: str = Field(description="Captured standard output.")
    stderr: str = Field(description="Captured standard error.")
    stdout_truncated: bool = Field(description="True when stdout was cut at the size cap.")
    stderr_truncated: bool = Field(description="True when stderr was cut at the size cap.")
    duration_ms: int = Field(description="How long the command ran, in milliseconds.")
    timed_out: bool = Field(
        description="True when the timeout fired and the process group was killed."
    )


def _convert(result) -> CommandOutcome:  # type: ignore[no-untyped-def]
    return CommandOutcome(
        argv=result.argv,
        cwd=result.cwd,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        stdout_truncated=result.stdout_truncated,
        stderr_truncated=result.stderr_truncated,
        duration_ms=result.duration_ms,
        timed_out=result.timed_out,
    )


def _resolve_cwd(raw_cwd: str | None, allowlist: Allowlist) -> Path | None:
    if raw_cwd is None:
        return None
    resolved = canonicalize_read_path(raw_cwd, allowlist)
    if not resolved.is_dir():
        raise OperationRefusedError(f"cwd is not a directory: {resolved}.")
    return resolved


def _effective_timeout(requested: float | None, limits: LimitsConfig) -> float:
    if requested is None:
        return limits.default_timeout_seconds
    if requested <= 0:
        raise InvalidPathError("timeout_seconds must be greater than zero.")
    if requested > limits.max_timeout_seconds:
        raise OperationRefusedError(
            f"timeout_seconds={requested} exceeds the configured maximum of "
            f"{limits.max_timeout_seconds}. Split the work or raise "
            "policy.limits.max_timeout_seconds."
        )
    return float(requested)


def execute_command(
    executable: str,
    args: list[str],
    *,
    cwd: str | None,
    timeout_seconds: float | None,
    use_pkexec: bool,
    read_allowlist: Allowlist,
    limits: LimitsConfig,
    commands: CommandsConfig,
) -> CommandOutcome:
    """Run an executable with an explicit argv, contained and bounded."""
    if not commands.run_command_enabled:
        raise OperationRefusedError(
            "Raw command execution is disabled (commands.run_command_enabled is "
            "false). Enable it in the configuration file to use run_command."
        )
    if not executable or not executable.strip():
        raise InvalidPathError("executable must not be empty.")
    if "\x00" in executable:
        raise InvalidPathError("executable must not contain a NUL byte.")
    if len(args) > MAX_ARGS:
        raise OperationRefusedError(
            f"Too many arguments ({len(args)}); the limit is {MAX_ARGS}."
        )
    for argument in args:
        if "\x00" in argument:
            raise InvalidPathError("Arguments must not contain NUL bytes.")

    if use_pkexec and not commands.allow_pkexec:
        raise OperationRefusedError(
            "Privilege escalation is disabled (commands.allow_pkexec is false)."
        )

    working_directory = _resolve_cwd(cwd, read_allowlist)
    timeout = _effective_timeout(timeout_seconds, limits)

    result = run_argv(
        [executable, *args],
        cwd=working_directory,
        timeout_seconds=timeout,
        max_output_bytes=limits.max_output_bytes,
        contain=commands.containment,  # type: ignore[arg-type]
        use_pkexec=use_pkexec,
        kill_grace_seconds=limits.kill_grace_seconds,
        memory_max_bytes=commands.containment_memory_max_bytes,
        cpu_quota=commands.containment_cpu_quota,
    )
    return _convert(result)


def execute_shell(
    script: str,
    *,
    cwd: str | None,
    timeout_seconds: float | None,
    use_pkexec: bool,
    read_allowlist: Allowlist,
    limits: LimitsConfig,
    commands: CommandsConfig,
) -> CommandOutcome:
    """Run a shell script as ``bash -lc`` inside the same containment."""
    if not commands.run_shell_enabled:
        raise OperationRefusedError(
            "Shell execution is disabled (commands.run_shell_enabled is false). "
            "Enable it in the configuration file to use run_shell."
        )
    if not script.strip():
        raise InvalidPathError("script must not be empty.")

    bash = shutil.which("bash")
    if bash is None:
        raise CommandFailedError(
            "run_shell needs bash, which was not found on PATH."
        )

    if use_pkexec and not commands.allow_pkexec:
        raise OperationRefusedError(
            "Privilege escalation is disabled (commands.allow_pkexec is false)."
        )

    working_directory = _resolve_cwd(cwd, read_allowlist)
    timeout = _effective_timeout(timeout_seconds, limits)

    result = run_argv(
        [bash, "-lc", script],
        cwd=working_directory,
        timeout_seconds=timeout,
        max_output_bytes=limits.max_output_bytes,
        contain=commands.containment,  # type: ignore[arg-type]
        use_pkexec=use_pkexec,
        kill_grace_seconds=limits.kill_grace_seconds,
        memory_max_bytes=commands.containment_memory_max_bytes,
        cpu_quota=commands.containment_cpu_quota,
    )
    return _convert(result)


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the command execution tools on *server*."""
    read_allowlist = config.read_allowlist()
    limits = config.policy.limits
    commands = config.commands

    @server.tool(
        title="Run a command",
        description=(
            "Run an executable with an explicit argument list. No shell is used, "
            "so pipes, redirects, globbing and command substitution do not apply; "
            "run a shell explicitly if you need them. Requires human approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def run_command(
        executable: Annotated[
            str,
            Field(description="Executable name or absolute path, for example 'ls'."),
        ],
        args: Annotated[
            list[str] | None,
            Field(description="Arguments passed verbatim as separate argv entries."),
        ] = None,
        cwd: Annotated[
            str | None,
            Field(description="Working directory, which must be inside an allowed directory."),
        ] = None,
        timeout_seconds: Annotated[
            float | None, Field(gt=0, description="Seconds before the process group is killed.")
        ] = None,
        use_pkexec: Annotated[
            bool,
            Field(description="Run through pkexec, which raises a system password prompt."),
        ] = False,
    ) -> CommandOutcome:
        """Run an executable with an explicit argv. Requires approval."""
        logger.info("run_command(executable=%r)", executable)
        argv = list(args or [])
        preview = " ".join([executable, *argv])
        try:
            return guarded(
                context,
                tool="run_command",
                arguments={"executable": executable, "args": argv, "cwd": cwd},
                summary=f"wants to run: {preview}",
                details=f"{'[pkexec] ' if use_pkexec else ''}{preview}"
                + (f"\ncwd: {cwd}" if cwd else ""),
                action=lambda: execute_command(
                    executable,
                    argv,
                    cwd=cwd,
                    timeout_seconds=timeout_seconds,
                    use_pkexec=use_pkexec,
                    read_allowlist=read_allowlist,
                    limits=limits,
                    commands=commands,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("run_command refused %r: %s", executable, exc)
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Run a shell script",
        description=(
            "Run a script through 'bash -lc', so pipes, redirects, globbing, and "
            "command substitution all work. This is the most powerful tool here. "
            "Requires human approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def run_shell(
        script: Annotated[str, Field(description="Shell script to run with bash -lc.")],
        cwd: Annotated[
            str | None,
            Field(description="Working directory, which must be inside an allowed directory."),
        ] = None,
        timeout_seconds: Annotated[
            float | None, Field(gt=0, description="Seconds before the process group is killed.")
        ] = None,
        use_pkexec: Annotated[
            bool,
            Field(description="Run through pkexec, which raises a system password prompt."),
        ] = False,
    ) -> CommandOutcome:
        """Run a shell script through bash -lc. Requires approval."""
        logger.info("run_shell(script_chars=%d)", len(script))
        try:
            return guarded(
                context,
                tool="run_shell",
                arguments={"script": script, "cwd": cwd},
                summary="wants to run a shell script",
                details=f"bash -lc {script!r}"
                + (f"\ncwd: {cwd}" if cwd else ""),
                action=lambda: execute_shell(
                    script,
                    cwd=cwd,
                    timeout_seconds=timeout_seconds,
                    use_pkexec=use_pkexec,
                    read_allowlist=read_allowlist,
                    limits=limits,
                    commands=commands,
                ),
            )
        except LinuxMCPError as exc:
            logger.warning("run_shell refused: %s", exc)
            raise ToolError(str(exc)) from exc
