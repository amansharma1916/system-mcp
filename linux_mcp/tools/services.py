"""systemd service inspection and control.

Listing and inspecting units is tier ``readonly`` and works without privileges.
Starting, stopping, and restarting are tier ``system`` and require approval.

User units (``--user``) are controlled directly. System units need privileges, so
they go through ``pkexec`` when ``commands.allow_pkexec`` is true, which raises a
polkit prompt for each action.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import CommandsConfig, Config
from linux_mcp.errors import InvalidPathError, LinuxMCPError, OperationRefusedError
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.tools._common import capture_program, require_program, run_program

logger = get_logger("tools.services")

Scope = Literal["user", "system"]
Action = Literal["start", "stop", "restart"]

_UNIT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:-]*$")
"""A systemd unit name. A leading dash is refused as well."""

_LIST_TIMEOUT = 30.0


class ServiceEntry(BaseModel):
    """One systemd unit."""

    unit: str = Field(description="Unit name, for example gdm.service.")
    load: str = Field(description="Whether systemd could load the unit.")
    active: str = Field(description="Active state, for example active or inactive.")
    sub: str = Field(description="Sub-state, for example running or dead.")
    description: str = Field(description="Unit description.")


class ServiceListResult(BaseModel):
    """The result of listing systemd units."""

    scope: str = Field(description="user or system.")
    services: list[ServiceEntry] = Field(description="Units that matched.")
    total: int = Field(description="How many units matched.")
    truncated: bool = Field(description="True when more matched than were returned.")


class ServiceStatusResult(BaseModel):
    """The result of inspecting one unit."""

    scope: str = Field(description="user or system.")
    unit: str = Field(description="Unit name.")
    exit_code: int | None = Field(
        default=None,
        description="systemctl's exit status. Non-zero is normal for an inactive unit.",
    )
    output: str = Field(description="systemctl's full human-readable status output.")


class ServiceActionResult(BaseModel):
    """The result of starting, stopping, or restarting a unit."""

    scope: str = Field(description="user or system.")
    unit: str = Field(description="Unit name.")
    action: str = Field(description="start, stop, or restart.")
    escalated: bool = Field(description="True when polkit was used for privileges.")


def _validate_unit(unit: str) -> str:
    if not isinstance(unit, str) or not _UNIT_NAME.match(unit):
        raise InvalidPathError(
            f"Invalid unit name {unit!r}. Expected letters, digits, and @ . _ : - "
            "starting with a letter or digit, for example 'gdm.service'."
        )
    return unit


def _scope_flags(scope: str) -> list[str]:
    if scope == "user":
        return ["--user"]
    if scope == "system":
        return []
    raise InvalidPathError(f"scope must be 'user' or 'system', got {scope!r}.")


def list_units(
    *, scope: str = "user", name_filter: str | None = None, limit: int = 200
) -> ServiceListResult:
    """List systemd units in the given scope."""
    require_program("systemctl", purpose="Listing systemd units")
    flags = _scope_flags(scope)
    output = run_program(
        [
            "systemctl",
            *flags,
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--plain",
            "--no-legend",
        ],
        purpose=f"systemctl {' '.join(flags)} list-units".strip(),
        timeout_seconds=_LIST_TIMEOUT,
    )

    services: list[ServiceEntry] = []
    for line in output.splitlines():
        line = line.strip().lstrip("●").strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        services.append(
            ServiceEntry(
                unit=parts[0],
                load=parts[1],
                active=parts[2],
                sub=parts[3],
                description=parts[4] if len(parts) > 4 else "",
            )
        )

    if name_filter:
        needle = name_filter.lower()
        services = [
            entry
            for entry in services
            if needle in entry.unit.lower() or needle in entry.description.lower()
        ]
    total = len(services)
    return ServiceListResult(
        scope=scope, services=services[:limit], total=total, truncated=total > limit
    )


def unit_status(*, unit: str, scope: str = "user") -> ServiceStatusResult:
    """Return systemctl's status output for one unit."""
    unit = _validate_unit(unit)
    require_program("systemctl", purpose="Reading service status")
    flags = _scope_flags(scope)
    exit_code, output = capture_program(
        ["systemctl", *flags, "status", unit, "--no-pager", "--full"],
        timeout_seconds=_LIST_TIMEOUT,
    )
    return ServiceStatusResult(
        scope=scope, unit=unit, exit_code=exit_code, output=output
    )


def control_unit(
    *,
    unit: str,
    action: str,
    scope: str = "user",
    commands: CommandsConfig,
) -> ServiceActionResult:
    """Start, stop, or restart a unit, escalating for system units if permitted."""
    unit = _validate_unit(unit)
    if action not in ("start", "stop", "restart"):
        raise InvalidPathError(
            f"action must be start, stop, or restart, got {action!r}."
        )
    require_program("systemctl", purpose=f"Running systemctl {action}")

    flags = _scope_flags(scope)
    escalated = False
    if scope == "system":
        if not commands.allow_pkexec:
            raise OperationRefusedError(
                "Controlling system units needs privileges, but "
                "commands.allow_pkexec is false. Set it to true, or control a "
                "user unit instead (scope='user')."
            )
        require_program("pkexec", purpose="Controlling a system service")
        escalated = True

    run_program(
        ["systemctl", *flags, action, unit],
        purpose=f"systemctl {action} {unit}",
        timeout_seconds=_LIST_TIMEOUT,
        use_pkexec=escalated,
    )
    logger.info("systemctl %s %s (%s scope, escalated=%s)", action, unit, scope, escalated)
    return ServiceActionResult(
        scope=scope, unit=unit, action=action, escalated=escalated
    )


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the service tools on *server*."""
    commands = config.commands

    @server.tool(
        title="List systemd services",
        description=(
            "List systemd service units in the user or system scope, optionally "
            "filtered by a substring of the unit name or description."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def list_services(
        scope: Annotated[
            Literal["user", "system"], Field(description="Which systemd scope to list.")
        ] = "user",
        name_filter: Annotated[
            str | None, Field(description="Only include units containing this text.")
        ] = None,
        limit: Annotated[int, Field(gt=0, le=2000)] = 200,
    ) -> ServiceListResult:
        """List systemd service units."""
        logger.info("list_services(scope=%r, name_filter=%r)", scope, name_filter)
        try:
            return guarded(
                context,
                tool="list_services",
                arguments={"scope": scope, "name_filter": name_filter},
                action=lambda: list_units(
                    scope=scope, name_filter=name_filter, limit=limit
                ),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Show service status",
        description=(
            "Show systemctl's status for one unit. A non-zero exit status is "
            "normal and simply means the unit is not active."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def service_status(
        unit: Annotated[str, Field(description="Unit name, for example gdm.service.")],
        scope: Annotated[
            Literal["user", "system"], Field(description="Which systemd scope.")
        ] = "user",
    ) -> ServiceStatusResult:
        """Show status for one unit."""
        logger.info("service_status(unit=%r, scope=%r)", unit, scope)
        try:
            return guarded(
                context,
                tool="service_status",
                arguments={"unit": unit, "scope": scope},
                action=lambda: unit_status(unit=unit, scope=scope),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Start a service",
        description="Start a systemd unit. Requires approval.",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def start_service(
        unit: Annotated[str, Field(description="Unit name to start.")],
        scope: Annotated[
            Literal["user", "system"], Field(description="Which systemd scope.")
        ] = "user",
    ) -> ServiceActionResult:
        """Start a unit. Requires approval."""
        return _control(context, commands, unit, "start", scope)

    @server.tool(
        title="Stop a service",
        description=(
            "Stop a systemd unit. Stopping a service the desktop depends on can "
            "end your session. Requires approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def stop_service(
        unit: Annotated[str, Field(description="Unit name to stop.")],
        scope: Annotated[
            Literal["user", "system"], Field(description="Which systemd scope.")
        ] = "user",
    ) -> ServiceActionResult:
        """Stop a unit. Requires approval."""
        return _control(context, commands, unit, "stop", scope)

    @server.tool(
        title="Restart a service",
        description="Restart a systemd unit. Requires approval.",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False),
    )
    def restart_service(
        unit: Annotated[str, Field(description="Unit name to restart.")],
        scope: Annotated[
            Literal["user", "system"], Field(description="Which systemd scope.")
        ] = "user",
    ) -> ServiceActionResult:
        """Restart a unit. Requires approval."""
        return _control(context, commands, unit, "restart", scope)


def _control(
    context: GuardContext,
    commands: CommandsConfig,
    unit: str,
    action: str,
    scope: str,
) -> ServiceActionResult:
    logger.info("%s_service(unit=%r, scope=%r)", action, unit, scope)
    try:
        return guarded(
            context,
            tool=f"{action}_service",
            arguments={"unit": unit, "scope": scope},
            summary=f"{action.capitalize()} {scope} service {unit}",
            details=f"systemctl {'--user ' if scope == 'user' else ''}{action} {unit}",
            action=lambda: control_unit(
                unit=unit, action=action, scope=scope, commands=commands
            ),
        )
    except LinuxMCPError as exc:
        raise ToolError(str(exc)) from exc
