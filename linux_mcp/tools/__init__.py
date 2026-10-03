"""MCP tools exposed by this server.

Each module in this package owns one capability and exposes a
``register(server, config, context)`` function that declares it on the server.
Adding a capability means adding one module here and listing it in
:data:`_REGISTRARS` - no other file changes, and every new capability gets its
own explicit tier in :data:`linux_mcp.policy.TIER_REGISTRY`.

Tools contain no policy logic of their own: they resolve paths, then call
:func:`linux_mcp.guard.guarded`, which enforces the tier, prompts for approval
when required, and writes the audit record.
"""

from __future__ import annotations

from collections.abc import Callable

from mcp.server import MCPServer

from linux_mcp.config import Config
from linux_mcp.guard import GuardContext
from linux_mcp.tools import (
    applications,
    audio,
    clipboard,
    commands,
    filesystem,
    filesystem_read,
    filesystem_write,
    notifications,
    packages,
    power,
    screenshots,
    services,
    settings,
    system,
)

Registrar = Callable[[MCPServer, Config, GuardContext], None]

_REGISTRARS: tuple[Registrar, ...] = (
    filesystem.register,
    applications.register,
    filesystem_read.register,
    filesystem_write.register,
    system.register,
    commands.register,
    settings.register,
    audio.register,
    notifications.register,
    packages.register,
    services.register,
    power.register,
    clipboard.register,
    screenshots.register,
)


def register_tools(server: MCPServer, config: Config) -> None:
    """Declare every tool on *server* using the validated *config*."""
    context = GuardContext.from_config(config)
    for register in _REGISTRARS:
        register(server, config, context)


__all__ = ["register_tools"]
