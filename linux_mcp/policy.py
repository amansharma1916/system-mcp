"""Policy engine: every tool declares a tier; nothing runs without one.

This module holds *no* MCP imports on purpose, so the whole permission model is
unit-testable in isolation. The rule is deny-by-default: a tool whose name is
absent from :data:`TIER_REGISTRY` is refused, so adding a tool without thinking
about its blast radius fails loudly instead of silently granting access.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from linux_mcp.errors import TierDisabledError, UndeclaredToolError


class Tier(str, Enum):
    """How much damage a tool can do, from harmless to arbitrary execution."""

    READONLY = "readonly"
    WRITE = "write"
    SYSTEM = "system"
    DESTRUCTIVE = "destructive"


TIER_ORDER: tuple[Tier, ...] = (
    Tier.READONLY,
    Tier.WRITE,
    Tier.SYSTEM,
    Tier.DESTRUCTIVE,
)
"""Ascending severity, useful for reporting enabled tiers in a stable order."""

TIER_DESCRIPTIONS: Mapping[Tier, str] = {
    Tier.READONLY: "read-only inspection; nothing on the system changes",
    Tier.WRITE: "creates or modifies files inside the configured write directories",
    Tier.SYSTEM: "changes system or session state",
    Tier.DESTRUCTIVE: "irreversible, or executes arbitrary commands",
}

TIER_REGISTRY: Mapping[str, Tier] = {
    # Existing tools (migrated to guard in Phase 1b).
    "browse_files": Tier.READONLY,
    "open_application": Tier.WRITE,
    # Phase 1 — read-only.
    "read_file": Tier.READONLY,
    "list_tree": Tier.READONLY,
    "search_files": Tier.READONLY,
    "search_content": Tier.READONLY,
    "file_info": Tier.READONLY,
    "checksum": Tier.READONLY,
    "get_system_info": Tier.READONLY,
    "get_resource_usage": Tier.READONLY,
    "list_processes": Tier.READONLY,
    # Phase 1 — write.
    "write_file": Tier.WRITE,
    "edit_file": Tier.WRITE,
    "create_directory": Tier.WRITE,
    "move_path": Tier.WRITE,
    "copy_path": Tier.WRITE,
    "trash_path": Tier.WRITE,
    # Phase 1 — system.
    "kill_process": Tier.SYSTEM,
    # Phase 1 — destructive.
    "delete_path": Tier.DESTRUCTIVE,
    "force_kill_process": Tier.DESTRUCTIVE,
    "run_command": Tier.DESTRUCTIVE,
    "run_shell": Tier.DESTRUCTIVE,
    # Phase 2 — read-only.
    "get_setting": Tier.READONLY,
    "list_settings": Tier.READONLY,
    "get_volume": Tier.READONLY,
    "list_packages": Tier.READONLY,
    "search_packages": Tier.READONLY,
    "package_info": Tier.READONLY,
    "list_services": Tier.READONLY,
    "service_status": Tier.READONLY,
    "get_clipboard": Tier.READONLY,
    # Phase 2 — write (visible but benign side effects).
    "send_notification": Tier.WRITE,
    "set_clipboard": Tier.WRITE,
    "take_screenshot": Tier.WRITE,
    # Phase 2 — system.
    "set_setting": Tier.SYSTEM,
    "set_volume": Tier.SYSTEM,
    "mute_audio": Tier.SYSTEM,
    "start_service": Tier.SYSTEM,
    "stop_service": Tier.SYSTEM,
    "restart_service": Tier.SYSTEM,
    "lock_screen": Tier.SYSTEM,
    "end_session": Tier.SYSTEM,
    "suspend_system": Tier.SYSTEM,
    # Phase 2 — destructive.
    "install_package": Tier.DESTRUCTIVE,
    "remove_package": Tier.DESTRUCTIVE,
    "update_system": Tier.DESTRUCTIVE,
    "shutdown_system": Tier.DESTRUCTIVE,
    "reboot_system": Tier.DESTRUCTIVE,
    "hibernate_system": Tier.DESTRUCTIVE,
}
"""Tool name -> tier. A name absent from this mapping is refused outright.

A tool's tier is decided by its **name only**; there is no per-argument tier.
Where a capability has a safe and a dangerous form, they are two tools
(``trash_path`` vs ``delete_path``) so the registry, the audit record, and the
approval dialog always agree on exactly one tier.
"""


@dataclass(frozen=True, slots=True)
class Policy:
    """Which tiers may run, and which of those need human approval."""

    enabled_tiers: frozenset[Tier]
    confirm_tiers: frozenset[Tier]

    def tier_of(self, tool_name: str) -> Tier:
        """Return the declared tier for *tool_name*, or refuse it."""
        tier = TIER_REGISTRY.get(tool_name)
        if tier is None:
            raise UndeclaredToolError(
                f"Tool {tool_name!r} has no declared policy tier and is refused "
                "(deny-by-default). Add it to TIER_REGISTRY in linux_mcp/policy.py "
                "to give it a tier."
            )
        return tier

    def is_enabled(self, tier: Tier) -> bool:
        """True when *tier* may execute at all."""
        return tier in self.enabled_tiers

    def requires_confirmation(self, tier: Tier) -> bool:
        """True when *tier* requires a human approval before executing."""
        return tier in self.confirm_tiers

    def require_enabled(self, tool_name: str) -> Tier:
        """Resolve *tool_name*'s tier, raising if it is undeclared or disabled."""
        tier = self.tier_of(tool_name)
        if not self.is_enabled(tier):
            enabled = ", ".join(t.value for t in TIER_ORDER if t in self.enabled_tiers)
            raise TierDisabledError(
                f"Tool {tool_name!r} is tier {tier.value!r}, which is disabled. "
                f"Enabled tiers: {enabled or 'none'}. Add {tier.value!r} to "
                "policy.enabled_tiers to allow it."
            )
        return tier
