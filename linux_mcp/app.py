"""Server assembly: identity, instructions, and tool registration.

``build_server`` is the only place that constructs the MCP server object, so
tests can build servers from synthetic configurations without touching the
filesystem or the environment.
"""

from __future__ import annotations

from mcp.server import MCPServer

from linux_mcp import __version__
from linux_mcp.config import Config
from linux_mcp.guard import describe_tiers
from linux_mcp.tools import register_tools

SERVER_NAME = "linux-system"
"""Identifier reported to MCP clients."""

SERVER_TITLE = "Linux system control"
"""Human-readable name shown in client UIs."""


def build_server(config: Config, *, log_level: str = "INFO") -> MCPServer:
    """Create the MCP server with every tool registered against *config*."""
    server = MCPServer(
        SERVER_NAME,
        title=SERVER_TITLE,
        version=__version__,
        instructions=build_instructions(config),
        log_level=log_level,
    )
    register_tools(server, config)
    return server


def build_instructions(config: Config) -> str:
    """Describe the available capabilities and their limits to the model.

    Telling the model exactly which directories, applications, and tiers are
    configured saves a round trip of failed attempts, and it repeats the
    boundary so the model does not try to work around it.
    """
    readable = ", ".join(str(root) for root in config.read_allowlist().roots)
    writable = ", ".join(str(root) for root in config.write_allowlist().roots)
    applications = ", ".join(_describe_application(spec) for spec in config.applications.values())
    tiers = describe_tiers(config.policy.policy())
    power_actions = ", ".join(sorted(config.power.allow)) or "none"

    return (
        "Local control of this Linux desktop, running as the desktop user. "
        f"Files: browse_files, read_file, file_info, checksum, search_files, "
        f"search_content, and list_tree operate on: {readable}. "
        f"write_file, edit_file, create_directory, move_path, copy_path, and "
        f"trash_path operate inside: {writable}. take_screenshot saves inside the "
        "same writable directories. "
        f"Applications: open_application launches: {applications or 'none'}. "
        "System: get_system_info, get_resource_usage, and list_processes inspect "
        "the machine; kill_process, force_kill_process, delete_path, run_command, "
        "and run_shell change or destroy things. "
        "Desktop: get_setting/set_setting/list_settings use gsettings; get_volume, "
        "set_volume, and mute_audio control sound; send_notification shows a "
        "notification; list_packages, search_packages, package_info, "
        "install_package, remove_package, and update_system manage software; "
        "list_services, service_status, start_service, stop_service, and "
        "restart_service manage systemd units; lock_screen, end_session, "
        "suspend_system, hibernate_system, shutdown_system, and reboot_system "
        f"control power (permitted actions: {power_actions}); get_clipboard and "
        "set_clipboard read and write the clipboard. "
        f"Policy tiers: {tiers}. Tools in a confirming tier open a desktop approval "
        "dialog naming the exact action; if no dialog can be shown the action is "
        "refused. A refusal is final - report it to the user instead of retrying. "
        "Privileged work (packages, system services) goes through pkexec, which "
        "raises its own password prompt. Every call is written to an audit log. "
        "When a request is refused, the error message names the boundary - use it "
        "instead of guessing."
    )


def _describe_application(spec) -> str:
    label = spec.name
    if spec.description:
        label = f"{label} ({spec.description})"
    if not spec.available:
        return f"{label} [configured but unavailable]"
    return label