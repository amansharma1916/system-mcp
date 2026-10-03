"""Command line entry point for the server.

``python server.py`` runs this. Everything here fails safely: configuration and
privilege problems produce a clear message on stderr and a non-zero exit status,
never a half-started server with a weaker policy.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from linux_mcp import __version__
from linux_mcp.app import build_server
from linux_mcp.config import Config, load_config
from linux_mcp.errors import LinuxMCPError, PrivilegeError
from linux_mcp.logging_setup import LOG_LEVELS, configure_logging
from linux_mcp.policy import TIER_ORDER

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3

LOG_LEVEL_ENV = "LINUX_MCP_LOG_LEVEL"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for ``python server.py --help``."""
    parser = argparse.ArgumentParser(
        prog="linux-mcp",
        description=(
            "Local Linux desktop MCP server speaking STDIO. Exposes filesystem, "
            "system, process, and command tools under a tiered policy: read-only "
            "tools run freely, write tools change files, and system/destructive "
            "tools require human approval through a desktop dialog."
        ),
        epilog=(
            "An MCP client normally launches this script itself, for example "
            "command: /path/to/.venv/bin/python, args: [/path/to/server.py]."
        ),
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help=(
            "Configuration file to read. Defaults to $LINUX_MCP_CONFIG, then "
            "config/config.yaml, then ~/.config/linux-mcp/config.yaml."
        ),
    )
    parser.add_argument(
        "--log-level",
        choices=LOG_LEVELS,
        default=os.environ.get(LOG_LEVEL_ENV, "INFO").upper(),
        help=(
            "Diagnostic verbosity for stderr (MCP traffic always uses stdout). "
            f"Default: ${LOG_LEVEL_ENV} or %(default)s."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate the configuration, print a summary, and exit without serving.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def ensure_not_root() -> None:
    """Refuse to run with root privileges.

    Raising here means the server cannot be started with ``sudo`` even if the
    user asks for it: an AI-facing filesystem and desktop capability must never
    run with more privilege than the human at the keyboard.
    """
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        raise PrivilegeError(
            "Refusing to run as root. This server exposes filesystem browsing and "
            "application launching to a language model, so it must run as your "
            "normal desktop user. Start it without sudo."
        )


def log_startup_summary(logger, config: Config) -> None:
    """Log what the server is about to be allowed to do."""
    logger.info("Configuration file: %s", config.source)
    logger.info(
        "Readable directories: %s",
        ", ".join(str(root) for root in config.read_allowlist().roots),
    )
    logger.info(
        "Writable directories: %s",
        ", ".join(str(root) for root in config.write_allowlist().roots),
    )
    policy = config.policy.policy()
    logger.info(
        "Enabled tiers: %s",
        ", ".join(tier.value for tier in TIER_ORDER if tier in policy.enabled_tiers)
        or "none",
    )
    logger.info(
        "Tiers requiring approval: %s",
        ", ".join(tier.value for tier in TIER_ORDER if tier in policy.confirm_tiers)
        or "none",
    )
    logger.info("Audit log: %s", config.policy.audit.path)
    logger.info("Command containment: %s", config.commands.containment)
    logger.info(
        "Allowed applications: %s", ", ".join(config.application_names()) or "none"
    )
    unavailable = [
        f"{spec.name} ({spec.unavailable_reason})"
        for spec in config.applications.values()
        if not spec.available
    ]
    if unavailable:
        logger.warning("Allowlisted but unavailable: %s", "; ".join(unavailable))
    logger.info(
        "Per-call entry limit for browse_files: %d", config.directories.max_entries
    )


def format_config_summary(config: Config) -> str:
    """Render the ``--check`` summary.

    Written to stdout only in ``--check`` mode, where no MCP session is being
    served and stdout is therefore not the protocol wire.
    """
    lines = [
        "Configuration is valid.",
        f"  file: {config.source}",
        f"  readable directories ({len(config.read_allowlist().roots)}):",
    ]
    lines.extend(f"    {root}" for root in config.read_allowlist().roots)
    lines.append(f"  writable directories ({len(config.write_allowlist().roots)}):")
    lines.extend(f"    {root}" for root in config.write_allowlist().roots)
    policy = config.policy.policy()
    enabled = ", ".join(
        tier.value for tier in TIER_ORDER if tier in policy.enabled_tiers
    ) or "none"
    confirming = ", ".join(
        tier.value for tier in TIER_ORDER if tier in policy.confirm_tiers
    ) or "none"
    lines.append(f"  tiers enabled: {enabled}")
    lines.append(f"  tiers requiring approval: {confirming}")
    lines.append(
        f"  approved via: {config.policy.approval.mechanism} "
        f"(timeout {config.policy.approval.timeout_seconds:g}s)"
    )
    lines.append(
        f"  audit log: {config.policy.audit.path} "
        f"({'enabled' if config.policy.audit.enabled else 'disabled'})"
    )
    lines.append(f"  command containment: {config.commands.containment}")
    lines.append(
        f"  allowed applications ({len(config.applications)}), max_entries="
        f"{config.directories.max_entries}:"
    )
    for spec in sorted(config.applications.values(), key=lambda item: item.name):
        status = "ok" if spec.available else f"UNAVAILABLE: {spec.unavailable_reason}"
        description = f" - {spec.description}" if spec.description else ""
        lines.append(f"    {spec.name} -> {' '.join(spec.command)}{description} [{status}]")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the server. Returns the process exit status."""
    args = build_parser().parse_args(argv)

    try:
        logger = configure_logging(args.log_level)
    except ValueError as exc:
        print(f"linux-mcp: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        ensure_not_root()
        config = load_config(args.config)
    except LinuxMCPError as exc:
        logger.error("%s", exc)
        return EXIT_CONFIG

    log_startup_summary(logger, config)

    if args.check:
        print(format_config_summary(config), file=sys.stdout)
        return EXIT_OK

    try:
        server = build_server(config, log_level=args.log_level)
    except LinuxMCPError as exc:
        logger.error("Could not build the MCP server: %s", exc)
        return EXIT_CONFIG
    except Exception:
        logger.exception("Unexpected failure while building the MCP server.")
        return EXIT_UNEXPECTED

    logger.info(
        "%s %s serving MCP over STDIO (stdout carries protocol messages only).",
        "linux-mcp",
        __version__,
    )
    try:
        server.run(transport="stdio")
    except KeyboardInterrupt:
        logger.info("Interrupted; shutting down.")
        return EXIT_OK
    except Exception:
        logger.exception("The MCP server terminated unexpectedly.")
        return EXIT_UNEXPECTED
    return EXIT_OK