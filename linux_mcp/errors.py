"""Typed, model-friendly errors.

Every failure this project raises on purpose derives from
:class:`LinuxMCPError`. Tool handlers translate these into MCP ``ToolError``
results, so the AI client receives a clear sentence it can act on instead of a
Python stack trace.

The messages are written for a language model: say what was refused, why, and
what the valid choices are.
"""

from __future__ import annotations


class LinuxMCPError(Exception):
    """Base class for all expected, user-facing failures."""


class ConfigError(LinuxMCPError):
    """The configuration file is missing, unreadable, or invalid."""


class PrivilegeError(LinuxMCPError):
    """The server was started with privileges it must not have (for example as root)."""


class InvalidPathError(LinuxMCPError):
    """The requested path is malformed: empty, relative, or contains junk."""


class PathOutsideAllowlistError(LinuxMCPError):
    """The requested path resolves outside every configured allowed directory."""


class PathDoesNotExistError(LinuxMCPError):
    """The requested path does not exist."""


class PathNotDirectoryError(LinuxMCPError):
    """The requested path exists but is not a directory."""


class DirectoryReadError(LinuxMCPError):
    """The directory exists but could not be listed, for example on EACCES."""


class ApplicationNotAllowedError(LinuxMCPError):
    """The requested application name is not in the configured allowlist."""


class ApplicationUnavailableError(LinuxMCPError):
    """The application is allowlisted but its executable cannot be used."""


class ApplicationLaunchError(LinuxMCPError):
    """The executable was found but launching it failed."""


class UndeclaredToolError(LinuxMCPError):
    """A tool has no declared policy tier and is therefore refused (deny-by-default)."""


class TierDisabledError(LinuxMCPError):
    """The tool's policy tier is disabled in the configuration."""


class ApprovalDeniedError(LinuxMCPError):
    """A human declined the action, or the approval prompt went unanswered."""


class ApprovalUnavailableError(LinuxMCPError):
    """No approval mechanism was available, so the action was refused."""


class ContainmentUnavailableError(LinuxMCPError):
    """Requested execution containment is not available on this system."""


class CommandTimeoutError(LinuxMCPError):
    """A command exceeded its timeout and was killed."""


class CommandFailedError(LinuxMCPError):
    """A command could not be started, or exited non-zero when failure was requested."""


class OutputLimitError(LinuxMCPError):
    """Requested output exceeds the configured size limit."""


class OperationRefusedError(LinuxMCPError):
    """A safety precondition refused the operation before it changed anything."""


class PrivilegeEscalationError(LinuxMCPError):
    """A privileged action was requested but escalation is not permitted."""