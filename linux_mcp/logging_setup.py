"""Diagnostic logging that can never corrupt the MCP protocol stream.

MCP over STDIO uses **stdout as the wire**, so every diagnostic record must
reach **stderr**. :func:`configure_logging` is the only place in this project
that installs log handlers, and it verifies afterwards that no handler is
attached to stdout - a single stray log line on stdout would break every
connected client.

Log records never contain file contents, environment variables, or other
secrets: tool arguments, resolved paths, and process ids only.
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "linux_mcp"
"""Root of this project's logger tree."""

LOG_LEVELS: tuple[str, ...] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_OWNED_ATTRIBUTE = "_linux_mcp_handler"


class StdoutLoggingError(RuntimeError):
    """A log handler writes to stdout, which would corrupt MCP STDIO traffic."""


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger inside this project's namespace."""
    if not name:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(f"{LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def normalize_level(level: str | int) -> int:
    """Translate a level name such as ``"INFO"`` into a :mod:`logging` constant."""
    if isinstance(level, int):
        return level
    candidate = str(level).strip().upper()
    if candidate not in LOG_LEVELS:
        raise ValueError(
            f"Invalid log level {level!r}; expected one of {', '.join(LOG_LEVELS)}."
        )
    return getattr(logging, candidate)


def assert_no_stdout_handlers() -> None:
    """Raise :class:`StdoutLoggingError` if any active handler writes to stdout."""
    for logger in [logging.getLogger()] + [
        logging.getLogger(name)
        for name in list(logging.Logger.manager.loggerDict)
        if name == LOGGER_NAME or name.startswith(f"{LOGGER_NAME}.")
    ]:
        for handler in logger.handlers:
            if getattr(handler, "stream", None) is sys.stdout:
                raise StdoutLoggingError(
                    f"{logger.name} has a handler on stdout; MCP STDIO traffic "
                    "would be corrupted. Log to stderr instead."
                )


def configure_logging(level: str | int = "INFO") -> logging.Logger:
    """Install a stderr handler on the root logger and return this package's logger.

    Idempotent: calling it twice does not duplicate handlers, and it never
    removes handlers installed by someone else (for example pytest's capture
    handler or an embedding application).
    """
    numeric_level = normalize_level(level)
    root = logging.getLogger()

    if not any(getattr(handler, _OWNED_ATTRIBUTE, False) for handler in root.handlers):
        handler = logging.StreamHandler(sys.stderr)
        setattr(handler, _OWNED_ATTRIBUTE, True)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))
        root.addHandler(handler)

    root.setLevel(numeric_level)
    assert_no_stdout_handlers()
    return get_logger()