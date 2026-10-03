"""Tests for stderr-only logging.

If a log record ever reaches stdout the MCP wire is corrupted and every client
breaks, so this property is asserted directly rather than assumed.

These tests use pytest's ``capsys`` fixture rather than replacing ``sys.stderr``
by hand: pytest re-installs its capture objects at the start of the *call* phase,
which silently undoes a manual patch made during fixture setup. Process-level
proof that stdout stays clean lives in ``test_stdio_integration.py``.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterator

import pytest

from linux_mcp.logging_setup import (
    StdoutLoggingError,
    assert_no_stdout_handlers,
    configure_logging,
    get_logger,
    normalize_level,
)


@pytest.fixture
def logging_state() -> Iterator[None]:
    """Undo the global logging changes made by ``configure_logging``."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    try:
        yield
    finally:
        for handler in list(root.handlers):
            if handler not in saved_handlers:
                root.removeHandler(handler)
                handler.close()
        root.setLevel(saved_level)


def test_records_are_written_to_stderr_and_never_to_stdout(
    capsys: pytest.CaptureFixture[str], logging_state: None
) -> None:
    logger = configure_logging("INFO")
    get_logger("test").info("diagnostic message")

    captured = capsys.readouterr()
    assert "diagnostic message" in captured.err
    assert captured.out == ""
    assert logger.name == "linux_mcp"


def test_configure_logging_is_idempotent(
    capsys: pytest.CaptureFixture[str], logging_state: None
) -> None:
    configure_logging("INFO")
    configure_logging("DEBUG")

    owned = [
        handler
        for handler in logging.getLogger().handlers
        if getattr(handler, "_linux_mcp_handler", False)
    ]
    assert len(owned) == 1
    assert logging.getLogger().level == logging.DEBUG


def test_a_stdout_handler_is_detected_and_refused(capsys: pytest.CaptureFixture[str]) -> None:
    handler = logging.StreamHandler(sys.stdout)
    logger = get_logger("test")
    logger.addHandler(handler)
    try:
        with pytest.raises(StdoutLoggingError) as excinfo:
            assert_no_stdout_handlers()
        assert "corrupted" in str(excinfo.value)
    finally:
        logger.removeHandler(handler)
        handler.close()

    assert_no_stdout_handlers()  # clean again


def test_a_stdout_handler_is_detected_on_the_root_logger(
    capsys: pytest.CaptureFixture[str],
) -> None:
    handler = logging.StreamHandler(sys.stdout)
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        with pytest.raises(StdoutLoggingError):
            assert_no_stdout_handlers()
    finally:
        root.removeHandler(handler)
        handler.close()


def test_the_own_handler_is_never_on_stdout(logging_state: None) -> None:
    configure_logging("INFO")
    assert_no_stdout_handlers()


@pytest.mark.parametrize("level", ["DEBUG", "info", "Warning", "error", "critical"])
def test_levels_are_accepted_case_insensitively(level: str) -> None:
    assert isinstance(normalize_level(level), int)


def test_invalid_level_is_rejected() -> None:
    with pytest.raises(ValueError) as excinfo:
        normalize_level("LOUD")
    assert "Invalid log level" in str(excinfo.value)
    with pytest.raises(ValueError):
        configure_logging("LOUD")


def test_integer_levels_are_passed_through() -> None:
    assert normalize_level(logging.WARNING) == logging.WARNING


def test_logger_names_are_namespaced() -> None:
    assert get_logger().name == "linux_mcp"
    assert get_logger("tools.filesystem").name == "linux_mcp.tools.filesystem"
    assert get_logger("linux_mcp.config").name == "linux_mcp.config"