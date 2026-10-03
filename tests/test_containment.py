"""Containment wrappers: argv construction and fail-closed availability."""

from __future__ import annotations

import pytest

from linux_mcp.containment import DEFAULT_CPU_QUOTA, build_wrapper
from linux_mcp.errors import ContainmentUnavailableError


def test_none_mode_produces_no_wrapper() -> None:
    assert build_wrapper("none", which=lambda name: "/usr/bin/systemd-run") is None


def test_systemd_scope_wrapper_has_caps_and_separator() -> None:
    wrapper = build_wrapper(
        "systemd-scope",
        memory_max_bytes=1024,
        cpu_quota="50%",
        which=lambda name: "/usr/bin/systemd-run",
    )
    assert wrapper is not None
    assert wrapper[0] == "/usr/bin/systemd-run"
    assert "--user" in wrapper
    assert "--scope" in wrapper
    assert "-p" in wrapper
    assert "MemoryMax=1024" in wrapper
    assert "CPUQuota=50%" in wrapper
    assert wrapper[-1] == "--"


def test_defaults_are_two_gib_and_two_cores() -> None:
    wrapper = build_wrapper("systemd-scope", which=lambda name: "/usr/bin/systemd-run")
    assert wrapper is not None
    assert "MemoryMax=2147483648" in wrapper
    assert f"CPUQuota={DEFAULT_CPU_QUOTA}" in wrapper


def test_missing_systemd_run_fails_closed() -> None:
    with pytest.raises(ContainmentUnavailableError):
        build_wrapper("systemd-scope", which=lambda name: None)


def test_unknown_mode_is_refused() -> None:
    with pytest.raises(ContainmentUnavailableError):
        build_wrapper("bubblewrap", which=lambda name: "/usr/bin/bwrap")  # type: ignore[arg-type]
