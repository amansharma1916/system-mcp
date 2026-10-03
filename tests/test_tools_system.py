"""System information and process tools."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from linux_mcp.errors import (
    InvalidPathError,
    OperationRefusedError,
    PathDoesNotExistError,
)
from linux_mcp.tools.system import (
    collect_processes,
    resource_usage,
    signal_process,
    system_information,
)


def test_system_information_reports_the_machine() -> None:
    info = system_information()
    assert info.hostname
    assert info.os_name
    assert info.kernel
    assert info.architecture
    assert info.cpu_count >= 1
    assert info.uid == os.getuid()
    assert len(info.load_average) == 3
    assert info.uptime_seconds > 0


def test_resource_usage_reports_memory_and_disk() -> None:
    usage = resource_usage()
    assert usage.memory_total_bytes > 0
    assert usage.memory_available_bytes > 0
    assert 0 <= usage.memory_used_percent <= 100
    assert usage.disk_total_bytes > 0
    assert 0 <= usage.disk_used_percent <= 100
    assert usage.top_processes


def test_collect_processes_includes_the_current_process() -> None:
    result = collect_processes(limit=1000)
    assert result.total_visible > 0
    assert os.getpid() in {process.pid for process in result.processes} or (
        result.total_visible > result.returned
    )


def test_collect_processes_filters_by_name() -> None:
    result = collect_processes(name_filter="python", limit=1000)
    assert all(
        "python" in process.name.lower() or "python" in process.command.lower()
        for process in result.processes
    )


def test_collect_processes_truncates_to_the_limit() -> None:
    result = collect_processes(limit=1)
    assert result.returned <= 1
    if result.total_visible > 1:
        assert result.truncated is True


def test_signal_process_refuses_a_non_positive_pid() -> None:
    with pytest.raises(InvalidPathError):
        signal_process(0)
    with pytest.raises(InvalidPathError):
        signal_process(-5)


def test_signal_process_refuses_the_server_itself() -> None:
    with pytest.raises(OperationRefusedError):
        signal_process(os.getpid())


def test_signal_process_refuses_a_missing_pid() -> None:
    with pytest.raises(PathDoesNotExistError):
        signal_process(999_999_999)


def test_signal_process_refuses_an_unknown_signal_name() -> None:
    with pytest.raises(InvalidPathError):
        signal_process(os.getpid() + 1, signal_name="SIGWHATEVER")


def test_signal_process_terminates_a_child_we_own() -> None:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        result = signal_process(child.pid, signal_name="SIGTERM")
        assert result.pid == child.pid
        assert result.signal == "SIGTERM"
        child.wait(timeout=5)
        assert child.returncode is not None
    finally:
        if child.poll() is None:  # pragma: no cover - defensive cleanup
            child.kill()
            child.wait(timeout=5)


def test_signal_process_reports_a_process_that_ignores_sigterm() -> None:
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print('ready', flush=True); "
                "time.sleep(30)"
            ),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        # Wait until the handler is installed, otherwise SIGTERM may arrive first.
        assert child.stdout.readline().strip() == "ready"
        result = signal_process(child.pid, signal_name="SIGTERM")
        time.sleep(0.1)
        # Still alive: SIGTERM was ignored, which is exactly why SIGKILL exists.
        assert result.name
        assert child.poll() is None
    finally:
        child.kill()
        child.wait(timeout=5)
