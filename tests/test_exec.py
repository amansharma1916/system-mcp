"""Execution runner: timeouts, tree-kill, truncation, and no-shell guarantees."""

from __future__ import annotations

import sys
import time

import pytest

from linux_mcp.errors import CommandFailedError, PrivilegeEscalationError
from linux_mcp.exec import build_command, run_argv


def nothing_installed(name: str) -> str | None:
    return None


def test_build_command_without_wrappers_is_the_argv_itself() -> None:
    assert build_command(["ls", "-la"], contain="none") == ["ls", "-la"]


def test_build_command_puts_pkexec_inner_most() -> None:
    command = build_command(
        ["pacman", "-S", "vim"],
        contain="systemd-scope",
        use_pkexec=True,
        which=lambda name: f"/usr/bin/{name}",
    )
    assert command[0] == "/usr/bin/systemd-run"
    assert "/usr/bin/pkexec" in command
    # pkexec must come after the containment separator, so it runs inside the scope.
    assert command.index("/usr/bin/pkexec") > command.index("--")
    assert command[-1] == "vim"


def test_build_command_refuses_pkexec_when_absent() -> None:
    with pytest.raises(PrivilegeEscalationError):
        build_command(["pacman", "-S", "vim"], use_pkexec=True, which=nothing_installed)


def test_run_argv_captures_stdout_and_exit_code() -> None:
    result = run_argv(
        [sys.executable, "-c", "print('hello')"],
        timeout_seconds=10,
        max_output_bytes=1000,
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "hello"
    assert result.timed_out is False
    assert result.stdout_truncated is False


def test_run_argv_reports_nonzero_without_raising_by_default() -> None:
    result = run_argv(
        [sys.executable, "-c", "raise SystemExit(3)"],
        timeout_seconds=10,
        max_output_bytes=1000,
    )
    assert result.exit_code == 3


def test_run_argv_check_true_raises_on_failure() -> None:
    with pytest.raises(CommandFailedError):
        run_argv(
            [sys.executable, "-c", "raise SystemExit(3)"],
            timeout_seconds=10,
            max_output_bytes=1000,
            check=True,
        )


def test_run_argv_truncates_large_output() -> None:
    result = run_argv(
        [sys.executable, "-c", "print('x' * 5000)"],
        timeout_seconds=10,
        max_output_bytes=100,
    )
    assert result.stdout_truncated is True
    assert len(result.stdout.encode("utf-8")) <= 100


def test_run_argv_does_not_split_multibyte_characters() -> None:
    result = run_argv(
        [sys.executable, "-c", "print('\u00e9' * 200)"],
        timeout_seconds=10,
        max_output_bytes=51,
    )
    assert result.stdout_truncated is True
    assert "\ufffd" not in result.stdout


def test_run_argv_kills_the_process_group_on_timeout() -> None:
    started = time.monotonic()
    result = run_argv(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        timeout_seconds=0.5,
        max_output_bytes=1000,
        kill_grace_seconds=3.0,
    )
    elapsed = time.monotonic() - started
    assert result.timed_out is True
    assert result.exit_code is None
    assert elapsed < 10


def test_run_argv_rejects_a_missing_executable() -> None:
    with pytest.raises(CommandFailedError):
        run_argv(
            ["definitely-not-a-real-program-xyz"],
            timeout_seconds=5,
            max_output_bytes=100,
        )


def test_run_argv_never_uses_a_shell() -> None:
    # Shell metacharacters in an argument are passed through literally.
    result = run_argv(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", "a; rm -rf /"],
        timeout_seconds=10,
        max_output_bytes=1000,
    )
    assert result.stdout.strip() == "a; rm -rf /"


def test_run_argv_honours_cwd(tmp_path) -> None:
    result = run_argv(
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        cwd=tmp_path,
        timeout_seconds=10,
        max_output_bytes=1000,
    )
    assert result.cwd == str(tmp_path)
    assert result.stdout.strip() == str(tmp_path)


def test_capture_output_false_does_not_wait_for_a_forked_grandchild() -> None:
    """Regression: a daemon that inherits the pipes must not stall the call.

    ``wl-copy`` forks a background process that keeps the inherited stdout and
    stderr open. When those are pipes, reading until EOF blocks long after the
    command itself has finished. With capture_output=False the streams go to
    /dev/null and the call returns as soon as the parent exits.
    """
    script = (
        "import os, time\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    time.sleep(5)\n"
        "    os._exit(0)\n"
        "print('parent finished', flush=True)\n"
    )
    started = time.monotonic()
    result = run_argv(
        [sys.executable, "-c", script],
        timeout_seconds=10,
        max_output_bytes=1000,
        capture_output=False,
    )
    elapsed = time.monotonic() - started
    assert result.exit_code == 0
    assert elapsed < 3, "waited for the forked grandchild to release the pipes"
