"""Raw command execution: gating, argv construction, cwd, and timeouts."""

from __future__ import annotations

import sys

import pytest

from linux_mcp.config import CommandsConfig, LimitsConfig
from linux_mcp.errors import (
    InvalidPathError,
    OperationRefusedError,
    PrivilegeEscalationError,
)
from linux_mcp.security import Allowlist
from linux_mcp.tools.commands import execute_command, execute_shell


@pytest.fixture
def allowlist(workspace) -> Allowlist:
    return Allowlist([workspace.allowed])


def run(allowlist, workspace, **kwargs):
    return execute_command(
        kwargs.pop("executable", sys.executable),
        kwargs.pop("args", ["-c", "print('hi')"]),
        cwd=kwargs.pop("cwd", None),
        timeout_seconds=kwargs.pop("timeout_seconds", None),
        use_pkexec=kwargs.pop("use_pkexec", False),
        read_allowlist=allowlist,
        limits=kwargs.pop("limits", LimitsConfig()),
        commands=kwargs.pop("commands", CommandsConfig(containment="none")),
    )


# --------------------------------------------------------------------------- #
# run_command
# --------------------------------------------------------------------------- #


def test_run_command_captures_output(allowlist, workspace) -> None:
    result = run(allowlist, workspace)
    assert result.exit_code == 0
    assert result.stdout.strip() == "hi"
    assert result.timed_out is False
    assert result.argv[0] == sys.executable


def test_run_command_reports_a_nonzero_exit(allowlist, workspace) -> None:
    result = run(allowlist, workspace, args=["-c", "raise SystemExit(7)"])
    assert result.exit_code == 7


def test_run_command_refuses_when_disabled(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError) as excinfo:
        run(allowlist, workspace, commands=CommandsConfig(run_command_enabled=False))
    assert "commands.run_command_enabled" in str(excinfo.value)


def test_run_command_accepts_an_empty_executable_arg_list(allowlist, workspace) -> None:
    result = run(
        allowlist,
        workspace,
        executable=sys.executable,
        args=["-c", "import sys; print(len(sys.argv))"],
    )
    assert result.stdout.strip() == "1"


def test_run_command_refuses_an_empty_executable(allowlist, workspace) -> None:
    with pytest.raises(InvalidPathError):
        run(allowlist, workspace, executable="", args=[])


def test_run_command_refuses_nul_in_arguments(allowlist, workspace) -> None:
    with pytest.raises(InvalidPathError):
        run(allowlist, workspace, args=["-c", "pass", "bad\x00arg"])


@pytest.mark.parametrize("refused", ["pkexec-only"])
def test_run_command_refuses_pkexec_when_disallowed(
    allowlist, workspace, refused
) -> None:
    with pytest.raises(OperationRefusedError):
        run(
            allowlist,
            workspace,
            use_pkexec=True,
            commands=CommandsConfig(containment="none", allow_pkexec=False),
        )


def test_run_command_refuses_pkexec_when_pkexec_is_missing(
    allowlist, workspace, monkeypatch
) -> None:
    monkeypatch.setattr("linux_mcp.exec.shutil.which", lambda name: None)
    with pytest.raises(PrivilegeEscalationError):
        run(
            allowlist,
            workspace,
            use_pkexec=True,
            commands=CommandsConfig(containment="none", allow_pkexec=True),
        )


def test_run_command_refuses_a_cwd_outside_the_allowlist(allowlist, workspace) -> None:
    from linux_mcp.errors import PathOutsideAllowlistError

    with pytest.raises(PathOutsideAllowlistError):
        run(allowlist, workspace, cwd=str(workspace.outside))


def test_run_command_uses_an_allowed_cwd(allowlist, workspace) -> None:
    result = run(
        allowlist,
        workspace,
        args=["-c", "import os; print(os.getcwd())"],
        cwd=str(workspace.allowed),
    )
    assert result.stdout.strip() == str(workspace.allowed)
    assert result.cwd == str(workspace.allowed)


def test_run_command_refuses_a_timeout_above_the_maximum(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError):
        run(
            allowlist,
            workspace,
            timeout_seconds=9999,
            limits=LimitsConfig(max_timeout_seconds=600),
        )


def test_run_command_kills_the_process_group_on_timeout(allowlist, workspace) -> None:
    result = run(
        allowlist,
        workspace,
        args=["-c", "import time; time.sleep(30)"],
        timeout_seconds=0.5,
        limits=LimitsConfig(max_timeout_seconds=600, kill_grace_seconds=3.0),
    )
    assert result.timed_out is True
    assert result.exit_code is None


# --------------------------------------------------------------------------- #
# run_shell
# --------------------------------------------------------------------------- #


def shell(allowlist, script, **kwargs):
    return execute_shell(
        script,
        cwd=kwargs.pop("cwd", None),
        timeout_seconds=kwargs.pop("timeout_seconds", None),
        use_pkexec=kwargs.pop("use_pkexec", False),
        read_allowlist=allowlist,
        limits=kwargs.pop("limits", LimitsConfig()),
        commands=kwargs.pop("commands", CommandsConfig(containment="none")),
    )


def test_run_shell_supports_pipes(allowlist, workspace) -> None:
    result = shell(allowlist, "printf 'a\\nb\\n' | wc -l")
    assert result.exit_code == 0
    assert result.stdout.strip() == "2"


def test_run_shell_builds_an_explicit_bash_argv(allowlist, workspace) -> None:
    result = shell(allowlist, "echo ok")
    assert result.argv[0].endswith("bash")
    assert result.argv[1] == "-lc"
    assert result.argv[2] == "echo ok"


def test_run_shell_refuses_when_disabled(allowlist, workspace) -> None:
    with pytest.raises(OperationRefusedError) as excinfo:
        shell(allowlist, "echo hi", commands=CommandsConfig(run_shell_enabled=False))
    assert "commands.run_shell_enabled" in str(excinfo.value)


def test_run_shell_refuses_an_empty_script(allowlist, workspace) -> None:
    with pytest.raises(InvalidPathError):
        shell(allowlist, "   ")


def test_run_shell_two_arg_command_is_not_reinterpreted(allowlist, workspace) -> None:
    # A semicolon inside a single argument is data, not a separator.
    result = shell(allowlist, "printf '%s' 'a; echo nope'")
    assert result.stdout == "a; echo nope"
