"""Tests for the ``open_application`` tool.

The security-critical properties are: only allowlisted names can be launched, no
shell or shell syntax is ever involved, arguments cannot be injected, and a
broken configuration produces a clear error instead of a crash.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from collections.abc import Callable

import pytest

from linux_mcp.config import ApplicationSpec, Config, build_application_spec
from linux_mcp.errors import (
    ApplicationLaunchError,
    ApplicationNotAllowedError,
    ApplicationUnavailableError,
)
from linux_mcp.policy import TIER_REGISTRY
from linux_mcp.tools import applications as applications_module
from linux_mcp.tools.applications import launch_application
from tests.conftest import Workspace

TRUE = shutil.which("true")
FALSE = shutil.which("false")


def spec(name: str, command: object, description: str = "") -> ApplicationSpec:
    """Build a spec through the real validation code path."""
    return build_application_spec(name, command, description)


def test_allowlisted_application_is_launched(
    make_config: Callable[..., Config],
) -> None:
    specs = {"ok": spec("ok", "true")}
    result = launch_application("ok", applications=specs, probe_seconds=2.0)

    assert result.launched is True
    assert result.name == "ok"
    assert result.executable == TRUE
    assert result.argv == [TRUE]
    assert result.message


def test_running_application_reports_its_pid(
    make_config: Callable[..., Config],
) -> None:
    """A process that stays alive is reported as running, with its pid."""
    specs = {"sleeper": spec("sleeper", [sys.executable, "-c", "import time; time.sleep(60)"])}
    result = launch_application("sleeper", applications=specs, probe_seconds=0.3)

    try:
        assert result.launched is True
        assert result.pid is not None
        os.kill(result.pid, 0)  # still alive
        assert str(result.pid) in result.message
    finally:
        assert result.pid is not None
        try:
            os.kill(result.pid, signal.SIGTERM)
            os.waitpid(result.pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass


def test_application_names_are_normalized() -> None:
    specs = {"code": spec("code", "true")}
    assert launch_application("  CODE  ", applications=specs, probe_seconds=2.0).name == "code"


def test_unknown_application_is_refused_with_the_allowlist() -> None:
    specs = {"code": spec("code", "true"), "firefox": spec("firefox", "true")}
    with pytest.raises(ApplicationNotAllowedError) as excinfo:
        launch_application("rm", applications=specs)

    message = str(excinfo.value)
    assert "not in the application allowlist" in message
    assert "code" in message and "firefox" in message
    assert "not supported" in message


def test_empty_application_name_is_refused() -> None:
    with pytest.raises(ApplicationNotAllowedError):
        launch_application("   ", applications={"code": spec("code", "true")})


def test_no_applications_configured_is_reported() -> None:
    with pytest.raises(ApplicationNotAllowedError) as excinfo:
        launch_application("code", applications={})
    assert "none configured" in str(excinfo.value)


@pytest.mark.parametrize(
    "attempt",
    [
        "true; touch {sentinel}",
        "true && touch {sentinel}",
        "true || touch {sentinel}",
        "true | tee {sentinel}",
        "true > {sentinel}",
        "$(touch {sentinel})",
        "`touch {sentinel}`",
        "../../bin/sh",
        "/bin/sh",
        "sh -c 'echo pwned > {sentinel}'",
        "--version",
        "true\nfalse",
    ],
)
def test_command_strings_cannot_be_executed(
    attempt: str, workspace: Workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every attempt must be refused, and nothing may be created on disk."""
    sentinel = workspace.sentinel
    name = attempt.format(sentinel=sentinel)
    specs = {"true": spec("true", "true")}

    with pytest.raises(ApplicationNotAllowedError):
        launch_application(name, applications=specs, probe_seconds=2.0)

    assert not sentinel.exists()


def test_launch_never_uses_a_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """Assert the exact Popen contract: list argv, no shell, stdout detached."""
    captured: dict[str, object] = {}

    class FakeProcess:
        pid = 4242

        def __init__(self, argv: list[str], **kwargs: object) -> None:
            captured["argv"] = argv
            captured["kwargs"] = kwargs

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)

    monkeypatch.setattr(applications_module.subprocess, "Popen", FakeProcess)

    probes = {"term": spec("term", ["true", "--window"])}
    result = launch_application("term", applications=probes, probe_seconds=0.1)

    assert captured["argv"] == [TRUE, "--window"]
    kwargs = captured["kwargs"]
    assert kwargs["shell"] is False
    assert kwargs["close_fds"] is True
    assert kwargs["start_new_session"] is True
    # All three standard streams must be detached from the MCP server: a child
    # writing to our stdout would corrupt the protocol stream.
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert result.pid == 4242


def test_unavailable_executable_is_reported_clearly() -> None:
    specs = {"ghost": spec("ghost", "definitely-not-a-real-executable-xyz")}
    assert specs["ghost"].available is False

    with pytest.raises(ApplicationUnavailableError) as excinfo:
        launch_application("ghost", applications=specs)

    message = str(excinfo.value)
    assert "cannot be launched" in message
    assert "not found on PATH" in message


def test_absolute_executable_that_does_not_exist_is_reported_clearly() -> None:
    specs = {"ghost": spec("ghost", "/nonexistent/bin/ghost")}
    with pytest.raises(ApplicationUnavailableError) as excinfo:
        launch_application("ghost", applications=specs)
    assert "not an executable file" in str(excinfo.value)


def test_executable_that_disappears_after_configuration_is_reported(
    workspace: Workspace,
) -> None:
    script = workspace.root / "my-app"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)

    specs = {"my-app": spec("my-app", str(script))}
    assert specs["my-app"].available is True

    script.unlink()  # the file goes away after startup

    with pytest.raises(ApplicationUnavailableError) as excinfo:
        launch_application("my-app", applications=specs)
    assert "missing or not executable" in str(excinfo.value)


def test_application_that_exits_immediately_with_an_error_is_a_launch_failure() -> None:
    specs = {"broken": spec("broken", "false")}
    with pytest.raises(ApplicationLaunchError) as excinfo:
        launch_application("broken", applications=specs, probe_seconds=2.0)

    message = str(excinfo.value)
    assert "exited immediately with status 1" in message
    assert "DISPLAY" in message  # points at the usual cause on a headless run


def test_oserror_from_popen_is_reported_as_a_launch_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exploding_popen(*args: object, **kwargs: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(applications_module.subprocess, "Popen", exploding_popen)

    specs = {"code": spec("code", "true")}
    with pytest.raises(ApplicationLaunchError) as excinfo:
        launch_application("code", applications=specs)
    assert "Failed to launch" in str(excinfo.value)


def test_directory_as_executable_is_marked_unavailable(workspace: Workspace) -> None:
    specs = {"dir": spec("dir", str(workspace.nested))}
    assert specs["dir"].available is False


def text_of(result) -> str:
    """Concatenate every text block of a CallToolResult."""
    return "\n".join(block.text for block in result.content if block.type == "text")


@pytest.mark.anyio
async def test_tool_description_and_schema_guide_the_model(
    make_config: Callable[..., Config], mcp_client
) -> None:
    config = make_config(applications={"true": spec("true", "true"), "false": spec("false", "false")})
    async with mcp_client(config) as client:
        tools = await client.list_tools()

    tool = next(item for item in tools.tools if item.name == "open_application")
    assert tool.description.startswith(
        "Launch an approved Linux desktop application from the configured application allowlist."
    )
    assert "Arbitrary commands are not supported" in tool.description
    assert "false, true" in tool.description  # the live allowlist
    assert tool.input_schema["required"] == ["name"]
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is False
    assert tool.annotations.open_world_hint is False


@pytest.mark.anyio
async def test_tool_surface_matches_the_designed_set(
    make_config: Callable[..., Config], mcp_client
) -> None:
    """Registration and the tier registry must agree exactly, in both directions.

    Every registered tool must have a declared tier (otherwise ``guard`` would
    refuse it at runtime), and every declared tier must belong to a registered
    tool (otherwise the registry has drifted from reality).
    """
    async with mcp_client(make_config()) as client:
        tools = await client.list_tools()

    names = {tool.name for tool in tools.tools}
    assert names == set(TIER_REGISTRY)
    # A few anchor names, so a wholesale rename cannot silently pass.
    assert {"browse_files", "open_application", "read_file", "run_shell"} <= names


@pytest.mark.anyio
async def test_destructive_tools_are_refused_by_default(
    make_config: Callable[..., Config], mcp_client
) -> None:
    """The command tools exist, but the default policy disables their tier.

    This is the safety property that replaces version 0.1.0's "there is no
    run_command at all": the capability is present and audited, but nothing in
    the ``destructive`` tier can run until the user opts in explicitly.
    """
    async with mcp_client(make_config()) as client:
        result = await client.call_tool("run_command", {"executable": "echo"})

    assert result.is_error is True
    message = result.content[0].text
    assert "destructive" in message
    assert "disabled" in message
    assert "policy.enabled_tiers" in message


@pytest.mark.anyio
async def test_tool_launches_an_allowlisted_application(
    make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config(applications={"true": spec("true", "true")})) as client:
        result = await client.call_tool("open_application", {"name": "true"})

    assert result.is_error is False
    payload = result.structured_content
    assert payload["launched"] is True
    assert payload["name"] == "true"
    assert payload["executable"] == TRUE
    assert payload["argv"] == [TRUE]


@pytest.mark.anyio
async def test_tool_refuses_an_unknown_application(
    make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config(applications={"true": spec("true", "true")})) as client:
        result = await client.call_tool("open_application", {"name": "rm -rf /"})

    assert result.is_error is True
    message = text_of(result)
    assert "not in the application allowlist" in message
    assert "not supported" in message


@pytest.mark.anyio
async def test_tool_refuses_an_unavailable_application(
    workspace: Workspace, make_config: Callable[..., Config], mcp_client
) -> None:
    config = make_config(applications={"ghost": spec("ghost", "definitely-not-real-xyz")})
    async with mcp_client(config) as client:
        result = await client.call_tool("open_application", {"name": "ghost"})

    assert result.is_error is True
    assert "cannot be launched" in text_of(result)


@pytest.mark.anyio
async def test_tool_rejects_a_missing_argument(
    make_config: Callable[..., Config], mcp_client
) -> None:
    async with mcp_client(make_config()) as client:
        result = await client.call_tool("open_application", {})

    assert result.is_error is True
    assert "validation error" in text_of(result)