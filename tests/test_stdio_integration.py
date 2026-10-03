"""End-to-end tests over real STDIO, including the client-compatibility gate.

A handshake-era MCP client (``protocolVersion`` 2025-06-18, which is what Gemini
CLI and Cline send) must be able to initialize, list tools, and call them by
launching ``python server.py`` as a subprocess. That behaviour is what this
module locks in, together with the rule that stdout carries nothing but JSON-RPC
while every diagnostic goes to stderr.

The driver below speaks raw JSON-RPC rather than using the SDK client, so it
tests exactly what an external client sees on the wire.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import textwrap
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from linux_mcp.policy import TIER_REGISTRY
from tests.conftest import Workspace

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_SCRIPT = REPO_ROOT / "server.py"
LEGACY_PROTOCOL = "2025-06-18"


class StdioServer:
    """A running ``server.py`` subprocess, driven with raw JSON-RPC messages."""

    def __init__(self, env: dict[str, str], cwd: Path) -> None:
        self.process = subprocess.Popen(
            [sys.executable, str(SERVER_SCRIPT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
            cwd=str(cwd),
        )
        assert self.process.stdin and self.process.stdout and self.process.stderr
        self.non_json_stdout: list[str] = []
        self.stderr_lines: list[str] = []
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        """Consume stderr continuously so a full pipe can never block the server."""
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.stderr_lines.append(line)

    @property
    def stderr_text(self) -> str:
        return "".join(self.stderr_lines)

    def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)

    def request(
        self,
        message_id: int,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Send a request and return its response, or fail with diagnostics."""
        self.send(
            {"jsonrpc": "2.0", "id": message_id, "method": method, "params": params or {}}
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            assert self.process.stdout is not None
            ready, _, _ = select.select([self.process.stdout], [], [], 0.5)
            if not ready:
                continue
            line = self.process.stdout.readline()
            if not line:
                continue
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self.non_json_stdout.append(line)
                continue
            if message.get("id") == message_id:
                return message
        pytest.fail(
            f"Timed out waiting for a response to {method!r}.\n"
            f"stderr so far:\n{self.stderr_text}"
        )

    def initialize(self, protocol_version: str = LEGACY_PROTOCOL) -> dict[str, Any]:
        """Perform the handshake an older client uses, and assert it succeeded."""
        response = self.request(
            1,
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "linux-mcp-tests", "version": "0.1.0"},
            },
        )
        assert "error" not in response, response
        self.notify("notifications/initialized")
        return response["result"]

    def call_tool(self, message_id: int, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self.request(
            message_id, "tools/call", {"name": name, "arguments": arguments}
        )
        assert "error" not in response, response
        return response["result"]

    def close(self) -> int | None:
        """Close stdin and wait for the server to exit on its own."""
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            return self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=15)
            return None


def result_text(result: dict[str, Any]) -> str:
    """Concatenate the text blocks of a tools/call result."""
    return "\n".join(block.get("text", "") for block in result.get("content", []))


@pytest.fixture
def config_path(workspace: Workspace, tmp_path: Path) -> Path:
    """A real YAML configuration file, read through the real loader."""
    path = tmp_path / "linux-mcp.yaml"
    path.write_text(
        textwrap.dedent(
            f"""
            directories:
              allow:
                - {workspace.allowed}
              max_entries: 50
            applications:
              allow:
                ok: "true"
                broken: "false"
            """
        ).lstrip(),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def stdio_server(
    config_path: Path, workspace: Workspace, tmp_path: Path
) -> Iterator[StdioServer]:
    """A running server subprocess configured through LINUX_MCP_CONFIG."""
    env = {
        **os.environ,
        "LINUX_MCP_CONFIG": str(config_path),
        "LINUX_MCP_LOG_LEVEL": "DEBUG",
        "HOME": str(workspace.root),
    }
    # Run from an unrelated directory so a ./config/config.yaml in the repository
    # cannot be picked up by accident.
    server = StdioServer(env, cwd=tmp_path)
    try:
        yield server
    finally:
        server.close()


def test_legacy_client_can_initialize_and_list_tools(stdio_server: StdioServer) -> None:
    """The compatibility gate: protocolVersion 2025-06-18 over stdio."""
    init = stdio_server.initialize()

    assert init["protocolVersion"] == LEGACY_PROTOCOL
    assert init["serverInfo"]["name"] == "linux-system"
    assert init["serverInfo"]["version"]
    assert "browse_files" in init["instructions"]
    assert "open_application" in init["instructions"]

    listed = stdio_server.request(2, "tools/list")
    tools = {tool["name"]: tool for tool in listed["result"]["tools"]}
    assert set(tools) == set(TIER_REGISTRY)

    assert tools["browse_files"]["description"].startswith(
        "List files and directories inside an allowed Linux directory."
    )
    assert tools["browse_files"]["inputSchema"]["required"] == ["path"]
    assert tools["open_application"]["inputSchema"]["required"] == ["name"]
    assert tools["open_application"]["annotations"]["readOnlyHint"] is False
    assert tools["browse_files"]["annotations"]["readOnlyHint"] is True


def test_browse_files_over_stdio(
    stdio_server: StdioServer, workspace: Workspace
) -> None:
    stdio_server.initialize()

    allowed = stdio_server.call_tool(2, "browse_files", {"path": str(workspace.allowed)})
    assert allowed["isError"] is False
    payload = allowed["structuredContent"]
    assert payload["path"] == str(workspace.allowed)
    assert {entry["name"] for entry in payload["entries"]} >= {"alpha.txt", "nested"}
    assert payload["allowed_directories"] == [str(workspace.allowed)]

    outside = stdio_server.call_tool(3, "browse_files", {"path": str(workspace.outside)})
    assert outside["isError"] is True
    message = result_text(outside)
    assert "Permission denied" in message
    assert "outside the configured allowed directories" in message

    traversal = stdio_server.call_tool(
        4, "browse_files", {"path": f"{workspace.allowed}/{'../' * 20}etc"}
    )
    assert traversal["isError"] is True
    assert "Permission denied" in result_text(traversal)

    symlink = stdio_server.call_tool(
        5, "browse_files", {"path": str(workspace.symlink_escape)}
    )
    assert symlink["isError"] is True
    assert "Permission denied" in result_text(symlink)

    relative = stdio_server.call_tool(6, "browse_files", {"path": "Downloads"})
    assert relative["isError"] is True
    assert "must be absolute" in result_text(relative)


def test_open_application_over_stdio(stdio_server: StdioServer) -> None:
    stdio_server.initialize()

    launched = stdio_server.call_tool(2, "open_application", {"name": "ok"})
    assert launched["isError"] is False
    assert launched["structuredContent"]["launched"] is True
    assert launched["structuredContent"]["argv"] == ["/usr/bin/true"] or launched[
        "structuredContent"
    ]["argv"][0].endswith("/true")

    unknown = stdio_server.call_tool(3, "open_application", {"name": "rm -rf /"})
    assert unknown["isError"] is True
    assert "not in the application allowlist" in result_text(unknown)

    broken = stdio_server.call_tool(4, "open_application", {"name": "broken"})
    assert broken["isError"] is True
    assert "exited immediately" in result_text(broken)


def test_stdout_carries_only_json_rpc(
    stdio_server: StdioServer, workspace: Workspace
) -> None:
    """No log line, warning, or stray print may ever reach the protocol stream."""
    stdio_server.initialize()
    stdio_server.request(2, "tools/list")
    stdio_server.call_tool(3, "browse_files", {"path": str(workspace.allowed)})
    stdio_server.call_tool(4, "browse_files", {"path": str(workspace.outside)})
    stdio_server.call_tool(5, "open_application", {"name": "ok"})

    assert stdio_server.non_json_stdout == []


def test_diagnostics_go_to_stderr(stdio_server: StdioServer, workspace: Workspace) -> None:
    stdio_server.initialize()
    stdio_server.call_tool(2, "browse_files", {"path": str(workspace.allowed)})

    stderr = stdio_server.stderr_text
    assert "Configuration file:" in stderr
    assert "Allowed directories:" in stderr
    assert "serving MCP over STDIO" in stderr
    assert "Traceback" not in stderr


def test_denials_are_logged_with_a_reason(
    stdio_server: StdioServer, workspace: Workspace
) -> None:
    stdio_server.initialize()
    stdio_server.call_tool(2, "browse_files", {"path": str(workspace.outside)})

    stderr = stdio_server.stderr_text
    assert "refused" in stderr
    assert "outside the configured allowed directories" in stderr


def test_server_exits_cleanly_when_the_client_disconnects(stdio_server: StdioServer) -> None:
    """The server must not outlive its client when stdin reaches EOF."""
    stdio_server.initialize()
    status = stdio_server.close()

    assert status == 0


def test_invalid_configuration_fails_fast_and_safely(tmp_path: Path) -> None:
    """A broken configuration must stop the server before it serves anything."""
    absent = tmp_path / "missing.yaml"
    completed = subprocess.run(
        [sys.executable, str(SERVER_SCRIPT)],
        input="",
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "LINUX_MCP_CONFIG": str(absent), "LINUX_MCP_LOG_LEVEL": "INFO"},
        cwd=str(tmp_path),
        check=False,
    )

    assert completed.returncode != 0
    assert completed.stdout == ""  # nothing that could be mistaken for protocol data
    assert "not found" in completed.stderr


def test_a_directory_outside_the_allowlist_cannot_be_configured_as_a_relative_path(
    tmp_path: Path,
) -> None:
    """Relative paths in the configuration are rejected, not silently accepted."""
    config = tmp_path / "bad.yaml"
    config.write_text(
        textwrap.dedent(
            """
            directories:
              allow:
                - Downloads
            """
        ).lstrip(),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, str(SERVER_SCRIPT)],
        input="",
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "LINUX_MCP_CONFIG": str(config)},
        cwd=str(tmp_path),
        check=False,
    )

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "absolute" in completed.stderr

def test_destructive_tool_is_refused_without_a_display_and_is_audited(
    workspace: Workspace, tmp_path: Path
) -> None:
    """End-to-end proof that a refused approval blocks execution.

    The destructive tier is explicitly enabled, so the only thing standing
    between the model and the command is the approval gate. With no graphical
    session available the gate must fail closed, the tool must return an error,
    and the audit log must record the denial.
    """
    audit_path = workspace.root / "audit.jsonl"
    config = tmp_path / "approval.yaml"
    config.write_text(
        textwrap.dedent(
            f"""
            directories:
              allow:
                - {workspace.allowed}
            applications:
              allow: {{}}
            policy:
              enabled_tiers: [readonly, write, system, destructive]
              confirm_tiers: [destructive]
              audit:
                path: {audit_path}
            commands:
              containment: none
            """
        ).lstrip(),
        encoding="utf-8",
    )

    env = {
        **os.environ,
        "LINUX_MCP_CONFIG": str(config),
        "LINUX_MCP_LOG_LEVEL": "DEBUG",
        "HOME": str(workspace.root),
    }
    # Remove every way of reaching a desktop dialog, so the gate cannot ask.
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    env.pop("XAUTHORITY", None)

    server = StdioServer(env, cwd=tmp_path)
    try:
        server.initialize()
        result = server.call_tool(
            2, "run_command", {"executable": "echo", "args": ["should-not-run"]}
        )

        assert result.get("isError") is True
        message = result_text(result).lower()
        assert "approval" in message

        assert audit_path.exists(), "a refusal must still be audited"
        audit = audit_path.read_text(encoding="utf-8")
        assert '"tool":"run_command"' in audit
        assert '"decision":"unavailable"' in audit
        assert '"outcome":"denied"' in audit
    finally:
        server.close()


def test_readonly_tool_runs_and_is_audited_over_stdio(
    workspace: Workspace, tmp_path: Path
) -> None:
    """A read-only tier tool executes without approval and lands in the audit log."""
    audit_path = workspace.root / "audit.jsonl"
    config = tmp_path / "readonly.yaml"
    config.write_text(
        textwrap.dedent(
            f"""
            directories:
              allow:
                - {workspace.allowed}
            applications:
              allow: {{}}
            policy:
              enabled_tiers: [readonly, write]
              audit:
                path: {audit_path}
            """
        ).lstrip(),
        encoding="utf-8",
    )

    env = {
        **os.environ,
        "LINUX_MCP_CONFIG": str(config),
        "HOME": str(workspace.root),
    }
    server = StdioServer(env, cwd=tmp_path)
    try:
        server.initialize()
        result = server.call_tool(2, "read_file", {"path": str(workspace.alpha)})

        assert result.get("isError") is not True
        assert "alpha" in result_text(result)

        audit = audit_path.read_text(encoding="utf-8")
        assert '"tool":"read_file"' in audit
        assert '"decision":"auto"' in audit
        assert '"outcome":"ok"' in audit
    finally:
        server.close()
