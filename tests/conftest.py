"""Shared fixtures for the test suite.

Fixtures build a real directory tree under pytest's ``tmp_path`` so the security
boundaries are exercised against a real filesystem, including real symlinks.
Paths are resolved before use because the allowlist compares fully resolved
paths, and ``/tmp`` itself is a symlink on some systems.

The tree looks like this::

    <root>/
    ├── allowed/            <- the only directory in the allowlist
    │   ├── alpha.txt
    │   ├── .hidden
    │   ├── nested/inner.txt
    │   ├── escape  -> ../outside      (symlink leaving the allowlist)
    │   ├── inside  -> nested          (symlink staying inside)
    │   └── broken  -> does-not-exist  (dangling symlink)
    ├── outside/secret.txt  <- must be unreachable
    └── allowed_evil/       <- shares a prefix with "allowed", must be unreachable
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
from mcp import Client

from linux_mcp.app import build_server
from linux_mcp.config import (
    ApplicationSpec,
    AuditConfig,
    CommandsConfig,
    Config,
    DirectoryPolicy,
    PolicyConfig,
)


@dataclass(frozen=True)
class Workspace:
    """A throwaway tree with an allowed directory and its neighbours."""

    root: Path
    allowed: Path
    nested: Path
    outside: Path
    sibling: Path
    alpha: Path
    hidden: Path
    symlink_escape: Path
    symlink_inside: Path
    symlink_broken: Path

    @property
    def sentinel(self) -> Path:
        """A path that must never appear as the result of a command injection."""
        return self.root / "pwned"


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    """Create the tree described in this module's docstring."""
    root = tmp_path.resolve()
    allowed = root / "allowed"
    nested = allowed / "nested"
    outside = root / "outside"
    sibling = root / "allowed_evil"
    for directory in (nested, outside, sibling):
        directory.mkdir(parents=True)

    alpha = allowed / "alpha.txt"
    alpha.write_text("alpha", encoding="utf-8")
    hidden = allowed / ".hidden"
    hidden.write_text("hidden file", encoding="utf-8")
    (nested / "inner.txt").write_text("inner", encoding="utf-8")
    (outside / "secret.txt").write_text("top secret", encoding="utf-8")
    (sibling / "sneaky.txt").write_text("sneaky", encoding="utf-8")

    symlink_escape = allowed / "escape"
    symlink_escape.symlink_to(outside, target_is_directory=True)
    symlink_inside = allowed / "inside"
    symlink_inside.symlink_to(nested, target_is_directory=True)
    symlink_broken = allowed / "broken"
    symlink_broken.symlink_to(allowed / "does-not-exist")

    return Workspace(
        root=root,
        allowed=allowed,
        nested=nested,
        outside=outside,
        sibling=sibling,
        alpha=alpha,
        hidden=hidden,
        symlink_escape=symlink_escape,
        symlink_inside=symlink_inside,
        symlink_broken=symlink_broken,
    )


@pytest.fixture
def make_config(workspace: Workspace) -> Callable[..., Config]:
    """Return a factory that builds validated-looking ``Config`` objects.

    The audit path defaults into the throwaway workspace so no test ever writes
    to the real ``~/.local/state/linux-mcp`` directory.
    """

    def _make(
        allow: Sequence[Path] | None = None,
        applications: dict[str, ApplicationSpec] | None = None,
        max_entries: int = 500,
        policy: PolicyConfig | None = None,
        commands: CommandsConfig | None = None,
    ) -> Config:
        return Config(
            source=workspace.root / "config.yaml",
            directories=DirectoryPolicy(
                allow=tuple(allow) if allow is not None else (workspace.allowed,),
                max_entries=max_entries,
            ),
            applications=dict(applications) if applications else {},
            policy=policy
            if policy is not None
            else PolicyConfig(audit=AuditConfig(path=workspace.root / "audit.jsonl")),
            commands=commands if commands is not None else CommandsConfig(),
        )

    return _make


@pytest.fixture
def make_context(make_config: Callable[..., Config]):
    """Return a factory building a GuardContext whose audit log lives in tmp_path."""
    from linux_mcp.guard import GuardContext

    def _make(**kwargs) -> GuardContext:
        return GuardContext.from_config(make_config(**kwargs))

    return _make


@pytest.fixture
def mcp_client() -> Callable[[Config], contextlib.AbstractAsyncContextManager[Client]]:
    """Return a factory for an in-process MCP client bound to a config.

    Uses the SDK's in-memory client, so tests exercise the real tool schemas and
    the real ``ToolError`` mapping without spawning a subprocess. The subprocess
    path is covered separately in ``test_stdio_integration.py``.
    """

    @contextlib.asynccontextmanager
    async def _client(config: Config) -> AsyncIterator[Client]:
        async with Client(build_server(config), raise_exceptions=True) as client:
            yield client

    return _client


@pytest.fixture
def anyio_backend() -> str:
    """Run ``@pytest.mark.anyio`` tests on asyncio (anyio's pytest plugin hook)."""
    return "asyncio"


@pytest.fixture
def clear_mcp_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove MCP-related environment variables so config lookup is deterministic."""
    for name in ("LINUX_MCP_CONFIG", "LINUX_MCP_LOG_LEVEL"):
        monkeypatch.delenv(name, raising=False)
    yield