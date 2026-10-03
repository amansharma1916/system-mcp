# linux-mcp Phase 1a — Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the policy, audit, approval, execution, and configuration foundation that every later tool depends on — without adding a single tool yet.

**Architecture:** Five new SDK-free core modules (`policy`, `redaction`, `audit`, `approval`, `containment`, `exec`) plus one composition module (`guard`), all layered under a single `guarded()` entry point. Tools call `guarded()`; they contain no policy logic. None of these modules import `mcp`, so every security boundary is unit-testable without a client.

**Tech Stack:** Python 3.10+, `mcp` 2.2.x (already present), PyYAML (already present), pytest (already present). No new runtime dependencies. `zenity` and `systemd-run` are invoked as external processes when needed.

**Spec:** `docs/superpowers/specs/2026-09-15-linux-mcp-full-control-design.md`

## Global Constraints

- Python floor is **3.10**; the codebase uses `from __future__ import annotations` and `X | None` style throughout — match it.
- **No new runtime dependencies.** `requirements.txt` stays `mcp` + `PyYAML`.
- **No `mcp` import** in `policy.py`, `redaction.py`, `audit.py`, `approval.py`, `containment.py`, `exec.py`, `guard.py`. Only `tools/*` and `app.py` may import `mcp`.
- Every module uses `from linux_mcp.logging_setup import get_logger` and logs to **stderr only**; never log to stdout (it is the MCP wire).
- Never log file contents, environment values, or secret-looking arguments; use `redaction` helpers.
- Defaults must be **fail-safe**: policy defaults to `enabled_tiers = {readonly, write}` and `confirm_tiers = {system, destructive}`.
- **No git repository is initialized in this project.** Do not add `git init` or run commits. Each task ends with a **Checkpoint** step (focused tests + ruff) instead of a commit. If the user later asks for commits, `git init` first.
- Run tests with the project interpreter: `/home/aman/Projects/system-mcp/.venv/bin/python -m pytest …` (system Python is externally managed).
- Lint with `/home/aman/Projects/system-mcp/.venv/bin/ruff check .` and keep it clean.
- Existing behaviour must not regress: `Config` gains new fields **with defaults**, so the existing `tests/conftest.py` `make_config` factory keeps working unchanged, and all 193 existing tests keep passing.

---

### Task 1: Tier model and policy engine

**Files:**
- Modify: `linux_mcp/errors.py` (append new error classes)
- Create: `linux_mcp/policy.py`
- Create: `tests/test_policy.py`

**Interfaces:**
- Consumes: `linux_mcp.errors.LinuxMCPError`.
- Produces:
  - `Tier` — `str`-valued `Enum` with members `READONLY="readonly"`, `WRITE="write"`, `SYSTEM="system"`, `DESTRUCTIVE="destructive"`.
  - `TIER_ORDER: tuple[Tier, ...]` — ascending severity.
  - `TIER_DESCRIPTIONS: Mapping[Tier, str]`.
  - `TIER_REGISTRY: Mapping[str, Tier]` — tool name → tier.
  - `Policy(enabled_tiers: frozenset[Tier], confirm_tiers: frozenset[Tier])` with `.tier_of(name) -> Tier`, `.is_enabled(tier) -> bool`, `.requires_confirmation(tier) -> bool`, `.require_enabled(name) -> Tier`.
  - Errors: `UndeclaredToolError`, `TierDisabledError`.

- [ ] **Step 1: Add the new error classes**

Append to `linux_mcp/errors.py`:

```python
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


class PrivilegeEscalationError(LinuxMCPError):
    """A privileged action was requested but escalation is not permitted."""
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_policy.py`:

```python
"""Policy engine: tier resolution, deny-by-default, and configuration gates."""

from __future__ import annotations

import pytest

from linux_mcp.errors import TierDisabledError, UndeclaredToolError
from linux_mcp.policy import (
    TIER_ORDER,
    TIER_REGISTRY,
    Policy,
    Tier,
)


def make_policy(
    enabled: set[Tier] | None = None,
    confirm: set[Tier] | None = None,
) -> Policy:
    return Policy(
        enabled_tiers=frozenset(enabled if enabled is not None else TIER_ORDER),
        confirm_tiers=frozenset(confirm if confirm is not None else TIER_ORDER),
    )


def test_tier_order_is_ascending_severity() -> None:
    assert TIER_ORDER == (Tier.READONLY, Tier.WRITE, Tier.SYSTEM, Tier.DESTRUCTIVE)


def test_registry_assigns_expected_tiers() -> None:
    assert TIER_REGISTRY["read_file"] is Tier.READONLY
    assert TIER_REGISTRY["write_file"] is Tier.WRITE
    assert TIER_REGISTRY["kill_process"] is Tier.SYSTEM
    assert TIER_REGISTRY["run_command"] is Tier.DESTRUCTIVE
    assert TIER_REGISTRY["run_shell"] is Tier.DESTRUCTIVE
    assert TIER_REGISTRY["delete_path"] is Tier.DESTRUCTIVE
    assert TIER_REGISTRY["trash_path"] is Tier.WRITE
    assert TIER_REGISTRY["force_kill_process"] is Tier.DESTRUCTIVE


def test_registry_has_no_duplicate_keys_by_construction() -> None:
    # A dict cannot hold duplicates; assert the mapping is non-empty and str-keyed.
    assert TIER_REGISTRY
    assert all(isinstance(name, str) and name for name in TIER_REGISTRY)


def test_tier_of_returns_declared_tier() -> None:
    assert make_policy().tier_of("run_command") is Tier.DESTRUCTIVE


def test_tier_of_refuses_undeclared_tool() -> None:
    with pytest.raises(UndeclaredToolError) as excinfo:
        make_policy().tier_of("definitely_not_a_tool")
    assert "deny-by-default" in str(excinfo.value)


def test_require_enabled_returns_tier_when_enabled() -> None:
    policy = make_policy(enabled={Tier.READONLY})
    assert policy.require_enabled("read_file") is Tier.READONLY


def test_require_enabled_refuses_disabled_tier() -> None:
    policy = make_policy(enabled={Tier.READONLY}, confirm=set())
    with pytest.raises(TierDisabledError) as excinfo:
        policy.require_enabled("run_command")
    message = str(excinfo.value)
    assert "destructive" in message
    assert "policy.enabled_tiers" in message


def test_requires_confirmation_is_explicit() -> None:
    policy = make_policy(enabled=set(TIER_ORDER), confirm={Tier.DESTRUCTIVE})
    assert policy.requires_confirmation(Tier.DESTRUCTIVE) is True
    assert policy.requires_confirmation(Tier.READONLY) is False


def test_enabling_a_tier_does_not_imply_confirming_it() -> None:
    policy = make_policy(enabled=set(TIER_ORDER), confirm=set())
    assert policy.is_enabled(Tier.DESTRUCTIVE) is True
    assert policy.requires_confirmation(Tier.DESTRUCTIVE) is False
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_policy.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_mcp.policy'`.

- [ ] **Step 4: Write the implementation**

Create `linux_mcp/policy.py`:

```python
"""Policy engine: every tool declares a tier; nothing runs without one.

This module holds *no* MCP imports on purpose, so the whole permission model is
unit-testable in isolation. The rule is deny-by-default: a tool whose name is
absent from :data:`TIER_REGISTRY` is refused, so adding a tool without thinking
about its blast radius fails loudly instead of silently granting access.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from linux_mcp.errors import TierDisabledError, UndeclaredToolError


class Tier(str, Enum):
    """How much damage a tool can do, from harmless to arbitrary execution."""

    READONLY = "readonly"
    WRITE = "write"
    SYSTEM = "system"
    DESTRUCTIVE = "destructive"


TIER_ORDER: tuple[Tier, ...] = (
    Tier.READONLY,
    Tier.WRITE,
    Tier.SYSTEM,
    Tier.DESTRUCTIVE,
)
"""Ascending severity, useful for reporting enabled tiers in a stable order."""

TIER_DESCRIPTIONS: Mapping[Tier, str] = {
    Tier.READONLY: "read-only inspection; nothing on the system changes",
    Tier.WRITE: "creates or modifies files inside the configured write directories",
    Tier.SYSTEM: "changes system or session state",
    Tier.DESTRUCTIVE: "irreversible, or executes arbitrary commands",
}

TIER_REGISTRY: Mapping[str, Tier] = {
    # Existing tools (migrated to guard in Phase 1b).
    "browse_files": Tier.READONLY,
    "open_application": Tier.WRITE,
    # Phase 1 — read-only.
    "read_file": Tier.READONLY,
    "list_tree": Tier.READONLY,
    "search_files": Tier.READONLY,
    "search_content": Tier.READONLY,
    "file_info": Tier.READONLY,
    "checksum": Tier.READONLY,
    "get_system_info": Tier.READONLY,
    "get_resource_usage": Tier.READONLY,
    "list_processes": Tier.READONLY,
    # Phase 1 — write.
    "write_file": Tier.WRITE,
    "edit_file": Tier.WRITE,
    "create_directory": Tier.WRITE,
    "move_path": Tier.WRITE,
    "copy_path": Tier.WRITE,
    "trash_path": Tier.WRITE,
    # Phase 1 — system.
    "kill_process": Tier.SYSTEM,
    # Phase 1 — destructive.
    "delete_path": Tier.DESTRUCTIVE,
    "force_kill_process": Tier.DESTRUCTIVE,
    "run_command": Tier.DESTRUCTIVE,
    "run_shell": Tier.DESTRUCTIVE,
}
"""Tool name -> tier. A name absent from this mapping is refused outright.

A tool's tier is decided by its **name only**; there is no per-argument tier.
Where a capability has a safe and a dangerous form, they are two tools
(``trash_path`` vs ``delete_path``) so the registry, the audit record, and the
approval dialog always agree on exactly one tier.
"""


@dataclass(frozen=True, slots=True)
class Policy:
    """Which tiers may run, and which of those need human approval."""

    enabled_tiers: frozenset[Tier]
    confirm_tiers: frozenset[Tier]

    def tier_of(self, tool_name: str) -> Tier:
        """Return the declared tier for *tool_name*, or refuse it."""
        tier = TIER_REGISTRY.get(tool_name)
        if tier is None:
            raise UndeclaredToolError(
                f"Tool {tool_name!r} has no declared policy tier and is refused "
                "(deny-by-default). Add it to TIER_REGISTRY in linux_mcp/policy.py "
                "to give it a tier."
            )
        return tier

    def is_enabled(self, tier: Tier) -> bool:
        """True when *tier* may execute at all."""
        return tier in self.enabled_tiers

    def requires_confirmation(self, tier: Tier) -> bool:
        """True when *tier* requires a human approval before executing."""
        return tier in self.confirm_tiers

    def require_enabled(self, tool_name: str) -> Tier:
        """Resolve *tool_name*'s tier, raising if it is undeclared or disabled."""
        tier = self.tier_of(tool_name)
        if not self.is_enabled(tier):
            enabled = ", ".join(t.value for t in TIER_ORDER if t in self.enabled_tiers)
            raise TierDisabledError(
                f"Tool {tool_name!r} is tier {tier.value!r}, which is disabled. "
                f"Enabled tiers: {enabled or 'none'}. Add {tier.value!r} to "
                "policy.enabled_tiers to allow it."
            )
        return tier
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_policy.py -v`
Expected: PASS — 9 passed.

- [ ] **Step 6: Checkpoint**

Run: `.venv/bin/python -m pytest tests/test_policy.py -q && .venv/bin/ruff check linux_mcp/policy.py linux_mcp/errors.py tests/test_policy.py`
Expected: tests pass, ruff reports no issues.

---

### Task 2: Secret redaction helpers

**Files:**
- Create: `linux_mcp/redaction.py`
- Create: `tests/test_redaction.py`

**Interfaces:**
- Produces:
  - `REDACTED: str` — the literal `"[redacted]"`.
  - `is_secret_key(name: str) -> bool` — matches `TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL`, case-insensitive.
  - `redact_value(value: str) -> str` — replaces secret-looking substrings.
  - `redact_any(value: object) -> object` — recursive over `Mapping`/`Sequence`/`str`.
  - `redact_mapping(data: Mapping[str, object]) -> dict[str, object]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_redaction.py`:

```python
"""Redaction: nothing secret may reach the audit log."""

from __future__ import annotations

from linux_mcp.redaction import (
    REDACTED,
    is_secret_key,
    redact_any,
    redact_mapping,
    redact_value,
)


def test_secret_keys_are_recognised_case_insensitively() -> None:
    for name in ("API_KEY", "github_token", "Password", "db_secret", "CREDENTIAL"):
        assert is_secret_key(name), name


def test_ordinary_keys_are_not_secret() -> None:
    for name in ("path", "argv", "cwd", "count", "monkey"):
        assert not is_secret_key(name), name


def test_redact_mapping_replaces_secret_keyed_values() -> None:
    result = redact_mapping({"path": "/tmp/x", "api_key": "whatever", "TOKEN": "abc"})
    assert result["path"] == "/tmp/x"
    assert result["api_key"] == REDACTED
    assert result["TOKEN"] == REDACTED


def test_redact_value_masks_known_token_shapes() -> None:
    assert "ghp_" not in redact_value("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    assert "sk-" not in redact_value("key sk-abcdefghijklmnopqrstuvwxyz")
    assert "AKIA" not in redact_value("aws AKIAIOSFODNN7EXAMPLE")
    assert "BEGIN RSA PRIVATE KEY" not in redact_value(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n"
    )


def test_redact_value_masks_password_assignments_and_bearer_tokens() -> None:
    assert REDACTED in redact_value("password=hunter2")
    assert REDACTED in redact_value("Authorization: Bearer abcdefghijklmnopqrstuv")


def test_redact_value_leaves_ordinary_text_alone() -> None:
    assert redact_value("ls -la /home/aman") == "ls -la /home/aman"


def test_redact_any_walks_nested_structures() -> None:
    data = {"outer": [{"api_key": "k"}, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"]}
    result = redact_any(data)
    assert result["outer"][0]["api_key"] == REDACTED
    assert REDACTED in result["outer"][1]


def test_redact_any_passes_through_non_strings() -> None:
    assert redact_any(5) == 5
    assert redact_any(None) is None
    assert redact_any(True) is True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_redaction.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_mcp.redaction'`.

- [ ] **Step 3: Write the implementation**

Create `linux_mcp/redaction.py`:

```python
"""Secret redaction for anything that leaves the process (audit log, logs).

Defence in depth, not a guarantee: it catches common credential shapes and
secret-looking key names. The audit log records *what was run*, not the contents
of files, so the highest-value secrets are never in scope in the first place.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

REDACTED = "[redacted]"
"""What a redacted value is replaced with."""

_SECRET_KEY_PATTERN = re.compile(
    r"TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL", re.IGNORECASE
)

_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bpassword\s*[=:]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}"),
)


def is_secret_key(name: str) -> bool:
    """True when a mapping key's *name* suggests its value is a secret."""
    return bool(_SECRET_KEY_PATTERN.search(name))


def redact_value(value: str) -> str:
    """Replace secret-looking substrings inside *value*."""
    for pattern in _SECRET_VALUE_PATTERNS:
        value = pattern.sub(REDACTED, value)
    return value


def redact_any(value: object) -> object:
    """Recursively redact *value*: mappings by key name, strings by shape."""
    if isinstance(value, Mapping):
        return redact_mapping(value)
    if isinstance(value, str):
        return redact_value(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [redact_any(item) for item in value]
    return value


def redact_mapping(data: Mapping[str, object]) -> dict[str, object]:
    """Redact every entry of *data*, by key name first, then by value shape."""
    result: dict[str, object] = {}
    for key, value in data.items():
        name = str(key)
        result[name] = REDACTED if is_secret_key(name) else redact_any(value)
    return result
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_redaction.py -v`
Expected: PASS — 8 passed.

- [ ] **Step 5: Checkpoint**

Run: `.venv/bin/python -m pytest tests/test_redaction.py -q && .venv/bin/ruff check linux_mcp/redaction.py tests/test_redaction.py`
Expected: tests pass, ruff clean.

---

### Task 3: Append-only audit log

**Files:**
- Create: `linux_mcp/audit.py`
- Create: `tests/test_audit.py`

**Interfaces:**
- Consumes: `redaction.redact_mapping`, `redaction.redact_value`, `logging_setup.get_logger`.
- Produces:
  - `GENESIS_HASH: str` — 64 zeros.
  - `AuditLog(path: Path, *, enabled: bool = True, max_bytes: int = 10_485_760)` with:
    - `.path -> Path`
    - `.record(*, tool, tier, decision, mechanism, arguments, outcome, error=None, cwd=None, exit_code=None, duration_ms=None) -> dict | None`
    - `.verify_chain() -> bool`
  - Record keys: `ts, tool, tier, decision, mechanism, arguments, cwd, exit_code, duration_ms, outcome, error, prev_hash, hash`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_audit.py`:

```python
"""Audit log: append-only, private, tamper-evident, and redacted."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from linux_mcp.audit import GENESIS_HASH, AuditLog
from linux_mcp.redaction import REDACTED


def make_log(tmp_path: Path, **kwargs) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", **kwargs)


def read_records(log: AuditLog) -> list[dict]:
    return [
        json.loads(line)
        for line in log.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_record_appends_one_json_line(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    event = log.record(
        tool="run_command",
        tier="destructive",
        decision="approved",
        mechanism="zenity",
        arguments={"argv": ["ls", "-la"]},
        outcome="ok",
        exit_code=0,
    )
    assert event is not None
    records = read_records(log)
    assert len(records) == 1
    assert records[0]["tool"] == "run_command"
    assert records[0]["tier"] == "destructive"
    assert records[0]["decision"] == "approved"
    assert records[0]["exit_code"] == 0


def test_disabled_log_writes_nothing(tmp_path: Path) -> None:
    log = make_log(tmp_path, enabled=False)
    assert log.record(
        tool="read_file",
        tier="readonly",
        decision="auto",
        mechanism=None,
        arguments={},
        outcome="ok",
    ) is None
    assert not log.path.exists()


def test_file_and_directory_permissions_are_private(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    log.record(
        tool="read_file",
        tier="readonly",
        decision="auto",
        mechanism=None,
        arguments={},
        outcome="ok",
    )
    assert stat.S_IMODE(log.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(log.path.parent.stat().st_mode) == 0o700


def test_arguments_are_redacted(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    log.record(
        tool="run_command",
        tier="destructive",
        decision="approved",
        mechanism="zenity",
        arguments={"api_key": "supersecret", "argv": ["curl", "-H", "Authorization: Bearer abcdefghijklmnopqrstuv"]},
        outcome="ok",
    )
    record = read_records(log)[0]
    assert record["arguments"]["api_key"] == REDACTED
    assert "abcdefghijklmnopqrstuv" not in json.dumps(record["arguments"])


def test_hash_chain_links_records(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    first = log.record(
        tool="read_file", tier="readonly", decision="auto",
        mechanism=None, arguments={}, outcome="ok",
    )
    second = log.record(
        tool="read_file", tier="readonly", decision="auto",
        mechanism=None, arguments={}, outcome="ok",
    )
    assert first["prev_hash"] == GENESIS_HASH
    assert second["prev_hash"] == first["hash"]
    assert log.verify_chain() is True


def test_verify_chain_detects_tampering(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    for _ in range(2):
        log.record(
            tool="read_file", tier="readonly", decision="auto",
            mechanism=None, arguments={}, outcome="ok",
        )
    lines = log.path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"outcome":"ok"', '"outcome":"evil"')
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert log.verify_chain() is False


def test_chain_resumes_across_instances(tmp_path: Path) -> None:
    first_log = make_log(tmp_path)
    first = first_log.record(
        tool="read_file", tier="readonly", decision="auto",
        mechanism=None, arguments={}, outcome="ok",
    )
    second_log = make_log(tmp_path)
    second = second_log.record(
        tool="read_file", tier="readonly", decision="auto",
        mechanism=None, arguments={}, outcome="ok",
    )
    assert second["prev_hash"] == first["hash"]
    assert second_log.verify_chain() is True


def test_rotation_keeps_previous_generation(tmp_path: Path) -> None:
    log = make_log(tmp_path, max_bytes=200)
    for _ in range(10):
        log.record(
            tool="read_file", tier="readonly", decision="auto",
            mechanism=None, arguments={"filler": "x" * 40}, outcome="ok",
        )
    rotated = log.path.with_suffix(log.path.suffix + ".1")
    assert rotated.exists()
    assert log.path.exists()


def test_oserror_is_logged_and_reraised(tmp_path: Path, monkeypatch) -> None:
    log = make_log(tmp_path)
    real_open = os.open

    def exploding_open(path, flags, *args, **kwargs):
        if str(path).endswith("audit.jsonl"):
            raise OSError("disk on fire")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", exploding_open)
    try:
        log.record(
            tool="read_file", tier="readonly", decision="auto",
            mechanism=None, arguments={}, outcome="ok",
        )
    except OSError as exc:
        assert "disk on fire" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected OSError to propagate")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_audit.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_mcp.audit'`.

- [ ] **Step 3: Write the implementation**

Create `linux_mcp/audit.py`:

```python
"""Append-only, tamper-evident audit log for every policy decision.

One JSON object per line. Each record carries the hash of the previous record,
so deleting or editing a line breaks the chain and :meth:`AuditLog.verify_chain`
reports it. Records are flushed and fsync-ed before the caller returns, so an
executed action cannot go unrecorded because of a crash.

The log records *what was requested and decided*, never file contents or
environment values; argument values are passed through
:func:`linux_mcp.redaction.redact_mapping` first.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from linux_mcp.logging_setup import get_logger
from linux_mcp.redaction import redact_mapping, redact_value

logger = get_logger("audit")

GENESIS_HASH = "0" * 64
"""``prev_hash`` of the very first record in a fresh log."""

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
"""Rotate once the log exceeds this size."""


class AuditLog:
    """Append JSONL audit records to *path*, creating it private if needed."""

    def __init__(
        self,
        path: Path,
        *,
        enabled: bool = True,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        self._path = Path(path)
        self._enabled = enabled
        self._max_bytes = max_bytes
        self._prev_hash = GENESIS_HASH
        if self._enabled:
            self._prepare()

    @property
    def path(self) -> Path:
        """Where records are written."""
        return self._path

    def _prepare(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError as exc:
            logger.warning("Could not chmod audit directory %s: %s", self._path.parent, exc)
        if self._path.exists():
            self._prev_hash = self._last_hash()
            os.chmod(self._path, 0o600)
        else:
            descriptor = os.open(self._path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(descriptor)

    def _last_hash(self) -> str:
        last_line = ""
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        last_line = line
        except OSError as exc:
            logger.warning("Could not read audit log %s: %s", self._path, exc)
            return GENESIS_HASH
        if not last_line:
            return GENESIS_HASH
        try:
            return str(json.loads(last_line).get("hash") or GENESIS_HASH)
        except ValueError:
            logger.warning("Audit log %s ends with an unreadable line.", self._path)
            return GENESIS_HASH

    def record(
        self,
        *,
        tool: str,
        tier: str,
        decision: str,
        mechanism: str | None,
        arguments: object,
        outcome: str,
        error: str | None = None,
        cwd: str | None = None,
        exit_code: int | None = None,
        duration_ms: int | None = None,
    ) -> dict | None:
        """Append one record and return it, or ``None`` when auditing is off."""
        if not self._enabled:
            return None

        event: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "tier": tier,
            "decision": decision,
            "mechanism": mechanism,
            "arguments": redact_mapping(arguments) if isinstance(arguments, dict) else arguments,
            "cwd": cwd,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "outcome": outcome,
            "error": redact_value(error) if error else None,
            "prev_hash": self._prev_hash,
        }
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        event["hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        line = json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n"
        self._rotate_if_needed()
        try:
            descriptor = os.open(
                self._path, os.O_APPEND | os.O_WRONLY | os.O_CREAT, 0o600
            )
            try:
                os.write(descriptor, line.encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            logger.error("Could not append to audit log %s: %s", self._path, exc)
            raise

        self._prev_hash = str(event["hash"])
        return event

    def _rotate_if_needed(self) -> None:
        try:
            if self._path.stat().st_size < self._max_bytes:
                return
        except OSError:
            return
        rotated = self._path.with_suffix(self._path.suffix + ".1")
        try:
            os.replace(self._path, rotated)
            os.chmod(rotated, 0o600)
        except OSError as exc:
            # Rotation failure must not lose the incoming record; log and append.
            logger.error("Could not rotate audit log %s: %s", self._path, exc)

    def verify_chain(self) -> bool:
        """Recompute every hash and confirm the chain is unbroken."""
        previous = GENESIS_HASH
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    recorded_hash = record.pop("hash", None)
                    canonical = json.dumps(
                        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    )
                    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                    if expected != recorded_hash or record.get("prev_hash") != previous:
                        return False
                    previous = str(recorded_hash)
        except (OSError, ValueError):
            return False
        return True
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_audit.py -v`
Expected: PASS — 9 passed.

- [ ] **Step 5: Checkpoint**

Run: `.venv/bin/python -m pytest tests/test_audit.py -q && .venv/bin/ruff check linux_mcp/audit.py tests/test_audit.py`
Expected: tests pass, ruff clean.

---

### Task 4: Approval gate (zenity, fail-closed)

**Files:**
- Create: `linux_mcp/approval.py`
- Create: `tests/test_approval.py`

**Interfaces:**
- Consumes: `errors.ApprovalDeniedError`, `errors.ApprovalUnavailableError`, `logging_setup.get_logger`.
- Produces:
  - `ApprovalRequest(tool: str, tier: str, summary: str, details: str)` — frozen dataclass.
  - `ApprovalDecision(allowed: bool, mechanism: str | None, reason: str, elapsed_seconds: float)` — frozen dataclass. `reason ∈ {"allow","deny","timeout","unavailable"}`.
  - `DialogRunner = Callable[[list[str], float], int]` — `(argv, timeout) -> exit status`.
  - `ApprovalGate(*, timeout_seconds: float = 60.0, runner: DialogRunner | None = None, which: Callable[[str], str | None] = shutil.which, environ: Mapping[str, str] | None = None)` with `.request(request: ApprovalRequest) -> ApprovalDecision`.

Exit-status mapping: `0 → allow`, `1 → deny`, `5 → timeout`, anything else / exception → `unavailable`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_approval.py`:

```python
"""Approval gate: the single most important control. It must never fail open."""

from __future__ import annotations

import subprocess

from linux_mcp.approval import ApprovalDecision, ApprovalGate, ApprovalRequest


REQUEST = ApprovalRequest(
    tool="run_command",
    tier="destructive",
    summary="Run a command",
    details="argv: ['ls', '-la']",
)


def gate(*, runner, timeout=60.0, which=lambda name: "/usr/bin/zenity", environ=None):
    return ApprovalGate(
        timeout_seconds=timeout,
        runner=runner,
        which=which,
        environ={"WAYLAND_DISPLAY": "wayland-0"} if environ is None else environ,
    )


def test_allow_when_the_dialog_exits_zero() -> None:
    decision = gate(runner=lambda argv, timeout: 0).request(REQUEST)
    assert decision == ApprovalDecision(
        allowed=True, mechanism="zenity", reason="allow", elapsed_seconds=decision.elapsed_seconds
    )
    assert decision.elapsed_seconds >= 0


def test_deny_when_the_dialog_exits_one() -> None:
    decision = gate(runner=lambda argv, timeout: 1).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "deny"
    assert decision.mechanism == "zenity"


def test_timeout_is_a_denial() -> None:
    decision = gate(runner=lambda argv, timeout: 5).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "timeout"


def test_runner_exception_is_unavailable_and_denied() -> None:
    def exploding(argv, timeout):
        raise OSError("no display")

    decision = gate(runner=exploding).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "unavailable"
    assert decision.mechanism is None


def test_runner_timeout_expiry_is_a_denial() -> None:
    def slow(argv, timeout):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    decision = gate(runner=slow).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "timeout"


def test_missing_zenity_is_unavailable() -> None:
    decision = gate(runner=lambda argv, timeout: 0, which=lambda name: None).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "unavailable"


def test_no_display_is_unavailable_even_if_zenity_exists() -> None:
    decision = gate(
        runner=lambda argv, timeout: 0,
        environ={},
    ).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "unavailable"


def test_unexpected_exit_status_is_unavailable() -> None:
    decision = gate(runner=lambda argv, timeout: 3).request(REQUEST)
    assert decision.allowed is False
    assert decision.reason == "unavailable"


def test_dialog_argv_carries_the_exact_action_and_defaults_to_deny() -> None:
    captured: list[list[str]] = []

    def capture(argv, timeout):
        captured.append(argv)
        return 1

    gate(runner=capture).request(REQUEST)
    argv = captured[0]
    assert argv[0] == "/usr/bin/zenity"
    assert "--question" in argv
    assert "--default-cancel" in argv
    assert "run_command" in " ".join(argv)
    assert "ls" in " ".join(argv)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_approval.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_mcp.approval'`.

- [ ] **Step 3: Write the implementation**

Create `linux_mcp/approval.py`:

```python
"""Human approval for dangerous actions, via a native desktop dialog.

Fail-closed by construction: every uncertain outcome (no ``zenity``, no display,
timeout, an unexpected exit status, an exception) is reported as
``reason="unavailable"`` with ``allowed=False``. There is deliberately no code
path that returns ``allowed=True`` other than the dialog's own "Allow" button.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from linux_mcp.logging_setup import get_logger

logger = get_logger("approval")

MECHANISM = "zenity"

DEFAULT_TIMEOUT_SECONDS = 60.0
"""How long a dialog may stay unanswered before the action is denied."""

_RUNNER_GRACE_SECONDS = 5.0
"""Extra time over the zenity timeout before we stop waiting on the process."""

_EXIT_ALLOW = 0
_EXIT_DENY = 1
_EXIT_TIMEOUT = 5


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """What the human is being asked to authorise."""

    tool: str
    tier: str
    summary: str
    details: str


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """The outcome of asking a human."""

    allowed: bool
    mechanism: str | None
    reason: str
    elapsed_seconds: float


DialogRunner = Callable[[list[str], float], int]
"""Run the dialog argv with a timeout and return its exit status."""


def _default_runner(argv: list[str], timeout: float) -> int:
    completed = subprocess.run(
        argv,
        timeout=timeout,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return int(completed.returncode)


class ApprovalGate:
    """Ask a human to allow or deny an action, failing closed on any doubt."""

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        runner: DialogRunner | None = None,
        which: Callable[[str], str | None] = shutil.which,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._runner = runner if runner is not None else _default_runner
        self._which = which
        self._environ = os.environ if environ is None else environ

    def request(self, request: ApprovalRequest) -> ApprovalDecision:
        """Ask for approval; never trust anything but an explicit "Allow"."""
        started = time.monotonic()

        if not (self._environ.get("DISPLAY") or self._environ.get("WAYLAND_DISPLAY")):
            logger.warning(
                "Approval needed for %s but no display is available; denying.",
                request.tool,
            )
            return self._unavailable(started)

        zenity = self._which(MECHANISM)
        if zenity is None:
            logger.warning(
                "Approval needed for %s but %s is not installed; denying.",
                request.tool,
                MECHANISM,
            )
            return self._unavailable(started)

        argv = [
            zenity,
            "--question",
            "--title=linux-mcp approval required",
            f"--text={self._render(request)}",
            "--ok-label=Allow",
            "--cancel-label=Deny",
            "--default-cancel",
            f"--timeout={int(self._timeout_seconds)}",
            "--width=520",
        ]

        try:
            status = self._runner(argv, self._timeout_seconds + _RUNNER_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            logger.warning("Approval dialog for %s timed out; denying.", request.tool)
            return self._deny(started, reason="timeout", mechanism=MECHANISM)
        except OSError as exc:
            logger.warning("Approval dialog for %s failed to run: %s", request.tool, exc)
            return self._unavailable(started)

        if status == _EXIT_ALLOW:
            logger.info("Approved %s via %s.", request.tool, MECHANISM)
            return ApprovalDecision(True, MECHANISM, "allow", time.monotonic() - started)
        if status == _EXIT_DENY:
            logger.info("Denied %s by the user.", request.tool)
            return self._deny(started, reason="deny", mechanism=MECHANISM)
        if status == _EXIT_TIMEOUT:
            logger.warning("Approval dialog for %s timed out; denying.", request.tool)
            return self._deny(started, reason="timeout", mechanism=MECHANISM)

        logger.warning(
            "Approval dialog for %s returned unexpected status %s; denying.",
            request.tool,
            status,
        )
        return self._unavailable(started)

    def _render(self, request: ApprovalRequest) -> str:
        # The model's own words are labelled untrusted; the exact action is shown
        # verbatim so the human approves what will actually run, not what the model
        # claims it will do.
        parts = [
            f"<b>{request.tool}</b> (tier: {request.tier})",
            "",
            "Exact action:",
            request.details,
        ]
        if request.summary:
            parts += ["", "Model's stated reason (untrusted):", request.summary]
        return "\n".join(parts)

    @staticmethod
    def _deny(started: float, *, reason: str, mechanism: str | None) -> ApprovalDecision:
        return ApprovalDecision(False, mechanism, reason, time.monotonic() - started)

    @staticmethod
    def _unavailable(started: float) -> ApprovalDecision:
        return ApprovalDecision(False, None, "unavailable", time.monotonic() - started)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_approval.py -v`
Expected: PASS — 9 passed.

- [ ] **Step 5: Checkpoint**

Run: `.venv/bin/python -m pytest tests/test_approval.py -q && .venv/bin/ruff check linux_mcp/approval.py tests/test_approval.py`
Expected: tests pass, ruff clean.

---

### Task 5: Execution containment wrapper

**Files:**
- Create: `linux_mcp/containment.py`
- Create: `tests/test_containment.py`

**Interfaces:**
- Consumes: `errors.ContainmentUnavailableError`.
- Produces:
  - `ContainmentMode = Literal["none", "systemd-scope"]`
  - `DEFAULT_MEMORY_MAX_BYTES = 2_147_483_648`, `DEFAULT_CPU_QUOTA = "200%"`
  - `build_wrapper(mode: ContainmentMode, *, memory_max_bytes: int = DEFAULT_MEMORY_MAX_BYTES, cpu_quota: str = DEFAULT_CPU_QUOTA, which: Callable[[str], str | None] = shutil.which) -> list[str] | None`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_containment.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_containment.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_mcp.containment'`.

- [ ] **Step 3: Write the implementation**

Create `linux_mcp/containment.py`:

```python
"""Optional execution containment: run a command in its own user scope.

``systemd-run --user --scope`` gives the command its own cgroup with memory and
CPU caps and guarantees the whole process tree is killed with it. If the wrapper
is requested but unavailable, this fails closed rather than silently running the
command uncontained.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from typing import Literal

from linux_mcp.errors import ContainmentUnavailableError

ContainmentMode = Literal["none", "systemd-scope"]

DEFAULT_MEMORY_MAX_BYTES = 2_147_483_648
"""2 GiB, comfortable for ordinary commands while bounding runaway allocation."""

DEFAULT_CPU_QUOTA = "200%"
"""Two cores; enough for builds while preventing a spin from owning the machine."""

_SYSTEMD_RUN = "systemd-run"


def build_wrapper(
    mode: ContainmentMode,
    *,
    memory_max_bytes: int = DEFAULT_MEMORY_MAX_BYTES,
    cpu_quota: str = DEFAULT_CPU_QUOTA,
    which: Callable[[str], str | None] = shutil.which,
) -> list[str] | None:
    """Return the argv prefix that wraps a command, or ``None`` for no wrapper."""
    if mode == "none":
        return None
    if mode != "systemd-scope":
        raise ContainmentUnavailableError(
            f"Unknown containment mode {mode!r}. Supported modes: none, systemd-scope."
        )

    executable = which(_SYSTEMD_RUN)
    if executable is None:
        raise ContainmentUnavailableError(
            f"Containment mode 'systemd-scope' was requested but {_SYSTEMD_RUN!r} "
            "is not installed. Install systemd, or set "
            "commands.containment to 'none' to accept uncontained execution."
        )

    return [
        executable,
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "-p",
        f"MemoryMax={memory_max_bytes}",
        "-p",
        f"CPUQuota={cpu_quota}",
        "--",
    ]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_containment.py -v`
Expected: PASS — 4 passed.

- [ ] **Step 5: Checkpoint**

Run: `.venv/bin/python -m pytest tests/test_containment.py -q && .venv/bin/ruff check linux_mcp/containment.py tests/test_containment.py`
Expected: tests pass, ruff clean.

---

### Task 6: Execution runner

**Files:**
- Create: `linux_mcp/exec.py`
- Create: `tests/test_exec.py`

**Interfaces:**
- Consumes: `containment.build_wrapper`, `containment.ContainmentMode`, `containment.DEFAULT_MEMORY_MAX_BYTES`, `containment.DEFAULT_CPU_QUOTA`, `errors.CommandFailedError`, `errors.PrivilegeEscalationError`.
- Produces:
  - `CommandResult(argv, cwd, exit_code, stdout, stderr, stdout_truncated, stderr_truncated, duration_ms, timed_out)` — frozen dataclass.
  - `build_command(argv, *, contain="none", use_pkexec=False, memory_max_bytes=..., cpu_quota=..., which=shutil.which) -> list[str]`
  - `run_argv(argv, *, cwd=None, env=None, timeout_seconds=30.0, max_output_bytes=100_000, contain="none", use_pkexec=False, kill_grace_seconds=3.0, memory_max_bytes=..., cpu_quota=..., check=False, which=shutil.which) -> CommandResult`

Order of wrapping: **containment first (outermost), then pkexec (inner)** → `systemd-run … -- pkexec cmd …`, so the kernel namespace/caps belong to the scope.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_exec.py`:

```python
"""Execution runner: timeouts, tree-kill, truncation, and no-shell guarantees."""

from __future__ import annotations

import shutil
import sys
import time

import pytest

from linux_mcp.errors import CommandFailedError, PrivilegeEscalationError
from linux_mcp.exec import build_command, run_argv


def no_systemd(name: str) -> str | None:
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
    assert "pkexec" in command
    # pkexec must come after the containment separator, so it runs inside the scope.
    assert command.index("pkexec") > command.index("--")
    assert command[-1] == "vim"


def test_build_command_refuses_pkexec_when_absent() -> None:
    with pytest.raises(PrivilegeEscalationError):
        build_command(["pacman", "-S", "vim"], use_pkexec=True, which=no_systemd)


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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_exec.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_mcp.exec'`.

- [ ] **Step 3: Write the implementation**

Create `linux_mcp/exec.py`:

```python
"""Run an external command safely: no shell, bounded time, bounded output.

This is the only module in the project that spawns a subprocess on behalf of the
model. It always passes an explicit argv with ``shell=False``; ``run_shell`` in
the command tools is built on top of it as ``["bash", "-lc", script]``, so even
the shell is an argv and never a string interpolated into one.

On timeout the whole process *group* is signalled, not just the direct child, so
a command cannot leave background children behind.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from linux_mcp.containment import (
    DEFAULT_CPU_QUOTA,
    DEFAULT_MEMORY_MAX_BYTES,
    ContainmentMode,
    build_wrapper,
)
from linux_mcp.errors import CommandFailedError, PrivilegeEscalationError
from linux_mcp.logging_setup import get_logger

logger = get_logger("exec")

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_OUTPUT_BYTES = 100_000
DEFAULT_KILL_GRACE_SECONDS = 3.0

_PKEXEC = "pkexec"


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Everything a tool needs to report about one execution."""

    argv: list[str]
    cwd: str | None
    exit_code: int | None
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_ms: int
    timed_out: bool


def build_command(
    argv: Sequence[str],
    *,
    contain: ContainmentMode = "none",
    use_pkexec: bool = False,
    memory_max_bytes: int = DEFAULT_MEMORY_MAX_BYTES,
    cpu_quota: str = DEFAULT_CPU_QUOTA,
    which: Callable[[str], str | None] = shutil.which,
) -> list[str]:
    """Assemble the final argv: containment outermost, escalation innermost."""
    command = [str(part) for part in argv]

    if use_pkexec:
        pkexec = which(_PKEXEC)
        if pkexec is None:
            raise PrivilegeEscalationError(
                f"Privilege escalation was requested but {_PKEXEC!r} is not "
                "installed, so the action cannot be run. Either install polkit, or "
                "set commands.allow_pkexec to false to disable escalation entirely."
            )
        command = [pkexec, *command]

    wrapper = build_wrapper(
        contain,
        memory_max_bytes=memory_max_bytes,
        cpu_quota=cpu_quota,
        which=which,
    )
    if wrapper is not None:
        command = [*wrapper, *command]
    return command


def run_argv(
    argv: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    contain: ContainmentMode = "none",
    use_pkexec: bool = False,
    kill_grace_seconds: float = DEFAULT_KILL_GRACE_SECONDS,
    memory_max_bytes: int = DEFAULT_MEMORY_MAX_BYTES,
    cpu_quota: str = DEFAULT_CPU_QUOTA,
    check: bool = False,
    which: Callable[[str], str | None] = shutil.which,
) -> CommandResult:
    """Run *argv* with no shell, returning captured output and status."""
    command = build_command(
        argv,
        contain=contain,
        use_pkexec=use_pkexec,
        memory_max_bytes=memory_max_bytes,
        cpu_quota=cpu_quota,
        which=which,
    )

    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            shell=False,
            cwd=None if cwd is None else str(cwd),
            env=None if env is None else dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        raise CommandFailedError(
            f"Could not start command {command[0]!r}: {exc}."
        ) from exc

    timed_out = False
    try:
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_group(process, kill_grace_seconds)
        stdout_bytes, stderr_bytes = process.communicate()

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout, stdout_truncated = _decode_truncated(stdout_bytes or b"", max_output_bytes)
    stderr, stderr_truncated = _decode_truncated(stderr_bytes or b"", max_output_bytes)

    result = CommandResult(
        argv=command,
        cwd=str(cwd) if cwd is not None else None,
        exit_code=None if timed_out else process.returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        duration_ms=duration_ms,
        timed_out=timed_out,
    )

    if timed_out:
        logger.warning("Command timed out after %.1fs: %s", timeout_seconds, command[0])
    logger.info(
        "Ran %s (exit=%s, %dms, timed_out=%s)",
        command[0],
        result.exit_code,
        duration_ms,
        timed_out,
    )

    if check and not timed_out and result.exit_code not in (0, None):
        raise CommandFailedError(
            f"Command {command[0]!r} exited with status {result.exit_code}. "
            f"stderr: {stderr.strip()[:500] or '(empty)'}"
        )
    return result


def _terminate_group(process: subprocess.Popen, grace_seconds: float) -> None:
    """SIGTERM the process group, then SIGKILL it if it does not go quietly."""
    try:
        group = os.getpgid(process.pid)
    except (ProcessLookupError, PermissionError):
        return
    try:
        os.killpg(group, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _decode_truncated(data: bytes, limit: int) -> tuple[str, bool]:
    """Decode *data*, cutting at *limit* bytes on a UTF-8 boundary."""
    truncated = len(data) > limit
    if not truncated:
        return data.decode("utf-8", "replace"), False

    cut = data[:limit]
    # Drop a partial multi-byte sequence so the decoded text has no U+FFFD.
    while cut and (cut[-1] & 0xC0) == 0x80:
        cut = cut[:-1]
    if cut and (cut[-1] & 0x80):
        cut = cut[:-1]
    return cut.decode("utf-8", "replace"), True
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_exec.py -v`
Expected: PASS — 11 passed.

- [ ] **Step 5: Checkpoint**

Run: `.venv/bin/python -m pytest tests/test_exec.py -q && .venv/bin/ruff check linux_mcp/exec.py tests/test_exec.py`
Expected: tests pass, ruff clean.

---

### Task 7: Configuration extensions

**Files:**
- Modify: `linux_mcp/config.py`
- Create: `tests/test_config_policy.py`

**Interfaces:**
- Consumes: `policy.Tier`, `policy.TIER_ORDER`.
- Produces new frozen dataclasses, each with a `default()` static method:
  - `ApprovalConfig(mechanism: str, timeout_seconds: float, remember_for_seconds: int)`
  - `AuditConfig(enabled: bool, path: Path, max_bytes: int)`
  - `LimitsConfig(default_timeout_seconds, max_timeout_seconds, kill_grace_seconds, max_output_bytes, max_read_bytes, rate_limit_per_minute)`
  - `PolicyConfig(enabled_tiers: frozenset[Tier], confirm_tiers: frozenset[Tier], approval: ApprovalConfig, audit: AuditConfig, limits: LimitsConfig)` with `.policy() -> Policy`
  - `FilesystemPolicy(read_allow: tuple[Path, ...], write_allow: tuple[Path, ...], follow_symlinks: bool)`
  - `CommandsConfig(run_command_enabled: bool, run_shell_enabled: bool, containment: str, containment_memory_max_bytes: int, containment_cpu_quota: str, allow_pkexec: bool)`
  - `WebConfig(enabled: bool, search_provider: str, max_fetch_bytes: int)`
  - `PackagesConfig(backend: str, use_pkexec: bool)`
  - `PowerConfig(allow: frozenset[str])`
- `Config` gains fields **with defaults**: `policy`, `filesystem`, `commands`, `web`, `packages`, `power`.
- New top-level keys accepted: `policy`, `filesystem`, `commands`, `web`, `packages`, `power`.

Safety defaults when a section is absent: `enabled_tiers={READONLY, WRITE}`, `confirm_tiers={SYSTEM, DESTRUCTIVE}`, `commands.run_command_enabled=True`, `commands.run_shell_enabled=True`, `commands.containment="systemd-scope"`, `commands.allow_pkexec=True`. `run_command` still cannot execute unless the `destructive` tier is explicitly enabled.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config_policy.py`:

```python
"""New configuration sections: parsing, defaults, and fail-closed validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from linux_mcp.config import parse_config
from linux_mcp.errors import ConfigError
from linux_mcp.policy import Tier


def parse(data, source: Path = Path("/tmp/config.yaml")):
    return parse_config(data, source=source, env={})


def base(directories, **extra):
    data = {"directories": {"allow": [str(directories)]}, "applications": {"allow": {}}}
    data.update(extra)
    return data


def test_defaults_when_new_sections_are_absent(tmp_path: Path) -> None:
    config = parse(base(tmp_path))
    assert config.policy.enabled_tiers == frozenset({Tier.READONLY, Tier.WRITE})
    assert config.policy.confirm_tiers == frozenset({Tier.SYSTEM, Tier.DESTRUCTIVE})
    assert config.policy.approval.mechanism == "zenity"
    assert config.commands.containment == "systemd-scope"
    assert config.filesystem.read_allow
    assert config.filesystem.write_allow == config.filesystem.read_allow


def test_policy_section_is_parsed(tmp_path: Path) -> None:
    config = parse(
        base(
            tmp_path,
            policy={
                "enabled_tiers": ["readonly", "write", "system", "destructive"],
                "confirm_tiers": ["destructive"],
                "approval": {"timeout_seconds": 15, "remember_for_seconds": 0},
                "limits": {"max_output_bytes": 2048},
            },
        )
    )
    assert Tier.DESTRUCTIVE in config.policy.enabled_tiers
    assert config.policy.confirm_tiers == frozenset({Tier.DESTRUCTIVE})
    assert config.policy.approval.timeout_seconds == 15
    assert config.policy.limits.max_output_bytes == 2048


def test_unknown_policy_tier_is_fatal(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        parse(base(tmp_path, policy={"enabled_tiers": ["readonly", "wizard"]}))
    assert "wizard" in str(excinfo.value)


def test_unknown_key_under_policy_is_fatal(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        parse(base(tmp_path, policy={"bogus": 1}))


def test_filesystem_write_allow_must_be_subset_of_read_allow(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    other = tmp_path / "other"
    allowed.mkdir()
    other.mkdir()
    with pytest.raises(ConfigError) as excinfo:
        parse(
            base(
                allowed,
                filesystem={"read_allow": [str(allowed)], "write_allow": [str(other)]},
            )
        )
    assert "write_allow" in str(excinfo.value)


def test_filesystem_section_selects_write_allow(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    writable = allowed / "writable"
    writable.mkdir(parents=True)
    config = parse(
        base(
            allowed,
            filesystem={"read_allow": [str(allowed)], "write_allow": [str(writable)]},
        )
    )
    assert config.filesystem.write_allow == (writable.resolve(),)


def test_commands_section_parsed(tmp_path: Path) -> None:
    config = parse(
        base(
            tmp_path,
            commands={"containment": "none", "allow_pkexec": False, "run_shell_enabled": False},
        )
    )
    assert config.commands.containment == "none"
    assert config.commands.allow_pkexec is False
    assert config.commands.run_shell_enabled is False


def test_invalid_containment_mode_is_fatal(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        parse(base(tmp_path, commands={"containment": "magic"}))


def test_policy_helper_builds_policy_object(tmp_path: Path) -> None:
    config = parse(base(tmp_path))
    policy = config.policy.policy()
    assert policy.is_enabled(Tier.READONLY) is True
    assert policy.is_enabled(Tier.DESTRUCTIVE) is False


def test_existing_config_construction_still_works(tmp_path: Path) -> None:
    """The new fields are defaulted, so old positional construction is unaffected."""
    from linux_mcp.config import Config, DirectoryPolicy

    config = Config(
        source=tmp_path / "c.yaml",
        directories=DirectoryPolicy(allow=(tmp_path,)),
        applications={},
    )
    assert config.policy is not None
    assert config.filesystem is not None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_config_policy.py -v`
Expected: FAIL — `ConfigError` for unknown keys (`policy`, `filesystem`, …) and `TypeError`/`AttributeError` for the new attributes.

- [ ] **Step 3: Add the new top-level keys and dataclasses**

In `linux_mcp/config.py`, replace the key tuple and add imports:

```python
from linux_mcp.policy import TIER_ORDER, Policy, Tier
```

```python
_TOP_LEVEL_KEYS = (
    "directories",
    "applications",
    "policy",
    "filesystem",
    "commands",
    "web",
    "packages",
    "power",
)
```

Add the dataclasses after `ApplicationSpec`:

```python
@dataclass(frozen=True, slots=True)
class ApprovalConfig:
    """How a human is asked to authorise a dangerous action."""

    mechanism: str = "zenity"
    timeout_seconds: float = 60.0
    remember_for_seconds: int = 0


@dataclass(frozen=True, slots=True)
class AuditConfig:
    """Where and whether audit records are written."""

    enabled: bool = True
    path: Path = Path("~/.local/state/linux-mcp/audit.jsonl")
    max_bytes: int = 10 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class LimitsConfig:
    """Caps that protect the model's context and this process's memory."""

    default_timeout_seconds: float = 30.0
    max_timeout_seconds: float = 600.0
    kill_grace_seconds: float = 3.0
    max_output_bytes: int = 100_000
    max_read_bytes: int = 1_000_000
    rate_limit_per_minute: int = 60


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    """Tier gates, approval settings, auditing, and limits."""

    enabled_tiers: frozenset[Tier] = frozenset({Tier.READONLY, Tier.WRITE})
    confirm_tiers: frozenset[Tier] = frozenset({Tier.SYSTEM, Tier.DESTRUCTIVE})
    approval: ApprovalConfig = field(default_factory=ApprovalConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)

    def policy(self) -> Policy:
        """Build the runtime :class:`~linux_mcp.policy.Policy` for these tiers."""
        return Policy(
            enabled_tiers=self.enabled_tiers,
            confirm_tiers=self.confirm_tiers,
        )


@dataclass(frozen=True, slots=True)
class FilesystemPolicy:
    """Directories the model may read, and the subset it may write."""

    read_allow: tuple[Path, ...]
    write_allow: tuple[Path, ...]
    follow_symlinks: bool = False


@dataclass(frozen=True, slots=True)
class CommandsConfig:
    """Raw command execution settings."""

    run_command_enabled: bool = True
    run_shell_enabled: bool = True
    containment: str = "systemd-scope"
    containment_memory_max_bytes: int = 2_147_483_648
    containment_cpu_quota: str = "200%"
    allow_pkexec: bool = True


@dataclass(frozen=True, slots=True)
class WebConfig:
    """Web retrieval settings (Phase 3)."""

    enabled: bool = True
    search_provider: str = "duckduckgo"
    max_fetch_bytes: int = 2_000_000


@dataclass(frozen=True, slots=True)
class PackagesConfig:
    """Package manager settings (Phase 2)."""

    backend: str = "pacman"
    use_pkexec: bool = True


@dataclass(frozen=True, slots=True)
class PowerConfig:
    """Which power/session actions are permitted (Phase 2)."""

    allow: frozenset[str] = frozenset({"lock", "logout", "suspend"})
```

Add `field` to the dataclasses import at the top:

```python
from dataclasses import dataclass, field
```

- [ ] **Step 4: Add the new fields to `Config`**

```python
@dataclass(frozen=True, slots=True)
class Config:
    """Validated configuration for one server run."""

    source: Path
    directories: DirectoryPolicy
    applications: Mapping[str, ApplicationSpec]
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    filesystem: FilesystemPolicy | None = None
    commands: CommandsConfig = field(default_factory=CommandsConfig)
    web: WebConfig = field(default_factory=WebConfig)
    packages: PackagesConfig = field(default_factory=PackagesConfig)
    power: PowerConfig = field(default_factory=PowerConfig)

    def read_allowlist(self) -> Allowlist:
        """Directories readable by the model (filesystem section, else directories)."""
        roots = (
            self.filesystem.read_allow
            if self.filesystem is not None
            else self.directories.allow
        )
        return Allowlist(roots)

    def write_allowlist(self) -> Allowlist:
        """Directories writable by the model; empty allowlist means no writes."""
        roots = (
            self.filesystem.write_allow
            if self.filesystem is not None
            else self.directories.allow
        )
        return Allowlist(roots)
```

> **Note on `write_allowlist`:** `Allowlist` currently raises when given an empty
> collection. A config may legitimately have no writable directories, so
> `_parse_filesystem` must always produce at least one entry by falling back to
> `read_allow` when `write_allow` is omitted or empty. Do not pass an empty
> sequence to `Allowlist`.

- [ ] **Step 5: Add the section parsers**

In `parse_config`, after `applications = _parse_applications(...)`, add:

```python
    policy_config = _parse_policy(data.get("policy"), source=source, env=env)
    filesystem = _parse_filesystem(
        data.get("filesystem"), directories=directories, source=source, env=env
    )
    commands = _parse_commands(data.get("commands"), source=source)
    web = _parse_web(data.get("web"), source=source)
    packages = _parse_packages(data.get("packages"), source=source)
    power = _parse_power(data.get("power"), source=source)
    return Config(
        source=source,
        directories=directories,
        applications=applications,
        policy=policy_config,
        filesystem=filesystem,
        commands=commands,
        web=web,
        packages=packages,
        power=power,
    )
```

Then append the parsers:

```python
_POLICY_KEYS = ("enabled_tiers", "confirm_tiers", "approval", "audit", "limits")
_APPROVAL_KEYS = ("mechanism", "timeout_seconds", "remember_for_seconds")
_AUDIT_KEYS = ("enabled", "path", "max_bytes")
_LIMITS_KEYS = (
    "default_timeout_seconds",
    "max_timeout_seconds",
    "kill_grace_seconds",
    "max_output_bytes",
    "max_read_bytes",
    "rate_limit_per_minute",
)
_FILESYSTEM_KEYS = ("read_allow", "write_allow", "follow_symlinks")
_COMMANDS_KEYS = (
    "run_command_enabled",
    "run_shell_enabled",
    "containment",
    "containment_memory_max_bytes",
    "containment_cpu_quota",
    "allow_pkexec",
)
_WEB_KEYS = ("enabled", "search_provider", "max_fetch_bytes")
_PACKAGES_KEYS = ("backend", "use_pkexec")
_POWER_KEYS = ("allow",)

_CONTAINMENT_MODES = ("none", "systemd-scope")
_POWER_ACTIONS = frozenset(
    {"lock", "logout", "suspend", "hibernate", "shutdown", "reboot"}
)


def _require_mapping(section: Any, *, name: str, source: Path) -> Mapping[str, Any]:
    if not isinstance(section, Mapping):
        raise ConfigError(
            f"'{name}' in {source} must be a mapping, got {type(section).__name__}."
        )
    return section


def _reject_unknown(section: Mapping[str, Any], allowed: Sequence[str], *, name: str, source: Path) -> None:
    unknown = sorted(str(key) for key in set(section) - set(allowed))
    if unknown:
        raise ConfigError(
            f"Unknown key(s) under '{name}' in {source}: {', '.join(unknown)}. "
            f"Supported keys: {', '.join(allowed)}."
        )


def _parse_tier_set(value: Any, *, name: str, source: Path) -> frozenset[Tier]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ConfigError(f"'{name}' in {source} must be a list of tier names.")
    tiers: list[Tier] = []
    for entry in value:
        try:
            tiers.append(Tier(entry))
        except ValueError:
            valid = ", ".join(tier.value for tier in TIER_ORDER)
            raise ConfigError(
                f"Unknown tier {entry!r} in '{name}' in {source}. "
                f"Valid tiers: {valid}."
            ) from None
    return frozenset(tiers)


def _positive_number(value: Any, *, name: str, source: Path, integer: bool = False) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"'{name}' in {source} must be a number, got {value!r}.")
    if value <= 0:
        raise ConfigError(f"'{name}' in {source} must be greater than zero, got {value}.")
    if integer:
        return int(value)
    return float(value)


def _parse_policy(section: Any, *, source: Path, env: Mapping[str, str] | None) -> PolicyConfig:
    if section is None:
        return PolicyConfig()
    section = _require_mapping(section, name="policy", source=source)
    _reject_unknown(section, _POLICY_KEYS, name="policy", source=source)

    enabled = (
        _parse_tier_set(section["enabled_tiers"], name="policy.enabled_tiers", source=source)
        if "enabled_tiers" in section
        else PolicyConfig().enabled_tiers
    )
    confirm = (
        _parse_tier_set(section["confirm_tiers"], name="policy.confirm_tiers", source=source)
        if "confirm_tiers" in section
        else PolicyConfig().confirm_tiers
    )

    approval = PolicyConfig().approval
    if "approval" in section:
        raw = _require_mapping(section["approval"], name="policy.approval", source=source)
        _reject_unknown(raw, _APPROVAL_KEYS, name="policy.approval", source=source)
        mechanism = str(raw.get("mechanism", approval.mechanism))
        if mechanism != "zenity":
            raise ConfigError(
                f"'policy.approval.mechanism' in {source} must be 'zenity', "
                f"got {mechanism!r}. No other approval mechanism is implemented."
            )
        approval = ApprovalConfig(
            mechanism=mechanism,
            timeout_seconds=_positive_number(
                raw.get("timeout_seconds", approval.timeout_seconds),
                name="policy.approval.timeout_seconds", source=source,
            ),
            remember_for_seconds=int(raw.get("remember_for_seconds", 0)),
        )

    audit = PolicyConfig().audit
    if "audit" in section:
        raw = _require_mapping(section["audit"], name="policy.audit", source=source)
        _reject_unknown(raw, _AUDIT_KEYS, name="policy.audit", source=source)
        audit = AuditConfig(
            enabled=bool(raw.get("enabled", True)),
            path=Path(
                os.path.expanduser(
                    expand_variables(str(raw.get("path", audit.path)), env)
                )
            ),
            max_bytes=_positive_number(
                raw.get("max_bytes", audit.max_bytes),
                name="policy.audit.max_bytes", source=source, integer=True,
            ),
        )

    limits = PolicyConfig().limits
    if "limits" in section:
        raw = _require_mapping(section["limits"], name="policy.limits", source=source)
        _reject_unknown(raw, _LIMITS_KEYS, name="policy.limits", source=source)
        limits = LimitsConfig(
            default_timeout_seconds=_positive_number(
                raw.get("default_timeout_seconds", limits.default_timeout_seconds),
                name="policy.limits.default_timeout_seconds", source=source,
            ),
            max_timeout_seconds=_positive_number(
                raw.get("max_timeout_seconds", limits.max_timeout_seconds),
                name="policy.limits.max_timeout_seconds", source=source,
            ),
            kill_grace_seconds=_positive_number(
                raw.get("kill_grace_seconds", limits.kill_grace_seconds),
                name="policy.limits.kill_grace_seconds", source=source,
            ),
            max_output_bytes=_positive_number(
                raw.get("max_output_bytes", limits.max_output_bytes),
                name="policy.limits.max_output_bytes", source=source, integer=True,
            ),
            max_read_bytes=_positive_number(
                raw.get("max_read_bytes", limits.max_read_bytes),
                name="policy.limits.max_read_bytes", source=source, integer=True,
            ),
            rate_limit_per_minute=_positive_number(
                raw.get("rate_limit_per_minute", limits.rate_limit_per_minute),
                name="policy.limits.rate_limit_per_minute", source=source, integer=True,
            ),
        )

    return PolicyConfig(enabled_tiers=enabled, confirm_tiers=confirm, approval=approval, audit=audit, limits=limits)


def _parse_filesystem(
    section: Any,
    *,
    directories: DirectoryPolicy,
    source: Path,
    env: Mapping[str, str] | None,
) -> FilesystemPolicy:
    if section is None:
        return FilesystemPolicy(read_allow=directories.allow, write_allow=directories.allow)
    section = _require_mapping(section, name="filesystem", source=source)
    _reject_unknown(section, _FILESYSTEM_KEYS, name="filesystem", source=source)

    def _roots(value: Any, *, name: str) -> tuple[Path, ...]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            raise ConfigError(f"'{name}' in {source} must be a list of directory paths.")
        resolved: list[Path] = []
        for entry in value:
            if not isinstance(entry, str):
                raise ConfigError(f"'{name}' entries in {source} must be strings.")
            try:
                resolved.append(canonicalize_configured_directory(entry, env=env))
            except LinuxMCPError as exc:
                logger.warning("Ignoring configured directory: %s", exc)
        return tuple(sorted(set(resolved), key=str))

    read_allow = _roots(section.get("read_allow", [str(p) for p in directories.allow]), name="filesystem.read_allow")
    if not read_allow:
        raise ConfigError(
            f"'filesystem.read_allow' in {source} resolves to no existing directories."
        )
    raw_write = section.get("write_allow")
    write_allow = _roots(raw_write, name="filesystem.write_allow") if raw_write else read_allow
    if not write_allow:
        write_allow = read_allow

    outside = [str(root) for root in write_allow if not any(root.is_relative_to(rd) for rd in read_allow)]
    if outside:
        raise ConfigError(
            f"'filesystem.write_allow' in {source} must be a subset of "
            f"'filesystem.read_allow'. Not readable: {', '.join(outside)}."
        )

    return FilesystemPolicy(
        read_allow=read_allow,
        write_allow=write_allow,
        follow_symlinks=bool(section.get("follow_symlinks", False)),
    )


def _parse_commands(section: Any, *, source: Path) -> CommandsConfig:
    if section is None:
        return CommandsConfig()
    section = _require_mapping(section, name="commands", source=source)
    _reject_unknown(section, _COMMANDS_KEYS, name="commands", source=source)
    containment = str(section.get("containment", CommandsConfig().containment))
    if containment not in _CONTAINMENT_MODES:
        raise ConfigError(
            f"'commands.containment' in {source} must be one of "
            f"{', '.join(_CONTAINMENT_MODES)}, got {containment!r}."
        )
    return CommandsConfig(
        run_command_enabled=bool(section.get("run_command_enabled", True)),
        run_shell_enabled=bool(section.get("run_shell_enabled", True)),
        containment=containment,
        containment_memory_max_bytes=_positive_number(
            section.get("containment_memory_max_bytes", CommandsConfig().containment_memory_max_bytes),
            name="commands.containment_memory_max_bytes", source=source, integer=True,
        ),
        containment_cpu_quota=str(section.get("containment_cpu_quota", CommandsConfig().containment_cpu_quota)),
        allow_pkexec=bool(section.get("allow_pkexec", True)),
    )


def _parse_web(section: Any, *, source: Path) -> WebConfig:
    if section is None:
        return WebConfig()
    section = _require_mapping(section, name="web", source=source)
    _reject_unknown(section, _WEB_KEYS, name="web", source=source)
    return WebConfig(
        enabled=bool(section.get("enabled", True)),
        search_provider=str(section.get("search_provider", "duckduckgo")),
        max_fetch_bytes=_positive_number(
            section.get("max_fetch_bytes", WebConfig().max_fetch_bytes),
            name="web.max_fetch_bytes", source=source, integer=True,
        ),
    )


def _parse_packages(section: Any, *, source: Path) -> PackagesConfig:
    if section is None:
        return PackagesConfig()
    section = _require_mapping(section, name="packages", source=source)
    _reject_unknown(section, _PACKAGES_KEYS, name="packages", source=source)
    return PackagesConfig(
        backend=str(section.get("backend", "pacman")),
        use_pkexec=bool(section.get("use_pkexec", True)),
    )


def _parse_power(section: Any, *, source: Path) -> PowerConfig:
    if section is None:
        return PowerConfig()
    section = _require_mapping(section, name="power", source=source)
    _reject_unknown(section, _POWER_KEYS, name="power", source=source)
    raw = section.get("allow", sorted(PowerConfig().allow))
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ConfigError(f"'power.allow' in {source} must be a list of action names.")
    actions = frozenset(str(item) for item in raw)
    unknown = sorted(actions - _POWER_ACTIONS)
    if unknown:
        raise ConfigError(
            f"Unknown power action(s) in {source}: {', '.join(unknown)}. "
            f"Valid actions: {', '.join(sorted(_POWER_ACTIONS))}."
        )
    return PowerConfig(allow=actions)
```

Also add to the imports at the top of `config.py`:

```python
from linux_mcp.security import expand_variables
```

(`expand_variables` already lives in `security.py` and is safe to import here; `config.py` already imports from `security`.)

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_config_policy.py -v`
Expected: PASS — 10 passed.

- [ ] **Step 7: Verify no regression in the existing config tests**

Run: `.venv/bin/python -m pytest tests/test_config.py -q`
Expected: PASS — all existing config tests still pass.

- [ ] **Step 8: Checkpoint**

Run: `.venv/bin/python -m pytest tests/test_config_policy.py tests/test_config.py -q && .venv/bin/ruff check linux_mcp/config.py tests/test_config_policy.py`
Expected: tests pass, ruff clean.

---

### Task 8: Write-path canonicalisation

**Files:**
- Modify: `linux_mcp/security.py`
- Create: `tests/test_security_write.py`

**Interfaces:**
- Produces: `canonicalize_write_path(raw: str, allowlist: Allowlist) -> Path`.

Behaviour:
- Existing path: resolved strictly, then must be inside the allowlist.
- Non-existent final component: its parent is resolved strictly and must be inside the allowlist; the returned path is `resolved_parent / candidate.name`.
- A symlink (or symlinked parent) that resolves outside the allowlist is **refused**, even if the link itself lives inside.
- The final component must not be `.` or `..`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_security_write.py`:

```python
"""Write-path policy: creation targets are as strictly checked as reads."""

from __future__ import annotations

import pytest

from linux_mcp.errors import PathOutsideAllowlistError
from linux_mcp.security import Allowlist, canonicalize_write_path


@pytest.fixture
def allowlist(workspace) -> Allowlist:
    return Allowlist([workspace.allowed])


def test_existing_file_inside_allowlist_is_returned(allowlist, workspace) -> None:
    assert canonicalize_write_path(str(workspace.alpha), allowlist) == workspace.alpha


def test_new_file_inside_allowlist_is_allowed(allowlist, workspace) -> None:
    target = workspace.allowed / "brand-new.txt"
    assert canonicalize_write_path(str(target), allowlist) == target


def test_new_file_in_new_subdirectory_is_allowed(allowlist, workspace) -> None:
    target = workspace.allowed / "newdir" / "file.txt"
    assert canonicalize_write_path(str(target), allowlist) == target


def test_write_outside_allowlist_is_refused(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_write_path(str(workspace.outside / "evil.txt"), allowlist)


def test_traversal_escape_is_refused(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_write_path(str(workspace.allowed / ".." / "outside" / "x"), allowlist)


def test_symlinked_parent_escaping_is_refused(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_write_path(str(workspace.symlink_escape / "x.txt"), allowlist)


def test_existing_symlink_escaping_is_refused(allowlist, workspace) -> None:
    with pytest.raises(PathOutsideAllowlistError):
        canonicalize_write_path(str(workspace.symlink_escape), allowlist)


def test_relative_path_is_refused(allowlist) -> None:
    from linux_mcp.errors import InvalidPathError

    with pytest.raises(InvalidPathError):
        canonicalize_write_path("relative.txt", allowlist)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_security_write.py -v`
Expected: FAIL — `ImportError: cannot import name 'canonicalize_write_path'`.

- [ ] **Step 3: Write the implementation**

Append to `linux_mcp/security.py`:

```python
def canonicalize_write_path(raw: str, allowlist: Allowlist) -> Path:
    """Resolve a model-supplied path for **writing** and prove it is allowed.

    Unlike :func:`canonicalize_directory`, the final component may not exist
    yet, because creating files is the point. The rule is therefore: resolve the
    parent strictly (following every symlink), require the resolved parent to be
    inside *allowlist*, and require the final component to be a plain name. An
    existing target is resolved in full instead, so a symlink pointing outside
    the allowlist is refused even when the link itself lives inside.
    """
    candidate = expand_and_normalize(raw)

    if candidate.name in ("", ".", ".."):
        raise InvalidPathError(
            f"Path must name a file or directory, not {raw!r}."
        )

    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        try:
            resolved_parent = _resolve_existing(candidate.parent)
        except PathDoesNotExistError as exc:
            raise PathDoesNotExistError(
                f"Parent directory does not exist: {candidate.parent}."
            ) from exc
        if not allowlist.contains(resolved_parent):
            raise PathOutsideAllowlistError(
                f"Permission denied: writing to {candidate} is outside the "
                f"configured write directories. It resolves to "
                f"{resolved_parent / candidate.name}, which is not allowed. "
                f"Allowed write directories: {allowlist.describe()}."
            )
        return resolved_parent / candidate.name

    if not allowlist.contains(resolved):
        raise PathOutsideAllowlistError(
            f"Permission denied: writing to {candidate} is outside the configured "
            f"write directories. It resolves to {resolved}, which is not allowed. "
            f"Allowed write directories: {allowlist.describe()}."
        )
    return resolved
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_security_write.py -v`
Expected: PASS — 8 passed.

- [ ] **Step 5: Checkpoint**

Run: `.venv/bin/python -m pytest tests/test_security_write.py tests/test_security.py -q && .venv/bin/ruff check linux_mcp/security.py tests/test_security_write.py`
Expected: new tests pass, existing security tests unregressed, ruff clean.

---

### Task 9: Guard — the single composition point

**Files:**
- Create: `linux_mcp/guard.py`
- Create: `tests/test_guard.py`

**Interfaces:**
- Consumes: `policy.Policy`, `policy.Tier`, `approval.ApprovalGate`, `approval.ApprovalRequest`, `approval.ApprovalDecision`, `audit.AuditLog`, `errors.*`.
- Produces:
  - `GuardContext(policy: Policy, audit: AuditLog, approval: ApprovalGate, limits: LimitsConfig)` — frozen dataclass.
  - `guarded(context, *, tool: str, arguments: Mapping[str, object], action: Callable[[], T], summary: str = "", details: str = "") -> T`
  - `GuardContext.from_config(config: Config) -> GuardContext` — builds the audit log and approval gate from a validated `Config`.
  - `describe_tiers(policy: Policy) -> str` — human-readable tier status for tool descriptions.

Behaviour:
- `require_enabled(tool)` first; disabled/undeclared raises before anything runs.
- If the tier needs confirmation, call the gate. Denied → audit `decision=<reason>` then raise `ApprovalDeniedError`, or `ApprovalUnavailableError` when `reason == "unavailable"`.
- Always audit exactly one record per call: `outcome="ok"` or `outcome="error"`.
- The audit record is written **before** returning.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_guard.py`:

```python
"""Guard: tier gate -> approval -> action -> audit, in that order, always."""

from __future__ import annotations

from pathlib import Path

import pytest

from linux_mcp.approval import ApprovalDecision, ApprovalRequest
from linux_mcp.audit import AuditLog
from linux_mcp.config import LimitsConfig
from linux_mcp.errors import (
    ApprovalDeniedError,
    ApprovalUnavailableError,
    TierDisabledError,
)
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.policy import Policy, Tier


class FakeGate:
    def __init__(self, decision: ApprovalDecision) -> None:
        self.decision = decision
        self.requests: list[ApprovalRequest] = []

    def request(self, request: ApprovalRequest) -> ApprovalDecision:
        self.requests.append(request)
        return self.decision


def allow() -> ApprovalDecision:
    return ApprovalDecision(True, "zenity", "allow", 0.1)


def deny(reason: str = "deny") -> ApprovalDecision:
    return ApprovalDecision(False, "zenity" if reason != "unavailable" else None, reason, 0.1)


def context(tmp_path: Path, *, gate, enabled=None, confirm=None) -> GuardContext:
    policy = Policy(
        enabled_tiers=frozenset(enabled if enabled is not None else {Tier.READONLY, Tier.WRITE}),
        confirm_tiers=frozenset(confirm if confirm is not None else set()),
    )
    return GuardContext(
        policy=policy,
        audit=AuditLog(tmp_path / "audit.jsonl"),
        approval=gate,
        limits=LimitsConfig(),
    )


def records(ctx: GuardContext) -> list[dict]:
    import json

    return [json.loads(line) for line in ctx.audit.path.read_text().splitlines() if line]


def test_readonly_action_runs_without_approval_and_is_audited(tmp_path: Path) -> None:
    gate = FakeGate(allow())
    ctx = context(tmp_path, gate=gate)
    result = guarded(
        ctx,
        tool="read_file",
        arguments={"path": "/tmp/x"},
        action=lambda: "content",
    )
    assert result == "content"
    assert gate.requests == []
    assert records(ctx)[0]["decision"] == "auto"
    assert records(ctx)[0]["outcome"] == "ok"


def test_disabled_tier_raises_before_the_action_runs(tmp_path: Path) -> None:
    ctx = context(tmp_path, gate=FakeGate(allow()), enabled={Tier.READONLY})
    called = False

    def action() -> None:
        nonlocal called
        called = True

    with pytest.raises(TierDisabledError):
        guarded(ctx, tool="run_command", arguments={}, action=action)
    assert called is False


def test_confirmed_action_runs_when_allowed(tmp_path: Path) -> None:
    gate = FakeGate(allow())
    ctx = context(
        tmp_path, gate=gate, enabled={Tier.DESTRUCTIVE}, confirm={Tier.DESTRUCTIVE}
    )
    result = guarded(ctx, tool="run_command", arguments={"argv": ["ls"]}, action=lambda: 42)
    assert result == 42
    assert len(gate.requests) == 1
    assert records(ctx)[0]["decision"] == "approved"
    assert records(ctx)[0]["mechanism"] == "zenity"


def test_confirmed_action_raises_when_denied_and_audits_denial(tmp_path: Path) -> None:
    gate = FakeGate(deny())
    ctx = context(
        tmp_path, gate=gate, enabled={Tier.DESTRUCTIVE}, confirm={Tier.DESTRUCTIVE}
    )
    called = False

    def action() -> None:
        nonlocal called
        called = True

    with pytest.raises(ApprovalDeniedError):
        guarded(ctx, tool="run_command", arguments={}, action=action)
    assert called is False
    assert records(ctx)[0]["decision"] == "deny"
    assert records(ctx)[0]["outcome"] == "denied"


def test_unavailable_approval_raises_approval_unavailable(tmp_path: Path) -> None:
    ctx = context(
        tmp_path, gate=FakeGate(deny("unavailable")), enabled={Tier.DESTRUCTIVE}, confirm={Tier.DESTRUCTIVE}
    )
    with pytest.raises(ApprovalUnavailableError):
        guarded(ctx, tool="run_command", arguments={}, action=lambda: None)


def test_action_failure_is_audited_and_reraised(tmp_path: Path) -> None:
    ctx = context(tmp_path, gate=FakeGate(allow()))
    with pytest.raises(ValueError):
        guarded(
            ctx,
            tool="read_file",
            arguments={"path": "/tmp/x"},
            action=lambda: (_ for _ in ()).throw(ValueError("boom")),
        )
    assert records(ctx)[0]["outcome"] == "error"
    assert "boom" in records(ctx)[0]["error"]


def test_arguments_are_redacted_in_the_audit_record(tmp_path: Path) -> None:
    ctx = context(tmp_path, gate=FakeGate(allow()))
    guarded(
        ctx,
        tool="read_file",
        arguments={"path": "/tmp/x", "api_key": "secret"},
        action=lambda: "ok",
    )
    assert records(ctx)[0]["arguments"]["api_key"] == "[redacted]"


def test_undeclared_tool_is_refused(tmp_path: Path) -> None:
    from linux_mcp.errors import UndeclaredToolError

    ctx = context(tmp_path, gate=FakeGate(allow()))
    with pytest.raises(UndeclaredToolError):
        guarded(ctx, tool="not_a_tool", arguments={}, action=lambda: None)


def test_from_config_builds_working_context(tmp_path: Path) -> None:
    """from_config must read the audit path and approval timeout from the config."""
    from linux_mcp.config import (
        AuditConfig,
        Config,
        DirectoryPolicy,
        PolicyConfig,
    )

    config = Config(
        source=tmp_path / "config.yaml",
        directories=DirectoryPolicy(allow=(tmp_path,)),
        applications={},
        policy=PolicyConfig(
            audit=AuditConfig(path=tmp_path / "audit.jsonl"),
            enabled_tiers=frozenset({Tier.READONLY, Tier.WRITE, Tier.DESTRUCTIVE}),
            confirm_tiers=frozenset({Tier.DESTRUCTIVE}),
        ),
    )
    ctx = GuardContext.from_config(config)
    assert ctx.audit.path == tmp_path / "audit.jsonl"
    assert ctx.policy.is_enabled(Tier.DESTRUCTIVE) is True
    assert ctx.policy.requires_confirmation(Tier.DESTRUCTIVE) is True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_guard.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'linux_mcp.guard'`.

- [ ] **Step 3: Write the implementation**

Create `linux_mcp/guard.py`:

```python
"""The one place a tool's permission decision is made.

Every tool calls :func:`guarded` and nothing else. That keeps the order of
operations identical everywhere: resolve the tier, refuse if disabled, ask a
human if the tier requires it, run the action, and write exactly one audit
record before returning. Tools contain no policy logic of their own.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from linux_mcp.approval import ApprovalGate, ApprovalRequest
from linux_mcp.audit import AuditLog
from linux_mcp.config import Config, LimitsConfig
from linux_mcp.errors import ApprovalDeniedError, ApprovalUnavailableError
from linux_mcp.logging_setup import get_logger
from linux_mcp.policy import Policy, Tier

logger = get_logger("guard")

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class GuardContext:
    """Everything a tool needs to run one guarded action."""

    policy: Policy
    audit: AuditLog
    approval: ApprovalGate
    limits: LimitsConfig

    @classmethod
    def from_config(cls, config: Config) -> GuardContext:
        """Build a context from a validated configuration."""
        return cls(
            policy=config.policy.policy(),
            audit=AuditLog(
                Path(config.policy.audit.path).expanduser(),
                enabled=config.policy.audit.enabled,
                max_bytes=config.policy.audit.max_bytes,
            ),
            approval=ApprovalGate(
                timeout_seconds=config.policy.approval.timeout_seconds,
            ),
            limits=config.policy.limits,
        )


def guarded(
    context: GuardContext,
    *,
    tool: str,
    arguments: Mapping[str, object],
    action: Callable[[], T],
    summary: str = "",
    details: str = "",
) -> T:
    """Run *action* under *tool*'s policy, auditing the outcome either way."""
    tier = context.policy.require_enabled(tool)

    decision = "auto"
    mechanism: str | None = None

    if context.policy.requires_confirmation(tier):
        request = ApprovalRequest(
            tool=tool,
            tier=tier.value,
            summary=summary or f"Run {tool}",
            details=details or _describe(arguments),
        )
        outcome = context.approval.request(request)
        if not outcome.allowed:
            context.audit.record(
                tool=tool,
                tier=tier.value,
                decision=outcome.reason,
                mechanism=outcome.mechanism,
                arguments=dict(arguments),
                outcome="denied",
                error=f"approval {outcome.reason}",
            )
            if outcome.reason == "unavailable":
                raise ApprovalUnavailableError(
                    f"{tool} requires human approval, but no approval dialog could "
                    "be shown, so the action was refused. Enable a graphical "
                    "session, or lower this tool's tier in policy.confirm_tiers."
                )
            raise ApprovalDeniedError(
                f"The user did not approve {tool} ({outcome.reason}), so nothing "
                "was run. Do not retry without the user's explicit request."
            )
        decision = "approved"
        mechanism = outcome.mechanism

    started = time.monotonic()
    try:
        result = action()
    except Exception as exc:
        context.audit.record(
            tool=tool,
            tier=tier.value,
            decision=decision,
            mechanism=mechanism,
            arguments=dict(arguments),
            outcome="error",
            error=str(exc),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        raise

    context.audit.record(
        tool=tool,
        tier=tier.value,
        decision=decision,
        mechanism=mechanism,
        arguments=dict(arguments),
        outcome="ok",
        duration_ms=int((time.monotonic() - started) * 1000),
    )
    return result


def _describe(arguments: Mapping[str, object]) -> str:
    lines = [f"{key}: {value!r}" for key, value in arguments.items()]
    return "\n".join(lines) if lines else "(no arguments)"


def describe_tiers(policy: Policy) -> str:
    """One-line summary of tier status, for embedding in tool descriptions."""
    from linux_mcp.policy import TIER_ORDER

    parts: list[str] = []
    for tier in TIER_ORDER:
        if not policy.is_enabled(tier):
            status = "disabled"
        elif policy.requires_confirmation(tier):
            status = "requires approval"
        else:
            status = "allowed"
        parts.append(f"{tier.value}={status}")
    return ", ".join(parts)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_guard.py -v`
Expected: PASS — 9 passed.

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/python -m pytest tests/ -q`
Expected: PASS — all existing 193 tests plus the new ones.

- [ ] **Step 6: Final checkpoint**

Run: `.venv/bin/ruff check . && .venv/bin/python server.py --check`
Expected: ruff clean; `--check` still validates an existing configuration.

---

## Definition of done for Phase 1a

1. `policy`, `redaction`, `audit`, `approval`, `containment`, `exec`, `guard` exist and are importable.
2. None of them imports `mcp`.
3. Every new module has tests; the focused suites pass.
4. The full existing suite still passes unchanged.
5. `ruff check .` is clean.
6. `server.py --check` still works with the user's real configuration.
7. No tool has been added yet — Phase 1b (tools) builds entirely on this foundation.

## Follow-on plan

Phase 1b (`docs/superpowers/plans/2026-09-15-linux-mcp-phase-1b-tools.md`) will add the Phase 1 tools on top of this foundation: `read_file`, `list_tree`, `search_files`, `search_content`, `file_info`, `checksum`, `write_file`, `edit_file`, `create_directory`, `move_path`, `copy_path`, `trash_path`, `delete_path`, `get_system_info`, `get_resource_usage`, `list_processes`, `kill_process`, `force_kill_process`, `run_command`, `run_shell` — each as a thin `register()` wrapper calling `guard.guarded`.
