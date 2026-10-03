"""Append-only, tamper-evident audit log for every policy decision.

One JSON object per line. Each record carries the hash of the previous record,
so deleting or editing a line breaks the chain and :meth:`AuditLog.verify_chain`
reports it. Records are flushed and fsync-ed before the caller returns, so an
executed action cannot go unrecorded because of a crash.

The log records *what was requested and decided*, never file contents or
environment values; argument values are passed through
:func:`linux_mcp.redaction.redact_mapping` first.

Rotation keeps a single previous generation (``audit.jsonl.1``) and the hash
chain continues across it: when the live file is empty after a rotation, the
chain is seeded from the last record of the rotated file. To verify a rotated
log, call :meth:`AuditLog.verify_chain` on the older file first and pass its last
``hash`` as ``expected_prev_hash`` when verifying the newer one.
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
        self._prepared = False

    @property
    def path(self) -> Path:
        """Where records are written."""
        return self._path

    @property
    def rotated_path(self) -> Path:
        """Where the previous generation is kept."""
        return self._path.with_suffix(self._path.suffix + ".1")

    def _ensure_prepared(self) -> None:
        """Create the file and seed the chain on first write, not on construction.

        Deferring this means building a :class:`~linux_mcp.guard.GuardContext`
        has no filesystem side effects, so importing or configuring the server
        never touches the user's home directory.
        """
        if self._prepared:
            return
        self._prepared = True
        self._prepare()

    def _prepare(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError as exc:
            logger.warning("Could not chmod audit directory %s: %s", self._path.parent, exc)
        if self._path.exists():
            self._prev_hash = self._last_hash(self._path)
            if self._prev_hash == GENESIS_HASH and self.rotated_path.exists():
                # Freshly rotated: continue the chain from the previous generation.
                self._prev_hash = self._last_hash(self.rotated_path)
            os.chmod(self._path, 0o600)
        else:
            descriptor = os.open(self._path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(descriptor)

    @staticmethod
    def _last_hash(path: Path) -> str:
        last_line = ""
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        last_line = line
        except OSError as exc:
            logger.warning("Could not read audit log %s: %s", path, exc)
            return GENESIS_HASH
        if not last_line:
            return GENESIS_HASH
        try:
            return str(json.loads(last_line).get("hash") or GENESIS_HASH)
        except ValueError:
            logger.warning("Audit log %s ends with an unreadable line.", path)
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
        self._ensure_prepared()

        event: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "tier": tier,
            "decision": decision,
            "mechanism": mechanism,
            "arguments": (
                redact_mapping(arguments) if isinstance(arguments, dict) else arguments
            ),
            "cwd": cwd,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "outcome": outcome,
            "error": redact_value(error) if error else None,
            "prev_hash": self._prev_hash,
        }
        canonical = json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        event["hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        line = json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ) + "\n"
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
        try:
            os.replace(self._path, self.rotated_path)
            os.chmod(self.rotated_path, 0o600)
        except OSError as exc:
            # Rotation failure must not lose the incoming record; log and append.
            logger.error("Could not rotate audit log %s: %s", self._path, exc)

    def verify_chain(self, *, expected_prev_hash: str = GENESIS_HASH) -> bool:
        """Recompute every hash and confirm the chain is unbroken.

        *expected_prev_hash* is the ``hash`` of the record immediately before
        this file's first record; use :data:`GENESIS_HASH` for an unrotated log.
        """
        previous = expected_prev_hash
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
