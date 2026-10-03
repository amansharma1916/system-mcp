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
    assert (
        log.record(
            tool="read_file",
            tier="readonly",
            decision="auto",
            mechanism=None,
            arguments={},
            outcome="ok",
        )
        is None
    )
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
        arguments={
            "api_key": "supersecret",
            "argv": ["curl", "-H", "Authorization: Bearer abcdefghijklmnopqrstuv"],
        },
        outcome="ok",
    )
    record = read_records(log)[0]
    assert record["arguments"]["api_key"] == REDACTED
    assert "abcdefghijklmnopqrstuv" not in json.dumps(record["arguments"])


def test_hash_chain_links_records(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    first = log.record(
        tool="read_file",
        tier="readonly",
        decision="auto",
        mechanism=None,
        arguments={},
        outcome="ok",
    )
    second = log.record(
        tool="read_file",
        tier="readonly",
        decision="auto",
        mechanism=None,
        arguments={},
        outcome="ok",
    )
    assert first["prev_hash"] == GENESIS_HASH
    assert second["prev_hash"] == first["hash"]
    assert log.verify_chain() is True


def test_verify_chain_detects_tampering(tmp_path: Path) -> None:
    log = make_log(tmp_path)
    for _ in range(2):
        log.record(
            tool="read_file",
            tier="readonly",
            decision="auto",
            mechanism=None,
            arguments={},
            outcome="ok",
        )
    lines = log.path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"outcome":"ok"', '"outcome":"evil"')
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert log.verify_chain() is False


def test_chain_resumes_across_instances(tmp_path: Path) -> None:
    first_log = make_log(tmp_path)
    first = first_log.record(
        tool="read_file",
        tier="readonly",
        decision="auto",
        mechanism=None,
        arguments={},
        outcome="ok",
    )
    second_log = make_log(tmp_path)
    second = second_log.record(
        tool="read_file",
        tier="readonly",
        decision="auto",
        mechanism=None,
        arguments={},
        outcome="ok",
    )
    assert second["prev_hash"] == first["hash"]
    assert second_log.verify_chain() is True


def test_rotation_keeps_previous_generation(tmp_path: Path) -> None:
    log = make_log(tmp_path, max_bytes=200)
    for _ in range(10):
        log.record(
            tool="read_file",
            tier="readonly",
            decision="auto",
            mechanism=None,
            arguments={"filler": "x" * 40},
            outcome="ok",
        )
    rotated = log.path.with_suffix(log.path.suffix + ".1")
    assert rotated.exists()
    assert log.path.exists()


def test_chain_continues_across_rotation(tmp_path: Path) -> None:
    log = make_log(tmp_path, max_bytes=200)
    for _ in range(6):
        log.record(
            tool="read_file",
            tier="readonly",
            decision="auto",
            mechanism=None,
            arguments={"filler": "x" * 40},
            outcome="ok",
        )
    rotated = log.path.with_suffix(log.path.suffix + ".1")
    rotated_lines = [
        line for line in rotated.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    start_hash = json.loads(rotated_lines[-1])["hash"]
    assert read_records(log)[0]["prev_hash"] == start_hash
    assert log.verify_chain(expected_prev_hash=start_hash) is True


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
            tool="read_file",
            tier="readonly",
            decision="auto",
            mechanism=None,
            arguments={},
            outcome="ok",
        )
    except OSError as exc:
        assert "disk on fire" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected OSError to propagate")
