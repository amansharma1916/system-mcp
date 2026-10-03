"""Clipboard tools. wl-clipboard/xclip are mocked; no real clipboard is touched."""

from __future__ import annotations

import pytest

from linux_mcp.errors import InvalidPathError, OperationRefusedError
from linux_mcp.tools import clipboard as clipboard_module
from linux_mcp.tools.clipboard import read_clipboard, write_clipboard


@pytest.fixture
def fake_clipboard(monkeypatch):
    calls: list[list[str]] = []
    payloads: list[bytes | None] = []
    read_result = {"code": 0, "text": ""}

    def fake_run(
        argv,
        *,
        purpose,
        timeout_seconds=15.0,
        use_pkexec=False,
        stdin_data=None,
        capture_output=True,
    ):
        calls.append(list(argv))
        payloads.append(stdin_data)
        return ""

    def fake_capture(argv, *, timeout_seconds=15.0, use_pkexec=False, stdin_data=None):
        calls.append(list(argv))
        return read_result["code"], read_result["text"]

    monkeypatch.setattr(clipboard_module, "run_program", fake_run)
    monkeypatch.setattr(clipboard_module, "capture_program", fake_capture)
    monkeypatch.setattr(
        clipboard_module.shutil, "which", lambda name: f"/usr/bin/{name}"
    )
    return calls, payloads, read_result


def test_wayland_reads_with_wl_paste(monkeypatch, fake_clipboard) -> None:
    calls, _payloads, read_result = fake_clipboard
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    read_result.update(code=0, text="hello")
    result = read_clipboard()
    assert result.text == "hello"
    assert result.backend == "wl-clipboard"
    assert result.length == 5
    assert calls[0] == ["wl-paste", "--no-newline"]


def test_wayland_writes_with_wl_copy_and_pipes_the_text(monkeypatch, fake_clipboard) -> None:
    calls, payloads, _read = fake_clipboard
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    result = write_clipboard("copy me")
    assert result.length == 7
    assert calls[0] == ["wl-copy"]
    assert payloads[0] == b"copy me"


def test_an_empty_clipboard_is_not_an_error(monkeypatch, fake_clipboard) -> None:
    _calls, _payloads, read_result = fake_clipboard
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    # wl-paste exits 1 when nothing has been copied yet.
    read_result.update(code=1, text="")
    result = read_clipboard()
    assert result.text == ""


def test_x11_falls_back_to_xclip(monkeypatch, fake_clipboard) -> None:
    calls, payloads, _read = fake_clipboard
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        clipboard_module.shutil,
        "which",
        lambda name: "/usr/bin/xclip" if name == "xclip" else None,
    )
    write_clipboard("x11 text")
    assert calls[0] == ["xclip", "-selection", "clipboard"]
    assert payloads[0] == b"x11 text"


def test_no_clipboard_tool_is_reported_clearly(monkeypatch) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setattr(clipboard_module.shutil, "which", lambda name: None)
    with pytest.raises(OperationRefusedError) as excinfo:
        read_clipboard()
    assert "wl-clipboard" in str(excinfo.value)


def test_an_oversized_clipboard_is_refused(monkeypatch, fake_clipboard) -> None:
    _calls, _payloads, read_result = fake_clipboard
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    read_result.update(code=0, text="x" * 1_000_001)
    with pytest.raises(OperationRefusedError):
        read_clipboard()


def test_oversized_write_is_refused(monkeypatch, fake_clipboard) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    with pytest.raises(InvalidPathError):
        write_clipboard("x" * 1_000_001)
