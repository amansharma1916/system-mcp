"""Screenshot tool. The capture programs are mocked; nothing is photographed."""

from __future__ import annotations

from pathlib import Path

import pytest

from linux_mcp.errors import OperationRefusedError, PathOutsideAllowlistError
from linux_mcp.security import Allowlist
from linux_mcp.tools import screenshots as screenshots_module
from linux_mcp.tools.screenshots import capture_screenshot, default_destination


@pytest.fixture
def allowlist(workspace) -> Allowlist:
    return Allowlist([workspace.allowed])


@pytest.fixture
def fake_capture(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(argv, *, purpose, timeout_seconds=15.0, use_pkexec=False, stdin_data=None):
        calls.append(list(argv))
        # Emulate the capture tool creating the file.
        Path(argv[1]).write_bytes(b"\x89PNG fake")
        return ""

    monkeypatch.setattr(screenshots_module, "run_program", fake_run)
    monkeypatch.setattr(
        screenshots_module.shutil, "which", lambda name: f"/usr/bin/{name}"
    )
    return calls


def test_wayland_uses_grim(monkeypatch, allowlist, workspace, fake_capture) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.delenv("XDG_CURRENT_DESKTOP", raising=False)
    target = workspace.allowed / "shot.png"
    result = capture_screenshot(str(target), write_allowlist=allowlist)
    assert result.tool == "grim"
    assert result.path == str(target)
    assert result.bytes_written > 0
    assert fake_capture[0] == ["/usr/bin/grim", str(target)]


def test_default_destination_lands_in_the_first_write_root(allowlist, workspace) -> None:
    destination = default_destination(allowlist)
    assert Path(destination).parent == workspace.allowed
    assert Path(destination).name.startswith("screenshot-")
    assert destination.endswith(".png")


def test_a_missing_path_uses_the_default(monkeypatch, allowlist, workspace, fake_capture) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.delenv("XDG_CURRENT_DESKTOP", raising=False)
    result = capture_screenshot(None, write_allowlist=allowlist)
    assert Path(result.path).parent == workspace.allowed


def test_writing_outside_the_allowlist_is_refused(monkeypatch, allowlist, workspace, fake_capture) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.delenv("XDG_CURRENT_DESKTOP", raising=False)
    with pytest.raises(PathOutsideAllowlistError):
        capture_screenshot(str(workspace.outside / "shot.png"), write_allowlist=allowlist)


def test_an_existing_file_is_not_overwritten(monkeypatch, allowlist, workspace, fake_capture) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.delenv("XDG_CURRENT_DESKTOP", raising=False)
    target = workspace.allowed / "taken.png"
    target.write_bytes(b"already here")
    with pytest.raises(OperationRefusedError):
        capture_screenshot(str(target), write_allowlist=allowlist)


def test_no_capture_tool_is_reported_clearly(monkeypatch, allowlist) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.delenv("XDG_CURRENT_DESKTOP", raising=False)
    monkeypatch.setattr(screenshots_module.shutil, "which", lambda name: None)
    with pytest.raises(OperationRefusedError) as excinfo:
        capture_screenshot(None, write_allowlist=allowlist)
    assert "grim" in str(excinfo.value)


def test_x11_uses_scrot_when_grim_is_absent(monkeypatch, allowlist, workspace, fake_capture) -> None:
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        screenshots_module.shutil,
        "which",
        lambda name: "/usr/bin/scrot" if name == "scrot" else None,
    )
    target = workspace.allowed / "x11.png"
    result = capture_screenshot(str(target), write_allowlist=allowlist)
    assert result.tool == "scrot"


def test_gnome_wayland_is_refused_with_an_explanation(monkeypatch, allowlist, workspace, fake_capture) -> None:
    """GNOME deliberately blocks programmatic capture; say so clearly."""
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "ubuntu:GNOME")
    with pytest.raises(OperationRefusedError) as excinfo:
        capture_screenshot(str(workspace.allowed / "shot.png"), write_allowlist=allowlist)
    message = str(excinfo.value)
    assert "GNOME" in message
    assert "Print Screen" in message
    assert fake_capture == [], "no capture program may be invoked on GNOME Wayland"


def test_gnome_on_x11_is_not_blocked(monkeypatch, allowlist, workspace, fake_capture) -> None:
    """The restriction is specific to GNOME on Wayland, not GNOME itself."""
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setenv("XDG_CURRENT_DESKTOP", "GNOME")
    target = workspace.allowed / "x11-gnome.png"
    result = capture_screenshot(str(target), write_allowlist=allowlist)
    assert result.tool in {"grim", "scrot", "maim"}
