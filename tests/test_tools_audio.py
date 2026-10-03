"""Audio tools: output parsing for both backends, bounds, and mute handling."""

from __future__ import annotations

import pytest

from linux_mcp.errors import InvalidPathError, OperationRefusedError
from linux_mcp.tools import audio as audio_module
from linux_mcp.tools.audio import change_mute, change_volume, read_volume


@pytest.fixture
def fake_mixer(monkeypatch):
    """Drive the audio module with canned program output."""
    calls: list[list[str]] = []
    responses: list[str] = []

    def fake_run(argv, *, purpose, timeout_seconds=15.0):
        calls.append(list(argv))
        return responses.pop(0) if responses else ""

    monkeypatch.setattr(audio_module, "run_program", fake_run)
    return calls, responses


def use_wpctl(monkeypatch) -> None:
    monkeypatch.setattr(audio_module, "_backend", lambda: "wpctl")


def use_pactl(monkeypatch) -> None:
    monkeypatch.setattr(audio_module, "_backend", lambda: "pactl")


# --------------------------------------------------------------------------- #
# wpctl
# --------------------------------------------------------------------------- #


def test_wpctl_volume_is_parsed(monkeypatch, fake_mixer) -> None:
    calls, responses = fake_mixer
    use_wpctl(monkeypatch)
    responses.append("Volume: 0.65\n")
    result = read_volume()
    assert result.percent == 65
    assert result.muted is False
    assert result.backend == "wpctl"
    assert calls[0] == ["wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@"]


def test_wpctl_muted_flag_is_parsed(monkeypatch, fake_mixer) -> None:
    _calls, responses = fake_mixer
    use_wpctl(monkeypatch)
    responses.append("Volume: 0.00 [MUTED]\n")
    result = read_volume()
    assert result.percent == 0
    assert result.muted is True


def test_wpctl_set_volume_uses_a_percentage(monkeypatch, fake_mixer) -> None:
    calls, responses = fake_mixer
    use_wpctl(monkeypatch)
    responses.extend(["", "Volume: 0.40\n"])
    result = change_volume(40)
    assert result.percent == 40
    assert calls[0] == ["wpctl", "set-volume", "@DEFAULT_AUDIO_SINK@", "40%"]


# --------------------------------------------------------------------------- #
# pactl
# --------------------------------------------------------------------------- #


def test_pactl_volume_and_mute_are_parsed(monkeypatch, fake_mixer) -> None:
    calls, responses = fake_mixer
    use_pactl(monkeypatch)
    responses.extend(
        ["Volume: front-left: 32768 /  50% / -18.06 dB,   front-right: 32768 /  50% /\n", "Mute: yes\n"]
    )
    result = read_volume()
    assert result.percent == 50
    assert result.muted is True
    assert result.backend == "pactl"
    assert calls[0][0] == "pactl"


def test_pactl_mute_uses_numeric_flags(monkeypatch, fake_mixer) -> None:
    calls, responses = fake_mixer
    use_pactl(monkeypatch)
    responses.extend(["", "Volume: front-left: 65536 / 100% / 0.00 dB\n", "Mute: no\n"])
    change_mute(True)
    assert calls[0] == ["pactl", "set-sink-mute", "@DEFAULT_SINK@", "1"]


# --------------------------------------------------------------------------- #
# behaviour shared by both
# --------------------------------------------------------------------------- #


def test_volume_bounds_are_enforced(monkeypatch, fake_mixer) -> None:
    use_wpctl(monkeypatch)
    for bad in (-1, 151, 1000):
        with pytest.raises(InvalidPathError):
            change_volume(bad)


def test_volume_accepts_amplification_up_to_the_cap(monkeypatch, fake_mixer) -> None:
    calls, responses = fake_mixer
    use_wpctl(monkeypatch)
    responses.extend(["", "Volume: 1.50\n"])
    result = change_volume(150)
    assert result.percent == 150
    assert calls[0][3] == "150%"


def test_mute_toggle_omits_the_flag_value(monkeypatch, fake_mixer) -> None:
    calls, responses = fake_mixer
    use_wpctl(monkeypatch)
    responses.extend(["", "Volume: 0.50 [MUTED]\n"])
    result = change_mute(None)
    assert calls[0] == ["wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@", "toggle"]
    assert result.muted is True


def test_unmute_sends_zero(monkeypatch, fake_mixer) -> None:
    calls, responses = fake_mixer
    use_wpctl(monkeypatch)
    responses.extend(["", "Volume: 0.50\n"])
    change_mute(False)
    assert calls[0][3] == "0"


def test_no_mixer_installed_is_reported_clearly(monkeypatch) -> None:
    monkeypatch.setattr(audio_module.shutil, "which", lambda name: None)
    with pytest.raises(OperationRefusedError) as excinfo:
        read_volume()
    assert "wpctl" in str(excinfo.value)
    assert "pactl" in str(excinfo.value)


def test_unparseable_output_is_reported(monkeypatch, fake_mixer) -> None:
    _calls, responses = fake_mixer
    use_wpctl(monkeypatch)
    responses.append("something unexpected\n")
    with pytest.raises(OperationRefusedError):
        read_volume()


def test_non_integer_volume_is_refused(monkeypatch, fake_mixer) -> None:
    use_wpctl(monkeypatch)
    with pytest.raises(InvalidPathError):
        change_volume("50")  # type: ignore[arg-type]
