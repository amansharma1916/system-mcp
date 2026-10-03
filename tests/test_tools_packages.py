"""Package tools. Everything is mocked: no test may touch a real package manager."""

from __future__ import annotations

import pytest

from linux_mcp.config import PackagesConfig
from linux_mcp.errors import InvalidPathError, OperationRefusedError
from linux_mcp.tools import packages as packages_module
from linux_mcp.tools.packages import (
    describe_package,
    install_packages,
    list_installed,
    remove_packages,
    search_repositories,
    upgrade_system,
)

PACMAN = PackagesConfig(backend="pacman", use_pkexec=True)


@pytest.fixture
def fake_programs(monkeypatch):
    """Capture every program invocation and return canned output."""
    calls: list[list[str]] = []
    responses: list[str] = []

    def fake_run(argv, *, purpose, timeout_seconds=15.0, use_pkexec=False, stdin_data=None):
        calls.append(list(argv))
        return responses.pop(0) if responses else ""

    monkeypatch.setattr(packages_module, "run_program", fake_run)
    monkeypatch.setattr(packages_module, "require_program", lambda name, purpose: f"/usr/bin/{name}")
    monkeypatch.setattr(packages_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    return calls, responses


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad", ["--noconfirm", "-S", "", "with space", "semi;colon", "a/b"])
def test_invalid_package_names_are_refused(fake_programs, bad) -> None:
    with pytest.raises(InvalidPathError):
        install_packages(PACMAN, [bad])


def test_install_requires_at_least_one_package(fake_programs) -> None:
    with pytest.raises(InvalidPathError):
        install_packages(PACMAN, [])


def test_search_query_is_validated(fake_programs) -> None:
    with pytest.raises(InvalidPathError):
        search_repositories(PACMAN, "   ")
    with pytest.raises(InvalidPathError):
        search_repositories(PACMAN, "--help")


def test_unknown_backend_is_refused(fake_programs) -> None:
    with pytest.raises(OperationRefusedError):
        search_repositories(PackagesConfig(backend="apt"), "x")


# --------------------------------------------------------------------------- #
# read-only operations
# --------------------------------------------------------------------------- #


def test_list_installed_parses_pacman_output(fake_programs) -> None:
    calls, responses = fake_programs
    responses.append("bash 5.2.037-1\nvim 9.1.0-1\n")
    result = list_installed(PACMAN)
    assert [entry.name for entry in result.packages] == ["bash", "vim"]
    assert result.packages[0].version == "5.2.037-1"
    assert calls[0] == ["pacman", "-Q"]


def test_list_installed_filters_by_substring(fake_programs) -> None:
    _calls, responses = fake_programs
    responses.append("bash 5.2\nvim 9.1\ngvim 9.1\n")
    result = list_installed(PACMAN, name_filter="vim")
    assert [entry.name for entry in result.packages] == ["gvim", "vim"]


def test_list_installed_truncates(fake_programs) -> None:
    _calls, responses = fake_programs
    responses.append("\n".join(f"pkg{i} 1.0" for i in range(10)))
    result = list_installed(PACMAN, limit=3)
    assert len(result.packages) == 3
    assert result.total == 10
    assert result.truncated is True


def test_search_parses_and_deduplicates(fake_programs) -> None:
    calls, responses = fake_programs
    responses.append("postgresql\npostgresql-libs\npostgresql\n")
    result = search_repositories(PACMAN, "postgres")
    assert result.matches == ["postgresql", "postgresql-libs"]
    assert result.total == 2
    assert calls[0] == ["pacman", "-Ssq", "postgres"]


def test_describe_package_returns_raw_text(fake_programs) -> None:
    calls, responses = fake_programs
    responses.append("Name            : vim\nVersion         : 9.1\n")
    result = describe_package(PACMAN, "vim")
    assert "Name" in result.raw
    assert calls[0] == ["pacman", "-Qi", "vim"]


# --------------------------------------------------------------------------- #
# privileged operations
# --------------------------------------------------------------------------- #


def test_install_builds_the_expected_argv_and_escalates(fake_programs) -> None:
    calls, responses = fake_programs
    responses.append("installed\n")
    result = install_packages(PACMAN, ["vim", "git"])
    assert result.escalated is True
    assert result.targets == ["vim", "git"]
    assert calls[0] == ["pacman", "-S", "--noconfirm", "vim", "git"]


def test_install_does_not_escalate_when_disabled(fake_programs) -> None:
    _calls, responses = fake_programs
    responses.append("ok\n")
    result = install_packages(PackagesConfig(backend="pacman", use_pkexec=False), ["vim"])
    assert result.escalated is False


def test_remove_cascades_by_default(fake_programs) -> None:
    calls, responses = fake_programs
    responses.append("removed\n")
    remove_packages(PACMAN, ["vim"])
    assert calls[0][1] == "-Rns"


def test_remove_without_cascade_uses_plain_r(fake_programs) -> None:
    calls, responses = fake_programs
    responses.append("removed\n")
    remove_packages(PACMAN, ["vim"], cascade=False)
    assert calls[0][1] == "-R"


def test_upgrade_runs_a_full_system_upgrade(fake_programs) -> None:
    calls, responses = fake_programs
    responses.append("upgraded\n")
    result = upgrade_system(PACMAN)
    assert result.action == "upgrade"
    assert calls[0] == ["pacman", "-Syu", "--noconfirm"]


def test_flatpak_backend_does_not_escalate(fake_programs) -> None:
    calls, responses = fake_programs
    responses.append("ok\n")
    result = install_packages(PackagesConfig(backend="flatpak"), ["org.gimp.GIMP"])
    assert result.escalated is False
    assert calls[0][0] == "flatpak"


def test_auto_backend_prefers_yay_when_present(monkeypatch, fake_programs) -> None:
    calls, responses = fake_programs
    monkeypatch.setattr(
        packages_module.shutil, "which", lambda name: f"/usr/bin/{name}" if name != "apt" else None
    )
    responses.append("yay 1.0\n")
    list_installed(PackagesConfig(backend="auto"))
    assert calls[0][0] == "yay"


def test_missing_backend_is_reported_clearly(monkeypatch) -> None:
    monkeypatch.setattr(packages_module.shutil, "which", lambda name: None)
    monkeypatch.setattr(packages_module, "require_program", lambda name, purpose: None)
    with pytest.raises(OperationRefusedError):
        list_installed(PackagesConfig(backend="pacman"))
