"""New configuration sections: parsing, defaults, and fail-closed validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from linux_mcp.config import Config, DirectoryPolicy, parse_config
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
    assert config.filesystem is not None
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
    assert config.filesystem is not None
    assert config.filesystem.write_allow == (writable.resolve(),)


def test_commands_section_parsed(tmp_path: Path) -> None:
    config = parse(
        base(
            tmp_path,
            commands={
                "containment": "none",
                "allow_pkexec": False,
                "run_shell_enabled": False,
            },
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


def test_power_actions_are_validated(tmp_path: Path) -> None:
    config = parse(base(tmp_path, power={"allow": ["lock", "shutdown"]}))
    assert config.power.allow == frozenset({"lock", "shutdown"})
    with pytest.raises(ConfigError):
        parse(base(tmp_path, power={"allow": ["explode"]}))


def test_existing_config_construction_still_works(tmp_path: Path) -> None:
    """The new fields are defaulted, so old positional construction is unaffected."""
    config = Config(
        source=tmp_path / "c.yaml",
        directories=DirectoryPolicy(allow=(tmp_path,)),
        applications={},
    )
    assert config.policy is not None
    assert config.filesystem is None
    assert config.read_allowlist().roots == (tmp_path.resolve(),)
    assert config.write_allowlist().roots == (tmp_path.resolve(),)
