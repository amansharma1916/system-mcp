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
