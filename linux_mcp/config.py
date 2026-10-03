"""Configuration loading and validation.

The configuration file belongs to the human user and is therefore *trusted*
input; everything the model sends is validated separately in
:mod:`linux_mcp.security`. Configuration is still validated strictly at
startup, and a missing or invalid file is fatal: the server must never start
with an empty or accidentally broad policy.
"""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from linux_mcp.errors import (
    ConfigError,
    LinuxMCPError,
    PathDoesNotExistError,
    PathNotDirectoryError,
)
from linux_mcp.logging_setup import get_logger
from linux_mcp.policy import TIER_ORDER, Policy, Tier
from linux_mcp.security import (
    Allowlist,
    canonicalize_configured_directory,
    contains_shell_metacharacters,
    expand_variables,
    validate_command_arguments,
    validate_command_name,
)

logger = get_logger("config")

CONFIG_PATH_ENV = "LINUX_MCP_CONFIG"
"""Environment variable naming the configuration file to use."""

DEFAULT_CONFIG_PATHS: tuple[Path, ...] = (
    Path("config/config.yaml"),
    Path("~/.config/linux-mcp/config.yaml"),
)
"""Locations searched when no configuration file is given explicitly."""

DEFAULT_MAX_ENTRIES = 500
"""How many entries ``browse_files`` returns per call unless configured otherwise."""

MAX_MAX_ENTRIES = 100_000
"""Upper bound for ``directories.max_entries``; guards against context blow-ups."""

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
_APPLICATIONS_KEYS = ("allow",)
_DIRECTORIES_KEYS = ("allow", "max_entries")
_APPLICATION_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_BROAD_DIRECTORIES = (Path("/"),)
"""Directories that grant effectively unrestricted read access; warned about."""


@dataclass(frozen=True, slots=True)
class DirectoryPolicy:
    """Which directories may be browsed, and how much of them is returned."""

    allow: tuple[Path, ...]
    max_entries: int = DEFAULT_MAX_ENTRIES

    def allowlist(self) -> Allowlist:
        """Return the :class:`~linux_mcp.security.Allowlist` for these roots."""
        return Allowlist(self.allow)


@dataclass(frozen=True, slots=True)
class ApplicationSpec:
    """One allowlisted desktop application."""

    name: str
    command: tuple[str, ...]
    description: str = ""
    available: bool = True
    unavailable_reason: str | None = None

    @property
    def executable(self) -> str:
        """The executable to run: absolute when it was resolved, else the bare name.

        A configured command that could not be resolved (see
        :attr:`available`) keeps its bare name so error messages can report
        "not found on PATH" instead of pointing at a path that was never there.
        """
        return self.command[0]

    def summary(self) -> str:
        """A short label such as ``code (Visual Studio Code)``."""
        return f"{self.name} ({self.description})" if self.description else self.name


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

    def application_names(self) -> tuple[str, ...]:
        """Every configured application name, sorted."""
        return tuple(sorted(self.applications))

    def available_application_names(self) -> tuple[str, ...]:
        """Configured applications whose executable was found, sorted."""
        return tuple(
            sorted(name for name, spec in self.applications.items() if spec.available)
        )

    def read_allowlist(self) -> Allowlist:
        """Directories readable by the model (filesystem section, else directories)."""
        roots = (
            self.filesystem.read_allow
            if self.filesystem is not None
            else self.directories.allow
        )
        return Allowlist(roots)

    def write_allowlist(self) -> Allowlist:
        """Directories writable by the model (filesystem section, else directories)."""
        roots = (
            self.filesystem.write_allow
            if self.filesystem is not None
            else self.directories.allow
        )
        return Allowlist(roots)


def resolve_config_path(
    path: Path | str | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Decide which configuration file to read.

    Precedence: the explicit argument (``--config``), then
    :data:`CONFIG_PATH_ENV`, then :data:`DEFAULT_CONFIG_PATHS`. An explicitly
    requested file that does not exist is an error; a file merely "not found"
    while searching the defaults produces a message explaining how to create
    one.
    """
    environ = os.environ if env is None else env

    if path is not None:
        candidate = Path(os.path.expanduser(str(path)))
        if not candidate.is_file():
            raise ConfigError(f"Configuration file not found: {candidate}.")
        return candidate

    from_env = environ.get(CONFIG_PATH_ENV)
    if from_env:
        candidate = Path(os.path.expanduser(from_env))
        if not candidate.is_file():
            raise ConfigError(
                f"Configuration file named by {CONFIG_PATH_ENV} not found: {candidate}."
            )
        return candidate

    for default in DEFAULT_CONFIG_PATHS:
        candidate = Path(os.path.expanduser(str(default)))
        if candidate.is_file():
            return candidate

    searched = ", ".join(
        str(Path(os.path.expanduser(str(item)))) for item in DEFAULT_CONFIG_PATHS
    )
    raise ConfigError(
        "No configuration file found. Searched: "
        f"{searched}. Copy config/config.example.yaml to "
        "~/.config/linux-mcp/config.yaml (or point LINUX_MCP_CONFIG at your own "
        "file) and list the directories and applications you want to allow."
    )


def load_config(
    path: Path | str | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> Config:
    """Read and validate the configuration file, or raise :class:`ConfigError`."""
    source = resolve_config_path(path, env=env)
    try:
        raw_text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read configuration file {source}: {exc}.") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {source}: {exc}.") from exc

    return parse_config(data, source=source, env=env)


def parse_config(
    data: Any,
    *,
    source: Path,
    env: Mapping[str, str] | None = None,
) -> Config:
    """Validate already-parsed configuration data."""
    if data is None:
        raise ConfigError(f"Configuration file {source} is empty.")
    if not isinstance(data, Mapping):
        raise ConfigError(
            f"Configuration file {source} must contain a mapping of settings, "
            f"got {type(data).__name__}."
        )

    unknown = sorted(str(key) for key in set(data) - set(_TOP_LEVEL_KEYS))
    if unknown:
        raise ConfigError(
            f"Unknown configuration key(s) in {source}: {', '.join(unknown)}. "
            f"Supported keys: {', '.join(_TOP_LEVEL_KEYS)}."
        )

    directories = _parse_directories(data.get("directories"), source=source, env=env)
    applications = _parse_applications(data.get("applications"), source=source)
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


def _parse_directories(
    section: Any,
    *,
    source: Path,
    env: Mapping[str, str] | None = None,
) -> DirectoryPolicy:
    if section is None:
        raise ConfigError(
            f"'directories' is required in {source}: add a 'directories.allow' "
            "list such as [~/Documents, ~/Downloads]."
        )
    if not isinstance(section, Mapping):
        raise ConfigError(
            f"'directories' in {source} must be a mapping with an 'allow' key, "
            f"got {type(section).__name__}."
        )

    unknown = sorted(str(key) for key in set(section) - set(_DIRECTORIES_KEYS))
    if unknown:
        raise ConfigError(
            f"Unknown key(s) under 'directories' in {source}: {', '.join(unknown)}. "
            f"Supported keys: {', '.join(_DIRECTORIES_KEYS)}."
        )

    raw_allow = section.get("allow")
    if not isinstance(raw_allow, Sequence) or isinstance(raw_allow, (str, bytes)):
        raise ConfigError(
            f"'directories.allow' in {source} must be a list of directory paths."
        )
    if not raw_allow:
        raise ConfigError(f"'directories.allow' in {source} must not be empty.")

    max_entries = _parse_max_entries(section.get("max_entries"), source=source)

    roots: list[Path] = []
    for entry in raw_allow:
        if not isinstance(entry, str):
            raise ConfigError(
                f"'directories.allow' entries in {source} must be strings, got "
                f"{type(entry).__name__}."
            )
        try:
            root = canonicalize_configured_directory(entry, env=env)
        except (PathDoesNotExistError, PathNotDirectoryError) as exc:
            # A directory that is simply not there yet (an unmounted volume, a
            # not-yet-created ~/Projects) is not a policy error: warn and carry on
            # with the directories that do exist.
            logger.warning("Ignoring configured directory: %s", exc)
            continue
        except LinuxMCPError:
            raise
        except Exception as exc:
            # Anything else (a bug in this module, an unexpected type) is reported
            # as a configuration problem rather than a traceback.
            raise ConfigError(f"Invalid directory {entry!r} in {source}: {exc}") from exc

        if not root.is_dir():
            logger.warning(
                "Ignoring configured directory %s: not a directory (after resolving %r).",
                root,
                entry,
            )
            continue
        if root in _BROAD_DIRECTORIES:
            logger.warning(
                "Configured directory %s allows browsing almost the whole "
                "filesystem; prefer narrower directories such as ~/Downloads.",
                root,
            )
        roots.append(root)

    if not roots:
        raise ConfigError(
            f"None of the configured directories in {source} exist, so "
            "browse_files would refuse every request. Fix 'directories.allow'."
        )

    deduplicated = tuple(sorted(set(roots), key=str))
    logger.debug("Allowed directories: %s", ", ".join(str(root) for root in deduplicated))
    return DirectoryPolicy(allow=deduplicated, max_entries=max_entries)


def _parse_max_entries(value: Any, *, source: Path) -> int:
    if value is None:
        return DEFAULT_MAX_ENTRIES
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(
            f"'directories.max_entries' in {source} must be a whole number, got {value!r}."
        )
    if value < 1:
        raise ConfigError(
            f"'directories.max_entries' in {source} must be at least 1, got {value}."
        )
    if value > MAX_MAX_ENTRIES:
        raise ConfigError(
            f"'directories.max_entries' in {source} must be at most "
            f"{MAX_MAX_ENTRIES}, got {value}."
        )
    return value


def _parse_applications(section: Any, *, source: Path) -> Mapping[str, ApplicationSpec]:
    if section is None:
        logger.warning(
            "No 'applications' section in %s: open_application will refuse every "
            "request until you allowlist at least one application.",
            source,
        )
        return {}
    if not isinstance(section, Mapping):
        raise ConfigError(
            f"'applications' in {source} must be a mapping with an 'allow' key, "
            f"got {type(section).__name__}."
        )

    unknown = sorted(str(key) for key in set(section) - set(_APPLICATIONS_KEYS))
    if unknown:
        raise ConfigError(
            f"Unknown key(s) under 'applications' in {source}: {', '.join(unknown)}. "
            f"Supported keys: {', '.join(_APPLICATIONS_KEYS)}."
        )

    raw_allow = section.get("allow")
    if raw_allow is None:
        logger.warning(
            "'applications.allow' is missing in %s: open_application will refuse "
            "every request until you allowlist at least one application.",
            source,
        )
        return {}
    if not isinstance(raw_allow, Mapping):
        raise ConfigError(
            f"'applications.allow' in {source} must be a mapping of "
            "name -> command, for example: {code: code, firefox: firefox}."
        )

    specs: dict[str, ApplicationSpec] = {}
    for raw_name, raw_value in raw_allow.items():
        name = _normalize_application_name(raw_name, source=source)
        if name in specs:
            raise ConfigError(
                f"Application name {name!r} is configured more than once in {source}."
            )
        specs[name] = _build_spec_from_value(name, raw_value, source=source)

    logger.debug("Allowlisted applications: %s", ", ".join(sorted(specs)) or "none")
    return specs


def _normalize_application_name(raw_name: Any, *, source: Path) -> str:
    if not isinstance(raw_name, str):
        raise ConfigError(
            f"Application names in {source} must be strings, got "
            f"{type(raw_name).__name__}."
        )
    name = raw_name.strip().lower()
    if not _APPLICATION_NAME_PATTERN.match(name):
        raise ConfigError(
            f"Application name {raw_name!r} in {source} is not allowed. Use "
            "lowercase letters, digits, dots, dashes or underscores, starting "
            "with a letter or digit, for example 'code' or 'gnome-terminal'."
        )
    return name


def _build_spec_from_value(name: str, value: Any, *, source: Path) -> ApplicationSpec:
    description = ""
    if isinstance(value, str):
        command: Any = value
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        command = list(value)
    elif isinstance(value, Mapping):
        unknown = sorted(
            str(key) for key in set(value) - {"command", "description", "enabled"}
        )
        if unknown:
            raise ConfigError(
                f"Unknown key(s) for application {name!r} in {source}: "
                f"{', '.join(unknown)}. Supported keys: command, description, enabled."
            )
        command = value.get("command")
        description = value.get("description") or ""
        if not isinstance(description, str):
            raise ConfigError(
                f"'description' for application {name!r} in {source} must be a string."
            )
        if value.get("enabled") is False:
            spec = build_application_spec(name, command or name, description)
            return ApplicationSpec(
                name=spec.name,
                command=spec.command,
                description=spec.description,
                available=False,
                unavailable_reason="disabled in the configuration file",
            )
    else:
        raise ConfigError(
            f"Application {name!r} in {source} must be a command string, a list "
            "[executable, arg, ...], or a mapping with a 'command' key."
        )

    return build_application_spec(name, command, description)


def build_application_spec(
    name: str,
    command: Any,
    description: str = "",
) -> ApplicationSpec:
    """Validate one application definition and resolve its executable.

    Accepted forms for *command*:

    * ``"code"`` - a bare executable name, looked up on ``PATH`` via
      :func:`shutil.which`.
    * ``"/usr/bin/code"`` - an absolute path.
    * ``["gnome-terminal", "--window"]`` - an executable plus fixed arguments.

    The executable is resolved once, here, so a broken entry is reported at
    startup and never halfway through a tool call. An entry whose executable
    cannot be found is kept in the allowlist but marked unavailable, so
    ``open_application`` can explain precisely what is wrong instead of
    claiming the application is unknown.
    """
    command_tuple = _normalize_command(name, command)
    executable = command_tuple[0]

    # A regular file with the execute bit set: os.access(X_OK) alone would also
    # accept a directory, which fails confusingly at launch time instead of here.
    if not (os.path.isfile(executable) and os.access(executable, os.X_OK)):
        reason = (
            f"the configured command {executable!r} is not an executable file"
            if os.path.isabs(executable)
            else f"{executable!r} was not found on PATH"
        )
        logger.warning(
            "Application %r is allowlisted but unavailable: %s. It stays in the "
            "allowlist so open_application can report the problem clearly.",
            name,
            reason,
        )
        return ApplicationSpec(
            name=name,
            command=command_tuple,
            description=description,
            available=False,
            unavailable_reason=reason,
        )

    return ApplicationSpec(
        name=name,
        command=command_tuple,
        description=description,
        available=True,
        unavailable_reason=None,
    )


def _normalize_command(name: str, command: Any) -> tuple[str, ...]:
    """Turn a configured command value into a validated argv tuple."""
    if isinstance(command, str):
        candidate = command.strip()
        if not candidate:
            raise ConfigError(f"Application {name!r} has an empty command.")
        if any(character.isspace() for character in candidate):
            raise ConfigError(
                f"Application {name!r} has command {command!r} containing "
                "whitespace. A command string must be a single executable; pass "
                "arguments with the list form: [gnome-terminal, --window]."
            )
        parts = (candidate,)
    elif isinstance(command, Sequence) and not isinstance(command, (str, bytes)):
        if not command:
            raise ConfigError(f"Application {name!r} has an empty command list.")
        parts = tuple(command)
    else:
        raise ConfigError(
            f"Application {name!r} must use a command string or a list "
            f"[executable, arg, ...], got {type(command).__name__}. Note that an "
            "unquoted YAML value such as true, false, yes, or no is a boolean, not "
            "a command: quote it, for example {'files': nautilus} or "
            "{'terminal': 'yes'}."
        )
    if not parts:
        raise ConfigError(f"Application {name!r} has an empty command.")

    validate_command_arguments(parts)
    executable = parts[0]
    if not isinstance(executable, str) or not executable:
        raise ConfigError(f"Application {name!r} has an invalid executable name.")

    if os.path.isabs(executable):
        if contains_shell_metacharacters(executable):
            raise ConfigError(
                f"Application {name!r} has an executable path containing shell "
                f"metacharacters: {executable!r}. This project never uses a shell; "
                "remove them from the configuration file."
            )
        return parts

    validate_command_name(executable)
    resolved = shutil.which(executable)
    if resolved is None:
        # Keep the bare name so the resulting error can say "not found on PATH";
        # inventing an absolute path here would produce a misleading message.
        return parts
    return (resolved,) + parts[1:]

# --------------------------------------------------------------------------- #
# Policy, filesystem, command, web, package, and power sections
# --------------------------------------------------------------------------- #

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


def _reject_unknown(
    section: Mapping[str, Any], allowed: Sequence[str], *, name: str, source: Path
) -> None:
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
                f"Unknown tier {entry!r} in '{name}' in {source}. Valid tiers: {valid}."
            ) from None
    return frozenset(tiers)


def _positive_number(
    value: Any, *, name: str, source: Path, integer: bool = False
) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"'{name}' in {source} must be a number, got {value!r}.")
    if value <= 0:
        raise ConfigError(
            f"'{name}' in {source} must be greater than zero, got {value}."
        )
    return int(value) if integer else float(value)


def _parse_policy(
    section: Any, *, source: Path, env: Mapping[str, str] | None
) -> PolicyConfig:
    if section is None:
        return PolicyConfig()
    section = _require_mapping(section, name="policy", source=source)
    _reject_unknown(section, _POLICY_KEYS, name="policy", source=source)

    defaults = PolicyConfig()
    enabled = (
        _parse_tier_set(
            section["enabled_tiers"], name="policy.enabled_tiers", source=source
        )
        if "enabled_tiers" in section
        else defaults.enabled_tiers
    )
    confirm = (
        _parse_tier_set(
            section["confirm_tiers"], name="policy.confirm_tiers", source=source
        )
        if "confirm_tiers" in section
        else defaults.confirm_tiers
    )

    approval = defaults.approval
    if "approval" in section:
        raw = _require_mapping(section["approval"], name="policy.approval", source=source)
        _reject_unknown(raw, _APPROVAL_KEYS, name="policy.approval", source=source)
        mechanism = str(raw.get("mechanism", approval.mechanism))
        if mechanism != "zenity":
            raise ConfigError(
                f"'policy.approval.mechanism' in {source} must be 'zenity', got "
                f"{mechanism!r}. No other approval mechanism is implemented."
            )
        approval = ApprovalConfig(
            mechanism=mechanism,
            timeout_seconds=_positive_number(
                raw.get("timeout_seconds", approval.timeout_seconds),
                name="policy.approval.timeout_seconds",
                source=source,
            ),
            remember_for_seconds=int(raw.get("remember_for_seconds", 0)),
        )

    audit = defaults.audit
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
                name="policy.audit.max_bytes",
                source=source,
                integer=True,
            ),
        )

    limits = defaults.limits
    if "limits" in section:
        raw = _require_mapping(section["limits"], name="policy.limits", source=source)
        _reject_unknown(raw, _LIMITS_KEYS, name="policy.limits", source=source)
        limits = LimitsConfig(
            default_timeout_seconds=_positive_number(
                raw.get("default_timeout_seconds", limits.default_timeout_seconds),
                name="policy.limits.default_timeout_seconds",
                source=source,
            ),
            max_timeout_seconds=_positive_number(
                raw.get("max_timeout_seconds", limits.max_timeout_seconds),
                name="policy.limits.max_timeout_seconds",
                source=source,
            ),
            kill_grace_seconds=_positive_number(
                raw.get("kill_grace_seconds", limits.kill_grace_seconds),
                name="policy.limits.kill_grace_seconds",
                source=source,
            ),
            max_output_bytes=_positive_number(
                raw.get("max_output_bytes", limits.max_output_bytes),
                name="policy.limits.max_output_bytes",
                source=source,
                integer=True,
            ),
            max_read_bytes=_positive_number(
                raw.get("max_read_bytes", limits.max_read_bytes),
                name="policy.limits.max_read_bytes",
                source=source,
                integer=True,
            ),
            rate_limit_per_minute=_positive_number(
                raw.get("rate_limit_per_minute", limits.rate_limit_per_minute),
                name="policy.limits.rate_limit_per_minute",
                source=source,
                integer=True,
            ),
        )

    return PolicyConfig(
        enabled_tiers=enabled,
        confirm_tiers=confirm,
        approval=approval,
        audit=audit,
        limits=limits,
    )


def _parse_filesystem(
    section: Any,
    *,
    directories: DirectoryPolicy,
    source: Path,
    env: Mapping[str, str] | None,
) -> FilesystemPolicy:
    if section is None:
        return FilesystemPolicy(
            read_allow=directories.allow, write_allow=directories.allow
        )
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

    read_allow = _roots(
        section.get("read_allow", [str(path) for path in directories.allow]),
        name="filesystem.read_allow",
    )
    if not read_allow:
        raise ConfigError(
            f"'filesystem.read_allow' in {source} resolves to no existing directories."
        )

    raw_write = section.get("write_allow")
    write_allow = (
        _roots(raw_write, name="filesystem.write_allow") if raw_write else read_allow
    )
    if not write_allow:
        write_allow = read_allow

    outside = [
        str(root)
        for root in write_allow
        if not any(root.is_relative_to(readable) for readable in read_allow)
    ]
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

    defaults = CommandsConfig()
    containment = str(section.get("containment", defaults.containment))
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
            section.get("containment_memory_max_bytes", defaults.containment_memory_max_bytes),
            name="commands.containment_memory_max_bytes",
            source=source,
            integer=True,
        ),
        containment_cpu_quota=str(
            section.get("containment_cpu_quota", defaults.containment_cpu_quota)
        ),
        allow_pkexec=bool(section.get("allow_pkexec", True)),
    )


def _parse_web(section: Any, *, source: Path) -> WebConfig:
    if section is None:
        return WebConfig()
    section = _require_mapping(section, name="web", source=source)
    _reject_unknown(section, _WEB_KEYS, name="web", source=source)
    defaults = WebConfig()
    return WebConfig(
        enabled=bool(section.get("enabled", True)),
        search_provider=str(section.get("search_provider", defaults.search_provider)),
        max_fetch_bytes=_positive_number(
            section.get("max_fetch_bytes", defaults.max_fetch_bytes),
            name="web.max_fetch_bytes",
            source=source,
            integer=True,
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
