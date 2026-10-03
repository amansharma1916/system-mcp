"""Filesystem and process-argument security policy.

This module is plain, synchronous, dependency-free policy: it has no MCP
imports, so every rule here is unit-testable in isolation.

The rule the whole project rests on: a path supplied by the model is only ever
used after it has been **fully resolved** (which follows every symlink) and
verified to live inside one of the configured allowed directories. Resolving
first and comparing afterwards is what makes ``..`` traversal and symlink
escapes impossible:

* ``/home/aman/Downloads/../../etc`` resolves to ``/etc``, which is not inside
  any allowed directory, so it is refused.
* ``/home/aman/Downloads/link`` where ``link -> /etc`` resolves to ``/etc``,
  so it is refused as well, even though the link itself lives in an allowed
  directory.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from linux_mcp.errors import (
    ConfigError,
    DirectoryReadError,
    InvalidPathError,
    PathDoesNotExistError,
    PathNotDirectoryError,
    PathOutsideAllowlistError,
)

_VARIABLE_PATTERN = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)

SHELL_METACHARACTERS = frozenset(";|&$`<>\\!*?[]{}()'\"~ \t\n\r")
"""Characters that are only meaningful to a shell, globbing, or a command line.

They must never appear in a configured executable name or in a bare
application name. This project never invokes a shell (``shell=False`` always),
so this is defence in depth: it turns a config typo or an injected name into a
loud failure instead of a puzzling "executable not found".
"""

_SAFE_BARE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
"""A bare executable name as accepted on ``PATH``, for example ``gnome-terminal``."""


def expand_variables(
    value: str,
    env: Mapping[str, str] | None = None,
    *,
    strict: bool = True,
) -> str:
    """Expand ``$VAR`` / ``${VAR}`` references.

    With ``strict=True`` (used for the configuration file) an undefined
    variable raises :class:`ConfigError`, because silently keeping the literal
    text would produce a confusing "directory does not exist" much later.
    """
    environ = os.environ if env is None else env

    def replace(match: re.Match[str]) -> str:
        name = match.group("braced") or match.group("plain")
        if name not in environ:
            if strict:
                raise ConfigError(
                    f"Undefined variable {name!r} in configuration value {value!r}."
                )
            return match.group(0)
        return environ[name]

    return _VARIABLE_PATTERN.sub(replace, value)


def expand_and_normalize(
    raw: str,
    *,
    expand_env: bool = False,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Validate a raw path string and return it as an absolute :class:`Path`.

    Only ``~`` is expanded for paths that come from the model (``expand_env``
    stays ``False``); ``$VAR`` expansion is reserved for the user-owned
    configuration file. The returned path is **not** resolved yet - call
    :func:`canonicalize_directory` for that.
    """
    if not isinstance(raw, str):
        raise InvalidPathError(f"Path must be a string, got {type(raw).__name__}.")

    value = raw.strip()
    if not value:
        raise InvalidPathError("Path must not be empty.")
    if "\x00" in value:
        raise InvalidPathError("Path must not contain a NUL byte.")
    if "\n" in value or "\r" in value:
        raise InvalidPathError("Path must not contain a line break.")

    if expand_env:
        value = expand_variables(value, env)
    value = os.path.expanduser(value)

    path = Path(value)
    if not path.is_absolute():
        raise InvalidPathError(
            f"Path must be absolute (it must start with '/'): {raw!r}. "
            "For example /home/aman/Downloads."
        )
    return path
class Allowlist:
    """An immutable set of directories that may be browsed.

    Roots must already be canonical (see
    :func:`canonicalize_configured_directory`), because :meth:`contains`
    compares fully resolved paths without touching the filesystem again.
    """

    __slots__ = ("_roots",)

    def __init__(self, roots: Iterable[Path]) -> None:
        unique = {Path(root) for root in roots}
        if not unique:
            raise ConfigError(
                "No allowed directories are configured, so browse_files would "
                "refuse every request. Add at least one entry under "
                "'directories.allow'."
            )
        self._roots: tuple[Path, ...] = tuple(sorted(unique, key=str))

    @property
    def roots(self) -> tuple[Path, ...]:
        """The allowed directories, in stable order."""
        return self._roots

    def contains(self, candidate: Path) -> bool:
        """True when *candidate* is, or lives inside, an allowed directory."""
        return any(
            candidate == root or candidate.is_relative_to(root)
            for root in self._roots
        )

    def describe(self) -> str:
        """A human-readable, comma-separated list for error messages."""
        return ", ".join(str(root) for root in self._roots)


def canonicalize_configured_directory(
    raw: str,
    *,
    env: Mapping[str, str] | None = None,
) -> Path:
    """Resolve one directory from the configuration file.

    The user's own configuration is the trust anchor, so symlinked entries such
    as a ``~/Documents`` that points at a mounted volume are allowed, as long
    as the path exists and is a directory.
    """
    candidate = expand_and_normalize(raw, expand_env=True, env=env)
    return _resolve_existing(candidate)


def canonicalize_directory(raw: str, allowlist: Allowlist) -> Path:
    """Resolve a model-supplied path and prove it is inside *allowlist*.

    Raises one of :class:`InvalidPathError`, :class:`PathDoesNotExistError`,
    :class:`PathNotDirectoryError`, :class:`PathOutsideAllowlistError`, or
    :class:`DirectoryReadError`. Never returns a path that escapes the
    allowlist, including through symlinks.
    """
    candidate = expand_and_normalize(raw)
    resolved = _resolve_existing(candidate)

    if not allowlist.contains(resolved):
        raise PathOutsideAllowlistError(_outside_message(candidate, resolved, allowlist))

    if not resolved.is_dir():
        raise PathNotDirectoryError(
            f"Not a directory: {resolved}. browse_files only lists directories; "
            "browse its parent directory to see this entry instead."
        )
    return resolved


def _resolve_existing(candidate: Path) -> Path:
    """Fully resolve *candidate*, translating OS errors into typed errors."""
    try:
        return candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PathDoesNotExistError(f"Directory does not exist: {candidate}.") from exc
    except NotADirectoryError as exc:
        raise PathNotDirectoryError(
            f"Not a directory: {candidate} (one of its components is a file)."
        ) from exc
    except PermissionError as exc:
        raise DirectoryReadError(
            f"Permission denied while resolving: {candidate}."
        ) from exc
    except OSError as exc:
        # ELOOP (symlink loop), ENAMETOOLONG and friends.
        raise InvalidPathError(
            f"Could not resolve path {candidate}: {exc.strerror or exc}."
        ) from exc


def _outside_message(candidate: Path, resolved: Path, allowlist: Allowlist) -> str:
    message = (
        "Permission denied: the requested directory is outside the configured "
        f"allowed directories. Requested: {candidate}."
    )
    if resolved != candidate:
        message += f" It resolves to {resolved}, which is not allowed."
    return f"{message} Allowed directories: {allowlist.describe()}."


def is_symlink_escape(path: Path, allowlist: Allowlist) -> bool:
    """True when *path* would resolve outside the allowlist.

    Used for reporting only: it answers "would browsing this entry be refused?"
    without following the link at the OS level, so a link pointing at ``/etc``
    is described but never opened.
    """
    return not allowlist.contains(Path(os.path.realpath(path)))


def read_symlink_target(path: Path) -> str | None:
    """Return the raw link target, or ``None`` if *path* is not a readable link."""
    try:
        return os.readlink(path)
    except OSError:
        return None


def validate_command_name(name: str) -> None:
    """Validate a bare executable name taken from the configuration file.

    Raises :class:`ConfigError` when the name contains a path separator, a
    shell metacharacter, whitespace, or any other character that a ``PATH``
    lookup cannot handle.
    """
    if not isinstance(name, str) or not name:
        raise ConfigError("A configured command name must be a non-empty string.")
    if "/" in name:
        raise ConfigError(
            f"Configured command name {name!r} contains a path separator; use a "
            "bare executable name (found on PATH) or an absolute path instead."
        )
    if not _SAFE_BARE_NAME.match(name):
        raise ConfigError(
            f"Configured command name {name!r} contains characters that are not "
            "allowed in an executable name. Use a bare name such as "
            "'gnome-terminal', or an absolute path, and pass arguments with the "
            "list form: [gnome-terminal, --option]."
        )


def contains_shell_metacharacters(value: str) -> bool:
    """True when *value* contains a character only a shell would interpret."""
    return any(char in SHELL_METACHARACTERS for char in value)


def validate_command_arguments(arguments: Sequence[str]) -> None:
    """Reject argument strings that cannot safely be passed to ``Popen``."""
    for argument in arguments:
        if not isinstance(argument, str):
            raise ConfigError(
                "Configured command arguments must be strings, got "
                f"{type(argument).__name__}."
            )
        if "\x00" in argument:
            raise ConfigError("Configured command arguments must not contain NUL bytes.")
        if "\n" in argument or "\r" in argument:
            raise ConfigError("Configured command arguments must not contain line breaks.")

def canonicalize_write_path(raw: str, allowlist: Allowlist) -> Path:
    """Resolve a model-supplied path for **writing** and prove it is allowed.

    Unlike :func:`canonicalize_directory`, the final component may not exist
    yet, because creating files and directories is the point. The path is first
    normalised with :meth:`pathlib.Path.resolve` in non-strict mode, which both
    follows symlinks for every existing component and normalises ``..``
    lexically - so ``allowed/newdir/../../outside/x`` becomes ``outside/x``
    before any decision is made, and cannot smuggle an escape through a
    directory that does not exist yet.

    The nearest **existing** ancestor is then resolved strictly and required to
    live inside *allowlist*; the non-existent tail is re-appended to it. A
    symlink whose target lies outside the allowlist is refused even when the
    link itself lives inside.
    """
    candidate = expand_and_normalize(raw)

    try:
        normalised = candidate.resolve(strict=False)
    except OSError as exc:
        raise InvalidPathError(
            f"Could not resolve path {candidate}: {exc.strerror or exc}."
        ) from exc

    missing: list[str] = []
    probe = normalised
    while True:
        if probe.exists():
            break
        parent = probe.parent
        if parent == probe:
            raise PathDoesNotExistError(
                f"No existing ancestor directory for: {candidate}."
            )
        missing.append(probe.name)
        probe = parent

    anchored = _resolve_existing(probe)
    if not allowlist.contains(anchored):
        raise PathOutsideAllowlistError(
            f"Permission denied: writing to {candidate} is outside the configured "
            f"write directories. It resolves to {normalised}, which is not allowed. "
            f"Allowed write directories: {allowlist.describe()}."
        )

    target = anchored
    for name in reversed(missing):
        target = target / name
    return target


def canonicalize_read_path(raw: str, allowlist: Allowlist) -> Path:
    """Resolve a model-supplied path for **reading** and prove it is allowed.

    Like :func:`canonicalize_directory` this requires the path to already exist
    and refuses anything that resolves outside *allowlist*; unlike it, the path
    may be a file as well as a directory.
    """
    candidate = expand_and_normalize(raw)
    resolved = _resolve_existing(candidate)
    if not allowlist.contains(resolved):
        raise PathOutsideAllowlistError(
            _outside_message(candidate, resolved, allowlist)
        )
    return resolved
