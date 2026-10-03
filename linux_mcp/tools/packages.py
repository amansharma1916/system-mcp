"""Package management through ``pacman``/``yay`` (Arch) or ``flatpak``.

Listing, searching, and inspecting packages are tier ``readonly`` and never need
privileges. Installing, removing, and upgrading are tier ``destructive``: they
run third-party package scripts as root and change the system in ways the user
may not be able to undo cleanly.

Privileged calls go through ``pkexec``, which raises a real polkit prompt. If
installation fails because nothing is listening on the system bus, the error
says so rather than reporting a bare exit status.
"""

from __future__ import annotations

import re
import shutil
from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from linux_mcp.config import Config, PackagesConfig
from linux_mcp.errors import InvalidPathError, LinuxMCPError, OperationRefusedError
from linux_mcp.guard import GuardContext, guarded
from linux_mcp.logging_setup import get_logger
from linux_mcp.tools._common import require_program, run_program

logger = get_logger("tools.packages")

_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9@._+][A-Za-z0-9@._+-]*$")
"""Arch and flatpak package names. A leading dash is refused as well."""

INSTALL_TIMEOUT = 900.0
"""Package operations are slow; five minutes is not unusual on a large update."""


class PackageEntry(BaseModel):
    """One installed or available package."""

    name: str = Field(description="Package name.")
    version: str = Field(description="Version string, or empty when not known.")
    description: str = Field(default="", description="Short description, when available.")


class PackageListResult(BaseModel):
    """The result of listing installed packages."""

    backend: str = Field(description="Which package manager was queried.")
    packages: list[PackageEntry] = Field(description="Matching packages.")
    total: int = Field(description="How many packages matched.")
    truncated: bool = Field(description="True when more matched than were returned.")


class PackageSearchResult(BaseModel):
    """The result of searching the repositories."""

    backend: str = Field(description="Which package manager was queried.")
    query: str = Field(description="The search term that was used.")
    matches: list[str] = Field(description="Names of matching packages.")
    total: int = Field(description="How many packages matched.")
    truncated: bool = Field(description="True when more matched than were returned.")


class PackageInfoResult(BaseModel):
    """The result of inspecting one package."""

    backend: str = Field(description="Which package manager was queried.")
    name: str = Field(description="Package name.")
    raw: str = Field(description="The package manager's full description text.")


class PackageActionResult(BaseModel):
    """The result of installing, removing, or upgrading."""

    backend: str = Field(description="Which package manager ran.")
    action: str = Field(description="install, remove, or upgrade.")
    targets: list[str] = Field(description="Packages that were acted on.")
    escalated: bool = Field(description="True when polkit was used to gain privileges.")
    output: str = Field(description="Combined output, truncated when very long.")


def _validate_package_name(name: str) -> str:
    if not isinstance(name, str) or not _PACKAGE_NAME.match(name):
        raise InvalidPathError(
            f"Invalid package name {name!r}. Package names may contain letters, "
            "digits, and @ . _ + - and must not start with a dash."
        )
    return name


def _validate_query(query: str) -> str:
    if not isinstance(query, str) or not query.strip():
        raise InvalidPathError("A search query must not be empty.")
    if query.startswith("-"):
        raise InvalidPathError("A search query must not start with a dash.")
    return query.strip()


def _backend(config: PackagesConfig) -> str:
    """Resolve the configured backend to a concrete program."""
    choice = config.backend
    if choice == "auto":
        choice = "yay" if shutil.which("yay") else "pacman"
    if choice not in ("pacman", "yay", "flatpak"):
        raise OperationRefusedError(
            f"Unknown package backend {choice!r}. Choose pacman, yay, flatpak, or auto."
        )
    if shutil.which(choice) is None:
        raise OperationRefusedError(
            f"The configured package backend {choice!r} is not installed."
        )
    return choice


def list_installed(
    config: PackagesConfig, *, name_filter: str | None = None, limit: int = 200
) -> PackageListResult:
    """List installed packages, optionally filtered by substring."""
    backend = _backend(config)
    if backend == "flatpak":
        output = run_program(
            ["flatpak", "list", "--app", "--columns=application,version"],
            purpose="flatpak list",
        )
        entries = []
        for line in output.splitlines():
            parts = line.split("\t")
            if parts and parts[0].strip():
                entries.append(
                    PackageEntry(
                        name=parts[0].strip(),
                        version=parts[1].strip() if len(parts) > 1 else "",
                    )
                )
    else:
        output = run_program([backend, "-Q"], purpose=f"{backend} -Q")
        entries = []
        for line in output.splitlines():
            parts = line.split(None, 1)
            if parts:
                entries.append(
                    PackageEntry(
                        name=parts[0],
                        version=parts[1].strip() if len(parts) > 1 else "",
                    )
                )

    if name_filter:
        needle = name_filter.lower()
        entries = [entry for entry in entries if needle in entry.name.lower()]
    entries.sort(key=lambda entry: entry.name)
    total = len(entries)
    return PackageListResult(
        backend=backend,
        packages=entries[:limit],
        total=total,
        truncated=total > limit,
    )


def search_repositories(
    config: PackagesConfig, query: str, *, limit: int = 100
) -> PackageSearchResult:
    """Search the configured repositories for *query*."""
    query = _validate_query(query)
    backend = _backend(config)
    if backend == "flatpak":
        output = run_program(
            ["flatpak", "search", query, "--columns=application"],
            purpose=f"flatpak search {query}",
        )
    else:
        output = run_program([backend, "-Ssq", query], purpose=f"{backend} -Ssq {query}")

    names = sorted({line.strip() for line in output.splitlines() if line.strip()})
    total = len(names)
    return PackageSearchResult(
        backend=backend,
        query=query,
        matches=names[:limit],
        total=total,
        truncated=total > limit,
    )


def describe_package(config: PackagesConfig, name: str) -> PackageInfoResult:
    """Return the package manager's full description of *name*."""
    name = _validate_package_name(name)
    backend = _backend(config)
    if backend == "flatpak":
        output = run_program(
            ["flatpak", "info", name], purpose=f"flatpak info {name}"
        )
    else:
        output = run_program([backend, "-Qi", name], purpose=f"{backend} -Qi {name}")
    return PackageInfoResult(backend=backend, name=name, raw=output)


def _escalate(config: PackagesConfig) -> bool:
    if not config.use_pkexec:
        return False
    require_program("pkexec", purpose="Privileged package operations")
    return True


def install_packages(config: PackagesConfig, names: list[str]) -> PackageActionResult:
    """Install one or more packages."""
    if not names:
        raise InvalidPathError("Provide at least one package to install.")
    checked = [_validate_package_name(name) for name in names]
    backend = _backend(config)
    if backend == "flatpak":
        arguments = ["flatpak", "install", "--noninteractive", "-y", *checked]
        escalated = False
    else:
        arguments = [backend, "-S", "--noconfirm", *checked]
        escalated = _escalate(config)

    output = run_program(
        arguments,
        purpose=f"Install {' '.join(checked)}",
        timeout_seconds=INSTALL_TIMEOUT,
        use_pkexec=escalated,
    )
    return PackageActionResult(
        backend=backend,
        action="install",
        targets=checked,
        escalated=escalated,
        output=output[-4000:],
    )


def remove_packages(
    config: PackagesConfig, names: list[str], *, cascade: bool = True
) -> PackageActionResult:
    """Remove one or more packages."""
    if not names:
        raise InvalidPathError("Provide at least one package to remove.")
    checked = [_validate_package_name(name) for name in names]
    backend = _backend(config)
    if backend == "flatpak":
        arguments = ["flatpak", "uninstall", "--noninteractive", "-y", *checked]
        escalated = False
    else:
        # -Rns removes the package, its unneeded dependencies, and its config.
        flags = "-Rns" if cascade else "-R"
        arguments = [backend, flags, "--noconfirm", *checked]
        escalated = _escalate(config)

    output = run_program(
        arguments,
        purpose=f"Remove {' '.join(checked)}",
        timeout_seconds=INSTALL_TIMEOUT,
        use_pkexec=escalated,
    )
    return PackageActionResult(
        backend=backend,
        action="remove",
        targets=checked,
        escalated=escalated,
        output=output[-4000:],
    )


def upgrade_system(config: PackagesConfig) -> PackageActionResult:
    """Upgrade every installed package."""
    backend = _backend(config)
    if backend == "flatpak":
        arguments = ["flatpak", "update", "--noninteractive", "-y"]
        escalated = False
    else:
        arguments = [backend, "-Syu", "--noconfirm"]
        escalated = _escalate(config)

    output = run_program(
        arguments,
        purpose="Upgrade the system",
        timeout_seconds=INSTALL_TIMEOUT,
        use_pkexec=escalated,
    )
    return PackageActionResult(
        backend=backend,
        action="upgrade",
        targets=[],
        escalated=escalated,
        output=output[-4000:],
    )


def register(server: MCPServer, config: Config, context: GuardContext) -> None:
    """Declare the package tools on *server*."""
    packages = config.packages

    @server.tool(
        title="List installed packages",
        description=(
            f"List installed packages using the {packages.backend} backend, "
            "optionally filtered by a substring of the name."
        ),
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def list_packages(
        name_filter: Annotated[
            str | None, Field(description="Only include packages whose name contains this.")
        ] = None,
        limit: Annotated[int, Field(gt=0, le=5000)] = 200,
    ) -> PackageListResult:
        """List installed packages."""
        logger.info("list_packages(name_filter=%r)", name_filter)
        try:
            return guarded(
                context,
                tool="list_packages",
                arguments={"name_filter": name_filter, "limit": limit},
                action=lambda: list_installed(
                    packages, name_filter=name_filter, limit=limit
                ),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Search for packages",
        description="Search the configured repositories for packages matching a term.",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def search_packages(
        query: Annotated[str, Field(description="Search term, for example 'postgres'.")],
        limit: Annotated[int, Field(gt=0, le=2000)] = 100,
    ) -> PackageSearchResult:
        """Search the repositories for packages."""
        logger.info("search_packages(query=%r)", query)
        try:
            return guarded(
                context,
                tool="search_packages",
                arguments={"query": query, "limit": limit},
                action=lambda: search_repositories(packages, query, limit=limit),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Inspect a package",
        description="Show the package manager's full description of one package.",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    def package_info(
        name: Annotated[str, Field(description="Exact package name.")],
    ) -> PackageInfoResult:
        """Show details for one package."""
        logger.info("package_info(name=%r)", name)
        try:
            return guarded(
                context,
                tool="package_info",
                arguments={"name": name},
                action=lambda: describe_package(packages, name),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Install packages",
        description=(
            "Install one or more packages. Runs third-party install scripts with "
            "system privileges, so this requires approval. Uses pkexec when "
            "configured, which raises a polkit password prompt."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def install_package(
        names: Annotated[
            list[str], Field(description="Package names to install.")
        ],
    ) -> PackageActionResult:
        """Install packages. Requires approval."""
        logger.info("install_package(names=%r)", names)
        try:
            return guarded(
                context,
                tool="install_package",
                arguments={"names": names},
                summary=f"Install: {', '.join(names)}",
                details=f"{packages.backend} install {' '.join(names)}"
                + (" (via pkexec)" if packages.use_pkexec else ""),
                action=lambda: install_packages(packages, list(names)),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Remove packages",
        description=(
            "Uninstall one or more packages. With cascade=true (the default) also "
            "removes now-unneeded dependencies and the package's configuration. "
            "Requires approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def remove_package(
        names: Annotated[list[str], Field(description="Package names to remove.")],
        cascade: Annotated[
            bool, Field(description="Also remove unneeded dependencies and config.")
        ] = True,
    ) -> PackageActionResult:
        """Remove packages. Requires approval."""
        logger.info("remove_package(names=%r, cascade=%s)", names, cascade)
        try:
            return guarded(
                context,
                tool="remove_package",
                arguments={"names": names, "cascade": cascade},
                summary=f"Remove: {', '.join(names)}",
                details=f"{packages.backend} remove {' '.join(names)}"
                + (" (cascade)" if cascade else "")
                + (" (via pkexec)" if packages.use_pkexec else ""),
                action=lambda: remove_packages(packages, list(names), cascade=cascade),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        title="Upgrade the system",
        description=(
            "Upgrade every installed package. On a rolling distribution this can "
            "be a large and disruptive operation, so it requires approval."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def update_system() -> PackageActionResult:
        """Upgrade all packages. Requires approval."""
        logger.info("update_system()")
        try:
            return guarded(
                context,
                tool="update_system",
                arguments={},
                summary="Upgrade every installed package",
                details=f"{packages.backend} full system upgrade"
                + (" (via pkexec)" if packages.use_pkexec else ""),
                action=lambda: upgrade_system(packages),
            )
        except LinuxMCPError as exc:
            raise ToolError(str(exc)) from exc
